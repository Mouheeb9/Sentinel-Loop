"""The pipeline's nodes.

Stubs have the real signature (state in, partial update out) but return fake values, steered by
a `StubScript` in the run config (`{"configurable": {"stub": StubScript(...)}}`), so tests can
force any path. Real implementations (`*_live`) replace them one at a time: enrich and triage
since Day 5, route since Day 11 (matcher injectable via `config["configurable"]["matcher"]`),
rule_gen and validate since Day 13 (model / validator injectable as "rulegen_model" /
"validator"), repair since Day 16 (event lookup injectable as "event_lookup").

`PipelineOptions` in `config["configurable"]["pipeline"]` switches retrieval, enrichment tools
and rule generation off for the eval baselines (evals/run.py); the default is everything on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

import yaml
from langchain_core.runnables import RunnableConfig

from sentinel.agents import repair as repair_module
from sentinel.agents.enrich import enrich_alert
from sentinel.agents.routing import triage_routed
from sentinel.agents.rule_gen import RuleGenError, generate_rule
from sentinel.graph.state import MAX_ATTEMPTS, Outcome, SentinelState
from sentinel.llm import chat_model, rulegen_model_name
from sentinel.schemas import FailedSample, TriageVerdict, ValidationResult
from sentinel.validation import validate as validate_module
from sentinel.validation.coverage import check_coverage


@dataclass(frozen=True)
class StubScript:
    verdict: str = "true_positive"
    # Existing Sigma rule that already detects the alert; None means no coverage.
    covering_rule_id: str | None = None
    # Pass/fail of each validation run in order; the last value repeats once the list runs out.
    validation_passes: tuple[bool, ...] = (True,)


@dataclass(frozen=True)
class PipelineOptions:
    retrieval: bool = True  # ATT&CK + Sigma context from pgvector
    tools: bool = True  # NVD / ThreatFox lookups during triage
    rules: bool = True  # write + validate a rule for uncovered attacks (off in triage evals)


def _script(config: RunnableConfig) -> StubScript:
    return config.get("configurable", {}).get("stub") or StubScript()


def _options(config: RunnableConfig | None) -> PipelineOptions:
    return (config or {}).get("configurable", {}).get("pipeline") or PipelineOptions()


def held_out_positives(result: ValidationResult) -> int:
    """Same-technique held-out attacks the rule was graded on (caught + missed)."""
    return result.true_positives + sum(f.should_fire for f in result.failed_samples)


def rule_recall(result: ValidationResult) -> float | None:
    """Share of the held-out same-technique attacks the rule catches; None when there are none."""
    n = held_out_positives(result)
    return result.true_positives / n if n else None


RuleVerdict = Literal["passed", "needs_review", "failed"]


def rule_verdict(result: ValidationResult) -> RuleVerdict:
    """Pass bar v2 (2026-10-07, ADR 0003): compiles, fires on NO benign event, and catches at
    least min(2, n) of the n held-out repeats of the attack (validator v2: same procedure when the
    alert has one, else same technique). n = 0: nothing to test recall on, so a human decides.

    v1 passed with a single held-out hit, so a near-fingerprint passed (repair-try2: 1 of 4
    repeats). A recall floor (>= .3) was dropped: n is at most 6 in golden-v1.1, and 2 of 6 already
    clears it. A benign hit always fails: in a SOC a noisy rule costs more than a missed variant."""
    if not result.compiled or result.compile_errors or result.false_positives:
        return "failed"
    n = held_out_positives(result)
    if n == 0:
        return "needs_review"
    return "passed" if result.true_positives >= min(2, n) else "failed"


def rule_passed(result: ValidationResult) -> bool:
    return rule_verdict(result) == "passed"


def stalled(validations: list[ValidationResult]) -> bool:
    """The last repair changed nothing the validator can see: same counts, same failing samples.
    Another attempt would most likely repeat it, so the loop stops and saves the quota."""
    if len(validations) < 2:
        return False

    def seen(v: ValidationResult) -> tuple:
        failing = sorted((s.sample_id, s.should_fire) for s in v.failed_samples)
        return v.compiled, v.true_positives, v.false_positives, failing

    return seen(validations[-1]) == seen(validations[-2])


def ingest(state: SentinelState) -> dict:
    return {}


def enrich(state: SentinelState) -> dict:
    return {"techniques": [], "sigma_rules": []}


def enrich_live(state: SentinelState, config: RunnableConfig) -> dict:
    if not _options(config).retrieval:
        return {"techniques": [], "sigma_rules": []}
    techniques, sigma_rules = enrich_alert(state["alert"])
    return {"techniques": techniques, "sigma_rules": sigma_rules}


def triage_live(state: SentinelState, config: RunnableConfig) -> dict:
    result = triage_routed(
        state["alert"],
        state.get("techniques", []),
        state.get("sigma_rules", []),
        config,
        use_tools=_options(config).tools,
    )
    return {
        "verdict": result.verdict,
        "triage_schema_retries": result.schema_retries,
        "triage_tier": result.tier,
        "triage_escalation": result.escalation,
        "triage_runs": result.runs_as_dicts(),
        "triage_cost_usd": result.cost_usd,
    }


def triage(state: SentinelState, config: RunnableConfig) -> dict:
    verdict = TriageVerdict(
        verdict=_script(config).verdict,
        confidence=0.5,
        technique_ids=[],
        reasoning="stub",
        evidence_refs=[],
        ioc_refs=[],
    )
    return {"verdict": verdict}


def route(state: SentinelState, config: RunnableConfig) -> dict:
    return {"covering_rule_id": _script(config).covering_rule_id}


def route_live(state: SentinelState, config: RunnableConfig) -> dict:
    """A true positive is covered when one of the retrieved Sigma rules fires on its events."""
    if state["verdict"].verdict != "true_positive":
        return {"covering_rule_id": None}
    matcher = (config or {}).get("configurable", {}).get("matcher")
    rule_ids = [h.id for h in state.get("sigma_rules", [])]
    result = check_coverage(state["alert"].events, rule_ids, matcher)
    return {"covering_rule_id": result.covering_rule_id, "coverage": asdict(result)}


def rule_gen_live(state: SentinelState, config: RunnableConfig) -> dict:
    """An uncovered true_positive -> a Sigma rule (agents/rule_gen.py). Never raises: a failed
    generation is a recorded outcome (rule_failed), not a crash of the whole run."""
    if not _options(config).rules:
        return {"draft_rule": "", "rulegen": {"skipped": True}}
    configurable = (config or {}).get("configurable", {})
    model_name = rulegen_model_name()
    model = configurable.get("rulegen_model") or chat_model(model_name)
    try:
        r = generate_rule(
            state["alert"], state["verdict"], state.get("sigma_rules", []), model, config
        )
    except RuleGenError as e:
        return {"draft_rule": "", "attempts": 1, "rulegen": {"error": str(e)[:1000]}}
    return {"draft_rule": r.rule_yaml, "attempts": 1, "rulegen": _info(r, model_name)}


def repair_live(state: SentinelState, config: RunnableConfig) -> dict:
    """The next version of a rule that failed validation: rule_gen again, told what the validator
    found (agents/repair.py). Never raises: no valid rule ends the run on the last validation."""
    configurable = (config or {}).get("configurable", {})
    model_name = rulegen_model_name()
    model = configurable.get("rulegen_model") or chat_model(model_name)
    lookup = configurable.get("event_lookup") or repair_module.default_event_lookup
    attempt = state.get("attempts", 0) + 1
    context = repair_module.build_repair_context(
        state["draft_rule"],
        state["validations"][-1],
        attempt,
        state.get("max_attempts", MAX_ATTEMPTS),
        lookup,
    )
    try:
        r = generate_rule(
            state["alert"], state["verdict"], state.get("sigma_rules", []), model, config, context
        )
    except RuleGenError as e:
        error = {"attempt": attempt, "error": str(e)[:1000]}
        return {"repairs": [error], "repair_failed": True}
    info = {"attempt": attempt, **_info(r, model_name)}
    return {"draft_rule": r.rule_yaml, "attempts": attempt, "repairs": [info]}


def _info(r, model_name: str) -> dict:
    return {
        "title": r.draft.title,
        "technique_ids": r.draft.technique_ids,
        "schema_retries": r.schema_retries,
        "input_tokens": r.input_tokens,
        "output_tokens": r.output_tokens,
        "llm_calls": r.llm_calls,
        "model": model_name,
    }


def validate_live(state: SentinelState, config: RunnableConfig) -> dict:
    """Mouadh's validator on the current draft. Until it exists the rule is recorded as
    unvalidated: rule_gen already proved it compiles and fires on its own alert, nothing more."""
    rule_yaml = state["draft_rule"]
    rule_id = str(yaml.safe_load(rule_yaml).get("id", "generated"))
    techniques = list(
        state.get("rulegen", {}).get("technique_ids") or state["verdict"].technique_ids
    )
    validator = (config or {}).get("configurable", {}).get("validator") or validate_module.validate
    try:
        result = validator(rule_yaml, state["alert"], techniques)
    except NotImplementedError as e:
        pending = ValidationResult(
            rule_id=rule_id,
            compiled=True,
            true_positives=0,
            false_positives=0,
            fp_rate=0.0,
            feedback=f"NOT VALIDATED ({e}): only known to compile and fire on its own alert",
        )
        return {"validations": [pending], "validation_pending": True}
    return {"validations": [result]}


def rule_gen(state: SentinelState) -> dict:
    return {"draft_rule": "title: stub rule v1", "attempts": 1}


def validate(state: SentinelState, config: RunnableConfig) -> dict:
    passes = _script(config).validation_passes
    run = len(state.get("validations", []))
    ok = passes[min(run, len(passes) - 1)]
    version = f"stub-v{state.get('attempts', 0)}"
    # Each failure names a different sample, so the stall check sees the repair change something.
    failed = [FailedSample(sample_id=version, should_fire=True, did_fire=False, event_ref="stub")]
    result = ValidationResult(
        rule_id=version,
        compiled=ok,
        compile_errors=[] if ok else ["stub failure"],
        true_positives=1 if ok else 0,
        false_positives=0,
        fp_rate=0.0,
        failed_samples=[] if ok else failed,
        feedback="" if ok else "stub: rule did not compile",
    )
    return {"validations": [result]}


def repair(state: SentinelState) -> dict:
    attempts = state.get("attempts", 0) + 1
    return {"draft_rule": f"title: stub rule v{attempts}", "attempts": attempts}


def output(state: SentinelState) -> dict:
    return {"outcome": _outcome(state)}


def _outcome(state: SentinelState) -> Outcome:
    verdict = state["verdict"].verdict
    if verdict == "benign_noisy":
        return "benign"
    if verdict == "needs_review":
        return "needs_review"
    if state.get("covering_rule_id"):
        return "covered"
    if state.get("rulegen", {}).get("skipped"):
        return "rule_skipped"
    if state.get("validation_pending"):
        return "rule_unvalidated"
    validations = state.get("validations", [])
    if not validations:
        return "rule_failed"
    return {
        "passed": "rule_passed",
        "needs_review": "rule_needs_review",
        "failed": "rule_failed",
    }[rule_verdict(validations[-1])]
