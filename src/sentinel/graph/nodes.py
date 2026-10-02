"""The pipeline's nodes.

Stubs have the real signature (state in, partial update out) but return fake values, steered by
a `StubScript` in the run config (`{"configurable": {"stub": StubScript(...)}}`), so tests can
force any path. Real implementations (`*_live`) replace them one at a time: enrich and triage
since Day 5, route since Day 11 (matcher injectable via `config["configurable"]["matcher"]`),
rule_gen and validate since Day 13 (model / validator injectable as "rulegen_model" /
"validator"). Repair is still a stub, so a live run tries one rule version (max_attempts=1).

`PipelineOptions` in `config["configurable"]["pipeline"]` switches retrieval, enrichment tools
and rule generation off for the eval baselines (evals/run.py); the default is everything on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

import yaml
from langchain_core.runnables import RunnableConfig

from sentinel.agents.enrich import enrich_alert
from sentinel.agents.routing import triage_routed
from sentinel.agents.rule_gen import RuleGenError, generate_rule
from sentinel.graph.state import Outcome, SentinelState
from sentinel.llm import chat_model, rulegen_model_name
from sentinel.schemas import TriageVerdict, ValidationResult
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


def rule_passed(result: ValidationResult) -> bool:
    # Placeholder for the Week 3 gate (TP/FP thresholds): compiles and every sample behaved.
    return result.compiled and not result.failed_samples and not result.compile_errors


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
    info = {
        "title": r.draft.title,
        "technique_ids": r.draft.technique_ids,
        "schema_retries": r.schema_retries,
        "input_tokens": r.input_tokens,
        "output_tokens": r.output_tokens,
        "llm_calls": r.llm_calls,
        "model": model_name,
    }
    return {"draft_rule": r.rule_yaml, "attempts": 1, "max_attempts": 1, "rulegen": info}


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
    result = ValidationResult(
        rule_id=f"stub-v{state.get('attempts', 0)}",
        compiled=ok,
        compile_errors=[] if ok else ["stub failure"],
        true_positives=1 if ok else 0,
        false_positives=0,
        fp_rate=0.0,
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
    return "rule_passed" if validations and rule_passed(validations[-1]) else "rule_failed"
