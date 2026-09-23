"""The pipeline's nodes.

Stubs have the real signature (state in, partial update out) but return fake values, steered by
a `StubScript` in the run config (`{"configurable": {"stub": StubScript(...)}}`), so tests can
force any path. Real implementations (`*_live`) replace them one at a time: enrich and triage
since Day 5; route, rule_gen, validate and repair are still stubs.
"""

from __future__ import annotations

from dataclasses import dataclass

from langchain_core.runnables import RunnableConfig

from sentinel.agents.enrich import enrich_alert
from sentinel.agents.routing import triage_routed
from sentinel.graph.state import Outcome, SentinelState
from sentinel.schemas import TriageVerdict, ValidationResult


@dataclass(frozen=True)
class StubScript:
    verdict: str = "true_positive"
    # Existing Sigma rule that already detects the alert; None means no coverage.
    covering_rule_id: str | None = None
    # Pass/fail of each validation run in order; the last value repeats once the list runs out.
    validation_passes: tuple[bool, ...] = (True,)


def _script(config: RunnableConfig) -> StubScript:
    return config.get("configurable", {}).get("stub") or StubScript()


def rule_passed(result: ValidationResult) -> bool:
    # Placeholder for the Week 3 gate (TP/FP thresholds): compiles and every sample behaved.
    return result.compiled and not result.failed_samples and not result.compile_errors


def ingest(state: SentinelState) -> dict:
    return {}


def enrich(state: SentinelState) -> dict:
    return {"techniques": [], "sigma_rules": []}


def enrich_live(state: SentinelState) -> dict:
    techniques, sigma_rules = enrich_alert(state["alert"])
    return {"techniques": techniques, "sigma_rules": sigma_rules}


def triage_live(state: SentinelState, config: RunnableConfig) -> dict:
    result = triage_routed(
        state["alert"], state.get("techniques", []), state.get("sigma_rules", []), config
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
    validations = state.get("validations", [])
    return "rule_passed" if validations and rule_passed(validations[-1]) else "rule_failed"
