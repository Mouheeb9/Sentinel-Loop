"""Two-tier triage: a cheap model answers first, a stronger one re-runs the alert when unsure.

Escalate when the tier-1 answer
  - has confidence below SENTINEL_ESCALATE_BELOW (default 0.7),
  - is needs_review (a second opinion is what that verdict asks for),
  - is true_positive without a technique (ambiguous mapping), or
  - never became a valid TriageVerdict (TriageError).

Tier 2 starts fresh from the same alert and context, not from tier 1's answer, so it can't
anchor on it; its lookups hit the tool cache that tier 1 filled. If tier 2 fails, tier 1's
answer stands (when there is one). Every run records model, tokens and cost so the trace shows
what each alert cost and which tier decided it.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from langchain_core.language_models import BaseChatModel
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import merge_configs

from sentinel.agents.triage import TriageError, TriageResult, triage_alert
from sentinel.llm import chat_model, cost_usd, escalation_model_name, triage_model_name
from sentinel.retrieval.search import Hit
from sentinel.schemas import Alert, TriageVerdict

DEFAULT_ESCALATE_BELOW = 0.7


def escalate_below() -> float:
    return float(os.environ.get("SENTINEL_ESCALATE_BELOW") or DEFAULT_ESCALATE_BELOW)


def escalation_reason(verdict: TriageVerdict, threshold: float) -> str | None:
    if verdict.confidence < threshold:
        return f"confidence {verdict.confidence:.2f} < {threshold}"
    if verdict.verdict == "needs_review":
        return "verdict needs_review"
    if verdict.verdict == "true_positive" and not verdict.technique_ids:
        return "true_positive without a technique"
    return None


@dataclass(frozen=True)
class TierRun:
    tier: int
    model: str
    ok: bool
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    llm_calls: int = 0
    lookups: tuple[dict, ...] = ()
    schema_retries: int = 0
    error: str | None = None


@dataclass(frozen=True)
class RoutedTriage:
    verdict: TriageVerdict
    tier: int  # which tier's verdict is final
    escalation: str | None  # why tier 2 ran, None if it didn't
    runs: tuple[TierRun, ...]

    @property
    def cost_usd(self) -> float | None:
        costs = [r.cost_usd for r in self.runs]
        return None if any(c is None for c in costs) else sum(costs)

    @property
    def schema_retries(self) -> int:
        return next(r.schema_retries for r in self.runs if r.tier == self.tier)

    def runs_as_dicts(self) -> list[dict]:
        return [asdict(r) for r in self.runs]


def triage_routed(
    alert: Alert,
    techniques: list[Hit],
    sigma_rules: list[Hit],
    config: RunnableConfig | None = None,
    *,
    tier1: tuple[str, BaseChatModel] | None = None,
    tier2: tuple[str, BaseChatModel] | None = None,
    threshold: float | None = None,
) -> RoutedTriage:
    """tier1/tier2: (model name, model). Default: from SENTINEL_TRIAGE_MODEL /
    SENTINEL_ESCALATION_MODEL. Pass tier2=None with SENTINEL_ESCALATION_MODEL=none for one tier."""
    threshold = escalate_below() if threshold is None else threshold
    if tier1 is None:
        tier1 = (triage_model_name(), chat_model(triage_model_name()))
    if tier2 is None and (name := escalation_model_name()):
        tier2 = (name, chat_model(name))

    run1, result1 = _run(1, tier1, alert, techniques, sigma_rules, config)
    if result1 is not None:
        reason = escalation_reason(result1.verdict, threshold)
    else:
        reason = f"tier 1 failed: {run1.error}"
    if reason is None or tier2 is None:
        if result1 is None:
            raise TriageError(run1.error or "tier 1 failed")
        return RoutedTriage(result1.verdict, 1, None, (run1,))

    run2, result2 = _run(2, tier2, alert, techniques, sigma_rules, config)
    if result2 is not None:
        return RoutedTriage(result2.verdict, 2, reason, (run1, run2))
    if result1 is not None:
        return RoutedTriage(result1.verdict, 1, reason, (run1, run2))
    raise TriageError(f"both tiers failed: {run1.error} / {run2.error}")


def _run(
    tier: int,
    named_model: tuple[str, BaseChatModel],
    alert: Alert,
    techniques: list[Hit],
    sigma_rules: list[Hit],
    config: RunnableConfig | None,
) -> tuple[TierRun, TriageResult | None]:
    name, model = named_model
    # Shows up on every LLM and tool observation of this tier in the Langfuse trace.
    tier_config = merge_configs(config, {"metadata": {"triage_tier": tier, "triage_model": name}})
    try:
        r = triage_alert(alert, techniques, sigma_rules, model, tier_config)
    except TriageError as e:
        run = TierRun(
            tier=tier,
            model=name,
            ok=False,
            input_tokens=e.input_tokens,
            output_tokens=e.output_tokens,
            cost_usd=cost_usd(name, e.input_tokens, e.output_tokens),
            error=str(e),
        )
        return run, None
    run = TierRun(
        tier=tier,
        model=name,
        ok=True,
        input_tokens=r.input_tokens,
        output_tokens=r.output_tokens,
        cost_usd=cost_usd(name, r.input_tokens, r.output_tokens),
        llm_calls=r.llm_calls,
        lookups=r.lookups,
        schema_retries=r.schema_retries,
    )
    return run, r
