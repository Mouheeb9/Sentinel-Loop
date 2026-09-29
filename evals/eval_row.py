"""The row contract between the eval runner (`evals/run.py`, Mouheb) and the scorers
(`evals/scorers.py`, Mouadh). One row per golden alert per config.

The runner writes rows; the scorers only read them (rows in, numbers out: no model calls, no DB).
Change this file only by a PR both of us review, like `schemas.py`.

The input alert is NOT copied into the row (it would bloat every results file). Scorers that need
it (hallucinated-IOC rate) get it from `evals.triage_smoke.load_golden()`, keyed by `alert_id`.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["true_positive", "benign_noisy", "needs_review"]


class EvalRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Which run this row belongs to.
    config: str  # "single-prompt" | "rag" | "rag-tools"
    alert_id: str

    # Golden truth, copied from data/golden/v1.jsonl.
    label: Verdict
    label_techniques: list[str]

    # Model output. All None when `error` is set (no valid TriageVerdict came back).
    verdict: Verdict | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    technique_ids: list[str] = Field(default_factory=list)
    ioc_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)

    # None = valid verdict. Otherwise "schema: ..." (TriageError) or "transport: ..." (429, ...).
    # Scorers count an error row as a wrong answer, never skip it.
    error: str | None = None
    # 0 = valid verdict on the first try, 1 = needed the one schema retry.
    schema_retries: int = 0

    # Cost and speed. cost_usd is None on free models (unknown, not zero).
    cost_usd: float | None = None
    latency_s: float  # wall clock for the whole alert, retries and tier 2 included
    tier: int | None = None  # which tier's verdict is final (1 or 2)

    trace: str | None = None  # Langfuse URL, for reading failures
