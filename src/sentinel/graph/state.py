"""The state that travels through the LangGraph pipeline.

Nodes never call each other. Each node reads the state and returns a dict of only the keys it
changed; LangGraph merges that into the state. How a key is merged is its *reducer*: plain keys
are overwritten, `validations` is appended to (so the repair loop keeps every attempt's feedback
instead of the last one silently replacing the rest).
"""

from __future__ import annotations

import operator
from typing import Annotated, Literal, NotRequired, TypedDict

from sentinel.retrieval.search import Hit
from sentinel.schemas import Alert, TriageVerdict, ValidationResult

# Max versions of a rule: the first draft + 2 repairs. The 3rd failed validation gives up.
MAX_ATTEMPTS = 3

Outcome = Literal[
    "benign",  # triage said benign_noisy: nothing to write
    "needs_review",  # triage unsure: hand to a human, no rule
    "covered",  # real threat, but an existing Sigma rule already detects it
    "rule_passed",  # new rule written and validated
    "rule_failed",  # rule still failing after MAX_ATTEMPTS versions
]


class SentinelState(TypedDict):
    # Input: the only key the caller must provide.
    alert: Alert

    # enrich: ATT&CK techniques and existing Sigma rules related to the alert.
    techniques: NotRequired[list[Hit]]
    sigma_rules: NotRequired[list[Hit]]

    # triage (schema_retries: 1 if the model needed its one retry to produce a valid verdict)
    verdict: NotRequired[TriageVerdict]
    triage_schema_retries: NotRequired[int]
    # Two-tier routing: which tier's verdict is final, why tier 2 ran (None: it didn't), one
    # dict per tier run (model, tokens, cost, lookups), total cost (None if a price is unknown).
    triage_tier: NotRequired[int]
    triage_escalation: NotRequired[str | None]
    triage_runs: NotRequired[list[dict]]
    triage_cost_usd: NotRequired[float | None]

    # route: id of an existing Sigma rule that already covers this alert, None if no coverage.
    covering_rule_id: NotRequired[str | None]

    # rule_gen / repair: the current Sigma rule as YAML text (overwritten on each repair).
    draft_rule: NotRequired[str]

    # validate: one result per validation run, oldest first (appended, never overwritten).
    validations: NotRequired[Annotated[list[ValidationResult], operator.add]]

    # rule_gen sets 1, each repair adds 1: the number of rule versions validated so far.
    # validate fails and attempts == MAX_ATTEMPTS -> give up (3 validations, 2 repairs).
    attempts: NotRequired[int]

    # output: why the run ended.
    outcome: NotRequired[Outcome]
