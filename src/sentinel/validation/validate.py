"""Grade a generated Sigma rule: compiles? catches held-out attacks? fires on benign activity?

Owner: Mouadh (Day 12). This file only fixes the signature so the pipeline (`validate_live` in
graph/nodes.py) and the rule-gen eval (evals/rulegen.py) can be built against it, like
`matcher.match` on Day 11. The body is his: see notes/day13-mouadh-tasks.md for the plan.
Change the signature only by a PR both of us review, like `schemas.py`.
"""

from __future__ import annotations

from sentinel.schemas import Alert, ValidationResult


def validate(rule_yaml: str, source_alert: Alert, technique_ids: list[str]) -> ValidationResult:
    """The rule's ValidationResult.

    - compiled / compile_errors: does the rule compile (matcher raises ValueError when not)?
    - true_positives: hits on held-out attack events of the same (parent) technique, never from
      the capture `source_alert` came from (leakage rule).
    - false_positives / fp_rate: hits on the benign corpus (golden benign_noisy + background).
    - failed_samples: each positive that missed and each benign that fired.
    - feedback: short and actionable, for the Week 3 repair loop.
    """
    raise NotImplementedError("validator not implemented yet (Mouadh, Day 12)")
