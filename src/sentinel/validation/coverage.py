"""Is this alert already detected by an existing Sigma rule? Deterministic, no model call.

The route node asks this for every true positive: the retrieved Sigma rules are run through the
matcher over the alert's own events, in retrieval order, and the first one that fires covers the
alert (the loop stops; no new rule is written). The coverage eval (evals/coverage.py) asks the
same question over the golden true positives.

"Not covered" is only claimed when matching really ran: a rule missing from the local checkout
or failing to compile is recorded, and a matcher that isn't available yet makes the answer
unknown (`unavailable`), never "no coverage" by accident.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.retrieval.sigma import DEFAULT_RULES_DIR
from sentinel.schemas import Event
from sentinel.validation import matcher as matcher_module
from sentinel.validation.rules import rule_yaml

Matcher = Callable[[str, list[Event]], list[str]]


@dataclass
class Coverage:
    covering_rule_id: str | None = None
    checked: list[str] = field(default_factory=list)  # rules the matcher ran, in order
    missing: list[str] = field(default_factory=list)  # no YAML in the local checkout
    broken: list[str] = field(default_factory=list)  # the matcher couldn't compile them
    unavailable: str | None = None  # why matching didn't run at all

    @property
    def known(self) -> bool:
        """False when the answer is unknown: no rule could actually be matched."""
        tried = bool(self.checked) or not (self.missing or self.broken)
        return self.unavailable is None and tried


def check_coverage(
    events: list[Event],
    rule_ids: list[str],
    matcher: Matcher | None = None,
    rules_dir: Path = DEFAULT_RULES_DIR,
) -> Coverage:
    match = matcher or matcher_module.match  # looked up per call, so tests can swap it
    own = {e.event_id for e in events}
    result = Coverage()
    for rule_id in rule_ids:
        text = rule_yaml(rule_id, rules_dir)
        if text is None:
            result.missing.append(rule_id)
            continue
        try:
            fired = match(text, events)
        except NotImplementedError as e:
            result.unavailable = str(e)
            return result
        except ValueError:
            result.broken.append(rule_id)
            continue
        result.checked.append(rule_id)
        if own & set(fired):
            result.covering_rule_id = rule_id
            return result
    return result
