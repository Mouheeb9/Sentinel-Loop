"""Run one Sigma rule over events: the contract between the route node (Mouheb) and the
validation stack (Mouadh, docs/validation-setup.md).

Owner: Mouadh (Day 11). This file only fixes the signature so `route_live` and the coverage
eval can be built against it; the body is his (sigma-cli / Zircolite over `Event.raw`).
Change the signature only by a PR both of us review, like `schemas.py`.
"""

from __future__ import annotations

from sentinel.schemas import Event


def match(rule_yaml: str, events: list[Event]) -> list[str]:
    """The `event_id`s of the events the rule fires on ([] when it fires on none).

    Raises ValueError when the rule can't be compiled, so a broken rule is never mistaken for
    "does not fire".
    """
    raise NotImplementedError("matcher not implemented yet (Mouadh, Day 11)")
