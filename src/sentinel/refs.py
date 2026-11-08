"""Does what a TriageVerdict points at actually exist in the alert?

Used twice: by triage, which rejects a verdict that cites values or fields the alert doesn't have
(output schema validation, Week 4), and by the eval scorer that counts hallucinated IOCs. Both
are set lookups after normalizing, not judgements.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from sentinel.schemas import Alert

# Alert metadata the triage message shows as trusted fields (build_user_message).
ALERT_FIELDS = frozenset({"alert_id", "detection_name", "severity"})
_EVENT_PATH = re.compile(r"^events\[(\d+)\]\.([a-z_]+(?:\.[a-z_]+)*)$")


def normalize(text: str) -> str:
    """Lowercase and forward slashes: the model writes C:/Users/... for C:\\Users\\..."""
    return text.lower().replace("\\", "/")


def strings(value: Any) -> Iterable[str]:
    """Every string/number leaf of a JSON value (so escaping never hides a match)."""
    if isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)
    elif value is not None and not isinstance(value, bool):
        yield str(value)


def missing_iocs(ioc_refs: Iterable[str], alert: Alert) -> list[str]:
    """IOCs that appear nowhere in the input alert (its events, raw fields included)."""
    haystack = "\n".join(normalize(s) for s in strings(alert.model_dump(mode="json")))
    return [ioc for ioc in ioc_refs if ioc.strip() and normalize(ioc.strip()) not in haystack]


def missing_evidence(evidence_refs: Iterable[str], alert: Alert) -> list[str]:
    """evidence_refs that are not a path to a field with a value. `raw` doesn't count: the model
    never sees it, so it can't have relied on it."""
    events = [e.model_dump(mode="json") for e in alert.events]
    return [ref for ref in evidence_refs if not _resolves(ref.strip(), events)]


def _resolves(ref: str, events: list[dict]) -> bool:
    if ref in ALERT_FIELDS:
        return True
    m = _EVENT_PATH.fullmatch(ref)
    if not m or int(m[1]) >= len(events):
        return False
    keys = m[2].split(".")
    if keys[0] in ("raw", "untrusted_fields"):
        return False
    node: Any = events[int(m[1])]
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return False
        node = node[key]
    return node not in (None, "", [], {})
