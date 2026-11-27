"""Repair context: what the rule writer is told about a rule that failed validation.

The validator's report is our own text (counts, alert ids, rule fields; it never quotes event
values), so it goes in as is. Event values are attacker-written, so they are looked up through
`failed_samples[].event_ref` and quoted inside <UNTRUSTED> blocks (rule_gen.repair_section).

Only **benign** hits are shown with their values. Missed held-out attacks are named by count and
id in the report, never shown: the validator grades the next version on those same attacks, so
showing them would let the model copy their values into the rule and pass on the data it was
graded with (tuning on the test set). Benign values are shown because "do not fire on this" is
how a detection engineer tunes a noisy rule; the unlabeled pool noise check stays unseen and
catches a rule that only learned to dodge the shown events.

History (2026-11-27, gold-v2): every earlier version is shown with its score (repeats caught,
benign hits; counts only). With only the last version, repair over-corrected: a version that
caught every repeat but hit benign events was tightened into one that caught none (day3-087,
-164, -050, day2-008 in gold-v2-base), and the next repair started from the empty one.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import cache

import yaml

from sentinel.agents.rule_form import ALLOWED_FIELDS
from sentinel.agents.rule_gen import RepairContext
from sentinel.schemas import Event, ValidationResult

MAX_BENIGN_SHOWN = 5  # enough to write a filter for (3 until gold-v2: 10 hits, 3 shown)

EventLookup = Callable[[str], Event | None]


def score(result: ValidationResult) -> str:
    """One version's grade in counts: what repair may know about the held-out attacks."""
    missed = sum(1 for s in result.failed_samples if s.should_fire)
    n = result.true_positives + missed
    if not result.compiled or result.compile_errors:
        return "did not compile"
    caught = f"caught {result.true_positives}/{n} held-out repeats" if n else "no repeats to test"
    return f"{caught}, fired on {result.false_positives} benign events"


def build_repair_context(
    previous_rule: str,
    result: ValidationResult,
    attempt: int,
    max_attempts: int,
    lookup: EventLookup,
    versions: list[str] | None = None,
    validations: list[ValidationResult] | None = None,
) -> RepairContext:
    """`versions` / `validations`: every version so far (oldest first), shown as a history so the
    model can aim between a too-broad and a too-narrow one. Defaults to the previous one only."""
    category = (yaml.safe_load(previous_rule).get("logsource") or {}).get("category")
    fields = sorted(ALLOWED_FIELDS.get(category, ()))
    hits = []
    for s in result.failed_samples:
        if s.should_fire or len(hits) == MAX_BENIGN_SHOWN:
            continue
        event = lookup(s.event_ref)
        if event is None:
            continue
        values = {f: str(event.raw[f]) for f in fields if event.raw.get(f) not in (None, "")}
        hits.append((s.sample_id, values))
    history = tuple(
        (i, _detection(rule), score(v))
        for i, (rule, v) in enumerate(zip(versions or [], validations or [], strict=False), start=1)
    )
    return RepairContext(
        attempt=attempt,
        max_attempts=max_attempts,
        previous_rule=previous_rule,
        report=result.feedback,
        benign_hits=tuple(hits),
        history=history if len(history) > 1 else (),
    )


def _detection(rule_yaml: str) -> str:
    """The detection block only: the part that changes between versions."""
    try:
        detection = yaml.safe_load(rule_yaml).get("detection") or {}
    except (yaml.YAMLError, AttributeError):
        return rule_yaml
    return yaml.safe_dump({"detection": detection}, sort_keys=False, allow_unicode=True)


def default_event_lookup(ref: str) -> Event | None:
    return _golden_events().get(ref)


@cache
def _golden_events() -> dict[str, Event]:
    """event_ref -> event for the validator's golden corpus (same format as validate._failed)."""
    from sentinel.validation import validate

    return {
        f"golden:{s.alert_id}/{s.event.event_id}": s.event for s in validate.default_corpus().golden
    }
