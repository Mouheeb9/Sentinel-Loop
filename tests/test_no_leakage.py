"""Guard: no raw capture may be used for both triage scoring and rule validation.

`data/golden/v1.jsonl` scores the triage agent. `data/validation/validation_datasets.txt` is a
held-out pool used only to check whether a generated Sigma rule fires correctly. If the same
capture appeared in both, a rule "validated" against it would really just be checked against the
answer key the agent was scored on, and the validation number would mean nothing.

See data/validation/README.md for the split rule.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_V1 = ROOT / "data" / "golden" / "v1.jsonl"
VALIDATION_LIST = ROOT / "data" / "validation" / "validation_datasets.txt"


def _golden_source_datasets() -> set[str]:
    return {
        json.loads(line)["source_dataset"]
        for line in GOLDEN_V1.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def _validation_source_datasets() -> set[str]:
    return {
        line.strip()
        for line in VALIDATION_LIST.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def test_golden_and_validation_pools_do_not_overlap():
    golden = _golden_source_datasets()
    validation = _validation_source_datasets()
    overlap = golden & validation

    assert not overlap, (
        "these source_dataset zips are in BOTH the golden pool and the validation pool -- "
        "a rule validated against them would be graded on the triage answer key:\n"
        + "\n".join(sorted(overlap))
    )


def test_validation_pool_is_non_empty():
    assert _validation_source_datasets(), "validation_datasets.txt is empty"


def test_validator_never_counts_the_source_capture_as_positive():
    """A rule that fires on every process_creation event, graded for each golden attack: none of
    its positives (hits or misses) may come from the source alert's own capture."""
    from sentinel.schemas import Alert
    from sentinel.validation.validate import Corpus, _relation, default_corpus, grade

    rule = (
        "title: everything\nid: 00000000-0000-4000-8000-000000000001\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n  sel:\n    Image|contains: ['.exe']\n  condition: sel\n"
    )
    golden = Corpus(golden=default_corpus().golden)  # no pool: CI has no captures
    by_alert = {s.alert_id: s for s in golden.golden}
    checked = 0
    for s in golden.golden:
        if s.label != "true_positive" or str(s.event.raw.get("EventID")) != "1":
            continue
        alert = Alert(alert_id=s.alert_id, detection_name="x", severity="high", events=[s.event])
        r = grade(rule, alert, list(s.technique_ids), golden)
        refs = {f.sample_id for f in r.failed_samples}
        assert all(by_alert[a].capture != s.capture for a in refs)
        same_capture = [
            o
            for o in golden.golden
            if o.capture == s.capture
            and o.alert_id != s.alert_id
            and o.label == "true_positive"
            and set(o.technique_ids) & set(s.technique_ids)
            and str(o.event.raw.get("EventID")) == "1"
        ]
        claimed = {t.upper() for t in s.technique_ids}
        held_out = [
            o
            for o in golden.golden
            if o.capture != s.capture
            and o.label == "true_positive"
            and _relation(claimed, o.technique_ids) == "same"
            and str(o.event.raw.get("EventID")) == "1"
        ]
        assert r.true_positives == len(held_out)  # fires on all: only held-out ones are counted
        checked += bool(same_capture)
    assert checked, "no golden capture holds two same-technique attacks: test proves nothing"
