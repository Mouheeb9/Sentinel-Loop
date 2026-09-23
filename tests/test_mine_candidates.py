"""Selector logic and spec hygiene for the golden-set batch builder (no raw captures needed)."""

import json
from pathlib import Path

import pytest
import yaml

from evals.check_labels import TechniqueIndex
from evals.mine_candidates import SPEC, kind_of, matches, to_label_row
from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.retrieval.attack import DEFAULT_BUNDLE

FIXTURES = Path(__file__).parent / "fixtures" / "sysmon"
LABELS = {"true_positive", "benign_noisy", "needs_review"}


def _event(name: str):
    return sysmon_to_event(json.loads((FIXTURES / name).read_text()))


def _items():
    spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
    return [(ds["name"], it) for ds in spec["datasets"] for it in ds["items"]]


# --- selectors ---------------------------------------------------------------------------------


def test_selector_matches_on_kind_and_case_insensitive_regex():
    mshta = _event("t1218_005_mshta.json")
    assert kind_of(mshta) == "process"
    assert matches(mshta, {"kind": "process", "image": r"MSHTA\.exe$"})
    assert not matches(mshta, {"kind": "registry", "image": r"mshta\.exe$"})  # wrong kind
    assert not matches(mshta, {"kind": "process", "image": r"^nothing$"})


def test_selector_can_match_registry_keys_and_needs_every_field_to_match():
    eventlog_key = _event("t1562_002_disable_eventlog.json")
    assert kind_of(eventlog_key) == "registry"
    assert matches(eventlog_key, {"kind": "registry", "key": r"EventLog.Start"})
    assert not matches(eventlog_key, {"kind": "registry", "key": r"EventLog.Start", "image": "x$"})


def test_process_is_the_default_kind():
    assert matches(_event("t1218_005_mshta.json"), {"image": "mshta"})


# --- the spec itself ---------------------------------------------------------------------------


def test_spec_items_are_well_formed():
    items = _items()
    assert len(items) > 50
    for name, it in items:
        where = f"{name}: {it['match']}"
        assert it["label"] in LABELS, where
        assert it["match"], where
        assert it["why"].strip(), where
        # only true positives carry technique IDs, and they carry at least one
        assert bool(it.get("technique")) == (it["label"] == "true_positive"), where
        assert len(it["why"]) < 260, f"rationale should be one short sentence: {where}"


def test_spec_dataset_names_are_unique():
    names = [ds["name"] for ds in yaml.safe_load(SPEC.read_text(encoding="utf-8"))["datasets"]]
    assert len(names) == len(set(names))


@pytest.mark.skipif(not DEFAULT_BUNDLE.exists(), reason="ATT&CK bundle not downloaded")
def test_spec_only_uses_live_attack_techniques():
    index = TechniqueIndex()
    for name, it in _items():
        for tid in it.get("technique", []):
            problem = index.problem_for("spec", tid)
            assert problem is None, f"{name}: {problem.message() if problem else ''}"


def test_label_row_follows_the_documented_row_format():
    item = {
        "alert_id": "day3-999",
        "label": "true_positive",
        "techniques": ["T1003.001"],
        "dataset": "some_capture",
        "why": "Because.",
    }
    row = to_label_row(item)
    assert list(row) == [
        "alert_id",
        "label",
        "technique_ids",
        "source_dataset",
        "rationale",
        "labeler",
        "labeled_at",
    ]
    assert row["source_dataset"] == "some_capture.zip"
    assert row["labeler"] == "claude-draft"
