"""Guard for retrieval probe set v3: built from golden alerts that are in neither triage split."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PROBES = yaml.safe_load((ROOT / "evals" / "retrieval_probes_v3.yaml").read_text(encoding="utf-8"))[
    "probes"
]
LABELS = {
    r["alert_id"]: r
    for r in map(
        json.loads, (ROOT / "data/golden/v1.1.jsonl").read_text(encoding="utf-8").splitlines()
    )
}
SPLIT = json.loads((ROOT / "data/golden/split-v1.json").read_text(encoding="utf-8"))


def test_thirty_unique_probes():
    assert len(PROBES) == 30
    assert len({p["id"] for p in PROBES}) == 30
    assert len({p["query"] for p in PROBES}) == 30


def test_sources_are_outside_dev_and_test():
    sealed = set(SPLIT["dev"]) | set(SPLIT["test"])
    leaked = [p["source"] for p in PROBES if p["source"] in sealed]
    assert not leaked, f"probe sources in a triage split: {leaked}"


def test_expected_ids_are_the_golden_labels():
    for p in PROBES:
        row = LABELS[p["source"]]
        assert row["label"] == "true_positive", p["id"]
        assert sorted(p["expected"]) == sorted(row["technique_ids"]), p["id"]


def test_probes_are_frozen():
    """Content hash of the parsed probes (line endings can't break it). A failure means someone
    edited a frozen query or expected ID: revert it and add a dated note instead."""
    import hashlib

    frozen = (ROOT / "evals" / "retrieval_probes_v3.sha256").read_text(encoding="utf-8").split()[0]
    actual = hashlib.sha256(json.dumps(PROBES, sort_keys=True).encode()).hexdigest()
    assert actual == frozen
