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
