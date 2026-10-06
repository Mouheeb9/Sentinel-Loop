"""Validator v2 contract: procedures.yaml groups golden attacks by HOW, labels stay untouched."""

from __future__ import annotations

import json

import pytest

from sentinel.schemas import ValidationResult
from sentinel.validation.validate import GOLDEN_LABELS, load_procedures


def _labels() -> list[dict]:
    return [json.loads(x) for x in GOLDEN_LABELS.read_text(encoding="utf-8").splitlines() if x]


def test_procedures_file_matches_golden_labels():
    procedures = load_procedures(_labels())
    assert procedures["day2-006"] != procedures["day3-053"]  # same technique, other procedure
    assert procedures["day2-006"].startswith("T1685.001/")


def test_procedure_must_match_a_label(tmp_path):
    path = tmp_path / "procedures.yaml"
    path.write_text("day2-006: T1059.001/powershell\n", encoding="utf-8")
    with pytest.raises(ValueError, match="day2-006"):
        load_procedures(_labels(), path)


def test_v2_fields_default_so_v0_results_stay_valid():
    result = ValidationResult(
        rule_id="r", compiled=True, true_positives=0, false_positives=0, fp_rate=0.0, feedback=""
    )
    assert (result.evidence, result.procedure_recall, result.sibling_recall) == ("ok", None, None)
