"""evals/rulegen.py without models: alert selection, summary, re-grading, resume."""

from __future__ import annotations

import json

from evals import rulegen as rg
from sentinel.run import RunResult
from sentinel.schemas import ValidationResult

RULE = "title: t\nid: x\nlogsource: {category: process_creation, product: windows}\n"


def _row(outcome: str, **kw) -> dict:
    base = {
        "alert_id": "a",
        "outcome": outcome,
        "rule_yaml": RULE,
        "rulegen": {"title": "t", "technique_ids": ["T1003"], "schema_retries": 0},
        "validation": {"compiled": True, "fp_rate": 0.0},
        "validation_pending": outcome == "rule_unvalidated",
        "triage_techniques": ["T1003"],
    }
    return base | kw


def test_summary_counts_rules_and_keeps_unvalidated_out_of_pass_rate():
    rows = [
        _row("rule_unvalidated"),
        _row("rule_passed", validation={"compiled": True, "fp_rate": 0.02}),
        _row("rule_failed", validation={"compiled": True, "fp_rate": 0.2}),
        _row("rule_failed", rule_yaml=None, rulegen={"error": "no valid RuleDraft"}),
        _row("needs_review", rule_yaml=None, rulegen=None),
        {"alert_id": "z", "error": "transport: 429"},
    ]
    s = rg.summarize(rows)
    assert s["alerts"] == 6 and s["finished"] == 5
    assert s["rules_generated"] == 3 and s["generation_failures"] == 1
    assert s["compile_rate"] == 1.0
    assert s["validated"] == 2 and s["validation_pass_rate"] == 0.5
    assert s["median_fp_rate"] == 0.11
    assert s["outcomes"]["rule_unvalidated"] == 1


def test_summary_separates_first_attempt_from_after_repair():
    rows = [
        _row("rule_passed", validation={"compiled": True, "fp_rate": 0.0}, attempt_passes=[True]),
        _row(
            "rule_passed",
            validation={"compiled": True, "fp_rate": 0.0},
            attempt_passes=[False, True],
            repairs=[{"attempt": 2}],
        ),
    ]
    s = rg.summarize(rows)
    assert s["first_attempt_pass_rate"] == 0.5 and s["validation_pass_rate"] == 1.0
    assert s["repairs"] == 1


def test_nothing_validated_gives_no_pass_rate():
    s = rg.summarize([_row("rule_unvalidated")])
    assert s["validation_pass_rate"] is None and s["median_fp_rate"] is None


def test_uncovered_dev_attacks_reads_coverage(tmp_path, monkeypatch):
    cov = tmp_path / "coverage.json"
    rows = [
        {"alert_id": "d1", "covering_rule_id": None},
        {"alert_id": "d2", "covering_rule_id": "r"},
        {"alert_id": "t1", "covering_rule_id": None},
        {"alert_id": "d3", "covering_rule_id": None},
    ]
    cov.write_text(json.dumps({"rows": rows}), encoding="utf-8")
    monkeypatch.setattr(rg, "COVERAGE", cov)
    monkeypatch.setattr(rg, "load_split", lambda name: (["d3", "d2", "d1"], "sha"))
    assert rg.uncovered_dev_attacks(5) == ["d1", "d3"]
    assert rg.uncovered_dev_attacks(1) == ["d1"]


def test_regrade_uses_the_validator_without_model_calls(monkeypatch):
    def fake(rule_yaml, alert, techniques):
        assert techniques == ["T1003"]
        return ValidationResult(
            rule_id="x", compiled=True, true_positives=1, false_positives=0, fp_rate=0.0,
            feedback="",
        )  # fmt: skip

    monkeypatch.setattr(rg.validate_module, "validate", fake)
    row = rg.regrade(_row("rule_unvalidated"), alert=None)
    assert row["outcome"] == "rule_passed" and row["validation_pending"] is False


def test_regrade_keeps_rows_while_no_validator_exists(monkeypatch):
    def not_implemented(*args):
        raise NotImplementedError("validator not implemented yet")

    monkeypatch.setattr(rg.validate_module, "validate", not_implemented)
    row = _row("rule_unvalidated")
    assert rg.regrade(row, alert=None) == row


def test_resume_skips_finished_alerts(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "RESULTS", tmp_path)
    monkeypatch.setattr(rg, "uncovered_dev_attacks", lambda n: ["a1", "a2"])
    labels = [
        {"alert_id": a, "label": "true_positive", "technique_ids": ["T1003"]} for a in ("a1", "a2")
    ]
    monkeypatch.setattr(rg, "load_golden", lambda: (labels, {"a1": None, "a2": None}))
    calls = []

    def fake_run(alert, trace, name=None):
        calls.append(alert)
        return {"outcome": "rule_unvalidated", "rule_yaml": RULE, "rulegen": {"title": "t"}}

    monkeypatch.setattr(rg, "run_one", fake_run)
    (tmp_path / "rulegen-v0.rows.jsonl").write_text(
        json.dumps({"alert_id": "a1", "outcome": "rule_unvalidated", "rule_yaml": RULE}) + "\n",
        encoding="utf-8",
    )
    rg.main(["--no-trace"])
    assert len(calls) == 1  # only a2 ran
    result = json.loads((tmp_path / "rulegen-v0.json").read_text(encoding="utf-8"))
    assert [r["alert_id"] for r in result["rows"]] == ["a1", "a2"]


def test_run_one_reads_the_pipeline_result(monkeypatch):
    from tests.test_rule_gen import VERDICT

    final = {
        "verdict": VERDICT,
        "outcome": "rule_unvalidated",
        "draft_rule": RULE,
        "rulegen": {"title": "t"},
        "validations": [
            ValidationResult(
                rule_id="x", compiled=True, true_positives=0, false_positives=0, fp_rate=0.0,
                feedback="NOT VALIDATED",
            )
        ],
        "validation_pending": True,
    }  # fmt: skip
    monkeypatch.setattr(rg, "run_alert", lambda *a, **k: RunResult(final, ["rule_gen"], None))
    row = rg.run_one(alert=None, trace=False)
    assert row["outcome"] == "rule_unvalidated" and row["validation_pending"]
    assert row["validation"]["feedback"] == "NOT VALIDATED"
    assert row["attempt_passes"] == [False]  # 0 FP, nothing to test on: needs review
    assert row["repairs"] == []
