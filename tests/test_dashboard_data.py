"""Dashboard data (stored results only): loop summary, attempts, and the trace-link guard."""

from __future__ import annotations

import json

from sentinel import dashboard_data as dd


def _rows(tmp_path, rows, name="loop-x"):
    path = tmp_path / f"{name}.rows.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return path


def test_loop_runs_and_summary(tmp_path):
    _rows(tmp_path, [{"fingerprint": 1}, {"alert_id": "a", "verdict": "x"}], name="triage-only")
    _rows(
        tmp_path,
        [
            {"alert_id": "a", "rule_yaml": "y", "outcome": "rule_passed", "attempt_passes": [True]},
            {"alert_id": "b", "rule_yaml": "y", "outcome": "rule_passed",
             "attempt_passes": [False, True]},
            {"alert_id": "c", "outcome": "benign"},
        ],
    )  # fmt: skip
    runs = dd.loop_runs(tmp_path)
    assert list(runs) == ["loop-x"]  # the triage-only file has no rule
    s = dd.loop_summary(dd.load_rows(runs["loop-x"]))
    assert (s["alerts"], s["rules"], s["pass_first_try"], s["pass_after_repair"]) == (3, 2, 1, 2)


def test_attempts_with_and_without_recalls():
    old = dd.attempts({"attempt_passes": [False, True]})
    assert old[1] == {"attempt": 2, "passed": True, "recall": None, "benign_hits": None}
    new = dd.attempts({"attempt_passes": [False], "attempt_recalls": [0.5], "attempt_fps": [1]})
    assert new == [{"attempt": 1, "passed": False, "recall": 0.5, "benign_hits": 1}]


def test_trace_link_only_to_langfuse():
    assert dd.trace_url({"trace": "https://cloud.langfuse.com/project/p/traces/t"})
    assert dd.trace_url({"trace": "javascript:alert(1)"}) is None
    assert dd.trace_url({"trace": "https://evil.example/cloud.langfuse.com/"}) is None
