"""evals/run.py without a model: run_alert is faked, results go to a temp dir."""

from __future__ import annotations

import json

import pytest

from evals import run as ev
from evals.scorers import AttackMap
from sentinel.agents.triage import TriageError
from sentinel.graph import nodes
from sentinel.run import RunResult
from sentinel.schemas import Alert, TriageVerdict

ALERT = {
    "alert_id": "a-1",
    "detection_name": "test",
    "severity": "medium",
    "events": [
        {
            "event_id": "e-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "source": "windows_sysmon",
            "host": "WS1",
            "process": {"image": "cmd.exe", "command_line": "cmd /c whoami"},
            "raw": {},
            "untrusted_fields": [],
        }
    ],
}


def _alerts(n: int) -> tuple[list[dict], dict[str, Alert]]:
    labels, alerts = [], {}
    for i in range(n):
        a = Alert.model_validate(ALERT | {"alert_id": f"a-{i}"})
        alerts[a.alert_id] = a
        labels.append(
            {"alert_id": a.alert_id, "label": "true_positive", "technique_ids": ["T1033"]}
        )
    return labels, alerts


def _ok(alert, **kw) -> RunResult:
    v = TriageVerdict(
        verdict="true_positive",
        confidence=0.9,
        technique_ids=["T1033"],
        reasoning="whoami",
        evidence_refs=["events[0].process.command_line"],
        ioc_refs=["cmd /c whoami"],
    )
    final = {"verdict": v, "triage_tier": 1, "triage_cost_usd": 0.0, "triage_runs": []}
    return RunResult(final=final, path=[], trace_url=None)


@pytest.fixture
def tmp_results(tmp_path, monkeypatch):
    monkeypatch.setattr(ev, "RESULTS", tmp_path)
    monkeypatch.setattr(ev, "PAUSE_S", 0)
    return tmp_path


def _rows(config: str) -> list[dict]:
    lines = ev.rows_path(config).read_text(encoding="utf-8").splitlines()
    return [json.loads(x) for x in lines[1:]]


def test_rows_follow_the_scorer_contract(tmp_results, monkeypatch):
    monkeypatch.setattr(ev, "run_alert", _ok)
    labels, alerts = _alerts(2)
    assert ev.run_config("rag", labels, alerts, trace=False, fresh=False)
    rows = _rows("rag")
    assert [r["row"]["alert_id"] for r in rows] == ["a-0", "a-1"]
    assert rows[0]["row"]["verdict"] == "true_positive" and rows[0]["row"]["tier"] == 1
    assert {"git_sha", "git_dirty", "at"} <= rows[0]["detail"].keys()

    attack = AttackMap(tactics={"T1033": frozenset({"discovery"})})
    result = ev.write_results("rag", labels, alerts, attack)
    assert result["scores"]["triage"]["accuracy"] == 1.0
    assert result["meta"]["complete"] is True
    assert result["meta"]["prompt_sha"] == ev.prompt_hash(ev.CONFIGS["rag"])


def test_resume_keeps_answers_and_schema_errors_retries_transport(tmp_results, monkeypatch):
    labels, alerts = _alerts(3)
    outcomes = iter([_ok, TriageError("bad"), RuntimeError("503 overloaded")])

    def flaky(alert, **kw):
        o = next(outcomes)
        if isinstance(o, Exception):
            raise o
        return o(alert)

    monkeypatch.setattr(ev, "run_alert", flaky)
    ev.run_config("rag", labels, alerts, trace=False, fresh=False)
    calls = []
    monkeypatch.setattr(
        ev, "run_alert", lambda alert, **kw: calls.append(alert.alert_id) or _ok(alert)
    )
    ev.run_config("rag", labels, alerts, trace=False, fresh=False)
    assert calls == ["a-2"]  # a-0 answered, a-1 schema error is a real outcome
    errors = {r["row"]["alert_id"]: r["row"]["error"] for r in _rows("rag")}
    assert errors["a-1"].startswith("schema") and errors["a-2"] is None


def test_changed_setup_starts_over(tmp_results, monkeypatch):
    monkeypatch.setattr(ev, "run_alert", _ok)
    labels, alerts = _alerts(2)
    ev.run_config("rag", labels, alerts, trace=False, fresh=False)
    monkeypatch.setenv("SENTINEL_ESCALATE_BELOW", "0.42")  # part of the fingerprint
    calls = []
    monkeypatch.setattr(ev, "run_alert", lambda alert, **kw: calls.append(1) or _ok(alert))
    ev.run_config("rag", labels, alerts, trace=False, fresh=False)
    assert len(calls) == 2


def test_daily_quota_stops_the_run(tmp_results, monkeypatch):
    def quota(alert, **kw):
        raise RuntimeError("Rate limit exceeded: free-models-per-day")

    monkeypatch.setattr(ev, "run_alert", quota)
    labels, alerts = _alerts(5)
    assert ev.run_config("rag", labels, alerts, trace=False, fresh=False) is False
    assert len(_rows("rag")) == 1

    attack = AttackMap(tactics={})
    meta = ev.write_results("rag", labels, alerts, attack)["meta"]
    assert meta["complete"] is False and meta["transport_errors"] == 1


def test_configs_differ_only_in_what_they_switch_off():
    assert ev.CONFIGS["single-prompt"] == nodes.PipelineOptions(retrieval=False, tools=False)
    assert ev.CONFIGS["rag-tools"] == nodes.PipelineOptions()
    hashes = {ev.prompt_hash(o) for o in ev.CONFIGS.values()}
    assert len(hashes) == 3


def test_retrieval_off_skips_the_database(monkeypatch):
    def boom(alert):
        raise AssertionError("retrieval must not run")

    monkeypatch.setattr(nodes, "enrich_alert", boom)
    config = {"configurable": {"pipeline": nodes.PipelineOptions(retrieval=False)}}
    assert nodes.enrich_live({"alert": None}, config) == {"techniques": [], "sigma_rules": []}


def test_tools_off_reaches_triage(monkeypatch):
    seen = {}

    def fake(alert, techniques, rules, config, *, use_tools):
        seen["use_tools"] = use_tools
        raise StopIteration

    monkeypatch.setattr(nodes, "triage_routed", fake)
    config = {"configurable": {"pipeline": nodes.PipelineOptions(tools=False)}}
    with pytest.raises(StopIteration):
        nodes.triage_live({"alert": None}, config)
    assert seen == {"use_tools": False}
