"""Demo recordings (sentinel/demo.py): stub pipeline only, no database, no model."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import demo
from sentinel.graph.nodes import StubScript
from sentinel.schemas import Alert

ALERT = Alert.model_validate_json(
    (Path(__file__).parent / "fixtures" / "alerts" / "day2-001.json").read_text(encoding="utf-8")
)


def _record(**stub) -> dict:
    return demo.record(ALERT, "t", live=False, stub=StubScript(**stub))


def test_one_event_per_node_in_path_order():
    rec = _record(validation_passes=(False, True))  # fail once -> repair -> pass
    nodes = [e["node"] for e in rec["events"]]
    assert nodes == rec["meta"]["path"]
    assert nodes[:4] == ["ingest", "enrich", "triage", "route"] and nodes[-1] == "output"
    assert "repair" in nodes and nodes.count("validate") == 2


def test_timings_are_ordered():
    events = _record()["events"]
    assert all(e["start"] <= e["end"] for e in events)
    assert all(a["end"] <= b["start"] + 1e-9 for a, b in zip(events, events[1:], strict=False))


def test_recording_is_plain_json():
    rec = _record()
    assert json.loads(json.dumps(rec)) == rec  # pydantic models were turned into dicts
    triage = next(e for e in rec["events"] if e["node"] == "triage")
    assert triage["update"]["verdict"]["verdict"] == "true_positive"


def test_benign_stops_after_route():
    rec = _record(verdict="benign_noisy")
    assert rec["meta"]["path"] == ["ingest", "enrich", "triage", "route", "output"]


def test_on_event_sees_each_event_as_it_happens():
    seen = []
    rec = demo.record(ALERT, "t", live=False, stub=StubScript(), on_event=seen.append)
    assert seen == rec["events"]


def test_save_load_and_list(tmp_path):
    rec = _record()
    path = demo.save(rec, tmp_path)
    assert demo.load(path) == rec
    assert demo.recordings(tmp_path) == {"t": path}
    (tmp_path / "junk.json").write_text("{}")
    with pytest.raises(ValueError):
        demo.load(tmp_path / "junk.json")


def test_find_alert(tmp_path):
    src = tmp_path / "c.json"
    src.write_text(json.dumps([{"alert": ALERT.model_dump(mode="json")}]))
    assert demo.find_alert(ALERT.alert_id, (src,)).alert_id == ALERT.alert_id
    with pytest.raises(SystemExit):
        demo.find_alert("nope", (src,))


def test_lookup_answers_come_from_the_tool_cache():
    from sentinel.tools.cache import MemoryToolCache

    cache = MemoryToolCache()
    cache.put("threatfox_ioc_lookup", "45.137.22.10", {"found": True, "malware": "AsyncRAT"})
    ev = {
        "node": "triage",
        "update": {
            "triage_runs": [
                {
                    "lookups": [
                        {"name": "threatfox_ioc_lookup", "args": {"ioc": "45.137.22.10"}},
                        {"name": "threatfox_ioc_lookup", "args": {"ioc": "13.107.4.50"}},
                    ]
                }
            ]
        },
    }
    looks = demo.attach_lookup_answers(ev, cache)["update"]["triage_runs"][0]["lookups"]
    assert looks[0]["answer"]["malware"] == "AsyncRAT" and looks[1]["answer"] is None
    assert demo.attach_lookup_answers({"node": "route"}, cache) == {"node": "route"}


EDGES = demo.graph_edges()


def test_graph_edges_are_the_real_pipeline():
    assert ("route", "rule_gen") in EDGES and ("validate", "repair") in EDGES
    assert ("repair", "validate") in EDGES and ("__start__", "ingest") in EDGES


def test_graph_before_any_event_is_all_idle():
    dot = demo.graph_dot([], None, EDGES)
    assert demo.OK not in dot and dot.startswith("digraph")


def test_graph_lights_the_running_node_and_counts_loops():
    rec = _record(validation_passes=(False, False, True))  # two repairs
    dot = demo.graph_dot(rec["events"][:3], "route", EDGES)
    assert f'route [fillcolor="{demo.BUSY}"' in dot
    full = demo.graph_dot(rec["events"], None, EDGES)
    assert 'validate -> repair [color="#16a34a" penwidth=2.6 label=" x2"' in full
    assert "route -> output" in full and "dashed" in full  # the branch not taken stays grey


def test_graph_marks_a_failed_rule_red():
    rec = _record(validation_passes=(False,))  # fails every time, runs out of attempts
    assert f'validate [fillcolor="{demo.BAD}"' in demo.graph_dot(rec["events"], None, EDGES)


def test_lookup_rows_summarize_threatfox_and_nvd():
    tf = {
        "found": True,
        "results": [
            {"malware_printable": "AsyncRAT", "threat_type": "botnet_cc", "confidence_level": 100}
        ],
    }
    nvd = {
        "found": True,
        "cvss": {"severity": "CRITICAL", "base_score": 10.0},
        "cisa_known_exploited": True,
    }
    update = {
        "triage_runs": [
            {
                "tier": 1,
                "lookups": [
                    {"name": "threatfox_ioc_lookup", "args": {"ioc": "1.2.3.4"}, "answer": tf},
                    {
                        "name": "threatfox_ioc_lookup",
                        "args": {"ioc": "5.6.7.8"},
                        "answer": {"found": False},
                    },
                    {"name": "nvd_cve_lookup", "args": {"cve_id": "CVE-2020-0796"}, "answer": nvd},
                ],
            }
        ]
    }
    rows = demo.lookup_rows(update)
    assert rows[0]["answer"] == "listed: AsyncRAT, botnet_cc, confidence 100"
    assert rows[1]["answer"] == "not listed"
    assert rows[2]["answer"].startswith("CRITICAL 10.0") and "CISA" in rows[2]["answer"]


def test_demo_page_replays_a_recording(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    demo.save(_record(validation_passes=(False, True)) | {}, tmp_path)
    monkeypatch.setenv("SENTINEL_DEMO_DIR", str(tmp_path))
    page = Path(__file__).parent.parent / "app" / "demo.py"
    at = AppTest.from_file(str(page), default_timeout=30).run()
    assert not at.exception
    assert len(at.expander) == len(demo.load(tmp_path / "t.json")["events"])


def test_record_switches_key_on_daily_quota(monkeypatch):
    for n in [n for n in demo.os.environ if n.startswith(demo.KEY_VAR)]:
        monkeypatch.delenv(n)
    monkeypatch.setenv(demo.KEY_VAR, "k1")
    monkeypatch.setenv(demo.KEY_VAR + "_b", "k2")
    seen = []

    def fake(alert, name, **kw):
        seen.append(demo.os.environ[demo.KEY_VAR])
        if seen[-1] == "k1":
            raise RuntimeError("Rate limit exceeded: free-models-per-day")
        return {"ok": True}

    monkeypatch.setattr(demo, "record", fake)
    assert demo.record_with_key_switch(ALERT, "t") == {"ok": True} and seen == ["k1", "k2"]
    monkeypatch.setattr(demo, "record", lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))
    with pytest.raises(ValueError):  # not a quota error: no switching
        demo.record_with_key_switch(ALERT, "t")
