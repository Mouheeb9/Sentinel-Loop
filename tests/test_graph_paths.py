from datetime import UTC, datetime

import pytest
from langgraph.errors import GraphRecursionError

from sentinel.graph.build import build_graph
from sentinel.graph.nodes import StubScript
from sentinel.schemas import Alert, Event

HEAD = ["ingest", "enrich", "triage", "route"]


def _alert():
    event = Event(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        source="windows_sysmon",
        host="host-1",
        raw={},
        untrusted_fields=[],
    )
    return Alert(alert_id="a-1", detection_name="test", severity="low", events=[event])


def _run(script):
    config = {"configurable": {"stub": script}}
    graph = build_graph()
    path = [
        node
        for step in graph.stream({"alert": _alert()}, config, stream_mode="updates")
        for node in step
    ]
    return path, graph.invoke({"alert": _alert()}, config)


@pytest.mark.parametrize(
    ("script", "expected_path", "outcome", "n_validations"),
    [
        (StubScript(verdict="benign_noisy"), HEAD + ["output"], "benign", 0),
        (StubScript(verdict="needs_review"), HEAD + ["output"], "needs_review", 0),
        (StubScript(covering_rule_id="sigma-123"), HEAD + ["output"], "covered", 0),
        (StubScript(), HEAD + ["rule_gen", "validate", "output"], "rule_passed", 1),
        (
            StubScript(validation_passes=(False, False, True)),
            HEAD + ["rule_gen", "validate", "repair", "validate", "repair", "validate", "output"],
            "rule_passed",
            3,
        ),
        (
            StubScript(validation_passes=(False,)),
            HEAD + ["rule_gen", "validate", "repair", "validate", "repair", "validate", "output"],
            "rule_failed",
            3,
        ),
    ],
    ids=["benign", "needs_review", "covered", "pass_first_try", "pass_third_try", "give_up"],
)
def test_paths(script, expected_path, outcome, n_validations):
    path, final = _run(script)
    assert path == expected_path
    assert final["outcome"] == outcome
    assert len(final.get("validations", [])) == n_validations


def test_benign_verdict_with_coverage_is_still_benign():
    _, final = _run(StubScript(verdict="benign_noisy", covering_rule_id="sigma-123"))
    assert final["outcome"] == "benign"


def test_runaway_loop_fails_loudly(monkeypatch):
    # Simulate a wiring bug: the attempt cap never triggers, so repair loops forever.
    monkeypatch.setattr("sentinel.graph.build.MAX_ATTEMPTS", 10**6)
    with pytest.raises(GraphRecursionError):
        _run(StubScript(validation_passes=(False,)))
