from datetime import UTC, datetime

from langgraph.graph import END, START, StateGraph

from sentinel.graph.state import SentinelState
from sentinel.schemas import Alert, Event, ValidationResult


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


def _validation(n):
    return ValidationResult(
        rule_id="r-1", compiled=True, true_positives=n, false_positives=0, fp_rate=0.0, feedback=""
    )


def test_validations_append_and_draft_rule_overwrites():
    def first(state):
        return {"draft_rule": "v1", "validations": [_validation(1)]}

    def second(state):
        return {"draft_rule": "v2", "validations": [_validation(2)]}

    g = StateGraph(SentinelState)
    g.add_node("first", first)
    g.add_node("second", second)
    g.add_edge(START, "first")
    g.add_edge("first", "second")
    g.add_edge("second", END)

    out = g.compile().invoke({"alert": _alert()})

    assert out["draft_rule"] == "v2"
    assert [v.true_positives for v in out["validations"]] == [1, 2]
