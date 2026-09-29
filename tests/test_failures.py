"""evals/failures.py on hand-made results: what counts as a failure, and the pre-sort hints."""

from __future__ import annotations

from evals import failures as fl
from evals.scorers import AttackMap
from sentinel.schemas import Alert

ATTACK = AttackMap(
    tactics={
        "T1059": frozenset({"execution"}),
        "T1059.001": frozenset({"execution"}),
        "T1059.005": frozenset({"execution"}),
        "T1003.001": frozenset({"credential-access"}),
        "T1547.001": frozenset({"persistence"}),
    }
)


def _row(alert_id: str, **kw) -> dict:
    return {
        "config": "rag",
        "alert_id": alert_id,
        "label": "true_positive",
        "label_techniques": ["T1059.001"],
        "verdict": "true_positive",
        "confidence": 0.9,
        "technique_ids": ["T1059.001"],
        "latency_s": 1.0,
    } | kw


def _result(rows: list[dict], retrieved: dict[str, list[str]], retrieval: bool = True) -> dict:
    return {
        "meta": {"retrieval": retrieval},
        "rows": rows,
        "details": {a: {"retrieved_techniques": t} for a, t in retrieved.items()},
    }


LABELS = {
    "ok": {"label": "true_positive", "technique_ids": ["T1059.001"], "labeler": "Mouadh"},
    "miss": {"label": "true_positive", "technique_ids": ["T1003.001"], "labeler": "Mouadh"},
    "reason": {"label": "true_positive", "technique_ids": ["T1059.001"], "labeler": "claude-draft"},
    "parent": {"label": "true_positive", "technique_ids": ["T1059.001"], "labeler": "Mouadh"},
    "schema": {"label": "benign_noisy", "technique_ids": [], "labeler": "Mouadh"},
    "net": {"label": "benign_noisy", "technique_ids": [], "labeler": "Mouadh"},
}


def test_failures_and_hints():
    rows = [
        _row("ok"),
        _row("miss", technique_ids=["T1059.001"]),
        _row("reason", verdict="benign_noisy", technique_ids=[]),
        _row("parent", technique_ids=["T1059"]),
        _row("schema", verdict=None, confidence=None, technique_ids=[], error="schema: bad"),
        _row("net", verdict=None, confidence=None, technique_ids=[], error="transport: 429"),
    ]
    retrieved = {
        "ok": ["T1059.001"],
        "miss": ["T1059.001", "T1547.001"],
        "reason": ["T1547.001", "T1059.001"],
        "parent": ["T1059.005"],  # only a sibling: same parent counts as retrieved
    }
    failures, transport = fl.find_failures(_result(rows, retrieved), LABELS, ATTACK)
    by_id = {f.row.alert_id: f for f in failures}

    assert transport == 1 and set(by_id) == {"miss", "reason", "parent", "schema"}
    assert by_id["miss"].hint.startswith("retrieval miss?") and "T1003.001" in by_id["miss"].hint
    assert by_id["reason"].hint == "reasoning error?" and by_id["reason"].draft_label
    assert by_id["parent"].hint == "reasoning error?" and by_id["parent"].technique_credit == 0.5
    assert by_id["schema"].hint == "schema error"
    assert by_id["reason"].reasons == [
        "verdict benign_noisy != true_positive",
        "technique credit 0.00",
    ]


def test_current_labels_win_over_the_row():
    """A label fixed after the run: the row that 'failed' against the old label drops out."""
    row = _row("reason", verdict="benign_noisy", technique_ids=[])
    fixed = {"reason": {"label": "benign_noisy", "technique_ids": [], "labeler": "Mouadh"}}
    failures, _ = fl.find_failures(_result([row], {"reason": []}), fixed, ATTACK)
    assert failures == []


def test_single_prompt_gets_no_retrieval_hint():
    row = _row("miss", technique_ids=["T1059.001"])
    failures, _ = fl.find_failures(_result([row], {}, retrieval=False), LABELS, ATTACK)
    assert [f.hint for f in failures] == ["(no retrieval)"]


def test_card_renders_event_label_and_bucket_line():
    alert = Alert.model_validate(
        {
            "alert_id": "reason",
            "detection_name": "test",
            "severity": "medium",
            "events": [
                {
                    "event_id": "e-1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "source": "windows_sysmon",
                    "host": "WS1",
                    "process": {"image": "powershell.exe", "command_line": "x" * 1000},
                    "raw": {},
                    "untrusted_fields": [],
                }
            ],
        }
    )
    row = _row("reason", verdict="benign_noisy", technique_ids=[])
    [f] = fl.find_failures(_result([row], {"reason": ["T1059.001"]}), LABELS, ATTACK)[0]
    card = fl.render_card(f, alert, LABELS["reason"])
    assert "**bucket:**" in card and "[draft label]" in card
    assert "powershell.exe" in card and "(+400)" in card  # long command lines are clipped
