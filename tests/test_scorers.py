"""Every scorer against a hand-built example whose right answer was worked out on paper.
A tiny AttackMap stands in for the ATT&CK bundle, so these run without data/raw/."""

from datetime import UTC, datetime

import pytest

from evals.eval_row import EvalRow
from evals.scorers import (
    AttackMap,
    cost_latency_scores,
    credit,
    hallucinated_iocs,
    ioc_scores,
    p95,
    schema_scores,
    score_all,
    technique_scores,
    triage_accuracy,
)
from sentinel.schemas import Alert, Event, ProcessInfo

ATTACK = AttackMap(
    tactics={
        "T1055": frozenset({"stealth", "privilege-escalation"}),
        "T1055.012": frozenset({"stealth", "privilege-escalation"}),
        "T1027": frozenset({"stealth"}),
        "T1003": frozenset({"credential-access"}),
        "T1003.001": frozenset({"credential-access"}),
        "T1685.001": frozenset({"stealth"}),
        "T1059.001": frozenset(),  # no own tactics: inherits T1059's
        "T1059": frozenset({"execution"}),
        "T1204": frozenset({"execution"}),
    },
    renames={"T1562.002": "T1685.001"},
)


def _row(**kw) -> EvalRow:
    base = {
        "config": "rag",
        "alert_id": "a-1",
        "label": "true_positive",
        "label_techniques": ["T1003.001"],
        "verdict": "true_positive",
        "confidence": 0.9,
        "technique_ids": ["T1003.001"],
        "latency_s": 1.0,
    }
    return EvalRow(**(base | kw))


def _err(**kw) -> EvalRow:
    return _row(verdict=None, confidence=None, technique_ids=[], error="transport: 429", **kw)


# --- credit: the labeling guide's worked example is test #1 ---------------------------------


@pytest.mark.parametrize(
    ("pred", "expected"),
    [
        ("T1055.012", 1.0),  # exact sub-technique
        ("T1055", 0.5),  # right parent, missed the method
        ("T1027", 0.25),  # right tactic (stealth, ex-Defense Evasion), wrong technique
        ("T1003", 0.0),  # wrong tactic entirely
    ],
)
def test_credit_labeling_guide_worked_example(pred, expected):
    assert credit(pred, "T1055.012", ATTACK) == expected


@pytest.mark.parametrize(
    ("pred", "gold", "expected"),
    [
        ("T1055.012", "T1055", 0.5),  # parent credit works in both directions
        ("T1003.001", "T1003.002", 0.5),  # sibling sub-techniques share the parent
        ("t1003.001 ", "T1003.001", 1.0),  # case and spaces don't matter
        ("T1562.002", "T1685.001", 1.0),  # old ATT&CK ID is renamed before comparing
        ("T1059.001", "T1204", 0.25),  # sub-technique inherits its parent's tactic
        ("T9999", "T1003", 0.0),  # unknown ID: no tactic, no credit
    ],
)
def test_credit_edge_cases(pred, gold, expected):
    assert credit(pred, gold, ATTACK) == expected


# --- technique precision / recall -----------------------------------------------------------


def test_technique_scores_hand_worked():
    rows = [
        _row(alert_id="a", label_techniques=["T1055.012"], technique_ids=["T1055.012"]),  # P1 R1
        _row(alert_id="b", label_techniques=["T1055.012"], technique_ids=["T1055", "T1003"]),
        # b: recall = best for gold = 0.5; precision = (0.5 + 0.0) / 2 = 0.25
        _row(alert_id="c", label_techniques=[], technique_ids=["T1027"]),  # P 0, no recall
        _row(alert_id="d", label_techniques=["T1003.001"], technique_ids=[]),  # R 0, no precision
        _row(alert_id="e", label="benign_noisy", label_techniques=[], technique_ids=[]),  # skipped
    ]
    s = technique_scores(rows, ATTACK)
    assert s["alerts_with_gold"] == 3 and s["alerts_with_pred"] == 3
    assert s["recall"] == pytest.approx((1 + 0.5 + 0) / 3)  # 0.5
    assert s["precision"] == pytest.approx((1 + 0.25 + 0) / 3)  # 0.41667
    p, r = (1.25 / 3), 0.5
    assert s["f1"] == pytest.approx(2 * p * r / (p + r))
    assert s["primary_exact_rate"] == pytest.approx(1 / 3)  # only "a" has the exact primary


def test_error_row_gets_recall_zero_even_with_techniques_left_over():
    row = _row(technique_ids=["T1003.001"], error="schema: bad json")
    s = technique_scores([row], ATTACK)
    assert s["recall"] == 0.0 and s["precision"] is None


# --- triage accuracy ------------------------------------------------------------------------


def test_triage_accuracy_counts_errors_as_wrong():
    rows = [
        _row(),  # TP -> TP, correct
        _row(verdict="benign_noisy"),  # TP -> benign: a missed attack
        _row(label="benign_noisy", verdict="benign_noisy"),  # correct
        _err(),  # TP -> error: wrong, not skipped
    ]
    s = triage_accuracy(rows)
    assert s["n"] == 4 and s["accuracy"] == 0.5
    assert s["missed_attacks"] == 1
    assert s["confusion"]["true_positive"]["error"] == 1
    assert s["per_class_recall"] == {
        "true_positive": pytest.approx(1 / 3),
        "benign_noisy": 1.0,
        "needs_review": None,  # no gold needs_review rows: undefined, not 0
    }


# --- hallucinated IOCs ----------------------------------------------------------------------


def _alert(alert_id="a-1") -> Alert:
    event = Event(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        source="windows_sysmon",
        host="WS01",
        process=ProcessInfo(
            image="C:\\Users\\Pedro\\Downloads\\payload.exe",
            command_line="payload.exe -connect 203.0.113.7",
        ),
        raw={"Hashes": "SHA256=ABCDEF0123"},
        untrusted_fields=["process.command_line"],
    )
    return Alert(alert_id=alert_id, detection_name="t", severity="high", events=[event])


def test_hallucinated_iocs_real_invented_and_slash_case():
    iocs = [
        "203.0.113.7",  # real, verbatim
        "c:/users/pedro/downloads/PAYLOAD.EXE",  # real: differs only in slashes and case
        "sha256=abcdef0123",  # real: only in raw, still part of the input event
        "evil.example.com",  # invented
    ]
    assert hallucinated_iocs(iocs, _alert()) == ["evil.example.com"]


def test_ioc_scores_rate_over_all_iocs():
    alerts = {"a-1": _alert("a-1"), "a-2": _alert("a-2")}
    rows = [
        _row(alert_id="a-1", ioc_refs=["203.0.113.7", "10.9.9.9"]),  # 1 of 2 invented
        _row(alert_id="a-2", ioc_refs=["WS01"]),  # host name: real
        _err(alert_id="a-2", ioc_refs=["made-up"]),  # error row: its IOCs are ignored
    ]
    s = ioc_scores(rows, alerts)
    assert (s["iocs_total"], s["iocs_hallucinated"]) == (3, 1)
    assert s["hallucinated_ioc_rate"] == pytest.approx(1 / 3)
    assert s["alerts_with_hallucination"] == 1
    assert s["examples"] == [{"alert_id": "a-1", "iocs": ["10.9.9.9"]}]


# --- schema, cost, latency ------------------------------------------------------------------


def test_schema_scores():
    rows = [_row(), _row(schema_retries=1), _err(), _row()]
    s = schema_scores(rows)
    assert s == {"schema_valid_rate": 0.75, "first_try_rate": 0.5, "errors": 1}


def test_p95_nearest_rank():
    assert p95(range(1, 21)) == 19  # ceil(0.95*20) = 19th smallest
    assert p95([5.0]) == 5.0
    assert p95([3, 1, 2]) == 3  # ceil(2.85) = 3rd smallest
    assert p95([]) is None


def test_cost_is_none_when_unknown_not_zero():
    free = cost_latency_scores([_row(), _row()])
    assert free["cost_per_alert_usd"] is None and free["cost_known_rows"] == 0
    paid = cost_latency_scores([_row(cost_usd=0.002), _row(cost_usd=0.004), _row()])
    assert paid["cost_per_alert_usd"] == pytest.approx(0.003) and paid["cost_known_rows"] == 2


# --- entry point ----------------------------------------------------------------------------


def test_score_all_accepts_dict_rows():
    rows = [_row().model_dump(), _err().model_dump()]
    s = score_all(rows, {"a-1": _alert()}, ATTACK)
    assert set(s) == {"triage", "techniques", "iocs", "schema", "cost_latency"}
    assert s["triage"]["accuracy"] == 0.5 and s["schema"]["errors"] == 1
