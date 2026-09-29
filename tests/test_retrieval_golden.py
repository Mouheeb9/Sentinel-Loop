"""evals/retrieval_golden.py scoring and question building. No database."""

from __future__ import annotations

import math

import pytest

from evals import retrieval_golden as rg
from evals.scorers import AttackMap
from sentinel.schemas import Alert

ATTACK = AttackMap(tactics={}, renames={"T1562.002": "T1685.001"})


def _case(kind: str, gold: list[str]) -> rg.Case:
    return rg.Case("x", "c", "q", kind, gold)


def test_technique_relevance_is_exact_and_follows_renames():
    rels = rg.relevance(_case("technique", ["T1562.002"]), [["T1685"], ["T1685.001"]], ATTACK)
    assert rels == [False, True]


def test_sigma_relevance_counts_the_parent_technique():
    tags = [["T1547.001"], [], ["T1003"], ["T1003.001", "T1059"]]
    assert rg.relevance(_case("sigma_rule", ["T1003.001"]), tags, ATTACK) == [0, 0, 1, 1]


def test_ndcg():
    assert rg.ndcg([True], 1) == 1.0
    assert rg.ndcg([False, True], 1) == 1 / math.log2(3)
    assert rg.ndcg([True, False, True], 2) == (1 + 1 / 2) / (1 + 1 / math.log2(3))
    assert rg.ndcg([False] * 5 + [True], 1) == 0.0  # beyond the top 5


def test_summary_per_task():
    rows = [
        {"task": "alert->attack", "first_rank": 1, "ndcg5": 1.0},
        {"task": "alert->attack", "first_rank": 7, "ndcg5": 0.0},
        {"task": "alert->attack", "first_rank": None, "ndcg5": 0.0},
        {"task": "alert->attack", "first_rank": 12, "ndcg5": 0.0},
        {"task": "alert->sigma", "first_rank": 2, "ndcg5": 0.5},
    ]
    s = rg.summarize(rows)
    a = s["alert->attack"]
    assert a["n"] == 4 and a["recall@5"] == 0.25 and a["recall@10"] == 0.5
    assert a["mrr"] == pytest.approx((1 + 1 / 7 + 1 / 12) / 4) and a["ndcg@5"] == 0.25
    assert s["alert->sigma"]["recall@5"] == 1.0 and "text->attack" not in s


ALERT = Alert.model_validate(
    {
        "alert_id": "a-1",
        "detection_name": "test",
        "severity": "medium",
        "events": [
            {
                "event_id": "e-1",
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "windows_sysmon",
                "host": "WS1",
                "process": {
                    "image": "C:\\Windows\\System32\\rundll32.exe",
                    "command_line": "rundll32.exe comsvcs.dll MiniDump 624",
                    "parent": {"image": "C:\\Windows\\System32\\cmd.exe"},
                },
                "raw": {"EventID": 1},
                "untrusted_fields": [],
            }
        ],
    }
)


def test_questions_built_from_an_alert():
    assert rg.command_query(ALERT) == "rundll32.exe comsvcs.dll MiniDump 624"
    fields = rg.fields_query(ALERT)
    assert "Image: C:\\Windows\\System32\\rundll32.exe" in fields
    assert "CommandLine: rundll32.exe comsvcs.dll MiniDump 624" in fields
    assert "ParentImage: C:\\Windows\\System32\\cmd.exe" in fields
    labels = [{"alert_id": "a-1", "label": "true_positive", "technique_ids": ["T1003.001"]}]
    cases = rg.alert_cases(labels, {"a-1": ALERT})
    assert sorted(c.task for c in cases) == [
        "alert->attack",
        "alert->sigma",
        "command->attack",
        "fields->sigma",
    ]
    assert all(c.gold == ["T1003.001"] for c in cases)
    sigma = [c for c in cases if c.kind == "sigma_rule"]
    assert all(c.logsource == "process_creation" for c in sigma)


def test_probe_questions_cover_both_text_tasks():
    cases = rg.probe_cases()
    assert {c.task for c in cases} == {"text->attack", "text->sigma"}
    assert len(cases) == 80  # 40 probes x 2 tasks
