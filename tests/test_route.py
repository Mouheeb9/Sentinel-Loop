"""route_live and coverage: which retrieved Sigma rule covers an alert, with a fake matcher."""

from __future__ import annotations

import pytest

from sentinel.graph import build, nodes
from sentinel.retrieval.search import Hit
from sentinel.schemas import Alert, TriageVerdict
from sentinel.validation import coverage as cov
from sentinel.validation import rules

R1, R2, R3 = (f"00000000-0000-0000-0000-00000000000{i}" for i in (1, 2, 3))

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
                "process": {"image": "rundll32.exe", "command_line": "comsvcs.dll MiniDump"},
                "raw": {},
                "untrusted_fields": [],
            }
        ],
    }
)


@pytest.fixture
def rules_dir(tmp_path, monkeypatch):
    for rid, name in ((R1, "one"), (R2, "two"), (R3, "three")):
        (tmp_path / f"{name}.yml").write_text(f"title: {name}\nid: {rid}\n", encoding="utf-8")
    monkeypatch.setattr(cov, "rule_yaml", lambda rid, _=None: rules.rule_yaml(rid, tmp_path))
    return tmp_path


def fires_on(*titles: str, event_ids=("e-1",)):
    def match(rule_yaml: str, events) -> list[str]:
        return list(event_ids) if any(f"title: {t}\n" in rule_yaml for t in titles) else []

    return match


def test_rule_yaml_finds_rules_by_id(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "r.yml").write_text(f"title: x\nid: '{R1.upper()}'\n", encoding="utf-8")
    assert "title: x" in rules.rule_yaml(R1, tmp_path)
    assert rules.rule_yaml(R2, tmp_path) is None
    (tmp_path / "c.yml").write_bytes(f"title: c\r\nid: {R3}  # Exec\r\n".encode())
    rules._index.cache_clear()  # a comment after the id, CRLF line ending
    assert "title: c" in rules.rule_yaml(R3, tmp_path)


def test_first_rule_that_fires_covers(rules_dir):
    missing = "ffffffff-0000-0000-0000-000000000000"
    c = cov.check_coverage(ALERT.events, [missing, R1, R2, R3], fires_on("two", "three"))
    assert c.covering_rule_id == R2
    assert c.checked == [R1, R2] and c.missing == [missing] and c.known


def test_firing_on_other_events_does_not_cover(rules_dir):
    c = cov.check_coverage(ALERT.events, [R1], fires_on("one", event_ids=("other",)))
    assert c.covering_rule_id is None and c.checked == [R1]


def test_broken_rule_is_recorded_not_treated_as_no_match(rules_dir):
    def match(rule_yaml, events):
        raise ValueError("does not compile")

    c = cov.check_coverage(ALERT.events, [R1, R2], match)
    assert c.broken == [R1, R2] and c.checked == [] and not c.known


def _unavailable(rule_yaml, events):
    raise NotImplementedError("matcher not available")


def test_missing_matcher_makes_coverage_unknown(rules_dir):
    c = cov.check_coverage(ALERT.events, [R1, R2], _unavailable)
    assert c.unavailable and c.covering_rule_id is None and not c.known


def _state(verdict: str) -> dict:
    v = TriageVerdict(
        verdict=verdict,
        confidence=0.9,
        technique_ids=[],
        reasoning="x",
        evidence_refs=[],
        ioc_refs=[],
    )
    hits = [
        Hit(
            id=rid,
            kind="sigma_rule",
            title=rid,
            text="",
            platforms=[],
            logsource=None,
            technique_ids=[],
            score=1.0,
            matched_by=["vector"],
        )
        for rid in (R1, R2)
    ]
    return {"alert": ALERT, "verdict": v, "sigma_rules": hits}


def test_route_live_covered_ends_the_run(rules_dir):
    state = _state("true_positive")
    update = nodes.route_live(state, {"configurable": {"matcher": fires_on("one")}})
    assert update["covering_rule_id"] == R1
    assert build.after_route(state | update) == "output"


def test_route_live_not_covered_goes_to_rule_gen(rules_dir):
    state = _state("true_positive")
    update = nodes.route_live(state, {"configurable": {"matcher": fires_on()}})
    assert update["covering_rule_id"] is None and update["coverage"]["checked"] == [R1, R2]
    assert build.after_route(state | update) == "rule_gen"


def test_route_live_skips_non_attacks(rules_dir):
    def boom(rule_yaml, events):
        raise AssertionError("matcher must not run for a benign verdict")

    update = nodes.route_live(_state("benign_noisy"), {"configurable": {"matcher": boom}})
    assert update == {"covering_rule_id": None}


def test_route_live_without_matcher_does_not_crash(rules_dir):
    """Eval runs use the live graph: without a usable matcher, route must record 'unknown'."""
    update = nodes.route_live(_state("true_positive"), {"configurable": {"matcher": _unavailable}})
    assert update["covering_rule_id"] is None and update["coverage"]["unavailable"]
