from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from sentinel.schemas import Event, ProcessInfo, TriageVerdict, ValidationResult


def _event(**overrides):
    base = dict(
        event_id="evt-1",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        source="windows_sysmon",
        host="host-1",
        raw={"CommandLine": "whoami"},
        untrusted_fields=["process.command_line"],
    )
    base.update(overrides)
    return Event(**base)


def test_event_requires_tz_aware_timestamp():
    with pytest.raises(ValidationError):
        _event(timestamp=datetime(2026, 1, 1))


def test_event_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        _event(unexpected_field="nope")


def test_process_info_self_reference():
    p = ProcessInfo(
        pid=100,
        image="cmd.exe",
        command_line="cmd.exe /c whoami",
        parent=ProcessInfo(pid=1, image="explorer.exe", command_line="explorer.exe"),
    )
    assert p.parent.image == "explorer.exe"


def test_triage_verdict_rejects_bad_technique_id():
    with pytest.raises(ValidationError):
        TriageVerdict(
            verdict="true_positive",
            confidence=0.9,
            technique_ids=["not-a-technique"],
            reasoning="because",
            evidence_refs=["process.command_line"],
            ioc_refs=[],
        )


def test_triage_verdict_accepts_valid_technique_id():
    v = TriageVerdict(
        verdict="true_positive",
        confidence=0.9,
        technique_ids=["T1059.001"],
        reasoning="because",
        evidence_refs=["process.command_line"],
        ioc_refs=["185.220.101.1"],
    )
    assert v.technique_ids == ["T1059.001"]


def _validation_result(**overrides):
    base = dict(
        rule_id="rule-1",
        compiled=True,
        true_positives=10,
        false_positives=1,
        fp_rate=0.1,
        feedback="looks fine",
    )
    base.update(overrides)
    return ValidationResult(**base)


def test_validation_result_requires_rule_id():
    with pytest.raises(ValidationError):
        ValidationResult(
            compiled=True,
            true_positives=10,
            false_positives=1,
            fp_rate=0.1,
            feedback="looks fine",
        )


@pytest.mark.parametrize("bad_rate", [-0.3, 12.5])
def test_validation_result_rejects_out_of_bounds_fp_rate(bad_rate):
    with pytest.raises(ValidationError):
        _validation_result(fp_rate=bad_rate)


def test_validation_result_accepts_valid_fp_rate():
    assert _validation_result(fp_rate=0.5).rule_id == "rule-1"
