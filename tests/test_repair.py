"""Repair loop: what the rule writer is told about a failed rule, and the repair edges."""

from __future__ import annotations

from langchain_core.messages import AIMessage

from sentinel.agents.repair import MAX_BENIGN_SHOWN, build_repair_context
from sentinel.agents.rule_form import RuleDraft
from sentinel.agents.rule_gen import render
from sentinel.graph import build, nodes
from sentinel.schemas import Event, ProcessInfo, ValidationResult
from tests.test_rule_gen import INJECTION, VALID, VERDICT, ScriptedModel, _alert, _call

RULE = render(RuleDraft.model_validate(VALID))


def _event(event_id: str, command_line: str) -> Event:
    return Event(
        event_id=event_id,
        timestamp="2026-10-06T10:00:00Z",
        source="windows_sysmon",
        host="ws-01",
        process=ProcessInfo(pid=1, command_line=command_line),
        raw={
            "EventID": 1,
            "Image": r"C:\Windows\System32\rundll32.exe",
            "CommandLine": command_line,
            "ProcessId": 1,  # not a rule field: never shown
        },
        untrusted_fields=["process.command_line"],
    )


def _failed(fp: int = 1, missed: int = 1) -> ValidationResult:
    samples = [
        {
            "sample_id": f"b{i}",
            "should_fire": False,
            "did_fire": True,
            "event_ref": f"golden:b{i}/e",
        }
        for i in range(fp)
    ] + [
        {
            "sample_id": f"m{i}",
            "should_fire": True,
            "did_fire": False,
            "event_ref": f"golden:m{i}/e",
        }
        for i in range(missed)
    ]
    return ValidationResult(
        rule_id="r",
        compiled=True,
        true_positives=1,
        false_positives=fp,
        fp_rate=fp / 20,
        failed_samples=samples,
        feedback="benign: fires on 1/20 benign_noisy events in process_creation (b0): too broad",
    )


EVENTS = {f"golden:b{i}/e": _event(f"b{i}", f"rundll32 benign {i}") for i in range(5)}
EVENTS["golden:m0/e"] = _event("m0", "rundll32 SECRET-ATTACK-VALUE")


def test_context_shows_benign_values_but_never_missed_attacks():
    ctx = build_repair_context(RULE, _failed(fp=5, missed=1), 2, 3, EVENTS.get)
    assert [sid for sid, _ in ctx.benign_hits] == ["b0", "b1", "b2"][:MAX_BENIGN_SHOWN]
    assert set(ctx.benign_hits[0][1]) == {"Image", "CommandLine"}  # rule fields only
    assert "SECRET-ATTACK-VALUE" not in str(ctx)  # graded on it next: never shown
    assert ctx.report.startswith("benign:") and (ctx.attempt, ctx.max_attempts) == (2, 3)


def test_unknown_event_ref_is_skipped():
    ctx = build_repair_context(RULE, _failed(), 2, 3, lambda ref: None)
    assert ctx.benign_hits == ()


def _state(**extra) -> dict:
    return {
        "alert": _alert(),
        "verdict": VERDICT,
        "sigma_rules": [],
        "draft_rule": RULE,
        "attempts": 1,
        "validations": [_failed()],
    } | extra


def _config(model) -> dict:
    return {"configurable": {"rulegen_model": model, "event_lookup": EVENTS.get}}


def test_repair_sends_the_report_and_quotes_values_as_untrusted():
    events = {"golden:b0/e": _event("b0", INJECTION)}
    model = ScriptedModel(replies=[_call(VALID)], seen=[])
    update = nodes.repair_live(
        _state(), {"configurable": {"rulegen_model": model, "event_lookup": events.get}}
    )
    assert update["attempts"] == 2 and update["repairs"][0]["attempt"] == 2
    prompt = model.seen[0][1].content
    assert "## REPAIR: write version 2 of 3" in prompt
    assert "too broad" in prompt  # the validator report
    assert f'CommandLine=<UNTRUSTED>"{INJECTION}"</UNTRUSTED>' in prompt
    assert "<UNTRUSTED>\ntitle: LSASS dump" in prompt  # previous rule is untrusted too
    assert build.after_repair(_state() | update) == "validate"


def test_failed_repair_ends_on_the_last_validation():
    model = ScriptedModel(replies=[AIMessage("no"), AIMessage("still no")], seen=[])
    state = _state()
    state |= nodes.repair_live(state, _config(model))
    assert state["repair_failed"] is True and state["attempts"] == 1
    assert build.after_repair(state) == "output"
    assert nodes.output(state)["outcome"] == "rule_failed"


def test_loop_stops_when_a_repair_changes_nothing():
    state = _state(attempts=2, validations=[_failed(), _failed()])
    assert nodes.stalled(state["validations"])
    assert build.after_validate(state) == "output"

    moved = _state(attempts=2, validations=[_failed(fp=2), _failed(fp=1)])
    assert not nodes.stalled(moved["validations"])
    assert build.after_validate(moved) == "repair"


def test_pass_on_the_second_version():
    passed = ValidationResult(
        rule_id="r", compiled=True, true_positives=2, false_positives=0, fp_rate=0.0, feedback=""
    )
    model = ScriptedModel(replies=[_call(VALID)], seen=[])
    state = _state()
    assert build.after_validate(state) == "repair"
    state |= nodes.repair_live(state, _config(model))
    state["validations"] = state["validations"] + [passed]
    assert build.after_validate(state) == "output"
    assert nodes.output(state)["outcome"] == "rule_passed"
    assert len(state["validations"]) == state["attempts"] == 2
