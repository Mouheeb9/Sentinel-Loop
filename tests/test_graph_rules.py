"""Live rule_gen / validate nodes and their edges, with a scripted model and injected validators."""

from __future__ import annotations

from langchain_core.messages import AIMessage

from sentinel.graph import build, nodes
from sentinel.schemas import ValidationResult
from tests.test_rule_gen import VALID, VERDICT, ScriptedModel, _alert, _call


def _state() -> dict:
    return {"alert": _alert(), "verdict": VERDICT, "sigma_rules": [], "covering_rule_id": None}


def _config(model=None, validator=None, rules: bool = True) -> dict:
    configurable = {"pipeline": nodes.PipelineOptions(rules=rules)}
    if model is not None:
        configurable["rulegen_model"] = model
    if validator is not None:
        configurable["validator"] = validator
    return {"configurable": configurable}


def _result(passed: bool) -> ValidationResult:
    return ValidationResult(
        rule_id="r",
        compiled=True,
        true_positives=2,
        false_positives=0 if passed else 3,
        fp_rate=0.0 if passed else 0.06,
        failed_samples=[]
        if passed
        else [{"sample_id": "b1", "should_fire": False, "did_fire": True, "event_ref": "e"}],
        feedback="" if passed else "fires on 3 benign events",
    )


def test_rules_off_skips_generation_without_a_model_call():
    state = _state() | nodes.rule_gen_live(_state(), _config(rules=False))
    assert state["rulegen"] == {"skipped": True} and state["draft_rule"] == ""
    assert build.after_rule_gen(state) == "output"
    assert nodes.output(state)["outcome"] == "rule_skipped"


def test_generated_rule_goes_to_validation_with_one_attempt():
    model = ScriptedModel(replies=[_call(VALID)], seen=[])
    update = nodes.rule_gen_live(_state(), _config(model))
    assert "title: LSASS dump via comsvcs MiniDump" in update["draft_rule"]
    assert update["rulegen"]["technique_ids"] == ["T1003.001"]
    assert update["attempts"] == 1 and update["max_attempts"] == 1  # repair is still a stub
    assert build.after_rule_gen(_state() | update) == "validate"


def test_failed_generation_is_an_outcome_not_a_crash():
    model = ScriptedModel(replies=[AIMessage("no"), AIMessage("still no")], seen=[])
    state = _state() | nodes.rule_gen_live(_state(), _config(model))
    assert "no valid RuleDraft" in state["rulegen"]["error"]
    assert build.after_rule_gen(state) == "output"
    assert nodes.output(state)["outcome"] == "rule_failed"


def _with_rule() -> dict:
    model = ScriptedModel(replies=[_call(VALID)], seen=[])
    return _state() | nodes.rule_gen_live(_state(), _config(model))


def test_without_a_validator_the_rule_is_unvalidated_never_passed():
    state = _with_rule()
    state |= nodes.validate_live(state, _config())  # the real validate() is still a stub
    assert state["validation_pending"] is True
    assert "NOT VALIDATED" in state["validations"][0].feedback
    assert build.after_validate(state) == "output"
    assert nodes.output(state)["outcome"] == "rule_unvalidated"


def test_validator_verdicts_drive_the_outcome():
    seen = {}

    def passing(rule_yaml, source_alert, technique_ids):
        seen["args"] = (source_alert.alert_id, technique_ids)
        return _result(True)

    state = _with_rule()
    state |= nodes.validate_live(state, _config(validator=passing))
    assert seen["args"] == ("a-1", ["T1003.001"])
    assert nodes.output(state)["outcome"] == "rule_passed"

    state = _with_rule()
    state |= nodes.validate_live(state, _config(validator=lambda *a: _result(False)))
    assert build.after_validate(state) == "output"  # max_attempts=1: no stub repair
    assert nodes.output(state)["outcome"] == "rule_failed"
