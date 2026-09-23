import pytest
from langchain_core.messages import AIMessage

from sentinel.agents.routing import escalation_reason, triage_routed
from sentinel.agents.triage import TriageError
from sentinel.llm import cost_usd
from sentinel.schemas import TriageVerdict
from tests.test_triage import VALID, ScriptedModel, _alert, _call

UNSURE = {**VALID, "confidence": 0.4}
BAD = {**VALID, "technique_ids": ["T13"]}


def _model(*replies):
    return ScriptedModel(replies=list(replies), seen=[])


def _routed(t1, t2):
    return triage_routed(
        _alert(), [], [], tier1=("m1:free", t1), tier2=("m2:free", t2), threshold=0.7
    )


@pytest.mark.parametrize(
    "args, expected",
    [
        (VALID, None),
        (UNSURE, "confidence 0.40 < 0.7"),
        ({**VALID, "verdict": "needs_review"}, "verdict needs_review"),
        ({**VALID, "technique_ids": []}, "true_positive without a technique"),
        ({**VALID, "verdict": "benign_noisy", "technique_ids": []}, None),
    ],
)
def test_escalation_reason(args, expected):
    assert escalation_reason(TriageVerdict(**args), 0.7) == expected


def test_confident_tier1_never_calls_tier2():
    r = _routed(_model(_call(VALID)), _model())
    assert (r.tier, r.escalation, len(r.runs)) == (1, None, 1)


def test_unsure_tier1_escalates_and_tier2_decides():
    r = _routed(_model(_call(UNSURE)), _model(_call(VALID)))
    assert r.tier == 2 and r.verdict.confidence == 0.9
    assert r.escalation.startswith("confidence") and [x.tier for x in r.runs] == [1, 2]


def test_tier1_schema_failure_escalates():
    r = _routed(_model(_call(BAD), _call(BAD)), _model(_call(VALID)))
    assert r.tier == 2 and r.escalation.startswith("tier 1 failed")
    assert r.runs[0].ok is False


def test_tier2_failure_keeps_tier1_answer():
    r = _routed(_model(_call(UNSURE)), _model(_call(BAD), _call(BAD)))
    assert r.tier == 1 and r.verdict.confidence == 0.4 and r.runs[1].ok is False


def test_both_tiers_failing_raises():
    with pytest.raises(TriageError):
        _routed(_model(_call(BAD), _call(BAD)), _model(AIMessage("no"), AIMessage("no")))


def test_cost_table():
    assert cost_usd("openrouter:x/y:free", 10_000, 1_000) == 0.0
    assert cost_usd("anthropic:claude-haiku-4-5", 1_000_000, 100_000) == pytest.approx(1.5)
    assert cost_usd("anthropic:claude-sonnet-5", 1_000_000, 100_000) == pytest.approx(3.0)
    assert cost_usd("openai:unknown", 1, 1) is None
