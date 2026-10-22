"""evals.foundry_smoke: the 12-alert batch and the outcome classes, with a fake model."""

from __future__ import annotations

from langchain_core.messages import AIMessage

from evals import foundry_smoke as fs
from evals.triage_smoke import load_golden

VERDICT = {
    "verdict": "true_positive",
    "technique_ids": ["T1059.001"],
    "confidence": 0.9,
    "reasoning": "encoded stager",
    "evidence_refs": ["events[0].process.command_line"],
    "ioc_refs": [],
}


class FakeModel:
    def __init__(self, reply=None, error=None):
        self.reply, self.error = reply, error

    def bind_tools(self, *a, **k):
        return self

    def invoke(self, messages):
        if self.error:
            raise self.error
        return self.reply


def _answer(**meta) -> AIMessage:
    call = {"name": fs.ANSWER_TOOL, "args": VERDICT, "id": "c1", "type": "tool_call"}
    return AIMessage("", tool_calls=[call], response_metadata=meta)


def _alert():
    return load_golden()[1]["day3-104"]


def test_batch_has_attacks_injections_and_benign():
    batch = fs.smoke_alerts(load_golden()[1])
    kinds = [k for k, _ in batch]
    assert (kinds.count("attack"), kinds.count("injection"), kinds.count("benign")) == (5, 5, 2)
    assert all("+inj-" in a.alert_id for k, a in batch if k == "injection")


def test_outcomes():
    ok = fs.classify(FakeModel(_answer(finish_reason="tool_calls")), _alert(), retrieval=False)
    assert ok["outcome"] == "ok" and ok["verdict"] == "true_positive"
    shield = {"prompt_filter_results": [{"content_filter_results": {"jailbreak": {
        "filtered": False, "detected": True}}}]}  # fmt: skip
    flagged = fs.classify(FakeModel(_answer(**shield)), _alert(), retrieval=False)
    assert flagged["outcome"] == "flagged"
    cut = fs.classify(FakeModel(_answer(finish_reason="content_filter")), _alert(), False)
    assert cut["outcome"] == "blocked"
    err = ValueError("Error code: 400 - {'error': {'code': 'content_filter'}}")
    assert fs.classify(FakeModel(error=err), _alert(), retrieval=False)["outcome"] == "blocked"
    auth = fs.classify(FakeModel(error=PermissionError("401")), _alert(), retrieval=False)
    assert auth["outcome"] == "error"


def test_azure_model_uses_the_name_as_deployment(monkeypatch):
    from sentinel.llm import chat_model

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "dummy")
    monkeypatch.setenv("OPENAI_API_VERSION", "2024-10-21")
    assert chat_model("azure_openai:triage-mini").deployment_name == "triage-mini"


def test_reasoning_deployment_sends_no_temperature(monkeypatch):
    from sentinel.llm import chat_model

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://x.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "dummy")
    monkeypatch.setenv("OPENAI_API_VERSION", "2025-04-01-preview")
    assert chat_model("azure_openai:gpt-5-mini").temperature is None  # gpt-5 rejects 0
    assert chat_model("azure_openai:gpt-4.1-mini").temperature == 0
