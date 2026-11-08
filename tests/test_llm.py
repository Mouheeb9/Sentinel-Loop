"""Model client settings that are easy to get wrong."""

from __future__ import annotations

from sentinel import llm


def test_openrouter_timeout_is_passed_in_milliseconds(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    monkeypatch.delenv("SENTINEL_LLM_TIMEOUT", raising=False)
    model = llm.chat_model("openrouter:nvidia/nemotron-3-super-120b-a12b:free")
    assert model.request_timeout == 300_000  # 300 s; 300 would be 0.3 s


def test_other_providers_take_seconds(monkeypatch):
    monkeypatch.setenv("SENTINEL_LLM_TIMEOUT", "120")
    assert llm._timeout_arg("anthropic:claude-haiku-4-5") == 120.0
    assert llm._timeout_arg("openrouter:x/y") == 120_000
