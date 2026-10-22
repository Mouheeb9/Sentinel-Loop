"""Which chat model each role uses. One env var per role, so switching provider is config only.

Triage runs in two tiers (see agents/routing.py): a cheap first pass, and a stronger model that
re-runs the alert when the first answer is unsure.

    SENTINEL_TRIAGE_MODEL=openrouter:nvidia/nemotron-3-super-120b-a12b:free       (tier 1, default)
    SENTINEL_ESCALATION_MODEL=openrouter:nvidia/nemotron-3-ultra-550b-a55b:free   (tier 2, default)
    SENTINEL_ESCALATION_MODEL=none                                                (tier 1 only)
    SENTINEL_RULEGEN_MODEL=...      rule generation (default: the tier-2 model; writing a rule is
                                    the harder task, and it runs only on uncovered attacks)
    later: anthropic:claude-haiku-4-5 (tier 1), anthropic:claude-sonnet-5 (tier 2)

Format is LangChain's `provider:model`. Every eval number is only comparable to numbers from the
same model strings, so re-run the baseline whenever one changes.
"""

from __future__ import annotations

import os

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

DEFAULT_TRIAGE_MODEL = "openrouter:nvidia/nemotron-3-super-120b-a12b:free"
DEFAULT_ESCALATION_MODEL = "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free"

# USD per million tokens (input, output). Anthropic list prices, checked 2026-09-23.
PRICES_PER_MTOK: dict[str, tuple[float, float]] = {
    "anthropic:claude-haiku-4-5": (1.00, 5.00),
    "anthropic:claude-sonnet-5": (2.00, 10.00),
}


def triage_model_name() -> str:
    return os.environ.get("SENTINEL_TRIAGE_MODEL") or DEFAULT_TRIAGE_MODEL


def escalation_model_name() -> str | None:
    """None when escalation is switched off."""
    name = os.environ.get("SENTINEL_ESCALATION_MODEL") or DEFAULT_ESCALATION_MODEL
    return None if name.lower() == "none" else name


def rulegen_model_name() -> str:
    return os.environ.get("SENTINEL_RULEGEN_MODEL") or DEFAULT_ESCALATION_MODEL


def request_timeout() -> float:
    """Seconds one model call may take before it counts as a transport error (retried, and a
    resumable eval re-runs the alert). Without it a provider that keeps the connection open but
    never answers hangs the run: gold-v1 sat 3.5 h on one call (19 Oct). Free models take up to
    ~3 min on a rule, hence the margin. SENTINEL_LLM_TIMEOUT overrides."""
    return float(os.environ.get("SENTINEL_LLM_TIMEOUT") or 300)


def _timeout_arg(name: str) -> float | int:
    """The timeout in the unit the provider's client takes. ChatOpenRouter's `timeout` is in
    MILLISECONDS (SDK timeout_ms); the others take seconds. Passing 300 to OpenRouter meant 0.3 s:
    every rule call timed out and the SDK retried for ~5 min before failing (19-20 Oct)."""
    seconds = request_timeout()
    return int(seconds * 1000) if name.startswith("openrouter:") else seconds


def chat_model(name: str) -> BaseChatModel:
    return init_chat_model(name, temperature=0, timeout=_timeout_arg(name))


def triage_model() -> BaseChatModel:
    return chat_model(triage_model_name())


def cost_usd(model_name: str, input_tokens: int, output_tokens: int) -> float | None:
    """Cost of one call. 0 for OpenRouter ':free' models, None when the price is unknown."""
    if model_name.endswith(":free"):
        return 0.0
    price = PRICES_PER_MTOK.get(model_name)
    if price is None:
        return None
    return (input_tokens * price[0] + output_tokens * price[1]) / 1_000_000
