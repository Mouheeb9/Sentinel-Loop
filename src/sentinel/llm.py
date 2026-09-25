"""Which chat model each role uses. One env var per role, so switching provider is config only.

Triage runs in two tiers (see agents/routing.py): a cheap first pass, and a stronger model that
re-runs the alert when the first answer is unsure.

    SENTINEL_TRIAGE_MODEL=openrouter:nvidia/nemotron-3-super-120b-a12b:free       (tier 1, default)
    SENTINEL_ESCALATION_MODEL=openrouter:nvidia/nemotron-3-ultra-550b-a55b:free   (tier 2, default)
    SENTINEL_ESCALATION_MODEL=none                                                (tier 1 only)
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


def chat_model(name: str) -> BaseChatModel:
    return init_chat_model(name, temperature=0)


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
