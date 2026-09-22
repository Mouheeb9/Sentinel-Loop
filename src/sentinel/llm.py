"""Which chat model each agent uses. One env var per role, so switching provider is config only.

    SENTINEL_TRIAGE_MODEL=openrouter:nvidia/nemotron-3-super-120b-a12b:free   (default)
    SENTINEL_TRIAGE_MODEL=anthropic:claude-haiku-4-5                         (later)

Format is LangChain's `provider:model`. Every eval number is only comparable to numbers from the
same model string, so re-run the baseline whenever this changes.
"""

from __future__ import annotations

import os

from langchain.chat_models import init_chat_model
from langchain_core.language_models import BaseChatModel

DEFAULT_TRIAGE_MODEL = "openrouter:nvidia/nemotron-3-super-120b-a12b:free"


def triage_model_name() -> str:
    return os.environ.get("SENTINEL_TRIAGE_MODEL") or DEFAULT_TRIAGE_MODEL


def triage_model() -> BaseChatModel:
    return init_chat_model(triage_model_name(), temperature=0)
