"""Langfuse tracing for one pipeline run. Optional: without keys it does nothing.

One alert = one trace, named `triage-alert`. The root observation (type `agent`) carries a
readable input (the normalized alert, no raw payload) and output (verdict + outcome). Under it,
the LangChain callback handler records every graph node, and from Day 5 every LLM call with
model, tokens and cost. Tags `config:<name>` and `owner:<name>` let the Week 2 eval runs be
compared per config and per person.

Log fields are attacker-controlled; in a trace they are only displayed, never executed, so they
are recorded as-is. Keep secrets out of state, since the handler records node inputs/outputs.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from sentinel.graph.state import SentinelState
from sentinel.schemas import Alert

TRACE_NAME = "triage-alert"


def tracing_configured() -> bool:
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY"))


@dataclass
class TraceRun:
    callbacks: list[Any] = field(default_factory=list)
    url: str | None = None
    _root: Any = None

    def finish(self, state: SentinelState) -> None:
        if self._root is not None:
            self._root.update(output=_summary(state))


@contextmanager
def trace_run(
    alert: Alert, *, config_name: str, owner: str, enabled: bool = True
) -> Iterator[TraceRun]:
    if not (enabled and tracing_configured()):
        yield TraceRun()
        return

    # Imported here so a run without keys never initializes the Langfuse client.
    from langfuse import get_client, propagate_attributes
    from langfuse.langchain import CallbackHandler

    client = get_client()
    try:
        with (
            client.start_as_current_observation(
                name=TRACE_NAME, as_type="agent", input=_alert_view(alert)
            ) as root,
            propagate_attributes(
                trace_name=TRACE_NAME,
                tags=[f"config:{config_name}", f"owner:{owner}"],
                metadata={"alert_id": alert.alert_id, "config": config_name},
            ),
        ):
            url = client.get_trace_url(trace_id=client.get_current_trace_id())
            yield TraceRun(callbacks=[CallbackHandler()], url=url, _root=root)
    finally:
        client.flush()  # short-lived CLI: without this the trace may never be sent


def _alert_view(alert: Alert) -> dict:
    # What a reviewer needs at a glance; the raw log record stays out of the trace input.
    return alert.model_dump(mode="json", exclude={"events": {"__all__": {"raw"}}})


def _summary(state: SentinelState) -> dict:
    verdict = state.get("verdict")
    return {
        "outcome": state.get("outcome"),
        "verdict": verdict.verdict if verdict else None,
        "confidence": verdict.confidence if verdict else None,
        "technique_ids": verdict.technique_ids if verdict else [],
        "covering_rule_id": state.get("covering_rule_id"),
        "attempts": state.get("attempts", 0),
        "draft_rule": state.get("draft_rule"),
    }
