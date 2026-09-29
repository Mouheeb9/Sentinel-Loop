"""Enrichment: retrieve ATT&CK techniques and existing Sigma rules related to an alert.

The retrieval query is built from the normalized event fields (image, command line, registry,
network), i.e. the same behavior an analyst would search for. Some of those fields are
attacker-controlled; that is fine for a similarity search, but note that an ATT&CK ID written
into a command line gets pinned to the top of the results (exact-ID pin in retrieve()).
"""

from __future__ import annotations

from sentinel.retrieval import store
from sentinel.retrieval.search import Hit, retrieve
from sentinel.schemas import Alert, Event

K = 5

_PLATFORM = {"windows_sysmon": "windows", "linux_auditd": "linux", "aws_cloudtrail": "aws"}
# Sysmon event ID -> Sigma logsource category, so rule retrieval sees matching rule types only.
_SYSMON_CATEGORY = {1: "process_creation", 3: "network_connection", 13: "registry_set"}


def search_plan(alert: Alert) -> tuple[str, str | None, str | None]:
    """(query, platform, logsource) the pipeline searches with; evals reuse it so they can't
    drift from what triage is actually shown."""
    first = alert.events[0]
    return enrichment_query(alert), _PLATFORM.get(first.source), _logsource(first)


def enrich_alert(alert: Alert, k: int = K) -> tuple[list[Hit], list[Hit]]:
    query, platform, logsource = search_plan(alert)
    with store.connect() as conn:
        techniques = retrieve(query, k, platform=platform, kind="technique", conn=conn)
        rules = retrieve(
            query, k, logsource=logsource, platform=platform, kind="sigma_rule", conn=conn
        )
    return techniques, rules


def enrichment_query(alert: Alert) -> str:
    parts: list[str] = []
    for e in alert.events:
        if e.process:
            parts += [e.process.image, e.process.command_line]
            if e.process.parent:
                parts += [e.process.parent.image, e.process.parent.command_line]
        if e.registry:
            parts += [e.registry.target_object, e.registry.details]
        if e.network:
            n = e.network
            parts.append(f"network connection to {n.dst_ip} port {n.dst_port} {n.protocol or ''}")
    return " ".join(p for p in parts if p)


def _logsource(event: Event) -> str | None:
    if event.source != "windows_sysmon":
        return None
    try:
        return _SYSMON_CATEGORY.get(int(event.raw.get("EventID", 0)))
    except (TypeError, ValueError):
        return None
