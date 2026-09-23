"""Enrichment tools the triage model may call, and the allow-list that enforces it.

The model can call exactly the tools in ALLOWED_TOOLS (plus the TriageVerdict answer tool). A
call to any other name raises ToolNotAllowedError instead of being ignored: a model asking for a
tool that was never offered is a sign that something in its input (a planted log field) is
steering it, and that should stop the run and show up in the injection results.

A bad argument (not a CVE id, not an IOC) or a failed upstream request is *not* fatal: the model
gets the error text back as the tool result and can carry on without that lookup.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import StructuredTool

from sentinel.schemas import Alert
from sentinel.tools import nvd, threatfox

_CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def lookup_targets(alert: Alert) -> list[str]:
    """Values in the alert the tools could actually look up: public IPs, URLs, CVE ids.

    Decides whether the model is offered the tools at all, so an alert with nothing to look up
    costs one model call, not two. Domains inside URLs count via the URL; bare domains in
    command lines are too noisy to spot (System.Management.Automation looks like one).
    """
    found: list[str] = []
    for e in alert.events:
        if e.network:
            for ip in (e.network.dst_ip, e.network.src_ip):
                if ip and _public_ip(ip):
                    found.append(ip)
        texts = [e.registry.details if e.registry else None]
        p = e.process
        while p:
            texts.append(p.command_line)
            p = p.parent
        for text in filter(None, texts):
            found += _CVE_IN_TEXT.findall(text) + _URL_IN_TEXT.findall(text)
    return list(dict.fromkeys(found))


def _public_ip(value: str) -> bool:
    try:
        kind, ip = threatfox.classify(value)
    except ValueError:
        return False
    return kind in ("ip", "ip_port") and threatfox.skip_reason(kind, ip) is None


class ToolNotAllowedError(RuntimeError):
    """The model called a tool outside the allow-list."""


def nvd_cve_lookup(cve_id: str) -> dict:
    """Look up a CVE in the NIST NVD: description, CVSS score and severity, CWE, and whether CISA
    lists it as known exploited. Only for a CVE id (CVE-YYYY-NNNN) that appears in the alert."""
    return nvd.lookup_cve(cve_id)


def threatfox_ioc_lookup(ioc: str) -> dict:
    """Check an indicator against abuse.ch ThreatFox (known malware C2, payload and botnet IOCs).
    Accepts a public IP, ip:port, domain, URL, MD5 or SHA256 that appears in the alert. A miss
    only means ThreatFox doesn't know it, not that it is benign."""
    return threatfox.lookup_ioc(ioc)


ALLOWED_TOOLS: dict[str, StructuredTool] = {
    t.name: t
    for t in (
        StructuredTool.from_function(nvd_cve_lookup, name=nvd.NAME),
        StructuredTool.from_function(threatfox_ioc_lookup, name=threatfox.NAME),
    )
}

# Anything that can go wrong with a valid, allowed call; returned to the model as text.
_RECOVERABLE = (ValueError, httpx.HTTPError, RuntimeError)


def check_allowed(name: str, extra: tuple[str, ...] = ()) -> None:
    if name not in ALLOWED_TOOLS and name not in extra:
        raise ToolNotAllowedError(f"model called {name!r}; allowed: {sorted(ALLOWED_TOOLS)}")


def run_tool(name: str, args: dict[str, Any], config: RunnableConfig | None = None) -> str:
    """Run one allowed tool, return its JSON result (or an error object) as the tool message.
    Passing the run config makes the call show up as a tool observation in the Langfuse trace."""
    check_allowed(name)
    try:
        result = ALLOWED_TOOLS[name].invoke(args, config=config)
    except _RECOVERABLE as e:
        result = {"error": f"{type(e).__name__}: {e}"}
    return json.dumps(result, ensure_ascii=False)
