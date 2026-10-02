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
    parts: list[str] = [c for c in (launch_context(e) for e in alert.events) if c]
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


def launch_context(event: Event) -> str | None:
    """One sentence on HOW the process was started, read from the parent -> child chain.

    Two file paths mean little to a keyword or vector search, and a model tends to tag the
    command it sees rather than the mechanism that ran it (a shell under services.exe is
    service execution, not just "cmd"). Fixed rules, no model call; the output is our own
    text, but it is derived from image paths an attacker can spoof (masquerading), so it is
    a hint, not evidence.
    """
    proc = event.process
    if proc is None or proc.parent is None or not proc.parent.image:
        return None
    parent = _norm(proc.parent.image)
    name = parent.rsplit("\\", 1)[-1]
    parent_cmd = (proc.parent.command_line or "").lower()
    child_is_shell = _norm(proc.image or "").rsplit("\\", 1)[-1] in _SHELLS
    for match, text in _LAUNCHERS:
        if match(parent, name, parent_cmd):
            if child_is_shell and name == "services.exe":
                text += "; a shell run as a service is typical of remote service execution"
            return f"Launch context: {text}."
    return None


def _norm(path: str) -> str:
    return path.strip().strip('"').lower().replace("/", "\\")


_SHELLS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe",
}  # fmt: skip
_WEB_WORKERS = {"w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "umworkerprocess.exe"}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "onenote.exe"}
# (parent path, parent file name, parent command line) -> matches?, description. First match wins.
_LAUNCHERS = [
    (
        lambda p, n, c: p.endswith("\\windows\\system32\\services.exe"),
        "started by services.exe (Service Control Manager), i.e. run as a Windows service",
    ),
    (
        lambda p, n, c: n in _WEB_WORKERS or n.startswith("tomcat"),
        "spawned by a web server worker process, typical of exploitation of a public-facing "
        "application or a web shell",
    ),
    (
        lambda p, n, c: n == "wmiprvse.exe",
        "started by the WMI provider host (wmiprvse.exe), i.e. executed through WMI",
    ),
    (
        lambda p, n, c: n == "wsmprovhost.exe",
        "started by the WinRM plugin host (wsmprovhost.exe), i.e. PowerShell remoting",
    ),
    (
        lambda p, n, c: (n == "svchost.exe" and "dcomlaunch" in c) or "-embedding" in c,
        "started through DCOM (a COM server launched with -Embedding)",
    ),
    (
        lambda p, n, c: n == "taskeng.exe" or (n == "svchost.exe" and "schedule" in c),
        "started by the Task Scheduler, i.e. a scheduled task",
    ),
    (
        lambda p, n, c: n in _OFFICE,
        "spawned by an Office application, typical of a malicious document or macro",
    ),
]


def _logsource(event: Event) -> str | None:
    if event.source != "windows_sysmon":
        return None
    try:
        return _SYSMON_CATEGORY.get(int(event.raw.get("EventID", 0)))
    except (TypeError, ValueError):
        return None
