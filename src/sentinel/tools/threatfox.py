"""ThreatFox (abuse.ch) IOC lookup: is this IP, domain, URL or file hash a known-bad indicator?

Private, loopback and other non-routable addresses and internal-only domains are answered locally
("skipped") without a request: they can't be in a public feed, and sending them would leak
internal names to a third party. ThreatFox stores IPs as "ip:port", so a bare IP is matched by
prefix. Answers are cached for 1 day (feeds change daily).

The results carry third-party text (malware names, tags). Only structured fields are kept; free
text like the reporter's comment is dropped.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time
from datetime import timedelta

import httpx

from sentinel.tools.cache import ToolCache, default_cache

NAME = "threatfox_ioc_lookup"
URL = "https://threatfox-api.abuse.ch/api/v1/"
TTL = timedelta(days=1)
TIMEOUT_S = 30
RETRIES = 3
MAX_RESULTS = 3

_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{64})$")  # md5, sha256
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# "SDXHelper.exe" matches the domain pattern. Not real TLDs (.zip and .mov are, so they stay).
_FILE_EXTENSIONS = frozenset(
    "exe dll sys bat cmd vbs vbe js jse wsf hta psm lnk scr msi cpl ocx xml xsl xsd txt log "
    "dat tmp ini cfg json yaml yml csv doc docx xls xlsx xlsm ppt pptx pdf rtf iso img evtx".split()
)
_INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".corp", ".home", ".localdomain", ".arpa")
_KEEP = (
    "ioc",
    "ioc_type",
    "threat_type",
    "malware_printable",
    "confidence_level",
    "first_seen",
    "last_seen",
    "tags",
)


def classify(ioc: str) -> tuple[str, str]:
    """Return (kind, normalized value). kind: ip, ip_port, domain, url, hash. Raises ValueError."""
    value = ioc.strip()
    low = value.lower()
    if low.startswith(("http://", "https://")):
        return "url", value
    if _HASH_RE.fullmatch(low):
        return "hash", low
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and "]" not in port:
        try:
            ipaddress.IPv4Address(host)
            return "ip_port", f"{host}:{int(port)}"
        except ValueError:
            pass
    try:
        return "ip", str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        pass
    if _DOMAIN_RE.fullmatch(low):
        if low.rsplit(".", 1)[1] in _FILE_EXTENSIONS:
            raise ValueError(f"looks like a file name, not a domain: {ioc!r}")
        return "domain", low
    raise ValueError(f"not an IP, ip:port, domain, URL, MD5 or SHA256: {ioc!r}")


def skip_reason(kind: str, value: str) -> str | None:
    if kind in ("ip", "ip_port"):
        ip = ipaddress.ip_address(value.rsplit(":", 1)[0] if kind == "ip_port" else value)
        if not ip.is_global:
            return "private or reserved address, not looked up"
    if kind == "domain" and (value.endswith(_INTERNAL_SUFFIXES) or "." not in value):
        return "internal domain, not looked up"
    return None


def lookup_ioc(ioc: str, cache: ToolCache | None = None) -> dict:
    kind, value = classify(ioc)
    if reason := skip_reason(kind, value):
        return {"ioc": value, "kind": kind, "found": False, "skipped": reason}
    cache = cache or default_cache()
    if (hit := cache.get(NAME, value, TTL)) is not None:
        return hit
    result = summarize(value, kind, _fetch(kind, value))
    cache.put(NAME, value, result)
    return result


def _query(kind: str, value: str) -> dict:
    if kind == "hash":
        return {"query": "search_hash", "hash": value}
    # Bare IP: prefix search, then filtered in summarize(). Everything else: exact.
    return {"query": "search_ioc", "search_term": value, "exact_match": kind != "ip"}


def _fetch(kind: str, value: str) -> dict:
    key = os.environ.get("ABUSE_CH_API_KEY")
    if not key:
        raise RuntimeError("ABUSE_CH_API_KEY is not set (see .env.example)")
    for attempt in range(RETRIES):
        r = httpx.post(URL, json=_query(kind, value), headers={"Auth-Key": key}, timeout=TIMEOUT_S)
        if (r.status_code == 429 or r.status_code >= 500) and attempt < RETRIES - 1:
            time.sleep(2 ** (attempt + 1))
            continue
        r.raise_for_status()
        return r.json()
    raise AssertionError("unreachable")


def summarize(value: str, kind: str, body: dict) -> dict:
    status = body.get("query_status")
    if status not in ("ok", "no_result"):
        raise RuntimeError(f"ThreatFox query failed: {status}")
    data = body.get("data") if status == "ok" else []
    rows = [d for d in data or [] if isinstance(d, dict)]
    if kind == "ip":  # prefix search also matches 1.2.3.40 for 1.2.3.4
        rows = [
            d for d in rows if d.get("ioc") == value or d.get("ioc", "").startswith(value + ":")
        ]
    return {
        "ioc": value,
        "kind": kind,
        "found": bool(rows),
        "matches": len(rows),
        "results": [{k: d.get(k) for k in _KEEP} for d in rows[:MAX_RESULTS]],
    }
