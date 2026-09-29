"""NVD CVE lookup (API 2.0): what a CVE is, how severe, and whether CISA lists it as exploited.

Rate limit: 50 requests per rolling 30 s with an API key, 5 without. A process-wide throttle keeps
calls 0.6 s apart (6 s without a key), and NVD's 403/429/503 "slow down" answers are retried with
backoff. Answers are cached for 7 days (CVE records change rarely).
"""

from __future__ import annotations

import os
import re
import threading
import time
from datetime import timedelta

import httpx

from sentinel.tools.cache import ToolCache, default_cache

NAME = "nvd_cve_lookup"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SOURCE = "nvd@nist.gov"
TTL = timedelta(days=7)
TIMEOUT_S = 30
RETRIES = 4
DESCRIPTION_CHARS = 500

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_lock = threading.Lock()
_last_call = 0.0


def normalize_cve(cve_id: str) -> str:
    cve = cve_id.strip().upper()
    if not _CVE_RE.fullmatch(cve):
        raise ValueError(f"not a CVE id: {cve_id!r} (expected CVE-YYYY-NNNN)")
    return cve


def lookup_cve(cve_id: str, cache: ToolCache | None = None) -> dict:
    cve = normalize_cve(cve_id)
    cache = cache or default_cache()
    if (hit := cache.get(NAME, cve, TTL)) is not None:
        return hit
    result = summarize(cve, _fetch(cve))
    cache.put(NAME, cve, result)
    return result


def _fetch(cve: str) -> dict:
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    for attempt in range(RETRIES):
        _throttle(0.6 if key else 6.0)
        r = httpx.get(URL, params={"cveId": cve}, headers=headers, timeout=TIMEOUT_S)
        if r.status_code in (403, 429, 503) and attempt < RETRIES - 1:
            time.sleep(2 ** (attempt + 1))
            continue
        r.raise_for_status()
        return r.json()
    raise AssertionError("unreachable")


def _throttle(min_interval: float) -> None:
    global _last_call
    with _lock:
        wait = _last_call + min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        _last_call = time.monotonic()


def summarize(cve: str, body: dict) -> dict:
    """Keep what a triage analyst needs; drop references, configurations and change history."""
    vulns = body.get("vulnerabilities") or []
    if not vulns:
        return {"cve_id": cve, "found": False}
    c = vulns[0]["cve"]
    description = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cwes = sorted(
        {
            d["value"]
            for w in c.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    return {
        "cve_id": cve,
        "found": True,
        "published": c.get("published", "")[:10],
        "status": c.get("vulnStatus"),
        "description": " ".join(description.split())[:DESCRIPTION_CHARS],
        "cvss": _cvss(c.get("metrics", {})),
        "cwe": cwes,
        "cisa_known_exploited": "cisaExploitAdd" in c,
        "cisa_added": c.get("cisaExploitAdd"),
    }


def _cvss(metrics: dict) -> dict | None:
    # Newest CVSS version first; within it, prefer NVD's own analysis over the vendor's (CNA)
    # score, e.g. Zerologon: NVD 10.0 vs Microsoft 5.5. Both can be typed "Secondary", so the
    # source decides, then "Primary". Some entries carry no cvssData at all.
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = [e for e in metrics.get(key) or [] if e.get("cvssData")]
        if not entries:
            continue
        m = min(entries, key=lambda e: (e.get("source") != NVD_SOURCE, e.get("type") != "Primary"))
        data = m["cvssData"]
        return {
            "version": data.get("version"),
            "base_score": data.get("baseScore"),
            "severity": data.get("baseSeverity") or m.get("baseSeverity"),
            "vector": data.get("vectorString"),
        }
    return None
