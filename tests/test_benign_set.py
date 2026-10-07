"""Validator v2 benign set (data/validation/benign/*.jsonl): well-formed and loaded as negatives."""

from __future__ import annotations

import json

from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.schemas import Alert
from sentinel.validation.validate import BENIGN, default_corpus, grade


def _rows() -> list[dict]:
    return [
        json.loads(line)
        for path in sorted(BENIGN.glob("*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_every_row_is_a_documented_process_event():
    rows = _rows()
    assert len({r["id"] for r in rows}) == len(rows) >= 30
    for r in rows:
        assert r["why"].strip(), r["id"]
        e = sysmon_to_event(r["event"])
        assert e is not None and int(e.raw["EventID"]) == 1, r["id"]


def test_benign_rows_are_loaded_as_negatives():
    ids = {s.alert_id for s in default_corpus().golden if s.label == "benign_noisy"}
    assert {f"bg:{r['id']}" for r in _rows() if r["id"].startswith("syn-")} <= ids


def test_broad_msbuild_xml_rule_now_hits_a_benign_build():
    # Day 12 rule_gen output for day3-056 (results/rulegen-try.json): MSBuild + any '.xml'.
    rule = r"""
title: MSBuild with XML
id: 6c81e1a5-63ae-56c2-870c-6bbf5a4a0000
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\MSBuild.exe'
    CommandLine|contains: '.xml'
  condition: selection
"""
    corpus = default_corpus()
    source = next(s for s in corpus.golden if s.alert_id == "day3-056")
    alert = Alert(alert_id="day3-056", detection_name="x", severity="high", events=[source.event])
    r = grade(rule, alert, ["T1127.001"], corpus)
    assert "bg:syn-msbuild-framework-docxml" in {f.sample_id for f in r.failed_samples}
