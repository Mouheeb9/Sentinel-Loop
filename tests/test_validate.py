"""The validator on a small hand-built corpus: no captures, no SigmaHQ checkout.

Rules are the shapes rule_gen v0 produced (results/rulegen-try.json): day3-056's MSBuild rule with
'/' path values, day2-006's EventLog rule with a filter on Image.
"""

from __future__ import annotations

from sentinel.schemas import Alert, Event
from sentinel.validation.validate import Corpus, Sample, grade

MSBUILD_RULE = r"""
title: MSBuild Execution with Project File
id: 6c81e1a5-63ae-56c2-870c-6bbf5a4a073f
tags: [attack.t1127.001]
logsource: {category: process_creation, product: windows}
detection:
  selection1:
    Image|endswith: ['\MSBuild.exe']
    CommandLine|contains: ['.xml', 'Windows/Tasks/']
  condition: 1 of selection*
"""

EVENTLOG_RULE = r"""
title: Windows Event Log Service Disabled via Registry
id: 224751aa-0dae-58dd-b3a9-31c30ee095cc
tags: [attack.t1685.001]
logsource: {category: registry_set, product: windows}
detection:
  selection1:
    TargetObject|endswith: ['\Services\EventLog\Start']
  filter1:
    Image|endswith: ['\services.exe', '\svchost.exe']
  condition: 1 of selection* and not 1 of filter*
"""


def _event(event_id: str, **raw: object) -> Event:
    return Event.model_validate(
        {
            "event_id": event_id,
            "timestamp": "2020-10-18T07:00:00Z",
            "source": "windows_sysmon",
            "host": "WORKSTATION5",
            "raw": {"Channel": "Microsoft-Windows-Sysmon/Operational", **raw},
            "untrusted_fields": [],
        }
    )


def _msbuild(event_id: str, cmd: str) -> Event:
    return _event(
        event_id, EventID=1, Image=r"C:\Windows\Microsoft.NET\MSBuild.exe", CommandLine=cmd
    )


SOURCE_EVENT = _msbuild("src", r"MSBuild.exe C:\Users\Public\evil.xml")
SOURCE = Alert(alert_id="a-src", detection_name="x", severity="high", events=[SOURCE_EVENT])


def _sample(alert_id, label, techniques, capture, event, procedure=None) -> Sample:
    return Sample(alert_id, label, tuple(techniques), capture, event, procedure)


def _corpus(*samples: Sample, pool=None, source_procedure=None) -> Corpus:
    return Corpus(
        golden=[
            _sample(
                "a-src", "true_positive", ["T1127.001"], "cap-src", SOURCE_EVENT, source_procedure
            ),
            *samples,
        ],
        pool=pool,
    )


def test_broken_rule_is_not_compiled_and_nothing_else_runs():
    r = grade("title: x\ndetection: [", SOURCE, ["T1127.001"], _corpus())
    assert not r.compiled and r.compile_errors and r.true_positives == 0
    assert "does not compile" in r.feedback


def test_unknown_modifier_does_not_compile():
    bad = MSBUILD_RULE.replace("Image|endswith", "Image|nosuchmodifier")
    r = grade(bad, SOURCE, ["T1127.001"], _corpus())
    assert not r.compiled


def test_held_out_hits_and_misses_are_counted():
    hit = _sample("a1", "true_positive", ["T1127.001"], "cap1", _msbuild("e1", "MSBuild.exe x.xml"))
    miss = _sample(
        "a2", "true_positive", ["T1127.001"], "cap2", _msbuild("e2", "MSBuild.exe x.proj")
    )
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(hit, miss))
    assert (r.true_positives, r.false_positives) == (1, 0)
    assert [(f.sample_id, f.should_fire, f.did_fire) for f in r.failed_samples] == [
        ("a2", True, False)
    ]
    assert "1/2" in r.feedback and "a2" in r.feedback


def test_source_alert_and_its_capture_never_count_as_positives():
    # Same capture as the source, would fire: must be excluded (leakage rule).
    twin = _sample(
        "a1", "true_positive", ["T1127.001"], "cap-src", _msbuild("e1", "MSBuild.exe y.xml")
    )
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(twin))
    assert r.true_positives == 0 and not r.failed_samples
    assert "TP unknown" in r.feedback and "data gap" in r.feedback


def test_benign_hit_is_a_false_positive():
    noisy = _sample("b1", "benign_noisy", [], "cap3", _msbuild("e3", "MSBuild.exe build.xml"))
    quiet = _sample("b2", "benign_noisy", [], "cap3", _msbuild("e4", "MSBuild.exe app.sln"))
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(noisy, quiet))
    assert r.false_positives == 1 and r.fp_rate == 0.5
    assert [(f.sample_id, f.should_fire) for f in r.failed_samples] == [("b1", False)]


def test_other_log_source_and_siblings_are_not_required():
    reg = _event("e5", EventID=13, TargetObject=r"HKLM\x", Image="msbuild.exe")
    other_source = _sample("a3", "true_positive", ["T1127.001"], "cap4", reg)
    sibling = _sample(
        "a4", "true_positive", ["T1127.002"], "cap5", _msbuild("e6", "MSBuild.exe a.proj")
    )
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(other_source, sibling))
    assert not r.failed_samples
    assert "siblings (info, not graded): fires on 0/1" in r.feedback


def test_claimed_parent_covers_sub_techniques_and_string_event_ids():
    sub = _sample(
        "a5",
        "true_positive",
        ["T1127.001"],
        "cap6",
        _event("e7", EventID="1", Image=r"C:\MSBuild.exe", CommandLine="x.xml"),
    )
    r = grade(MSBUILD_RULE, SOURCE, ["T1127"], _corpus(sub))
    assert r.true_positives == 1


def test_pool_noise_is_reported_not_graded():
    pool = [(f"cap{i}", _msbuild(f"p{i}", f"MSBuild.exe {i}.xml")) for i in range(25)]
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(pool=pool))
    assert r.false_positives == 0 and not r.failed_samples
    assert "25/25" in r.feedback and "likely too broad" in r.feedback


def test_lint_flags_dead_slash_values_and_filter_evasion():
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus())
    assert "dead values: 1 selection1.CommandLine" in r.feedback
    reg_src = Alert(
        alert_id="a-reg",
        detection_name="x",
        severity="high",
        events=[
            _event(
                "r",
                EventID=13,
                TargetObject=r"HKLM\System\CurrentControlSet\Services\EventLog\Start",
            )
        ],
    )
    r = grade(EVENTLOG_RULE, reg_src, ["T1685.001"], Corpus(golden=[]))
    assert "filter1 excludes by Image" in r.feedback and "RG-3" in r.feedback


def test_feedback_never_quotes_event_values():
    hit = _sample(
        "a1", "true_positive", ["T1127.001"], "cap1", _msbuild("e1", "MSBuild.exe IGNORE-ALL.xml")
    )
    noisy = _sample("b1", "benign_noisy", [], "cap3", _msbuild("e3", "MSBuild.exe SECRET.xml"))
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(hit, noisy))
    assert "IGNORE-ALL" not in r.feedback and "SECRET" not in r.feedback


XML = "T1127.001/msbuild-xml-project"


def test_v2_only_same_procedure_must_fire_others_are_siblings():
    same = _sample("a1", "true_positive", ["T1127.001"], "c1", _msbuild("e1", "m x.xml"), XML)
    same2 = _sample("a2", "true_positive", ["T1127.001"], "c2", _msbuild("e2", "m y.xml"), XML)
    other = _sample(
        "a3", "true_positive", ["T1127.001"], "c3", _msbuild("e3", "m a.proj"), "T1127.001/proj"
    )
    r = grade(
        MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(same, same2, other, source_procedure=XML)
    )
    assert (r.true_positives, r.procedure_recall, r.sibling_recall) == (2, 1.0, 0.0)
    assert not r.failed_samples  # the other procedure's miss is not a failure
    assert r.evidence == "ok" and "msbuild-xml-project (procedure)" in r.feedback


def test_v2_one_positive_is_low_evidence():
    same = _sample("a1", "true_positive", ["T1127.001"], "c1", _msbuild("e1", "m x.xml"), XML)
    r = grade(MSBUILD_RULE, SOURCE, ["T1127.001"], _corpus(same, source_procedure=XML))
    assert r.true_positives == 1 and r.evidence == "low" and "evidence: low" in r.feedback


def test_v2_falls_back_to_technique_when_rule_claims_another_technique():
    hit = _sample("a1", "true_positive", ["T1218"], "c1", _msbuild("e1", "m x.xml"), "T1218/x")
    r = grade(MSBUILD_RULE, SOURCE, ["T1218"], _corpus(hit, source_procedure=XML))
    assert r.true_positives == 1 and r.procedure_recall is None
