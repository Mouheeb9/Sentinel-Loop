"""The Sigma matcher on real event shapes. Self-contained: no SigmaHQ checkout, no captures.

The attack event is the golden comsvcs MiniDump capture (T1003.001) as Sysmon logged it; the rule
is SigmaHQ's "Process Memory Dump Via Comsvcs.DLL" (646ea171), detection copied verbatim.
Parity with the Zircolite CLI was checked by hand on 32 golden process_creation events x the whole
SigmaHQ windows/process_creation folder: same 35 rules, same 44 hits.
"""

from __future__ import annotations

import pytest

from sentinel.schemas import Event
from sentinel.validation.matcher import match

COMSVCS_RULE = r"""
title: Process Memory Dump Via Comsvcs.DLL
id: 646ea171-dded-4578-8a4d-65e9822892e3
status: test
tags: [attack.credential-access, attack.t1003.001]
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
        - CommandLine|contains: 'rundll32'
    selection_cli_1:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'full'
        CommandLine|contains:
            - '#-'
            - '#+'
            - '#24'
            - '24 '
            - 'MiniDump'
            - '#65560'
    selection_generic:
        CommandLine|contains|all:
            - '24'
            - 'comsvcs'
            - 'full'
        CommandLine|contains:
            - ' #'
            - ',#'
            - ', #'
            - '"#'
    condition: (selection_img and 1 of selection_cli_*) or selection_generic
level: high
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


DUMP = _event(
    "attack",
    EventID=1,
    Image=r"C:\Windows\System32\rundll32.exe",
    OriginalFileName="RUNDLL32.EXE",
    ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    CommandLine=r'"C:\Windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump'
    r" 756 C:\Users\wardog\AppData\Local\Temp\lsass-comsvcs.dmp full",
)
BENIGN = _event(
    "benign",
    EventID="1",  # Sysmon JSON exports carry it as a string too
    Image=r"C:\Windows\System32\rundll32.exe",
    OriginalFileName="RUNDLL32.EXE",
    CommandLine=r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
)


def test_fires_on_the_known_attack_event_only():
    assert match(COMSVCS_RULE, [BENIGN, DUMP]) == ["attack"]


def test_does_not_fire_on_benign_rundll32():
    assert match(COMSVCS_RULE, [BENIGN]) == []


def test_values_match_case_insensitively():
    shouted = DUMP.model_copy(
        update={
            "event_id": "upper",
            "raw": DUMP.raw
            | {"CommandLine": DUMP.raw["CommandLine"].upper(), "Image": r"C:\X\RUNDLL32.EXE"},
        }
    )
    assert match(COMSVCS_RULE, [shouted]) == ["upper"]


def test_logsource_category_filters_on_event_id():
    """Same fields on a registry event (EID 13): a process_creation rule must not fire."""
    registry = DUMP.model_copy(update={"event_id": "reg", "raw": DUMP.raw | {"EventID": 13}})
    assert match(COMSVCS_RULE, [registry]) == []


def test_field_missing_from_every_event_is_null_not_an_error():
    rule = """
title: parent only
logsource: {product: windows, category: process_creation}
detection:
    sel: {ParentCommandLine|contains: 'mshta'}
    condition: sel
"""
    assert match(rule, [DUMP]) == []


def test_null_and_regex_modifiers():
    rule = r"""
title: regex and null
logsource: {product: windows, category: process_creation}
detection:
    sel: {CommandLine|re: 'MiniDump \d+ '}
    no_user: {User: null}
    condition: sel and no_user
"""
    assert match(rule, [DUMP, BENIGN]) == ["attack"]


@pytest.mark.parametrize(
    "broken",
    [
        "title: no logsource\ndetection: {sel: {Image: x}, condition: sel}",
        "title: bad condition\nlogsource: {category: process_creation, product: windows}\n"
        "detection: {sel: {Image: x}, condition: sel and missing}",
        "not: [valid: yaml",
    ],
)
def test_broken_rule_raises_value_error(broken):
    with pytest.raises(ValueError, match="does not compile"):
        match(broken, [DUMP])


def test_no_events_is_empty():
    assert match(COMSVCS_RULE, []) == []


def test_field_spelled_two_ways_across_events():
    # Logs spell some fields both ways (ProcessId / ProcessID); SQLite column names are
    # case-insensitive, so they share one column instead of crashing the table build.
    a = _event("a", EventID=1, ProcessId="4", Image=r"C:\Windows\System32\rundll32.exe")
    b = _event("b", EventID=1, ProcessID="7", Image=r"C:\Windows\System32\notepad.exe")
    rule = COMSVCS_RULE.replace(
        "condition: (selection_img and 1 of selection_cli_*) or selection_generic",
        "condition: selection_img",
    )
    assert match(rule, [a, b]) == ["a"]
