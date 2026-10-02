"""The rule form and its YAML builder, checked end to end with the real Sigma matcher."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from sentinel.agents.rule_form import RuleDraft, escape_value, render
from sentinel.schemas import Event
from sentinel.validation.matcher import match


def _event(event_id: str, **raw: object) -> Event:
    return Event.model_validate(
        {
            "event_id": event_id,
            "timestamp": "2020-10-18T07:00:00Z",
            "source": "windows_sysmon",
            "host": "WS1",
            "raw": {"EventID": 1, **raw},
            "untrusted_fields": [],
        }
    )


DUMP = _event(
    "dump",
    Image=r"C:\Windows\System32\rundll32.exe",
    CommandLine=r"rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 624 C:\t\l.dmp full",
)
OTHER = _event("other", Image=r"C:\Windows\System32\rundll32.exe", CommandLine="rundll32 a.dll,b")


def _draft(**kw) -> RuleDraft:
    base = {
        "title": "LSASS dump via comsvcs MiniDump",
        "description": "rundll32 loading comsvcs.dll with the MiniDump export.",
        "category": "process_creation",
        "selections": [
            {
                "items": [
                    {"field": "Image", "match": "endswith", "values": [r"\rundll32.exe"]},
                    {
                        "field": "CommandLine",
                        "match": "contains",
                        "values": ["comsvcs", "MiniDump"],
                    },
                ]
            }
        ],
        "technique_ids": ["T1003.001"],
        "level": "high",
    }
    return RuleDraft.model_validate(base | kw)


def test_rendered_rule_compiles_and_fires_only_on_the_attack():
    rule = render(_draft())
    assert match(rule, [OTHER, DUMP]) == ["dump"]
    body = yaml.safe_load(rule)
    assert body["tags"] == ["attack.t1003.001"]
    assert body["logsource"] == {"category": "process_creation", "product": "windows"}
    assert body["detection"]["condition"] == "1 of selection*"


def test_filters_exclude_known_benign_cases():
    flt = [{"items": [{"field": "CommandLine", "match": "contains", "values": ["624"]}]}]
    rule = render(_draft(filters=flt))
    assert yaml.safe_load(rule)["detection"]["condition"] == "1 of selection* and not 1 of filter*"
    assert match(rule, [DUMP]) == []


def test_same_form_gives_same_rule_id():
    assert yaml.safe_load(render(_draft()))["id"] == yaml.safe_load(render(_draft()))["id"]


def test_wildcards_in_attacker_values_are_matched_literally():
    """A planted `*` must not turn the rule into 'match everything'."""
    star = _draft(
        selections=[{"items": [{"field": "CommandLine", "match": "equals", "values": ["*"]}]}]
    )
    rule = render(star)
    assert match(rule, [DUMP, OTHER]) == []
    assert match(rule, [_event("lit", CommandLine="*")]) == ["lit"]


@pytest.mark.parametrize(
    "value",
    [r"C:\Windows\System32\rundll32.exe", r"C:\dir\*.dmp", "a?b", "trailing\\", r"two\\slashes"],
)
def test_escaped_values_round_trip_through_the_matcher(value):
    draft = _draft(
        selections=[{"items": [{"field": "CommandLine", "match": "equals", "values": [value]}]}]
    )
    rule = render(draft)
    events = [_event("exact", CommandLine=value), _event("x", CommandLine=value + "x")]
    assert match(rule, events) == ["exact"]


def test_escape_value_examples():
    assert escape_value(r"C:\Windows\a.exe") == r"C:\Windows\a.exe"
    assert escape_value("a*b?") == r"a\*b\?"
    assert escape_value("end\\") == "end\\\\"


@pytest.mark.parametrize(
    "change, message",
    [
        ({"category": "file_event"}, "category"),
        (
            {"selections": [{"items": [{"field": "Hashes", "match": "equals", "values": ["x"]}]}]},
            "not allowed",
        ),
        (
            {"selections": [{"items": [{"field": "Image", "match": "re", "values": [".*"]}]}]},
            "match",
        ),
        (
            {"selections": [{"items": [{"field": "Image", "match": "equals", "values": [" "]}]}]},
            "empty value",
        ),
        (
            {
                "selections": [
                    {"items": [{"field": "Image", "match": "equals", "values": ["a\nb"]}]}
                ]
            },
            "one line",
        ),
        ({"technique_ids": ["T1003.1"]}, "invalid ATT&CK"),
        ({"title": "x\ncondition: 1"}, "one line"),
        ({"extra_key": 1}, "extra"),
    ],
)
def test_unsafe_or_invalid_forms_are_refused(change, message):
    with pytest.raises(ValidationError, match=message):
        _draft(**change)


def test_values_cannot_inject_yaml_structure():
    nasty = "x'\n  condition: selection1\n"
    with pytest.raises(ValidationError):
        _draft(selections=[{"items": [{"field": "Image", "match": "equals", "values": [nasty]}]}])
    quoted = "a: b, {c: d}, [e], 'f', \"g\" # h"
    rule = render(
        _draft(
            selections=[
                {"items": [{"field": "CommandLine", "match": "equals", "values": [quoted]}]}
            ]
        )
    )
    assert yaml.safe_load(rule)["detection"]["selection1"] == {"CommandLine": [quoted]}


def test_forward_slashes_in_path_fields_become_backslashes():
    """Free models drop backslashes in JSON, so path fields are written with '/'."""
    draft = _draft(
        selections=[
            {
                "items": [
                    {"field": "Image", "match": "endswith", "values": ["/System32/rundll32.exe"]},
                    {"field": "CommandLine", "match": "contains", "values": ["/c"]},
                ]
            }
        ]
    )
    image, cmd = draft.selections[0].items
    assert image.values == [r"\System32\rundll32.exe"]
    assert cmd.values == ["/c"]  # CommandLine keeps '/': it's a real switch character
    event = _event("e", Image=r"C:\Windows\System32\rundll32.exe", CommandLine="x /c y")
    assert match(render(draft), [event]) == ["e"]
