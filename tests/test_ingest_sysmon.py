import json
from pathlib import Path

import pytest

from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.schemas import Event

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sysmon"
MANIFEST = json.loads((FIXTURES_DIR / "manifest.json").read_text())


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["file"] for e in MANIFEST])
def test_fixture_normalizes_to_schema_valid_event(entry):
    raw = json.loads((FIXTURES_DIR / entry["file"]).read_text())

    event = sysmon_to_event(raw)

    assert isinstance(event, Event)
    assert event.source == "windows_sysmon"

    match entry["event_id"]:
        case 1:
            assert event.process is not None
        case 3:
            assert event.network is not None
        case 13:
            assert event.registry is not None


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["file"] for e in MANIFEST])
def test_normalization_is_stable(entry):
    raw = json.loads((FIXTURES_DIR / entry["file"]).read_text())

    first = sysmon_to_event(raw)
    second = sysmon_to_event(json.loads((FIXTURES_DIR / entry["file"]).read_text()))

    assert first == second
    assert first.event_id == second.event_id


def test_manifest_covers_every_supported_event_id():
    assert {e["event_id"] for e in MANIFEST} == {1, 3, 13}


def test_fixture_names_match_their_contents():
    # A file named after a technique must be labeled with it; background events are "bg_".
    for e in MANIFEST:
        if e["technique_id"] is None:
            assert e["file"].startswith(f"bg_eid{e['event_id']}_"), e["file"]
        else:
            prefix = e["technique_id"].lower().replace(".", "_") + "_"
            assert e["file"].startswith(prefix), e["file"]


def test_manifest_lists_every_fixture_file():
    on_disk = {p.name for p in FIXTURES_DIR.glob("*.json")} - {"manifest.json"}
    assert on_disk == {e["file"] for e in MANIFEST}
