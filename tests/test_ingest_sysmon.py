import json
from pathlib import Path

import pytest

from sentinel.ingest.sysmon import sysmon_to_event
from sentinel.schemas import Event

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "sysmon"
MANIFEST = json.loads((FIXTURES_DIR / "manifest.json").read_text())


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["technique_id"] for e in MANIFEST])
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


@pytest.mark.parametrize("entry", MANIFEST, ids=[e["technique_id"] for e in MANIFEST])
def test_normalization_is_stable(entry):
    raw = json.loads((FIXTURES_DIR / entry["file"]).read_text())

    first = sysmon_to_event(raw)
    second = sysmon_to_event(json.loads((FIXTURES_DIR / entry["file"]).read_text()))

    assert first == second
    assert first.event_id == second.event_id


def test_manifest_covers_ten_distinct_techniques():
    technique_ids = {e["technique_id"] for e in MANIFEST}
    assert len(technique_ids) == 10
