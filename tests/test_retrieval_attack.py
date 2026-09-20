from pathlib import Path

from sentinel.retrieval.attack import load_attack_chunks

FIXTURE = Path(__file__).parent / "fixtures" / "attack" / "mini-bundle.json"


def test_one_chunk_per_live_technique():
    chunks = load_attack_chunks(FIXTURE)
    assert [c.id for c in chunks] == ["T1003.001"]  # revoked and deprecated are dropped


def test_chunk_carries_structure_and_detection_guidance():
    (chunk,) = load_attack_chunks(FIXTURE)
    assert chunk.kind == "technique"
    assert chunk.platforms == ["windows"]
    assert chunk.technique_ids == ["T1003.001"]
    assert "Tactics: credential-access" in chunk.text
    assert "Data sources: Process Access" in chunk.text
    assert "- Watch for access to lsass.exe." in chunk.text


def test_citations_and_link_urls_are_stripped():
    (chunk,) = load_attack_chunks(FIXTURE)
    assert "Citation" not in chunk.text
    assert "https://" not in chunk.text
    assert "Dump LSASS memory." in chunk.text


def test_formatting_tags_are_stripped_but_command_placeholders_survive():
    (chunk,) = load_attack_chunks(FIXTURE)
    for tag in ("<code>", "</code>", "<b>", "</b>", "<br>"):
        assert tag not in chunk.text
    assert "Run procdump -p <PID> or mimikatz." in chunk.text
    assert "\nSecond line." in chunk.text
