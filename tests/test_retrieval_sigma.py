from pathlib import Path

from sentinel.retrieval.sigma import load_sigma_chunks

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"


def _by_id():
    return {c.id: c for c in load_sigma_chunks(FIXTURES)}


def test_deprecated_and_unparseable_rules_are_skipped():
    assert set(_by_id()) == {
        "a49fa4d5-11db-418c-8473-1e014a8dd462",
        "11111111-1111-1111-1111-111111111111",
    }


def test_technique_tag_becomes_attack_id_and_metadata():
    chunk = _by_id()["a49fa4d5-11db-418c-8473-1e014a8dd462"]
    assert chunk.kind == "sigma_rule"
    assert chunk.technique_ids == ["T1003.001"]  # tactic tag is not a technique
    assert chunk.platforms == ["windows"]
    assert chunk.logsource == "process_access/windows"


def test_text_keeps_title_logsource_tags_and_exact_identifiers():
    text = _by_id()["a49fa4d5-11db-418c-8473-1e014a8dd462"].text
    assert text.startswith("Lsass Memory Dump via Comsvcs DLL")
    assert "Logsource: process_access/windows" in text
    assert "attack.t1003.001" in text
    assert "comsvcs.dll" in text


def test_rule_with_only_a_tactic_tag_is_kept_without_technique_ids():
    chunk = _by_id()["11111111-1111-1111-1111-111111111111"]
    assert chunk.technique_ids == []
    assert chunk.logsource == "windows/security"


def test_huge_detection_block_is_truncated(tmp_path):
    hashes = "\n".join(f"            - 'hash{i:06d}'" for i in range(5000))
    (tmp_path / "big.yml").write_text(
        "title: Vulnerable Driver Load\nid: 33333333-3333-3333-3333-333333333333\n"
        "logsource:\n    product: windows\ndetection:\n    selection:\n        Hashes|contains:\n"
        f"{hashes}\n    condition: selection\n"
    )
    (chunk,) = load_sigma_chunks(tmp_path)
    assert len(chunk.text) < 3000
    assert chunk.text.startswith("Vulnerable Driver Load")
    assert chunk.text.endswith("... (truncated)")
