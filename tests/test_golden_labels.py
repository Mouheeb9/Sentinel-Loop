from pathlib import Path

import pytest

from evals.check_labels import LABELS, Problem, TechniqueIndex, check_labels, fix_labels
from sentinel.retrieval.attack import DEFAULT_BUNDLE

FIXTURE = Path(__file__).parent / "fixtures" / "attack" / "renumbering-bundle.json"


@pytest.fixture(scope="module")
def index() -> TechniqueIndex:
    return TechniqueIndex(FIXTURE)


def _write(tmp_path: Path, *rows: tuple[str, list[str]]) -> Path:
    path = tmp_path / "labels.jsonl"
    lines = [
        f'{{"alert_id": "{aid}", "label": "true_positive", "technique_ids": '
        f"[{', '.join(repr(t).replace(chr(39), chr(34)) for t in tids)}], "
        f'"rationale": "keep me"}}\n'
        for aid, tids in rows
    ]
    path.write_bytes("".join(lines).encode("utf-8"))
    return path


# --- the guard on the real labels ------------------------------------------------------------


@pytest.mark.skipif(not DEFAULT_BUNDLE.exists(), reason="ATT&CK bundle not downloaded")
def test_every_golden_label_uses_a_live_attack_technique():
    problems = check_labels(LABELS)
    assert not problems, (
        "golden labels use dead ATT&CK technique IDs:\n"
        + "\n".join(p.message() for p in problems)
        + "\n\nfix with: uv run python -m evals.check_labels --fix"
    )


# --- what the checker reports ------------------------------------------------------------------


def test_live_ids_are_fine(index, tmp_path):
    assert check_labels(_write(tmp_path, ("a1", ["T1001", "T1002"])), index) == []


def test_revoked_id_with_one_successor_names_it(index, tmp_path):
    (p,) = check_labels(_write(tmp_path, ("a1", ["T2001"])), index)
    assert p.message() == "alert a1 uses T2001 - revoked, use T1001"
    assert p.auto_fixable


def test_chain_of_renumberings_resolves_to_the_live_id(index, tmp_path):
    (p,) = check_labels(_write(tmp_path, ("a1", ["T2002"])), index)  # T2002 -> T2001 -> T1001
    assert p.successors == ("T1001",)


def test_split_technique_is_reported_not_guessed(index, tmp_path):
    (p,) = check_labels(_write(tmp_path, ("a1", ["T2003"])), index)
    assert p.successors == ("T1001", "T1002")
    assert not p.auto_fixable
    assert "split into several: T1001, T1002; pick one by hand" in p.message()


def test_deprecated_and_orphaned_and_unknown_ids_need_a_human(index, tmp_path):
    problems = check_labels(_write(tmp_path, ("a1", ["T2004", "T2005", "T9000"])), index)
    assert [p.kind for p in problems] == ["deprecated", "revoked", "unknown"]
    assert not any(p.auto_fixable for p in problems)
    assert "no replacement" in problems[0].message()
    assert "no replacement found" in problems[1].message()
    assert "not a known ATT&CK technique" in problems[2].message()


# --- what --fix does ---------------------------------------------------------------------------


def test_fix_rewrites_only_the_technique_ids_of_affected_labels(index, tmp_path):
    path = _write(tmp_path, ("a1", ["T1001"]), ("a2", ["T2001"]), ("a3", ["T1002"]))
    before = path.read_bytes().decode().splitlines(keepends=True)

    fixed = fix_labels(path, check_labels(path, index))

    after = path.read_bytes().decode().splitlines(keepends=True)
    assert [(p.technique_id, p.successors[0]) for p in fixed] == [("T2001", "T1001")]
    assert after[0] == before[0] and after[2] == before[2]  # untouched lines are identical
    assert after[1] == before[1].replace('"T2001"', '"T1001"')  # everything else on it too
    assert check_labels(path, index) == []


def test_fix_leaves_ambiguous_ids_alone(index, tmp_path):
    path = _write(tmp_path, ("a1", ["T2003"]), ("a2", ["T2001"]))
    fix_labels(path, check_labels(path, index))
    remaining = check_labels(path, index)
    assert [(p.alert_id, p.technique_id) for p in remaining] == [("a1", "T2003")]


def test_fix_does_not_duplicate_an_id_the_label_already_has(index, tmp_path):
    path = _write(tmp_path, ("a1", ["T1001", "T2001"]))  # T2001 is now T1001 again
    fix_labels(path, check_labels(path, index))
    assert '"technique_ids": ["T1001"]' in path.read_text()


def test_fix_preserves_line_endings(index, tmp_path):
    path = _write(tmp_path, ("a1", ["T2001"]))
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    fix_labels(path, check_labels(path, index))
    assert path.read_bytes().endswith(b"}\r\n")


def test_fix_with_nothing_to_fix_does_not_touch_the_file(index, tmp_path):
    path = _write(tmp_path, ("a1", ["T2003"]))
    stamp = path.read_bytes()
    assert fix_labels(path, [Problem("a1", "T2003", "revoked", ("T1001", "T1002"))]) == []
    assert path.read_bytes() == stamp
