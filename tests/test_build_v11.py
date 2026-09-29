import json
from pathlib import Path

import pytest

from evals.build_v11 import (
    DRAFT,
    REVIEW_LOG,
    V1,
    Review,
    ReviewLogError,
    apply_reviews,
    load_reviews,
)
from evals.check_labels import TechniqueIndex, check_labels
from sentinel.retrieval.attack import DEFAULT_BUNDLE


def _row(aid: str, labeler: str = DRAFT, techniques: tuple[str, ...] = ("T1059",)) -> str:
    return json.dumps(
        {
            "alert_id": aid,
            "label": "true_positive",
            "technique_ids": list(techniques),
            "source_dataset": "x.zip",
            "rationale": "as drafted",
            "labeler": labeler,
            "labeled_at": "2026-09-21",
        }
    )


def _log(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "review-log.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_confirmed_row_becomes_human_reviewed_and_others_are_untouched():
    lines = [_row("a"), _row("b")]
    out = apply_reviews(lines, [Review("a", "Mouadh", "2026-09-27", {})])
    a = json.loads(out[0])
    assert (a["labeler"], a["labeled_at"], a["technique_ids"]) == (
        "Mouadh",
        "2026-09-27",
        ["T1059"],
    )
    assert out[1] == lines[1]  # byte for byte


def test_changed_row_gets_the_new_values():
    changes = {"technique_ids": ["T1210"], "rationale": "now correct"}
    out = apply_reviews([_row("a")], [Review("a", "Mouadh", "2026-09-27", changes)])
    row = json.loads(out[0])
    assert row["technique_ids"] == ["T1210"] and row["rationale"] == "now correct"
    assert list(row) == list(json.loads(_row("a")))  # same key order


def test_a_row_that_is_not_a_draft_cannot_be_reviewed_again():
    with pytest.raises(ReviewLogError, match="only `claude-draft`"):
        apply_reviews([_row("a", labeler="Mouheb+Partner")], [Review("a", "Mouadh", "d", {})])


def test_applying_the_log_twice_gives_the_same_result():
    reviews = [Review("a", "Mouadh", "2026-09-27", {"technique_ids": ["T1210"]})]
    once = apply_reviews([_row("a"), _row("b")], reviews)
    assert apply_reviews(once, reviews) == once


def test_log_naming_a_missing_row_fails():
    with pytest.raises(ReviewLogError, match="not in the file"):
        apply_reviews([_row("a")], [Review("zzz", "Mouadh", "d", {})])


def test_invalid_label_is_rejected():
    with pytest.raises(ReviewLogError, match="not valid"):
        apply_reviews([_row("a")], [Review("a", "Mouadh", "d", {"label": "maybe"})])


def test_confirmed_and_changed_in_one_session_is_rejected(tmp_path):
    log = _log(
        tmp_path,
        "- {reviewer: M, date: '2026-09-27', confirmed: [a],\n"
        "   changed: {a: {label: benign_noisy}}}\n",
    )
    with pytest.raises(ReviewLogError, match="confirmed AND changed"):
        load_reviews(log)


def test_changed_entry_that_changes_nothing_is_rejected(tmp_path):
    log = _log(tmp_path, "- {reviewer: M, date: '2026-09-27', changed: {a: {why: nothing}}}\n")
    with pytest.raises(ReviewLogError, match="changes nothing"):
        load_reviews(log)


def test_a_later_session_replaces_an_earlier_one(tmp_path):
    log = _log(
        tmp_path,
        "- {reviewer: M, date: '2026-09-26', confirmed: [a]}\n"
        "- {reviewer: M, date: '2026-09-27', changed: {a: {technique_ids: [T1210]}}}\n",
    )
    (review,) = load_reviews(log)
    assert review.date == "2026-09-27" and review.changes == {"technique_ids": ["T1210"]}


# --- the real log against the real frozen file --------------------------------------------------


def test_real_review_log_applies_cleanly_to_frozen_v1():
    lines = V1.read_text(encoding="utf-8").splitlines()
    out = apply_reviews(lines, load_reviews(REVIEW_LOG))
    assert len(out) == len(lines)
    drafts = lambda ls: sum(json.loads(x)["labeler"] == DRAFT for x in ls)  # noqa: E731
    assert drafts(out) == drafts(lines) - len(load_reviews(REVIEW_LOG))


@pytest.mark.skipif(not DEFAULT_BUNDLE.exists(), reason="ATT&CK bundle not downloaded")
def test_v11_techniques_are_all_live(tmp_path):
    lines = V1.read_text(encoding="utf-8").splitlines()
    path = tmp_path / "v1.1.jsonl"
    path.write_text("\n".join(apply_reviews(lines, load_reviews(REVIEW_LOG))) + "\n", "utf-8")
    assert not check_labels(path, TechniqueIndex())
