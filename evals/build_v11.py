"""Build golden-v1.1 from frozen golden-v1 plus the human review log.

    uv run python -m evals.build_v11            # dry run: print what would change
    uv run python -m evals.build_v11 --write    # write data/golden/v1.1.jsonl and sync labels.jsonl

`v1.jsonl` is frozen and never edited. `data/golden/review-log.yaml` records, per review session,
which `claude-draft` rows a human checked (`confirmed`) or corrected (`changed`). A row becomes
human-reviewed ONLY by appearing in that log: its `labeler` becomes the reviewer and `labeled_at`
the review date. Rows not in the log stay exactly as they were, byte for byte.

The build is deterministic, so it can be re-run after every review session. `labels.jsonl` (the
working pool the label guard checks) gets the same edits, so the two files never disagree.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

GOLDEN = Path(__file__).resolve().parents[1] / "data" / "golden"
V1 = GOLDEN / "v1.jsonl"
V11 = GOLDEN / "v1.1.jsonl"
LABELS = GOLDEN / "labels.jsonl"
REVIEW_LOG = GOLDEN / "review-log.yaml"

DRAFT = "claude-draft"
LABELS_ALLOWED = {"true_positive", "benign_noisy", "needs_review"}
# what a `changed` entry may edit; `why` is the reason and only lives in the log
EDITABLE = {"label": "label", "technique_ids": "technique_ids", "rationale": "rationale"}


class ReviewLogError(ValueError):
    """The review log contradicts the golden file it is applied to."""


@dataclass(frozen=True)
class Review:
    alert_id: str
    reviewer: str
    date: str
    changes: dict[str, Any]  # empty = confirmed as drafted


def load_reviews(path: Path = REVIEW_LOG) -> list[Review]:
    """Flatten the log to one Review per row; a later session replaces an earlier one."""
    sessions = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    latest: dict[str, Review] = {}
    for n, s in enumerate(sessions, 1):
        for key in ("reviewer", "date"):
            if not s.get(key):
                raise ReviewLogError(f"review session #{n} has no `{key}`")
        confirmed = list(s.get("confirmed") or [])
        changed = dict(s.get("changed") or {})
        both = set(confirmed) & set(changed)
        if both:
            raise ReviewLogError(f"session #{n}: {sorted(both)} listed as confirmed AND changed")
        for aid in confirmed:
            latest[aid] = Review(aid, s["reviewer"], str(s["date"]), {})
        for aid, edit in changed.items():
            unknown = set(edit) - set(EDITABLE) - {"was", "why"}
            if unknown:
                raise ReviewLogError(f"session #{n}: {aid} has unknown keys {sorted(unknown)}")
            changes = {EDITABLE[k]: v for k, v in edit.items() if k in EDITABLE}
            if not changes:
                raise ReviewLogError(f"session #{n}: {aid} is `changed` but changes nothing")
            latest[aid] = Review(aid, s["reviewer"], str(s["date"]), changes)
    return list(latest.values())


def apply_reviews(lines: list[str], reviews: list[Review]) -> list[str]:
    """Return `lines` with the reviewed rows rewritten; every other line is kept verbatim."""
    by_id = {r.alert_id: r for r in reviews}
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        if not line.strip():
            out.append(line)
            continue
        row = json.loads(line)
        review = by_id.get(row["alert_id"])
        if review is None:
            out.append(line)
            continue
        seen.add(review.alert_id)
        # a row this reviewer already stamped is re-applied harmlessly, so the build can be re-run
        if row["labeler"] not in (DRAFT, review.reviewer):
            raise ReviewLogError(
                f"{review.alert_id}: labeler is {row['labeler']!r}, "
                f"only `{DRAFT}` rows are reviewed"
            )
        row.update(review.changes)
        if row["label"] not in LABELS_ALLOWED:
            raise ReviewLogError(f"{review.alert_id}: label {row['label']!r} is not valid")
        row["labeler"] = review.reviewer
        row["labeled_at"] = review.date
        out.append(json.dumps(row, ensure_ascii=False))
    missing = sorted(set(by_id) - seen)
    if missing:
        raise ReviewLogError(f"review log names rows that are not in the file: {missing}")
    return out


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: Path, lines: list[str], like: Path) -> None:
    """Write with the same line endings as `like` (the Windows checkout is CRLF, git stores LF)."""
    eol = "\r\n" if b"\r\n" in like.read_bytes() else "\n"
    path.write_bytes((eol.join(lines) + eol).encode("utf-8"))


def _summary(lines: list[str]) -> str:
    rows = [json.loads(x) for x in lines if x.strip()]
    drafts = sum(r["labeler"] == DRAFT for r in rows)
    return f"{len(rows)} rows, {drafts} still `{DRAFT}`"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="write v1.1.jsonl and sync labels.jsonl")
    args = ap.parse_args()

    reviews = load_reviews()
    v1 = _read_lines(V1)
    v11 = apply_reviews(v1, reviews)
    changed = [r for r in reviews if r.changes]
    print(f"review log: {len(reviews)} rows reviewed, {len(changed)} corrected")
    for r in changed:
        edits = ", ".join(f"{k} -> {v}" for k, v in r.changes.items() if k != "rationale")
        print(f"  {r.alert_id}: {edits}")
    print(f"v1   : {_summary(v1)}")
    print(f"v1.1 : {_summary(v11)}")

    if not args.write:
        print("dry run; add --write to write files")
        return
    _write_lines(V11, v11, like=V1)
    _write_lines(LABELS, apply_reviews(_read_lines(LABELS), reviews), like=LABELS)
    print(f"written {V11.name} and synced {LABELS.name}")


if __name__ == "__main__":
    main()
