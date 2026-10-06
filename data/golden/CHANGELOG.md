# Golden set changelog

Frozen versions are never edited. Any change is a new version plus a line here.

## v1 (2026-09-21)

- `v1.jsonl`: 150 rows = 100 true_positive (44 distinct primary techniques) + 50 benign_noisy.
- Built from `labels.jsonl` (working pool): all `needs_review` rows excluded (23), plus 5 redundant
  unreviewed benign rows dropped (day3-055, 080, 162, 167, 178).
- Human-reviewed: the 40 day2 rows and day3-101..150 (reviewed with Mouadh; 127/129/133/138 -> needs_review,
  118 -> T1003.002, 113 -> T1003).
- NOT yet human-reviewed: 77 day3 rows outside 101..150 (45 true_positive, 32 benign_noisy), still
  `labeler: claude-draft`. Reviewed on 2026-09-21 by reading the rationales; kept as drafted. Corrections go to v2.

## v1.1 (in progress, built from v1 + review-log.yaml)

- `v1.1.jsonl` is `v1.jsonl` plus `data/golden/review-log.yaml`; `v1.jsonl` is untouched. Rebuild with
  `uv run python -m evals.build_v11 --write` (also syncs `labels.jsonl`). A row counts as human-reviewed
  ONLY if it is in the log; its `labeler` becomes the reviewer and `labeled_at` the review date.
- 2026-09-26/27, Mouadh reviewed 83 rows. First 22 (the 21 dev-split drafts + day3-163) checked against the raw
  events in session: 19 confirmed, 3 corrected: day3-048 T1134.001 -> T1134, day3-163 T1134.001 -> T1134
  because the event shows the pipe, not the impersonation, and day3-113 T1003 -> T1210 for
  `lsadump::zerologon /exploit`), then the other 61 unreviewed drafts, confirmed unchanged on his
  attestation (not re-checked row by row in session).
- The last 33 (day3-101..150, reviewed with Mouadh on 2026-09-21 per the v1 notes, `labeler` never updated) are
  stamped `Mouadh` / 2026-09-21 on his confirmation of 2026-09-27; no label changed.
- v1.1: 150 rows, 116 human-labeled by Mouadh (83 + 33), 34 by `Mouheb+Partner`, 0 `claude-draft`. 3 labels
  changed in total (048, 163, 113). Not tagged yet.

## procedures.yaml (2026-10-06, validator v2)

- New file `procedures.yaml`: groups golden true_positive alerts by procedure (HOW, not WHAT) for
  validator v2. Labels in `v1.1.jsonl` are untouched. 80 rows (every TP whose primary technique has
  >=2 golden TPs), 47 procedures; 12 can test a rule on another capture with the same log source.
  Drafted from the v1.1 rationales, verified by Mouadh against the events on 2026-10-06.
