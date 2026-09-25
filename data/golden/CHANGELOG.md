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
