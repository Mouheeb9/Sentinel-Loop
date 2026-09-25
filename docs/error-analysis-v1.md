# Error analysis v1 (Day 9)

Source: `results/failures-<config>.md` from `uv run python -m evals.failures`, dev split only.
Labels: golden-v1.1 (fill in the `golden_sha` shown at the top of each failures file).
Each failure is read by a human and put in exactly one bucket; the hint in the card is a guess.

## Counts

| Bucket | single-prompt | rag | rag-tools | Total |
|---|---|---|---|---|
| Retrieval miss (gold technique never reached the model) | n/a | | | |
| Reasoning error (the context was there, the conclusion was wrong) | | | | |
| Schema error (no valid verdict) | | | | |
| Label error (the golden label is wrong -> fix in golden, re-score) | | | | |
| **Read** | | | | |

Rule: more than 2 label errors -> fix the labeling guide before anything else.

## Examples (2-3 per bucket)

### Retrieval miss

### Reasoning error

### Schema error

### Label error

## Top bucket -> Day 10

- Bucket:
- The one change we try:
