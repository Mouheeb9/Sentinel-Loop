# Week 1 retro (Days 1-7, 2026-09-18 to 2026-09-24)

Draft by Mouheb on Day 8; Mouadh adds his side before it is merged.

## What shipped

- Frozen `schemas.py` contracts, docker/pgvector skeleton, LangGraph pipeline with stubs and
  Langfuse tracing.
- Retrieval over 697 ATT&CK techniques + 3,144 Sigma rules; recall@5 0.90 / 0.95 on probe sets
  v1 / v2.
- Golden set `golden-v1`: 150 alerts (100 true_positive / 50 benign_noisy), 44 primary techniques.
- Triage agent: untrusted fields fenced, forced tool call, NVD/ThreatFox lookups behind an
  allow-list, two-tier routing.
- Eval runner (3 configs, resumable, fingerprinted) + scorers (partial-credit technique F1,
  hallucinated-IOC rate); first attack-success rate: 20% (2/10 payloads).

## What took longer than planned

- **Model quota.** No paid API; the OpenRouter free tier gives 50 requests/day shared by both of
  us. The baseline needs ~600-900 requests, so it runs as a daily slice instead of one run.
  As of Day 8: single-prompt done (dev, n=30: accuracy 0.87, technique F1 0.47), rag 7/30,
  rag-tools not started.
- **Labeling.** Mining 150 alerts from single-technique captures needed many captures (each holds
  only 1-4 real attack events), and ATT&CK renumbered several techniques mid-week
  (`check_labels` now guards this).
- **Retrieval index** build: ~45 min on CPU.

## What we cut or changed

- Full 150-alert baseline -> 30-alert dev split (`data/golden/split-v1.json`) + 30-alert sealed
  test split. Tune on dev, report on test once (Day 13-14).
- Lexical leg of hybrid retrieval: off by default (lost to vector-only under RRF).

## Known debts moved to Week 2

- 77 golden rows are still `labeler: claude-draft` (not human-reviewed): Mouadh, Day 8-9 ->
  `golden-v1.1`. Risk: a Claude-drafted label scoring a model's answer.
- Retrieval probe sets v1 and v2 are spent (tuned against); v3 from real alert behavior needed
  before any more retrieval tuning (Day 11).
- Baseline incomplete (quota); chart in README once all three configs finish on dev.
- Day 6 ASR is on 10 payloads only; corpus grows to 40 on Day 10.

## Mouadh

- _What took longer than planned:_
- _What to change in Week 2:_
