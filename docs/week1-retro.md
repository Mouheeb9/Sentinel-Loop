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

- 77 golden rows were still `labeler: claude-draft` (not human-reviewed). Done 2026-09-27:
  Mouadh reviewed them all -> `golden-v1.1` (3 technique fixes).
- Retrieval probe sets v1 and v2 are spent (tuned against); v3 from real alert behavior needed
  before any more retrieval tuning (Day 11).
- Baseline incomplete (quota). Done 2026-09-27: all three configs finished on dev.
- Day 6 ASR is on 10 payloads only; corpus grows to 40 on Day 10.

## Mouadh

### What took longer than planned

- **Reviewing the golden labels.** 138 rows were drafted fast (`claude-draft`), but checking each
  one against its capture, the labeling guide and the current ATT&CK release took days. I tagged
  `golden-v1` on Day 4 with 77 rows still unreviewed; the full review (`golden-v1.1`, 3 technique
  fixes) only finished on 2026-09-27, three days into Week 2.
- **ATT&CK renumbering.** Several defense-evasion techniques moved mid-week (T1562.002 ->
  T1685.001, T1070.001 -> T1685.005, ...) and tactics changed (`stealth`, `defense-impairment`).
  Labels, the threat model and the scorers' tactic map all had to follow.
- **The Day 6 attack-success number.** The first `results/asr-day6.json` came from the stub
  pipeline (ASR 0.0, "not wired yet"); the real run (20%, 2/10) was only done on Day 7.
- **Git on a shared machine.** Switching identities, stashing Mouheb's work, and criss-cross
  merges (two merge bases) that GitHub showed as conflicts while local git merged clean cost time
  on almost every handoff.
- **Model quota.** The live injection run competes with Mouheb's baseline for the same 50
  free requests a day, so it waits.

### What to change in Week 2

- **Label in small daily batches, and never tag a golden set with unreviewed rows.** A tag means
  "human-reviewed"; `check_labels` + `labeler` must say so before tagging.
- **Never commit a result file without checking it came from the live pipeline** (model name and
  non-stub outputs in the file).
- **Push my branch at the end of every session and merge `origin/main` into it before opening a
  PR,** so PRs stay small and the criss-cross conflict doesn't come back.
- **Agree the quota day with Mouheb in advance** for any live run (the 40-case ASR run needs ~80
  requests: two days).
- **Write the contract first** (signature stub + tests, like the matcher and validator) before
  building on each other's code: it worked well on Day 11-12.
