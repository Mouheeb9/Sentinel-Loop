# Sentinel Loop

Sentinel Loop is a closed-loop detection engineering system: an alert comes in, a multi-agent
pipeline triages it, maps it to MITRE ATT&CK, and for real threats with no existing coverage,
writes a Sigma rule, validates it against labeled telemetry, measures its false-positive rate,
and opens a PR — merged only if it passes an automated eval gate in CI. Its differentiator is
treating log fields as attacker-controlled input: a red-team suite attacks the pipeline through
indirect prompt injection, measures attack success rate, the agent is hardened, and the
before/after curve is published against the OWASP LLM Top 10.

Built by Mouheb (AI/agent engineering) and **Partner** (detection engineering / AI security).

## Status

Week 1, Day 3 — retrieval corpus (ATT&CK + Sigma) and the golden-dataset labeling grind.

## Golden dataset: how we measured labeling quality

The eval harness is only as trustworthy as its labels, so the first 40 alerts were labeled
independently by two people (one AI engineer, one detection engineer) before comparing.

- **Initial disagreement rate: 7 of 40 (17.5%).**
- Every disagreement was resolved by amending the labeling guide rather than picking a winner,
  which produced 4 written rules, for example: OS bookkeeping triggered as a side effect of
  nearby activity is `benign_noisy`; a bare "program was launched" record with no follow-on
  evidence is `needs_review`, not a guess either way.
- Final composition of the first 40: 10 `true_positive`, 24 `benign_noisy`, 6 `needs_review`.
- Batch 2 (138 more alerts, mined from 56 further OTRF captures by `evals/mine_candidates.py`) brings
  the set to 178: 104 `true_positive` across 45 distinct techniques, 55 `benign_noisy`,
  19 `needs_review`. These rows are drafts (`labeler: claude-draft`) pending human review, and
  the set is not frozen (`golden-v1`) until that review is done.

The three labels are `true_positive`, `benign_noisy` (an actor doing its normal job that still
looks suspicious) and `needs_review` (no evidence either way).

## Retrieval: how we know it works

The triage agent grounds its answers in an index over two corpora: **ATT&CK Enterprise** (697
live techniques, one chunk each, with detection guidance) and **SigmaHQ** (3,144 rules, one chunk
each). Chunks are embedded with Jina v2 base (768 dims, 8,192-token window, so nothing is
truncated) and stored in pgvector with an HNSW index. `retrieve()` combines vector search, metadata
filters (platform, logsource, kind) and exact ATT&CK IDs pinned to the top.

Before any prompt tuning, retrieval was measured on its own with **recall@5**: for a hand-written
description of a behavior, is the right technique among the top 5 results? The probe sets were
frozen (hashed) before any search ran, and scored strictly (exact technique ID, no parent credit).

| Probe set | Vector + ID pin (default) | Hybrid (+ keyword leg) |
|---|---|---|
| 20 probes (v1) | **0.90** | 0.75 |
| 20 held-out probes (v2) | **0.95** | 0.90 |

- The Day 3 target of 0.80 is met. Queries that name a tool (`vssadmin`, `wevtutil`) score 1.00;
  purely descriptive queries are the weak spot.
- **The keyword leg did not earn its place.** The first hybrid version scored 0.80 on v1. Reworking
  it (rare words only, IDF-weighted) and testing on the held-out v2 set left it below plain vector
  search on both sets, so it is off by default. Reason: when results are merged by rank, a chunk
  found by both lists beats the correct chunk found by only one. To be re-tested in Week 2 on
  queries built from real alerts.
- 40 probes is a small sample (one probe is 2.5 to 5 points), so the direction is reliable and the
  size of the gap is not. Both sets are now spent for tuning; further work needs a fresh set.
- ATT&CK renumbers techniques between releases (e.g. `T1562.002` became `T1685.001`), which would
  make a label silently unmatchable. `evals/check_labels.py` and a guard test fail on any dead ID
  in the golden labels and can rewrite unambiguous ones.

Raw results: `evals/results/`. Probe files and scoring rules: `evals/retrieval_probes*.yaml`.

## Setup

```bash
uv sync
docker compose up -d
cp .env.example .env   # fill in ANTHROPIC_API_KEY, LANGFUSE_* keys
uv run pytest
```

Retrieval corpora are downloaded on demand and not committed (`data/raw/` is gitignored):

```bash
mkdir -p data/raw/attack
curl -sSL -o data/raw/attack/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git data/raw/sigma/repo
git -C data/raw/sigma/repo sparse-checkout set rules

uv run python -m sentinel.retrieval.index   # embeds 3,841 chunks; ~45 min on CPU, resumable
uv run python -m evals.retrieval_eval --probes evals/retrieval_probes_v2.yaml
uv run python -m evals.check_labels         # golden labels must use live ATT&CK technique IDs
```
