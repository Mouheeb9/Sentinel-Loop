# Experiments log

One change per row, measured on the **dev** split only (test stays sealed until Day 13-14).
A reverted change is still a row. Retrieval rows cost no model quota:
`uv run python -m evals.retrieval_golden [--lexical] --label <name>` -> `results/retrieval/<name>-dev.json`.

Noise: dev has 20 true positives, so one alert = 0.05 of recall. A change must move recall@5 by
more than ~0.10 (2 alerts) to count.

## Retrieval (20 dev attacks, golden-v1.1)

| # | Date | Change | Embedding | Tech recall@5 | @10 | @20 | MRR | Rule recall@5 | Kept? |
|---|---|---|---|---|---|---|---|---|---|
| R0 | 2026-09-27 | Baseline: vector-only, 1 chunk per technique / rule | jina-v2-base-en | 0.35 | 0.60 | 0.60 | 0.27 | 0.65 | baseline |
| R1 | 2026-09-27 | + lexical leg under RRF (`--lexical`) | jina-v2-base-en | 0.40 | 0.55 | 0.65 | 0.31 | 0.60 | no: +1 alert = noise |
| R2 | 2026-09-27 | Technique parts: description groups (~600 chars) + 1 per detection analytic, header `T.. Parent: Name`, best part ranks the technique (`--parts`, 3,525 parts) | jina-v2-base-en | 0.40 | 0.45 | 0.55 | 0.28 | 0.65 | no: +1 at @5 is noise, worse at @10/@20 |

Observations from R0:
- 7 of the 13 misses are not in the top 20 at all: a reranker alone can't fix those; the search
  has to find them first (chunking / query / model).
- The same few chunks show up in almost every top 5 (`T1218.014`, `T1218.003`, `T1555.004`,
  `T1547.001`) whatever the alert: "hub" chunks that are close to every query.
- The hand-written probe sets scored 0.90-0.95 recall@5 on the same index: they were much easier
  than real alert queries, which is why this eval replaces them.

Observations from R2:
- Chunking was not the cause: the same hub techniques (`T1218.014`, `T1218.003`, `T1547.001`)
  still lead almost every result list, with small parts as with whole techniques.
- So the mismatch is between the query and the corpus: the query is raw telemetry (paths,
  command lines, registry keys), the corpus is prose. Next candidates, one at a time: a corpus
  closer to telemetry (ATT&CK procedure examples), or a different embedding model.
- The parts code was removed on 2026-09-27 (it didn't help any model either, see B/C).

## Retrieval A/B by question type (from 2026-09-27)

`evals/retrieval_golden.py` now scores six question types separately (see its docstring).
Text tasks: the 40 frozen probes v1+v2. Alert tasks: the 20 dev attacks (19 have a command line).
Cells: recall@5 / recall@10 / MRR / NDCG@5.

| Setup | text->attack | text->sigma | alert->attack | alert->sigma | command->attack | fields->sigma |
|---|---|---|---|---|---|---|
| A: jina-v2, vector only (R0) | .93/.95/.72/.70 | .93/.93/.71/.59 | .35/.60/.27/.27 | .65/.65/.51/.31 | .42/.53/.34/.35 | .50/.60/.44/.24 |
| jina-v2 + old keyword leg (R1, not real BM25) | .82/.95/.65/.64 | .82/.95/.68/.48 | .40/.55/.31/.31 | .60/.70/.35/.23 | .47/.53/.43/.43 | .35/.65/.31/.19 |
| B: SecEmbed-small, whole techniques (256 tokens) | .60/.70/.50/.48 | .82/.93/.63/.47 | .35/.40/.25/.27 | .40/.50/.23/.16 | .42/.47/.29/.32 | .35/.50/.31/.20 |
| B + technique parts (parent-child) | .72/.80/.58/.56 | .82/.93/.63/.47 | .25/.25/.18/.19 | .40/.50/.23/.16 | .26/.42/.19/.19 | .35/.50/.31/.20 |
| C: SecEmbed-base, whole techniques (256 tokens) | .53/.60/.41/.41 | .62/.72/.39/.24 | .30/.35/.21/.22 | .50/.50/.32/.20 | .37/.37/.25/.28 | .55/.70/.39/.25 |
| C + technique parts (parent-child) | .42/.57/.33/.31 | .62/.72/.39/.24 | .30/.30/.28/.28 | .50/.50/.32/.20 | .32/.32/.29/.30 | .55/.70/.39/.25 |
| BM25 alone (`--bm25 --no-vector`) | .75/.80/.66/.64 | .80/.90/.65/.44 | .40/.60/.34/.33 | .65/.65/.43/.28 | .47/.63/.35/.37 | .60/.65/.40/.26 |
| **D: BM25 + Jina (RRF)** (`--bm25`) | .90/.93/.70/.69 | .93/.97/.73/.51 | **.60/.65/.34/.40** | .70/.75/.52/.31 | .53/.58/.39/.42 | .50/.60/.41/.26 |
| F: D + SecReranker on the top 50 (`--bm25 --rerank`) | .90/.95/.70/.69 | .82/.95/.68/.49 | .40/.55/.31/.32 | .65/.65/.49/.30 | .37/.53/.36/.35 | .55/.55/.42/.24 |

Reading A: the search is good on clean English descriptions (0.93) and weak on real alerts
(0.35-0.65). The gap is the problem to solve, not the text tasks.

Reading B and C (2026-09-27): both SecEmbed models lose to Jina on almost every question type,
including plain-English descriptions (0.53-0.72 vs 0.93). Checked it isn't a setup error: vectors
are normalized, and a brute-force ranking in numpy gives exactly the database's order (10/10).
The model card's 0.97 recall@5 was measured on the author's own test set; it doesn't carry over
to our questions. Removed on 2026-09-27 (code, PyTorch dependency, model files, indexes).

Reading D (2026-09-27): first real gain. alert->attack recall@5 0.35 -> 0.60 (+5 of 20 alerts, well
above the ~0.10 noise), command->attack 0.42 -> 0.53, text questions unchanged (0.90-0.93). BM25
alone is already better than Jina alone on alerts (0.40): exact words like `comsvcs.dll` matter,
and the two searches find different right answers, so merging them helps. Made the pipeline
default on 2026-09-27 (`search.USE_BM25 = True`); triage re-measured on dev with
`uv run python -m evals.run --split dev --configs rag --run bm25` (results/bm25/).

Reading F (2026-09-27): the reranker undoes most of D's gain on alerts (alert->attack 0.60 -> 0.40,
command->attack 0.53 -> 0.37) and is slow on CPU (~12,000 question/candidate pairs took over 10
minutes; about 2-3 s added per alert). Not kept; code removed. D stays the best setup.

Flags in the table above are from the time of each run. Today `evals/retrieval_golden.py` runs D
by default; `--no-bm25` gives A, `--no-vector` gives BM25 alone.

## Triage with BM25 + vector search (dev, 30 alerts, `results/bm25/`)

| Config | Search | Accuracy | Technique F1 | Exact primary technique | Hallucinated-IOC rate |
|---|---|---|---|---|---|
| rag (baseline, `results/`) | vector only | 0.83 | 0.58 | 0.60 | 0.15 |
| rag (`results/bm25/`) | vector + BM25 | 0.90 | 0.62 | 0.60 | 0.12 |

3 verdicts fixed (day2-014, day3-071, day3-095), 1 broken (day3-048). Every number moved the right
way, but on 30 alerts one alert = 0.033: +0.07 accuracy is 2 alerts net, at the edge of noise.
The retrieval gain (0.35 -> 0.60) is the solid result; the triage gain is consistent with it but
small. Kept.

### Noise: same config run twice (`results/bm25-repeat/`, 2026-09-28)

| Run | Accuracy | Technique F1 | Exact primary technique | Hallucinated-IOC rate |
|---|---|---|---|---|
| rag + BM25 (`results/bm25/`) | 0.90 | 0.62 | 0.60 | 0.12 |
| rag + BM25, repeat (`results/bm25-repeat/`) | 0.90 | 0.59 | 0.55 | 0.16 |

Same code, same prompt (2edd88418b70), same alerts. The headline accuracy is identical, but 4 of
30 verdicts flipped (day2-031, day3-048, day3-071, day3-095; they cancel out) and 9 technique lists
changed. So the per-alert churn is ~13% of verdicts, and the aggregate noise is about
0.03 F1, 0.05 exact-primary, 0.04 IOC rate. Consequences:
- The BM25 triage gain over vector-only (+0.07 accuracy, +0.02 to +0.05 F1) is **within noise**
  for F1 and borderline for accuracy (both BM25 runs 0.90 vs 0.83 is consistent, 2 alerts).
  BM25 stays because of the retrieval eval, where it is deterministic (no model sampling).
- Two of the flipping alerts (day3-071, day3-095) are the ones BM25 "fixed": they are unstable,
  not fixed. Future triage changes must beat ~0.07 accuracy / ~0.05 F1 on dev to count, or be
  run twice.
