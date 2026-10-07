# Week 2 retro (Days 8-14, 2026-09-25 to 2026-10-04)

Draft by Mouheb on Day 14, Mouadh's side added 2026-10-05, test-split numbers filled in
2026-10-06. Week 2 was planned to end on Thu 1 Oct; it ran 5 days over (quota, review).

## What shipped

- **Week 1 gate closed:** CI (ruff + pytest on every PR, branch protection: 1 review + green
  check), frozen dev/test split (`split-v1.json`, test sealed), baseline on dev for all three
  configs, `baseline-v0` tag, error analysis (`docs/error-analysis-v1.md`), Week 1 retro.
- **Labels:** `golden-v1.1`: all 150 rows human-reviewed (116 Mouadh, 34 Mouheb + partner, 0
  `claude-draft`), 3 technique fixes; labeling guide rule 3 exception (script host in a
  user-writable folder → TP).
- **Retrieval:** BM25 + vector search, launch context (parent → child chain): alert → technique
  recall@5 0.35 → 0.65, alert → Sigma rule 0.65 → 0.75. Retrieval test set by task, probe set v3
  frozen for Week 3.
- **Triage (dev, 30 alerts):** accuracy 0.83 → 0.90-0.93, technique F1 0.58 → 0.57-0.63
  (within run-to-run noise of about ±0.05).
- **Coverage:** existing SigmaHQ rules (top 5 retrieved) catch 46/100 golden attacks: the other
  54 are the gap rule generation targets.
- **The loop, end to end:** route node + Mouadh's matcher (pySigma → SQLite, parity with
  Zircolite), rule generation (strict form → code-built YAML, self-check on its own alert), and
  Mouadh's validator (held-out attacks, benign set, 10.8k-event noise pool, lints). First live
  run through all 7 nodes on 2026-10-04.
- **Rule generation v0 (5 uncovered dev attacks):** 3 rules, 3/3 compile, 2/3 pass (pass rule
  v1), 0 benign hits. Read-out table in `docs/experiments.md`.
- **Security:** injection corpus 10 → 40 payloads (5 categories × 8), threat-model section for
  model-written rules (RG-1..RG-6).
- **Injection ASR (`asr-v1.json`, 40 payloads, no defenses, 2026-10-05):** 25% (10/40). Worst:
  tool_hijack 4/8, then fake_system_msg 3/8, context_stuffing 2/8, encoded 1/8, direct_override
  0/8. 5 successes leaked the canary (certain); 5 changed the verdict with no canary, and some of
  those may be run-to-run noise (about 4 in 30 verdicts change between identical runs).
- **ADR 0001** (partial-credit scoring, by Mouheb) and **ADR 0002** (two-tier routing, by Mouadh).

## Test split (the honest number, run once)

| | before (`baseline-v0`, rag) | after (BM25 + launch context, rag) |
|---|---|---|
| alerts | 30/30 | 30/30 |
| accuracy | 0.97 | 0.90 |
| attack recall | 0.95 (1 missed) | 0.95 (1 missed) |
| benign recall | 1.00 | 0.80 (2 benign called attacks) |
| technique F1 | 0.60 | 0.62 |
| exact primary technique | 0.55 | 0.50 |
| invented IOCs | 0.06 | 0.02 |

**Verdict: a tie, not a win.** The search gain on dev (recall@5 0.35 → 0.65) did not carry over
to triage on test: F1 +0.02 is inside the ±0.05 noise. Fewer invented IOCs, paid with 2 false
positives where a keyword in a benign event matched a technique name (`W32Time` → T1547.003,
`-Embedding` → T1021.003). Both runs miss the same PurpleSharp attack (day3-137). Hypotheses
logged in `docs/experiments.md`, to be checked on dev, not tuned on these test alerts. Chart:
`results/charts/week2.png`; raw results: `results/test/rag.json` (after),
`results/test/before-baseline-v0/rag.json` (before, run from a `baseline-v0` worktree).

Note: the test split scored higher than dev for the baseline (0.97 vs 0.83 accuracy): with 30
alerts, the split itself moves the number. Compare before/after on the same split only.

## What took longer than planned

- **Quota again.** 50 free requests a day, shared. Every live run is a daily slice; the
  injection run (about 80 requests) was killed at the 1-hour background limit with nothing saved
  (runner now writes after each case). Test split takes 2 days.
- **Retrieval research.** A week of A/B tests (SecEmbed, SecReranker, parent-child chunks) to
  keep one change (BM25). Worth it, but it pushed rule generation from Day 12 to 2 Oct.
- **Label review** finished on 27 Sep, three days into the week, and blocked `golden-v1.1`.
- **Git on a shared machine:** identities, stashes, criss-cross merges, and Claude running git
  write commands on 27 Sep (a stash hid result files mid-eval). Rule since: Claude gives the
  commands, we run them.

## What we learned

- **One change at a time, measured twice.** Run-to-run noise is about ±0.05 F1 / 4 of 30
  verdicts. Without the repeat runs we would have "kept" changes that were luck.
- **Test on real data.** Hand-written probes scored 0.93; real alerts scored 0.35 on the same
  search. Model cards measure on their authors' tests.
- **Sigma lists mean "any of".** The model wrote value lists meaning AND; our own prompt invited
  it. Fixed with an explicit `all` flag. Then it over-corrected into a fingerprint (0/7): too
  broad vs too narrow needs feedback, not instructions.
- **Errors flow downstream.** Triage's technique choice decides which attacks the validator
  compares a rule with. A retrieval miss now costs rule quality too.
- **Contract first** (signature stub + tests before the other person builds: matcher,
  validator) made the two halves fit on the first try.

## Mouheb

### What to change in Week 3

- **Plan quota per day with Mouadh** before starting any live run (who uses it, for what).
- **Run long evals in a normal terminal**, not as 1-hour background tasks.
- **Commit at the end of each task**, not after a batch of days (Day 9-11 sat uncommitted).
- **Write the experiment entry before running**, with the threshold that would make me keep it.

## Mouadh

### What took longer than planned

- **Label review** (116 rows) finished on 27 Sep, not Day 8, and held up `golden-v1.1` for
  everyone.
- **Branch out of date with main:** two PRs needed a merge of `origin/main` into `mouadh` first
  (28 and 29 Sep) to fix conflicts.
- **Injection runner fix sat in a stash** from 3 Oct to 5 Oct, on no branch, while the retro
  already counted it as done. The 40-payload run (`asr-v1.json`) only ran on 5 Oct, and its first
  5 cases failed because Docker (the Postgres tool cache) was not running.
- **Validator "same technique" positives** turned out too coarse (`day2-006`): a rule can pass
  against attacks that use a different procedure.

### What to change in Week 3

- **Merge `origin/main` into `mouadh` at the start of each day**, not when the PR conflicts.
- **No stash for unfinished work:** commit it to my branch (a WIP commit is fine) so it can't get
  lost or forgotten.
- **Plan quota per day with Mouheb** before any live run, starting with `asr-v1.json`.
- **Keep contract first** (signature + one test before building): it worked for the matcher and
  the validator.

## Week 3 plan (Days 15-21): close the loop

1. **Repair loop** (Mouheb): validator feedback (missed attacks, benign hits, lints) goes back to
   rule_gen, max 3 attempts; event values quoted as untrusted via `failed_samples[].event_ref`.
   Measure pass rate and recall on the 10 uncovered dev attacks, attempt 1 vs 3.
2. **Validator v2** (Mouadh): procedure-level positives (same technique is too coarse:
   day2-006), bigger benign set (`cmd /c`, MSBuild), "low evidence" when ≤1 held-out positive.
3. **CI eval gate** (both): a small frozen eval (stub + recorded model outputs, no quota) that
   fails the PR when scores drop below the agreed floor.
4. **Injection:** finish `asr-v1.json` (40 payloads, before any defense), batch_03
   rule-poisoning cases (TH-05..07).
5. **Triage fixes before rules:** 2 of 5 rule attempts were lost to triage errors; DCOM / T1210 /
   T1134 retrieval misses (procedure examples from ATT&CK as the next search idea).
6. **Deploy:** decide target and scope (agreed in the Week 3 guide).

Rules unchanged: tune on dev, report on test; one change at a time; no model switch mid-week.
