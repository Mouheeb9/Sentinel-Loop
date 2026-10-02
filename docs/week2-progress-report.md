# Sentinel Loop: progress report, Day 8 to now (25-30 Sep 2026)

Written 2026-09-30. Covers Week 2 so far, for Mouheb (AI side) and Mouadh (security side).
Hard words are explained in the glossary at the end.

---

## 1. The short version

- **Week 1 is closed.** The baseline (the "before" numbers) is measured on all three setups, the
  eval is protected against cheating by accident (dev/test split), and CI checks every pull request.
- **All 150 golden labels are now human-reviewed** (golden-v1.1, Mouadh). Before, 77 were drafts
  written by Claude.
- **The search got much better.** On real alerts, the right ATT&CK technique is in the top 5
  results for **65%** of attacks, up from **35%**. Main cause: adding BM25 keyword search next to
  the vector search. A small extra gain came from "launch context".
- **Triage accuracy went from 0.83 to about 0.90-0.93**, but on 30 alerts this is close to the
  luck level. We measured the luck (same setup run twice) to know what counts as real.
- **Tried and dropped:** smaller technique chunks, two security embedding models (SecEmbed), and a
  security reranker (SecReranker). All measured, none helped, all removed.
- **Mouadh built the injection test set (40 attacks) and the Sigma matcher** (runs a rule on an
  alert). The matcher is pushed but not merged into `main` yet.
- **Not started yet: rule generation** (the AI writing a Sigma rule), the core of Week 3.
- **Schedule:** calendar says Day 13 of 14; real progress is about Day 11-12. We are about 2 days
  behind on the rule-writing loop, ahead on measurement quality.

---

## 2. Day by day

### Day 8 (Fri 25 Sep): close Week 1

**Mouheb**
- **CI** (`.github/workflows/ci.yml`): GitHub runs lint (`ruff check`), format check
  (`ruff format --check`) and all tests on every pull request. No model calls, no database, no
  secrets. Database tests skip themselves on GitHub.
- **Dev/test split** (`evals/split.py`, `data/golden/split-v1.json`):
  - **dev** = the 30 alerts the baseline runs on. We may read their failures and tune on them.
  - **test** = 30 other alerts, never looked at, run once at the end (Day 14).
  - Both have 20 attacks + 10 benign. The file has a content hash, so moving an alert between dev
    and test is detected. `--split test` refuses to run without `--unseal-test`.
- `--split dev|test` added to the eval runner (`evals/run.py`).
- **Tag `baseline-v0`** pushed: the exact code of the "before" numbers.
- **Week 1 retro** drafted (`docs/week1-retro.md`). Mouadh's section is still empty.
- Fixed on the way: ruff was also reformatting the Notion export markdown (excluded it); a stale
  README count.

**Mouadh**
- Reviewed all 77 draft labels. Result: **golden-v1.1** (`data/golden/v1.1.jsonl`), 3 technique
  fixes (day3-048 and day3-163 T1134.001 -> T1134, day3-113 T1003 -> T1210). Every change is in
  `data/golden/CHANGELOG.md` and `data/golden/review-log.yaml`, built by `evals/build_v11.py`.

**Git trouble that day:** PR #3 showed a conflict on GitHub (not locally) because of a "criss-cross"
history (two common ancestors). Fixed by merging `main` into `Mouheb` locally.

### Day 9 (Sat 26 Sep): read the failures

**Mouheb**
- **Failure reader** (`evals/failures.py`): writes `results/failures-<config>.md`, one card per
  wrong answer with the event, the label and why, the model's answer and reasoning, what the search
  returned, and the trace link. It also guesses the cause:
  - "retrieval miss?" = the right technique was not in the search results at all;
  - "reasoning error?" = it was there and the model still got it wrong.
- Template for the joint session: `docs/error-analysis-v1.md`.

**Mouadh**
- Updated the labeling guide with two new rules: "tag what the event shows, not what the tool is
  known for" and "wrapper events" (`cmd.exe /c <something>`).

**Not done:** the joint session that fills `docs/error-analysis-v1.md` with counts per bucket.

### Day 10 (Sun 27 - Mon 28 Sep): one fix at a time, measured

This became the biggest part of the week. See section 3 for the numbers.

**Mouheb**
- Finished the baseline on dev (all three setups, 30 alerts each) after several days of free quota.
- Switched scoring to golden-v1.1.
- Built a **retrieval test on real alerts** (`evals/retrieval_golden.py`), no model calls, split
  into 6 question types. It showed the old hand-written test questions were far too easy (0.93)
  compared with real alerts (0.35).
- Tested, one at a time: smaller technique chunks, the old keyword leg, SecEmbed-small,
  SecEmbed-base, **BM25**, SecReranker. Only BM25 helped. Everything else was removed.
- Ran triage with BM25 on dev, then **ran it a second time to measure luck**.
- Log of every experiment, kept or dropped: `docs/experiments.md`.

**Mouadh**
- **Injection test set to 40 attacks** (`injection/cases/batch_02.json`, 5 categories x 8),
  mapped to OWASP LLM01 and to the log field each attack enters through. Checked with the stub
  (fake model). The live attack-rate run (about 80 model requests) is not done yet.
- PR #2 (golden-v1.1 + 40 injection cases) merged into `main`.

### Day 11 (Tue 29 Sep, started early on the 26th): the route node and the matcher

**Mouheb** (done early, on Day 9's date)
- **`route_live`**: after triage says "attack", it runs the retrieved Sigma rules on the alert's
  event. If one fires, the alert is "covered" and the loop stops; otherwise it goes to rule
  generation. No model call. Files: `src/sentinel/validation/coverage.py`, `rules.py` (finds a
  rule's YAML by its ID in the SigmaHQ copy), `graph/nodes.py`.
- It records "unknown" instead of crashing or lying when no matcher is available.
- `evals/coverage.py`: measures how many golden attacks an existing public rule already catches.
  **Not run yet**: it needs Mouadh's matcher on the same branch.
- CI fix (`394b0a3`): one test needed the ATT&CK file, which is not on GitHub.
- PR #3 (all of Mouheb's work since Day 8) merged into `main`.

**Mouadh**
- **Sigma matcher** (`src/sentinel/validation/matcher.py`): turns a Sigma rule into SQL (pySigma,
  the same engine Zircolite uses) and runs it on the alert's events in an in-memory database.
  Milliseconds per rule, nothing written to disk. Same results as Zircolite on 32 golden events
  (35 rules, 44 hits). 10 tests. **Pushed on `mouadh`, no PR yet.**

### Day 12-13 (Tue 29 - Wed 30 Sep)

**Mouheb**
- **Launch context**: turns the parent -> child process chain into one plain sentence (for example
  "started by services.exe = run as a Windows service"), added to the search text and to the
  prompt. Fixed rules, no model call. Measured on retrieval and on triage, twice.
- Not started: **rule generation v0**.

**Mouadh**
- Not started: probe set v3, rule validator.

---

## 3. Results

### 3.1 Triage (the AI's verdict), dev split, 30 alerts, golden-v1.1 labels

| Setup | Accuracy | Technique F1 | Exact technique | Invented IOCs |
|---|---|---|---|---|
| single-prompt (model alone) | 0.87 | 0.42 | - | 0.13 |
| rag, vector search (baseline) | 0.83 | 0.58 | 0.60 | 0.15 |
| rag-tools (baseline) | 0.93 | 0.57 | - | 0.15 |
| rag + BM25, run 1 / run 2 | 0.90 / 0.90 | 0.62 / 0.59 | 0.60 / 0.55 | 0.12 / 0.16 |
| rag + BM25 + launch context, run 1 / run 2 | 0.90 / 0.93 | 0.63 / 0.57 | 0.65 / 0.60 | 0.16 / 0.11 |

How to read it:
- **Luck level:** the same setup run twice changed 4 of 30 verdicts and moved F1 by 0.03. So a gap
  smaller than about 0.07 accuracy or 0.05 F1 is not proof.
- Accuracy went 0.83 -> about 0.90-0.93. Consistent across 4 runs, but small.
- A model that always says "attack" would get 0.67 accuracy on this set; the weak number is still
  the technique F1 (about 0.60).
- The "invented IOC" rate is mostly the model dropping backslashes (`C:Users...`), not real
  invention. To fix in the scorer or the prompt.
- Tools (NVD, ThreatFox) were used on 1 alert out of 23: our alerts are Windows endpoint events
  with almost no CVEs or public IPs. The tools will matter for cloud alerts later.

### 3.2 Retrieval (the search), dev split, no model, no luck

Is the right answer in the top 5? (recall@5)

| Question type | Vector only (start) | + BM25 | + launch context (now) |
|---|---|---|---|
| alert -> technique | 0.35 | 0.60 | **0.65** |
| alert -> Sigma rule | 0.65 | 0.70 | **0.75** |
| command line -> technique | 0.42 | 0.53 | 0.53 |
| Sigma fields -> rule | 0.50 | 0.50 | 0.50 |
| plain-English text -> technique | 0.93 | 0.90 | 0.90 |
| plain-English text -> rule | 0.93 | 0.93 | 0.93 |

MRR (how high the first right answer is) for alert -> technique: 0.27 -> 0.34 -> 0.43.

### 3.3 What we tried and dropped (all in `docs/experiments.md`)

| Idea | What it is | Result |
|---|---|---|
| Old keyword leg | rare-word matching, merged with vector search | +1 alert = luck. Off. |
| Smaller technique chunks (parent-child) | search small pieces, return the whole technique | No gain; same "hub" results on top. Removed. |
| SecEmbed-small / SecEmbed-base | embedding models trained on security text | Worse than Jina on almost every question type (0.53-0.60 vs 0.93 on plain text). Checked it was not a setup bug. Removed. |
| SecReranker | second model that re-sorts the top 50 | Undid most of BM25's gain (0.60 -> 0.40) and slow on CPU. Removed. |
| **BM25** | classic keyword search (rare words count more) | **Kept: 0.35 -> 0.60.** |
| **Launch context** | parent -> child chain as a sentence | **Kept:** small search gain, fixed day3-176, no harm. |

Lesson: a model page's score is measured on its author's own test. Only your own test counts.

---

## 4. Where the code and the data are

| What | Where |
|---|---|
| Eval runner (triage) | `evals/run.py` (`--split dev`, `--run NAME` -> `results/NAME/`) |
| Dev/test split | `evals/split.py`, `data/golden/split-v1.json` |
| Failure reader | `evals/failures.py` -> `results/failures-*.md` |
| Retrieval test | `evals/retrieval_golden.py` -> `results/retrieval/` |
| Coverage test | `evals/coverage.py` (waits for the matcher) |
| BM25 search | `src/sentinel/retrieval/bm25.py`, used in `search.py` |
| Launch context | `src/sentinel/agents/enrich.py` (`launch_context`) |
| Route node | `src/sentinel/graph/nodes.py` (`route_live`), `src/sentinel/validation/` |
| Matcher (Mouadh) | `src/sentinel/validation/matcher.py` on `mouadh` |
| Injection set (Mouadh) | `injection/cases/batch_01.json`, `batch_02.json`, `taxonomy.md` |
| Golden labels | `data/golden/v1.1.jsonl`, `CHANGELOG.md` |
| Experiment log | `docs/experiments.md` |

Tests: 219, all passing. CI green on `main`.

---

## 5. Git and GitHub state (30 Sep)

- `main` has everything from both of you up to 29 Sep: PR #2 (Mouadh: golden-v1.1 + 40 injection
  cases) and PR #3 (Mouheb: Day 8-11 + BM25) are merged.
- `Mouheb`: 1 commit after that (launch context, `70351ca`).
- `mouadh`: the matcher (`959e262`) needs a PR into `main`.
- Tags: `golden-v1`, `baseline-v0`. **Missing: `golden-v1.1`** (Mouadh).
- **Branch protection on `main` is still off.**
- **Contribution graph:** commits count only once on `main` and only if the commit email is added
  and verified in GitHub -> Settings -> Emails (`mouhebbezi5@gmail.com`). The first 4 commits used
  a typo address (`@gamil.com`) and can't be linked.
- The shared machine was left with Mouadh's git identity once; check `git config user.email`
  before committing.

---

## 6. What is left

**This week (Day 12-14)**
| Who | Task |
|---|---|
| Mouadh | PR for the matcher; tag `golden-v1.1`; retro section; probe set v3; live attack-rate run on 40 cases (quota) |
| Mouheb | Run `evals/coverage.py` once the matcher is merged (README number); **rule generation v0** |
| Mouadh | Rule validator (compile + true/false positives on labeled data) |
| Both | Error-analysis session -> `docs/error-analysis-v1.md` (1 hour); Day 13 pairing: the whole loop end to end on real alerts |
| Both | Day 14: run once on the sealed test split, the honest final number |
| Mouheb | Turn on branch protection; add the Gmail address to GitHub |

**Known problems to fix later**
- The "invented IOC" metric counts dropped backslashes as invented.
- `uv sync` uninstalls Zircolite (not in the dependency list).
- Free model quota: 50 requests a day, shared. Every triage run takes 1-2 days.

---

## 7. What went wrong (and the rule we took from it)

- **Claude ran git commands (merge, stash) without asking** on 27 Sep. A stash hid result files
  while an eval was running, which cost quota. Rule since then: Claude never runs git write
  commands; it gives the commands.
- **Three changes at once** was proposed for retrieval; we changed one thing at a time instead,
  which is how we know BM25 is the thing that worked.
- **Hand-written test questions were too easy** (0.93 vs 0.35 on real alerts). Test on real data.

---

## 8. Glossary

- **Baseline:** the "before" numbers, measured before any improvement.
- **Dev / test split:** dev = alerts you may study and tune on; test = alerts kept sealed for the
  final honest number.
- **CI:** GitHub runs the tests automatically on every pull request.
- **Retrieval / search:** finding the ATT&CK techniques and Sigma rules related to an alert, to
  show them to the AI.
- **Embedding / vector search:** a model turns text into numbers so texts with similar meaning can
  be found. Our model: Jina v2.
- **BM25:** keyword search. A text scores higher when it has the question's words often and when
  those words are rare overall (`comsvcs.dll` counts more than `process`).
- **RRF:** a way to merge two ranked lists: each item gets points for how high it is in each list.
- **Reranker:** a second, slower model that re-sorts the top results by reading question and
  candidate together.
- **recall@5:** is a right answer in the top 5? **MRR:** how high the first right answer is.
  **NDCG@5:** how well ordered the top 5 is.
- **Accuracy:** share of alerts with the right verdict (attack / benign / needs review).
- **Technique F1:** how right the ATT&CK technique IDs are, with partial credit.
- **Noise / luck:** how much results move when you run the exact same thing twice.
- **Golden set:** the 150 alerts with human-checked right answers.
- **Route node / coverage:** the step that checks whether an existing Sigma rule already catches
  the attack; coverage = the share of attacks already caught.
- **Matcher:** code that runs one Sigma rule on an alert's events and says which events it fires on.
- **Injection / ASR:** attacks hidden in log fields that try to trick the AI; ASR = attack success
  rate, the share of those attacks that work.
