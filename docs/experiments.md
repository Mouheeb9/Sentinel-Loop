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

## Launch context: the parent -> child chain as a sentence (2026-09-29)

Failure reading of the two BM25 runs: 6-7 of 8 failures were retrieval misses, and in the one
prompt failure (day3-176) the right technique (T1569.002) was in the context but the model tagged
the command (cmd/PowerShell) instead of how it was started (services.exe). The parent image and
command line were already in the search query, but two file paths say nothing about the mechanism.

Change (one idea, two places): `enrich.launch_context(event)` turns the parent -> child chain into
one fixed sentence (services.exe = run as a service, w3wp.exe = web server worker, wmiprvse.exe =
WMI, wsmprovhost.exe = WinRM, -Embedding / DcomLaunch = DCOM, Task Scheduler, Office parent).
Fixed rules, no model call; services.exe only on its real System32 path (masquerading). It is
put (1) at the start of the search query and (2) as a `LAUNCH CONTEXT` line in the prompt, plus
one system-prompt rule: read the chain, the launch mechanism is often the primary technique.
The run fingerprint now also hashes the user-message layout and the search query.

Reach: 30 of 178 golden alerts get a context (16 TP, 14 benign_noisy, so it must not push
benign service/DCOM/task activity to true_positive). On dev: day3-095 (w3wp -> T1190),
day3-176 (services.exe -> T1569.002), day3-165 (benign, DCOM: watch for a false positive).

Retrieval (deterministic, `results/retrieval/before-launch-dev.json` -> `launch-context-dev.json`):

| Task | R@5 | R@10 | MRR | NDCG@5 |
|---|---|---|---|---|
| alert->attack | .60 -> **.65** | .65 -> .70 | .34 -> **.43** | .40 -> .48 |
| alert->sigma | .70 -> **.75** | .75 -> .75 | .52 -> .56 | .31 -> .33 |
| text / command / fields tasks | unchanged | | | |

Triage (dev, run twice, must beat ~0.05 F1 / ~0.07 accuracy over rag+BM25 0.90 / 0.62 and 0.59):

| Run | Accuracy | Technique F1 | Exact primary | Hallucinated-IOC rate |
|---|---|---|---|---|
| rag + BM25 (`bm25/`, `bm25-repeat/`) | 0.90 / 0.90 | 0.62 / 0.59 | 0.60 / 0.55 | 0.12 / 0.16 |
| + launch context (`launch-context/`, `launch-context-repeat/`) | 0.90 / 0.93 | 0.63 / 0.57 | 0.65 / 0.60 | 0.16 / 0.11 |

Averages: accuracy 0.90 -> 0.92, F1 0.61 -> 0.60, exact primary 0.58 -> 0.63, IOC 0.14 -> 0.14.
All within noise, so the aggregate triage effect is not proven. The targeted alerts did change,
the same way in both runs: day3-176 now gets T1569.002 (services.exe; before, T1059 in all runs),
day3-095 gets T1505.003 (web shell: right mechanism family, gold is T1190, still no credit). No
new false positive on benign alerts with a context (day3-165 stays benign_noisy in all 4 runs).
Kept: deterministic retrieval gain (alert->attack MRR 0.34 -> 0.43), fixes the prompt failure it
was aimed at, no harm measured.

## Rule generation v0, end to end (2026-10-02, `results/rulegen-v0.json`)

`uv run python -m evals.rulegen`: the first 5 dev attacks with no covering rule, full live
pipeline (triage -> route -> rule_gen -> validate). No validator yet, so no rule can pass.

| Alert | Triage | Outcome | Rule |
|---|---|---|---|
| day2-006 (T1685.001) | true_positive, right technique | rule_unvalidated | registry `...\Services\EventLog\Start` set to 4: clean, no filter this time |
| day2-014 (T1059.005) | needs_review | no rule | - (the open label question) |
| day3-048 (T1134) | benign_noisy (wrong) | no rule | - |
| day3-056 (T1127.001) | true_positive, right technique | rule_unvalidated, 1 retry | MSBuild + "Tasks" in the command line (the self-check sent the first draft back) |
| day3-070 (T1059.003) | true_positive | rule_unvalidated | cmd.exe from a Desktop program, command line contains "/c" OR "Desktop" OR ".exe" |

Rules generated 3/5 (the other 2 stopped at triage, as designed), compile rate 3/3, all fire on
their own alert. Validation pass rate and FP rate: pending Mouadh's validator
(`--validate-only` will grade these rules with no new model calls).

Seen in the rules: the model writes several values in one field as if they must ALL match, but
Sigma ORs them (day3-070: any `cmd /c` launched from a Desktop program). Candidate fix: an `all`
option on a field test (Sigma's `|all` modifier).

## 2026-10-04: rule_gen `all` flag (Sigma value lists are OR)

**Problem (rulegen-v0, day3-070):** the model wrote `CommandLine|contains: [/c, Desktop, .exe]`
meaning AND; Sigma ORs a value list, so any `cmd /c ...` matched. The system prompt itself said
"several keywords in one selection (all must match)", which invited it. Second, silent bug: two
items with the same field+match were merged by `_selection_yaml` into one OR list.

**Change:** `FieldMatch.all` renders `|all` (AND); `equals` + `all` + several values refused; a
field+match may appear once per selection; prompt explains OR vs `all=true`; self-check feedback
says "all of". 5 new tests (real matcher: OR rule fires on `cmd.exe /c dir`, `all` rule does not).

**Live (results/rulegen-v1-all.json, day3-070 only, 1 schema retry):** the model used
`CommandLine|contains|all: [/c, MoveExcel4.exe]` + `ParentImage|endswith: GruntHTTP.exe`.
Fixed the broadness, but swung to a fingerprint: TP 0/7 held-out same-technique attacks, FP 0/23,
noise 0/238 (v0 rule: TP 4/7). One alert, so not a measurement, just a direction.

**Next:** too broad vs too narrow is the job of the repair loop (Week 3): the validator feedback
("fires on 0/7 held-out attacks") goes back to the model. Also the pass rule (Day 13) decides
whether 0/7 TP with 0 FP is acceptable.

## 2026-10-04: validator pass rule v1 (Day 13)

**v0 rule (placeholder):** pass only if every held-out same-technique attack fires and no benign
event does. Too strict: a narrow, correct rule (one launcher pattern) fails because other attacks
labeled T1059.003 use a different launcher.

**v1 (`nodes.rule_passed`, used by the graph and `evals/rulegen.py`):** compiles AND 0 benign hits
AND (>=1 held-out same-technique attack fires, OR none exists to test). Recall
(`nodes.rule_recall` = TP / held-out positives) is reported per row and as `median_recall`, not
required. Rationale: in a SOC a noisy rule costs more than a missed variant; one hit proves the
rule generalizes beyond its own capture, a fingerprint gets 0.

**Re-graded (no model calls):**

| run | alert | v0 rule | v1 rule | TP / held-out | FP |
|---|---|---|---|---|---|
| rulegen-v0 | day2-006 | fail | fail | 0/1 | 0 |
| rulegen-v0 | day3-056 | pass | pass | none to test | 0 |
| rulegen-v0 | day3-070 | fail | **pass** | 4/7 (recall .57) | 0 |
| rulegen-v1-all | day3-070 | fail | fail | 0/7 | 0 |

rulegen-v0 pass rate 1/3 -> 2/3. Known gap: "none to test" (day3-056) passes on the benign side
alone; the benign set is small (golden benign_noisy + background), so the pool noise line is the
only breadth signal there.

## 2026-10-04: first live end-to-end run (Day 13 checkpoint)

`uv run python -m sentinel.run --alert data/raw/e2e/day3-071.json --config-name e2e-day13`
(day3-071 = dev TP, DCOM lateral movement via MoveExcel4.exe, label T1021.003, no existing rule
covers it; alert JSON exported to gitignored data/raw/e2e/). ~5 requests.

Path ingest -> enrich -> triage -> route -> rule_gen -> validate -> output: every node ran live.

- **triage:** true_positive (right), but T1059.003/T1204.002 (wrong: label T1021.003; the known
  DCOM retrieval miss). Tier 1 confidence .60 -> escalated to tier 2 (.75).
- **rule_gen:** 1 self-check retry; rule = `Image|endswith MoveExcel4.exe` + user-profile path +
  parent cmd.exe: a fingerprint of this tool name.
- **validate:** 0/7 held-out attacks, 0/23 benign, 0/238 pool -> **rule_failed** (pass rule v1
  works as intended: precise but does not generalize).

**Lesson: technique errors propagate.** The validator grades a rule against held-out attacks of
the technique *triage* claimed. Here triage's T1059.003 sent the rule to the wrong comparison set;
a correct T1021.003 rule would be graded against DCOM attacks. Retrieval quality (Week 2 error
analysis: 5-6 of 7-8 failures are retrieval misses) now limits rule quality too.
Open: repair loop (Week 3) is still a stub (max_attempts=1), so a failed rule stops here.

## 2026-10-04: rulegen-v0 rule review (Day 13 read-out)

Every rulegen-v0 row, graded with pass rule v1. Cause = generator (bad rule logic), validator
(wrong verdict), data (corpus can't judge the rule) or triage (no rule was generated).
DRAFT: Mouheb + Mouadh to confirm.

| alert | rule (detection) | v1 verdict | cause | why |
|---|---|---|---|---|
| day2-006 (T1685.001) | `TargetObject` ends with `Services\EventLog\Start` AND `Details` contains `DWORD (0x00000004)` (EventLog service set to disabled) | fail (0/1 held-out, 0 FP) | **data** (validator verdict too harsh) | Rule is precise and sound. The only held-out T1685.001 attack, day3-053, is a different procedure (sets `...\Audit\ProcessCreationIncludeCmdLine_Enabled` to 0: turns off command-line logging). No rule for one procedure catches the other. 1 hit in 9,779 pool events. |
| day2-014 (T1059.005) | none | needs_review | **triage** | Triage stopped at needs_review (wscript + .vbs; label kept TP by Mouadh, guide rule 3 exception added 2026-10-03). |
| day3-048 (T1134) | none | benign | **triage** | Triage said benign (wrong): a missed attack, no rule attempted. |
| day3-056 (T1127.001) | `Image` ends with `MSBuild.exe` AND `CommandLine` contains `Tasks` | pass (no held-out positive, 0 FP) | **data** | No other T1127.001 attack outside the source capture, so recall can't be measured; passes on the benign side only. `Tasks` is a weak keyword (a project path), a likely FP source in real networks. |
| day3-070 (T1059.003) | `ParentImage` contains `Desktop` AND `Image` ends with `cmd.exe` AND `CommandLine` contains any of `/c`, `Desktop`, `.exe` | pass (4/7, recall .57, 0 FP) | **generator** (partial) | The value list was meant as AND (fixed today: `all` flag). The 3 misses are other procedures, not rule errors: day3-054 launcher.exe from explorer, day3-068 cmd from hh.exe, day3-119 cmd from mshta.exe. |

**Summary:** 5 alerts → 3 rules, 3/3 compile, 2/3 pass, 0 benign hits. Of 5: 2 triage, 2 data,
1 generator (partial). No validator bug found; one verdict judged too harsh (day2-006).

**Follow-ups (Week 3):**
1. **Procedure-level positives:** grade against held-out attacks of the same *procedure*, not only
   the same technique (T1685.001 covers several ways to impair logging). Until then, a fail with
   ≤1 held-out positive is reported as low-evidence, not as a real failure.
2. **Benign set too small to catch broad rules** (day3-070's OR list fired on 0 benign events):
   add benign `cmd /c` and MSBuild events.
3. **Triage before rules:** 2/5 rule attempts were lost to triage errors.

## 2026-10-06: test split before/after (Week 2 final number) + 2 hypotheses

Sealed test split, rag, n=30 each, run once. Before = `baseline-v0` (vector only, prompt
2edd88418b70); after = vector+BM25 + launch context (prompt a7a0d78eaac5). Chart:
`results/charts/week2.png`.

| | before | after |
|---|---|---|
| accuracy | 0.97 | 0.90 |
| attack recall | 0.95 (1 missed) | 0.95 (1 missed) |
| benign recall | 1.00 | 0.80 (2 called attacks) |
| technique F1 | 0.60 | 0.62 |
| exact primary technique | 0.55 | 0.50 |
| invented IOCs | 0.06 | 0.02 |

**Verdict: a tie, not a win.** F1 +0.02 is inside the ±0.05 noise; fewer invented IOCs, paid
with 2 false positives. The after-run errors (read only after both runs completed):
- `day2-007` benign (lsass writes its W32Time value) → TP T1547.003 Time Providers.
- `day2-025` benign (`smartscreen.exe -Embedding`, normal COM self-launch) → TP T1021.003 DCOM.
- `day3-137` TP (PurpleSharp spraying + Kerberoasting) → benign. Both runs miss it.

**Hypotheses (NOT to be tuned on these test alerts; check on dev first):**
1. **Keyword priming:** a string in a benign event that matches a technique name or its
   procedure text (`W32Time`, `-Embedding`) pulls that technique in, and the model treats the
   match as evidence. BM25 likely makes it worse (exact-token leg). Check: dev benign alerts
   called TP, with a technique whose name/keyword appears in the event. Keep a fix only if dev
   benign recall rises with no attack-recall loss beyond noise.
2. **Adversary-simulation tools read as admin activity:** PurpleSharp (and similar: Atomic Red
   Team, Caldera) are treated as legitimate tooling. Labeling guide says TP. Check: dev alerts
   from simulation frameworks. Candidate fix: one line in the triage prompt + a guide example.
Triage stays frozen this week (Week 3 guide); both go to the Day 19 slot or Week 4.

## 2026-10-06: repair-try on day3-070 (repair loop, first live run)

Repair never ran: rule version 1 failed both rule_gen tries (path ends rule_gen -> output).
Try 1: two `CommandLine contains` items in one selection (refused by the form since 10-04).
Try 2: `CommandLine contains all of ['/c', '/Desktop/', '172.18.39.6']`: '/' path in a non-path
field (never matches Sysmon's '\') + the IP (fingerprint). Fix (no quota): self-check names the
'/' mistake when the '\' version would match (`_slash_hint`). Re-run as `repair-try2`.

## 2026-10-06: repair-try2 on day3-070: first repair that turned a fail into a pass

Path: rule_gen -> validate (fail) -> repair -> validate (pass). 2 rule versions, 1 repair call.
- **v1** "GruntHTTP.exe spawning cmd.exe to run MoveExcel4.exe": a fingerprint of this event,
  failed (0 held-out hits).
- **v2** (after the validator report): ParentImage in a user-writable folder (`\Users\`,
  `\Desktop\`, `\Temp\`...) -> `cmd.exe` -> CommandLine contains all of `.exe` + a private-IP
  prefix (`10.` / `172.` / `192.168.`). TP 1/7 (recall .14), benign 0/23, pool 0/238 -> pass.

**The loop works:** the report ("missed 6, compare their fields") moved the model from a tool-name
fingerprint to a behavior. **The pass bar is low:** v2 passes with 1/7, below the Day 12 v0 rule
(4/7), and the loop stops at the first pass. `'10.'` as a substring also matches version numbers
("Windows 10."), a real-network FP the 23-event benign set can't see.
**For ADR 0003 floors (Mouadh + Mouheb):** consider a recall floor (e.g. ≥2 held-out hits or
recall ≥ .3 when ≥3 positives exist) or "keep repairing while recall rises". Decide on loop-v1
data (10 alerts), not this one.
