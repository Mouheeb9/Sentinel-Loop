# Error analysis v1 (Day 9, written 2026-10-02)

**Status: draft by Mouheb (with Claude). Mouadh to confirm the buckets, especially the two marked
"label question".**

Source: the baseline runs on the dev split (30 alerts, `results/single-prompt.json`, `rag.json`,
`rag-tools.json`), read with `uv run python -m evals.failures`. Labels: golden-v1.1. Each failure
goes in exactly one bucket; the tool's hint ("retrieval miss?" / "reasoning error?") was checked
by reading the event, the label and the model's answer.

A failure = wrong verdict, or a technique that is not fully right (partial credit below 1).

## Counts (baseline)

| Bucket | single-prompt | rag | rag-tools | Total (rag + rag-tools) |
|---|---|---|---|---|
| Retrieval miss (the right technique never reached the model) | n/a (no search) | 8 | 8 | 16 |
| Reasoning error (the context was there, the conclusion was wrong) | 14 | 1 | 1 | 2 |
| Schema error (no valid verdict) | 0 | 0 | 0 | 0 |
| Label question (the golden label may be wrong) | 1 | 1 | 0 | 1 |
| **Failures read** | 15 | 10 | 9 | 19 |

single-prompt has no search, so every failure is the model's own knowledge: counted as reasoning.
4 of its 15 are partial credit for an older ATT&CK ID (for example T1562.001 where this ATT&CK
release uses T1685.001).

Label questions: 1 (under the "more than 2 -> fix the guide first" rule).

## Examples

### Retrieval miss (8 of 10 in rag)

The search never showed the right technique, so the model could not pick it. They group into
three patterns:

| Alert | Event | Right answer | Model said | What the search showed instead |
|---|---|---|---|---|
| day3-071, day3-166 | `MoveExcel4.exe 172.18.39.6` (a tool that runs Excel macros on another host over DCOM) | T1021.003 DCOM | needs_review | T1070.010, T1218.014, T1570 ... |
| day3-113, day3-151 | `mimikatz.exe "lsadump::zerologon ... /exploit"` (Zerologon, CVE-2020-1472) | T1210 exploit a remote service | T1003 / T1003.001 credential dumping | T1218.014, T1218.003, T1204 ... |
| day3-048 | `CreateNamedPipe.exe MSSE-1337-server` (Cobalt Strike getsystem pipe name) | T1134 token manipulation | T1059.003 | T1218.003, T1218.014, T1555.004 ... |
| day3-095 | `cmd /c whoami`, parent `w3wp.exe` (IIS web server) | T1190 exploit public-facing app | benign_noisy | T1555.004, T1505.002 ... |
| day3-176 | command run by `services.exe` | T1569.002 service execution | T1059.001 | T1059.001, T1543.003 ... |
| day2-006 | `payload.exe` sets EventLog service Start = 4 (disabled) | T1685.001 | T1562.001 (older ID, 0.5 credit) | persistence techniques (T1547.*) |

Pattern: the meaning is in a **tool name, a pipe name, a CVE keyword or the parent process**, not in
words that match ATT&CK's prose. The same "hub" techniques (T1218.014, T1218.003) fill the top 5.

### Reasoning error (1 in rag)

- **day2-031** (benign): Task Scheduler writes the cache entry of a new task
  (`...\Schedule\TaskCache\Tree\MordorSchtask\SD`). The label is benign_noisy: this record appears
  for every task, malicious or not. The model said true_positive / T1053.005, so it ignored the
  benign rule "OS bookkeeping as a side effect is benign_noisy". T1053.005 was in its context.

### Schema error

None: every run produced a valid verdict.

### Label question (for Mouadh)

- **day2-014**: `wscript.exe launcher.vbs` from the user's Desktop, started by explorer.exe
  (double-click). Label: true_positive T1059.005. The model gave the right technique but said
  needs_review: "no obfuscation or follow-on activity in this single event". That is exactly
  labeling-guide tie-break rule 3 ("weak single indicator -> needs_review"), and the new rule
  "tag what the event shows, not what the tool is known for" (the name "launcher" hints at Empire,
  the event shows a script run). Either the label should be needs_review, or the guide needs an
  exception for script files run from user folders.
- **day3-113 / day3-151** (counted as retrieval misses above): the model's T1003 is what mimikatz
  is known for, but the command line shows the Zerologon exploit, so T1210 matches the guide's
  "wrapper event" rule. Keep the label; noted only because the model's answer is defensible.

## Top bucket -> Day 10

- **Bucket: retrieval miss** (8 of 10 rag failures, 16 of 19 overall).
- **The change we tried:** improve the search, one change at a time (`docs/experiments.md`):
  BM25 keyword search (kept: right technique in the top 5 for 35% -> 60% of dev attacks), then
  launch context (kept: 60% -> 65%, fixed day3-176).

## After the fixes (rag + BM25 + launch context, two runs)

7 and 8 failures (was 10). What is left:

| Bucket | Run 1 | Run 2 | Alerts |
|---|---|---|---|
| Retrieval miss | 5 | 6 | day3-071, day3-166 (DCOM), day3-113, day3-151 (Zerologon), day3-048 (pipe name), day3-145 in run 2 |
| Reasoning error | 1 | 1 | day3-095: T1190 is now in the context, the model chose T1505.003 (web shell): close, no credit |
| Label question | 1 | 1 | day2-014 (see above) |

Fixed since baseline: day3-176 (service execution), day2-006 (new ATT&CK ID), day2-031 (benign
task cache, both runs).

**Next for the search:** the remaining misses all hinge on knowing that a specific tool, pipe name
or exploit keyword means a specific technique (MoveExcel4 = DCOM, zerologon = T1210, MSSE-*-server
= getsystem). ATT&CK's procedure examples ("software X used Y") carry exactly that knowledge;
adding them to the search is the next candidate.
