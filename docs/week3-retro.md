# Week 3 retro (Days 15-21, 2026-10-05 to 2026-10-21)

Draft by Mouheb on 2026-10-21; Mouadh's side and the `_pending_` cells still to fill. Week 3 was
planned to end on Sun 11 Oct; it ran 10 days over (quota, a provider outage, a timeout bug).

## What shipped

- **Week 2 closed:** test-split before/after (a tie: F1 .60 -> .62, accuracy .97 -> .90, invented
  IOCs .06 -> .02), chart, README table, tag `week2`.
- **Repair loop:** validator feedback (missed alert ids, benign hits quoted as untrusted, lints)
  goes back to rule_gen, 3 attempts, keeps the best version, stops when the feedback repeats.
  Missed attacks are never shown to the model (RG-7). First fail -> pass on 2026-10-06 (day3-070).
- **Validator v2** (Mouadh): procedure-level positives (`procedures.yaml`, 80 attacks, 47
  procedures), sibling recall reported, `evidence: low` with <= 1 positive; benign set v1 (+31
  `cmd /c`, MSBuild, script-host events).
- **Pass bar v2:** 0 FP + min(2, n) held-out repeats caught; no repeat -> `rule_needs_review`
  (a human decides in the PR).
- **Rules become pull requests:** `sentinel.publish` commits a passed rule on `rule/<alert-id>`
  and opens a draft PR (dry run by default, never pushes `main`).
- **CI gates:** rule gate (Mouadh: every changed rule re-validated, fails on any FP, compile or
  lint error; PR #11 blocked, #12 green) and triage eval gate (prompt hash guard + floors from 2
  dev runs, ADR 0003).
- **Rule form fix:** a repeated field test is an AND group (the hidden "one test per field" rule
  caused 5 of 10 loop-v1 failures); `/` paths in CommandLine fixed from the event. Replay of the
  rejected answers: 0/8 -> 7/8 valid.
- **First generated rule PR:** `rule/day3-104` (Empire encoded stager), CI green.
  Merge: _pending_ (Mouadh's review).
- **ADR 0003** (eval-gate floors, Mouadh + Mouheb).

## The numbers

**Repair, attempt 1 vs attempt 3** (testable set, 14 alerts, 4 procedures):

| run | triage | rules | pass @1 | pass @3 | survive review |
|---|---|---|---|---|---|
| gold-v1 | golden label | 14 | 0 | **7** | ~6 |
| e2e-v1-ultra | real (ultra) | 13 | 1 | **6** | ~4 |

Every pass but one came from repair. On the 10 uncovered dev attacks (loop-v1 -> loop-v2): 0
passes, 4 `needs_review` (no same-procedure repeat to test with), 3 failed, 3 no rule (triage
needs_review). Those alerts mostly have nothing to grade against: a data gap, not a model one.

**Where it works and where it doesn't** (e2e-v1-ultra):

| procedure | passed |
|---|---|
| T1059.001 Empire encoded stager | 4/5 |
| T1047 WmiPrvSE child process | 1/2 |
| T1059.003 C2 implant spawns cmd | 1/4 |
| T1569.002 services spawns shell | 0/3 |

- **Rule-poisoning ASR (batch_03, TH-05..07):** _pending_ (Mouadh).
- **Rules merged through the gate:** _pending_ (target 1: day3-104).

## What took longer than planned

- **Quota.** 50 free requests a day; a 14-alert run takes 2 days. Every live number is a
  multi-day job, and a re-measure of the triage prompt (~35 requests) is a day by itself.
- **A 300 ms timeout** (ChatOpenRouter takes milliseconds, we wrote 300 meaning seconds): every
  call timed out and retried, which looked like a 12-minute hang per alert. Fixed in f17bb5d;
  ~2 min per alert since.
- **Provider outage.** The free tier-1 model (super) returned 404 for days; e2e ran on ultra
  with escalation off, so it is not the same setup as the dev triage numbers.
- **The rule form** fought the model for a week (hidden constraint, misleading error) before the
  Langfuse traces showed why.
- **No commits 2026-10-09 to 2026-10-14:** _pending_ (reason).

## What we learned

- **Repair is the engine, but it's blind.** First-try pass rate is about 0; repair lifts it to
  about half. It fixes what the report can name (add a flag, drop a field); it can't find the
  common part of attacks it never sees (GruntHTTP, services, WMI all stay one hit short).
- **Check the label policy before blaming the model.** Retrieval had the labeled technique in
  the top 5 on 14/14 alerts. Triage's "misses" (T1007 for `sc query`, T1047 for `wmic`, the
  regsvr32 launcher) were defensible tags, one straight from our own prompt; only 087 was a real
  error. Labels now carry both layers (launcher + action); the validator accepts any of them.
- **0 FP is only as good as the benign set.** Rules 125 (any exe under WmiPrvSE), 141 (`-e`
  matches `-ExecutionPolicy`) and 087 (any shell under services.exe) pass with 0 FP and would
  fire on normal admin activity. ~53 benign process events can't see that.
- **Make every constraint visible.** A rule the model can't see in the schema or prompt is a rule
  it will break, and a bad error message makes the fix worse than the mistake.
- **Gates change behavior.** The eval gate blocked a prompt change the same day it was made
  (2026-10-21): no prompt change ships without a dev re-measure.

## Mouheb

### What to change in Week 4

- **Log recall per repair attempt**, not just pass/fail, to see if failed repairs get closer.
- **Check env values against the code** before running a multi-day eval (e2e lost a run to a
  shorthand model name).
- **One live run per day, planned with Mouadh**, quota written in the guide's table first.

## Mouadh

### What took longer than planned

_pending_

### What to change in Week 4

_pending_

## Week 4 plan (cut down, about 10 days behind)

Proposal, to agree together:

1. **Close Week 3:** merge day3-104, README loop diagram + chart, tag `loop-v1`.
2. **Mouadh, data:** second-layer labels (050, 164, 108, 101), benign set v2 (admin PowerShell,
   SCCM/msiexec, WMI-launched tools, services -> cmd installers); re-grade stored rules (no quota).
3. **Mouheb, triage:** re-measure the 087 prompt rule on dev (`triage-v3`), keep only above noise.
4. **Mouadh, security:** a smaller batch_03 (rule poisoning) and its ASR.
5. **Deploy:** ADR 0004 on day 1 (local docker-compose + recorded demo is the cheapest option).
6. **Demo:** Streamlit dashboard + video. Cut first if late: hardening and the full
   injection re-run.
