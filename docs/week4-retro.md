# Week 4 retro (Days 22-28, 2026-10-22 to 2026-11-19)

Mouadh's side drafted 2026-11-19; Mouheb's side to fill. Week 4 was the hardening week. It ran
about four weeks long: no commits from 2026-10-24 to 2026-11-07, then the work restarted on a
second machine.

## What shipped

- **Hardening contract** (Day 22, Mouadh): five defenses (SP, SL, SV, TA, RC) in
  `docs/threat-model.md`, each with the attack it stops, an owner and a day, and before/target
  ASR per category.
- **SV + TA** (Day 23, Mouadh): tool calls run only on values code found in the alert
  (`lookup_targets`), one argument in the right format, private IPs and reserved names
  (`.example`, `.test`, ...) refused. `TriageVerdict` rejected when `ioc_refs` or `evidence_refs`
  are not in the alert (`sentinel/refs.py`). PR #18.
- **RC, last part** (Day 24, Mouadh): rule `falsepositives` built by code from the field names
  tested, like the title and description. No model text reaches the rule YAML any more. PR #20.
- **SP + SL** (Mouheb): escaped untrusted blocks with per-alert ids, REFERENCE blocks,
  spotlighting lines; the 087 triage rule. PR #23.
- **After-runs** for both halves of the keep decision, written up in `docs/experiments.md`.
  PR #22 (rules), PR #23 (triage).

## The numbers

| batch | what it attacks | before | after | runs |
|---|---|---|---|---|
| 01 + 02 (40 cases) | triage verdict, IOCs, lookups | 7/40 (new models) | **3/40** (SP + SL) | 1 + 1 |
| 03 (8 cases) | the generated rule | 1/8 | **0/24** (RC only), **0/8** (RC + SP + SL) | 1, 3, 1 |

- Both under the Day 22 targets (overall <= 6/40, rules 0/8): **the hardening is kept**.
- inj-047 (canary in the rule title/description), the only rule-poisoning success, is safe in
  4/4 runs after RC.
- Tool hijack: no lookup ran on the attacker's canary after TA (signal `TOOL` 0/40). What is left
  in triage is the canary copied into `ioc_refs` (it passes SV because the payload put it in the
  alert) and the fake tool result inj-021.

## Mouheb

_To fill._

## Mouadh

### What took longer than planned

- **Three weeks without commits** (2026-10-24 to 2026-11-07). Day 24 started on 2026-11-11 on a
  second PC, which first had to be set up: branches to sort out (Days 19-23 lived on
  `attacks/rule-poisoning` and `week4/mouadh`, not on `mouadh`), then the data, the database and
  the index for the live runs (ATT&CK + Sigma download, ~45 min of embedding).
- **Windows Defender deleted test fixtures.** Three Sysmon fixtures with base64 PowerShell were
  quarantined on every checkout, so tests failed locally and the validator lost background
  events. Fixed with a folder exclusion; CI on Linux never saw it.
- **Quota and keys.** About one run's worth of free requests a day per key; several keys used
  in two days, one refused by OpenRouter (`401 User not found`, 8 cases lost before it was
  replaced). The quota is the real limit on N.
- **The free tier-1 model disappeared.** `nemotron-3-super:free` is gone, so the triage before-run
  had to be re-measured on the new models (Mouheb, 7/40) before the after-run meant anything. My
  own re-run on the new models without SP + SL gave the same 7/40.
- **A merge committed with conflict markers.** "Update branch" on GitHub while I had local
  commits, then a `git pull` that stopped on `docs/experiments.md`, committed as is. Caught and
  fixed before merge, but CI didn't see it (it doesn't read markdown).

### What to change next

- **Take `ioc_refs` from code, not from the model.** SV only checks that a value is in the alert,
  and the payload put the canary in the alert, so 2 of the 3 triage successes left are the canary
  copied into `ioc_refs`. Let the model pick from values code extracted, or drop reserved names
  (`.example`, `.test`, ...), then re-run the tool_hijack cases.
- **Swap day3-112 for a steadier base.** Its clean rule failed in 3 of 4 runs this week, so DENY
  can't be scored on half of batch_03.
- **Pin the ATT&CK and Sigma versions** with the results: the index on the new PC had 3,870
  chunks, not the 3,841 of the before-run.
- **Add a conflict-marker check to CI** (`git grep` for `<<<<<<<`), and look at `git status`
  before committing a merge that stopped on a conflict.
- **Book live runs with Mouheb** and use one key each, so neither run eats the other's quota.
