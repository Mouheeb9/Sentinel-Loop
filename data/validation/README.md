# data/validation

Held out from `data/golden/` on purpose. `data/golden/` scores the triage agent (does it call
the right verdict/technique); `data/validation/` is a separate pool used only to check whether a
*generated Sigma rule* actually fires on real telemetry (Week 3 repair loop, Zircolite).

## The split rule

Every raw capture in `data/raw/security-datasets/*.zip` (113 total, gitignored — see README
"Setup" to re-download) is assigned to exactly one pool:

- **golden pool**: any zip referenced by `source_dataset` in a `data/golden/v1.jsonl` row (69 zips).
- **validation pool**: everything else (44 zips), frozen in `validation_datasets.txt`.

**No zip is ever in both pools.** A generated Sigma rule must never be validated against the same
capture the triage agent was scored on — that would be grading against the answer key.

`validation_datasets.txt` is frozen the same day golden-v1 was frozen (2026-09-22). If golden ever
adds a new capture (v2+), re-derive this list (any golden zip must be removed from here) and note
it in `data/golden/CHANGELOG.md`.

Enforced by `tests/test_no_leakage.py`.

## How the validator uses it (v0, Day 12)

`src/sentinel/validation/validate.py` grades a generated rule on three sample sets:

| Set | Source | Graded? |
|---|---|---|
| **Positives** (must fire) | golden `true_positive` alerts (v1.1) with a technique the rule claims (a claimed parent covers its sub-techniques), same log source as the rule, **never from the source alert's capture** | yes: each miss is a `failed_sample` |
| **Negatives** (must not fire) | golden `benign_noisy` alerts + hand-checked background events (`tests/fixtures/sysmon/bg_*.json`), in the rule's log source | yes: each hit is a `failed_sample`, `fp_rate = hits / benign checked` |
| **Noise check** | every Sysmon EID 1/3/13 event in the 44 held-out captures here (~10.8k events), same log source as the rule | no: reported in `feedback` only |

Why positives come from golden and not from here: this pool has no event-level labels yet, so
there is no way to know which of its events are the attack. The golden set does, and the
leakage rule still holds where it matters: the rule never sees the alerts it is graded on (rule_gen
only gets the source alert), and nothing from the source alert's capture counts. The triage
answer key is not reused for tuning: if the Week 3 repair loop iterates on these positives, the
final number must be re-measured on held-out labels (below).

Why the pool is not graded: those captures contain attacks too, so a hit is not proof of a false
positive. Hundreds of hits do mean the rule is too broad (feedback says "likely too broad" from 20).

Known gaps, written in the feedback rather than hidden:
- Many techniques have no other golden alert: TP is then "unknown (data gap)", not 0, and the rule
  can still pass on negatives alone.
- Sibling sub-techniques (rule claims T1218.005, alert is T1218.011) are reported, not required.
- The benign set is small (about 20-50 events per log source).

## Status

Event-level validation labels for this pool (which event in which capture is the attack) are
**not built yet**: Week 3. They turn the noise check into real TP/FP numbers and give a clean
held-out score for the repair loop.
