# ADR 0001: Partial credit for ATT&CK technique scoring

- **Status:** Accepted (in use since Week 1, Day 7)
- **Date:** 2026-10-04
- **Decision by:** Mouadh (labeling guide section 4, `evals/scorers.py`)
- **Written by:** Mouheb (Week 2 ADR swap)

## Context

Every triage verdict carries ATT&CK technique IDs, and the golden set labels each attack with
one or more. We need one number for "how right are the techniques" that we can compare across
configs and weeks.

ATT&CK is a tree: tactic (why) → technique (how) → sub-technique (exact method). A model that
says `T1055` (Process Injection) for a `T1055.012` (Process Hollowing) alert has found the
mechanism but missed the method. Scoring that 0, like a completely wrong answer, hides real
progress; scoring it 1 hides a real miss. An analyst handed `T1055` still knows where to look.

Two more facts shaped the decision:
- ATT&CK renumbers techniques between releases (`T1562.002` → `T1685.001`). A model trained on
  an older release answers with the old ID: that is not a wrong answer.
- Alerts can have several gold IDs and the model can predict several, so we need both
  precision (no invented techniques) and recall (no missed ones).

## Decision

Score each predicted ID against each gold ID (`scorers.credit`), after mapping both through
ATT&CK renames:

| Match | Credit |
|---|---|
| Exact (sub-)technique | 1.0 |
| Same parent technique (either side may be the parent; siblings too) | 0.5 |
| Shared tactic only | 0.25 |
| Otherwise | 0.0 |

Per alert: recall = mean over gold IDs of the best credit any prediction earns; precision = mean
over predicted IDs of the best credit against any gold ID. Both are macro-averaged over alerts,
F1 = 2PR / (P + R). A benign alert with no gold and no prediction is not scored; techniques
invented on a benign alert score precision 0; an error row scores recall 0 (never skipped).

Alongside F1 we always report **`primary_exact_rate`**: the share of attacks whose first
predicted ID equals the first gold ID, with no partial credit.

## Options considered

| Option | For | Against |
|---|---|---|
| **Exact match only** | Simple, strict, nothing to argue about | `T1055` for `T1055.012` = 0, same as `T1003`; old-release IDs = 0; small changes in reasoning look like nothing |
| **Partial credit by tree distance (chosen)** | Rewards finding the mechanism; matches how an analyst uses the answer; comparable across ATT&CK releases via renames | Weights (0.5 / 0.25) are a judgment call; tactic credit is generous because many techniques share a tactic |
| **Partial credit, no tactic level** (1.0 / 0.5 / 0) | Removes the most generous level | Loses "right category" signal; on our data almost no difference (below) |
| **LLM judge for "close enough"** | Handles nuance | Costs quota, non-deterministic, a model grading a model; rejected for a core metric |

## Evidence (2026-10-04, dev split, v1.1 labels, same rows rescored)

| Run | partial F1 | no-tactic F1 | exact-only F1 | gold IDs at 1.0 / 0.5 / 0.25 / 0 |
|---|---|---|---|---|
| baseline rag | 0.58 | 0.56 | 0.53 | 12 / 1 / 1 / 6 |
| launch-context rag | 0.63 | 0.62 | 0.62 | 14 / 0 / 1 / 5 |
| launch-context-repeat rag | 0.57 | 0.55 | 0.55 | 13 / 0 / 1 / 6 |

Partial credit adds **+0.01 to +0.05** F1 over exact-only. Our models are almost always either
exactly right or wrong; partial credit changes the ranking of no config. So it does not inflate
the headline number, and the run-to-run noise (about ±0.05 F1, Day 10) is as large as its whole
effect.

## Consequences

- F1 is readable as "mostly exact matches", but always report it with `primary_exact_rate` so a
  reader can see the strict number too.
- Sibling sub-techniques get 0.5 (`T1218.005` for `T1218.011`): generous, since they are
  different methods. Accepted for now: rare on our data.
- The rename map comes from the ATT&CK bundle: a new release can change scores without any model
  change. The bundle version is part of the eval setup; re-score old runs after an upgrade.
- Changing a weight changes every past number: do it only with a new ADR and a re-score of all
  stored runs (`evals.run --score-only` makes that free).
- The rule validator does not use partial credit: it compares rules with held-out attacks of the
  same technique, where a parent covers its sub-techniques (`validation/validate.py`).

## Revisit when

- Partial credit starts changing which config wins (the effect grows above the noise).
- We score sub-technique precision in rule generation, where siblings should probably get 0.
