# ADR 0003: CI gate floors for triage and generated rules

- **Status:** Proposed (Mouheb to review; triage floors already in `config/eval_gate.yaml`)
- **Date:** 2026-10-07
- **Decision by:** Mouheb + Mouadh (pass bar v2 agreed 2026-10-07)
- **Written by:** Mouadh
- **Code:** `evals/gate.py` + `config/eval_gate.yaml` (triage, Mouheb), `evals/validate_rules.py`
  (rules, Mouadh), `nodes.rule_verdict` (pass bar v2)

## Context

From Week 3 the loop opens pull requests: a model-written Sigma rule goes to
`rules/generated/<alert-id>.yml` as a draft PR, and prompt or retrieval changes keep landing on
`main`. A human approves every PR, but a reviewer misses things, and a rule file can change after
the validator graded it inside the loop. So CI must refuse two things on its own:

1. a change that makes triage worse than what we measured, and
2. a generated rule that is noisy, broken, or proves nothing.

CI has no model, no database and no secrets. It can only check numbers already measured (stored
dev-split answers) and run the validator, which needs only the golden data in the repo.

The hard part is the threshold. Our dev split is 30 alerts on free models, and the same prompt
run twice does not give the same score. A floor at the measured score fails an unlucky re-run of
an unchanged prompt; a floor far below it lets a real regression through.

> Same problem as an IDS threshold: too tight and it fires on normal jitter, too loose and it
> misses the real anomaly. You set it just below normal behaviour.

## Decision

### 1. Triage floors (`evals.gate`, every PR)

The committed dev results must come from today's triage input (prompt hash, models, search,
alerts); otherwise the PR fails until it re-measures on dev. The stored answers are then
re-scored with the current labels and must stay within:

| Metric | Run 1 | Run 2 | Floor | Margin |
|---|---|---|---|---|
| Verdict accuracy | .90 | .93 | **≥ .83** | 2 alerts of 30 |
| Attack recall (TP called TP) | .85 | .90 | **≥ .80** | 1 attack of 20 |
| Technique F1 (partial credit, ADR 0001) | .63 | .57 | **≥ .52** | measured noise .05 |
| Schema valid | 1.00 | 1.00 | **≥ .95** | 1 alert of 30 |
| Invented IOC rate | .16 | .11 | **≤ .20** | measured noise .05 |

Runs 1 and 2 = the same prompt (`a7a0d78eaac5`), twice: `results/launch-context`,
`results/launch-context-repeat`. Rule: **floor = the worse run minus the run-to-run noise**,
rounded to whole alerts where the metric counts alerts.

### 2. Rule floors (`evals.validate_rules`, every PR, every file in `rules/generated/`)

Pass bar v2, on validator v2 (`data/golden/procedures.yaml`). Let n = held-out repeats of the
same attack procedure (same technique when the alert has no procedure), never from the source
alert's own capture.

| Check | Fails the PR when |
|---|---|
| Compiles | invalid YAML, or Sigma the matcher can't run |
| **False positives** | fires on **any** benign event (golden `benign_noisy`, background, benign set v1) |
| **Hits** | catches fewer than **min(2, n)** of the n repeats |
| Lints | a filter on a process name (`Image`, `ParentImage`, `OriginalFileName`: RG-3) or `/` path values that never match |
| Gradable | source alert not in the golden set, or no ATT&CK technique in `tags` |

**n = 0** (nothing to test the rule on): the gate passes it as **NEEDS HUMAN REVIEW**
(`rule_needs_review`, `evidence: low`), never as a plain pass. The reviewer decides.

## Options considered

| Option | For | Against |
|---|---|---|
| **Triage: floor = measured score** | Strictest | Fails an unchanged prompt on an unlucky run |
| **Triage: fixed round numbers (e.g. F1 ≥ .50)** | Easy to explain | Not tied to anything we measured |
| **Triage: worse run minus noise (chosen)** | Unlucky re-run passes, a real drop fails | Two runs is a thin noise estimate |
| **Rules: ≥ 1 hit (pass bar v1)** | Accepts narrow correct rules | A near-fingerprint passed: repair-try2 caught 1 of 4 |
| **Rules: recall ≥ .3** | Scales with the group | Never binds: n is at most 6, and 2 of 6 = .33 already |
| **Rules: min(2, n) hits + 0 FP (chosen)** | A rule must catch the attack again, not just its own copy | n = 1 still needs only one hit |
| **Rules: allow 1 FP** | Fewer blocked rules | In a SOC a noisy rule costs more than a missed variant |
| **Rules: n = 0 fails** | Nothing unproven merges | Blocks 25 of 47 procedures forever (they have no repeat) |

## Evidence

**Triage noise** (same prompt, two dev runs each):

| Pair | Accuracy | Attack recall | F1 | Invented IOC |
|---|---|---|---|---|
| launch-context | .90 / .93 | .85 / .90 | .63 / .57 | .16 / .11 |
| bm25 | .90 / .90 | .90 / .85 | .63 / .60 | .13 / .16 |

The biggest gap is .05 on F1 and on IOCs, and 1 attack on recall. Schema validity was 1.00 on
all four runs.

**Rule pass bar v2 on the stored rules** (re-graded, no model calls):

| Rule | Hits | FP | Gate |
|---|---|---|---|
| rulegen-v0 day3-070 (GruntHTTP procedure) | 4/4 | 0 | pass |
| repair-try2 day3-070 (near-fingerprint) | 1/4 | 0 | **fail**: needs 2 |
| rulegen-try day3-056 (MSBuild `.xml`) | n = 0 | 1 | **fail**: benign hit + dead `/` values |
| rulegen-v0 day2-006, day3-056 | n = 0 | 0 | needs human review |

**Procedure group sizes** (procedures.yaml): 25 procedures have 1 alert (n = 0), 17 have 2
(n = 1), 3 have 3, 1 has 5, 1 has 7. So most generated rules will be `needs_review` or need a
single hit: the golden set, not the bar, limits how much CI can prove.

**Checkpoint (Day 17):** the broad MSBuild rule is blocked and the day3-070 rule passes, on
Linux in a clean clone (same as CI).

## Consequences

- A PR that changes the triage prompt, model, search or alerts must re-run dev
  (`uv run python -m evals.run --split dev --configs rag --run NAME`) and point
  `config/eval_gate.yaml` at the new results. That costs ~40 requests of the 50/day quota.
- Lowering a floor is a change to this ADR, reviewed by both of us, not a config edit.
- Label fixes re-score stored answers: a relabel can fail the gate without a prompt change.
- Every generated rule is re-checked on every PR, so a change to the validator or the benign
  set can turn a merged rule red. That is intended: fix or remove the rule.
- `needs_review` rules can merge only with a human approval (branch protection already
  requires one); the PR body says why.
- The fingerprint hashes alert files with CRLF line endings on every OS, so Windows-measured
  results match CI on Linux.

## Revisit when

- We have 3+ runs of one prompt: replace "worse of 2 minus .05" with a measured spread.
- The test split is re-measured: check the floors hold there too.
- procedures.yaml grows (more repeats per procedure): consider min(3, n), or a recall floor.
- A paid or stronger model moves the scores: re-derive every floor from new runs.
