# ADR 0002: Two-tier triage routing on free models

- **Status:** Accepted (in use since Week 1, Day 6)
- **Date:** 2026-10-05
- **Decision by:** Mouheb (`src/sentinel/agents/routing.py`)
- **Written by:** Mouadh (Week 2 ADR swap)

## Context

Triage needs a model that is right on hard alerts, but we have no paid API: the OpenRouter free
tier gives 50 requests a day, shared by both of us. Every request spent on an easy alert is one
less for the eval, injection and rule-generation runs.

Most alerts are easy (a clear attack or clear OS noise) and a mid-size model gets them right.
A few are ambiguous, and those are where a stronger model can help. A SOC handles this the same
way: an L1 analyst closes what is clear and escalates the rest to L2.

## Decision

Two models, both free on OpenRouter:

| Tier | Model | Runs on |
|---|---|---|
| 1 | `nvidia/nemotron-3-super-120b-a12b:free` | every alert |
| 2 | `nvidia/nemotron-3-ultra-550b-a55b:free` | only when tier 1 escalates |

Tier 1's answer is escalated when (`escalation_reason`):
- confidence is below `SENTINEL_ESCALATE_BELOW` (default **0.7**),
- the verdict is `needs_review` (that verdict asks for a second opinion),
- the verdict is `true_positive` with no technique (ambiguous mapping), or
- tier 1 never produced a valid `TriageVerdict`.

Tier 2 **starts fresh** from the same alert and retrieved context, not from tier 1's answer, so it
cannot anchor on it. Its tool lookups hit the cache tier 1 filled. If tier 2 fails, tier 1's
answer stands. Every run records which tier decided, the model, tokens and cost, in the eval row
(`tier`, `detail.escalation`) and in the Langfuse trace.

## Options considered

| Option | For | Against |
|---|---|---|
| **Tier 1 only** | 1 request per alert, simplest | No second opinion on the alerts that need it most |
| **Tier 2 only** | Strongest model on every alert | Slower, and the bigger free model has the stricter rate limits; spends its effort on alerts tier 1 already gets right |
| **Two tiers, escalate on uncertainty (chosen)** | Strong model only where tier 1 is unsure; about 1.13 requests per alert | Relies on the model's own confidence, which is coarse (below) |
| **Both models on every alert, vote** | Disagreement is a good uncertainty signal | 2 requests per alert, halves what fits in a day |

## Evidence (stored eval rows, 7 dev runs + 16 test alerts, 2026-09-24 to 2026-10-04)

| | alerts | correct verdict |
|---|---|---|
| decided by tier 1 | 196 (87%) | 184 (94%) |
| escalated, decided by tier 2 | 29 (13%) | 14 (48%) |

- **Escalation costs little:** 13% of alerts, so about 1.13 model requests per alert on average.
- **The router finds the hard alerts.** Escalated alerts are right half the time, the others 94%
  of the time. The same few alerts escalate run after run (`day3-166` in 6 of 7 dev runs,
  `day2-013` in 5, then `day2-014`, `day2-031`, `day3-071`).
- **Tier 2 often answers `needs_review` on real attacks** (`day2-014`, `day3-071`, `day3-166`).
  That scores as wrong, but it is an honest answer for an analyst queue, not a missed attack.
- **Confidence is coarse.** 28 of 29 escalations were for low confidence, and 24 of those were at
  exactly 0.60. The model mostly answers 0.6, 0.7 or higher, so the 0.7 threshold works like
  "escalate when the model says 0.6".
- **What we did not measure:** whether tier 2 is *better* than tier 1 on these alerts. Rows store
  only the final answer, not tier 1's answer on escalated alerts, so there is no before/after.

## Consequences

- Each run's fingerprint records `tier1_model`, `tier2_model` and `escalate_below`: changing any of
  them is a config change, compared only on the same split.
- An escalated alert costs 2 requests or more: plan daily quota with the escalation rate in mind.
- No model switch mid-week (Week 2 rule): a new tier-1 model changes which alerts escalate.
- `needs_review` from tier 2 is the end of the line: there is no tier 3, the alert goes to a human.
- Free models can be removed or rate-limited by OpenRouter at any time. Setting
  `SENTINEL_ESCALATION_MODEL=none` falls back to one tier.

## Revisit when

- We store tier 1's verdict on escalated alerts and can measure tier 2's gain (add it to the row).
- The escalation rate goes above about 25%: the quota saving disappears.
- A paid model or a larger free quota makes a single strong tier affordable.
- Confidence stays clustered at 0.6: try escalating on disagreement or on retrieval score instead.
