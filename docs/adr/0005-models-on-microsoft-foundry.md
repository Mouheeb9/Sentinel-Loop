# ADR 0005: Models on Microsoft Foundry (Azure) instead of free OpenRouter

- **Status:** Proposed, conditional on the content-filter smoke test below
- **Date:** 2026-10-22
- **Decision by:** Mouheb (Mouadh to review)
- **Written by:** Mouheb (Mouadh should write the review notes: it changes every number he owns)
- **Code:** `src/sentinel/llm.py` (one more provider), `evals/foundry_smoke.py` (the gate test)

## Context

Every model call so far went to free OpenRouter models (nemotron-3 super / ultra), and that
shaped the whole project:

- **50 requests/day, shared.** A 14-alert run takes 2 days, the injection after-run 2-3 days, and
  most numbers are N=1 because a repeat costs a day. Week 4's plan had only ~200 requests to
  spend after the hardening freeze.
- **The free tier is unreliable.** The tier-1 endpoint (super) was down for days (404), so e2e
  ran on ultra only, a setup that matches none of the dev triage numbers.
- **Model quality caps the loop.** First-attempt rule pass rate is 1/13; technique choice is the
  weakest triage number (F1 ~0.60).

Mouheb has an Azure free trial ($200 for 30 days) and is preparing AI-103 (building agents on
Azure), so Foundry is both an option and a skill to show.

> Same trade as moving a SOC from a free threat feed to a paid one: better coverage, but every
> detection threshold tuned on the old feed has to be re-checked on the new one.

## Decision (proposed)

1. Triage (both tiers) and rule generation move to models deployed in **Microsoft Foundry**,
   keeping two-tier routing (ADR 0002): a cheaper model first, a stronger one on low confidence
   and for rule generation. Model names are config (`SENTINEL_*_MODEL`), as before.
2. **Gate before anything else:** a smoke test of ~10 alerts (real attacks + injection payloads
   + 2 benign) through the real triage prompt, with the default content filter and with a custom
   high-severity-only filter. Keep this ADR only if real attacks are not blocked under the filter
   we deploy (see "Content filters").
3. The old numbers stay as they are, labeled "nemotron". If the new setup shows a clear gain, the
   key ones are re-measured on Foundry (triage dev x2, injection batches 01-03, e2e), and the CI
   floors (ADR 0003) are reset from those runs.
4. A budget alert on the subscription before the first call.

## Content filters (the main risk)

Our inputs are real attack telemetry (encoded PowerShell stagers, LSASS dumps, C2 implants) and,
in the injection batches, prompts that are deliberately malicious. Azure applies content filters
and Prompt Shields to every call. Outcomes per alert in the smoke test:

- **ok:** normal answer.
- **blocked:** HTTP 400 `content_filter` on the prompt, or `finish_reason=content_filter`.
- **flagged:** answered, but the filter annotations mark it (e.g. jailbreak detected).

A blocked **real attack** is a failure of the triage tool (an analyst can't triage what the model
refuses to read). A blocked **injection payload** is a defense: it goes into the hardening
before/after chart as its own layer, measured on and off.

## Options considered

| option | for | against |
|---|---|---|
| stay on free OpenRouter | $0; all numbers stay comparable | 50/day, outages, N=1 everywhere, weak first-try rules |
| Anthropic API (the plan's "later" line in `llm.py`) | strong models, no content filter surprise on security text | paid from day 1, no credits |
| **Microsoft Foundry** | $200 credits now, top-tier models, AI-103 fit, enterprise filters as an extra defense to measure | filters may block real attacks; trial quota per model/region may be low; credits end after 30 days |

## Consequences

- Before/after comparisons are only valid on one model: the "before" numbers for the hardening
  chart must be re-run on Foundry (cheap with credits).
- Every result row already records the model string, so mixed-model rows can't be confused.
- Content filter outcomes become part of the result rows (blocked/flagged), not just errors.
- After the credits: pay-as-you-go at our volume should be tens of dollars a month (to confirm
  from Foundry pricing once the models are chosen), or Azure for Students. One free trial per
  person (Azure terms), so no trial rotation.

## Revisit when

- The smoke test blocks real attacks under every filter setting we may use: stay on OpenRouter
  for triage, or try another provider.
- Credits end and pay-as-you-go turns out more than the project is worth.
