# Sentinel Loop — Labeling Guide

This document defines how every alert in the golden dataset gets labeled, so two different people, on two different days, produce the same label for the same alert. If you're unsure how to label something, the answer should be in this file — if it isn't, add it.

---

## 1. True Positive vs. Benign-but-Noisy

**True Positive** — real adversary behavior is present. The activity reflects something an attacker would actually do to achieve a goal (access credentials, move laterally, persist, exfiltrate), not just activity that superficially resembles it.

**Benign-but-Noisy** — legitimate activity that a naive rule would still flag. The behavior can look identical to an attack on its face; what makes it noise instead of a threat is the surrounding context. Following the Palantir ADS framework's approach, don't write vague exclusions like "ignore admin scripts" — define specific, checkable characteristics instead:

- The process is digitally signed by a known vendor
- It runs on a predictable schedule (matches a known cron/task entry)
- It touches only expected file paths for its role
- It corresponds to an installed, known application (verifiable via software inventory)

Example: a backup tool reading thousands of files in sequence looks identical to staged exfiltration at the event level. It's benign-but-noisy only if it's signed, scheduled, and touching only the directories it's supposed to back up — not because "it's probably fine."

**Needs Review** — evidence is genuinely ambiguous even after applying the tie-break rules below. Don't force a verdict; an honest "unclear" beats a wrong confident label.

---

## 2. Assigning Technique IDs

Following the Palantir ADS framework's convention: **always tag both the tactic (parent category) and the technique together** — e.g. `Credential Access / OS Credential Dumping`, not just a bare technique ID.

- Every `true_positive` alert gets exactly **one primary technique**, with its tactic.
- **Sub-technique vs. parent:** ATT&CK techniques like T1003 (OS Credential Dumping) or T1055 (Process Injection) have many sub-techniques underneath them (T1003.001 LSASS Memory, T1055.012 Process Hollowing, etc.). Tag the **specific sub-technique** only if the evidence clearly shows the exact mechanism (e.g. you see LSASS memory being read → `T1003.001`). If the evidence only shows "something dumped credentials" without revealing how, stop at the parent technique (`T1003`).
- Additional **secondary technique IDs** may be added only if the alert genuinely reflects more than one distinct technique — not because two seem plausible.

---

## 3. Tie-Break Rules

Some ATT&CK techniques are near-mirrors of each other and will cause real confusion. Resolve these in advance rather than guessing case-by-case:

1. **Acquire vs. Compromise pairs** (e.g. `T1583` Acquire Infrastructure vs. `T1584` Compromise Infrastructure; `T1585` Establish Accounts vs. `T1586` Compromise Accounts) — if you can't tell whether the adversary bought/created the resource or stole it, default to the **Compromise** variant. It assumes less about intent and is the safer default for scoring.
2. **Two techniques seem equally plausible** → tag one primary, one secondary — don't guess and drop the other.
3. **Evidence is present but weak** (a single indicator, no corroborating context) → label `needs_review`, not `true_positive`.
4. **Could be an attack or a legitimate admin action** → check the Benign-but-Noisy criteria in Section 1 before defaulting to `true_positive`.
5. **Still unresolved** → flag it in the `rationale` field and discuss with your labeling partner before finalizing. Every resolved tie-break gets added back into this list.

---

## 4. Partial-Credit Spec

This defines what the eventual accuracy number actually means.

| Match quality | Score |
|---|---|
| Exact sub-technique match | 1.0 |
| Correct parent technique only | 0.5 |
| Correct tactic only (right category, wrong technique) | 0.25 |
| Wrong | 0.0 |

**Worked example.** True label: `T1055.012` (Process Hollowing, under Defense Evasion).

- Model predicts `T1055.012` → **1.0** (exact match)
- Model predicts `T1055` (Process Injection, no specific sub-technique) → **0.5** (correctly identified the broad mechanism, missed the exact method)
- Model predicts `T1027` (Obfuscated Files, also Defense Evasion) → **0.25** (right tactic, wrong technique)
- Model predicts `T1003` (OS Credential Dumping, Credential Access) → **0.0** (wrong tactic entirely)

---

## 5. Row Format (`data/golden/labels.jsonl`)

| Field | Description |
|---|---|
| `alert_id` | Unique identifier for the alert |
| `label` | One of `true_positive`, `benign_noisy`, `needs_review` |
| `technique_ids` | List of ATT&CK technique IDs, tagged with tactic (primary first, then secondary) |
| `source_dataset` | Which corpus the alert came from |
| `rationale` | One short sentence explaining the label |
| `labeler` | Name of the person who labeled it |
| `labeled_at` | Timestamp of labeling |

---

## 6. Amendment Log

Track every time this guide changes because of a real labeling disagreement.

| Date | Change | Reason |
|---|---|---|
| _(fill in as you go)_ | | |