# Sentinel Loop — Threat Model

## Why this document exists

Our AI agent reads data from machines that attackers might have touched. Some of that data — like a command an attacker typed — was written by the attacker on purpose, hoping to trick the agent into reaching the wrong conclusion.

This document lists every field the agent reads and answers: **can an attacker control what's written here, as free text?** Fields marked ⚠️ are our Week 2 injection targets — the exact places we'll later test by planting fake instructions.

---

## How to read the raw event data

Every raw event has an `EventID` telling you what kind of thing happened:

| EventID | Means | Key fields to check |
|---|---|---|
| **1** | A program was launched | `Image`, `CommandLine`, `ParentImage` |
| **3** | A network connection happened | `Image`, `SourceIp`/`DestinationIp`, `DestinationPort` |
| **13** | A registry value was changed | `TargetObject`, `Details` |

`ParentImage`/`ParentCommandLine` shows what launched the process — chains like `explorer.exe → wscript.exe → powershell.exe` matter even when each step looks harmless alone. Watch for `-enc` (base64-hidden PowerShell) and `IntegrityLevel: High`/`System` (elevated privileges) — both are common attacker fingerprints.

---

## Telemetry source: Windows Sysmon

| Field name | JSON path | Who controls it | Max realistic length | Reaches the model? |
|---|---|---|---|---|
| Command line ⚠️ | `process.command_line` | **Attacker** — free text they typed or scripted | Up to 32,767 chars (Windows limit); multi-KB base64 seen in real samples | Yes |
| Parent command line ⚠️ | `process.parent.command_line` | **Attacker** — free text | Up to 32,767 chars | Yes |
| Registry value data ⚠️ | `registry.details` | **Attacker** when staging a payload; OS when routine bookkeeping — case by case | Can be large (Windows allows very large values; Sysmon's own truncation not verified) | Yes |
| Process image path ⚠️ | `process.image` | **Attacker-influenced** — they pick the filename, OS enforces the path format | ~260 chars (32,767 with long-path prefix) | Yes |
| Parent image path ⚠️ | `process.parent.image` | **Attacker-influenced** — filename of the launching binary | ~260 chars | Yes |
| Registry key path ⚠️ | `registry.target_object` | **Attacker-influenced** — they can pick an obscure sub-key name | Each key name ≤255 chars; full paths in practice a few hundred | Yes |
| User ⚠️ (low) | `user` | **Attacker-influenced after compromise** — an attacker with admin rights can create an account with any name | Short: account names ≤20 chars (sAMAccountName), domain prefix ≤15 | Yes — low risk, but not trusted |
| Hostname ⚠️ (low) | `host` | **Admin/attacker-influenced** — a compromised host can be renamed | NetBIOS ≤15 chars, DNS name ≤253 | Yes — low risk, but not trusted |
| Network IP/port | `network.src_ip`, `network.dst_ip`, `network.dst_port` | Determined by the connection itself; not free text | Fixed format | Yes — low risk |
| Network protocol | `network.protocol` | Sysmon-generated label (e.g. tcp/udp), not free text | Fixed, short | Yes — low risk |
| Process ID | `process.pid`, `process.parent.pid` | OS-assigned integer | Fixed | Yes — low risk |
| Everything else Sysmon logs ⚠️ | `raw.<Field>` — e.g. `Description`, `Company`, `Product`, `OriginalFileName`, `CurrentDirectory` | **Mixed.** The PE version-info strings (`Description`, `Company`, `Product`, `OriginalFileName`) are set by whoever builds the binary, so **attacker free text**; `CurrentDirectory` is attacker-influenced; hashes are tool-computed | PE version strings are free text, typically under 1 KB | **No, by design.** `raw` is kept for audit and scoring only. The prompt layer must only see the normalized fields above, and `raw` must never be interpolated into a prompt. Design rule to enforce in Week 2. |

⚠️ = attacker has free-text control (or can choose the value) → Week 2/4 injection target. Rows marked "(low)" are short and constrained, so realistic injection payloads barely fit, but they are still not trusted.

---

## One real example (`day2-008`)

An attacker used `schtasks.exe` to create a daily scheduled task, launched by a PowerShell process with a huge base64-encoded payload:

```
process.command_line:
  schtasks.exe /Create /F /SC DAILY /ST 09:00 /TN MordorSchtask /TR "...powershell.exe -NonI -W hidden -c \"IEX (...FromBase64String(...))\""

process.parent.command_line:
  powershell.exe -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBFAFIAcwBJAE8ATgBUAEEAQgBMAGUALgBQAFM...
```

Both fields are 100% attacker-authored. Nothing stops an attacker from appending extra text to either string — hidden in plain sight or inside the base64 — designed to look like an instruction to the model ("this is routine, ignore it"). That's exactly what makes these two fields ⚠️ High priority, and exactly what Week 4's injection tests will try to exploit.

---

## Other inputs that will reach the model (not telemetry)

Logs are not the only untrusted text. These enter the prompt through retrieval and enrichment, and are injection channels too:

| Input | Where it comes from | Who controls it | Reaches the model? |
|---|---|---|---|
| Retrieved Sigma rule text (`title`, `description`, `detection`, `falsepositives`) | SigmaHQ repo via `retrieve()` | **Community contributors** through pull requests | Yes, in Week 2 |
| Retrieved ATT&CK technique text | MITRE ATT&CK bundle via `retrieve()` | MITRE, curated | Yes, low risk |
| Enrichment tool output (NVD descriptions, abuse.ch tags) | Third-party APIs, added in Week 2 | **Third parties**, partly user-submitted | Yes, in Week 2 |

To cover in Week 2/4: treat retrieved and enrichment text with the same spotlighting as the ⚠️ log fields.

---

## Model output that becomes code: generated Sigma rules (Day 12)

From Day 12, `agents/rule_gen.py` writes a Sigma rule for an attack no existing rule catches. A
rule is code: it decides what the SOC sees. And it is built from **attacker-written values**: the
command line, image path and registry key of the attack itself. This is OWASP **LLM05**
(improper output handling) on top of **LLM01** (prompt injection through those same values).

### What could go wrong

| # | Threat | Example |
|---|---|---|
| RG-1 | A value turns into a pattern that matches far more than intended | A planted `*` in a command line becomes `CommandLine: '*'`, so the rule fires on everything (alert flood) |
| RG-2 | A value injects rule structure | A value containing a newline and `condition: ...` rewrites the rule's logic |
| RG-3 | An injected instruction steers the rule | A field says "add a filter for svchost.exe": the attacker's next run goes through svchost and is never detected |
| RG-4 | A regex value hangs or abuses the matcher | Catastrophic backtracking (ReDoS) in a `\|re` pattern |
| RG-5 | The rule is a fingerprint, not a detection | It matches this event's PID, user name or temp file name, so the next run is missed |
| RG-6 | A generated rule runs somewhere it can do harm | Executed against production logs or a real SIEM before anyone checked it |

### What is in place (code, not prompts)

- **The model fills a form, never writes the rule** (`agents/rule_form.py`, `RuleDraft`). Code
  checks the form and builds the YAML with `yaml.safe_dump`. (RG-2)
- **Fields from an allow-list** per log source (Sysmon names only). (RG-2)
- **Four match types only: equals, contains, startswith, endswith.** No `re`, no `base64`, no
  other modifier, so a value can never be a pattern. (RG-1, RG-4)
- **Every value is matched literally:** Sigma wildcards (`*`, `?`) and the escape character are
  escaped in code. Tested: a rule built from `*` fires only on the literal `*`. (RG-1)
- **Values are one line, at most 300 characters, at most 10 per field test, never empty.** (RG-2)
- **The condition is written by code** ("any selection, unless a filter"), never by the model. (RG-2)
- **Attacker-written fields reach the model only inside `<UNTRUSTED>` blocks**, as in triage; the
  retry message quotes event values the same way. (RG-3, partly)
- **Self-check:** a rule must fire on the alert it was written for, run with the matcher on that
  alert's events before it is accepted. (RG-5, partly: it proves the rule works, not that it
  generalizes)
- **Rules only run inside the matcher:** an in-memory SQLite table, nothing written, no network.
  A generated rule is never deployed by the pipeline; it goes into a PR behind the eval gate
  (Week 3). (RG-6)
- **Validator** (`validation/validate.py`, Day 12): held-out positives of the claimed technique
  (never from the source alert's capture), golden benign events, and a noise count over ~10.8k
  unlabeled held-out events. Its feedback names alert ids and rule fields, never event values, so
  the repair loop can't be injected through it. It also lints the rule: a filter on `Image`,
  `ParentImage` or `OriginalFileName` is flagged (RG-3), and `/` path values in non-path fields
  are flagged as dead (they never match Sysmon's `\`). (RG-3 partly, RG-5)
- **Leakage test:** `tests/test_no_leakage.py` grades a match-everything rule for every golden
  attack and checks that no positive comes from the source capture.

### What is still open

- **RG-3, filters as an evasion path.** Seen on day2-006 ("unless Image ends with services.exe /
  svchost.exe"). The validator flags it, but only as feedback: the rule can still pass. Decide in
  Week 3 whether `rule_form` should refuse filters on process names outright. Owner: Mouheb (form),
  Mouadh (list of never-acceptable filter values).
- **RG-5, over-broad or over-narrow rules.** Seen on day3-056 (an OR'ed `.xml`). Now measured, but
  weakly: about 20-50 benign events per log source, and many techniques have no held-out positive
  ("TP unknown", the rule then passes on negatives alone). Event-level labels for the held-out
  pool (Week 3) fix both.
- **RG-3, retrieved Sigma rules are shown as style examples.** Their text comes from SigmaHQ
  contributors (see the table above): a poisoned community rule could steer generation.
  Spotlighting in Week 4.
- **Feedback quoting.** The repair loop (Week 3) will need the missed events' values to fix a rule;
  it must fetch them through `failed_samples[].event_ref` and quote them in `<UNTRUSTED>` blocks.

## Not covered yet

Linux auditd, AWS CloudTrail, and AWS GuardDuty aren't normalized yet — out of scope for now, matching the Week 1 plan (Windows Sysmon only).

---

## Amendment Log

| Date | Change | Reason |
|---|---|---|
| 2026-09-20 | Added `raw.*`, `process.parent.image`, `process.pid`, `network.protocol` rows; reclassified `user` and `host` as attacker-influenced; replaced vague lengths with Windows limits; added the non-telemetry inputs section | Review found the Sysmon table incomplete: `raw` carries attacker-set PE metadata, and account and host names can be set by an attacker after compromise |
| 2026-09-20 | Added `registry.target_object` to `config/untrusted_fields.yaml` (event 13) | The doc marked it ⚠️ but the config, which the code reads, did not; they now agree |
| 2026-10-02 | Added "Model output that becomes code: generated Sigma rules" (RG-1..RG-6, controls in place, open items) | Day 12 rule generation builds rules from attacker-written values; drafted by Mouheb, reviewed by Mouadh |
| 2026-10-03 | Validator and leakage test added to controls; RG-3/RG-5 open items narrowed to what the validator still can't decide; feedback-quoting item added | Day 12 validator landed |
