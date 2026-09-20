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
| Command line ⚠️ | `process.command_line` | **Attacker** — free text they typed or scripted | Very large (multi-KB base64 seen in real samples) | Yes |
| Parent command line ⚠️ | `process.parent.command_line` | **Attacker** — free text | Very large | Yes |
| Registry value data ⚠️ | `registry.details` | **Attacker** when staging a payload; OS when routine bookkeeping — case by case | Varies, can be large | Yes |
| Process image path ⚠️ | `process.image` | **Attacker-influenced** — they pick the filename, OS enforces the path format | ~260 chars | Yes |
| Registry key path ⚠️ | `registry.target_object` | **Attacker-influenced** — they can pick an obscure sub-key name | Standard registry path length | Yes |
| User | `process.user` / `user` | OS-controlled | Fixed, short | Yes — low risk |
| Network IP/port | `network.src_ip`, `network.dst_ip`, `network.dst_port` | OS-controlled | Fixed, short | Yes — low risk |
| Hostname | `host` | OS-controlled | Fixed, short | Yes — low risk |

⚠️ = attacker has free-text control → Week 2/4 injection target.

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

## Not covered yet

Linux auditd, AWS CloudTrail, and AWS GuardDuty aren't normalized yet — out of scope for now, matching the Week 1 plan (Windows Sysmon only).

---

## Amendment Log

| Date | Change | Reason |
|---|---|---|
| _(fill in as you go)_ | | |