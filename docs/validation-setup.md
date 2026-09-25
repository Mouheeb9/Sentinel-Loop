# Validation setup: sigma-cli + Zircolite

How to compile Sigma rules and run them against telemetry, reproducibly. Written by Partner,
Day 5, so Mouheb can wire this into the automated `validate` node without asking.

## Install

Both tools are installed into the project's `uv`-managed `.venv`. **Do not use bare `pip`** —
this venv has no `pip.exe` seeded, so `pip install X` silently installs into your *global*
Python instead of the venv. Always use `uv add` / `uv pip`.

```powershell
# sigma-cli: a real project dependency, tracked in pyproject.toml
uv add --group dev sigma-cli pysigma-backend-elasticsearch

# a SigmaHQ ruleset to convert/run against (not committed, gitignored scratch clone)
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma-rules-tmp

# zircolite: NOT installable from PyPI (broken/incompatible metadata) -> clone + install
# from source instead. Not added to pyproject.toml; it's a standalone tool, not a library
# our code imports.
git clone --depth 1 https://github.com/wagga40/zircolite
uv pip install .\zircolite
```

## Proof 1 — sigma-cli compiles a real rule

```powershell
uv run sigma convert -t lucene -p ecs_windows sigma-rules-tmp/rules/windows/process_creation/proc_creation_win_mshta_http.yml
```

`-p ecs_windows`, not `-p sysmon` — `sysmon` is not a registered pipeline for the
`elasticsearch`/`lucene` backend family (check what's available with
`uv run sigma list pipelines <backend>`). `ecs_windows` is the Winlogbeat/ECS field mapping,
the right one for Sysmon-sourced rules going into an Elastic-family query.

Expected: prints a Lucene query, no error.

## Proof 2 — Zircolite fires on a known-malicious sample (external, sanity check)

Decoupled from our own data, to isolate "is the tool broken" from "is our data weird":

```powershell
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
uv run python zircolite\zircolite.py -e EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx -r sigma-rules-tmp\rules\windows\process_creation -p sysmon
```

Expected: 2 detections (`Script Interpreter Execution From Suspicious Folder` / T1059,
`Potential Dropper Script Execution Via WScript/CScript/MSHTA` / T1059.005+T1059.007).

Note: the `Discovery/` folder in this same repo gives **0** hits against `process_creation`
rules — not a bug, that folder only has pipe/network/group-enum events (Sysmon EID 3/18,
Security 4661/4798/4799), no Sysmon EID 1 (process creation) events at all. Match the rule
category to the event type actually present.

## Proof 3 — Zircolite confirms a real golden-set label, end to end

```powershell
uv run python zircolite\zircolite.py -e data\raw\security-datasets\psh_mshta_html_application_execution.zip -j -r sigma-rules-tmp\rules\windows\process_creation -p sysmon
```

Zircolite reads the `.zip` directly (`-j` = JSON-lines input; Mordor captures are JSON, not
raw `.evtx` — Zircolite's archive support handles the zip itself, no manual unzip needed).

`data/golden/labels.jsonl` row for this dataset:

```json
{"alert_id": "day2-005", "label": "true_positive", "technique_ids": ["T1218.005"], "source_dataset": "psh_mshta_html_application_execution.zip", ...}
```

Expected and actual result: top hit is `Suspicious MSHTA Child Process → T1218.005` (1 event),
plus 4 related rules (T1059, T1059.005/.001/.007, T1202) on the same capture — matches the
golden label exactly. This is the reproducible "rule you know should fire, fires, hit count
matches expectation" proof for the checkpoint.

## Gotchas

- `pip install X` in this venv installs globally, not into `.venv` — always `uv add` (project
  dependency) or `uv pip install` (venv-only, skips lock resolution; use for tools like
  `zircolite` that break `uv add`'s resolver).
- `zircolite` has no working PyPI release — install from its own repo clone.
- Rule category must match the event type in the file (`process_creation` needs Sysmon EID 1
  present; a folder of pipe/network/registry events gives a real, correct 0 hits).
- `--version` is not a valid `sigma` flag (there is no top-level version flag on this CLI).
