# data/validation/benign

Benign process events the validator uses as **negatives** (a rule that fires on one gets a false
positive). Added for validator v2 (2026-10-06) because the captures hold almost no harmless
`cmd /c`, MSBuild or script-host activity: the old benign set had 0 `cmd /c` and 0 MSBuild events,
so over-broad rules for those tools passed.

One JSON object per line: `{"id", "why", "event"}`, `event` = a raw Sysmon EventID 1 record.

| file | rows | source |
|---|---|---|
| `synthetic-v1.jsonl` | 20 | **Hand-written** (ids `syn-*`): everyday dev/admin activity (Visual Studio and CI builds, npm, VS Code, GPO logon scripts, SCCM, slmgr/OSPP/prnmngr, a vendor .hta). Not real telemetry: field values follow real Sysmon output, but the events never happened. |
| `real-v1.jsonl` | 12 | Real, from the captures: `cscript MonitorKnowledgeDiscovery.vbs` run by the monitoring agent (MonitoringHost.exe). Not attack events, not golden alerts. |

Rules:
- Every row is hand-checked by Mouadh before use; `why` says why it is benign.
- No user-writable-folder script hosts (labeling guide rule 3 calls those true_positive).
- Changes are logged in `data/golden/CHANGELOG.md`. Checked by `tests/test_benign_set.py`.
