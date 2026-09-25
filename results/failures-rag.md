# Failures: rag

2 failures out of 7 rows (dev; 1 transport errors skipped). Model openrouter:nvidia/nemotron-3-super-120b-a12b:free, prompt 2edd88418b70, labels b9ec2d319642.

Hints (guesses, not buckets): reasoning error? 1, retrieval miss? 1

---
### day2-014  (verdict needs_review != true_positive)

**hint:** reasoning error?  
**bucket:** _retrieval miss | reasoning error | schema error | label error_  
**note:** 

**Alert:** Atomic capture — manual review (medium), source dataset `empire_launcher_vbs.zip`

Event 0:
- source `windows_sysmon`, host `WORKSTATION5.theshire.local`, user `THESHIRE\pgustavo`
- process `C:\Windows\System32\wscript.exe`
- command line `"C:\windows\System32\WScript.exe" "C:\Users\pgustavo\Desktop\launcher.vbs" `
- parent `C:\Windows\explorer.exe` `C:\windows\Explorer.EXE`

**Label:** true_positive ['T1059.005'] by `Mouheb+Partner`: wscript.exe executing a script named launcher.vbs from the user's Desktop.
**Model:** needs_review ['T1059.005'] (confidence 0.4), tier 2, escalated: confidence 0.60 < 0.7
**Technique credit:** 1.00

> A user (pgustavo) launched wscript.exe from the legitimate system path to run a VBScript file (launcher.vbs) on their Desktop, with explorer.exe as parent — typical of a user double-clicking a script. The Desktop is a common location for both legitimate user scripts and malware delivered via phishing; no obfuscation, suspicious arguments, or follow-on activity are visible in this single event.

**Retrieved techniques (top 5):** ['T1547.001', 'T1218.011', 'T1037.001', 'T1059.005', 'T1218.014']  
**Retrieved Sigma rules:** ['e4a6b256-3e47-40fc-89d2-7a477edd6915', '1228c958-e64e-4e71-92ad-7d429f4138ba', 'c27515df-97a9-4162-8a60-dc0eeb51b775', '7cce6fc8-a07f-4d84-a53e-96e1879843c9', '438025f9-5856-4663-83f7-52f878a70a50']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/a791fcfd49ba05f2c5f38100081f823a

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

> The event shows a user-level process payload.exe from the Downloads directory modifying the EventLog service start type to disabled (DWORD 0x00000004), which is an attempt to impair defensive logging capabilities.

**Retrieved techniques (top 5):** ['T1547.002', 'T1547.001', 'T1543.003', 'T1547.010', 'T1218.011']  
**Retrieved Sigma rules:** ['790317c0-0a36-4a6a-a105-6e576bf99a14', '07743f65-7ec9-404a-a519-913db7118a8d', '46490193-1b22-4c29-bdd6-5bf63907216f', 'dc5c24af-6995-49b2-86eb-a9ff62199e82', '9c226817-8dc9-46c2-a58d-66655aafd7dc']
**Trace:** https://cloud.langfuse.com/project/cmub63msw005had0chtdazpl6/traces/cc4cceb5d8bd983c83935d24835aeefc
