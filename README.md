# Advanced hunting queries for Microsoft Defender Security Center
This repo contains some personal [queries](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-overview) I developed for MS Defender Security Center for known threats

Hope can be useful. If you find any FP or you want suggest some modification please send a PR

## Red Canary - detection of Ryuk ransomware
Detection opportunities highlighted in Red Canary blog post [A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/)

### Detection Opportunity 1: Process hollowing of cmd.exe
```
DeviceProcessEvents
| where InitiatingProcessFileName == "cmd.exe"
| where ProcessCommandLine matches regex "^$"
| where FileName has_any("net.exe", "explorer.exe", "nltest.exe")
```

### Detection Opportunity 2: Enumerating domain trusts activity with nltest.exe
```
DeviceProcessEvents
| where FileName == "nltest.exe"
| where ProcessCommandLine has_any("/dclist:", "/domain_trusts", "/all_trusts")
```

### Detection Opportunity 3: Enumerating domain admins with net group
```
DeviceProcessEvents
| where FileName == "net.exe"
// exclude local PC groups enumeration from the results, can generate FP
// e.g. you have hits for local groups when Defender ATP collects the investigation package
| where ProcessCommandLine !contains "localgroup"
| where ProcessCommandLine contains "group"
```

### Detection Opportunity 4: Process hollowing of explorer.exe
```
DeviceProcessEvents
| where FileName == "svchost.exe"
| where InitiatingProcessFileName !in ("services.exe", "MsMpEng.exe")
// exclude from the search parent process svchost.exe with -k option
| where not(InitiatingProcessFileName == "svchost.exe" and InitiatingProcessCommandLine contains "-k")
```
TODO: I see some False Positive, try to improve the search

```
DeviceProcessEvents
| where FileName == "svchost.exe"
| where ProcessCommandLine matches regex "^$"
// exclude from the search parent process svchost.exe with -k option
| where not(InitiatingProcessFileName == "svchost.exe" and InitiatingProcessCommandLine contains "-k")
```

### Detection Opportunity 5: Attempted lateral movement via WMI + PowerShell + Cobalt Strike
```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-encodedcommand"
```

```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where InitiatingProcessFileName == "cmd.exe"
| where InitiatingProcessParentFileName == "wmiprvse.exe"
```

### Detection Opportunity 6: Lateral movement via Cobalt Strike’s SMB PsExec module
```
DeviceProcessEvents
| where FileName == "rundll32.exe"
| where ProcessCommandLine matches regex "^$"
```
TODO: implemnent connection check for the process

### Detection Opportunity 7: Enumerating enterprise administrator accounts
Check Detection Opportunity 3

### Detection Opportunity 10: Adfind extracting information from Active Directory
```
DeviceProcessEvents
| where FileName == "adfind.exe"
```

## Vitali Kremez - detection of Ryuk ransomware
Detection steps highlighted in Vitali Kremez blog post [Anatomy of Attack: Inside BazarBackdoor to Ryuk Ransomware "one" Group via Cobalt Strike](https://www.advanced-intel.com/post/anatomy-of-attack-inside-bazarbackdoor-to-ryuk-ransomware-one-group-via-cobalt-strike)

### Step 4: Review the network of the host via "net view"
```
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "net.exe"
| where ProcessCommandLine contains "view"
// exclude FP
| where ProcessCommandLine !contains "vmware-view-usbd"
```

### Step 13: Grant net share full access to all for Ryuk ransomware
```
DeviceProcessEvents
| where FileName == "net.exe"
| where ProcessCommandLine has "share" and ProcessCommandLine contains "GRANT"
```
Check for a GRANT; on the post Vitali shows a FULL access to Everyone ```net share aaa$=C:\aaa /GRANT:Everyone,FULL```

# FireEye - Back in a Bit: Attacker Use of the Windows Background Intelligent Transfer Service
Detection of bitsadmin.exe usage to download malware and create persistence as shown in FireEye post [Back in a Bit: Attacker Use of the Windows Background Intelligent Transfer Service](https://www.fireeye.com/blog/threat-research/2021/03/attacker-use-of-windows-background-intelligent-transfer-service.html)

### bitsadmin download activity
```
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName == "bitsadmin.exe"
| where ProcessCommandLine contains_cs "download"
```
Check using bitsadmin to create a job that downloads an executable (malware) and stores it somewhere

### bitsadmin create a persistent job activity
```
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName == "bitsadmin.exe"
| where ProcessCommandLine contains_cs "persistence"
```
Check using bitsadmin to create a job to gain persistence
