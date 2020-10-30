# Advanced hunting queries for Microsoft Defender Security Center
This repo contains some personal [queries](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/advanced-hunting-overview) I developed for MS Defender Security Center for known threats

Hope can be useful. If you find any FP or you want suggest some modification please send a PR

## Ryuk ransomware
Following rules map the detection opportunities highlighted in Red Canary blog post [A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak](https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/). 
I suggest to read the blog post and then try the queries on your Security Center to identify FP or anomalies to be investigated

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
| where ProcessCommandLine contains "group"
```

### Detection Opportunity 4: Process hollowing of explorer.exe
```
DeviceProcessEvents
| where FileName == "svchost.exe"
| where InitiatingProcessFileName !in ("services.exe", "MsMpEng.exe")
```
TODO: I see some False Positive, try to improve the search

```
DeviceProcessEvents
| where FileName == "svchost.exe"
| where ProcessCommandLine matches regex "^$"
```
TODO: I see some False Positive, try to improve the search (parent process is ```svchost -k```)

### Detection Opportunity 5: Attempted lateral movement via WMI + PowerShell + Cobalt Strike
```
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLinecontains "-encodedcommand"
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
