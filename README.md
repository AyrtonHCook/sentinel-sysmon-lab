# Microsoft Sentinel Lab: Sysmon & Security Logs

**Goal:** Ingest and analyse Windows Security + Sysmon logs in Microsoft Sentinel.  
**Skills Gained:** Log collection with AMA, KQL query writing, detection engineering.

---

## Overview
This lab collects logs from a Windows 10 VM into Sentinel.  
I created custom KQL rules to detect process creation anomalies, encoded PowerShell, and suspicious child processes.

---

## Quick Start
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "-enc"
```

---

## Results
- Logs ingested successfully via AMA + Sysmon.  
- Detected encoded PowerShell and anomalous process chains.  

---

## MITRE ATT&CK Mapping
| Tactic         | Technique                        | Evidence                 |
|----------------|----------------------------------|--------------------------|
| Execution      | T1059.001 (PowerShell)           | Encoded PowerShell logs  |
| Persistence    | T1547.001 (Registry Run Keys)    | Registry-based startup   |
| Defense Evasion| T1036 (Masquerading)             | Process name anomalies   |

---

## Documentation
- Full case study: [`/docs/sentinel-case-study.md`](docs/sentinel-case-study.md)  
- Detection queries in `/detections/`  
- Screenshots in `/screenshots/`

---

## Roadmap
- Add Sigma → Sentinel rule translation  
- Extend to Linux AMA ingestion  
- Automate dashboard creation
