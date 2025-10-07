# Microsoft Sentinel Lab: Windows Security & Sysmon Logs

## Summary
This lab configures Microsoft Sentinel to ingest both Windows Security Events and Sysmon telemetry from a Windows 10 virtual machine. The Azure Monitor Agent (AMA) collects log data that is validated through heartbeats and log count queries. Three scheduled analytics rules detect elevated command prompts, encoded PowerShell execution, and brute-force logins. Manual adversary simulations confirmed telemetry flow and alert fidelity, with observation notes recorded for each validation step; supporting screenshots are cataloged separately for reference rather than embedded here.

## Goal
Deploy Microsoft Sentinel with the Azure Monitor Agent to capture high-fidelity Windows host telemetry (Security Events and Sysmon) and validate custom detections for suspicious command execution and credential attack behaviors in a controlled lab environment.

## Skills Demonstrated
- Microsoft Sentinel workspace configuration and data connector management
- Azure Monitor Agent deployment and Data Collection Rule (DCR) assignment
- Sysmon installation and verification on Windows 10
- Kusto Query Language (KQL) analytics rule authoring and tuning
- Threat detection testing through manual adversary simulation
- Log validation and troubleshooting across multiple telemetry tables
- MITRE ATT&CK technique mapping to detections

## Environment and Setup
| Item | Details |
| --- | --- |
| Host | Windows 10 VM connected to Microsoft Sentinel |
| SIEM | Microsoft Sentinel workspace with scheduled analytics rules |
| Agent | Azure Monitor Agent (Heartbeat Category `Azure Monitor Agent`, Version `1.37.0.0`) |
| Telemetry Sources | Windows Security Events (`SecurityEvent` table), Sysmon (`Event` table with `Microsoft-Windows-Sysmon/Operational`) |
| Additional Tooling | Sysmon (default configuration) |
| Evidence | Validation notes detailing heartbeat, ingestion confirmation, detection rules, and alerting (see Supplementary Evidence for screenshot references) |

## Quick Reproduction
1. Deploy AMA to the Windows 10 VM via Azure VM extensions and confirm heartbeat logs.
2. Enable the Windows Security Events data connector in Sentinel and verify EventID 4688 process creation logs.
3. Install Sysmon with the default configuration and assign a DCR for `Microsoft-Windows-Sysmon/Operational!*`.
4. Run validation KQL queries:
   ```kql
   search *
   | summarize Events=count() by $table
   ```
   ```kql
   Event
   | where EventLog == "Microsoft-Windows-Sysmon/Operational"
   | summarize Count=count() by EventID
   ```
   ```kql
   SecurityEvent
   | summarize Count=count() by EventID
   ```
5. Configure the scheduled analytics rules listed in the Findings section with a 5-minute frequency and lookback.
6. Simulate attacks: launch elevated `cmd.exe`, execute PowerShell with `-enc`, and perform repeated failed logins followed by success.

## Findings
- **AMA heartbeat confirms agent health** — Heartbeat entries show Category `Azure Monitor Agent` and Version `1.37.0.0`, recorded during validation of the Windows 10 host named `SentinelVM1` (captured in `images/heartbeat.png`).
- **Windows Security Events ingestion validated** — EventID 4688 process creation logs populate `SecurityEvent`, confirming successful collection through the AMA and DCR pipeline (illustrated in `images/securityevent_ingestion.png`).
- **Sysmon telemetry flowing through DCR** — Sysmon events are visible in the `Event` table after targeting `Microsoft-Windows-Sysmon/Operational!*` via a custom XPath query in the SysmonWindows data collection rule (documented in `images/sysmondcr.png`).
- **Detection rules operational** — Scheduled analytics rules for elevated command prompts, encoded PowerShell execution, and brute-force logins are enabled, each mapped to appropriate MITRE ATT&CK tactics (summarized in `images/detection_rules.png`).
- **Alert raised during testing** — A Sentinel incident was generated when an elevated `cmd.exe` execution was simulated, demonstrating end-to-end alerting (evidenced by `images/alert_trigger.png`).

## Results Summary
| Artefact | What it Proves |
| --- | --- |
| AMA heartbeat validation | AMA deployed and reporting heartbeats with Category `Azure Monitor Agent` and Version `1.37.0.0` |
| Security event ingestion validation | `SecurityEvent` table receiving Windows Security telemetry including EventID 4688 |
| Sysmon DCR configuration | Sysmon logs ingested via the SysmonWindows DCR targeting `Microsoft-Windows-Sysmon/Operational!*` |
| Analytics rule status review | Analytics rules configured, enabled, and aligned with MITRE tactics |
| Alert trigger observation | Detection rules generate incidents when simulated attack activity is executed |

## MITRE ATT&CK Mapping (if applicable)
| Technique ID | Technique Name | Detection / Evidence |
| --- | --- | --- |
| T1059 | Command and Scripting Interpreter | Elevated `cmd.exe` detection rule confirmed during lab validation |
| T1059.001 | PowerShell | Encoded PowerShell execution rule reviewed and tested |
| T1110 | Brute Force | Failed login correlation rule validated against simulated brute-force activity |

## Lessons Learned
- Assigning Data Collection Rules is mandatory for AMA ingestion.
- Sysmon requires explicit installation and DCR configuration to surface data in Sentinel.
- `SourceSystem` labels can be misleading; validate using Category and Version fields.
- Generating fresh telemetry on demand is the fastest path to detection testing.

## Safe Handling / Cost Control
- Disable or delete unused analytics rules after testing to prevent unnecessary alerting.
- Stop or deallocate the Windows 10 VM when the lab is idle to avoid compute charges.
- Remove the AMA extension and DCRs if the lab environment is being torn down permanently.

## Case Study Link
No `docs/CASESTUDY.md` file is present in this repository.

## Supplementary Evidence (Screenshots catalogued externally)
- `images/heartbeat.png` — KQL query against the Heartbeat table demonstrating AMA activity.
- `images/securityevent_ingestion.png` — SecurityEvent table results showing EventID 4688 process creation logs.
- `images/sysmondcr.png` — Data Collection Rule configuration targeting Sysmon operational logs.
- `images/detection_rules.png` — Sentinel analytics rules dashboard with custom detections enabled.
- `images/alert_trigger.png` — Incident generated by the elevated command prompt analytic rule.
