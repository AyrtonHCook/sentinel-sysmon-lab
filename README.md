# Microsoft Sentinel Lab: Windows Security & Sysmon Logs

## Summary
This lab records my build of a Microsoft Sentinel monitoring capability for a Windows 10 workstation, completed during defensive security studies. I provisioned a dedicated Sentinel workspace, onboarded the host by deploying the Azure Monitor Agent (AMA) through a Data Collection Rule (DCR), installed Sysmon so that the operational channel streamed into the Event table, and authored analytics rules for elevated command prompts, encoded PowerShell, and brute-force activity. Targeted simulations confirmed that host actions generate Sentinel incidents. The artefacts stored alongside this README show how telemetry, analytics logic, and incident workflows align.

I ran the project as an aspiring security analyst preparing for professional placements. Verification points measured log latency, confirmed key identifiers, and judged the investigative value of Sysmon enrichment, with observations recorded immediately to drive evidence-based refinements.

## Goal
Deploy Microsoft Sentinel with the Azure Monitor Agent to capture high-fidelity Windows host telemetry (Security Events and Sysmon) and validate custom detections for suspicious command execution and credential attack behaviours in a controlled lab environment.

## Skills Demonstrated
- Microsoft Sentinel workspace configuration and data connector management
- Azure Monitor Agent deployment and Data Collection Rule assignment
- Sysmon installation and verification on Windows 10
- Kusto Query Language (KQL) analytics rule authoring and tuning
- Threat detection testing through manual adversary simulation
- Log validation and troubleshooting across multiple telemetry tables
- MITRE ATT&CK technique mapping to detections

Completing the lab required me to integrate infrastructure deployment with detection engineering and investigative testing, demonstrating that I can deliver an end-to-end monitoring solution and present the outcomes clearly.

## Environment and Setup
| Item | Details |
| --- | --- |
| Host | Windows 10 virtual machine onboarded to Microsoft Sentinel |
| SIEM | Microsoft Sentinel workspace with scheduled analytics rules |
| Agent | Azure Monitor Agent (Heartbeat Category `Azure Monitor Agent`, Version `1.37.0.0`) |
| Telemetry Sources | Windows Security Events (`SecurityEvent` table) and Sysmon (`Event` table, `Microsoft-Windows-Sysmon/Operational`) |
| Additional Tooling | Sysmon with default configuration package |
| Evidence | Validation notes covering heartbeat, ingestion checks, detection status, and incident confirmation (refer to Supplementary Evidence) |

I selected AMA to align with Microsoft’s current ingestion model and to practise managing Data Collection Rules at scale. Sysmon ran with the default configuration to highlight benefits available without bespoke XML tuning, reflecting the constraints that early-career analysts often face when joining an existing security team.

## Quick Reproduction
The workflow comprised creating Sentinel-ready Azure resources, attaching the Windows virtual machine, deploying AMA with a DCR that captures Security Events and the Sysmon operational channel, enabling three scheduled analytics rules, and executing adversary simulations to provoke alerts. Detailed portal paths, command references, and timing notes are retained in [`CASE_STUDY.md`](CASE_STUDY.md) for practitioners who require procedural guidance.

## Findings
- **AMA heartbeat confirms agent health** — Heartbeat records for `SentinelVM1` display Category `Azure Monitor Agent` with Version `1.37.0.0`, proving the agent installation is functioning and reachable.
- **Windows Security Events ingestion validated** — Event ID 4688 process creation telemetry consistently populates the `SecurityEvent` table via AMA and the associated DCR, affirming coverage of core audit logs needed for process-based detections.
- **Sysmon telemetry flowing through DCR** — Sysmon events arrive in the `Event` table when the custom XPath `Microsoft-Windows-Sysmon/Operational!*` is targeted, demonstrating that enhanced endpoint telemetry supplements native security logs.
- **Detection rules operational** — Scheduled analytics for elevated command prompts, encoded PowerShell execution, and brute-force authentication are enabled, mapped to ATT&CK tactics, and show expected status in the Sentinel portal.
- **Alert raised during testing** — Simulated elevated `cmd.exe` execution triggered a Sentinel incident, evidencing end-to-end detection from host activity through to incident triage.

Together these findings trace the journey from configuration decisions to observable system behaviour, illustrating how native Windows logging and Sysmon enrichment combine to provide layered visibility.

## Results Summary
| Artefact | What it Proves |
| --- | --- |
| AMA heartbeat validation | Confirms AMA deployment and heartbeat reporting with Category `Azure Monitor Agent` and Version `1.37.0.0` |
| Security event ingestion validation | Demonstrates `SecurityEvent` table ingestion of Event ID 4688 process creation telemetry |
| Sysmon DCR configuration | Verifies Sysmon logs enter Sentinel through the SysmonWindows DCR targeting `Microsoft-Windows-Sysmon/Operational!*` |
| Analytics rule status review | Shows custom analytics rules are configured, enabled, and aligned to MITRE tactics |
| Alert trigger observation | Proves detection logic generates incidents when simulated attack activity occurs |

The artefacts provide qualitative and quantitative proof: heartbeat checks confirm the infrastructure foundation, event queries evidence telemetry flow, configuration screenshots document the content engineering work, and the incident record shows how the SOC would experience the detection.

## MITRE ATT&CK Mapping (if applicable)
| Technique ID | Technique Name | Detection / Evidence |
| --- | --- | --- |
| T1059 | Command and Scripting Interpreter | Elevated `cmd.exe` detection rule confirmed during lab validation |
| T1059.001 | PowerShell | Encoded PowerShell execution rule reviewed and tested |
| T1110 | Brute Force | Failed login correlation rule validated against simulated brute-force activity |

These mappings were embedded in the rule metadata so that incident responders can quickly identify which ATT&CK behaviours are being covered. Aligning detections to ATT&CK also helped me evaluate coverage breadth and ensured the lab speaks the same language as industry playbooks.

## Lessons Learned
- Data Collection Rules must be targeted precisely; after observing delayed events, I confirmed that assigning the DCR directly to the virtual machine resolved the gap.
- Sysmon delivers value only when both installation and DCR scoping are complete; missing either step leaves the Event table empty even though the service is running locally.
- Cross-referencing the `SourceSystem`, `Category`, and `Version` fields provided a reliable way to differentiate AMA traffic from legacy agents during validation queries.
- Generating on-demand telemetry by running small attack simulations accelerated analytic testing and gave me confidence in how Sentinel timelines reflect real user actions.

Capturing these lessons means I can apply them quickly in internships or junior roles, helping teams avoid common onboarding pitfalls.

## Safe Handling / Cost Control
- Disable or delete analytics rules when the lab is dormant to avoid unnecessary alert noise and preserve rule quotas.
- Stop or deallocate the Windows 10 virtual machine when idle to reduce compute expenditure during study periods.
- Remove the AMA extension and related DCRs before decommissioning the environment to prevent residual resource charges or stale configuration drift.

Following these practices keeps the lab affordable for a student budget while maintaining readiness for future demonstrations.

## Case Study Link
See [`CASE_STUDY.md`](CASE_STUDY.md) for the narrative walkthrough, portal references, and evidence log supporting this summary.

## Supplementary Evidence (Screenshots catalogued externally)
- `images/heartbeat.png` — Heartbeat table query illustrating AMA activity.
- `images/securityevent_ingestion.png` — SecurityEvent results showing Event ID 4688 process creation logs.
- `images/sysmondcr.png` — Data Collection Rule configuration capturing Sysmon operational events.
- `images/detection_rules.png` — Sentinel analytics rules dashboard with custom detections enabled.
- `images/alert_trigger.png` — Incident generated by the elevated command prompt analytic rule.

These screenshots substantiate the checkpoints referenced throughout this document and allow reviewers to validate my findings rapidly.
