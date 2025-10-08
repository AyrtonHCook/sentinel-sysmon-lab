# Microsoft Sentinel Lab: Windows Security & Sysmon Logs

## Summary
I treated this lab as a chance to prove I can stand up Microsoft Sentinel monitoring for a Windows 10 workstation from scratch. I spun up a dedicated Sentinel workspace, onboarded the VM by deploying the Azure Monitor Agent (AMA) through a Data Collection Rule (DCR), installed Sysmon so its operational channel landed in the Event table, and wrote analytics rules for elevated command prompts, encoded PowerShell, and brute-force activity. Running targeted simulations showed me that real host actions create Sentinel incidents. The artefacts alongside this README capture how telemetry, analytics logic, and incident handling lined up during the build.

I kept notes like a trainee analyst who wants evidence for every decision. I measured log latency, tracked key identifiers, and checked how useful the Sysmon fields felt, updating the setup as soon as I spotted a gap.

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

Working through the lab forced me to blend infrastructure setup with detection engineering and hands-on testing, so I could show an end-to-end monitoring workflow and explain what each stage achieved.

## Environment and Setup
| Item | Details |
| --- | --- |
| Host | Windows 10 virtual machine onboarded to Microsoft Sentinel |
| SIEM | Microsoft Sentinel workspace with scheduled analytics rules |
| Agent | Azure Monitor Agent (Heartbeat Category `Azure Monitor Agent`, Version `1.37.0.0`) |
| Telemetry Sources | Windows Security Events (`SecurityEvent` table) and Sysmon (`Event` table, `Microsoft-Windows-Sysmon/Operational`) |
| Additional Tooling | Sysmon with default configuration package |
| Evidence | Validation notes covering heartbeat, ingestion checks, detection status, and incident confirmation (refer to Supplementary Evidence) |

I chose AMA so I could practise Microsoft’s current ingestion pattern and learn how DCRs scale. Running Sysmon with the default config let me observe how much value I could get before diving into custom XML, which matches what a junior analyst might inherit.

## Quick Reproduction
The workflow involved creating Sentinel-ready Azure resources, attaching the Windows virtual machine, deploying AMA with a DCR that collects Security Events and the Sysmon operational channel, enabling three scheduled analytics rules, and running small adversary simulations to trigger alerts. Detailed portal paths, command references, and timing notes live in [`CASE_STUDY.md`](CASE_STUDY.md) for anyone who wants step-by-step guidance.

## Findings
- **AMA heartbeat confirms agent health** — Heartbeat records for `SentinelVM1` show Category `Azure Monitor Agent` with Version `1.37.0.0`, so I know the agent is installed and reachable.
- **Windows Security Events ingestion validated** — Event ID 4688 process creation telemetry reliably lands in the `SecurityEvent` table via AMA and the linked DCR, giving me the baseline process data I needed.
- **Sysmon telemetry flowing through DCR** — Sysmon events appear in the `Event` table when the custom XPath `Microsoft-Windows-Sysmon/Operational!*` is targeted, proving the enhanced telemetry supplements the native logs.
- **Detection rules operational** — Scheduled analytics for elevated command prompts, encoded PowerShell, and brute-force authentication are enabled, mapped to ATT&CK tactics, and show the expected status in the Sentinel portal.
- **Alert raised during testing** — Simulated elevated `cmd.exe` execution generated a Sentinel incident, confirming the pipeline from host activity to incident triage.

Seeing these checkpoints one after another made it obvious how Windows logging and Sysmon enrichment combine to give layered visibility.

## Results Summary
| Artefact | What it Proves |
| --- | --- |
| AMA heartbeat validation | Confirms AMA deployment and heartbeat reporting with Category `Azure Monitor Agent` and Version `1.37.0.0` |
| Security event ingestion validation | Demonstrates `SecurityEvent` table ingestion of Event ID 4688 process creation telemetry |
| Sysmon DCR configuration | Verifies Sysmon logs enter Sentinel through the SysmonWindows DCR targeting `Microsoft-Windows-Sysmon/Operational!*` |
| Analytics rule status review | Shows custom analytics rules are configured, enabled, and aligned to MITRE tactics |
| Alert trigger observation | Proves detection logic generates incidents when simulated attack activity occurs |

Together the artefacts combine heartbeat checks, event queries, configuration screenshots, and the final incident record so anyone can follow my evidence trail.

## MITRE ATT&CK Mapping (if applicable)
| Technique ID | Technique Name | Detection / Evidence |
| --- | --- | --- |
| T1059 | Command and Scripting Interpreter | Elevated `cmd.exe` detection rule confirmed during lab validation |
| T1059.001 | PowerShell | Encoded PowerShell execution rule reviewed and tested |
| T1110 | Brute Force | Failed login correlation rule validated against simulated brute-force activity |

I added the MITRE ATT&CK mappings inside each rule so I could immediately see which behaviours I was covering and check my coverage breadth against common playbooks.

## Lessons Learned
- Data Collection Rules need precise targeting; when I saw delayed events, assigning the DCR directly to the VM closed the gap.
- I realised Sysmon only sends data if it’s installed and correctly linked to the DCR; missing either part leaves the Event table empty even though the service runs locally.
- Checking the `SourceSystem`, `Category`, and `Version` fields side by side helped me separate AMA traffic from older agents during validation queries.
- Generating on-demand telemetry by running controlled attack simulations sped up analytic testing and helped me understand how Sentinel timelines relate to user actions.

Capturing these reflections means I can carry them into placements and help teams avoid common onboarding mistakes.

## Safe Handling / Cost Control
- Disable or delete analytics rules when the lab is dormant to avoid unnecessary alert noise and preserve rule quotas.
- Stop or deallocate the Windows 10 virtual machine when idle to reduce compute expenditure during study periods.
- Remove the AMA extension and related DCRs before decommissioning the environment to prevent residual resource charges or stale configuration drift.

These habits keep the lab affordable for a student budget while leaving it ready for the next round of testing.

## Case Study Link
See [`CASE_STUDY.md`](CASE_STUDY.md) for the narrative walkthrough, portal references, and evidence log that back up this summary.

## Supplementary Evidence (Screenshots catalogued externally)
- `images/heartbeat.png` — Heartbeat table query illustrating AMA activity.
- `images/securityevent_ingestion.png` — SecurityEvent results showing Event ID 4688 process creation logs.
- `images/sysmondcr.png` — Data Collection Rule configuration capturing Sysmon operational events.
- `images/detection_rules.png` — Sentinel analytics rules dashboard with custom detections enabled.
- `images/alert_trigger.png` — Incident generated by the elevated command prompt analytic rule.

These screenshots support each checkpoint in this document so reviewers can verify my findings quickly.
