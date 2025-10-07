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
> The numbered stages below assume you have the **Contributor** role in the target subscription and access to a Windows 10 lab virtual machine. Each stage lists the exact Azure portal path or PowerShell/command prompt action that was used in the reference build so that you can reproduce the lab end to end.

1. **Prepare Azure resources**
   - Portal navigation: **Home > Resource groups > Create** → create a group such as `sentinel-lab-rg` in the region that hosts your VM.
   - Portal navigation: **Home > Log Analytics workspaces > Create** → place the workspace (for example `sentinel-lab-law`) in the same region/resource group and note the workspace ID.
   - Enable Microsoft Sentinel: **Microsoft Sentinel > Create** → select the workspace created above and complete the enablement wizard. The workspace now appears under **Microsoft Sentinel > Workspaces**.
2. **Associate the Windows VM with the workspace**
   - Portal navigation: **Virtual machines > <your Windows VM> > Identity** → confirm the VM has a system-assigned managed identity (enable if needed).
   - Portal navigation: **Virtual machines > <your Windows VM> > Logs** → select the Log Analytics workspace created earlier; this links the VM and ensures the workspace is available when you deploy AMA.
3. **Deploy the Azure Monitor Agent (AMA)**
   - Portal navigation: **Virtual machines > <your Windows VM> > Extensions + applications > Add** → choose **AzureMonitorWindowsAgent** and accept the defaults.
   - Create a Data Collection Rule (DCR): **Azure Monitor > Data Collection Rules > Create**. Use the `Windows servers` template, target the VM, and select the Log Analytics workspace. Name the rule (e.g., `Windows-AMA-DCR`).
   - Validation query (run in Sentinel Logs):
     ```kql
     Heartbeat
     | where Category == "Azure Monitor Agent"
     | summarize LatestVersion = any(Version) by Computer
     ```
     Expect to see the VM with Version `1.37.0.0` or later.
4. **Enable Windows Security Events via AMA**
   - Portal navigation: **Microsoft Sentinel > <workspace> > Content management > Data connectors > Windows Security Events via AMA**.
   - Select **Open connector page**, choose **Connect**, and associate the connector with the DCR created in step 3 (check **Process creation events** so that Event ID 4688 is included).
   - Validation query:
     ```kql
     SecurityEvent
     | where EventID == 4688
     | summarize Events = count() by Computer, Process
     ```
     Generate a fresh process (e.g., launch Notepad) if the count is zero.
5. **Install Sysmon and add the Sysmon event stream**
   - On the Windows VM open an elevated PowerShell session and run:
     ```powershell
     Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
     Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
     & "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i
     ```
   - Update the DCR: **Azure Monitor > Data Collection Rules > Windows-AMA-DCR > Edit** → under **Collect and deliver > Windows event logs**, add a custom XPath of `Microsoft-Windows-Sysmon/Operational!*` targeting the **Event** table.
   - Validation query:
     ```kql
     Event
     | where EventLog == "Microsoft-Windows-Sysmon/Operational"
     | summarize Events = count() by EventID
     ```
6. **Configure analytics rules**
   - Portal navigation: **Microsoft Sentinel > <workspace> > Configuration > Analytics > + Create > Scheduled query rule**.
   - Create or enable rules that mirror the lab detections:
     - *Suspicious Elevated Command Prompt Activity* — 5-minute run frequency, 5-minute lookback.
     - *Encoded PowerShell Execution* — same schedule, raise Medium severity.
     - *Brute Force Login Detection* — aggregate failed logons followed by success.
   - Ensure each rule is **Enabled** and mapped to the appropriate MITRE tactic.
7. **Run validation simulations from the VM**
   - Elevated command prompt: `Start-Process cmd.exe -Verb RunAs` (accept the UAC prompt).
   - Encoded PowerShell: `powershell.exe -EncodedCommand SQBFAFgALgBlAHgAZQAgACIAQwBtAGQAIgA=` (decodes to `IEX "Cmd"` for harmless execution).
   - Brute-force pattern: run `runas /user:.\labuser cmd.exe` three times with an incorrect password, then a fourth time with the correct password.
   - Each action should emit SecurityEvent/Sysmon telemetry. Allow 5–10 minutes for Sentinel analytics to evaluate.
8. **Confirm alerts and document evidence**
   - Portal navigation: **Microsoft Sentinel > <workspace> > Incidents** → verify incidents tied to the three rules appear and capture screenshots.
   - Record the query outputs and incident IDs to maintain reproducibility notes (see `CASE_STUDY.md` for the expected evidence format).

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
See [`CASE_STUDY.md`](CASE_STUDY.md) for a narrative walkthrough and evidence summary.

## Supplementary Evidence (Screenshots catalogued externally)
- `images/heartbeat.png` — KQL query against the Heartbeat table demonstrating AMA activity.
- `images/securityevent_ingestion.png` — SecurityEvent table results showing EventID 4688 process creation logs.
- `images/sysmondcr.png` — Data Collection Rule configuration targeting Sysmon operational logs.
- `images/detection_rules.png` — Sentinel analytics rules dashboard with custom detections enabled.
- `images/alert_trigger.png` — Incident generated by the elevated command prompt analytic rule.
