# CDR – Remote WMI Execution on DC
🗓️ Published: 2025-02-20

---

**Time:** 9:41 AM  
**Description:** A PowerShell command was remotely executed from (or to) a Domain Controller.

---

## 💍 Rule Description

This custom detection rule focuses on **WMI-based remote execution** events specifically targeting Domain Controllers.  
Remote WMI execution on DCs can be an indicator of lateral movement or unauthorized admin activities.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == @"WMI execution"
| extend Command = todynamic(AdditionalFields)["WMI execution"]
| project Timestamp, ReportId, DeviceName, IPAddress, DestinationDeviceName, AccountName, AccountDomain, Command
```

### 🔖 Remarks on Filtering
- Similar to PowerShell remote executions, you can **add filters** to remove legitimate machine-to-machine or DC-to-DC scenarios.
- Validate if the source and destination machines are part of normal admin workflows.
- If unexpected, investigate the command invoked and verify the user's intent.

---

## 🛠️ Recommended Steps

1. **Correlate the IP or DeviceName**  
   Confirm if the request originated from a known admin workstation or a suspicious host.
2. **Review the Command**  
   Is it a standard WMI query or does it look malicious, e.g., a script that downloads or modifies system files?
3. **Check User Legitimacy**  
   Confirm if the account used is privileged and if they truly performed this operation.
4. **Add Additional KQL Filters**  
   Exclude known service accounts, monitored hosts, or standard DC maintenance tasks to reduce noise.

---

## 🧩 Context & Mitigation

- WMI is powerful for remote system administration but often abused for stealthy lateral movement.
- Ensure least privilege and monitor all remote admin protocols. 
- Combine with additional telemetry (EDR logs, event logs) for a full picture.

---

**Source**  
_CDR – Remote WMI execution on DC (Feb 20, 2025, 9:41 AM).  
PowerShell command executed remotely from or to a DC.  
Custom Detection Rule: YES_

> *Filter can be added to remove legitimate machine or DC to DC scenario*

---

_Use this detection as part of your broader Microsoft Defender for Identity strategy to detect suspicious remote execution activities._
