# MDI Custom Detection Rule – Task Scheduling Created Remotely on DC
🗓️ Published: 2025-02-20

---

**Time:** 9:49 AM  
**Description:** A new task scheduling has been created on a Domain Controller.

---

## Rule Description

This custom detection rule focuses on **task scheduling events** initiated on a DC.  
Malicious actors may use scheduled tasks for persistence, execution of payloads, or lateral movement.

---

## Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == @"task scheduling"
| extend ParsedFields=parse_json(AdditionalFields)
| project Timestamp,ReportId, ActionType, TargetDeviceName, AccountName, AccountDomain,
         TaskName=tostring(ParsedFields.TaskName),
         TaskCommand=tostring(ParsedFields.TaskCommand)
```

### Remarks on Filtering
- Add exclusions for known systems or automation tools if needed.
- Task names or commands associated with your organization's standard operations can be whitelisted.

---

## ⚠️ Risk Analysis

- **Persistence via Scheduled Task**
  A scheduled task can be used to re-execute malicious payloads on reboot or at defined intervals.
- **Remote Privileged Execution**
  Only privileged users should be able to create tasks on DCs remotely.
- **Command Execution Visibility**
  Monitoring `TaskCommand` reveals the nature of the action being scheduled.

---

## Recommended Actions

1. **Inspect the TaskCommand**
   - Does it launch PowerShell, cmd, or suspicious binaries?
2. **Identify the TaskName**
   - Some attackers use misleading or hidden names.
3. **Validate the Account and Source**
   - Confirm the legitimacy of the user and source system.
4. **Correlate with Other Alerts**
   - Was this preceded by lateral movement or login events?
5. **Respond**
   - Disable the scheduled task.
   - Investigate and isolate the host if malicious behavior is confirmed.

---

## References

- [Microsoft Defender for Identity – Task scheduling events](https://learn.microsoft.com/en-us/defender-for-identity/)
- [MITRE ATT&CK T1053 – Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)

---

**Source**  
https://jeffreyappel.nl/microsoft-defender-for-endpoint-series-advanced-hunting-and-custom-detections-part8/
https://github.com/DanielpFR/MDI

