# MDI Custom Detection Rule – Service Created Remotely on DC
🗓️ Published: 2025-03-20

---

**Time:** 11:45 AM  
**Description:** A new service has been remotely created on a Domain Controller.

---

## Rule Description

This custom detection rule identifies **remote service creation events** targeting Domain Controllers.  
Creating a service remotely is often a sign of persistence or lateral movement during post-exploitation.

---

## Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == @"Service creation"
| extend ParsedFields=parse_json(AdditionalFields)
| project Timestamp,ReportId, ActionType, TargetDeviceName, AccountName, AccountDomain,
         ServiceName=tostring(ParsedFields.ServiceName),
         ServiceCommand=tostring(ParsedFields.ServiceCommand)
| where ServiceName != @"Microsoft Monitoring Agent Azure VM Extension Heartbeat Service"
| where ServiceName != @"MOMAgentInstaller"
| where ServiceName !contains @"MpKsl"
```

### Remarks on Filtering
- You can filter out known legitimate agents or system services to reduce noise.
- Add additional `ServiceName` exclusions as needed.
- Cross-check with your known deployment tools (e.g., ConfigMgr, monitoring agents, etc.).

---

## ⚠️ Risk Analysis

- **Persistence Mechanism**  
  Attackers may install malicious services that auto-start with system boot.
- **Privilege Abuse**  
  Only privileged users can remotely create services on DCs.
- **Stealth Operations**  
  Custom or renamed services can go undetected in daily ops.

---

## Recommended Actions

1. **Review the Created Service**
   - What is the name and command of the service?
   - Is it tied to a known agent or part of a legitimate deployment?
2. **Validate the Source and Actor**
   - Who initiated the creation?
   - Is the device or user known and authorized?
3. **Correlate with Other Signals**
   - Combine with logon events or remote execution alerts (WMI, PSExec, etc.)
4. **Respond Accordingly**
   - Stop and disable the service if malicious.
   - Isolate the host and initiate investigation.

---

## References

- [Microsoft Defender for Identity – Service creation events](https://learn.microsoft.com/en-us/defender-for-identity/)
- [MITRE ATT&CK T1543.003 – Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

---

**Source**  
https://github.com/DanielpFR/MDI