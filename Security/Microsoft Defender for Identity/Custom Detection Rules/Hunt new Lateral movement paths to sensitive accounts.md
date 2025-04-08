# MDI Custom Detection Rule – Hunt for Newly Identified Lateral Movement Paths to Sensitive Accounts
🗓️ Published: 2025-02-20

---

## 💍 Rule Description

**Microsoft Defender for Identity** identifies **new lateral movement paths** to sensitive accounts — similar to BloodHound analysis.  
These paths highlight potential escalation opportunities that attackers could exploit to gain access to high-value accounts.

> A newly discovered path suggests that, if followed, an attacker could take over a sensitive account.

---

## ⚠️ Risk Analysis

- **Privilege Escalation Path Mapping**  
  Shows that the environment allows reachable paths to sensitive accounts.
- **Attack Surface Visibility**  
  Identifies internal weaknesses before attackers can exploit them.
- **Real-Time Risk Emergence**  
  New paths could result from config drift, permissions, or account changes.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == "Potential lateral movement path identified"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend LateralMovementPathToSensitiveAccount = AdditionalFields.['ACTOR.ACCOUNT']
| extend FromAccount = AdditionalFields.['FROM.ACCOUNT']
| project
     Timestamp,
     LateralMovementPathToSensitiveAccount,
     FromAccount,
     DeviceName,
     AccountName,
     AccountDomain,
     ReportId
```

---

## 🛠️ Recommended Actions

1. **Map and Review the Path**
   - Use the visualized path in Defender for Identity or tools like BloodHound.
2. **Limit Access**
   - Reduce local admin rights, group memberships, or open sessions that enable these paths.
3. **Harden Source Accounts**
   - Protect accounts that are starting points with MFA and device hygiene.
4. **Enable Just-in-Time Access**
   - Use Privileged Identity Management to eliminate standing privileges.

---

## 💎 References

- [Microsoft Docs – Lateral Movement Paths](https://learn.microsoft.com/en-us/defender-for-identity/understand-lateral-movement-paths)
- [Original Detection Rule on GitHub](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/NewLateralMovementPathToSensitiveAccountIdentified.md)

