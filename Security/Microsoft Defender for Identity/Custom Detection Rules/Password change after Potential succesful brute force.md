# MDI Custom Detection Rule – Password Change After Successful Brute Force
🗓️ Published: 2025-02-20

---

## 🧠 MITRE ATT&CK Techniques

- [T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## 💍 Rule Description

Adversaries may attempt brute-force attacks to gain access to accounts when passwords are unknown or password hashes are obtained.  
Once successful, the attacker may immediately **change the password** to maintain persistence and block legitimate user access.

This rule identifies brute force patterns **followed by a password change**, using correlated thresholds and timing.

Variables used in this rule:

- `FailedLogonsThreshold` – Minimum failed attempts (default: 20)
- `SuccessfulLogonsThreshold` – Minimum successful logons (default: 1)
- `TimeWindow` – Time period in which failed and successful attempts occur (default: 15 minutes)
- `SearchWindow` – Time gap between the brute force and the password change (default: 120 minutes)

---

## ⚠️ Risk Analysis

- **Persistence After Access**  
  Changing passwords post-compromise is a strong sign of attacker intent to **maintain access**.
- **User Lockout and Service Disruption**  
  May result in helpdesk activity or service account failure.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
let FailedLogonsThreshold = 20;
let SuccessfulLogonsThreshold = 1;
let TimeWindow = 15m;
// Time between the succesful brute force and password change. Difference should be added in minutes
let SearchWindow = 120;
IdentityLogonEvents
// Filter emtpy UPN
| where isnotempty(AccountUpn)
| summarize
    TotalAttempts = count(),
    SuccessfulAttempts = countif(ActionType == "LogonSuccess"),
    FailedAttempts = countif(ActionType == "LogonFailed")
    by bin(Timestamp, TimeWindow), AccountUpn
// Use variables to define brute force attack
| where SuccessfulAttempts >= SuccessfulLogonsThreshold and FailedAttempts >= FailedLogonsThreshold
// join password changes
| join kind=inner (IdentityDirectoryEvents
    | where Timestamp > ago(30d)
    | where ActionType == "Account Password changed"
    | where isnotempty(TargetAccountUpn)
    | extend PasswordChangeTime = Timestamp
    | project PasswordChangeTime, TargetAccountUpn)
    on $left.AccountUpn == $right.TargetAccountUpn
// Collect timedifference between brute force (note that is uses the bin time) and the password change
| extend TimeDifference = datetime_diff('minute', PasswordChangeTime, Timestamp)
// Remove all entries where the password change took place before the brute force
| where TimeDifference > 0
| where TimeDifference <= SearchWindow
```

---

## 🛠️ Recommended Actions

1. **Review Account Activity**
   - Correlate with VPN or RDP access.
   - Determine if account is linked to an interactive user or service.

2. **Force Password Reset**
   - Initiate emergency credential reset and investigate downstream systems.

3. **Audit for Lateral Movement**
   - Follow up with activity on Tier 0 assets.

---

## 💎 References

- [MITRE ATT&CK T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE DS0002 – User Account Modification](https://attack.mitre.org/datasources/DS0002/#User%20Account%20Modification)
- [Original Detection Rule on GitHub](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/PasswordChangeAfterSuccesfulBruteForce.md)

