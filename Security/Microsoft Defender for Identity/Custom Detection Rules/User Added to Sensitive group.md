# MDI Custom Detection – User Added to Sensitive Group  
🗓️ Published: 2025-04-08  

---

## 📄 Description

This detection identifies when a user is added to **highly privileged Active Directory groups**, such as Domain Admins, Enterprise Admins, or Exchange Admins.  
This kind of activity is often associated with privilege escalation attempts.

Adversaries who gain elevated group memberships can perform actions with far-reaching impact across the environment.

Inspired by MITRE ATT&CK Technique [T1078.002 – Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002)

---

## ⚠️ Risk Analysis

- **Full Domain Control**  
  Membership in sensitive groups provides near-unrestricted control over the domain and infrastructure.

- **Persistence and Evasion**  
  Attackers may use elevated rights to create backdoors, disable security tools, or extract credentials.

- **False Positives**  
  Admins may legitimately assign users to privileged groups. Always validate against change management logs.

---

## 🔍 Detection Logic (KQL Query)

```kql
let SensitiveGroups = dynamic(['Domain Admins', 'Enterprise Admins', 'Exchange Admins']); // Add your sensitive groups to this list
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType == "Group Membership changed"
| extend Group = parse_json(AdditionalFields).['TO.GROUP']
| extend GroupAdditionInitiatedBy = parse_json(AdditionalFields).['ACTOR.ACCOUNT']
| project-reorder Group, GroupAdditionInitiatedBy
| where Group has_any (SensitiveGroups)
```

---

## 🛠️ Recommended Actions

- **Validate if the change was expected** via admin logs or ticketing system.
- **Review the initiator account activity** around the time of the group change.
- **Restrict who can modify group memberships** and audit all changes to sensitive groups.
- **Alert and respond automatically** to unexpected changes using Defender for Identity or Sentinel rules.

---

## 📎 References

- [Original detection rule](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/UserAddedToSensitiveGroup.md)
- [Microsoft Docs – Sensitive Entities in Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/entity-tags#sensitive-entities)
- [MITRE T1078.002 – Domain Accounts](https://attack.mitre.org/techniques/T1078/002)

---
