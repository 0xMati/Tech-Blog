# MDI Custom Detection Rule – A User Is Added or Removed to the Most Sensitive AD Groups
🗓️ Published: 2025-01-19

---

**Time:** 10:02 AM  
**Description:** Detects when a user is added to or removed from **sensitive Active Directory groups**, including default and custom ones.

---

## 💍 Rule Description

This custom detection rule monitors **group membership changes** for a predefined list of sensitive groups.  
It identifies whether the action was an **addition** or **removal**, and logs the associated actor and target user.

You can add or remove groups in the list below, including any custom security groups used in your organization.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
let SensitiveGroupName = pack_array(
    'Account Operators',
    'Administrators',
    'Domain Admins',
    'Backup Operators',
    'Domain Controllers',
    'Enterprise Admins',
    'Enterprise Read-only Domain Controllers',
    'Group Policy Creator Owners',
    'Incoming Forest Trust Builders',
    'Microsoft Exchange Servers',
    'Network Configuration Operators',
    'Print Operators',
    'Read-only Domain Controllers',
    'Replicator',
    'Schema Admins',
    'Server Operators',
    'My custom Sensitive group'
);

IdentityDirectoryEvents
| where Application == "Active Directory"
| where ActionType == "Group Membership changed"
| extend ToGroup = tostring(parse_json(AdditionalFields).["TO.GROUP"])
| extend FromGroup = tostring(parse_json(AdditionalFields).["FROM.GROUP"])
| extend Action = iff(isempty(ToGroup), "Remove", "Add")
| extend GroupName = iff(isempty(ToGroup), FromGroup, ToGroup)
| where GroupName in~ (SensitiveGroupName)
| project Timestamp, ReportId, ToGroup, FromGroup,
          Target_Account = TargetAccountDisplayName,
          Target_UPN = TargetAccountUpn,
          AccountSid, DC = DestinationDeviceName,
          Actor = AccountName, ActorDomain = AccountDomain, AdditionalFields
| sort by Timestamp desc
```

---

## ⚠️ Risk Analysis

- **Privilege Escalation**  
  Adding users to highly privileged groups like `Domain Admins` can result in full domain compromise.

- **Stealthy Removals**  
  Removal from sensitive groups may indicate privilege cleanup after unauthorized use.

- **Audit Gaps**  
  Without this detection, changes to group memberships could go unnoticed for long periods.

---

## 🛠️ Recommended Actions

1. **Validate the Action**
   - Confirm whether the change is part of an approved process.
2. **Review Actor Identity**
   - Was the actor authorized to make this change?
3. **Inspect the Target Account**
   - Is this account meant to be in a privileged group?
4. **Harden Change Control**
   - Implement group change approvals and alerts for Tier 0 groups.
5. **Audit Custom Groups**
   - Include business-critical or delegated admin groups that aren’t in the default list.

---

## 💎 References

- [Microsoft Security – Active Directory Monitoring](https://learn.microsoft.com/en-us/defender-for-identity/)
- [MITRE ATT&CK T1098 – Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Privileged Access Workstation (PAW)](https://aka.ms/PAW)

---

**Source**  
https://github.com/DanielpFR/MDI
