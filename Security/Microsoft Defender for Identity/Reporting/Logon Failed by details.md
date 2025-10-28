---
title: "Report: Failed Logon & details in Active Directory"
date: 2025-10-22
---

## Logon Failed & details

This query is used to generate a report of failed logons to Active Directory, with details.

It can help track problems of authentication mechanisms used in the environment and provide visibility into the usage patterns of protocols such as NTLM, Kerberos, etc.

### Query

```kusto
IdentityLogonEvents
| where Timestamp > ago(30d)  // Activités des 90 derniers jours
| where ActionType == "LogonFailed"
| where Application == "Active Directory"
| project Timestamp, DeviceName, AccountName, Protocol, FailureReason, IPAddress, LogonType
| order by Timestamp desc
```

### Use Case

- **Monitoring** authentication protocol failure
- **Detection** of unexpected increases in failed authentication


