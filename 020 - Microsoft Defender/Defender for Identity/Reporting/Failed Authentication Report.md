---
title: "Report: Failed Authentication report in Active Directory"
date: 2025-04-22
---

## Logon failed by failure reason

KQL query will provide a report of failure reason for logon failed

### Query

```kusto
IdentityLogonEvents
| where ActionType == "LogonFailed"
| where Application == "Active Directory"
| summarize count() by FailureReason
```

![](assets/Failed%20Authentication%20Report/2025-04-22-13-50-40.png)

### Use Case

- **Monitoring** authentication logon failed

### Source
https://github.com/DanielpFR/MDI

