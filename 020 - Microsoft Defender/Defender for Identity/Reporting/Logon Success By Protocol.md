---
title: "Report: Logon Success by Protocol in Active Directory"
date: 2025-04-22
---

## Logon Success by Protocol

This query is used to generate a report of successful logons to Active Directory, summarized by protocol.

It can help track the distribution of authentication mechanisms used in the environment and provide visibility into the usage patterns of protocols such as NTLM, Kerberos, etc.

### Query

```kusto
IdentityLogonEvents
| where Timestamp > ago (7d) // shows activies in the last 7 days
| where ActionType == "LogonSuccess"
| where Application == "Active Directory"
| summarize count() by Protocol
```

### Use Case

- **Monitoring** authentication protocol distribution
- **Baseline** establishment for normal behavior
- **Detection** of unexpected increases in legacy protocol usage (e.g., NTLM)


