---
title: "Report: Kerberos vs NTLM Usage in Active Directory"
date: 2025-04-22
---

## Logon Success by Protocol

KQL query will provide the ratio of the success logon using NTLM and Kerberos

### Query

```kusto
IdentityLogonEvents
| where Timestamp > ago (7d) // shows activies in the last 7 days
| where ActionType == "LogonSuccess"
| where Application == "Active Directory"
| where Protocol in ("Ntlm", "Kerberos")
| summarize count() by Protocol
```
![](assets/Kerberos%20vs%20NTLM%20Usage/2025-04-22-13-43-33.png)


### Use Case

- **Monitoring** authentication protocol distribution

### Source
https://github.com/DanielpFR/MDI

