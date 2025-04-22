---
title: "Report: NTLM V1 Usage in Active Directory"
date: 2025-04-22
---

## NTLM V1 Logon

Since the NTLMv1 hash is always at the same length, it is only a matter of seconds if an attacker wants to crack it. In addition, the challenge-response mechanism exposes the password to offline cracking. It is recommended not to use it if possible.

### Query

```kusto
IdentityLogonEvents
| where Timestamp > ago (7d) // shows activies in the last 7 days
| where ActionType == "LogonSuccess"
| where Application == "Active Directory"
| where Protocol in ("Ntlm", "Kerberos")
| summarize count() by Protocol
```


### Use Case

- **Monitoring** authentication NTLM V1

### Source
https://github.com/DanielpFR/MDI

