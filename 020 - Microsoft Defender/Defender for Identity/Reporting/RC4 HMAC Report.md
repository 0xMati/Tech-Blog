---
title: "Report: Weak cipher such as DES or RC4 report in Active Directory"
date: 2025-04-22
---

## RC4HMAC Logon

KQL query will provide a report of Weak cipher

### Query

```kusto
IdentityLogonEvents
| where Protocol == @"Kerberos"
| extend ParsedFields=parse_json(AdditionalFields)
| project Timestamp, ActionType, DeviceName, IPAddress, DestinationDeviceName, AccountName, AccountDomain, EncryptionType = tostring(ParsedFields.EncryptionType)
| where EncryptionType == @"Rc4Hmac"
```

### Use Case

- **Monitoring** RC4HMAC

### Source
https://github.com/DanielpFR/MDI

