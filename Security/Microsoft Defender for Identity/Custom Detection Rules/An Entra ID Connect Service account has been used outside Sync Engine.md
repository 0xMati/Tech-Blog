---
title: "An Entra ID Connect Service Account Has Been Used Outside Sync Engine"
date: 2025-04-24
categories: ["Privilege escalation"]
mitre_techniques: ["T1098"]
---

## An Entra ID Connect Service Account Has Been Used Outside Sync Engine

This article describes how to detect the usage of Entra ID (Azure AD) Connect service accounts outside of their expected operational context — specifically, outside of the Azure AD Connect Sync Engine server.

### Query Information

- **Category:** Privilege escalation
- **MITRE Technique:** T1098 - [Account Manipulation](https://attack.mitre.org/techniques/T1098/)

### Description

Entra ID Connect (formerly Azure AD Connect) uses service accounts to synchronize identities between on-premises Active Directory and Entra ID. These accounts should only be used on the designated synchronization servers. If these accounts are used elsewhere, it may indicate credential misuse or a compromise.

This Kusto query detects logons of service accounts related to Azure AD Connect on devices **other than** the official sync servers.

This example use these sample accounts :

   - svc.aadc.maad@contoso.com, svc.aadc.maad@fabrikam.local for MA Accounts
   - AADCgMSA$ for the GMSA account of the engine
   - entraIDConnectServer.contoso.com, entraIDConnectServerStaging.contoso.com has Entra ID Connect Servers

### Detection Query

```kql
IdentityLogonEvents
| where AccountUpn in ('svc.aadc.maad@contoso.com', 'svc.aadc.maad@fabrikam.local') 
   or AccountName == 'AADCgMSA$'
| where DeviceName !in~ ('entraIDConnectServer.contoso.com', 'entraIDConnectServerStaging.contoso.com')
| extend AdditionalInfo = parse_json(AdditionalFields)
| project
     Timestamp,
     AccountUpn,
     DeviceName,
     AccountDomain,
     ActionType,
     LogonType,
     Protocol,
     ReportId,
     AccountName
| extend AccountCustomEntity = AccountUpn
```

### Risk

If the Entra ID Connect service account is used on an unauthorized machine, an attacker may be attempting to exploit its elevated permissions for lateral movement or privilege escalation.

### Response

- Investigate the device where the logon occurred.
- Verify if the usage was legitimate (e.g., troubleshooting by a system admin).
- Rotate the credentials of the affected service account.
- Review audit logs and related events on the suspicious host.

### Source

- Custom rule based on security best practices.
