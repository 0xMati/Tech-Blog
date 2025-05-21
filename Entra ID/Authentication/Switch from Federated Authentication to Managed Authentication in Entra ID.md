---
title: "Switch from Federated Authentication to Managed Authentication in Entra ID with powershell"
date: 2025-05-21
---

# 🔁 Switching Entra ID Domain from Federated to Managed (PHS)

## 🎯 Objective

This article describes how to switch a Tenant in Microsoft Entra ID from **Federated** to **Managed** authentication.
This is typically required when deprecating an Active Directory Federation Services (AD FS) setup in favor of managed authentication (e.g. PHS/PTA).

## ✅ Prerequisites

- Entra ID Global Administrator privileges
- Microsoft Graph PowerShell SDK installed (`Microsoft.Graph` module)
- Ensure that Users Hashes are already synced to Entra ID (e.g., passwords are synced via Entra Connect)
- Backup of current federation settings (optional but recommended)

## 📦 Install Microsoft Graph PowerShell (if not already done)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Then connect:

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All", "Domain.ReadWrite.All", "Directory.Read.All"
```

> ⚠️ You may need to consent to these permissions or have an admin do so.

## 🔍 Check Current Domain Authentication Settings

```powershell
Get-MgDomainFederationConfiguration -DomainId yourdomain.com
```

Or check directly:

```powershell
Get-MgDomain -DomainId yourdomain.com | Select-Object Id, AuthenticationType
```

You should see `Federated` as the authentication type.

## 🔄 Convert Domain to Managed

### ✅ Option 1: Use Microsoft Graph (preferred)

```powershell
Set-MgDomainFederationConfiguration -DomainId yourdomain.com -AuthenticationType Managed
```

### ❌ Option 2: Use MSOnline module (**deprecated and no longer functional**)

```powershell
Connect-MsolService
Set-MsolDomainAuthentication -DomainName yourdomain.com -Authentication Managed
```

> ⚠️ **Deprecated**: The MSOnline module has been officially deprecated by Microsoft and **no longer works** in most environments as of 2024.  
> Attempts to use it will result in authentication or permission errors.  
> Please use the Microsoft Graph PowerShell SDK instead (`Set-MgDomainFederationConfiguration`).

## ✅ Post-Switch Validation

You can re-check the auth type:

```powershell
Get-MgDomain -DomainId yourdomain.com | Select-Object Id, AuthenticationType
```

Or test login with a federated user at `https://myapps.microsoft.com`.

## 📚 References

- [Microsoft Docs – Convert Domain to Managed](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-to-managed)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
