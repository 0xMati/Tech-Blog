---
title: "Switch between Federated and Managed Authentication in Entra ID with PowerShell"
date: 2025-05-21
---

# 🔁 Switching Entra ID Domain from Federated to Managed (PHS)

## Objective

This article describes how to switch a Tenant in Microsoft Entra ID from **Federated** to **Managed** authentication.
This is typically required when deprecating an Active Directory Federation Services (AD FS) setup in favor of managed authentication (e.g. PHS/PTA).

## Prerequisites

- Entra ID Global Administrator privileges
- Microsoft Graph PowerShell SDK installed (`Microsoft.Graph` module)
- Ensure that Users Hashes are already synced to Entra ID (e.g., passwords are synced via Entra Connect)
- Backup of current federation settings (optional but recommended)

## Install Microsoft Graph PowerShell (if not already done)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement
```

Then connect:

```powershell
Connect-MgGraph -Scopes "User.ReadWrite.All", "Domain.ReadWrite.All", "Directory.Read.All"
```

> ⚠️ You may need to consent to these permissions or have an admin do so.

## Check Current Domain Authentication Settings

```powershell
Get-MgDomainFederationConfiguration -DomainId yourdomain.com
```

Or check directly:

```powershell
Get-MgDomain -DomainId yourdomain.com | Select-Object Id, AuthenticationType
```

You should see `Federated` as the authentication type.

## Convert Domain to Managed

### ✅ Option 1: Use Microsoft Graph (preferred)

```powershell
Update-MgDomain -DomainId 0x1mati.online -AuthenticationType Managed

```

![](assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-10-00-16.png)

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

# Switching Entra ID Domain from Managed to Federated Authentication (with ADFS)

## Objective

How to configure a Tenant in Microsoft Entra ID to use **Federated** authentication via AD FS instead of **Managed** authentication. This is typically required when onboarding an ADFS infrastructure (e.g., adfs.contoso.com) or re-enabling federation for an existing domain.

## ✅ Prerequisites

- Entra ID **Global Administrator** privileges.  
- The target domain (e.g., `yourdomain.com`) must already be **verified** in Azure AD.  
- A running **AD FS** service (e.g., `adfs.contoso.com`) with a valid signing certificate exported in DER (`.cer`) format.  
- Microsoft Graph PowerShell module **Microsoft.Graph.Identity.DirectoryManagement** installed.

## Install Microsoft Graph PowerShell Module

```powershell
# Install and import the Directory Management module
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Import-Module Microsoft.Graph.Identity.DirectoryManagement
```

## Enable Federation for Your Domain

1. **Connect to Microsoft Graph**

    ```powershell
    Connect-MgGraph -Scopes Domain.ReadWrite.All
    ```

2. **Prepare and encode your AD FS signing certificate**

Export your current ADFS Signin Certificate:

![](assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-09-51-08.png)

Run powershell commands:

    ```powershell
    $certPath    = "C:\temp\adfs-signing.cer"
    $certContent = [Convert]::ToBase64String(
                       (Get-Content -Path $certPath -Encoding Byte)
                   )
    ```

3. **Create the federation configuration**

    ```powershell
    New-MgDomainFederationConfiguration `
      -DomainId "yourdomain.com" `
      -IssuerUri "urn:federation:yourdomain.com" `
      -PassiveSignInUri "https://adfs.contoso.com/adfs/ls/" `
      -ActiveSignInUri "https://adfs.contoso.com/adfs/services/trust/2005/usernamemixed" `
      -MetadataExchangeUri "https://adfs.contoso.com/adfs/services/trust/mex" `
      -SigningCertificate $certContent `
      -SignOutUri "https://adfs.contoso.com/adfs/ls/?wa=wsignout1.0" `
      -FederatedIdpMfaBehavior "enforceMfaByFederatedIdp" `
      -PreferredAuthenticationProtocol "wsFed"
    ```

![](assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-09-54-10.png)

> **Note:**  
> - `-MetadataExchangeUri` lets Entra ID import your AD FS metadata for certificate auto-rollover.  
> - `-FederatedIdpMfaBehavior` set to `enforceMfaByFederatedIdp` forces MFA at ADFS and avoids duplicate prompts.  
> - `-PreferredAuthenticationProtocol` must be **lowercase** `wsFed`, `saml`, or `unknownFutureValue`.

## Validate Your Federation Configuration

```powershell
# Confirm the domain is now federated
Get-MgDomain -DomainId "yourdomain.com" | Select-Object Id, AuthenticationType
# => AuthenticationType: Federated

# View detailed federation settings
Get-MgDomainFederationConfiguration -DomainId "yourdomain.com" | Format-List
```

## Update or Rotate Your Federation Settings

If you need to renew the certificate, change endpoints, or adjust MFA behavior:

```powershell
# Retrieve the existing federation config
$fed = Get-MgDomainFederationConfiguration -DomainId "yourdomain.com"

# Update with a new certificate or modified parameters
Update-MgDomainFederationConfiguration `
  -DomainId "yourdomain.com" `
  -InternalDomainFederationId $fed.Id `
  -SigningCertificate "<NewBase64Cert>" `
  -FederatedIdpMfaBehavior "enforceMfaByFederatedIdp"
```

## ADFS Configuration

To establish trust on the AD FS side, configure a **Relying Party Trust** for your Azure AD domain and define the necessary claim rules:

<< Coming soon >>


## Post-Federation Validation

- Test login at [https://myapps.microsoft.com](https://myapps.microsoft.com) with a federated user (`@yourdomain.com`).  


## 📚 References

- [Microsoft Docs – Convert Domain to Managed](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-to-managed)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
