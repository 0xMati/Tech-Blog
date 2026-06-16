---
title: "Switch between Federated and Managed Authentication in Entra ID with PowerShell"
date: 2025-05-21
---

# 🔁 Switch between Federated and Managed Authentication in Entra ID with PowerShell

This article covers the **two opposite migrations** of a verified domain in Microsoft Entra ID, end-to-end with the Microsoft Graph PowerShell SDK:

| Direction | Typical scenario | Where to look |
|---|---|---|
| **Federated → Managed** | Decommissioning AD FS in favor of PHS / PTA | [Part 1](#part-1--federated--managed-decommissioning-ad-fs) |
| **Managed → Federated** | Onboarding (or re-onboarding) an AD FS farm | [Part 2](#part-2--managed--federated-onboarding-ad-fs) |

The common prerequisites and inventory commands below apply to both directions.

---

## Common prerequisites

- Entra ID **Global Administrator** privileges.
- Microsoft Graph PowerShell SDK installed.
- The target domain (e.g. `yourdomain.com`) must already be **verified** in Entra ID.

### Install Microsoft Graph PowerShell

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force
Import-Module Microsoft.Graph.Identity.DirectoryManagement
```

### Connect to Microsoft Graph

```powershell
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Directory.Read.All"
```

> ⚠️ You may need admin consent on these scopes.

### Check current domain authentication settings

```powershell
# Authentication type (Managed | Federated)
Get-MgDomain -DomainId yourdomain.com | Select-Object Id, AuthenticationType

# Full federation configuration (only relevant if already Federated)
Get-MgDomainFederationConfiguration -DomainId yourdomain.com | Format-List
```

---

# Part 1 — Federated → Managed (decommissioning AD FS)

## When to use this

You have an AD FS farm fronting authentication for `yourdomain.com` and you want to switch the domain to **Managed** authentication (Password Hash Sync or Pass-through Authentication). Typically the final cut-over after a **Staged Rollout** campaign.

### Prerequisites specific to this direction

- User password hashes are **already synced to Entra ID** (Entra Connect / Cloud Sync, PHS enabled), **or** PTA agents are deployed and healthy.
- If you use **PTA**: at least **2 PTA agents on different servers** for high availability, and Microsoft recommends enabling **PHS as a fallback** so sign-ins keep working if all agents lose connectivity to a domain controller.
- You have validated cloud authentication on a representative subset of users via **Staged Rollout**.

## Pre-flight — Verify residual AD FS usage

Before flipping the domain to **Managed**, you want to know **who and what still authenticates through AD FS**. This is especially useful when you have been using **Staged Rollout** to progressively move users to cloud authentication: it lets you confirm that the remaining users / apps relying on AD FS is acceptably low (ideally zero) before the cut-over.

Four complementary angles. Use whichever matches your tooling.

### Option A — Entra admin center: AD FS application activity (no setup required)

**Entra admin center → Monitoring & health → Usage & insights → AD FS application activity**.

This built-in report lists every application that has emitted authentication requests against AD FS, with usage counts. It is the fastest way to get a complete picture, no KQL required, no Log Analytics workspace required.

Reference: [What are Microsoft Entra sign-in logs? – AD FS application activity](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#microsoft-entra-usage-and-insights).

### Option B — Entra admin center: Sign-in logs filter (no Log Analytics required)

If you do not have a Log Analytics workspace, you can do the same triage directly from the Sign-in logs UI:

**Entra admin center → Monitoring & health → Sign-in logs → Add filters → Incoming token type**, then tick **SAML 1.1** and **SAML 2.0**.

This surfaces the exact same events as the KQL queries below (same underlying field, `IncomingTokenType`), filtered through the portal. Switch between the **User sign-ins (interactive)** and **User sign-ins (non-interactive)** tabs to cover both flows. You can then **Download** the filtered view as CSV / JSON for further analysis.

### Option C — KQL on Log Analytics (if Sign-in logs are exported to a workspace)

The field that reliably identifies a **fresh authentication that transited through AD FS** in the Entra sign-in logs is **`IncomingTokenType`**: a value of `saml11` or `saml20` means the user presented a SAML assertion issued by your federated IdP (AD FS) to Entra.

> ⚠️ Pitfall to avoid: `TokenIssuerType` and `AuthenticationProtocol` look like the obvious fields to filter on (and the [Microsoft Graph signIn schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta) lists `ADFederationServices` and `wsFederation` as possible values) but in practice on standard ADFS deployments these fields are populated as `AzureAD` / `none` even for AD FS-issued sign-ins. The reliable signal is `IncomingTokenType`.

```kql
// Interactive sign-ins that came through AD FS
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName endswith "@yourdomain.com"
| where IncomingTokenType has_any ("saml11", "saml20")
| summarize Count = count(),
            LastSeen = max(TimeGenerated),
            Apps = make_set(AppDisplayName, 20)
            by UserPrincipalName, ClientAppUsed
| order by Count desc
```

```kql
// Non-interactive sign-ins that came through AD FS
// (this is where legacy clients hide: Exchange ActiveSync, EWS, ROPC, scripted service accounts)
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName endswith "@yourdomain.com"
| where IncomingTokenType has_any ("saml11", "saml20")
| summarize Count = count() by UserPrincipalName, AppDisplayName, ClientAppUsed
| order by Count desc
```

> Note: the non-interactive query above has the same column semantics as the interactive one (per the Microsoft Graph signIn schema) but has not been validated against real federated non-interactive traffic in the author's lab. Sanity-check the output against your environment.

```kql
// Top apps that still depend on AD FS, both flows combined
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName endswith "@yourdomain.com"
| where IncomingTokenType has_any ("saml11", "saml20")
| summarize FreshAuthsViaADFS = count(),
            UniqueUsers = dcount(UserPrincipalName)
            by AppDisplayName
| order by FreshAuthsViaADFS desc
```

### Option D — AD FS Security event log (server-side view)

If you want to know what AD FS itself **received** (regardless of what Entra logged), parse the **Security** event log of every AD FS server:

- **Event ID 1200** – "The Federation Service issued a valid token" (success)
- **Event ID 1202** – "The Federation Service failed to issue a valid token" (failure)

This requires AD FS auditing to be enabled:

```powershell
Set-AdfsProperties -AuditLevel Basic   # or Verbose for more detail
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
```

A ready-to-use script that aggregates these events (top users, top relying parties, protocol distribution, hourly distribution, success/failure ratios) is provided alongside this article:

→ [Analyze-ADFSAuthentication.ps1](Analyze-ADFSAuthentication.ps1)

It supports AD FS 2016 / 2019 / 2022, can target multiple servers via WinRM, and exports both the raw events and aggregated CSV reports.

## Backup federation configuration (before the switch)

When you flip the domain to **Managed**, the federation configuration object held by Entra ID is removed. Before doing this, export it to JSON so you can recreate it exactly if you need to roll back.

```powershell
$domain     = "yourdomain.com"
$backupPath = "C:\temp\fed-backup-$domain-$(Get-Date -Format yyyyMMdd-HHmm).json"

Get-MgDomainFederationConfiguration -DomainId $domain |
    Select-Object IssuerUri, PassiveSignInUri, ActiveSignInUri, MetadataExchangeUri,
                  SigningCertificate, NextSigningCertificate, SignOutUri,
                  FederatedIdpMfaBehavior, PreferredAuthenticationProtocol,
                  PromptLoginBehavior, IsSignedAuthenticationRequestRequired |
    ConvertTo-Json -Depth 10 |
    Out-File -FilePath $backupPath -Encoding utf8
```

The `SigningCertificate` property is already base64-encoded inside the object, no extra handling is needed.

> ⚠️ This backup only covers the **Entra-side** federation configuration. It does **not** back up the AD FS farm itself (config DB, claim rules, signing cert private keys…). If you also need a farm-side backup, use the [AD FS Rapid Restore Tool](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restoration-tool) from the [microsoft/adfsToolbox](https://github.com/Microsoft/adfsToolbox) repository.

## Convert domain to Managed

The flip command is the same whether the target sign-in method is **PHS** or **PTA** — only the prerequisites differ. With PTA, remember that cloud sign-ins will remain dependent on the on-prem AD and the PTA agents: if all agents lose connectivity to a DC, sign-ins fail. Microsoft recommends keeping PHS enabled as a fallback.

### ✅ Option 1: Microsoft Graph (preferred)

```powershell
Update-MgDomain -DomainId yourdomain.com -AuthenticationType Managed
```

![](../../assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-10-00-16.png)

### ❌ Option 2: MSOnline module (deprecated and no longer functional)

```powershell
Connect-MsolService
Set-MsolDomainAuthentication -DomainName yourdomain.com -Authentication Managed
```

> ⚠️ **Deprecated**: The MSOnline module has been officially deprecated by Microsoft and **no longer works** in most environments as of 2024.
> Attempts to use it will result in authentication or permission errors.
> Use the Microsoft Graph PowerShell SDK instead.

## Post-switch validation

```powershell
Get-MgDomain -DomainId yourdomain.com | Select-Object Id, AuthenticationType
# => AuthenticationType: Managed
```

Then test login at [https://myapps.microsoft.com](https://myapps.microsoft.com) with a user from the domain.

## Rollback (Managed → Federated) using the JSON backup

If you need to revert the change, re-federate the domain using the JSON file produced earlier.

```powershell
$backupPath = "C:\temp\fed-backup-yourdomain.com-YYYYMMDD-HHmm.json"
$fed        = Get-Content $backupPath | ConvertFrom-Json

# 1. Switch the domain back to Federated
Update-MgDomain -DomainId "yourdomain.com" -AuthenticationType Federated

# 2. Recreate the federation configuration from the backup
New-MgDomainFederationConfiguration `
    -DomainId "yourdomain.com" `
    -IssuerUri $fed.IssuerUri `
    -PassiveSignInUri $fed.PassiveSignInUri `
    -ActiveSignInUri $fed.ActiveSignInUri `
    -MetadataExchangeUri $fed.MetadataExchangeUri `
    -SigningCertificate $fed.SigningCertificate `
    -SignOutUri $fed.SignOutUri `
    -FederatedIdpMfaBehavior $fed.FederatedIdpMfaBehavior `
    -PreferredAuthenticationProtocol $fed.PreferredAuthenticationProtocol
```

Then validate as in the **Post-switch validation** section above (the `AuthenticationType` should report `Federated` again). See also [Part 2](#part-2--managed--federated-onboarding-ad-fs) for the full Managed → Federated procedure and field semantics.

> ⚠️ **Things to know before relying on this rollback:**
>
> - **AD FS must still be running and reachable.** The Entra-side rollback does nothing if the farm has been decommissioned in the meantime. Do not retire AD FS until you are confident the cut-over is final.
> - **Already-issued cloud tokens stay valid until they expire.** Users who got an Entra-issued token during the managed window will keep using it until refresh. Do not expect an instantaneous "everyone is back on AD FS" behaviour.
> - **MFA registrations performed during the managed window are kept.** Users do not lose anything they registered while on cloud auth.
> - If the farm itself was modified or broken between the switch and the rollback, restoring the Entra-side config is not enough — restore the farm too (see [AD FS Rapid Restore Tool](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restoration-tool)).

---

# Part 2 — Managed → Federated (onboarding AD FS)

## When to use this

You want a verified domain in Entra ID to delegate authentication to an existing **AD FS** farm (e.g. `adfs.contoso.com`). Typical scenarios: initial onboarding of an AD FS infrastructure, or re-enabling federation on a domain that was previously managed.

## Prerequisites specific to this direction

- A running **AD FS** service (e.g. `adfs.contoso.com`) reachable from the internet on the passive/active endpoints.
- The AD FS **token-signing certificate** exported in DER (`.cer`) format.
- The federation **endpoints URLs** known (Passive sign-in, Active sign-in, Metadata exchange, Sign-out).

## Enable federation for your domain

### 1. Prepare and encode the AD FS signing certificate

Export the current AD FS signing certificate:

![](../../assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-09-51-08.png)

Then base64-encode it:

```powershell
$certPath    = "C:\temp\adfs-signing.cer"
$certContent = [Convert]::ToBase64String(
                    (Get-Content -Path $certPath -Encoding Byte)
                )
```

### 2. Create the federation configuration

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

![](../../assets/Switch%20from%20Federated%20Authentication%20to%20Managed%20Authentication%20in%20Entra%20ID/2025-07-03-09-54-10.png)

> **Notes:**
> - `-MetadataExchangeUri` lets Entra ID import your AD FS metadata for certificate auto-rollover.
> - `-FederatedIdpMfaBehavior` set to `enforceMfaByFederatedIdp` forces MFA at AD FS and avoids duplicate prompts.
> - `-PreferredAuthenticationProtocol` must be **lowercase** `wsFed`, `saml`, or `unknownFutureValue`.

## Validate the federation configuration

```powershell
# Confirm the domain is now federated
Get-MgDomain -DomainId "yourdomain.com" | Select-Object Id, AuthenticationType
# => AuthenticationType: Federated

# View detailed federation settings
Get-MgDomainFederationConfiguration -DomainId "yourdomain.com" | Format-List
```

Then test login at [https://myapps.microsoft.com](https://myapps.microsoft.com) with a user from the domain — you should be redirected to your AD FS sign-in page.

## Update or rotate the federation settings

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

## AD FS-side configuration

To establish trust on the AD FS side, configure a **Relying Party Trust** for your Entra ID domain and define the necessary claim rules.

<< Coming soon >>

---

## 📚 References

- [Microsoft Docs – Convert Domain to Managed](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-to-managed)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Microsoft Graph signIn schema (beta) – `incomingTokenType`, `tokenIssuerType`, `authenticationProtocol`](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta)
- [What are Microsoft Entra sign-in logs? – AD FS application activity](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#microsoft-entra-usage-and-insights)
- [microsoft/adfsToolbox (ADFSDiagnosticsModule, AD FS Rapid Restore Tool)](https://github.com/Microsoft/adfsToolbox)
- [AD FS Rapid Restoration Tool](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restoration-tool)
- [Staged Rollout for migrating from AD FS to PHS](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-staged-rollout)
