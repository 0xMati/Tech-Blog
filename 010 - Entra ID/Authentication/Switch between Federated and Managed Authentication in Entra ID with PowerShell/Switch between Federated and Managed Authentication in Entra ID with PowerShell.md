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

### Option A — Entra admin center: AD FS application migration (no setup required)

**Entra admin center → Monitoring & health → Usage & insights → AD FS application migration**.

This built-in report lists every application that has emitted authentication requests against AD FS, with usage counts. It is the fastest way to get a complete picture, no KQL required, no Log Analytics workspace required.

Reference: [What are Microsoft Entra sign-in logs? – AD FS application migration](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#microsoft-entra-usage-and-insights).

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

This requires AD FS security auditing to be enabled, which is **three distinct steps** (enabling only the audit level is not enough — events will not be written until all three are in place):

**1. Authorize the AD FS service account to write to the Security log.** Add `NT SERVICE\adfssrv` (the AD FS service account) to the **Generate security audits** user right (`Local Security Policy → Security Settings → Local Policies → User Rights Assignment`). This lets the service write entries to the Security event channel.

**2. Enable the "Application Generated" audit subcategory.** AD FS writes through the Windows Auditing API, which is gated by this subcategory:

```powershell
auditpol.exe /set /subcategory:"Application Generated" /success:enable /failure:enable
```

**3. Set the AD FS audit level and log types.** The audit level controls *how many* events are produced; the log types control *which* event types AD FS actually records:

```powershell
Set-AdfsProperties -AuditLevel Basic   # or Verbose for more detail
Set-AdfsProperties -LogLevel Errors,FailureAudits,Information,SuccessAudits,Warnings
```

> On Windows Server 2016+, `AuditLevel` is already `Basic` by default — but steps 1 and 2 are still required for events to reach the Security log.

Reference: [Enabling AD FS Security Auditing and shipping event logs to Microsoft Sentinel](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/enabling-ad-fs-security-auditing-%F0%9F%93%A1-and-shipping-event-logs-to-microsoft-sentine/3610464).

> ⚠️ **Size the Security log before you rely on it.** Once auditing is on, AD FS writes several events per authentication, so the **Security** log fills up fast. With the default size (often **128 MB**, sometimes as low as 20 MB) a busy farm can wrap in **hours**, silently overwriting the oldest events — and your lookback window quietly shrinks to almost nothing. Raise the maximum size to at least **1 GB**, and **4 GB or more** on high-volume farms or when you want a multi-week window. Do this on **every** AD FS server:
>
> ```powershell
> # 1 GB (value is in bytes); bump to 4294967296 for 4 GB
> wevtutil set-log Security /maxsize:1073741824
> # Check current setting
> wevtutil get-log Security
> ```
>
> Sizing the log only buys you a longer local retention window. For real long-term retention, ship the events to a SIEM (Sentinel, etc.) as described in the reference above.

A ready-to-use script that aggregates these events (top users, top relying parties, protocol distribution, hourly distribution, success/failure ratios) is provided alongside this article:

→ [Analyze-ADFSAuthentication.ps1](Analyze-ADFSAuthentication.ps1)

It supports AD FS 2016 / 2019 / 2022, can target multiple servers via WinRM, and exports both the raw events and aggregated CSV reports.

> ⚠️ **Query every node of the farm.** A token event (1200/1202) is only written on the AD FS node that actually processed the request. In a multi-node farm behind a load balancer, pointing the script at a single node gives only a **partial** view. List all nodes explicitly to get complete coverage:
>
> ```powershell
> .\Analyze-ADFSAuthentication.ps1 -ComputerName adfs01,adfs02,adfs03 -Days 30 -IncludeFailures -OpenReport
> ```
>
> Run from a host that can reach each node over WinRM, with rights to read their Security log. By default (no `-ComputerName`) the script only reads the **local** machine.

## Backup federation configuration (before the switch)

When you flip the domain to **Managed**, the federation configuration object held by Entra ID is removed. Before doing this, export it to JSON so you can recreate it exactly if you need to roll back.

```powershell
# Connect first (skip if you already ran the connection from Common prerequisites).
# Reading the config only needs a read scope:
Connect-MgGraph -Scopes "Domain.Read.All", "Directory.Read.All"

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

> The `Authentication needed. Please call Connect-MgGraph` error simply means there is no active Graph session — run the `Connect-MgGraph` line above first. If you already connected in [Common prerequisites](#common-prerequisites) with `Domain.ReadWrite.All`, that session also works here (a write scope is a superset of the read scope) and you can skip the extra `Connect-MgGraph`.

> ⚠️ This backup only covers the **Entra-side** federation configuration. It does **not** back up the AD FS farm itself (config DB, claim rules, signing cert private keys…). If you also need a farm-side backup, use the [AD FS Rapid Restore Tool](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restoration-tool) from the [microsoft/adfsToolbox](https://github.com/Microsoft/adfsToolbox) repository.

## Convert domain to Managed

The flip command is the same whether the target sign-in method is **PHS** or **PTA** — only the prerequisites differ. With PTA, remember that cloud sign-ins will remain dependent on the on-prem AD and the PTA agents: if all agents lose connectivity to a DC, sign-ins fail. Microsoft recommends keeping PHS enabled as a fallback.

### ✅ Option 1: Microsoft Graph (preferred)

```powershell
# Connect first (skip if you already ran the connection from Common prerequisites).
# Flipping the domain writes to it, so a write scope is required:
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Directory.Read.All"

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
# Connect first (skip if you already ran the connection from Common prerequisites).
# Re-federating writes to the domain, so a write scope is required:
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Directory.Read.All"

# Set your domain once; it is reused everywhere below.
$domain     = "yourdomain.com"
$backupPath = "C:\temp\fed-backup-$domain-YYYYMMDD-HHmm.json"
$fed        = Get-Content $backupPath | ConvertFrom-Json

# Rebuild the federation parameters from the backup.
#    Creating the federation configuration is what re-federates the domain, so there
#    is NO separate "switch back to Federated" step. Do not call
#    'Update-MgDomain -AuthenticationType Federated' for this: it is not supported and
#    returns 400 BadRequest - "Changing authenticationType from Managed to Federated
#    is currently not supported."
$params = @{
    IssuerUri           = $fed.IssuerUri
    PassiveSignInUri    = $fed.PassiveSignInUri
    ActiveSignInUri     = $fed.ActiveSignInUri
    MetadataExchangeUri = $fed.MetadataExchangeUri
    SigningCertificate  = $fed.SigningCertificate
    SignOutUri          = $fed.SignOutUri
}

# FederatedIdpMfaBehavior is MANDATORY on create - an empty value fails with
# "FederatedIdpMfaBehavior cannot be empty". If the domain never had it set, fall
# back to the documented default behavior (acceptIfMfaDoneByFederatedIdp).
if (-not [string]::IsNullOrWhiteSpace($fed.FederatedIdpMfaBehavior)) {
    $params.FederatedIdpMfaBehavior = $fed.FederatedIdpMfaBehavior
} else {
    $params.FederatedIdpMfaBehavior = "acceptIfMfaDoneByFederatedIdp"
}

# Other optional properties: include them only when the backup has a real value,
# so an empty enum (e.g. PromptLoginBehavior) is not sent.
if (-not [string]::IsNullOrWhiteSpace($fed.PreferredAuthenticationProtocol)) {
    $params.PreferredAuthenticationProtocol = $fed.PreferredAuthenticationProtocol
}
if (-not [string]::IsNullOrWhiteSpace($fed.PromptLoginBehavior)) {
    $params.PromptLoginBehavior = $fed.PromptLoginBehavior
}
if ($null -ne $fed.IsSignedAuthenticationRequestRequired) {
    $params.IsSignedAuthenticationRequestRequired = [bool]$fed.IsSignedAuthenticationRequestRequired
}
if (-not [string]::IsNullOrWhiteSpace($fed.NextSigningCertificate)) {
    $params.NextSigningCertificate = $fed.NextSigningCertificate
}

# Apply the configuration. A domain can hold only ONE federation configuration, so
# create it if none exists, otherwise update the existing one. Creating it is what
# re-federates the domain.
$existing = Get-MgDomainFederationConfiguration -DomainId $domain -ErrorAction SilentlyContinue
if ($existing) {
    Update-MgDomainFederationConfiguration -DomainId $domain `
        -InternalDomainFederationId $existing.Id @params
} else {
    New-MgDomainFederationConfiguration -DomainId $domain @params
}
```

> 💡 **Why the splatting + default approach?**
> - **No `Update-MgDomain -AuthenticationType Federated` step.** Microsoft Entra ID does not support flipping `authenticationType` from Managed back to Federated directly (it returns `400 BadRequest – Changing authenticationType from Managed to Federated is currently not supported`). Creating the federation configuration is what re-federates the domain.
> - **`FederatedIdpMfaBehavior` is mandatory on create.** If the domain never had it set, the backup holds an empty string and the call fails with `FederatedIdpMfaBehavior cannot be empty`. Per the [Microsoft Graph reference](https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation?view=graph-rest-1.0), the value must be one of `acceptIfMfaDoneByFederatedIdp`, `enforceMfaByFederatedIdp` or `rejectMfaByFederatedIdp`; when it was never set Entra ID behaves as `acceptIfMfaDoneByFederatedIdp`, so the snippet supplies that default explicitly.
> - **Other optional enums** (e.g. `PromptLoginBehavior`) are only sent when the backup has a real value, to avoid the same empty-enum rejection.

> ⚠️ **`Domain already has Federation Configuration set` (400)?** A domain can hold only one federation configuration. If the domain is already `Federated` (or a config lingered from a previous attempt), `New-MgDomainFederationConfiguration` fails with this error. The create-or-update logic above handles both cases; if you run the commands manually, use `Update-MgDomainFederationConfiguration` when a config already exists.

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
# Connect first (skip if you already ran the connection from Common prerequisites).
# Creating the federation configuration writes to the domain, so a write scope is required:
Connect-MgGraph -Scopes "Domain.ReadWrite.All", "Directory.Read.All"

New-MgDomainFederationConfiguration `
    -DomainId "yourdomain.com" `
    -IssuerUri "http://yourdomain.com/adfs/services/trust/" `
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

### Parameter reference

| Parameter | Purpose |
|---|---|
| `IssuerUri` | Unique identifier of the AD FS token issuer (e.g. `http://yourdomain.com/adfs/services/trust/`). Entra ID uses it to recognize tokens coming from your IdP. |
| `PassiveSignInUri` | URL that **web** (browser) clients are redirected to for sign-in — the AD FS sign-in page (`/adfs/ls/`). |
| `ActiveSignInUri` | URL used by **rich / legacy** clients (non-browser, WS-Trust, e.g. older Outlook) → `.../trust/2005/usernamemixed`. |
| `MetadataExchangeUri` | Metadata endpoint (`/mex`). Used by Entra ID for **certificate auto-rollover**: 30 days before expiry it fetches the new signing certificate from here. |
| `SigningCertificate` | The AD FS **token-signing certificate** (public key, base64). Lets Entra ID verify the signature of tokens issued by AD FS. |
| `SignOutUri` | **Sign-out** URL: where the client is redirected when signing out of Entra services. |
| `NextSigningCertificate` | **Fallback** signing certificate (the next one), used automatically when the primary expires — avoids an outage during rollover. |
| `PreferredAuthenticationProtocol` | Preferred protocol: `wsFed` or `saml`. **Must be set explicitly** for the passive sign-in flow to work. |
| `FederatedIdpMfaBehavior` | Controls how Entra ID treats MFA performed by AD FS (see table below). |
| `PromptLoginBehavior` | Sign-in prompt behavior: `translateToFreshPasswordAuthentication`, `nativeSupport`, or `disabled`. Governs how `prompt=login` is passed to AD FS. |
| `IsSignedAuthenticationRequestRequired` | If `true`, Entra ID **signs** the SAML authentication requests sent to the IdP (with the OrgID signing key). Default `false`. |

**`FederatedIdpMfaBehavior` values** (the key security setting):

| Value | Behavior |
|---|---|
| `acceptIfMfaDoneByFederatedIdp` | Entra ID **accepts** the MFA performed by AD FS. If AD FS didn't perform MFA, Entra ID performs it. *(default)* |
| `enforceMfaByFederatedIdp` | Entra ID accepts MFA done by AD FS; otherwise it **redirects** the request back to AD FS to perform MFA. |
| `rejectMfaByFederatedIdp` | Entra ID **always performs** its own MFA and **rejects** MFA claimed by AD FS. Most secure (prevents a compromised IdP from asserting MFA was done). |

Reference: [internalDomainFederation resource type (Microsoft Graph)](https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation?view=graph-rest-1.0).

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

The Graph commands above configure the **Entra-side** of the trust. For the federation to actually work, AD FS must also trust Entra ID as a **relying party** and emit the claims Entra expects. When AD FS is set up with Microsoft Entra Connect, this relying party trust and its claim rules are created automatically. Since we are **not** using Entra Connect here, you configure it manually.

> ℹ️ This section covers the **WS-Federation** scenario — the same one used throughout this article (`PreferredAuthenticationProtocol = wsFed`, AD FS issuing SAML 1.1 tokens over WS-Fed/WS-Trust). A third-party **SAML 2.0 SP-Lite** IdP is a *different* scenario (protocol `saml`, with `IDPEmail` + a persistent `NameID`); see [Use a SAML 2.0 IdP for SSO](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp) if that is your case.

> Entra ID acts as the **relying party**; your AD FS farm is the **identity provider**. Entra ID does **not** read metadata from your IdP — AD FS must publish the correct claims.

### 1. Add the relying party trust (import Entra metadata)

In **AD FS Management → Relying Party Trusts → Add Relying Party Trust**, import the data from the Microsoft 365 / Entra ID published federation metadata:

```
https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml
```

(For the China-specific Microsoft 365 instance, use `https://nexus.partner.microsoftonline-p.cn/federationmetadata/saml20/federationmetadata.xml`.)

The relying party identifier (realm) for the Microsoft cloud is `urn:federation:MicrosoftOnline`.

### 2. Required issuance claims (WS-Fed)

AD FS must issue, in the token sent to Entra ID:

| Claim | Meaning |
|---|---|
| **UPN** | The user's **UserPrincipalName**, which must match the `UserPrincipalName` of the synced user in Entra ID. Standard claim type: `http://schemas.xmlsoap.org/claims/UPN`. |
| **ImmutableID** | The source anchor, which must match the user's `OnPremisesImmutableId` in Entra ID. AD FS claim type: `http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID` (typically sourced from `objectGUID` or `ms-DS-ConsistencyGuid`). |
| **issuerID** *(multi-domain only)* | When several top-level domains are federated, AD FS must emit an `issuerID` that matches the per-domain `IssuerUri` so Entra can map the token to the right domain. Claim type: `http://schemas.microsoft.com/ws/2008/06/identity/claims/issuerid`. |

> ⚠️ The **UPN** and **ImmutableID** values issued by AD FS must exactly match the `UserPrincipalName` and `OnPremisesImmutableId` of the synced user in Entra ID, otherwise federated sign-in fails. Users must be provisioned/synced in Entra ID **before** they can sign in.

#### Inspect or export the existing claim rules

If you already have a working relying party trust (for example, one previously created by Entra Connect), you can read its issuance transform rules directly on the AD FS server:

```powershell
# Locate the Microsoft 365 / Entra relying party trust
Get-AdfsRelyingPartyTrust | Where-Object { $_.Identifier -contains "urn:federation:MicrosoftOnline" } |
    Select-Object Name, Identifier

# Dump the issuance transform rules (claim rule language)
$rp = Get-AdfsRelyingPartyTrust | Where-Object { $_.Identifier -contains "urn:federation:MicrosoftOnline" }
$rp.IssuanceTransformRules
```

#### Reference claim rules

The following issuance transform rules are the ones generated for a standard AD FS ↔ Microsoft 365 relying party trust. The three rules below are the essential ones for federated sign-in (UPN, ImmutableID, and — for multiple federated domains — issuerID):

```text
@RuleName = "Issue UPN"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/claims/UPN"),
    query = "samAccountName={0};userPrincipalName;{1}",
    param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);

@RuleName = "Issue Immutable ID"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => issue(store = "Active Directory", types = ("http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"),
    query = "samAccountName={0};objectGUID;{1}",
    param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);

@RuleName = "Issue nameidentifier"
c:[Type == "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"]
 => issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", Value = c.Value,
    Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
```

For a **multi-domain** federation, AD FS also emits an `issuerID` whose value is rewritten per UPN suffix so it matches the per-domain `IssuerUri` (`http://<domain>/adfs/services/trust/`). Replace the domain list in the regex with your own federated top-level domains:

```text
@RuleName = "Issue issuerid when it is not a computer account"
c1:[Type == "http://schemas.xmlsoap.org/claims/UPN"]
 && c2:[Type == "http://schemas.microsoft.com/ws/2012/01/accounttype", Value == "User"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/issuerid",
    Value = regexreplace(c1.Value,
    "(?i)(^([^@]+)@)(?<domain>(contoso\.com|fabrikam\.com))$",
    "http://${domain}/adfs/services/trust/"));
```

> 💡 The `objectGUID` source above is the default. If your Entra ID source anchor is `ms-DS-ConsistencyGuid`, point the **Issue Immutable ID** rule at `ms-DS-ConsistencyGuid` instead and keep it consistent with what your directory synchronization writes to `OnPremisesImmutableId`.

> ℹ️ A real trust contains additional pass-through rules (primary SID, MFA instant, password expiry, `insideCorporateNetwork`, certificate context, etc.). Those support extra scenarios (device registration, password expiry notifications, conditional access) and are not strictly required for basic federated authentication.

### References for this section

- [Manage and customize AD FS — Modify AD FS claim rules](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-management#modify-ad-fs-claim-rules)
- [The Role of the Claim Rule Language](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dd807118(v=ws.11))
- [Use a SAML 2.0 IdP for SSO](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-saml-idp) *(the alternative, SAML 2.0 scenario)*

---

## 📚 References

- [Microsoft Docs – Convert Domain to Managed](https://learn.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-fed-to-managed)
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Microsoft Graph signIn schema (beta) – `incomingTokenType`, `tokenIssuerType`, `authenticationProtocol`](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta)
- [What are Microsoft Entra sign-in logs? – AD FS application migration](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins#microsoft-entra-usage-and-insights)
- [microsoft/adfsToolbox (ADFSDiagnosticsModule, AD FS Rapid Restore Tool)](https://github.com/Microsoft/adfsToolbox)
- [AD FS Rapid Restoration Tool](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restoration-tool)
- [Staged Rollout for migrating from AD FS to PHS](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-staged-rollout)
