# Playing with Conditional Access with API
*Managing Entra ID Conditional Access like code using Microsoft Graph*
🗓️ Published: 2025-12-13

---

## Why this matters

Conditional Access is often configured manually in the Entra portal.
However, Microsoft Graph allows you to **manage Conditional Access policies like any other piece of code**:

- Automated
- Versioned
- Backed up
- Restored
- Audited
- Monitored

This document provides **practical API demos** to illustrate how Conditional Access can be handled **as code**.

---

## Prerequisites

- Entra ID role: **Conditional Access Administrator** (or Global Administrator)
- Microsoft Graph delegated permissions:
  - `Policy.Read.All`
  - `Policy.ReadWrite.ConditionalAccess`
  - `AuditLog.Read.All`
- PowerShell **5.1 compatible**
- Microsoft Graph PowerShell SDK

### Install Microsoft Graph module

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

### Authenticate to Microsoft Graph

```powershell
Connect-MgGraph -Scopes `
  "Policy.Read.All",
  "Policy.ReadWrite.ConditionalAccess",
  "AuditLog.Read.All"
```

---

## 1. List Conditional Access policies
*Discover which policies are enforced in the tenant*

**Graph endpoint:**  
`GET /identity/conditionalAccess/policies`

```powershell
Get-MgIdentityConditionalAccessPolicy |
  Select-Object Id, DisplayName, State, CreatedDateTime |
  Format-Table -AutoSize
```

---

## 2. Create a Conditional Access policy
*Deploy a policy using code, disabled by default for safety*

**Graph endpoint:**  
`POST /identity/conditionalAccess/policies`

Example: Require MFA for Azure Management.

```powershell
$policy = @{
  DisplayName = "DEMO - Require MFA for Azure Management"
  State       = "disabled"
  Conditions  = @{
    Users = @{
      IncludeUsers = @("All")
    }
    Applications = @{
      IncludeApplications = @(
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" # Azure Management
      )
    }
  }
  GrantControls = @{
    Operator = "OR"
    BuiltInControls = @("mfa")
  }
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

---

## 3. Update an existing policy
*Modify policy state or scope programmatically*

**Graph endpoint:**  
`PATCH /identity/conditionalAccess/policies/{id}`

```powershell
$policyId = "<POLICY-ID>"

Update-MgIdentityConditionalAccessPolicy `
  -ConditionalAccessPolicyId $policyId `
  -State "enabled"
```

---

## 4. Backup Conditional Access policies
*Export all policies to JSON for versioning or rollback*

```powershell
$backupPath = ".\CA-Backup"
New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

$policies = Get-MgIdentityConditionalAccessPolicy -All
Write-Host "Found $($policies.Count) policies to backup" -ForegroundColor Cyan

foreach ($policy in $policies) {

    # Sanitize filename (Windows-safe)
    $safeName = ($policy.DisplayName -replace '[\\/:*?"<>|]', '_') + "_$($policy.Id)"
    $filePath = Join-Path $backupPath "$safeName.json"

    # Convert to hashtable first for clean JSON serialization
    $policy | ConvertTo-Json -Depth 20 |
        Out-File $filePath -Encoding UTF8

    Write-Host "  Saved: $($policy.DisplayName)" -ForegroundColor Green
}

Write-Host "Backup complete -> $((Resolve-Path $backupPath).Path)" -ForegroundColor Cyan
```

---

## 5. Restore a Conditional Access policy
*Recreate a policy from a JSON backup*

```powershell
$policyJson = Get-Content ".\CA-Backup\policy.json" -Raw |
  ConvertFrom-Json

New-MgIdentityConditionalAccessPolicy -BodyParameter $policyJson
```

---

## 6. Delete a Conditional Access policy
*Remove obsolete or deprecated policies*

```powershell
$policyId = "<POLICY-ID>"

Remove-MgIdentityConditionalAccessPolicy `
  -ConditionalAccessPolicyId $policyId
```

---

## 7. Monitor Conditional Access changes
*Track who changed what and when*

```powershell
Get-MgAuditLogDirectoryAudit -Filter "category eq 'Policy'" |
Where-Object {
    $_.ActivityDisplayName -match "conditional access"
} |
ForEach-Object {

    $tr = $_.TargetResources |
          Where-Object { $_.DisplayName } |
          Select-Object -First 1

    [PSCustomObject]@{
        TimeGenerated = $_.ActivityDateTime
        Action        = $_.ActivityDisplayName
        PolicyName    = $tr.DisplayName
        PolicyId      = $tr.Id
        InitiatedBy   = if ($_.InitiatedBy.User) {
                          $_.InitiatedBy.User.DisplayName
                        } elseif ($_.InitiatedBy.App) {
                          $_.InitiatedBy.App.DisplayName
                        } else {
                          "Unknown"
                        }
    }
} |
Sort-Object TimeGenerated -Descending |
Format-Table -AutoSize
```

---

## 8. Test safely with Report-only mode
*Validate policy impact before enforcing*

```powershell
Update-MgIdentityConditionalAccessPolicy `
  -ConditionalAccessPolicyId $policyId `
  -State "reportOnly"
```

---

## 9. Recommended Conditional Access policies
*A baseline matrix to build your policy set — adapt to your environment*

> 💡 **Before you start:**
> - Always create a **break-glass account** excluded from ALL policies
> - Deploy new policies in **Report-only** mode first
> - Define **Named Locations** (trusted IPs, countries) before referencing them

### Tier 0 — Identity Foundation (deploy first)

| # | Policy name | Scope | Grant / Session | Priority |
|---|-------------|-------|-----------------|----------|
| 1 | ✅ Require MFA for all users | All users | MFA | 🔴 Critical |
| 2 | ✅ Block legacy authentication | All users | Block | 🔴 Critical |
| 3 | ✅ Require MFA for admins (all admin roles) | Directory roles | MFA + Compliant device | 🔴 Critical |
| 4 | ✅ Protect break-glass account (allow only from trusted location) | Break-glass account | MFA | 🔴 Critical |

### Tier 1 — Device Trust & Compliance

| # | Policy name | Scope | Grant / Session | Priority |
|---|-------------|-------|-----------------|----------|
| 5 | ✅ Require compliant device for Office 365 | All users → Office 365 | Compliant device | 🟠 High |
| 6 | ✅ Require approved client app (mobile) | All users → Office 365 (iOS, Android) | Approved client app OR App protection policy | 🟠 High |
| 7 | ✅ Block unmanaged devices (or limit to browser-only) | All users → Office 365 | Session: no persistent browser + limited web | 🟠 High |
| 8 | ✅ Require compliant device for Azure Management | All users → Azure Management | Compliant device + MFA | 🟠 High |

### Tier 2 — Risk-Based & Location

| # | Policy name | Scope | Grant / Session | Priority |
|---|-------------|-------|-----------------|----------|
| 9 | ✅ Block high-risk sign-ins (Entra ID Protection) | All users | Block | 🟡 Medium |
| 10 | ✅ Require password change on high-risk users | All users | MFA + Password change | 🟡 Medium |
| 11 | ✅ Block sign-ins from disallowed countries | All users | Block | 🟡 Medium |
| 12 | ✅ Require MFA for risky sign-ins (medium+) | All users | MFA | 🟡 Medium |
| 13 | ⚠️ Restrict token lifetime (Sign-in frequency) | All users → Office 365 | Session: sign-in frequency 12h | 🟡 Medium |

### Tier 3 — Advanced / Hardening

| # | Policy name | Scope | Grant / Session | Priority |
|---|-------------|-------|-----------------|----------|
| 14 | ✅ Require phishing-resistant MFA for admins | Directory roles | Authentication strength: Phishing-resistant | 🟢 Recommended |
| 15 | ✅ Block admin access outside trusted network | Directory roles (excl. break-glass) | Block if not Named Location | 🟢 Recommended |
| 16 | ✅ Require Terms of Use for guests | Guest users | ToU + MFA | 🟢 Recommended |
| 17 | ✅ Block device code flow & authentication transfer | All users | Block (Device code flow, Authentication transfer) | 🟢 Recommended |
| 18 | ⚠️ Token Protection (Preview) | All users → Exchange, SharePoint | Session: Token protection | 🟢 Recommended |

> 🔑 **Key reminders:**
> - Policies **1–4** are non-negotiable — deploy them day one
> - **Authentication Strength** (policy 14) replaces the old "Require MFA" grant when you need phishing-resistant methods specifically (FIDO2, Passkey, WHfB, CBA)
> - Policy **17** blocks device code flow attacks (Storm-1811 / Teams vishing) — heavily recommended
> - **Report-only** mode is your best friend — use section 8 above to toggle safely

---

## Key takeaways

- Conditional Access can be **fully automated**
- Policies can be **treated as code**
- Backup and restore become trivial
- Changes are **auditable**
- Large environments become **manageable at scale**

---

## Final message

> If Conditional Access is critical to your security posture,
> **it deserves the same engineering discipline as code.**
