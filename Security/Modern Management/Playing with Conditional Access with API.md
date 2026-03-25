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
