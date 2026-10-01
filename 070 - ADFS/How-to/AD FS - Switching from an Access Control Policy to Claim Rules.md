---
title: "AD FS: Switching from an Access Control Policy to Claim Rules"
date: 2026-09-29
---

# AD FS: Switching from an Access Control Policy to Claim Rules

**Unassigning a policy template is not an undo button for yesterday's authorization rules.**

AD FS 2016 introduced Access Control Policies (ACPs) as a template-based way to express access conditions, including MFA. That policy model and direct configuration of issuance authorization rules are mutually exclusive for the relevant RP configuration. Custom issuance-transform rules, which choose the claims sent to the application, are a different surface.

This note covers one existing relying party trust. It does not convert every RP in a farm or author a new set of custom rules.

## The command and its scope

Microsoft documents `Set-AdfsRelyingPartyTrust -AccessControlPolicyName $null` as **unassigning the policy template**. It does not delete the shared template or recover a historical ruleset. Inspect the resulting authorization and additional-authentication rules instead of assuming what the effective policy became.

| Setting | Question it answers |
|---|---|
| `AccessControlPolicyName` and its parameters | Which template is assigned to this RP? |
| `IssuanceAuthorizationRules` | Who may receive a token under the direct-rules model? |
| `AdditionalAuthenticationRules` | Which additional-authentication conditions are configured here? |
| `IssuanceTransformRules` | Which claims are emitted to the application? |

## Record the before-state

On an AD FS administration host with the ADFS module and configuration-change rights, use Windows PowerShell 5.1. In a WID farm, perform configuration writes on the primary.

```powershell
Import-Module ADFS -ErrorAction Stop
$rpIdentifier = 'urn:corp:claimsportal'
$matchesBefore = @(Get-AdfsRelyingPartyTrust -Identifier $rpIdentifier -ErrorAction Stop)
if ($matchesBefore.Count -ne 1) {
    throw 'Expected exactly one relying party.'
}
$before = $matchesBefore[0]
$before | Select-Object Name, Identifier, AccessControlPolicyName,
    AccessControlPolicyParameters, IssuanceAuthorizationRules,
    AdditionalAuthenticationRules, IssuanceTransformRules
```

Retain this state, the assigned policy's definition and parameter values in the change record. A formatted console view is not a full backup. If the intended rollback depends on a shared custom template, preserve that definition too: its current contents may change independently of this RP.

Before unassigning, establish the intended access/MFA behavior and a tested recovery path. Do not remove the template simply to expose another UI tab on a live application.

## Preview, apply deliberately, then read back

```powershell
Set-AdfsRelyingPartyTrust -TargetIdentifier $rpIdentifier `
    -AccessControlPolicyName $null -WhatIf -ErrorAction Stop
```

`-WhatIf` previews the configuration operation, not its effect on real authentication. When the before-state and replacement behavior have been reviewed, run the same command with `-Confirm` instead of `-WhatIf`. This is a real change to the selected RP; keep it within the planned change window.

```powershell
$matchesAfter = @(Get-AdfsRelyingPartyTrust -Identifier $rpIdentifier -ErrorAction Stop)
if ($matchesAfter.Count -ne 1) {
    throw 'Unable to identify the RP after the operation.'
}
$after = $matchesAfter[0]
if (-not [string]::IsNullOrEmpty($after.AccessControlPolicyName)) {
    throw 'An access control policy is still assigned.'
}
$after | Select-Object IssuanceAuthorizationRules,
    AdditionalAuthenticationRules, IssuanceTransformRules
```

Run the readback **after the real operation**; after a preview alone, the original assignment should still exist. Do not overwrite the returned rules with an empty string or a blanket permit merely to make the application work. Compare their actual behavior with the intended access and MFA conditions before any additional edit.

**Verify:** test an allowed user, an expected denial and the applicable MFA/intranet/extranet cases using fresh authentication. A missing ACP name is evidence of unassignment, not evidence that authorization is correct. Global authentication policy and the application can impose additional requirements.

## Returning to the policy model

Restore the recorded template assignment and its reviewed parameter values through the supported RP configuration surface, then repeat the same tests. An ACP name alone is insufficient for a parameterized policy. If direct rules were edited in the meantime, retain them and plan the transition between the mutually exclusive models; do not claim that assigning a policy preserves an independently active custom authorization layer.

For rule composition, use the [existing MFA-rule article](ADFS%20and%20MFA%20-%20Configuring%20multiple%20additional%20authentication%20rules.md). For the different processing stages, see [AD FS claims explained](../Concepts/AD%20FS%20Claims%20Explained%20-%20Attribute%20Stores,%20Claim%20Descriptions%20and%20Token%20Issuance.md).

## References

- [Microsoft Learn: Access Control Policies in AD FS](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/access-control-policies-in-ad-fs)
- [Microsoft Learn: Set-AdfsRelyingPartyTrust, including unassigning a policy template](https://learn.microsoft.com/en-us/powershell/module/adfs/set-adfsrelyingpartytrust?view=windowsserver2025-ps)