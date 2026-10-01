---
title: "MFA Registration Report with Microsoft Graph: Registration Is Not Usage"
date: 2026-10-01
---

# MFA Registration Report with Microsoft Graph: Registration Is Not Usage

**A registered method is not evidence that MFA was required or performed.**

Old reports based on `Get-MsolUser` and `StrongAuthenticationMethods` answered an enrollment question, despite often being called "MFA usage reports." Use Microsoft Graph's registration report for that inventory. Use sign-in evidence for actual authentication activity.

## Read the right fields

| Field | Meaning | Does not prove |
|---|---|---|
| `IsMfaRegistered` | A strong method has been registered for MFA | That policy currently allows the method |
| `IsMfaCapable` | A strong method is registered and allowed by the authentication methods policy | That Conditional Access requires MFA for every application |
| `MethodsRegistered` | Registered method types | That every listed method counts as an MFA factor or is supported by an AD FS adapter |
| `LastUpdatedDateTime` | When the report was updated | The last registration, MFA prompt or successful sign-in |

This is a Microsoft Entra registration inventory, not a directory of methods registered in third-party MFA systems. Being capable in Entra ID also does not establish that a particular method works through the AD FS Entra MFA adapter.

## Query with Graph PowerShell

Use a management host with `Microsoft.Graph.Authentication` and `Microsoft.Graph.Reports` installed. Windows PowerShell 5.1 requires the Graph SDK's supported .NET prerequisites; an AD FS role and local elevation are not required for this cloud report.

The report requires Microsoft Entra ID P1 or P2. For this delegated example, use consented `AuditLog.Read.All` and a supported directory role such as **Reports Reader**. A Graph scope and a directory role are separate requirements. Replace the sample tenant ID:

```powershell
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Reports -ErrorAction Stop
$tenantId = '11111111-2222-3333-4444-555555555555'
Connect-MgGraph -TenantId $tenantId -Scopes 'AuditLog.Read.All' `
    -ContextScope Process -NoWelcome -ErrorAction Stop
```

Retrieve all pages before deriving counts or exporting. Keep Boolean values as Booleans; a missing value must not silently become "not registered":

```powershell
$registration = @(Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop)
if ($registration.Count -eq 0) {
    throw 'No registration rows returned. Check tenant, access and report coverage before exporting.'
}

$report = @(foreach ($entry in $registration) {
    if ($entry.IsMfaRegistered -isnot [bool] -or $entry.IsMfaCapable -isnot [bool]) {
        throw 'A registration row has missing or invalid MFA flags; do not publish partial counts.'
    }
    [pscustomobject]@{
        UserId = $entry.Id
        UserPrincipalName = $entry.UserPrincipalName
        IsMfaRegistered = $entry.IsMfaRegistered
        IsMfaCapable = $entry.IsMfaCapable
        MethodsRegistered = @($entry.MethodsRegistered) -join ';'
        ReportUpdatedAt = $entry.LastUpdatedDateTime
    }
})

[pscustomobject]@{
    ReportedUsers = $report.Count
    Registered = @($report | Where-Object { $_.IsMfaRegistered -eq $true }).Count
    NotRegistered = @($report | Where-Object { $_.IsMfaRegistered -eq $false }).Count
    Capable = @($report | Where-Object { $_.IsMfaCapable -eq $true }).Count
    RegisteredButNotCapable = @($report | Where-Object {
        $_.IsMfaRegistered -eq $true -and $_.IsMfaCapable -eq $false
    }).Count
}
```

After a successful query, export the retained rows to a new local file:

```powershell
$exportPath = Join-Path $PWD ('MfaRegistration-{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$report | Export-Csv -LiteralPath $exportPath -NoTypeInformation `
    -Encoding UTF8 -NoClobber -ErrorAction Stop
```

The CSV contains identity data. Store it accordingly and import identity strings as text when using spreadsheet tools. This example reads registration state; it neither resets methods nor changes MFA policy.

## Interpret omissions and latency

- **Not real time:** Microsoft documents a reporting delay of up to 36 hours for most users, occasionally longer. Check the report timestamp before treating a recent enrollment as missing.
- **Not all directory accounts:** disabled and soft-deleted users are absent. An absent row is not proof of nonregistration. Do not use this row count as the denominator for the entire tenant without reconciling the populations.
- **Not a compliance verdict:** registration, allowed methods, authentication strength and the application's access policy answer different questions.

**Verify:** compare a few known registered and unregistered accounts with the Entra registration report after allowing for its refresh. Confirm that `Registered + NotRegistered = ReportedUsers`; inspect the registered-but-not-capable group separately. A failed API request is not a tenant with zero MFA registrations.

## When the question really is usage

Use **Authentication methods > Activity > Usage** and the authentication details of relevant sign-in records. Distinguish a fresh MFA challenge from a requirement satisfied by an existing token claim. The usage dashboard also has exclusions, including some third-party MFA and token-claim-satisfied scenarios.

For an AD FS-only relying party, Entra sign-in logs are not a complete application authentication history. Correlate the AD FS and application evidence rather than treating this enrollment CSV as an MFA audit trail.

## References

- [Microsoft Graph: List userRegistrationDetails](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0)
- [Microsoft Graph: Registration field definitions](https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0)
- [Microsoft Learn: Authentication methods activity, licensing and reporting limits](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)