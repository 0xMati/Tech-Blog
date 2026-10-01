---
title: "AD FS Alternate Login ID"
date: 2026-09-29
---

# AD FS Alternate Login ID

**Changing what a user types is not the same as changing the user's UPN or the identity an application receives.**

AD FS Alternate Login ID lets username/password authentication look up an AD user through another configured attribute, such as `mail`. It is useful when the UPN cannot reasonably be aligned with the user's sign-in address. Microsoft recommends aligning UPN and primary SMTP address where possible rather than adding this indirection by default.

## Keep the three identities separate

| Item | Fictional example | Changed by this AD FS setting? |
|---|---|---|
| On-premises UPN | `LabUser@corp.example` | No |
| Alternate attribute entered at sign-in | `LabUser@sign-in.example`, stored in `mail` | Selects the lookup attribute, not its values |
| Subject/UPN/NameID sent to the RP | Whatever that trust's validated identity contract requires | Not automatically made consistent by changing the lookup |

This is also separate from the attribute Entra Connect synchronizes as the cloud UPN, Entra's email-alternate-sign-in feature for managed identities, or a cosmetic change to the AD FS username label. For Microsoft 365 federation, coordinate the directory, synchronization and federation settings. Microsoft's documentation recommends the supported Entra Connect configuration workflow for that integrated scenario.

## Check the prerequisites first

- The selected LDAP attribute must identify the intended user uniquely across the configured forests. Check duplicates, missing values and collisions with other users' UPNs.
- AD FS needs the appropriate forest trust/read access and reachable global catalogs in the user-account forests. An unavailable forest is not proof of uniqueness across all forests.
- Both `AlternateLoginID` and `LookupForests` must be configured. Use forest DNS names, not email suffixes chosen merely because they appear after `@`.
- This lookup feature applies to the username/password paths supported by AD FS. **WIA uses the Windows/UPN identity path**, not a user typing the alternate attribute. Certificate authentication is another path again.
- For Entra federation, verify the routable/verified domain and cloud identity requirements separately. Do not copy old Office/Lync registry workarounds as a current client baseline.

AD FS tries the alternate lookup first and can fall back to UPN if it cannot identify an account that way. That does not make collisions harmless: if one user's alternate value equals another user's UPN, the first lookup can identify the wrong account for the supplied credentials or prevent the expected sign-in. Multiple alternate-ID matches cause failure.

## Observe, then preview the configuration

Use Windows PowerShell 5.1 with the ADFS module and appropriate administration rights. Configuration writes in a WID farm belong on the primary server.

```powershell
Import-Module ADFS -ErrorAction Stop
$providers = @(Get-AdfsClaimsProviderTrust -Identifier 'AD AUTHORITY' -ErrorAction Stop)
if ($providers.Count -ne 1) {
    throw 'Expected the built-in Active Directory claims provider.'
}
$beforeAlternateId = [pscustomobject]@{
    AlternateLoginID = $providers[0].AlternateLoginID
    LookupForests = $providers[0].LookupForests
}
$beforeAlternateId
```

Retain these two values in the change record. The next command is a **preview** for the fictional forest `corp.example`; it does not populate or deduplicate `mail` in AD:

```powershell
Set-AdfsClaimsProviderTrust -TargetIdentifier 'AD AUTHORITY' `
    -AlternateLoginID 'mail' -LookupForests @('corp.example') `
    -WhatIf -ErrorAction Stop
```

After the directory and application checks, use `-Confirm` instead of `-WhatIf` to make the reviewed change. This affects the built-in provider, not just the one application used for testing. Read the same provider back to confirm both settings.

## Verify the identity, not just the welcome page

| Test | Expected evidence |
|---|---|
| Unique alternate ID with correct password | The intended AD account authenticates; the application receives the expected stable identity |
| Existing UPN sign-in | Its behavior remains as designed, including any alternate-ID collision |
| Duplicate alternate value | A clear lookup failure, not selection of an arbitrary account |
| Missing alternate attribute | The documented UPN fallback is tested with the relevant client |
| Intranet WIA | Correct identity/claims even though alternate text lookup was not used |
| External username/password | Same intended account and RP outcome through WAP |
| GC/forest availability issue | Directory reachability is diagnosed, not hidden by a successful fallback in another case |

Event 364 with messages such as **MSIS8014/MSIS8015** can identify multiple-account matches; inspect the actual exception, forest and timestamp. The generic event ID alone is not a duplicate-attribute diagnosis. Record errors without publishing the account names or credentials.

## Rollback

Restore the **recorded pair** of settings, not just the attribute name:

```powershell
Set-AdfsClaimsProviderTrust -TargetIdentifier 'AD AUTHORITY' `
    -AlternateLoginID $beforeAlternateId.AlternateLoginID `
    -LookupForests $beforeAlternateId.LookupForests -WhatIf -ErrorAction Stop
```

Review, then replace `-WhatIf` with `-Confirm` for the actual rollback. Microsoft documents disabling the feature by setting **both** values to `$null`; that is appropriate only if disabled was the intended prior state. Restoring these settings does not revert separately changed AD attributes, Entra Connect rules or RP claim rules.

For the distinction between authentication input and issued claims, see [AD FS claims explained](../Concepts/AD%20FS%20Claims%20Explained%20-%20Attribute%20Stores,%20Claim%20Descriptions%20and%20Token%20Issuance.md).

## Reference

- [Microsoft Learn: Configuring Alternate Login ID](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configuring-alternate-login-id), including uniqueness, WIA and forest-lookup limitations.