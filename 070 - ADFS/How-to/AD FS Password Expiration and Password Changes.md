---
title: "AD FS Password Expiration and Password Changes"
date: 2026-10-01
---

# AD FS Password Expiration and Password Changes

**A password-change page is not a password-reset service.**

AD FS provides a native page at `/adfs/portal/updatepassword/`. Use its documented endpoint and content controls before considering custom redirects or a separate password application.

## 1. Identify the user journey

| Situation | Question to resolve |
|---|---|
| User knows the current password and wants a new one | Can the native change page complete the directory operation? |
| Password expired or must change at next logon | Does this server build and client authentication path present and complete the change flow? |
| User forgot the password | Use the organization's reset/help-desk or SSPR process; the native page does not replace identity recovery |
| Account locked, disabled or restricted | Investigate account state; a new page URL does not remove directory controls |
| Existing application session still works | SSO/session lifetime is separate from the next fresh password validation |

The native form asks for the account, the existing password and the new password. An expired password, a temporary first-logon password and a forgotten password are different test cases. A noninteractive client cannot necessarily display the browser flow, and a WIA challenge is not an AD FS forms page.

Microsoft Entra SSPR and password writeback are separately configured services with their own prerequisites and licensing. Enabling an AD FS endpoint does not enable writeback or cloud identity recovery.

## 2. Read the historical version caveat correctly

The Microsoft Learn customization page still describes navigating from a **Workplace Joined device**. That wording is not a universal requirement for every patched AD FS release: **KB3035025**, specifically for Windows Server 2012 R2, removed the registered-device requirement for this feature.

Do not install that old hotfix on later Windows Server releases or use its existence as a current support/lifecycle statement. Record the deployed OS, cumulative update level, AD FS version and client path. Test an unregistered external client separately if that is part of the required experience. Page availability, automatic handling of an expired password and successful password change are three different observations.

## 3. Capture the exact endpoint state

On an AD FS administration host, use Windows PowerShell 5.1 and AD FS administrative rights. In a WID farm, make farm configuration changes from the primary. The initial query is read-only and requires exactly one matching endpoint:

```powershell
Import-Module ADFS -ErrorAction Stop
$endpointPath = '/adfs/portal/updatepassword/'
$passwordEndpoints = @(Get-AdfsEndpoint -ErrorAction Stop |
    Where-Object { $_.AddressPath -eq $endpointPath })
if ($passwordEndpoints.Count -ne 1) {
    throw 'Expected exactly one native update-password endpoint.'
}
$passwordEndpoint = $passwordEndpoints[0]
if ($passwordEndpoint.Enabled -isnot [bool] -or
    $passwordEndpoint.Proxy -isnot [bool]) {
    throw 'Expected endpoint flags are unavailable; check the installed version.'
}
$endpointBefore = [pscustomobject]@{
    AddressPath = $passwordEndpoint.AddressPath
    Enabled = $passwordEndpoint.Enabled
    Proxy = $passwordEndpoint.Proxy
}
$endpointBefore
```

Keep this before-state in the change record. A missing property is not the same as a disabled endpoint.

## 4. Separate native activation from external exposure

In AD FS Management, find **Endpoints > Other > /adfs/portal/updatepassword/**. **Enable** makes the endpoint available on AD FS; **Enable on proxy** is a separate choice for access through WAP.

The following previews activation. External publication remains off in this example unless `$publishExternally` is deliberately changed to `$true`:

```powershell
$publishExternally = $false
if (-not $endpointBefore.Enabled) {
    Enable-AdfsEndpoint -TargetAddressPath $endpointPath -WhatIf -ErrorAction Stop
}
if ($publishExternally -and -not $endpointBefore.Proxy) {
    Set-AdfsEndpoint -TargetAddressPath $endpointPath -Proxy $true `
        -WhatIf -ErrorAction Stop
}
```

Leaving `$publishExternally` false **does not remove an existing proxy publication**. It simply makes no proxy change. Review the captured state and intended exposure first.

After rechecking that the state has not changed concurrently, replace the relevant `-WhatIf` with `-Confirm` to apply that change. Microsoft's procedure requires a **manual AD FS service restart after enabling the endpoint**. Coordinate node-by-node restarts with load balancing and check service health before returning each node to rotation.

Read the state back, without overwriting `$endpointBefore`:

```powershell
Get-AdfsEndpoint -ErrorAction Stop |
    Where-Object { $_.AddressPath -eq $endpointPath } |
    Select-Object AddressPath, FullUrl, Enabled, Proxy
```

Navigate to `https://fs.corp.example/adfs/portal/updatepassword/`, using the real federation hostname with valid TLS. Test the direct internal path and, if intended, the actual external WAP path. A 200 response or visible form proves neither that AD accepted the password nor that every farm node is ready.

## 5. Verify the change operation

Use an account intended for testing password changes and track each attempt. Check the normal directory password policy, any fine-grained policy and password filters; do not lower those controls to make a test succeed.

| Test | Evidence to retain |
|---|---|
| Known current password, acceptable new password | User-facing completion and subsequent fresh authentication |
| New password rejected by policy | Expected failure, without recording either password |
| Expired password | Exact entry path, prompt and outcome on the installed release |
| Must change at next logon | Separate outcome from ordinary expiry |
| Internal versus external route | Intended availability and actual WAP/AD FS node |
| Client without device registration | Actual behavior, not an assumption based on an old screenshot |

AD FS 2016 auditing documents password-change events **1204** and **1205** for success/error. Correlate applicable events with the transaction using the [logging guide](../Troubleshoot/Troubleshooting%20AD%20FS%20-%20Logs,%20Activity%20IDs%20and%20Evidence%20Collection.md). A directory connectivity, permission or policy failure is not a branding issue.

Do not record password submissions in browser traces or debug bundles. Do not infer that all existing sessions are revoked because the password changed; verify session behavior independently where it matters.

## 6. Customize the explanation, not the credential flow

The supported description control is `Set-AdfsGlobalWebContent` with `UpdatePasswordPageDescriptionText`. Capture the existing content and culture-specific variants before changing them. Use fixed explanatory text or a fixed organizational support link, and follow the [web-theme guide](Customizing%20AD%20FS%20Sign-In%20Pages%20-%20Web%20Themes%20and%20onload.js.md) for preview and restoration.

Avoid JavaScript injected into description fields, automatic redirection based on an error string, or forwarding the user to a URL supplied in an arbitrary query parameter. Base64-encoding a return URL does not validate its destination. An app that cannot complete the native flow needs a defined reset/change journey, not a browser redirect that hides the original failure.

## 7. Restore only the endpoint settings changed here

Preview restoration of the captured flags. Selectively apply the relevant operations with confirmation, account for the required service restart and retest both paths:

```powershell
Set-AdfsEndpoint -TargetAddressPath $endpointBefore.AddressPath `
    -Proxy $endpointBefore.Proxy -WhatIf -ErrorAction Stop
if ($endpointBefore.Enabled) {
    Enable-AdfsEndpoint -TargetAddressPath $endpointBefore.AddressPath `
        -WhatIf -ErrorAction Stop
}
else {
    Disable-AdfsEndpoint -TargetAddressPath $endpointBefore.AddressPath `
        -WhatIf -ErrorAction Stop
}
```

This restores endpoint configuration, **not a user's previous password**. Content changes and client state have their own before-state and validation.

## References

- [Microsoft Learn: Update password customization](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/update-password-customization)
- [Microsoft Support: KB3035025, registered-device requirement removed on Windows Server 2012 R2](https://support.microsoft.com/help/3035025)
- [Microsoft Learn: Enable-AdfsEndpoint](https://learn.microsoft.com/en-us/powershell/module/adfs/enable-adfsendpoint?view=windowsserver2025-ps)
- [Microsoft Learn: Set-AdfsEndpoint](https://learn.microsoft.com/en-us/powershell/module/adfs/set-adfsendpoint?view=windowsserver2025-ps)
- [Microsoft Learn: Disable-AdfsEndpoint](https://learn.microsoft.com/en-us/powershell/module/adfs/disable-adfsendpoint?view=windowsserver2025-ps)
- [Microsoft Learn: Password writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback)