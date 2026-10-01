---
title: "Customizing AD FS Sign-In Pages: Web Themes and onload.js"
date: 2026-09-29
---

# Customizing AD FS Sign-In Pages: Web Themes and onload.js

**A custom sign-in page should change the presentation, not quietly replace the authentication protocol.**

AD FS 2012 R2 and later expose supported web-content and theme configuration instead of requiring edits to an IIS application. For a current deployment, start with those controls, clone the existing theme and keep a recorded rollback. This guide combines branding and small UI adjustments; it is not an application-development tutorial.

## 1. Use the right customization surface

| Need | Native surface | Boundary |
|---|---|---|
| Company name, help/privacy links, sign-in descriptions and error messages | Global web content | Farm-wide content is separate from theme assets |
| Logo, illustration, CSS and additional resources | Web theme | Work on a copy, not an undocumented file in the installation directory |
| Application-specific messages or branding | RP web content/theme, supported from AD FS 2016 | Check the RP-specific override as well as the global setting |
| Behavior not exposed by the native controls | Custom theme's `onload.js` | Runs on multiple AD FS pages; limit and test its effects |
| Choosing an IdP or changing authentication policy | HRD/authentication configuration | Not an HTML-hiding or redirect-script problem |

Use the current cmdlet help for the exact fields of `Set-AdfsGlobalWebContent`, `Set-AdfsRelyingPartyWebContent` and `Set-AdfsRelyingPartyWebTheme`. Global and per-RP parameters are not all named identically. Locale-specific content and right-to-left rendering must be reviewed where used.

Microsoft explicitly excludes customizations that change redirect flows or AD FS protocol parameters from the supported model. Do not copy a collection of old `onload.js` fragments wholesale: changing login submission, injecting external scripts or rewriting a return URL has a different impact from updating a label.

## 2. Inventory and stage a separate theme

Use Windows PowerShell 5.1 on an AD FS administration host with configuration rights. In a WID farm, make configuration writes on the primary. Retain the original theme export, active name, global content and any RP-specific overrides before editing.

```powershell
Import-Module ADFS -ErrorAction Stop
$webBefore = Get-AdfsWebConfig -ErrorAction Stop
Get-AdfsWebTheme -ErrorAction Stop | Select-Object Name, IsBuiltinTheme
$webBefore | Select-Object ActiveThemeName
```

Choose an unused theme name and a new local export directory. The following **creates a theme after confirmation and exports files**; it does not activate the theme:

```powershell
$themeName = 'CorpSignIn-20260929'
$exportPath = 'C:\AdfsThemeReview\CorpSignIn-20260929'
if (@(Get-AdfsWebTheme -ErrorAction Stop | Where-Object Name -eq $themeName).Count) {
    throw 'Choose a new theme name; do not overwrite an existing theme.'
}
if (Test-Path -LiteralPath $exportPath) {
    throw 'Choose a new export directory.'
}
New-AdfsWebTheme -Name $themeName -SourceName $webBefore.ActiveThemeName -Confirm -ErrorAction Stop
Export-AdfsWebTheme -Name $themeName -DirectoryPath $exportPath -ErrorAction Stop
```

Cloning the active theme preserves its current basis instead of assuming the installation still uses `default`. For a new theme generation or changed server version, deliberately choose and test that baseline. Exported files are a working copy: editing them does not automatically update the stored AD FS theme.

## 3. Prefer native content and asset changes

For reviewed local image files, preview changes to the **inactive copy**:

```powershell
Set-AdfsWebTheme -TargetName $themeName `
    -Logo @{Path='C:\AdfsThemeReview\logo.png'} `
    -Illustration @{Path='C:\AdfsThemeReview\illustration.png'} `
    -WhatIf -ErrorAction Stop
```

Use appropriately sized assets for the selected theme, preserving readable contrast and layout on small screens. Record locale-specific assets before replacing any collection. After review, use `-Confirm` instead of `-WhatIf` to store the change. That still does not activate this previously inactive theme.

For ordinary descriptions, help links and custom error messages, use the native web-content configuration before reaching for JavaScript. Use useful support text without exposing tenant details, full exception data or identities in authentication failures. Treat an error-page text change as presentation, not repair of the underlying error.

## 4. Append narrowly scoped onload.js logic

Keep the original exported `script\onload.js` code and append the smallest necessary addition. The built-in code also handles layout/form factors. Test element existence because the script can run on forms, HRD, password-update and other pages.

This example updates a text label only where that element exists. It uses `textContent`, not HTML assembled from a request parameter:

```javascript
(function () {
    var loginMessage = document.getElementById('loginMessage');
    if (loginMessage) {
        loginMessage.textContent = 'Sign in with your organization account';
    }
})();
```

Use native localized web content instead when it satisfies the requirement. A hard-coded string like this one is not automatically translated, and element IDs must be checked against the actual theme after an upgrade.

### The specific case: a read-only username field

For a reviewed flow that already supplies the intended username, an interface can discourage accidental editing. The following changes only an existing, nonempty input:

```javascript
(function () {
    var loginForm = document.forms.namedItem('loginForm');
    var userNameField = loginForm ? loginForm.elements.namedItem('UserName') : null;
    if (userNameField && userNameField.tagName === 'INPUT' && userNameField.value) {
        userNameField.readOnly = true;
    }
})();
```

**This is not an identity restriction.** A client can change HTML or submit another value. It neither binds the user's identity to an application nor authorizes access. Do not populate the field from unvalidated URL data or lock an empty field. Leave account-switching and recovery paths usable, and enforce identity/access requirements on the server.

On AD FS 2016 and later, preview loading the reviewed exported file:

```powershell
Set-AdfsWebTheme -TargetName $themeName `
    -OnLoadScriptPath (Join-Path $exportPath 'script\onload.js') `
    -WhatIf -ErrorAction Stop
```

The older 2012 R2 procedure uses `AdditionalFileResource` for `/adfs/portal/script/onload.js`. That is a version distinction, not a second operation to apply alongside `-OnLoadScriptPath`. Do not inject a `<script>` into sign-in description HTML as a substitute for the documented resource configuration.

## 5. Test, then select the intended scope

```mermaid
flowchart LR
    Inventory[Record current state] --> Copy[Clone and export]
    Copy --> Edit[Edit inactive copy]
    Edit --> Test[Test page and protocol paths]
    Test --> Apply[Activate reviewed scope]
    Apply --> Verify[Verify or restore before-state]
```

An inactive theme still needs a supported test environment or controlled RP deployment to test the real AD FS pages. A JavaScript unit test is not a full AD FS sign-in test.

| Test | Verify |
|---|---|
| Forms sign-in, empty and prefilled username | Keyboard use, errors, account switching and normal submission |
| HRD and external IdP | Missing login-form elements do not cause script errors or change routing |
| MFA, certificate selection and password update | The script does not interfere with pages it was not meant to modify |
| Supported languages, mobile and desktop | Text fits, images load and controls remain accessible |
| Logout and application return | No protocol parameter or callback changes |
| CSP and browser console | No new blocked resources or script errors; do not loosen CSP just to hide a faulty customization |

Preview **global activation** only after the files have actually been imported and tested:

```powershell
Set-AdfsWebConfig -ActiveThemeName $themeName -WhatIf -ErrorAction Stop
```

For an RP-specific deployment on a version that supports it, the alternative scope is:

```powershell
Set-AdfsRelyingPartyWebTheme -TargetRelyingPartyName 'ClaimsPortal' `
    -SourceWebThemeName $themeName -WhatIf -ErrorAction Stop
```

Choose the intended scope; do not run both as a default sequence. Replace `-WhatIf` with `-Confirm` for the approved activation, then read the corresponding global/RP configuration back and test the real sign-in path, including WAP where used.

For the relationship with headers, see [AD FS HTTP response headers](Hardening%20AD%20FS%20HTTP%20Response%20Headers%20-%20HSTS,%20CSP%20and%20Validation.md). For identity routing, see [HRD configuration](AD%20FS%20Home%20Realm%20Discovery%20-%20Choosing%20the%20Identity%20Provider.md).

## 6. Roll back the surface that changed

For a global theme switch, preview restoration of the recorded theme:

```powershell
Set-AdfsWebConfig -ActiveThemeName $webBefore.ActiveThemeName -WhatIf -ErrorAction Stop
```

Restore the reviewed value with confirmation, then repeat the failed scenario. A global switch does not undo RP-specific overrides, separate global/RP text changes, or files already changed inside the original theme. Restore those from their own before-state rather than indiscriminately deleting the customization. Keep the old theme intact until validation is complete.

## References

- [Microsoft Learn: AD FS user sign-in customization](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-user-sign-in-customization)
- [Microsoft Learn: Advanced customization and supported boundaries](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/advanced-customization-of-ad-fs-sign-in-pages)
- [Microsoft Learn: Per-RP customization in AD FS 2016 and later](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-customization-in-windows-server)
- [Microsoft Learn: New-AdfsWebTheme](https://learn.microsoft.com/en-us/powershell/module/adfs/new-adfswebtheme?view=windowsserver2025-ps)