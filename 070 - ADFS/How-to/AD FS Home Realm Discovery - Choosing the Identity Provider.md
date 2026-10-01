---
title: "AD FS Home Realm Discovery: Choosing the Identity Provider"
date: 2026-09-29
---

# AD FS Home Realm Discovery: Choosing the Identity Provider

**Home Realm Discovery chooses where to authenticate. It does not decide what the user may access.**

When AD FS trusts several claims providers, Home Realm Discovery (HRD) routes the user to an identity source. The choice can depend on the RP's provider list, intranet behavior, an organizational-account suffix, request hints and previously stored browser state. A customized button or a remembered choice is not proof that authentication succeeded.

## Identify the three decisions

```text
Requested application (RP)
    -> identity source (HRD / claims provider)
        -> authentication and RP policy
            -> token and application landing state
```

The RP identifies the application; a claims provider supplies the identity; RelayState or the application's return state concerns navigation after the protocol exchange. Changing one is not a substitute for configuring another. See [AD FS authentication flows](../Concepts/AD%20FS%20Authentication%20Flows%20-%20Trusts,%20Identifiers,%20Metadata%20and%20Endpoints.md) and the [RelayState guide](../Concepts/What%20is%20ADFS%20Relay%20State.md).

## Inventory the current routing

Run on an AD FS administration host with Windows PowerShell 5.1. Use the WID primary for configuration writes. Select the actual RP identifier and retain this before-state in the change record:

```powershell
Import-Module ADFS -ErrorAction Stop
$rpIdentifier = 'urn:corp:claimsportal'
$rpResults = @(Get-AdfsRelyingPartyTrust -Identifier $rpIdentifier -ErrorAction Stop)
if ($rpResults.Count -ne 1) {
    throw 'Expected exactly one relying party.'
}
$rpBefore = $rpResults[0]
$providersBefore = @(Get-AdfsClaimsProviderTrust -ErrorAction Stop)
$webBefore = Get-AdfsWebConfig -ErrorAction Stop
$propertiesBefore = Get-AdfsProperties -ErrorAction Stop

$rpBefore | Select-Object Name, Identifier, ClaimsProviderName
$providersBefore | Select-Object Name, Identifier, Enabled, OrganizationalAccountSuffix
$webBefore | Select-Object HRDCookieEnabled, HRDCookieLifetime
$propertiesBefore | Select-Object IntranetUseLocalClaimsProvider
```

The local AD provider can appear on the HRD page under the federation service's display name, while its configuration name is `Active Directory`. Read identifiers and names rather than inferring the underlying trust from a branded label.

## Choose the smallest applicable change

### Route an account suffix to an existing provider

For an already configured and verified partner claims provider, suffix-based discovery can avoid asking every user to choose from a list:

```powershell
Set-AdfsClaimsProviderTrust -TargetName 'Partner IdP' `
    -OrganizationalAccountSuffix @('partner.example', 'subsidiary.example') `
    -WhatIf -ErrorAction Stop
```

This sets the provider's **complete suffix list**. Record and merge any existing entries deliberately; do not erase them with a one-item example. These are suffixes used for discovery, not creation of a federation trust or proof that the person owns the entered address. Define ownership of overlapping suffixes before deployment.

### Limit the provider list for one RP

```powershell
Set-AdfsRelyingPartyTrust -TargetIdentifier $rpIdentifier `
    -ClaimsProviderName @('Active Directory', 'Partner IdP') `
    -WhatIf -ErrorAction Stop
```

Again, this is a complete list, not an append operation. Confirm that all listed trusts exist and that the RP should accept their identity sources. Do not implement this restriction by merely hiding HTML elements: server-side trust and issuance policy remain authoritative.

### Prefer local AD on the intranet

```powershell
Set-AdfsProperties -IntranetUseLocalClaimsProvider $true -WhatIf -ErrorAction Stop
```

This is **farm-wide**, unlike the preceding RP setting. Microsoft's HRD guidance notes an interaction: when an RP-specific provider list exists, it must include `Active Directory` for the intended intranet bypass. Do not interpret this setting as removing external providers from every application or forcing a particular user-authentication method.

Run only the chosen operation, not all three as a universal recipe. After reviewing its scope and retained state, replace `-WhatIf` with `-Confirm` for the actual change, then read the corresponding object back. Previews do not simulate the user's routing or validate partner authentication.

## Cookies and hints explain many apparent inconsistencies

An HRD cookie remembers identity-source selection. It is not the AD FS authentication cookie, the application's session or an authorization decision. Diagnose an existing browser session and a clean profile separately before changing the farm-wide cookie configuration.

Request hints are protocol-specific. For example, a WS-Federation home-realm hint is not a SAML RelayState value. In an AD FS-to-AD FS WS-Federation relationship, Microsoft documents the CP's `PromptLoginFederation` setting for forwarding supported prompt/login hints. Apply that only to the correct trust and protocol, not as an unqualified global command.

Avoid scripting redirects or editing protocol parameters in `onload.js` to implement routing. Microsoft's customization guidance excludes changes that alter AD FS redirect flows or protocol parameters from the supported customization model.

## Verify and roll back

| Case | What to observe |
|---|---|
| Clean browser, each intended account suffix | Correct identity source, then correct user and RP outcome |
| Existing HRD cookie | Whether remembered state explains a different route |
| Intranet versus WAP/extranet | The applicable path and local-provider behavior |
| RP with a restricted list versus another RP | The intended per-application difference |
| Unknown suffix or disabled provider | Controlled failure/selection behavior, not a redirect loop |
| Upstream IdP with login/prompt hints | What the receiving provider actually honors |

**Verify:** follow the redirects and correlate both providers' results. Reaching the desired login page is not evidence that the downstream token or application permission is correct.

For rollback, restore the recorded suffix list, RP provider list or intranet flag through the same configuration surface. Restore cookie settings separately only if they were changed. Do not use an empty array as shorthand for a remembered default: an explicit restriction and an inherited/unrestricted state can have different meanings. Repeat the clean/existing-session tests after restoration.

## References

- [Microsoft Learn: Home Realm Discovery customization](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/home-realm-discovery-customization)
- [Microsoft Learn: Get-AdfsWebConfig](https://learn.microsoft.com/en-us/powershell/module/adfs/get-adfswebconfig?view=windowsserver2025-ps)
- [Microsoft Learn: Advanced sign-in customization boundaries](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/advanced-customization-of-ad-fs-sign-in-pages)