---
title: "AD FS and MFA Registration: Guiding Unregistered Users"
date: 2026-10-01
---

# AD FS and MFA Registration: Guiding Unregistered Users

**A link to enrollment can help a user. It cannot repair an adapter or bypass registration policy.**

The built-in Entra MFA adapter does not register verification methods inline on the AD FS page. An unregistered user can therefore reach an AD FS error instead of an enrollment wizard. Registration takes place in Entra, and the user then retries the original application.

This note replaces the historical "detect an English error and redirect after five seconds" recipe with explicit guidance. It complements the [adapter configuration and certificate guide](../How-to/AD%20FS%20and%20Microsoft%20Entra%20MFA%20-%20Configuration%20and%20Certificate%20Renewal.md).

## First establish which problem occurred

| Observation | Check before changing the sign-in page |
|---|---|
| User has no usable verification method | Registration state, allowed methods and adapter support |
| "The selected authentication method is not available" | Method/provider availability and correlated server error; not unique proof of nonregistration |
| Failures occur on only one AD FS node | That node's MFA certificate, private key, tenant public credential and outbound path |
| Enrollment repeatedly returns to the same error | Federation primary-authentication choices and policies protecting registration |
| Previously enrolled user cannot manage methods | Required fresh authentication, available alternative methods and recovery process |

Read the actual AD FS policy rather than assuming the MFA adapter is used as the second factor:

```powershell
Get-AdfsGlobalAuthenticationPolicy -ErrorAction Stop |
    Format-List PrimaryIntranetAuthenticationProvider, PrimaryExtranetAuthenticationProvider,
        AdditionalAuthenticationProvider, AllowAdditionalAuthenticationAsPrimary
```

The [Graph registration report](../../010%20-%20Entra%20ID/Reports/MFA%20Registration%20Report%20with%20Microsoft%20Graph%20-%20Registration%20Is%20Not%20Usage.md) helps with population planning, but its refresh delay makes it unsuitable as a real-time sign-in decision. Correlate the user's current method state and server/cloud events for the failing request.

## Provide a registration path that can actually succeed

Direct users to the documented [MFA setup entry point](https://aka.ms/mfasetup), or the organization's validated Security info entry point, and have them return to the application after completing registration.

Check the tenant/account in use, especially for guests. A method registered in the user's home tenant does not automatically represent the same registration state in a resource tenant. Use a modern browser; an old embedded webview is not a good registration surface.

**Registration has its own authentication requirements.** Combined registration, existing methods and Conditional Access targeting **Register security information** affect what the user must present. A historical promise that every unregistered federated user can enroll using only a password is not a substitute for testing the current tenant's policy.

Plan first-use and lost-method recovery before making the Entra MFA adapter the only primary path. A supported bootstrap method, such as a properly issued Temporary Access Pass where applicable, belongs to the Entra registration design; it is not a credential that automatically works in an AD FS forms field. Do not exempt all registration from protection simply to break a loop.

## Optional error-page hint, not error detection

Prefer existing support/help content when sufficient. If the custom AD FS error page needs a registration link, append a small addition to the exported `onload.js` using the [theme staging and rollback procedure](../How-to/Customizing%20AD%20FS%20Sign-In%20Pages%20-%20Web%20Themes%20and%20onload.js.md).

The following example adds the same conditional advice wherever the current theme exposes a nonempty `errorMessage` element. It **does not classify the error** or establish that the user is unregistered. It leaves the original error and diagnostic links intact:

```javascript
(function () {
    var errorMessage = document.getElementById('errorMessage');
    if (!errorMessage || !errorMessage.parentNode || !errorMessage.textContent.trim() ||
        document.getElementById('mfaRegistrationHelp')) {
        return;
    }

    var help = document.createElement('p');
    help.id = 'mfaRegistrationHelp';
    help.appendChild(document.createTextNode(
        'If you have not registered your security info, '
    ));

    var link = document.createElement('a');
    link.href = 'https://aka.ms/mfasetup';
    link.textContent = 'open MFA setup';
    help.appendChild(link);
    help.appendChild(document.createTextNode(
        ', then return to this application and try again. Otherwise, contact your support team.'
    ));

    errorMessage.parentNode.appendChild(help);
})();
```

Localize the message and validate the element IDs against the actual theme, including the 2019 paginated experience. No error-string matching means the advice can also appear for unrelated errors; keep the wording conditional and scope the customization appropriately. Do not inject a username, tenant hint or return URL from untrusted query data into the link.

This intentionally has no timer, no `window.location` rewrite and no hidden error details. It offers an explicit navigation choice after failure, rather than changing an in-progress authentication protocol flow. The original request is not automatically resumed by this snippet.

## Verify the complete journey

Test an unenrolled user, an enrolled user with a temporarily unavailable method, an unrelated authentication error, and pages without an error element. Check repeated script execution, languages, desktop/mobile layout and CSP. The hint should appear at most once and never replace the original error.

Then test the real registration route under the relevant Conditional Access policies. Confirm the method is permitted and usable by the AD FS adapter, return to the RP and complete a fresh sign-in. A changed page message is not evidence that enrollment or MFA succeeded.

## References

- [Microsoft Learn: AD FS and Entra MFA registration behavior](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-and-azure-mfa)
- [Microsoft Learn: Combined MFA and SSPR registration](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined)
- [Microsoft Learn: Conditional Access for security information registration](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration)