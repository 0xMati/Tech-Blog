---
title: "AD FS Logout Explained: Application Sessions, Federation Cookies and Single Logout"
date: 2026-09-25
---

# AD FS Logout Explained: Application Sessions, Federation Cookies and Single Logout

**A successful logout page does not prove that every application session or previously issued token is now unusable.**

An application and AD FS maintain different session state. Single Logout (SLO) coordinates participating sessions; it is not a universal command to sign a user out of Windows, every device and every API.

> **TL;DR**
> - The application must terminate its own session.
> - Federation sign-out must use the protocol and endpoints actually configured for that application.
> - Other applications must support and process logout notifications; a redirect alone is not proof.
> - Windows Integrated Authentication or an upstream IdP session can immediately authenticate the user again.

## 1. Which session are you closing?

| State | Owner | Effect of signing out at AD FS |
|---|---|---|
| Application cookie/server session | Relying party (RP) | Requires application cleanup, directly or through a supported logout exchange |
| AD FS browser SSO session | AD FS | Can be ended by the appropriate federation sign-out flow |
| Upstream identity-provider session | Another IdP trusted by AD FS | Depends on that protocol, trust and provider's logout behavior |
| Windows logon/Kerberos state | Client operating system | Not ended by deleting a browser cookie |
| Issued access token | Issuer and accepting API | Do not assume browser sign-out immediately invalidates every issued token |

Closing a tab is not a reliable session-termination mechanism. Likewise, clearing only the application's cookie can make the next visit silently obtain a new application session through the still-active federation session.

## 2. Follow the application's protocol

| Protocol | Logout conversation | What to verify |
|---|---|---|
| WS-Federation passive | A sign-out request such as `/adfs/ls/?wa=wsignout1.0`; cleanup notifications can use `wsignoutcleanup1.0` | The application processes its cleanup request and removes its own session |
| SAML 2.0 | `LogoutRequest` / `LogoutResponse` through configured Single Logout endpoints and bindings | Correct issuer/destination, NameID/session context, request correlation, status and signature validation for that binding |
| OpenID Connect | Browser redirect to the provider's advertised `end_session_endpoint` | AD FS version/application support, registered logout/return destinations and application-cookie cleanup |

`wsignoutcleanup1.0` is a participant-cleanup action, not a newer or older spelling of the initiating sign-out request. SAML `LogoutResponse` is not a login assertion. OAuth token issuance by itself does not define a universal browser logout flow.

For an OIDC application, inspect the actual discovery document rather than inventing an endpoint or copying Microsoft Entra endpoints into an AD FS integration:

```powershell
$metadata = Invoke-RestMethod `
    -Uri 'https://fs.corp.example/adfs/.well-known/openid-configuration' `
    -Method Get -ErrorAction Stop

$metadata | Select-Object issuer, end_session_endpoint,
    frontchannel_logout_supported, frontchannel_logout_session_supported
```

Use the application's supported middleware to initiate logout and validate any return URI against its registration. Do not place live tokens in documentation, diagnostics shared publicly or arbitrary logout URLs.

AD FS added OIDC front-channel logout to updated AD FS 2016 and later. Microsoft documents **best-effort** notifications to each participating application's registered `LogoutUri`, with the relevant `sid` session identifier. That callback must clear the application's authentication state. It is different from `post_logout_redirect_uri`, the registered destination to which the browser returns after sign-out.

Microsoft also explicitly notes that a client retaining a valid refresh token can obtain another access token after logout. The application must discard its authenticated artifacts when processing sign-out; do not describe the browser operation as global token revocation.

## 3. What the SAML captures show

These five historical captures are retained as illustrations, not evidence of current Windows Server 2022/2025 behavior. Encoded messages, cookies and correlation/session values have been masked. The accompanying internal email conversation is not reproduced.

### A browser-mediated exchange

The application creates a logout request, the browser transports it to AD FS, and the response returns to the application's configured logout endpoint. The application must validate the result and terminate the appropriate session. The diagram shows one RP; it omits additional participants and failure handling.

![Historical browser-mediated SAML logout flow](assets/AD%20FS%20Logout%20Explained%20-%20Application%20Sessions,%20Federation%20Cookies%20and%20Single%20Logout/capture-04.png)

### Other participating sessions

The annotated overview highlights requests and responses involving another participant. This requires that participant to support the relevant logout flow. It does not mean every application the user has ever visited is automatically discovered and signed out.

![Historical annotated overview of logout across session participants](assets/AD%20FS%20Logout%20Explained%20-%20Application%20Sessions,%20Federation%20Cookies%20and%20Single%20Logout/capture-03.png)

### A response that needs investigation

The trace reports that a signature is not present for a particular `LogoutResponse`. Investigate the endpoint, binding, trust configuration and relevant message validation. The screenshot alone does not establish a universal signing rule, identify the faulty participant or justify disabling signature checks.

![Historical AD FS trace reporting a missing logout-response signature, with identifier removed](assets/AD%20FS%20Logout%20Explained%20-%20Application%20Sessions,%20Federation%20Cookies%20and%20Single%20Logout/capture-01.png)

A `SAMLResponse` field in an HTTP trace proves only that a message was transported. Decode it privately and examine its actual message type, issuer, status and correlation. Depending on the binding, signature evidence can be carried differently; absence of one XML element is not a complete validation result.

![Historical HTTP inspector showing the SAMLResponse field with its encoded contents removed](assets/AD%20FS%20Logout%20Explained%20-%20Application%20Sessions,%20Federation%20Cookies%20and%20Single%20Logout/capture-02.png)

### Application logout versus a redirect to an IdP page

The historical Shibboleth test page exposes application session context and different logout links. The important distinction is the application's logout handler and its resulting session state, not the destination page's appearance. The visible lab hostnames are examples, not configuration values to reuse.

![Historical application session and logout test page with session and message values removed](assets/AD%20FS%20Logout%20Explained%20-%20Application%20Sessions,%20Federation%20Cookies%20and%20Single%20Logout/capture-05.png)

## 4. Verify logout with two applications

1. Establish a known session in applications A and B in the same browser profile.
2. Initiate logout through A's supported handler and record the protocol exchange without publishing tokens/cookies.
3. Verify that A no longer accepts its previous session, then test whether B processed the expected logout notification.
4. Compare AD FS sign-out with a new visit: seamless Windows authentication or a retained upstream session can create a new login immediately.
5. Test an already-issued API token separately according to the API's validation/revocation model. Do not infer its status from browser cookies.

Use a fresh navigation or server request rather than only the Back button or a cached page. Browser restrictions, unreachable participant endpoints and application exceptions can leave a partially completed logout. Preserve failed responses and correlation data privately.

## 5. Common misreadings

| Observation | Better interpretation |
|---|---|
| The AD FS logout page appears | The browser reached a page; check application cleanup and the actual exchange |
| The next visit signs in without a password prompt | A new authentication may have occurred through WIA or another existing session |
| One RP signed out, another did not | Check participation, logout support, endpoint reachability and local cleanup |
| A service still accepts an access token | Browser logout is not proof of token revocation |

## References

- [Microsoft: single log-out for OpenID Connect with AD FS](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-logout-openid-connect)
- [Microsoft: AD FS OpenID Connect and OAuth concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-openid-connect-oauth-concepts)
- [OpenID Foundation: RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OASIS: SAML 2.0 Profiles, Single Logout Profile](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [OASIS: WS-Federation 1.2](https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html)