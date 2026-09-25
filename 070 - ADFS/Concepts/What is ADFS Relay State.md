---
title: "Understanding RelayState in ADFS (IDP Initiated Sign-On)"
date: 2025-04-08
---

## Definition

AD FS supports several federation and authorization protocols. This article focuses specifically on **SAML RelayState** and AD FS IdP-initiated SAML launch URLs, not OAuth/OIDC or every AD FS redirect.

**RelayState** is state carried alongside a SAML protocol message. The application may use it as an opaque reference to a requested resource or its own saved request context. It is not necessarily a URL, is not a claim inside the assertion, and is not a trusted authorization decision.

The receiving application must validate/resolve that state. Treating arbitrary RelayState as an unrestricted redirect destination can create an open redirect. Keep its size within the applicable binding/client limits; the SAML HTTP bindings specify an 80-byte limit for RelayState.

---

## IDP Initiated Sign-On vs SP Initiated Sign-On

In an **SP-initiated login**, the application creates the authentication request and can retain a correlation/state record before redirecting the browser to the identity provider.

In an **IdP-initiated login**, the launch starts at the identity provider without an application-generated AuthnRequest for that exchange. The RP must support and accept that unsolicited-response scenario. Do not assume that an application requiring request correlation can be made compatible merely by adding a landing-page URL.

RelayState can convey the application's expected landing-state value, but choosing the upstream identity provider through Home Realm Discovery (HRD) is a different decision.

---

## RelayState Structure

The SAML standard does **not** define every RelayState value as a two-part AD FS structure. Distinguish the opaque value delivered to the RP from the AD FS IdP-initiated launch convention:

| Layer | Contents |
|---|---|
| Application's SAML RelayState | The opaque value the application understands, for example a short server-side state reference or allowed relative destination |
| AD FS launch payload | `RPID=<encoded relying-party identifier>&RelayState=<encoded application state>` |
| Browser launch URL | The entire payload is URL-encoded as the outer `RelayState` query parameter |

`RPID` must match the intended configured relying-party identifier. It is not necessarily the ACS URL. `NR` is not a universal second component of SAML RelayState, and a chain of federation services does not give every intermediary the same state contract.

WS-Federation uses its own parameters, including `wctx` for requestor context. OAuth/OIDC uses `state` for request/response correlation. These are related application concerns, not interchangeable parameter names.

See [AD FS Authentication Flows](AD%20FS%20Authentication%20Flows%20-%20Trusts,%20Identifiers,%20Metadata%20and%20Endpoints.md) for the separate issuer, RP identifier, callback and HRD roles.

---

## Common Use Cases

- A portal launches a specific SAML RP that supports IdP-initiated sign-in.
- An RP uses a short state value to recover its intended application destination.
- A test distinguishes RP selection from application-state handling without changing either trust's issuer identity.

UPN-based routing to an identity provider and HRD are not, by themselves, examples of RelayState processing.

---

## Demo Behavior

The AD FS IdP-initiated page may intentionally be disabled. Check the actual farm setting:

```powershell
Get-AdfsProperties -ErrorAction Stop |
	Select-Object EnableIdpInitiatedSignonPage
```

Verify the supported RelayState behavior/configuration for the farm version and the RP's ability to accept IdP-initiated SAML responses. Do not apply AD FS 2.0 web.config edits to a current Windows Server 2022/2025 deployment or enable a page solely because an old screenshot uses it.

Visiting the page without selecting an RP can demonstrate authentication to AD FS; it is not an end-to-end application sign-in test. Prefer the application's normal SP-initiated path when that is its supported entry point.

---

## URL Generator Tool

No external generator is required. Encode the two inner values, then encode the complete AD FS payload once for the outer query string:

```powershell
function New-AdfsIdpInitiatedSamlUrl {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][uri]$FederationOrigin,
		[Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RelyingPartyIdentifier,
		[Parameter(Mandatory)][AllowEmptyString()][string]$RelayState
	)

	if (-not $FederationOrigin.IsAbsoluteUri -or $FederationOrigin.Scheme -ne 'https' -or
		$FederationOrigin.AbsolutePath -ne '/' -or $FederationOrigin.Query -or
		$FederationOrigin.Fragment -or $FederationOrigin.UserInfo) {
		throw 'Provide only the trusted HTTPS federation origin, without credentials, path, query or fragment.'
	}
	if ([Text.Encoding]::UTF8.GetByteCount($RelayState) -gt 80) {
		throw 'Use an application-owned short state reference instead of exceeding the SAML binding limit.'
	}

	$payload = 'RPID={0}&RelayState={1}' -f
		[uri]::EscapeDataString($RelyingPartyIdentifier),
		[uri]::EscapeDataString($RelayState)

	'{0}/adfs/ls/idpinitiatedsignon.aspx?RelayState={1}' -f
		$FederationOrigin.GetLeftPart([UriPartial]::Authority),
		[uri]::EscapeDataString($payload)
}

New-AdfsIdpInitiatedSamlUrl -FederationOrigin 'https://fs.corp.example' `
	-RelyingPartyIdentifier 'urn:corp:applications:portal' -RelayState '/reports'
```

This constructs a URL only. It does not create a trust, enable a feature, authenticate a user or prove that the RP accepts the state. Do not feed it tokens, cookies or secret values.

Use the original unencoded inputs. Pre-encoding the values before passing them to the function adds an unwanted encoding layer. Verify at the RP that its received state matches the original application value and that unexpected destinations are rejected.

### Historical generator capture

The existing capture is retained to illustrate the two encoding layers. The retired CodePlex utility and its AD FS 2.0-era compatibility guidance are not installation recommendations for current servers.

![Historical AD FS RelayState generator showing RP selection and nested URL encoding](<./assets/What is ADFS Relay State/2025-04-08-16-34-55.png>)

## References

- [Microsoft: troubleshoot the AD FS IdP-initiated sign-in page](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-initiatedsignon)
- [OASIS: SAML 2.0 Bindings and RelayState](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)

