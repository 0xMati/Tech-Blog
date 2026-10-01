---
title: "AD FS Extended Protection and Channel Binding"
date: 2026-10-01
---

# AD FS Extended Protection and Channel Binding

**TLS protects a connection. Extended Protection also checks how authentication is bound to it.**

An integrated-authentication exchange can be valid in isolation yet arrive through an unintended intermediary. Extended Protection for Authentication (EPA) adds binding checks that help prevent relaying that authentication to another endpoint.

## 1. What a Channel Binding Token does

With Windows authentication over HTTPS, there are two relevant layers: the outer TLS protection and the inner authentication exchange, such as Kerberos or NTLM. A **Channel Binding Token (CBT)** supplies information about the outer channel to the authentication mechanism. A compatible server checks that information against what it expects.

```text
Client -- TLS + Windows authentication bound to that TLS endpoint --> Server

Client -- TLS endpoint A --> Intermediary -- TLS endpoint B --> Server
          binding seen by client              binding seen by server
```

If an intermediary substitutes a different TLS endpoint, the binding information can differ. Rejecting that exchange can be the protection working, not a reason to turn it off.

The exact binding depends on the authentication/TLS implementation; do not describe every CBT as a unique TLS session key. It is not the server's private key and not the user's password. Kerberos/NTLM relay does not require recovering a plaintext password, and disabling EPA does not itself make all HTTPS payloads readable.

EPA is one layer. It does not replace correct SPNs, TLS name/chain validation, current clients, application authorization or protection of tokens after issuance.

## 2. Read the AD FS setting, not a generic framework label

`ExtendedProtectionTokenCheck` is a farm-level AD FS property. The AD FS cmdlet reference defines these values:

| Value | Meaning |
|---|---|
| `Require` | Enforce extended protection; incompatible clients/paths can fail |
| `Allow` | Apply extended protection where supported, retaining compatibility for clients without it |
| `None` | Do not enforce extended protection |

The cmdlet documentation describes `Allow` as the default. That is not evidence of the current setting in an upgraded or customized farm. Generic WCF descriptions using "Partial" and "Full" are explanatory terms, not the AD FS parameter values to paste into a command.

On an AD FS administration host, this Windows PowerShell 5.1 inventory distinguishes an unavailable property from a real `$false` value:

```powershell
Import-Module ADFS -ErrorAction Stop
$properties = Get-AdfsProperties -ErrorAction Stop
foreach ($settingName in @('ExtendedProtectionTokenCheck', 'IgnoreTokenBinding')) {
    $settingProperty = $properties.PSObject.Properties[$settingName]
    [pscustomobject]@{
        Setting = $settingName
        Exposed = $null -ne $settingProperty
        Value = if ($null -eq $settingProperty) { '<not exposed>' } else { $settingProperty.Value }
    }
}
```

This does not change policy or establish that the client actually used channel binding. Correlate the effective setting with the authentication path and events.

## 3. Why TLS intermediaries and certificate changes matter

| Path | Diagnostic consequence |
|---|---|
| Direct intranet WIA | Check browser capability, service identity and the actual AD FS TLS endpoint |
| HTTPS inspection/debugging proxy | The client can see the interceptor's certificate instead of the federation certificate |
| Load balancer terminating federation TLS | AD FS requirements explicitly do not support TLS termination at the load balancer |
| WAP proxying federation authentication | Follow the AD FS/WAP certificate requirements, not generic reverse-proxy assumptions |
| Recent certificate renewal | Compare actual bindings on every participating node, not only a console certificate record |

Microsoft's AD FS requirements state that WAP and the federation servers must use the **same TLS certificate and key** when proxying WIA or when `ExtendedProtectionTokenCheck` is enabled. A newly issued certificate with the same hostname is not necessarily the same certificate/key.

WAP is a supported federation-aware proxy; its requirements do not authorize arbitrary TLS offload elsewhere. Use the [TLS certificate replacement guide](../How-to/ADFS%20and%20WAP%20-%20Replace%20SSL%20Certificate.md) to inspect the intended rollout, and the [WAP trust guide](../Troubleshoot/WAP%20trust%20to%20ADFS%20broken.md) to distinguish TLS identity from proxy-trust credentials.

## 4. Token Binding is a different feature

| Mechanism | What it addresses |
|---|---|
| EPA/CBT | Binding compatible authentication exchanges to their transport context |
| HTTP Token Binding | A separate protocol using client key possession to bind tokens to a client/TLS context |
| SAML/JWT signature | Integrity and issuer authenticity, subject to the recipient's actual validation |
| TLS client certificate authentication | Proof involving a client certificate and private key, plus mapping/policy |
| Cloud token-protection policy | Product-specific protection and supported-client requirements; not an AD FS EPA setting |

Historical AD FS 2016 notes describe Token Binding interoperability problems on specific Windows/browser/inspection combinations and changing `IgnoreTokenBinding`. That property is separate from `ExtendedProtectionTokenCheck`. Neither a 2016 workaround nor the presence of the parameter proves that a current browser negotiates HTTP Token Binding.

Capture the exact OS/browser/server builds, negotiated behavior and intermediary involved before attributing a failure to it. Do not set `IgnoreTokenBinding` to true across the farm merely because a sign-in fails after an HTTPS inspection change.

## 5. Diagnose without weakening the baseline first

1. Confirm the actual authentication method. A `Negotiate` header alone does not prove Kerberos or successful CBT validation.
2. Compare a working and failing client on the same intended path. Record certificate identity, node, time and correlation information.
3. Identify every TLS endpoint and intermediary. A direct-path comparison must retain the federation hostname, SNI and certificate validation.
4. Inspect AD FS/WAP errors and the installed version's relevant settings. A generic 401 is not uniquely an EPA error.
5. Correct a demonstrated certificate, client, routing or unsupported-termination problem, then repeat the original transaction.

If a narrowly scoped support investigation requires a temporary setting change, retain the exact before-state, document the farm-wide protection impact and restore it after the discriminating test. A successful sign-in with protection disabled is evidence about compatibility, not proof of a satisfactory final configuration.

For collection technique, see [HTTP traces](../Troubleshoot/AD%20FS%20HTTP%20Traces%20-%20Capture,%20Read%20and%20Redact.md) and [WIA browser behavior](../Troubleshoot/AD%20FS%20WIA%20-%20Browser%20Configuration%20and%20Forms%20Fallback.md). This note does not prescribe a universal `Require` rollout or a disable-and-retry repair.

## References

- [Microsoft Learn: Extended Protection for Authentication overview](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/extended-protection-for-authentication-overview)
- [Microsoft Learn: Set-AdfsProperties, ExtendedProtectionTokenCheck and IgnoreTokenBinding](https://learn.microsoft.com/en-us/powershell/module/adfs/set-adfsproperties?view=windowsserver2025-ps)
- [Microsoft Learn: AD FS requirements, TLS certificates and load balancers](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-requirements)
- [RFC 8471: The Token Binding Protocol Version 1.0](https://www.rfc-editor.org/rfc/rfc8471)