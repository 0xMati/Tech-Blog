# OIDC Custom Claims Automation in Entra ID
🗓️ Published: 2026-04-20

## Introduction

When you integrate an application using OpenID Connect (OIDC) in Microsoft Entra ID, the tokens issued by default contain a limited set of claims. Often, applications need **additional information** in the ID token or access token — things like the user's email, UPN, groups, or even custom attributes.

Entra ID provides two distinct mechanisms for adding claims to OIDC tokens:
- **Optional Claims** via the App Registration (Token Configuration)
- **Claims Mapping** via the Enterprise Application (OIDC-Based Sign-On)

While the Azure portal makes it straightforward to configure these manually, many organizations need to **automate** this process — whether for repeatable deployments, CI/CD pipelines, or managing dozens of app registrations at scale.

In this article, we'll cover:
✅ The difference between Optional Claims and Claims Mapping
✅ Security requirements (custom signing keys vs. acceptMappedClaims)
✅ A complete PowerShell script to automate everything

---

## Two Mechanisms, Two Purposes

Entra ID offers two separate places to customize token claims. They serve different needs and operate on different objects.

### Optional Claims (App Registration)

📍 **Where**: App Registration → Token Configuration
📦 **API Object**: `optionalClaims` on the **Application** object

This is the standard way to add **predefined claims** from the Entra ID schema into your tokens.

You can choose claims for:
- **ID Token** — used during sign-in (OIDC)
- **Access Token** — used to call APIs
- **SAML Token** — used for SAML-based SSO

Common optional claims:

| Claim | Description |
|---|---|
| `email` | User's email address |
| `upn` | User Principal Name |
| `given_name` | First name |
| `family_name` | Last name |
| `preferred_username` | Preferred username |
| `groups` | Group memberships (max 200 in JWT) |
| `sid` | Session ID |
| `auth_time` | Time of authentication |
| `acct` | Account status (0 = member, 1 = guest) |
| `ipaddr` | Client IP address |

**Limitation**: You can only choose from Microsoft's predefined list — no custom mapping or transformations.

### Claims Mapping (Enterprise Application)

📍 **Where**: Enterprise Application → Single Sign-On → Attributes & Claims
📦 **API Object**: `ClaimsMappingPolicy` on the **Service Principal**

This is the advanced mechanism that allows:
- 🔄 **Renaming** a claim in the token (e.g., send `user.userprincipalname` as `custom_id`)
- 🧩 **Mapping custom attributes** (extension attributes, directory custom attributes)
- ⚙️ **Applying transformations** (regex, concatenation, conditions, Extract, ToUpper, etc.)
- 📌 **Adding constant values**
- 🎯 **Conditional claims** based on user type or group membership

**Important**: Originally designed for SAML, this mechanism now **also supports OIDC/JWT tokens**.

### Comparison

| | **Optional Claims** | **Claims Mapping** |
|---|---|---|
| **Configured on** | Application (App Registration) | Service Principal (Enterprise App) |
| **Flexibility** | Predefined list only | Any user attribute, transformations, conditions |
| **API** | `Update-MgApplication -OptionalClaims` | `New-MgPolicyClaimsMappingPolicy` |
| **Security requirement** | None | Custom signing key or `acceptMappedClaims` |
| **Conflict resolution** | — | Claims Mapping takes priority |

> ⚠️ If the same claim is defined in both places, the **Claims Mapping Policy wins**.

---

## Security Requirements for Claims Mapping

When you customize claims via Claims Mapping, Entra ID requires you to prove that the application is **aware** that its tokens may contain modified claims. This prevents malicious actors from altering token content without the app's knowledge.

There are **two options** — they are **mutually exclusive**.

### Option 1: Custom Signing Key (Recommended)

The token is signed with a **certificate specific to your application** instead of Entra ID's global signing key. The application must validate the token using this dedicated key.

**How it works**:
1. Generate or obtain a certificate (self-signed is fine for testing)
2. Upload the private key (Sign) + public key (Verify) to the Application object
3. The application validates the token via the metadata endpoint with `?appid={client-id}`

**Token validation URL**:
```
https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration?appid={client-id}
```

**When to use**: ✅ Multi-tenant apps (mandatory), ✅ Production workloads

### Option 2: acceptMappedClaims (Simple)

Set the `acceptMappedClaims` property to `true` in the application manifest. This tells Entra ID that the app agrees to receive mapped claims without a custom signing key.

**When to use**: ✅ Single-tenant apps only, ✅ Dev/test environments

**Limitations**:
- ❌ **Cannot be used with multi-tenant apps** (security risk)
- The token audience must use a **verified domain** of your tenant
- Otherwise you get error `AADSTS501461`

### Comparison

| | Custom Signing Key | acceptMappedClaims |
|---|---|---|
| **Multi-tenant** | ✅ Required | ❌ Forbidden |
| **Single-tenant** | ✅ Recommended | ✅ Possible |
| **Configuration** | PowerShell / Graph API (certificate) | One property in manifest |
| **Complexity** | Medium (certificate lifecycle) | Very simple |
| **Security** | Higher | Acceptable |

---

## The Enterprise Application Mystery

A common gotcha when automating Entra ID with PowerShell or Graph API: **creating an App Registration does NOT automatically create the Enterprise Application** (Service Principal).

In the Azure portal, when you create an App Registration, the Service Principal is created silently behind the scenes. But with Graph API / PowerShell, these are **two separate operations**:

```
App Registration  ──────►  POST /applications
                              (Application object)

Enterprise App    ──────►  POST /servicePrincipals
                              (Service Principal object)
```

If you forget to create the Service Principal, you won't have an Enterprise Application, and you won't be able to:
- Assign users or groups
- Configure Claims Mapping
- See the app in "Enterprise Applications" in the portal

The automation script below handles this with a `-CreateEnterpriseApp` switch.

---

## Automation Script

The PowerShell script `Set-OidcOptionalClaims.ps1` (included in this folder) automates the full lifecycle:

### Features

| Feature | Parameter |
|---|---|
| Create a new App Registration | `-AppDisplayName` (without `-AppObjectId`) |
| Update an existing App Registration | `-AppObjectId` |
| Configure optional claims (ID Token) | `-IdTokenClaims` |
| Configure optional claims (Access Token) | `-AccessTokenClaims` |
| Set redirect URI (Web or SPA) | `-RedirectUri`, `-WebApp` |
| Create the Enterprise Application | `-CreateEnterpriseApp` |
| Enable acceptMappedClaims | `-AcceptMappedClaims` |
| Configure custom signing certificate | `-CustomSigningCertPfxPath`, `-CustomSigningCertCerPath`, `-CustomSigningCertPassword` |
| Configure Claims Mapping Policy | `-ClaimsMappingSchema` |

### Prerequisites

```powershell
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
```

### Usage Examples

#### New app with optional claims + Enterprise Application

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "MyWeatherApp" `
    -RedirectUri "https://myapp.contoso.com/callback" `
    -WebApp `
    -CreateEnterpriseApp `
    -IdTokenClaims "email","upn","given_name","family_name","groups" `
    -AccessTokenClaims "email","groups"
```

#### Update an existing app with custom claims

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "MyWeatherApp" `
    -AppObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IdTokenClaims "email","upn","groups","sid" `
    -AccessTokenClaims "email","groups"
```

#### Claims Mapping with acceptMappedClaims (mono-tenant, simple)

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "MyWeatherApp" `
    -AppObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -CreateEnterpriseApp `
    -AcceptMappedClaims `
    -ClaimsMappingSchema @(
        @{ Source="user"; ID="userprincipalname"; JwtClaimType="custom_id" },
        @{ Source="user"; ID="mail"; JwtClaimType="email" }
    )
```

#### Claims Mapping with custom signing certificate (multi-tenant, secure)

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "MyWeatherApp" `
    -AppObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -CreateEnterpriseApp `
    -CustomSigningCertPfxPath "C:\certs\myapp.pfx" `
    -CustomSigningCertCerPath "C:\certs\myapp.cer" `
    -CustomSigningCertPassword "MyPassword" `
    -ClaimsMappingSchema @(
        @{ Source="user"; ID="userprincipalname"; JwtClaimType="custom_id" },
        @{ Source="user"; ID="groups"; JwtClaimType="groups" }
    )
```

#### Full creation with everything

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "MonApp" `
    -RedirectUri "https://monapp.contoso.com/callback" `
    -WebApp `
    -CreateEnterpriseApp `
    -IdTokenClaims "email","upn","given_name","family_name","groups" `
    -AccessTokenClaims "email","groups" `
    -AcceptMappedClaims `
    -ClaimsMappingSchema @(
        @{ Source="user"; ID="userprincipalname"; JwtClaimType="custom_id" },
        @{ Source="user"; ID="groups"; JwtClaimType="groups" }
    )
```

---

## How It Works Under the Hood

Here's the flow the script follows:

```
    ┌──────────────────────────────────────────────────┐
    │                  PARAMETERS                      │
    │  AppDisplayName, Claims, Security Options, etc.  │
    └──────────────────────┬───────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │            CONNECT TO MICROSOFT GRAPH            │
    │     Scopes: Application.ReadWrite.All            │
    │             Directory.ReadWrite.All (if SP)      │
    │             Policy.ReadWrite.AppConfig (if CMP)  │
    └──────────────────────┬───────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌──────────────────┐     ┌──────────────────────┐
    │  NEW APP         │     │  EXISTING APP        │
    │  New-MgApp       │     │  Update-MgApp        │
    │  + Graph perms   │     │  (OptionalClaims)    │
    └────────┬─────────┘     └──────────┬───────────┘
             │                          │
             └────────────┬─────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────────────┐
    │          SERVICE PRINCIPAL (if requested)         │
    │   Check if exists → Create if missing            │
    └──────────────────────┬───────────────────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌──────────────────┐     ┌──────────────────────┐
    │  OPTION 2        │     │  OPTION 1            │
    │  acceptMapped    │     │  Custom Signing Key  │
    │  Claims = true   │     │  (PFX + CER)         │
    └────────┬─────────┘     └──────────┬───────────┘
             │                          │
             └────────────┬─────────────┘
                          │
                          ▼
    ┌──────────────────────────────────────────────────┐
    │          CLAIMS MAPPING POLICY (if schema)       │
    │   Remove old policies → Create new → Assign SP  │
    └──────────────────────┬───────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │                   RESULT OUTPUT                  │
    │     App info, claims configured, security mode   │
    └──────────────────────────────────────────────────┘
```

---

## Available Claim Transformations (Enterprise App)

When using Claims Mapping via the Enterprise Application portal or API, you can apply transformations:

| Transformation | Description |
|---|---|
| `ExtractMailPrefix()` | Extracts the part before `@` from an email or UPN |
| `ToLower()` / `ToUpper()` | Case conversion |
| `Join()` | Concatenates two attributes with an optional separator |
| `Substring()` | Extracts a substring (fixed length or end of string) |
| `Contains()` | Outputs a value if input contains a specified string |
| `StartWith()` / `EndWith()` | Conditional output based on prefix/suffix |
| `IfEmpty()` / `IfNotEmpty()` | Fallback logic when an attribute is null |
| `Extract() - Before/After/Between` | Extract parts of a string around a delimiter |
| `ExtractAlpha()` / `ExtractNumeric()` | Extract alphabetic or numeric prefix/suffix |
| `RegexReplace()` | Full regex-based transformation (up to 20 replacements) |

---

## Key Takeaways

| Need | Where to configure | Automation |
|---|---|---|
| Standard claims (email, upn, groups…) | App Registration → Token Configuration | `Update-MgApplication -OptionalClaims` |
| Custom mapping / transformations | Enterprise App → Attributes & Claims | `New-MgPolicyClaimsMappingPolicy` |
| Both at once | Possible — Claims Mapping wins on conflicts | The script handles both |
| Security for Claims Mapping | Custom signing key (multi-tenant) or `acceptMappedClaims` (single-tenant) | Both options in the script |
| Enterprise Application missing | Always create the Service Principal explicitly | `-CreateEnterpriseApp` switch |

---

## References

- [Customize claims issued in the JWT for enterprise applications](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization)
- [Optional claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
- [Configure a custom signing key](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization#configure-a-custom-signing-key)
- [Microsoft Graph: Update application - optionalClaims](https://learn.microsoft.com/en-us/graph/api/application-update)
- [Microsoft Graph: claimsMappingPolicy](https://learn.microsoft.com/en-us/graph/api/resources/claimsmappingpolicy)
