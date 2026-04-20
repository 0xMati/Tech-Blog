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
✅ Common automation pitfalls and how to avoid them
✅ A complete PowerShell script to automate everything
✅ How to manage Claims Mapping Policies after deployment

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
| **API** | `Update-MgApplication -OptionalClaims` | `New-MgPolicyClaimMappingPolicy` |
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

## Automation Pitfalls

When automating Entra ID app provisioning with PowerShell or Graph API, several gotchas can trip you up. These are all behaviors that differ from the portal experience.

### The Missing Enterprise Application

Creating an App Registration via Graph API does **NOT** automatically create the Enterprise Application (Service Principal). In the Azure portal, both are created together behind the scenes, but with the API these are **two separate operations**:

```
App Registration  ──────►  POST /applications
                              (Application object)

Enterprise App    ──────►  POST /servicePrincipals
                              (Service Principal object)
```

If you forget to create the Service Principal, you won't be able to:
- Assign users or groups
- Configure Claims Mapping
- See the app in "Enterprise Applications" in the portal

The automation script handles this with a `-CreateEnterpriseApp` switch.

### The Visibility Tag

Even after creating the Service Principal via PowerShell, the Enterprise Application may **not appear** in the portal's default list — you can only find it by searching its Object ID.

This is because the portal filters the list to show only apps tagged with `WindowsAzureActiveDirectoryIntegratedApp`. The portal adds this tag automatically; PowerShell does **not**.

The fix is to include the tag at creation time:

```powershell
New-MgServicePrincipal -AppId $app.AppId -Tags @("WindowsAzureActiveDirectoryIntegratedApp")
```

Without this tag, the app works perfectly — it's just invisible in the default filtered view. The automation script includes this tag automatically.

### Microsoft Graph SDK Naming Inconsistencies

The Microsoft Graph PowerShell SDK has inconsistent naming for Claims Mapping cmdlets. This can cause `CommandNotFoundException` errors if you guess the names:

| Element | Convention | Example |
|---|---|---|
| **Cmdlet name** | Singular `ClaimMapping` (no 's') | `New-MgPolicyClaimMappingPolicy` |
| **Parameter name** | Plural `ClaimsMapping` (with 's') | `-ClaimsMappingPolicyId` |
| **Exception** | `Remove-MgServicePrincipalClaimMappingPolicyByRef` | Uses `-ClaimMappingPolicyId` (no 's') |

> 💡 Always verify cmdlet signatures with `Get-Command <cmdlet> -Syntax` before using them.

**Required modules**:
- `Microsoft.Graph.Applications` — for app registration and service principal management
- `Microsoft.Graph.Identity.SignIns` — for claims mapping policy cmdlets

---

## Portal vs. PowerShell: Managing Claims Mapping

The Azure portal and PowerShell are **mutually exclusive** when it comes to editing Claims Mapping. Understanding this is critical before choosing your approach.

### The "Overwritten by a Claim Mapping Policy" Message

When a Claims Mapping Policy has been applied via Graph API or PowerShell, the Enterprise Application's **Attributes & Claims** panel displays a warning:

> *"This configuration was overwritten by a claim mapping policy created via Graph/PowerShell"*

This is **normal and expected**. The claims are correctly configured — the portal simply cannot display or edit them visually because they come from an external policy object.

### How It Works

| Mode | Editable in the portal | Automatable |
|---|---|---|
| **Portal** creates the claims config | ✅ Yes | ❌ No |
| **PowerShell/Graph** creates a ClaimsMappingPolicy | ❌ No | ✅ Yes |

### Three Practical Strategies

#### Strategy 1: Full PowerShell (recommended for mass deployment)

The script manages everything. The portal is read-only for claims. To modify claims later, rerun the script with an updated `-ClaimsMappingSchema`. Best for organizations deploying many apps or managing claims in a CI/CD pipeline.

#### Strategy 2: Hybrid — Script for Setup, Portal for Claims Mapping

Use the script **without** the `-ClaimsMappingSchema` parameter. The script creates the App Registration, Enterprise Application, optional claims, and security settings (`-AcceptMappedClaims` or custom signing key). Then configure the claims mapping **manually** in the portal under Enterprise App → Attributes & Claims. Since no PowerShell policy exists, the portal remains fully editable.

```powershell
# Example: script sets up everything EXCEPT claims mapping
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "XX-MyTestApp" `
    -RedirectUri "https://xx-mytestapp.contoso.com/callback" `
    -WebApp `
    -CreateEnterpriseApp `
    -IdTokenClaims "email","upn","given_name","family_name","groups" `
    -AccessTokenClaims "email","groups" `
    -AcceptMappedClaims
# Then: configure claims mapping manually in the portal
```

Best for: deploy once, then let admins manage claims visually.

#### Strategy 3: Reclaim Portal Control

If a PowerShell policy already exists and you want to switch back to portal editing:
1. Go to Enterprise App → Single Sign-On → Attributes & Claims
2. The portal will offer to **delete** the external policy and replace it with its own configuration
3. Once done, the portal becomes editable again — but the PowerShell policy is gone

> ⚠️ This is a **one-way operation**. The PowerShell policy will be deleted. If you need to go back to automation later, you'll have to recreate it.

---

## The Automation Script

The PowerShell script `Set-OidcOptionalClaims.ps1` (included in this folder) automates the full lifecycle.

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
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

### Usage Examples

#### New app with optional claims + Enterprise Application

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "XX-MyTestApp" `
    -RedirectUri "https://xx-mytestapp.contoso.com/callback" `
    -WebApp `
    -CreateEnterpriseApp `
    -IdTokenClaims "email","upn","given_name","family_name","groups" `
    -AccessTokenClaims "email","groups"
```

#### Update an existing app with custom claims

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "XX-MyTestApp" `
    -AppObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -IdTokenClaims "email","upn","groups","sid" `
    -AccessTokenClaims "email","groups"
```

#### Claims Mapping with acceptMappedClaims (mono-tenant, simple)

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "XX-MyTestApp" `
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
    -AppDisplayName "XX-MyTestApp" `
    -AppObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
    -CreateEnterpriseApp `
    -CustomSigningCertPfxPath "C:\certs\xx-mytestapp.pfx" `
    -CustomSigningCertCerPath "C:\certs\xx-mytestapp.cer" `
    -CustomSigningCertPassword "MyPassword" `
    -ClaimsMappingSchema @(
        @{ Source="user"; ID="userprincipalname"; JwtClaimType="custom_id" },
        @{ Source="user"; ID="groups"; JwtClaimType="groups" }
    )
```

#### Full creation with everything

```powershell
.\Set-OidcOptionalClaims.ps1 `
    -AppDisplayName "XX-MyTestApp" `
    -RedirectUri "https://xx-mytestapp.contoso.com/callback" `
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

### How It Works Under the Hood

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
    │   Check if exists → Create with visibility tag   │
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

## Managing Claims Mapping Policies with PowerShell

After deployment, you may need to inspect, modify, or delete the Claims Mapping Policy assigned to an application. Here are the common operations.

### Retrieve the Current Policy

```powershell
Connect-MgGraph -Scopes "Policy.Read.All", "Application.Read.All"

# Find the Service Principal (use Select-Object -First 1 to avoid array issues)
$sp = Get-MgServicePrincipal -Filter "displayName eq 'XX-MyTestApp'" | Select-Object -First 1

# Get assigned Claims Mapping Policies
$policies = Get-MgServicePrincipalClaimMappingPolicy -ServicePrincipalId $sp.Id

# Display the policy definition (JSON)
foreach ($p in $policies) {
    Write-Host "Policy ID    : $($p.Id)" -ForegroundColor Cyan
    Write-Host "Display Name : $($p.DisplayName)" -ForegroundColor Cyan
    Write-Host "Definition   :" -ForegroundColor Green
    $p.Definition | ForEach-Object { $_ | ConvertFrom-Json | ConvertTo-Json -Depth 10 }
}
```

### Modify an Existing Policy

```powershell
Connect-MgGraph -Scopes "Policy.ReadWrite.ApplicationConfiguration"

# Get the current policy
$sp = Get-MgServicePrincipal -Filter "displayName eq 'XX-MyTestApp'" | Select-Object -First 1
$policy = (Get-MgServicePrincipalClaimMappingPolicy -ServicePrincipalId $sp.Id)[0]

# Define the updated claims schema
$newDefinition = @{
    ClaimsMappingPolicy = @{
        Version              = 1
        IncludeBasicClaimSet = $true
        ClaimsSchema         = @(
            @{ Source = "user"; ID = "userprincipalname"; JwtClaimType = "custom_id" }
            @{ Source = "user"; ID = "mail";              JwtClaimType = "email" }
            @{ Source = "user"; ID = "givenname";         JwtClaimType = "first_name" }
            @{ Source = "user"; ID = "surname";           JwtClaimType = "last_name" }
        )
    }
}

# Update the policy (| Out-Null avoids a threading error on PowerShell 5.1)
Update-MgPolicyClaimMappingPolicy -ClaimsMappingPolicyId $policy.Id `
    -Definition @(($newDefinition | ConvertTo-Json -Depth 10 -Compress)) | Out-Null

Write-Host "Policy updated." -ForegroundColor Green
```

### Delete a Policy and Unassign It

```powershell
$sp = Get-MgServicePrincipal -Filter "displayName eq 'XX-MyTestApp'" | Select-Object -First 1
$policies = Get-MgServicePrincipalClaimMappingPolicy -ServicePrincipalId $sp.Id

foreach ($p in $policies) {
    # Unassign from the Service Principal
    Remove-MgServicePrincipalClaimMappingPolicyByRef -ServicePrincipalId $sp.Id -ClaimMappingPolicyId $p.Id
    # Delete the policy object
    Remove-MgPolicyClaimMappingPolicy -ClaimsMappingPolicyId $p.Id
    Write-Host "Removed and deleted policy $($p.Id)" -ForegroundColor Yellow
}
```

> 💡 After deleting the policy via PowerShell, the portal's Attributes & Claims panel becomes editable again.

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
| Custom mapping / transformations | Enterprise App → Attributes & Claims | `New-MgPolicyClaimMappingPolicy` |
| Both at once | Possible — Claims Mapping wins on conflicts | The script handles both |
| Security for Claims Mapping | Custom signing key (multi-tenant) or `acceptMappedClaims` (single-tenant) | Both options in the script |
| Enterprise Application missing | Always create the Service Principal explicitly | `-CreateEnterpriseApp` switch |
| Portal editing after PowerShell | Delete the policy first, or use hybrid strategy | See "Portal vs. PowerShell" section |

---

## References

- [Customize claims issued in the JWT for enterprise applications](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization)
- [Optional claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
- [Configure a custom signing key](https://learn.microsoft.com/en-us/entra/identity-platform/jwt-claims-customization#configure-a-custom-signing-key)
- [Microsoft Graph: Update application - optionalClaims](https://learn.microsoft.com/en-us/graph/api/application-update)
- [Microsoft Graph: claimsMappingPolicy](https://learn.microsoft.com/en-us/graph/api/resources/claimsmappingpolicy)
