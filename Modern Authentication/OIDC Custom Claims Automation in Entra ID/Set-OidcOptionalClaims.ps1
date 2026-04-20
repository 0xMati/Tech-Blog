#Requires -Modules Microsoft.Graph.Applications
#Requires -Modules Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Automates OIDC optional claims, claims mapping, and security configuration for Entra ID applications.

.DESCRIPTION
    This script can:
    - Create a new App Registration or update an existing one
    - Configure optional claims (ID Token and Access Token)
    - Create the Enterprise Application (Service Principal) if missing
    - Enable acceptMappedClaims (single-tenant only) or configure a custom signing certificate
    - Create and assign a Claims Mapping Policy on the Service Principal

.EXAMPLE
    # New app with optional claims + Enterprise App
    .\Set-OidcOptionalClaims.ps1 -AppDisplayName "XX-MyTestApp" -RedirectUri "https://xx-mytestapp.contoso.com/callback" -WebApp -CreateEnterpriseApp

.EXAMPLE
    # Existing app with claims mapping + acceptMappedClaims
    .\Set-OidcOptionalClaims.ps1 -AppDisplayName "XX-MyTestApp" -AppObjectId "xxx" -CreateEnterpriseApp -AcceptMappedClaims `
        -ClaimsMappingSchema @(@{Source="user"; ID="userprincipalname"; JwtClaimType="custom_id"})

.EXAMPLE
    # Existing app with claims mapping + custom signing certificate
    .\Set-OidcOptionalClaims.ps1 -AppDisplayName "XX-MyTestApp" -AppObjectId "xxx" -CreateEnterpriseApp `
        -CustomSigningCertPfxPath "C:\certs\xx-mytestapp.pfx" -CustomSigningCertCerPath "C:\certs\xx-mytestapp.cer" -CustomSigningCertPassword "pwd" `
        -ClaimsMappingSchema @(@{Source="user"; ID="userprincipalname"; JwtClaimType="custom_id"})
#>

param(
    [Parameter(Mandatory)]
    [string]$AppDisplayName,

    [string]$AppObjectId,

    [string[]]$IdTokenClaims     = @("email", "upn", "given_name", "family_name"),
    [string[]]$AccessTokenClaims = @("email"),

    [string]$RedirectUri,
    [switch]$WebApp,
    [switch]$CreateEnterpriseApp,

    # --- Claims Mapping (Enterprise App) ---
    [hashtable[]]$ClaimsMappingSchema,
    # Ex: @(@{Source="user"; ID="userprincipalname"; JwtClaimType="custom_id"}, @{Source="user"; ID="mail"; JwtClaimType="email"})

    # --- Security: choose ONE of the two options ---
    [switch]$AcceptMappedClaims,          # Option 2: simple, single-tenant only
    [string]$CustomSigningCertPfxPath,    # Option 1: path to .pfx file
    [string]$CustomSigningCertCerPath,    # Option 1: path to .cer file
    [string]$CustomSigningCertPassword    # Option 1: password for the .pfx
)

# ============================================================
# Import modules
# ============================================================
Import-Module Microsoft.Graph.Applications -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop

# ============================================================
# Validations
# ============================================================
if ($AcceptMappedClaims -and $CustomSigningCertPfxPath) {
    Write-Error "Choose -AcceptMappedClaims OR -CustomSigningCert*, not both. They are mutually exclusive."
    return
}

if ($CustomSigningCertPfxPath -and (-not $CustomSigningCertCerPath -or -not $CustomSigningCertPassword)) {
    Write-Error "For custom signing key, provide all three: -CustomSigningCertPfxPath, -CustomSigningCertCerPath and -CustomSigningCertPassword."
    return
}

# ============================================================
# Connection
# ============================================================
$scopes = @("Application.ReadWrite.All")
if ($CreateEnterpriseApp -or $ClaimsMappingSchema) { $scopes += "Directory.ReadWrite.All" }
if ($ClaimsMappingSchema) { $scopes += "Policy.ReadWrite.ApplicationConfiguration" }
Connect-MgGraph -Scopes $scopes

# ============================================================
# Build optional claims
# ============================================================
$optionalClaims = @{
    IdToken     = $IdTokenClaims     | ForEach-Object { @{ Name = $_; Essential = $false } }
    AccessToken = $AccessTokenClaims | ForEach-Object { @{ Name = $_; Essential = $false } }
}

# ============================================================
# Create or update App Registration
# ============================================================
if ($AppObjectId) {
    Write-Host "Updating app ($AppObjectId)..." -ForegroundColor Yellow
    Update-MgApplication -ApplicationId $AppObjectId -OptionalClaims $optionalClaims
    $app = Get-MgApplication -ApplicationId $AppObjectId -Property Id, AppId, DisplayName, OptionalClaims

} else {
    Write-Host "Creating app '$AppDisplayName'..." -ForegroundColor Yellow

    $params = @{
        DisplayName    = $AppDisplayName
        SignInAudience = "AzureADMyOrg"
        OptionalClaims = $optionalClaims
    }

    if ($RedirectUri) {
        if ($WebApp) {
            $params.Web = @{
                RedirectUris          = @($RedirectUri)
                ImplicitGrantSettings = @{ EnableIdTokenIssuance = $true }
            }
        } else {
            $params.Spa = @{ RedirectUris = @($RedirectUri) }
        }
    }

    $app = New-MgApplication @params
    Write-Host "App Registration created (ObjectId: $($app.Id))" -ForegroundColor Green

    # Add delegated permissions: openid, profile, email
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $requiredScopes = @("openid", "profile", "email")
    $resourceAccess = $graphSp.Oauth2PermissionScopes |
        Where-Object { $requiredScopes -contains $_.Value } |
        ForEach-Object { @{ Id = $_.Id; Type = "Scope" } }

    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @(
        @{
            ResourceAppId  = "00000003-0000-0000-c000-000000000000"
            ResourceAccess = $resourceAccess
        }
    )
    Write-Host "Graph permissions (openid, profile, email) added." -ForegroundColor Green
    $app = Get-MgApplication -ApplicationId $app.Id -Property Id, AppId, DisplayName, OptionalClaims
}

# ============================================================
# Enterprise Application (Service Principal)
# ============================================================
$sp = $null
if ($CreateEnterpriseApp -or $ClaimsMappingSchema -or $CustomSigningCertPfxPath) {
    $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue
    if (-not $sp) {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        if ($sp) {
            Write-Host "Enterprise Application created (SP ObjectId: $($sp.Id))" -ForegroundColor Green
        } else {
            Write-Warning "Failed to create Service Principal (Enterprise Application)"
        }
    } else {
        Write-Host "Enterprise Application already exists (SP ObjectId: $($sp.Id))" -ForegroundColor Green
    }
}

# ============================================================
# Option 2: acceptMappedClaims (single-tenant only)
# ============================================================
if ($AcceptMappedClaims) {
    Write-Host "Enabling acceptMappedClaims on the app..." -ForegroundColor Yellow
    Update-MgApplication -ApplicationId $app.Id -Api @{ AcceptMappedClaims = $true }
    Write-Host "acceptMappedClaims = true configured." -ForegroundColor Green
}

# ============================================================
# Option 1: Custom signing key
# ============================================================
if ($CustomSigningCertPfxPath) {
    Write-Host "Configuring custom signing key..." -ForegroundColor Yellow

    $pfxBytes = Get-Content $CustomSigningCertPfxPath -AsByteStream -Raw
    $cerBytes = Get-Content $CustomSigningCertCerPath -AsByteStream -Raw
    $base64Pfx = [Convert]::ToBase64String($pfxBytes)
    $base64Cer = [Convert]::ToBase64String($cerBytes)

    $securePwd = ConvertTo-SecureString -String $CustomSigningCertPassword -Force -AsPlainText
    $cert = Get-PfxCertificate -FilePath $CustomSigningCertPfxPath -Password $securePwd

    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($cert.Thumbprint))
    $customKeyId = [Convert]::ToBase64String($hash)

    $guid1 = [guid]::NewGuid().ToString()
    $guid2 = [guid]::NewGuid().ToString()

    $body = @{
        keyCredentials = @(
            @{
                customKeyIdentifier = $customKeyId
                endDateTime         = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                startDateTime       = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                keyId               = $guid1
                type                = "X509CertAndPassword"
                usage               = "Sign"
                key                 = $base64Pfx
                displayName         = $cert.Subject
            },
            @{
                customKeyIdentifier = $customKeyId
                endDateTime         = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                startDateTime       = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                keyId               = $guid2
                type                = "AsymmetricX509Cert"
                usage               = "Verify"
                key                 = $base64Cer
                displayName         = $cert.Subject
            }
        )
        passwordCredentials = @(
            @{
                customKeyIdentifier = $customKeyId
                keyId               = $guid1
                endDateTime         = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                startDateTime       = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                secretText          = $CustomSigningCertPassword
            }
        )
    }

    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)" -Body $body
    Write-Host "Custom signing key configured." -ForegroundColor Green
    Write-Host "  Thumbprint : $($cert.Thumbprint)" -ForegroundColor DarkGray
    Write-Host "  Expiration : $($cert.NotAfter)" -ForegroundColor DarkGray
}

# ============================================================
# Claims Mapping Policy (Enterprise App)
# ============================================================
if ($ClaimsMappingSchema -and $sp) {
    Write-Host "Configuring Claims Mapping Policy..." -ForegroundColor Yellow

    # Remove existing policies
    $existingPolicies = Get-MgServicePrincipalClaimMappingPolicy -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
    foreach ($p in $existingPolicies) {
        Remove-MgServicePrincipalClaimMappingPolicyByRef -ServicePrincipalId $sp.Id -ClaimsMappingPolicyId $p.Id
        Remove-MgPolicyClaimsMappingPolicy -ClaimsMappingPolicyId $p.Id -ErrorAction SilentlyContinue
        Write-Host "  Removed old policy ($($p.Id))" -ForegroundColor DarkGray
    }

    # Create new policy
    $policyDefinition = @{
        ClaimsMappingPolicy = @{
            Version              = 1
            IncludeBasicClaimSet = $true
            ClaimsSchema         = $ClaimsMappingSchema
        }
    }

    $policy = New-MgPolicyClaimsMappingPolicy `
        -DisplayName "ClaimsMapping - $AppDisplayName" `
        -Definition @(($policyDefinition | ConvertTo-Json -Depth 10 -Compress))

    # Assign to Service Principal
    New-MgServicePrincipalClaimMappingPolicyByRef -ServicePrincipalId $sp.Id `
        -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/policies/claimsMappingPolicies/$($policy.Id)" }

    Write-Host "Claims Mapping Policy created and assigned." -ForegroundColor Green
    foreach ($claim in $ClaimsMappingSchema) {
        Write-Host "  $($claim.ID) -> $($claim.JwtClaimType)" -ForegroundColor DarkGray
    }
}

# ============================================================
# Result
# ============================================================
Write-Host "`n=== Result ===" -ForegroundColor Cyan
Write-Host "Display Name        : $($app.DisplayName)"
Write-Host "Object ID           : $($app.Id)"
Write-Host "App (Client) ID     : $($app.AppId)"
if ($sp) { Write-Host "SP Object ID        : $($sp.Id)" }
Write-Host "`nOptional Claims (ID Token) :" -ForegroundColor Green
$app.OptionalClaims.IdToken | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host "Optional Claims (Access Token) :" -ForegroundColor Green
$app.OptionalClaims.AccessToken | ForEach-Object { Write-Host "  - $($_.Name)" }

if ($AcceptMappedClaims) { Write-Host "`nSecurity : acceptMappedClaims = true" -ForegroundColor Yellow }
if ($CustomSigningCertPfxPath) { Write-Host "`nSecurity : Custom signing key configured" -ForegroundColor Yellow }

Disconnect-MgGraph
