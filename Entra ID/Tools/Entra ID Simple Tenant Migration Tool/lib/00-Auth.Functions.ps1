#Requires -Version 5.1

Set-StrictMode -Version Latest
$script:ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Internal Auth State
# ------------------------------------------------------------

$existing = Get-Variable -Name 'EIDMAuthState' -Scope Script -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    $script:EIDMAuthState = @{
        GraphSourceConnected = $false
        GraphTargetConnected = $false
        GraphConnectedTenant = $null
    }
}


# ------------------------------------------------------------
# Graph helpers
# ------------------------------------------------------------

function Get-EIDMGraphScopes {
    return @(
        'User.Read.All',
        'User.ReadWrite.All',
        'Group.Read.All',
        'Directory.Read.All'
    )
}

function Resolve-EIDMTenantId {
    param(
        [Parameter(Mandatory)][string]$TenantIdOrDomain
    )

    # Connect-MgGraph -TenantId accepts a GUID or tenant domain (e.g., *.onmicrosoft.com).
    # Centralized function for future validation.
    return $TenantIdOrDomain
}

function Test-EIDMGraphContextForTenant {
    param(
        [Parameter(Mandatory)][string]$ExpectedTenant
    )

    try {
        $ctx = Get-MgContext
        if (-not $ctx) { return $false }

        # Depending on module version, TenantId might be available or not.
        $tenantFromContext = $null

        if ($ctx.PSObject.Properties.Name -contains 'TenantId') {
            $tenantFromContext = $ctx.TenantId
        }
        elseif ($ctx.PSObject.Properties.Name -contains 'Tenant') {
            $tenantFromContext = $ctx.Tenant
        }

        if ([string]::IsNullOrWhiteSpace($tenantFromContext)) {
            # Fallback to our internal state (we cannot reliably read tenant from context)
            return ($script:EIDMAuthState.GraphConnectedTenant -eq $ExpectedTenant)
        }

        # If ExpectedTenant looks like GUID, compare directly.
        # If ExpectedTenant is a domain, we cannot map domain -> GUID without extra calls,
        # so we rely on our internal "GraphConnectedTenant" for that case.
        $looksGuid = ($ExpectedTenant -match '^[0-9a-fA-F-]{36}$')
        if ($looksGuid) {
            return ($tenantFromContext -eq $ExpectedTenant)
        }

        return ($script:EIDMAuthState.GraphConnectedTenant -eq $ExpectedTenant)
    }
    catch {
        return $false
    }
}

function Disconnect-EIDMGraphIfNeeded {
    try {
        $ctx = Get-MgContext
        if ($ctx) {
            Disconnect-MgGraph | Out-Null
        }
    }
    catch {
        # Ignore disconnect errors
    }

    $script:EIDMAuthState.GraphConnectedTenant = $null
}

function Connect-EIDMGraphInteractive {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string]$TenantIdOrDomain,
        [Parameter(Mandatory)][string]$SideLabel  # SOURCE / TARGET
    )

    $tenant = Resolve-EIDMTenantId -TenantIdOrDomain $TenantIdOrDomain
    $scopes = Get-EIDMGraphScopes

    Write-Host ""
    Write-Host ("Connecting to Microsoft Graph ({0} tenant: {1})..." -f $SideLabel, $tenant) -ForegroundColor Cyan
    Write-Host "An interactive sign-in window may appear. Use the correct admin account for this tenant." -ForegroundColor DarkGray

    # Force tenant context to reduce cross-tenant confusion
    Connect-MgGraph -TenantId $tenant -Scopes $scopes | Out-Null

    $mg = Get-MgContext
    if (-not $mg) {
        throw "Graph connection failed: no Graph context returned after Connect-MgGraph."
    }

    # Record the tenant we intended (domain or guid)
    $script:EIDMAuthState.GraphConnectedTenant = $tenant

    Write-Host ("Graph connection established ({0})." -f $SideLabel) -ForegroundColor Green
}

function Ensure-EIDMGraphConnectionForTenant {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string]$TenantIdOrDomain,
        [Parameter(Mandatory)][string]$SideLabel
    )

    $expected = Resolve-EIDMTenantId -TenantIdOrDomain $TenantIdOrDomain

    # If context looks good, keep it
    if (Test-EIDMGraphContextForTenant -ExpectedTenant $expected) {
        return
    }

    # Otherwise, disconnect and reconnect (token may be expired, wrong tenant, or no context)
    Disconnect-EIDMGraphIfNeeded

    try {
        Connect-EIDMGraphInteractive -Ctx $Ctx -TenantIdOrDomain $expected -SideLabel $SideLabel
    }
    catch {
        # One retry (interactive auth can be flaky)
        Write-Host "Graph connection attempt failed. Retrying once..." -ForegroundColor Yellow
        Disconnect-EIDMGraphIfNeeded
        Connect-EIDMGraphInteractive -Ctx $Ctx -TenantIdOrDomain $expected -SideLabel $SideLabel
    }

    if (-not (Test-EIDMGraphContextForTenant -ExpectedTenant $expected)) {
        throw "Graph connection validation failed: unable to confirm the expected tenant context."
    }
}

# ------------------------------------------------------------
# Graph - Source / Target
# ------------------------------------------------------------

function Ensure-EIDMGraphSourceConnection {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $tenant = $Ctx.Config.Tenants.Source.TenantIdOrDomain
    Ensure-EIDMGraphConnectionForTenant -Ctx $Ctx -TenantIdOrDomain $tenant -SideLabel 'SOURCE'

    $script:EIDMAuthState.GraphSourceConnected = $true
    $script:EIDMAuthState.GraphTargetConnected = $false
}

function Ensure-EIDMGraphTargetConnection {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $tenant = $Ctx.Config.Tenants.Target.TenantIdOrDomain
    Ensure-EIDMGraphConnectionForTenant -Ctx $Ctx -TenantIdOrDomain $tenant -SideLabel 'TARGET'

    $script:EIDMAuthState.GraphTargetConnected = $true
    $script:EIDMAuthState.GraphSourceConnected = $false
}

# ------------------------------------------------------------
# Troubleshooting helper
# ------------------------------------------------------------

function Reset-EIDMAuthState {
    Disconnect-EIDMGraphIfNeeded

    $script:EIDMAuthState.GraphSourceConnected = $false
    $script:EIDMAuthState.GraphTargetConnected = $false
    $script:EIDMAuthState.GraphConnectedTenant = $null

    Write-Host "Auth state reset." -ForegroundColor Yellow
}

# ------------------------------------------------------------
# Exchange Online - Interactive connections (Source/Target)
# ------------------------------------------------------------

if (-not (Get-Variable -Name EIDMExoState -Scope Script -ErrorAction SilentlyContinue)) {
    $script:EIDMExoState = @{
        SourceConnected = $false
        TargetConnected = $false
    }
}


function Ensure-EIDMExchangeSourceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    if ($script:EIDMExoState.SourceConnected) { return }

    $tenant = $Ctx.Config.Tenants.Source.TenantIdOrDomain

    Write-Host ""
    Write-Host "Connecting to Exchange Online (SOURCE tenant: $tenant)..." -ForegroundColor Cyan
    Write-Host "Tip: Sign in with a SOURCE tenant admin account." -ForegroundColor DarkGray

    # Connect-ExchangeOnline prompts interactively
    Connect-ExchangeOnline -ShowBanner:$false

    try {
        # Lightweight validation
        $null = Get-OrganizationConfig -ErrorAction Stop
    }
    catch {
        throw ("Exchange Online connection validation failed (SOURCE). Error: {0}" -f $_.Exception.Message)
    }

    $script:EIDMExoState.SourceConnected = $true
    Write-Host "Exchange Online SOURCE connection established." -ForegroundColor Green
}

function Ensure-EIDMExchangeTargetConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    if ($script:EIDMExoState.TargetConnected) { return }

    $tenant = $Ctx.Config.Tenants.Target.TenantIdOrDomain

    Write-Host ""
    Write-Host "Connecting to Exchange Online (TARGET tenant: $tenant)..." -ForegroundColor Cyan
    Write-Host "Tip: Sign in with a TARGET tenant admin account." -ForegroundColor DarkGray

    Connect-ExchangeOnline -ShowBanner:$false

    try {
        $null = Get-OrganizationConfig -ErrorAction Stop
    }
    catch {
        throw ("Exchange Online connection validation failed (TARGET). Error: {0}" -f $_.Exception.Message)
    }

    $script:EIDMExoState.TargetConnected = $true
    Write-Host "Exchange Online TARGET connection established." -ForegroundColor Green
}


# ------------------------------------------------------------
# SharePoint Online - Interactive connections (Source/Target)
# ------------------------------------------------------------

if (-not (Get-Variable -Name EIDMSpoState -Scope Script -ErrorAction SilentlyContinue)) {
    $script:EIDMSpoState = @{
        SourceConnected = $false
        TargetConnected = $false
        SourceAdminUrl  = $null
        TargetAdminUrl  = $null
    }
}

function Get-EIDMSpoAdminUrlFromTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantIdOrDomain
    )

    # Accept: contoso.onmicrosoft.com OR contoso
    $name = $TenantIdOrDomain
    if ($name -match '^([^\.]+)\.onmicrosoft\.com$') {
        $name = $Matches[1]
    }
    elseif ($name -match '^([^\.]+)\.') {
        # domain like contoso.com -> cannot derive admin URL reliably
        throw "Cannot derive SharePoint admin URL from custom domain '$TenantIdOrDomain'. Please use the *.onmicrosoft.com domain in config."
    }

    return ("https://{0}-admin.sharepoint.com" -f $name)
}

function Ensure-EIDMSharePointSourceConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    if ($script:EIDMSpoState.SourceConnected) { return }

    # PS 5.1: TLS 1.2 often required
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $tenant   = $Ctx.Config.Tenants.Source.TenantIdOrDomain
    $adminUrl = Get-EIDMSpoAdminUrlFromTenant -TenantIdOrDomain $tenant
    $script:EIDMSpoState.SourceAdminUrl = $adminUrl

    Write-Host ""
    Write-Host "Connecting to SharePoint Online (SOURCE admin: $adminUrl)..." -ForegroundColor Cyan
    Write-Host "Tip: Sign in with a SOURCE tenant SharePoint admin account." -ForegroundColor DarkGray

    # Helpful info for troubleshooting
    $spoMod = Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell | Sort-Object Version -Descending | Select-Object -First 1
    if ($spoMod) {
        Write-Host ("SPO module: {0} ({1})" -f $spoMod.Name, $spoMod.Version) -ForegroundColor DarkGray
    }

    # 1) Primary attempt
    try {
        Connect-SPOService -Url $adminUrl
    }
    catch {
        Write-Host "[ERROR] Connect-SPOService failed." -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red

        # 2) Fallback: -UseWebLogin (when available)
        $hasUseWebLogin = $false
        try {
            $hasUseWebLogin = (Get-Command Connect-SPOService -ErrorAction Stop).Parameters.ContainsKey("UseWebLogin")
        } catch { $hasUseWebLogin = $false }

        if ($hasUseWebLogin) {
            Write-Host "Retrying with -UseWebLogin..." -ForegroundColor Yellow
            try {
                Connect-SPOService -Url $adminUrl -UseWebLogin
            }
            catch {
                Write-Host "[ERROR] Connect-SPOService -UseWebLogin failed." -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                throw "Could not connect to SharePoint Online (SOURCE)."
            }
        }
        else {
            throw "Could not connect to SharePoint Online (SOURCE)."
        }
    }

    # Lightweight validation (often fails if account is not SharePoint admin)
    try {
        $null = Get-SPOTenant -ErrorAction Stop
    }
    catch {
        throw ("SharePoint Online connection validation failed (SOURCE). Ensure the account is SharePoint Admin. Error: {0}" -f $_.Exception.Message)
    }

    $script:EIDMSpoState.SourceConnected = $true
    Write-Host "SharePoint Online SOURCE connection established." -ForegroundColor Green
}



function Ensure-EIDMSharePointTargetConnection {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $tenant = $Ctx.Config.Tenants.Target.TenantIdOrDomain

    Write-Host ""
    Write-Host "SharePoint Online connection requested (TARGET tenant: $tenant)." -ForegroundColor Yellow
    Write-Host "Not implemented yet. Please implement Ensure-EIDMSharePointTargetConnection in lib\00-Auth.Functions.ps1." -ForegroundColor Yellow

    throw "Dependency not implemented: SharePointTarget"
}
# ------------------------------------------------------------
# Prerequisites (Modules) - Interactive install (PowerShell 5.1)
# ------------------------------------------------------------

function Ensure-EIDMPrerequisites {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host "  Checking prerequisites (PowerShell modules)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host ""

    # PowerShell 5.1 / PSGallery requires TLS 1.2 in many environments
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    catch {
        # Ignore if not supported (rare)
    }

    # Required modules list (LOCKED - do not reduce)
    $required = @(
        'Microsoft.Graph.Authentication',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Users.Actions',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Applications',
        'ExchangeOnlineManagement',
        'Microsoft.Online.SharePoint.PowerShell'
    )

    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($m in $required) {
        if (-not (Test-EIDMModuleAvailable -Name $m)) {
            $missing.Add($m) | Out-Null
        }
        else {
            Write-Host ("[OK]   {0}" -f $m) -ForegroundColor Green
        }
    }

    if ($missing.Count -eq 0) {
        Write-Host ""
        Write-Host "[OK] All required modules are available." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "[WARN] Missing modules detected:" -ForegroundColor Yellow
    foreach ($m in $missing) {
        Write-Host ("  - {0}" -f $m) -ForegroundColor Yellow
    }
    Write-Host ""

    $install = Read-Host "Do you want to install missing modules now from PSGallery? [Y/n]"
    if ([string]::IsNullOrWhiteSpace($install)) { $install = 'Y' }
    $install = $install.Trim()

    if ($install.ToUpper() -notin @('Y','YES')) {
        throw "Prerequisites not met. Missing modules were not installed."
    }

    # Ensure PSGallery exists and is trusted enough for interactive install
    Ensure-EIDMPowerShellGalleryReady

    foreach ($m in $missing) {
        Write-Host ""
        Write-Host ("Installing module: {0}" -f $m) -ForegroundColor Cyan
        Install-EIDMModule -Name $m
        Write-Host ("[OK] Installed: {0}" -f $m) -ForegroundColor Green
    }

    # Final verification
    Write-Host ""
    Write-Host "Re-checking modules..." -ForegroundColor Cyan

    $stillMissing = @()
    foreach ($m in $required) {
        if (-not (Test-EIDMModuleAvailable -Name $m)) {
            $stillMissing += $m
        }
    }

    if ($stillMissing.Count -gt 0) {
        Write-Host ""
        Write-Host "[ERROR] Some modules are still missing after install:" -ForegroundColor Red
        foreach ($m in $stillMissing) {
            Write-Host ("  - {0}" -f $m) -ForegroundColor Red
        }
        throw "Prerequisites not met after installation."
    }

    Write-Host ""
    Write-Host "[OK] All required modules are now available." -ForegroundColor Green
}

function Test-EIDMModuleAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $found = Get-Module -ListAvailable -Name $Name -ErrorAction Stop
        return ($null -ne $found)
    }
    catch {
        return $false
    }
}

function Ensure-EIDMPowerShellGalleryReady {
    [CmdletBinding()]
    param()

    # Ensure NuGet provider exists (common install prerequisite)
    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget) {
            Write-Host "Installing NuGet provider..." -ForegroundColor Cyan
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
        }
    }
    catch {
        # If this fails, Install-Module will likely fail too - let it bubble later.
    }

    # Ensure PSGallery repository is registered
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
        if (-not $repo) {
            Write-Host "Registering PSGallery repository..." -ForegroundColor Cyan
            Register-PSRepository -Default | Out-Null
        }
    }
    catch {
        # Ignore - Install-Module will surface the real error
    }

    # We won't force "Trusted" automatically (some environments prefer Prompt)
    # but we can warn if it's not trusted.
    try {
        $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction SilentlyContinue
        if ($repo -and $repo.InstallationPolicy -ne 'Trusted') {
            Write-Host "[INFO] PSGallery is not set to Trusted (installation may prompt)." -ForegroundColor DarkGray
        }
    }
    catch {
        # Ignore
    }
}

function Install-EIDMModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name
    )

    # CurrentUser to avoid admin requirement
    try {
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        throw ("Failed to install module '{0}': {1}" -f $Name, $_.Exception.Message)
    }
}
