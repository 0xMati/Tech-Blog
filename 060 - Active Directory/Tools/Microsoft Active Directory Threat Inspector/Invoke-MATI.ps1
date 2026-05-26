# Invoke-MATI.ps1
# MATIv2 - Microsoft Active Directory Threat Inspector v2
# Main entry point - orchestrates the full assessment pipeline.
#
# Usage:
#   .\Invoke-MATI.ps1
#   .\Invoke-MATI.ps1 -ConfigPath .\Config\custom.config.psd1
#   .\Invoke-MATI.ps1 -CategoriesOnly Config,Kerberos
#   .\Invoke-MATI.ps1 -RulesOnly MATI-CONFIG-001,MATI-KERB-005

#requires -Version 7.0

[CmdletBinding()]
param(
    # Path to an alternative configuration file
    [string]$ConfigPath,

    # DNS name of the forest to analyze
    [string]$TargetForest,

    # Run only specific categories (comma-separated)
    [string[]]$CategoriesOnly,

    # Run only specific rule IDs (comma-separated)
    [string[]]$RulesOnly,

    # Skip report generation (useful for quick checks)
    [switch]$NoReport,

    # Skip score history save
    [switch]$NoHistory
)

$ErrorActionPreference = 'Stop'
$selectedTargetForest = if ([string]::IsNullOrWhiteSpace($TargetForest)) { $null } else { $TargetForest.Trim() }
$script:MATIExecutionContext = $null
$script:MATICurrentLogonForest = $null

# Resolve root path
$RootPath = $PSScriptRoot

function Get-MATICurrentLogonForestName {
    try {
        return [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    }
    catch {
        return $null
    }
}

function Read-MATITargetForest {
    param(
        [string]$CurrentTargetForest
    )

    $defaultLabel = if ([string]::IsNullOrWhiteSpace($CurrentTargetForest)) {
        if ([string]::IsNullOrWhiteSpace($script:MATICurrentLogonForest)) {
            'current logon forest'
        } else {
            $script:MATICurrentLogonForest
        }
    } else {
        $CurrentTargetForest
    }

    $inputForest = Read-Host "    Forest DNS name to analyze [Press Enter for default: $defaultLabel]"
    if ([string]::IsNullOrWhiteSpace($inputForest)) {
        return $CurrentTargetForest
    }

    return $inputForest.Trim()
}

function Get-MATIExecutionContext {
    param(
        [System.Security.Principal.WindowsIdentity]$Identity
    )

    if (-not $Identity) {
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    }

    $accountName = $Identity.Name
    $samAccountName = if ($accountName -match '\\') { ($accountName -split '\\', 2)[1] } else { $env:USERNAME }
    $domainNetBIOS = if ($accountName -match '\\') { ($accountName -split '\\', 2)[0] } else { $env:USERDOMAIN }
    $userPrincipalName = $null
    $userDomainDns = $env:USERDNSDOMAIN
    $userDistinguishedName = $null
    $userSid = if ($Identity.User) { $Identity.User.Value } else { $null }

    if ($userSid) {
        try {
            $adsiUser = [ADSI]("LDAP://<SID=$userSid>")
            if ($adsiUser.Properties['samAccountName'].Count -gt 0) {
                $samAccountName = [string]$adsiUser.Properties['samAccountName'][0]
            }
            if ($adsiUser.Properties['userPrincipalName'].Count -gt 0) {
                $userPrincipalName = [string]$adsiUser.Properties['userPrincipalName'][0]
            }
            if ($adsiUser.Properties['distinguishedName'].Count -gt 0) {
                $userDistinguishedName = [string]$adsiUser.Properties['distinguishedName'][0]
            }
        }
        catch { }
    }

    if ([string]::IsNullOrWhiteSpace($userDomainDns) -and $userDistinguishedName) {
        $userDomainDns = (($userDistinguishedName -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object {
            $_.Substring(3)
        }) -join '.'
    }

    if ([string]::IsNullOrWhiteSpace($userPrincipalName)) {
        if (-not [string]::IsNullOrWhiteSpace($userDomainDns) -and -not [string]::IsNullOrWhiteSpace($samAccountName)) {
            $userPrincipalName = "$samAccountName@$userDomainDns"
        } else {
            $userPrincipalName = $accountName
        }
    }

    $computerName = $env:COMPUTERNAME
    $machineDomain = $null
    $fqdn = $computerName
    try {
        $ipProps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if (-not [string]::IsNullOrWhiteSpace($ipProps.DomainName)) {
            $machineDomain = $ipProps.DomainName
            $fqdn = "$computerName.$machineDomain"
        }
    }
    catch { }

    if ([string]::IsNullOrWhiteSpace($machineDomain)) {
        try {
            $machineDomain = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Domain
        }
        catch { }
    }

    if ($fqdn -eq $computerName) {
        try {
            $fqdn = [System.Net.Dns]::GetHostEntry($computerName).HostName
        }
        catch { }
    }

    $operatingSystem = [System.Environment]::OSVersion.VersionString
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($osInfo.Caption) {
            $operatingSystem = $osInfo.Caption
        }
    }
    catch { }

    return @{
        User = [PSCustomObject]@{
            DomainNetBIOS     = $domainNetBIOS
            DomainDns         = $userDomainDns
            SamAccountName    = $samAccountName
            UserPrincipalName = $userPrincipalName
            SID               = $userSid
        }
        Machine = [PSCustomObject]@{
            ComputerName     = $computerName
            FQDN             = $fqdn
            Domain           = $machineDomain
            OperatingSystem  = $operatingSystem
            PowerShell       = $PSVersionTable.PSVersion.ToString()
        }
    }
}

function Write-MATIExecutionContext {
    param(
        [hashtable]$MATIContext,
        [string]$Header = '  [~] Execution context...'
    )

    if (-not $MATIContext) {
        return
    }

    Write-Host $Header -ForegroundColor Yellow

    if ($MATIContext.User) {
        Write-Host "    User domain   : $($MATIContext.User.DomainNetBIOS) / $($MATIContext.User.DomainDns)" -ForegroundColor White
        Write-Host "    SamAccountName: $($MATIContext.User.SamAccountName)" -ForegroundColor White
        Write-Host "    UPN           : $($MATIContext.User.UserPrincipalName)" -ForegroundColor White
    }

    if ($MATIContext.Machine) {
        Write-Host "    Computer name : $($MATIContext.Machine.ComputerName)" -ForegroundColor White
        Write-Host "    FQDN          : $($MATIContext.Machine.FQDN)" -ForegroundColor White
        Write-Host "    Machine domain: $($MATIContext.Machine.Domain)" -ForegroundColor White
        Write-Host "    OS            : $($MATIContext.Machine.OperatingSystem)" -ForegroundColor White
    }
}

# ==================================================================
# 0. Banner
# ==================================================================
Clear-Host
$banner = @"

    ███╗   ███╗ █████╗ ████████╗██╗
    ████╗ ████║██╔══██╗╚══██╔══╝██║
    ██╔████╔██║███████║   ██║   ██║
    ██║╚██╔╝██║██╔══██║   ██║   ██║
    ██║ ╚═╝ ██║██║  ██║   ██║   ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝
    Microsoft Active Directory Threat Inspector

"@
# Read version from config
$configFile = if ($ConfigPath -and (Test-Path $ConfigPath)) { $ConfigPath } else { Join-Path $RootPath 'Config\MATI.config.psd1' }
$matiVersion = if (Test-Path $configFile) { (Import-PowerShellDataFile $configFile).General.Version } else { '?.?.?' }

Write-Host $banner -ForegroundColor Cyan
Write-Host "    v$matiVersion | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "    $('-' * 50)" -ForegroundColor DarkGray
$script:MATICurrentLogonForest = Get-MATICurrentLogonForestName

# ==================================================================
# 0.01 PowerShell version check
# ==================================================================
if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "    [OK] PowerShell $($PSVersionTable.PSVersion) detected" -ForegroundColor Green
} else {
    Write-Host "    [ERROR] PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host "    Download PowerShell 7: https://aka.ms/powershell-release?tag=stable" -ForegroundColor Yellow
    Write-Host ""
    throw "MATI requires PowerShell 7 or later. Please re-run this script using pwsh.exe."
}
Write-Host ""

# ==================================================================
# 0.02 PowerShell elevation check
# ==================================================================
Write-Host "  [~] Checking PowerShell elevation..." -ForegroundColor Yellow
$isLocalAdmin = $false
try {
    $currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
    $isLocalAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isLocalAdmin) {
        Write-Host "    [OK] PowerShell session is running as Administrator" -ForegroundColor Green
    } else {
        Write-Host "    [!!] PowerShell session is NOT running as Administrator" -ForegroundColor Yellow
        Write-Host "         Some local and remote checks may return partial results." -ForegroundColor Yellow

        $continueChoice = Read-Host "    Continue anyway without elevation? [Y/N]"
        if ($continueChoice.Trim().ToUpper() -ne 'Y') {
            Write-Host "    Exiting MATI. Please re-run PowerShell with 'Run as Administrator'." -ForegroundColor Cyan
            return
        }

        Write-Host "    [!] Continuing without elevation - results may be incomplete." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not verify PowerShell elevation: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    [!] Continuing - local privilege-dependent checks may fail." -ForegroundColor Yellow
}
Write-Host ""

# ==================================================================
# 0.03 Permission prerequisite check
# ==================================================================
Write-Host "  [~] Checking permissions..." -ForegroundColor Yellow
try {
    $currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
    $tokenGroupSids = $currentIdentity.Groups | ForEach-Object { $_.Value }
    $isDomainAdmin     = $tokenGroupSids | Where-Object { $_ -match '-512$' }
    $isEnterpriseAdmin = $tokenGroupSids | Where-Object { $_ -match '-519$' }
    $forest        = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $isMultiDomain = $forest.Domains.Count -gt 1
    $permOk = $true

    if ($isMultiDomain) {
        if ($isEnterpriseAdmin) {
            Write-Host "    [OK] Enterprise Admins membership detected (multi-domain forest - $($forest.Domains.Count) domains)" -ForegroundColor Green
        } elseif ($isDomainAdmin) {
            Write-Host "    [!!] Domain Admins detected - but NOT Enterprise Admins" -ForegroundColor Yellow
            Write-Host "         Multi-domain forest with $($forest.Domains.Count) domains detected." -ForegroundColor Yellow
            Write-Host "         Cross-domain analysis may be incomplete. Enterprise Admins is recommended." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host "    Minimum required  : Domain Admins" -ForegroundColor Yellow
            Write-Host "    Recommended       : Enterprise Admins (multi-domain forest detected)" -ForegroundColor Yellow
            $permOk = $false
        }
    } else {
        if ($isDomainAdmin) {
            Write-Host "    [OK] Domain Admins membership detected" -ForegroundColor Green
        } elseif ($isLocalAdmin) {
            Write-Host "    [!!] Builtin\Administrators detected - but NOT Domain Admins" -ForegroundColor Yellow
            Write-Host "         Some AD collectors may return partial results." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host "    Minimum required : Domain Admins" -ForegroundColor Yellow
            $permOk = $false
        }
    }

    if (-not $permOk) {
        $continueChoice = Read-Host "    Continue anyway with potentially incomplete results? [Y/N]"
        if ($continueChoice.Trim().ToUpper() -ne 'Y') {
            Write-Host "    Exiting MATI. Please re-run with appropriate permissions." -ForegroundColor Cyan
            return
        }
        Write-Host "    [!] Continuing with current permissions - results may be incomplete." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not verify AD permissions: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    [!] Continuing - some collectors may fail if permissions are insufficient." -ForegroundColor Yellow
}
Write-Host ""

# ==================================================================
# 0.04 Execution context
# ==================================================================
try {
    $script:MATIExecutionContext = Get-MATIExecutionContext -Identity $currentIdentity
    Write-MATIExecutionContext -MATIContext $script:MATIExecutionContext -Header '  [~] Capturing execution context...'
} catch {
    Write-Host "  [!] Could not capture execution context: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# ==================================================================
# 0.05 Define Threat Detection function
# ==================================================================
function Invoke-MATIThreatDetection {
    $global:MATIMode = 'ThreatDetection'
    Write-Host ""
    Write-Host "    [>] Launching Threat Detection & Security Analysis..." -ForegroundColor Green
    Write-Host ""

    # Load engine components
    $engineFiles = @(
        'Models\Finding.ps1'
        'Engine\Initialize-MATIEngine.ps1'
        'Engine\Get-MATISummarySnapshot.ps1'
        'Engine\Invoke-MATICollectors.ps1'
        'Engine\Invoke-MATIRules.ps1'
        'Engine\ConvertTo-MATIReport.ps1'
        'Scoring\Get-MATIScore.ps1'
    )
    foreach ($file in $engineFiles) {
        $filePath = Join-Path $RootPath $file
        if (Test-Path $filePath) {
            . $filePath
        } else {
            throw "Engine component not found: $filePath"
        }
    }

    # Initialize engine
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ctx = Initialize-MATIEngine -RootPath $RootPath -ConfigPath $ConfigPath -TargetForest $selectedTargetForest
    $ctx.ExecutionContext = if ($script:MATIExecutionContext) { $script:MATIExecutionContext } else { Get-MATIExecutionContext }
    $ctx.Config['_ExecutionContext'] = $ctx.ExecutionContext

    $transcriptPath = Join-Path $ctx.OutputRoot 'MATI.transcript.txt'
    $transcriptStarted = $false

    try {
        try {
            Start-Transcript -Path $transcriptPath -Force -IncludeInvocationHeader -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
            Write-Host "  [+] Transcript started: $transcriptPath" -ForegroundColor Green
            Write-MATIExecutionContext -MATIContext $ctx.ExecutionContext -Header '  [~] Execution context recorded in transcript...'
        } catch {
            Write-Warning "  [!] Could not start transcript: $($_.Exception.Message)"
        }

        # Apply runtime filters
        if ($CategoriesOnly) {
            $ctx.Rules = [System.Collections.Generic.List[hashtable]]@(
                $ctx.Rules | Where-Object { $_['_Category'] -in $CategoriesOnly }
            )
            Write-Host "  [~] Filtered to categories: $($CategoriesOnly -join ', ')" -ForegroundColor Yellow
        }
        if ($RulesOnly) {
            $ctx.Rules = [System.Collections.Generic.List[hashtable]]@(
                $ctx.Rules | Where-Object { $_.Id -in $RulesOnly }
            )
            Write-Host "  [~] Filtered to rules: $($RulesOnly -join ', ')" -ForegroundColor Yellow
        }

        # Run collectors
        Invoke-MATICollectors -EngineContext $ctx

        # Execute rules
        Invoke-MATIRules -EngineContext $ctx

        # Calculate score
        $score = Get-MATIScore -EngineContext $ctx

        # Generate reports
        if (-not $NoReport) {
            ConvertTo-MATIReport -EngineContext $ctx
        }

        # Save score history
        if (-not $NoHistory) {
            Save-MATIScoreHistory -EngineContext $ctx
            Write-Host "  [+] Score history updated.`n" -ForegroundColor Green
        }

        # Final summary
        $sw.Stop()
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  MATI Assessment Complete" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Cyan
        Write-Host "  Score     : $($score.Score) / $($score.BaseScore)  (Grade: $($score.Grade))" -ForegroundColor White
        Write-Host "  Findings  : $($score.TotalFindings)" -ForegroundColor White
        Write-Host "  Forest    : $($ctx.Config['_TargetForest'])" -ForegroundColor White
        Write-Host "  Duration  : $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor White
        Write-Host "  Output    : $($ctx.OutputRoot)" -ForegroundColor White
        Write-Host "  Transcript: $transcriptPath" -ForegroundColor White
        Write-Host "================================================================`n" -ForegroundColor Cyan
    }
    finally {
        if ($transcriptStarted) {
            try {
                Stop-Transcript | Out-Null
                Write-Host "  [+] Transcript saved: $transcriptPath`n" -ForegroundColor Green
            } catch {
                Write-Warning "  [!] Could not stop transcript cleanly: $($_.Exception.Message)"
            }
        }
    }
}

function Invoke-MATITieringMode {
    $global:MATIMode = 'TieringModel'
    Write-Host ""
    Write-Host "    [>] Launching Tiering Model implementation..." -ForegroundColor Green
    Write-Host ""

    $tieringOutputRoot = Join-Path $RootPath 'Outputs\Tiering'
    if (-not (Test-Path $tieringOutputRoot)) {
        New-Item -ItemType Directory -Path $tieringOutputRoot -Force | Out-Null
    }

    $transcriptPath = Join-Path $tieringOutputRoot ("MATI.Tiering.transcript.{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    $transcriptStarted = $false

    try {
        try {
            Start-Transcript -Path $transcriptPath -Force -IncludeInvocationHeader -ErrorAction Stop | Out-Null
            $transcriptStarted = $true
            Write-Host "  [+] Tiering transcript started: $transcriptPath" -ForegroundColor Green
            if ($script:MATIExecutionContext) {
                Write-MATIExecutionContext -MATIContext $script:MATIExecutionContext -Header '  [~] Execution context recorded in transcript...'
            }
        } catch {
            Write-Warning "  [!] Could not start tiering transcript: $($_.Exception.Message)"
        }

        $tieringMenuPath = Join-Path $RootPath 'Tiering\Invoke-MATITieringMenu.ps1'
        if (Test-Path $tieringMenuPath) {
            . $tieringMenuPath
            Invoke-MATITieringMenu -RootPath $RootPath -Config @{ ConfigFile = $configFile }
        } else {
            Write-Host "    [ERROR] Tiering module not found: $tieringMenuPath" -ForegroundColor Red
        }
    }
    finally {
        if ($transcriptStarted) {
            try {
                Stop-Transcript | Out-Null
                Write-Host "  [+] Tiering transcript saved: $transcriptPath`n" -ForegroundColor Green
            } catch {
                Write-Warning "  [!] Could not stop tiering transcript cleanly: $($_.Exception.Message)"
            }
        }
    }
}

# ==================================================================
# 0.05 Main Menu
# ==================================================================
$mainLoop = $true
while ($mainLoop) {
Write-Host ""
Write-Host "    ┌─────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "    │                  MAIN MENU                      │" -ForegroundColor Cyan
Write-Host "    ├─────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "    │  [1]  Threat Detection & Security Analysis      │" -ForegroundColor Green
Write-Host "    │  [2]  Implement Tiering Model                    │" -ForegroundColor Green
Write-Host "    │  [Q]  Quit                                      │" -ForegroundColor Red
Write-Host "    └─────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$menuChoice = Read-Host "    Select an option [1/2/Q]"
switch ($menuChoice.Trim().ToUpper()) {
    '2' {
        Invoke-MATITieringMode
        # Loop back to main menu
    }
    'Q' {
        Write-Host "    Exiting MATI. Goodbye!" -ForegroundColor Cyan
        $mainLoop = $false
        return
    }
    '1' {
        $selectedTargetForest = Read-MATITargetForest -CurrentTargetForest $selectedTargetForest
        Invoke-MATIThreatDetection
        # Loop back to main menu
    }
    default {
        Write-Host "    [!] Invalid option. Please select 1, 2, or Q." -ForegroundColor Yellow
    }
}
} # end main menu loop
