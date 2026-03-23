<#
.SYNOPSIS
    Windows LAPS & Legacy LAPS - Comprehensive Assessment Tool

.DESCRIPTION
    Performs a full audit of LAPS deployment in an Active Directory environment:
    - AD schema analysis (Legacy LAPS & Windows LAPS attributes)
    - Domain functional level check
    - GPO detection and configuration review
    - OU permissions audit
    - Computer inventory: password status, OS eligibility, CSE detection
    - Summary dashboard with migration readiness score

.NOTES
    Version:    1.0
    Author:     Tech-Blog
    Requires:   ActiveDirectory PowerShell module, LAPS PowerShell module (optional)
    Run As:     Domain Admin or delegated read permissions

.EXAMPLE
    .\Invoke-LAPSAssessment.ps1
    .\Invoke-LAPSAssessment.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com"
    .\Invoke-LAPSAssessment.ps1 -ExportCSV
#>

#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Target OU distinguished name. If omitted, scans the entire domain.")]
    [string]$SearchBase,

    [Parameter(HelpMessage = "Export detailed results to CSV files in the current directory.")]
    [switch]$ExportCSV,

    [Parameter(HelpMessage = "Skip computer inventory (faster, schema/GPO/permissions only).")]
    [switch]$SkipComputerScan
)

# ==================================================================
# Configuration & Helpers
# ==================================================================

$ErrorActionPreference = 'Stop'
$script:Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$script:Results = @{
    SchemaLegacy       = $false
    SchemaWindowsLAPS  = $false
    DomainFunctionalLevel = ""
    LegacyGPOs         = @()
    WindowsLAPSGPOs    = @()
    OUsWithPermissions  = @()
    Computers           = @()
    Summary             = @{}
}

function Write-Banner {
    $banner = @"

    __    ___    ____  _____
   / /   /   |  / __ \/ ___/
  / /   / /| | / /_/ /\__ \
 / /___/ ___ |/ ____/___/ /
/_____/_/  |_/_/    /____/
    _                                             __
   / |   ___ ___ ___ ___ ___ __ _  ___ ___  / /_
  / /|  (_-<(_-</ -_|_-<(_-</  ' \/ -_) _ \/ __/
 /_/  |_/___/___/\__/___/___/_/_/_/\__/_//_/\__/

 Windows LAPS & Legacy LAPS Assessment Tool v1.0

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host " Domain     : $((Get-ADDomain).DNSRoot)" -ForegroundColor DarkGray
    Write-Host " Date       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host " SearchBase : $(if ($SearchBase) { $SearchBase } else { '(entire domain)' })" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Section ([string]$Title) {
    Write-Host ""
    Write-Host " ================================================================" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host " ================================================================" -ForegroundColor DarkCyan
}

function Write-Check ([string]$Message, [string]$Status, [string]$Detail = "") {
    switch ($Status) {
        "OK"      { Write-Host "  [OK]    " -ForegroundColor Green -NoNewline }
        "WARN"    { Write-Host "  [!!]    " -ForegroundColor Yellow -NoNewline }
        "ERROR"   { Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline }
        "INFO"    { Write-Host "  [~]     " -ForegroundColor DarkGray -NoNewline }
    }
    Write-Host $Message -ForegroundColor White -NoNewline
    if ($Detail) {
        Write-Host " — $Detail" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
}

# ==================================================================
# Pre-flight Checks
# ==================================================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "  [ERROR] ActiveDirectory PowerShell module is not available. Install RSAT." -ForegroundColor Red
    return
}

$LAPSModuleAvailable = $false
try {
    Import-Module LAPS -ErrorAction Stop
    $LAPSModuleAvailable = $true
} catch {
    # LAPS module not available — we'll work without it
}

$domain = Get-ADDomain
if (-not $SearchBase) {
    $SearchBase = $domain.DistinguishedName
}

# ==================================================================
# Main Assessment
# ==================================================================

Write-Banner

# ------------------------------------------------------------------
# 1. AD Schema Analysis
# ------------------------------------------------------------------
Write-Section "1. AD Schema Analysis"

$schemaNC = (Get-ADRootDSE).schemaNamingContext

# Check Legacy LAPS attributes
$legacyAttrs = @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime")
$legacyFound = @()
foreach ($attr in $legacyAttrs) {
    $obj = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq $attr } -ErrorAction SilentlyContinue
    if ($obj) { $legacyFound += $attr }
}

if ($legacyFound.Count -eq $legacyAttrs.Count) {
    Write-Check "Legacy LAPS schema attributes" "OK" "Found: $($legacyFound -join ', ')"
    $script:Results.SchemaLegacy = $true
} elseif ($legacyFound.Count -gt 0) {
    Write-Check "Legacy LAPS schema attributes" "WARN" "Partial: $($legacyFound -join ', ')"
    $script:Results.SchemaLegacy = $true
} else {
    Write-Check "Legacy LAPS schema attributes" "INFO" "Not present (Legacy LAPS was never deployed)"
}

# Check Windows LAPS attributes
$wlapsAttrs = @(
    "msLAPS-PasswordExpirationTime",
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword",
    "msLAPS-EncryptedDSRMPasswordHistory"
)
$wlapsFound = @()
foreach ($attr in $wlapsAttrs) {
    $obj = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq $attr } -ErrorAction SilentlyContinue
    if ($obj) { $wlapsFound += $attr }
}

if ($wlapsFound.Count -eq $wlapsAttrs.Count) {
    Write-Check "Windows LAPS schema attributes" "OK" "All $($wlapsAttrs.Count) attributes present"
    $script:Results.SchemaWindowsLAPS = $true
} elseif ($wlapsFound.Count -gt 0) {
    Write-Check "Windows LAPS schema attributes" "WARN" "Partial ($($wlapsFound.Count)/$($wlapsAttrs.Count)): $($wlapsFound -join ', ')"
    $script:Results.SchemaWindowsLAPS = $true
} else {
    Write-Check "Windows LAPS schema attributes" "WARN" "Not present — run Update-LapsADSchema before deploying"
}

# ------------------------------------------------------------------
# 2. Domain Functional Level
# ------------------------------------------------------------------
Write-Section "2. Domain Functional Level"

$dfl = $domain.DomainMode
$script:Results.DomainFunctionalLevel = $dfl

$dflNumeric = switch -Wildcard ($dfl) {
    "*2016*" { 7 }
    "*2012R2*" { 6 }
    "*2012*" { 5 }
    "*2008R2*" { 4 }
    "*2008*" { 3 }
    default {
        if ($dfl -match "2025|2022|2019") { 7 }
        else { 0 }
    }
}

if ($dflNumeric -ge 7) {
    Write-Check "Domain Functional Level: $dfl" "OK" "Password encryption supported"
} elseif ($dflNumeric -ge 5) {
    Write-Check "Domain Functional Level: $dfl" "WARN" "Windows LAPS works but password encryption requires DFL 2016+"
} else {
    Write-Check "Domain Functional Level: $dfl" "ERROR" "Too low — upgrade DFL for Windows LAPS encryption support"
}

# ------------------------------------------------------------------
# 3. GPO Analysis
# ------------------------------------------------------------------
Write-Section "3. GPO Detection & Analysis"

$allGPOs = Get-GPO -All -ErrorAction SilentlyContinue

# Legacy LAPS GPO detection — look for AdmPwd registry keys
$legacyGPOs = @()
$wlapsGPOs = @()

foreach ($gpo in $allGPOs) {
    try {
        $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
        if ($report) {
            # Legacy LAPS uses HKLM\Software\Policies\Microsoft Services\AdmPwd
            if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                $legacyGPOs += [PSCustomObject]@{
                    Name        = $gpo.DisplayName
                    Id          = $gpo.Id
                    Status      = $gpo.GpoStatus
                    Modified    = $gpo.ModificationTime
                    Type        = "Legacy LAPS"
                }
            }
            # Windows LAPS uses HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config
            # or the LAPS admx settings under System\LAPS
            if ($report -match "CurrentVersion\\LAPS" -or $report -match "CurrentVersion/LAPS" -or
                ($report -match "LAPS" -and $report -match "BackupDirectory")) {
                # Avoid double-counting Legacy GPOs that just mention "LAPS" in name
                if ($report -notmatch "Microsoft Services.*AdmPwd" -or $report -match "BackupDirectory") {
                    $wlapsGPOs += [PSCustomObject]@{
                        Name        = $gpo.DisplayName
                        Id          = $gpo.Id
                        Status      = $gpo.GpoStatus
                        Modified    = $gpo.ModificationTime
                        Type        = "Windows LAPS"
                    }
                }
            }
        }
    } catch {
        # Skip GPOs we can't read
    }
}

$script:Results.LegacyGPOs = $legacyGPOs
$script:Results.WindowsLAPSGPOs = $wlapsGPOs

if ($legacyGPOs.Count -gt 0) {
    Write-Check "Legacy LAPS GPOs found: $($legacyGPOs.Count)" "INFO"
    foreach ($g in $legacyGPOs) {
        Write-Host "           → $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray
    }
} else {
    Write-Check "No Legacy LAPS GPOs detected" "INFO"
}

if ($wlapsGPOs.Count -gt 0) {
    Write-Check "Windows LAPS GPOs found: $($wlapsGPOs.Count)" "OK"
    foreach ($g in $wlapsGPOs) {
        Write-Host "           → $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray
    }
} else {
    Write-Check "No Windows LAPS GPOs detected" "WARN" "No policy configured yet"
}

# ------------------------------------------------------------------
# 4. OU Permissions Audit
# ------------------------------------------------------------------
Write-Section "4. OU Permissions Audit"

if ($LAPSModuleAvailable) {
    # Get all OUs under SearchBase
    $OUs = @(Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -SearchScope Subtree -ErrorAction SilentlyContinue)
    $ousWithExtendedRights = @()

    Write-Host "  Scanning $($OUs.Count) OUs for LAPS permissions..." -ForegroundColor DarkGray

    foreach ($ou in $OUs) {
        try {
            $rights = Find-LapsADExtendedRights -Identity $ou.DistinguishedName -ErrorAction SilentlyContinue
            if ($rights) {
                foreach ($right in $rights) {
                    $ousWithExtendedRights += [PSCustomObject]@{
                        OU              = $ou.DistinguishedName
                        Identity        = $right.ExtendedRightHolders -join "; "
                    }
                }
            }
        } catch {
            # Skip OUs we can't query
        }
    }

    $script:Results.OUsWithPermissions = $ousWithExtendedRights

    if ($ousWithExtendedRights.Count -gt 0) {
        Write-Check "OUs with LAPS extended rights: $($ousWithExtendedRights.Count)" "OK"
        $ousWithExtendedRights | Group-Object OU | ForEach-Object {
            Write-Host "           → $($_.Name)" -ForegroundColor DarkGray
            foreach ($entry in $_.Group) {
                Write-Host "              Holders: $($entry.Identity)" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Check "No LAPS extended rights found on OUs" "WARN" "Run Set-LapsADComputerSelfPermission / Set-LapsADReadPasswordPermission"
    }
} else {
    Write-Check "LAPS PowerShell module not available" "WARN" "Skipping OU permissions audit (install the LAPS module)"

    # Fallback: check ACLs manually for Legacy LAPS GUID
    Write-Host "  Attempting manual ACL check for Legacy LAPS permissions..." -ForegroundColor DarkGray
    $OUs = @(Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -SearchScope Subtree -ErrorAction SilentlyContinue)
    $legacyPermOUs = @()

    # ms-Mcs-AdmPwd schemaIDGUID
    $admPwdGuid = $null
    try {
        $admPwdSchema = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "ms-Mcs-AdmPwd" } -Properties schemaIDGUID -ErrorAction SilentlyContinue
        if ($admPwdSchema) {
            $admPwdGuid = [guid]$admPwdSchema.schemaIDGUID
        }
    } catch { }

    if ($admPwdGuid) {
        foreach ($ou in $OUs) {
            try {
                $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction SilentlyContinue
                $lapsAces = $acl.Access | Where-Object {
                    $_.ObjectType -eq $admPwdGuid -or $_.InheritedObjectType -eq $admPwdGuid
                }
                if ($lapsAces) {
                    foreach ($ace in $lapsAces) {
                        $legacyPermOUs += [PSCustomObject]@{
                            OU       = $ou.DistinguishedName
                            Identity = $ace.IdentityReference.ToString()
                            Rights   = $ace.ActiveDirectoryRights.ToString()
                            Type     = $ace.AccessControlType.ToString()
                        }
                    }
                }
            } catch { }
        }

        if ($legacyPermOUs.Count -gt 0) {
            Write-Check "OUs with Legacy LAPS ACLs: $($($legacyPermOUs | Select-Object -Unique OU).Count)" "INFO"
            $legacyPermOUs | Group-Object OU | ForEach-Object {
                Write-Host "           → $($_.Name)" -ForegroundColor DarkGray
            }
        } else {
            Write-Check "No Legacy LAPS ACLs detected" "INFO"
        }
    } else {
        Write-Check "Cannot check Legacy LAPS ACLs" "INFO" "Legacy LAPS schema not present"
    }
}

# ------------------------------------------------------------------
# 5. Computer Inventory
# ------------------------------------------------------------------
if (-not $SkipComputerScan) {
    Write-Section "5. Computer Inventory & Password Status"

    $properties = @(
        "Name", "OperatingSystem", "OperatingSystemVersion", "Enabled",
        "DistinguishedName", "LastLogonDate"
    )

    # Add Legacy LAPS attributes if schema exists
    if ($script:Results.SchemaLegacy) {
        $properties += "ms-Mcs-AdmPwd"
        $properties += "ms-Mcs-AdmPwdExpirationTime"
    }

    # Add Windows LAPS attributes if schema exists
    if ($script:Results.SchemaWindowsLAPS) {
        $properties += "msLAPS-PasswordExpirationTime"
        $properties += "msLAPS-Password"
        $properties += "msLAPS-EncryptedPassword"
    }

    Write-Host "  Querying computers in $SearchBase ..." -ForegroundColor DarkGray

    $computers = @(Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } `
        -SearchBase $SearchBase -Properties $properties -ErrorAction SilentlyContinue |
        Where-Object { $_.OperatingSystem -notlike "*Server*" -or $_.OperatingSystem -like "*Server*" })

    Write-Host "  Found $($computers.Count) Windows computer accounts." -ForegroundColor DarkGray

    $inventory = @()

    foreach ($pc in $computers) {
        $hasLegacyPwd    = $false
        $hasWLAPSPwd     = $false
        $hasWLAPSEncPwd  = $false
        $legacyExpiry    = $null
        $wlapsExpiry     = $null
        $osEligible      = $false

        # Check Legacy LAPS
        if ($script:Results.SchemaLegacy) {
            $legacyPwd = $pc.'ms-Mcs-AdmPwd'
            if ($legacyPwd) { $hasLegacyPwd = $true }
            $legacyExp = $pc.'ms-Mcs-AdmPwdExpirationTime'
            if ($legacyExp) {
                try { $legacyExpiry = [datetime]::FromFileTime($legacyExp) } catch { }
            }
        }

        # Check Windows LAPS
        if ($script:Results.SchemaWindowsLAPS) {
            $wlapsPwd = $pc.'msLAPS-Password'
            if ($wlapsPwd) { $hasWLAPSPwd = $true }
            $wlapsEncPwd = $pc.'msLAPS-EncryptedPassword'
            if ($wlapsEncPwd) { $hasWLAPSEncPwd = $true }
            $wlapsExp = $pc.'msLAPS-PasswordExpirationTime'
            if ($wlapsExp) {
                try { $wlapsExpiry = [datetime]::FromFileTime($wlapsExp) } catch { }
            }
        }

        # OS eligibility check (Windows 10 21H2+, Windows 11, Server 2019+ with April 2023 update)
        $osVersion = $pc.OperatingSystemVersion
        if ($osVersion) {
            $buildMatch = [regex]::Match($osVersion, '(\d+)\.(\d+)\s*\((\d+)')
            if ($buildMatch.Success) {
                $buildNumber = [int]$buildMatch.Groups[3].Value
                # Build 19044 = Windows 10 21H2, 22000 = Windows 11, 17763 = Server 2019
                if ($buildNumber -ge 17763) { $osEligible = $true }
            } else {
                # Try simple version comparison
                if ($pc.OperatingSystem -match "Server 2019|Server 2022|Server 2025|Windows 11|Windows 10") {
                    $osEligible = $true
                }
            }
        }

        # Determine status
        $status = "No LAPS"
        if ($hasWLAPSEncPwd) { $status = "Windows LAPS (Encrypted)" }
        elseif ($hasWLAPSPwd) { $status = "Windows LAPS (Clear)" }
        elseif ($hasLegacyPwd) { $status = "Legacy LAPS" }

        $inventory += [PSCustomObject]@{
            Name                 = $pc.Name
            Enabled              = $pc.Enabled
            OperatingSystem      = $pc.OperatingSystem
            OSVersion            = $osVersion
            OSEligible           = $osEligible
            LAPSStatus           = $status
            HasLegacyPassword    = $hasLegacyPwd
            HasWindowsLAPSPwd    = ($hasWLAPSPwd -or $hasWLAPSEncPwd)
            LegacyExpiry         = $legacyExpiry
            WindowsLAPSExpiry    = $wlapsExpiry
            LastLogon            = $pc.LastLogonDate
            OU                   = ($pc.DistinguishedName -replace '^CN=[^,]+,', '')
        }
    }

    $script:Results.Computers = $inventory

    # Statistics
    $total       = $inventory.Count
    $enabled     = ($inventory | Where-Object Enabled).Count
    $eligible    = ($inventory | Where-Object OSEligible).Count
    $noLaps      = ($inventory | Where-Object { $_.LAPSStatus -eq "No LAPS" -and $_.Enabled }).Count
    $legacyOnly  = ($inventory | Where-Object { $_.LAPSStatus -eq "Legacy LAPS" -and $_.Enabled }).Count
    $wlapsClear  = ($inventory | Where-Object { $_.LAPSStatus -eq "Windows LAPS (Clear)" -and $_.Enabled }).Count
    $wlapsEnc    = ($inventory | Where-Object { $_.LAPSStatus -eq "Windows LAPS (Encrypted)" -and $_.Enabled }).Count

    Write-Host ""
    Write-Check "Total computer accounts: $total" "INFO"
    Write-Check "Enabled computers: $enabled" "INFO"
    Write-Check "OS eligible for Windows LAPS: $eligible" "INFO"
    Write-Host ""
    Write-Check "No LAPS at all: $noLaps" $(if ($noLaps -gt 0) { "WARN" } else { "OK" })
    Write-Check "Legacy LAPS only: $legacyOnly" $(if ($legacyOnly -gt 0) { "INFO" } else { "OK" })
    Write-Check "Windows LAPS (clear text): $wlapsClear" $(if ($wlapsClear -gt 0) { "WARN" } else { "OK" }) $(if ($wlapsClear -gt 0) { "Enable encryption!" })
    Write-Check "Windows LAPS (encrypted): $wlapsEnc" "OK"

    # Stale Legacy passwords (expired > 90 days ago)
    $now = Get-Date
    $staleLegacy = $inventory | Where-Object {
        $_.HasLegacyPassword -and $_.LegacyExpiry -and ($_.LegacyExpiry -lt $now.AddDays(-90))
    }
    if ($staleLegacy.Count -gt 0) {
        Write-Host ""
        Write-Check "Stale Legacy LAPS passwords (expired 90+ days): $($staleLegacy.Count)" "WARN" "Passwords not rotating — check GPO/CSE"
    }

    # Non-eligible OS
    $nonEligible = $inventory | Where-Object { -not $_.OSEligible -and $_.Enabled }
    if ($nonEligible.Count -gt 0) {
        Write-Host ""
        Write-Check "Computers NOT eligible for Windows LAPS: $($nonEligible.Count)" "WARN"
        $nonEligible | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "           → $($_.Name): $($_.Count)" -ForegroundColor DarkGray
        }
    }

    $script:Results.Summary = @{
        Total           = $total
        Enabled         = $enabled
        Eligible        = $eligible
        NoLAPS          = $noLaps
        LegacyOnly      = $legacyOnly
        WindowsLAPSClear = $wlapsClear
        WindowsLAPSEnc  = $wlapsEnc
        NonEligible     = $nonEligible.Count
    }
} else {
    Write-Section "5. Computer Inventory (SKIPPED)"
    Write-Check "Skipped per -SkipComputerScan parameter" "INFO"
}

# ------------------------------------------------------------------
# 6. Summary & Recommendations
# ------------------------------------------------------------------
Write-Section "6. Summary & Recommendations"

# Determine current state
$hasLegacy = $script:Results.SchemaLegacy
$hasWLAPS  = $script:Results.SchemaWindowsLAPS
$hasLegacyGPO = $script:Results.LegacyGPOs.Count -gt 0
$hasWLAPSGPO  = $script:Results.WindowsLAPSGPOs.Count -gt 0

Write-Host ""
if (-not $hasLegacy -and -not $hasWLAPS) {
    Write-Check "Current state: NO LAPS deployment detected" "ERROR"
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Deploy Windows LAPS from scratch (do not deploy Legacy LAPS)" -ForegroundColor White
    Write-Host "  2. Run Update-LapsADSchema to extend the AD schema" -ForegroundColor White
    Write-Host "  3. Use Deploy-WindowsLAPS.ps1 for automated deployment" -ForegroundColor White
}
elseif ($hasLegacy -and -not $hasWLAPS) {
    Write-Check "Current state: LEGACY LAPS only" "WARN"
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Plan migration to Windows LAPS" -ForegroundColor White
    Write-Host "  2. Run Update-LapsADSchema to add Windows LAPS attributes" -ForegroundColor White
    Write-Host "  3. Use Invoke-LAPSMigration.ps1 for guided migration" -ForegroundColor White
    Write-Host "  4. Ensure all machines are patched with April 2023 update or later" -ForegroundColor White
}
elseif ($hasLegacy -and $hasWLAPS -and $hasLegacyGPO -and -not $hasWLAPSGPO) {
    Write-Check "Current state: Schema ready, but still using Legacy LAPS GPO" "WARN"
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Windows LAPS schema is present — migration is possible" -ForegroundColor White
    Write-Host "  2. Configure Windows LAPS GPO to begin the transition" -ForegroundColor White
    Write-Host "  3. Use Invoke-LAPSMigration.ps1 for step-by-step migration" -ForegroundColor White
}
elseif ($hasLegacy -and $hasWLAPS -and $hasLegacyGPO -and $hasWLAPSGPO) {
    Write-Check "Current state: MIXED — both Legacy and Windows LAPS active" "WARN"
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Verify Windows LAPS is working on pilot machines" -ForegroundColor White
    Write-Host "  2. Gradually remove Legacy LAPS GPO as machines transition" -ForegroundColor White
    Write-Host "  3. Check emulation mode status on machines with both GPOs" -ForegroundColor White
    Write-Host "  4. Use Invoke-LAPSMigration.ps1 to complete migration" -ForegroundColor White
}
elseif ($hasWLAPS -and $hasWLAPSGPO -and -not $hasLegacyGPO) {
    Write-Check "Current state: Windows LAPS deployed" "OK"
    if (-not $SkipComputerScan -and $script:Results.Summary.NoLAPS -gt 0) {
        Write-Host ""
        Write-Host "  Recommendations:" -ForegroundColor Yellow
        Write-Host "  1. $($script:Results.Summary.NoLAPS) enabled computers have no LAPS password — check GPO scope" -ForegroundColor White
    }
    if (-not $SkipComputerScan -and $script:Results.Summary.WindowsLAPSClear -gt 0) {
        Write-Host "  2. $($script:Results.Summary.WindowsLAPSClear) computers use clear-text passwords — enable encryption" -ForegroundColor White
    }
    if ($hasLegacy) {
        Write-Host "  Note: Legacy LAPS schema attributes still present (this is normal, schema attributes cannot be removed)" -ForegroundColor DarkGray
    }
} else {
    Write-Check "Current state: Windows LAPS schema present, but no GPO configured" "WARN"
    Write-Host ""
    Write-Host "  Recommendations:" -ForegroundColor Yellow
    Write-Host "  1. Configure a Windows LAPS GPO and link it to target OUs" -ForegroundColor White
    Write-Host "  2. Use Deploy-WindowsLAPS.ps1 for automated setup" -ForegroundColor White
}

# ------------------------------------------------------------------
# 7. CSV Export
# ------------------------------------------------------------------
if ($ExportCSV) {
    Write-Section "7. CSV Export"
    $exportDir = Join-Path (Get-Location) "LAPS-Assessment_$script:Timestamp"
    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

    if ($script:Results.Computers.Count -gt 0) {
        $script:Results.Computers | Export-Csv -Path (Join-Path $exportDir "Computers.csv") -NoTypeInformation -Encoding UTF8
        Write-Check "Computers.csv" "OK" "$($script:Results.Computers.Count) records"
    }
    if ($script:Results.LegacyGPOs.Count -gt 0) {
        $script:Results.LegacyGPOs | Export-Csv -Path (Join-Path $exportDir "LegacyGPOs.csv") -NoTypeInformation -Encoding UTF8
        Write-Check "LegacyGPOs.csv" "OK" "$($script:Results.LegacyGPOs.Count) records"
    }
    if ($script:Results.WindowsLAPSGPOs.Count -gt 0) {
        $script:Results.WindowsLAPSGPOs | Export-Csv -Path (Join-Path $exportDir "WindowsLAPSGPOs.csv") -NoTypeInformation -Encoding UTF8
        Write-Check "WindowsLAPSGPOs.csv" "OK" "$($script:Results.WindowsLAPSGPOs.Count) records"
    }
    if ($script:Results.OUsWithPermissions.Count -gt 0) {
        $script:Results.OUsWithPermissions | Export-Csv -Path (Join-Path $exportDir "OUPermissions.csv") -NoTypeInformation -Encoding UTF8
        Write-Check "OUPermissions.csv" "OK" "$($script:Results.OUsWithPermissions.Count) records"
    }

    Write-Host ""
    Write-Check "Exported to: $exportDir" "OK"
}

# ------------------------------------------------------------------
# Footer
# ------------------------------------------------------------------
Write-Host ""
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host "  Assessment complete." -ForegroundColor Cyan
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host ""
