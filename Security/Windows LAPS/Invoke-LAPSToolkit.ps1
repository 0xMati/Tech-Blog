<#
.SYNOPSIS
    Windows LAPS Toolkit — All-in-one Assessment, Deployment & Migration Tool

.DESCRIPTION
    Interactive menu-driven tool that consolidates all Windows LAPS operations:
      1. Assessment  — Full audit of LAPS state (schema, GPOs, permissions, computer inventory)
      2. Deployment  — Automated Windows LAPS deployment (schema, permissions, GPO)
      3. Migration   — Guided Legacy LAPS to Windows LAPS migration (5 phases)
      4. Quick Tools — Password retrieval, forced rotation, diagnostics

.NOTES
    Version:    1.1
    Author:     Tech-Blog
    Requires:   ActiveDirectory module, GroupPolicy module, LAPS module (for deployment/migration)
    Run As:     Domain Admin (Schema Admin for schema updates)

.EXAMPLE
    .\Invoke-LAPSToolkit.ps1
#>

#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param()

# ==================================================================
# Global State
# ==================================================================

$ErrorActionPreference = 'Stop'
$script:Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$script:Domain = $null
$script:SchemaNC = $null
$script:LAPSModuleAvailable = $false
$script:HasLegacySchema = $false
$script:HasWLAPSSchema = $false
$script:DFLSupportsEncryption = $false

# ==================================================================
# UI Helpers
# ==================================================================

function Write-Banner {
    Clear-Host
    $banner = @"

    __    ___    ____  _____
   / /   /   |  / __ \/ ___/
  / /   / /| | / /_/ /\__ \       Windows LAPS Toolkit v1.1
 / /___/ ___ |/ ____/___/ /       All-in-one Assessment,
/_____/_/  |_/_/    /____/        Deployment & Migration

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  Domain : $($script:Domain.DNSRoot)" -ForegroundColor DarkGray
    Write-Host "  Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Section ([string]$Title) {
    Write-Host ""
    Write-Host " ================================================================" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host " ================================================================" -ForegroundColor DarkCyan
}

function Write-Status ([string]$Message, [string]$Status, [string]$Detail = "") {
    switch ($Status) {
        "OK"    { Write-Host "  [OK]    " -ForegroundColor Green -NoNewline }
        "WARN"  { Write-Host "  [!!]    " -ForegroundColor Yellow -NoNewline }
        "ERROR" { Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline }
        "INFO"  { Write-Host "  [~]     " -ForegroundColor DarkGray -NoNewline }
        "RUN"   { Write-Host "  [>>]    " -ForegroundColor Cyan -NoNewline }
        "SKIP"  { Write-Host "  [--]    " -ForegroundColor DarkGray -NoNewline }
    }
    Write-Host $Message -ForegroundColor White -NoNewline
    if ($Detail) { Write-Host " — $Detail" -ForegroundColor DarkGray }
    else { Write-Host "" }
}

function Show-Menu ([string]$Title, [string[]]$Options, [switch]$AllowBack) {
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │  $Title$(' ' * (57 - $Title.Length))│" -ForegroundColor Cyan
    Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "   [$($i + 1)] " -ForegroundColor Cyan -NoNewline
        Write-Host $Options[$i] -ForegroundColor White
    }

    if ($AllowBack) {
        Write-Host ""
        Write-Host "   [0] " -ForegroundColor DarkGray -NoNewline
        Write-Host "Back to main menu" -ForegroundColor DarkGray
    }

    Write-Host ""
    $choice = Read-Host "  Select"
    return $choice
}

function Read-Param ([string]$Prompt, [string]$Default = "", [switch]$Mandatory) {
    $suffix = if ($Default) { " [$Default]" } else { "" }
    $value = Read-Host "  $Prompt$suffix"
    if (-not $value -and $Default) { $value = $Default }
    if (-not $value -and $Mandatory) {
        Write-Host "  This value is required." -ForegroundColor Red
        return Read-Param -Prompt $Prompt -Default $Default -Mandatory
    }
    return $value
}

function Confirm-Action ([string]$Message) {
    Write-Host ""
    $answer = Read-Host "  $Message (y/N)"
    return ($answer -eq 'y' -or $answer -eq 'Y')
}

function Pause-Screen {
    Write-Host ""
    Read-Host "  Press Enter to continue"
}

# ==================================================================
# Pre-flight & Initialization
# ==================================================================

function Initialize-Toolkit {
    # AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Host "  [ERROR] ActiveDirectory module not available. Install RSAT." -ForegroundColor Red
        exit 1
    }

    # GroupPolicy module
    try {
        Import-Module GroupPolicy -ErrorAction Stop
    } catch {
        Write-Host "  [!!] GroupPolicy module not available. Deployment/Migration features will be limited." -ForegroundColor Yellow
    }

    # LAPS module
    try {
        Import-Module LAPS -ErrorAction Stop
        $script:LAPSModuleAvailable = $true
    } catch { }

    $script:Domain = Get-ADDomain
    $script:SchemaNC = (Get-ADRootDSE).schemaNamingContext

    # Check schemas
    if (Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq "ms-Mcs-AdmPwd" } -ErrorAction SilentlyContinue) {
        $script:HasLegacySchema = $true
    }
    if (Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq "msLAPS-Password" } -ErrorAction SilentlyContinue) {
        $script:HasWLAPSSchema = $true
    }

    # DFL
    $script:DFLSupportsEncryption = $script:Domain.DomainMode -match "2016|2019|2022|2025"
}

# ██████████████████████████████████████████████████████████████████
#  1. ASSESSMENT
# ██████████████████████████████████████████████████████████████████

function Invoke-Assessment {
    $searchBase = Read-Param "Target OU (leave empty for entire domain)" -Default $script:Domain.DistinguishedName
    $exportCSV  = Confirm-Action "Export results to CSV?"

    Write-Banner
    Write-Section "LAPS Assessment"

    # ── 1. Schema ──
    Write-Section "1. AD Schema Analysis"

    $legacyAttrs = @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime")
    $legacyFound = @()
    foreach ($attr in $legacyAttrs) {
        if (Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq $attr } -ErrorAction SilentlyContinue) {
            $legacyFound += $attr
        }
    }
    if ($legacyFound.Count -eq $legacyAttrs.Count) {
        Write-Status "Legacy LAPS schema attributes" "OK" "Found: $($legacyFound -join ', ')"
    } elseif ($legacyFound.Count -gt 0) {
        Write-Status "Legacy LAPS schema attributes" "WARN" "Partial: $($legacyFound -join ', ')"
    } else {
        Write-Status "Legacy LAPS schema attributes" "INFO" "Not present"
    }

    $wlapsAttrs = @(
        "msLAPS-PasswordExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory"
    )
    $wlapsFound = @()
    foreach ($attr in $wlapsAttrs) {
        if (Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq $attr } -ErrorAction SilentlyContinue) {
            $wlapsFound += $attr
        }
    }
    if ($wlapsFound.Count -eq $wlapsAttrs.Count) {
        Write-Status "Windows LAPS schema attributes" "OK" "All $($wlapsAttrs.Count) attributes present"
    } elseif ($wlapsFound.Count -gt 0) {
        Write-Status "Windows LAPS schema attributes" "WARN" "Partial ($($wlapsFound.Count)/$($wlapsAttrs.Count))"
    } else {
        Write-Status "Windows LAPS schema attributes" "WARN" "Not present — run Update-LapsADSchema -Verbose"
    }

    # ── 2. DFL ──
    Write-Section "2. Domain Functional Level"
    $dfl = $script:Domain.DomainMode
    if ($script:DFLSupportsEncryption) {
        Write-Status "DFL: $dfl" "OK" "Password encryption supported"
    } else {
        Write-Status "DFL: $dfl" "WARN" "Encryption requires DFL 2016+"
    }

    # ── 3. GPOs ──
    Write-Section "3. GPO Detection"
    $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
    $legacyGPOs = @()
    $wlapsGPOs = @()

    foreach ($gpo in $allGPOs) {
        try {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
            if ($report) {
                if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                    $legacyGPOs += [PSCustomObject]@{ Name = $gpo.DisplayName; Id = $gpo.Id; Modified = $gpo.ModificationTime }
                }
                if (($report -match "CurrentVersion\\LAPS" -or $report -match "CurrentVersion/LAPS" -or
                    ($report -match "LAPS" -and $report -match "BackupDirectory")) -and
                    ($report -notmatch "Microsoft Services.*AdmPwd" -or $report -match "BackupDirectory")) {
                    $wlapsGPOs += [PSCustomObject]@{ Name = $gpo.DisplayName; Id = $gpo.Id; Modified = $gpo.ModificationTime }
                }
            }
        } catch { }
    }

    if ($legacyGPOs.Count -gt 0) {
        Write-Status "Legacy LAPS GPOs: $($legacyGPOs.Count)" "INFO"
        foreach ($g in $legacyGPOs) { Write-Host "           → $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray }
    } else { Write-Status "No Legacy LAPS GPOs detected" "INFO" }

    if ($wlapsGPOs.Count -gt 0) {
        Write-Status "Windows LAPS GPOs: $($wlapsGPOs.Count)" "OK"
        foreach ($g in $wlapsGPOs) { Write-Host "           → $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray }
    } else { Write-Status "No Windows LAPS GPOs detected" "WARN" }

    # ── 4. OU Permissions ──
    Write-Section "4. OU Permissions Audit"
    $OUs = @(Get-ADOrganizationalUnit -Filter * -SearchBase $searchBase -SearchScope Subtree -ErrorAction SilentlyContinue)
    Write-Host "  Scanning $($OUs.Count) OUs..." -ForegroundColor DarkGray

    $ousWithRights = @()
    if ($script:LAPSModuleAvailable) {
        foreach ($ou in $OUs) {
            try {
                $rights = Find-LapsADExtendedRights -Identity $ou.DistinguishedName -ErrorAction SilentlyContinue
                if ($rights) {
                    foreach ($r in $rights) {
                        $ousWithRights += [PSCustomObject]@{
                            OU = $ou.DistinguishedName; Identity = $r.ExtendedRightHolders -join "; "
                        }
                    }
                }
            } catch { }
        }
        if ($ousWithRights.Count -gt 0) {
            Write-Status "OUs with LAPS extended rights: $($ousWithRights.Count)" "OK"
            $ousWithRights | Group-Object OU | ForEach-Object {
                Write-Host "           → $($_.Name)" -ForegroundColor DarkGray
                foreach ($e in $_.Group) { Write-Host "              Holders: $($e.Identity)" -ForegroundColor DarkGray }
            }
        } else {
            Write-Status "No LAPS extended rights found" "WARN"
        }
    } else {
        Write-Status "LAPS module not available — skipping detailed OU audit" "WARN"
    }

    # ── 5. Computer Inventory ──
    Write-Section "5. Computer Inventory & Password Status"

    $properties = @("Name", "OperatingSystem", "OperatingSystemVersion", "Enabled", "DistinguishedName", "LastLogonDate")
    if ($script:HasLegacySchema) { $properties += "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" }
    if ($script:HasWLAPSSchema)  { $properties += "msLAPS-PasswordExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword" }

    Write-Host "  Querying computers in $searchBase ..." -ForegroundColor DarkGray
    $computers = @(Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } -SearchBase $searchBase -Properties $properties -ErrorAction SilentlyContinue)
    Write-Host "  Found $($computers.Count) computer accounts." -ForegroundColor DarkGray

    $inventory = @()
    foreach ($pc in $computers) {
        $hasLegacy = $false; $hasWLAPS = $false; $hasWLAPSEnc = $false; $osOK = $false
        $legExpiry = $null; $wlExpiry = $null

        if ($script:HasLegacySchema -and $pc.'ms-Mcs-AdmPwd') { $hasLegacy = $true }
        if ($script:HasLegacySchema -and $pc.'ms-Mcs-AdmPwdExpirationTime') {
            try { $legExpiry = [datetime]::FromFileTime($pc.'ms-Mcs-AdmPwdExpirationTime') } catch { }
        }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-Password') { $hasWLAPS = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-EncryptedPassword') { $hasWLAPSEnc = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-PasswordExpirationTime') {
            try { $wlExpiry = [datetime]::FromFileTime($pc.'msLAPS-PasswordExpirationTime') } catch { }
        }

        if ($pc.OperatingSystem -match "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025") { $osOK = $true }

        $status = "No LAPS"
        if ($hasWLAPSEnc)  { $status = "Windows LAPS (Encrypted)" }
        elseif ($hasWLAPS) { $status = "Windows LAPS (Clear)" }
        elseif ($hasLegacy) { $status = "Legacy LAPS" }

        $inventory += [PSCustomObject]@{
            Name = $pc.Name; Enabled = $pc.Enabled; OS = $pc.OperatingSystem
            OSVersion = $pc.OperatingSystemVersion; OSEligible = $osOK; LAPSStatus = $status
            HasLegacy = $hasLegacy; HasWindowsLAPS = ($hasWLAPS -or $hasWLAPSEnc)
            LegacyExpiry = $legExpiry; WLAPSExpiry = $wlExpiry; LastLogon = $pc.LastLogonDate
            OU = ($pc.DistinguishedName -replace '^CN=[^,]+,', '')
        }
    }

    $enabled  = ($inventory | Where-Object Enabled).Count
    $eligible = ($inventory | Where-Object OSEligible).Count
    $noLaps   = ($inventory | Where-Object { $_.LAPSStatus -eq "No LAPS" -and $_.Enabled }).Count
    $legOnly  = ($inventory | Where-Object { $_.LAPSStatus -eq "Legacy LAPS" -and $_.Enabled }).Count
    $wlClear  = ($inventory | Where-Object { $_.LAPSStatus -eq "Windows LAPS (Clear)" -and $_.Enabled }).Count
    $wlEnc    = ($inventory | Where-Object { $_.LAPSStatus -eq "Windows LAPS (Encrypted)" -and $_.Enabled }).Count

    Write-Host ""
    Write-Status "Total: $($inventory.Count)  |  Enabled: $enabled  |  OS eligible: $eligible" "INFO"
    Write-Host ""
    Write-Status "No LAPS: $noLaps" $(if ($noLaps -gt 0) { "WARN" } else { "OK" })
    Write-Status "Legacy LAPS: $legOnly" $(if ($legOnly -gt 0) { "INFO" } else { "OK" })
    Write-Status "Windows LAPS (clear): $wlClear" $(if ($wlClear -gt 0) { "WARN" } else { "OK" }) $(if ($wlClear -gt 0) { "Enable encryption!" })
    Write-Status "Windows LAPS (encrypted): $wlEnc" "OK"

    $stale = $inventory | Where-Object { $_.HasLegacy -and $_.LegacyExpiry -and ($_.LegacyExpiry -lt (Get-Date).AddDays(-90)) }
    if ($stale.Count -gt 0) {
        Write-Host ""
        Write-Status "Stale Legacy passwords (90+ days expired): $($stale.Count)" "WARN"
    }

    $nonElig = $inventory | Where-Object { -not $_.OSEligible -and $_.Enabled }
    if ($nonElig.Count -gt 0) {
        Write-Host ""
        Write-Status "Not eligible for Windows LAPS: $($nonElig.Count)" "WARN"
        $nonElig | Group-Object OS | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "           → $($_.Name): $($_.Count)" -ForegroundColor DarkGray
        }
    }

    # ── 6. Summary ──
    Write-Section "6. Summary & Recommendations"
    Write-Host ""

    $hasLegGPO = $legacyGPOs.Count -gt 0
    $hasWGPO   = $wlapsGPOs.Count -gt 0

    if (-not $script:HasLegacySchema -and -not $script:HasWLAPSSchema) {
        Write-Status "NO LAPS deployment detected" "ERROR"
        Write-Host "  → Deploy Windows LAPS from scratch using option [2] in the main menu" -ForegroundColor Yellow
    } elseif ($script:HasLegacySchema -and -not $script:HasWLAPSSchema) {
        Write-Status "LEGACY LAPS only — migration recommended" "WARN"
        Write-Host "  → Use option [3] in the main menu for guided migration" -ForegroundColor Yellow
    } elseif ($script:HasLegacySchema -and $hasLegGPO -and -not $hasWGPO) {
        Write-Status "Schema ready but still using Legacy GPO" "WARN"
        Write-Host "  → Use option [3] to complete the migration" -ForegroundColor Yellow
    } elseif ($hasLegGPO -and $hasWGPO) {
        Write-Status "MIXED state — both Legacy and Windows LAPS active" "WARN"
        Write-Host "  → Use option [3] to finish transition and clean up Legacy" -ForegroundColor Yellow
    } elseif ($hasWGPO -and -not $hasLegGPO) {
        Write-Status "Windows LAPS deployed" "OK"
        if ($noLaps -gt 0) { Write-Host "  → $noLaps computers still without LAPS — check GPO scope" -ForegroundColor Yellow }
        if ($wlClear -gt 0) { Write-Host "  → $wlClear computers with clear-text passwords — enable encryption" -ForegroundColor Yellow }
    } else {
        Write-Status "Windows LAPS schema present but no GPO configured" "WARN"
        Write-Host "  → Use option [2] to deploy" -ForegroundColor Yellow
    }

    # ── 7. CSV Export ──
    if ($exportCSV) {
        Write-Section "7. CSV Export"
        $dir = Join-Path (Get-Location) "LAPS-Assessment_$script:Timestamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        if ($inventory.Count -gt 0) {
            $inventory | Export-Csv -Path (Join-Path $dir "Computers.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "Computers.csv — $($inventory.Count) records" "OK"
        }
        if ($legacyGPOs.Count -gt 0) {
            $legacyGPOs | Export-Csv -Path (Join-Path $dir "LegacyGPOs.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "LegacyGPOs.csv" "OK"
        }
        if ($wlapsGPOs.Count -gt 0) {
            $wlapsGPOs | Export-Csv -Path (Join-Path $dir "WindowsLAPSGPOs.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "WindowsLAPSGPOs.csv" "OK"
        }
        if ($ousWithRights.Count -gt 0) {
            $ousWithRights | Export-Csv -Path (Join-Path $dir "OUPermissions.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "OUPermissions.csv" "OK"
        }
        Write-Host ""
        Write-Status "Exported to: $dir" "OK"
    }

    Pause-Screen
}

# ██████████████████████████████████████████████████████████████████
#  2. DEPLOYMENT
# ██████████████████████████████████████████████████████████████████

function Invoke-Deployment {
    Write-Banner
    Write-Section "Windows LAPS Deployment"

    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS PowerShell module not available" "ERROR" "Install April 2023+ update"
        Pause-Screen; return
    }

    # Collect parameters interactively
    Write-Host ""
    Write-Host "  Configure deployment parameters:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray

    $targetOU     = Read-Param "Target OU (DN)" -Mandatory
    $readGroup    = Read-Param "Read/Reset group (DOMAIN\Group)" -Mandatory
    $gpoName      = Read-Param "GPO name" -Default "Windows LAPS Policy"
    $pwdLength    = [int](Read-Param "Password length" -Default "20")
    $pwdAge       = [int](Read-Param "Password age (days)" -Default "30")
    $postAuthH    = [int](Read-Param "Post-auth reset delay (hours)" -Default "8")
    $adminAcct    = Read-Param "Custom admin account name (leave empty for built-in)"
    $doEncrypt    = $script:DFLSupportsEncryption

    if (-not $doEncrypt) {
        Write-Status "DFL does not support encryption — passwords will be stored in clear text" "WARN"
    }

    # Verify OU
    try { Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null }
    catch { Write-Status "OU not found: $targetOU" "ERROR"; Pause-Screen; return }

    # Verify group
    try {
        $grpName = $readGroup -replace '^[^\\]+\\', ''
        Get-ADGroup -Identity $grpName -ErrorAction Stop | Out-Null
    } catch { Write-Status "Group not found: $readGroup" "ERROR"; Pause-Screen; return }

    # Summary
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Target OU         : $targetOU" -ForegroundColor White
    Write-Host "  Read/Reset Group  : $readGroup" -ForegroundColor White
    Write-Host "  GPO Name          : $gpoName" -ForegroundColor White
    Write-Host "  Password          : $pwdLength chars, $pwdAge days, encryption=$doEncrypt" -ForegroundColor White
    Write-Host "  Post-Auth Delay   : $postAuthH hours" -ForegroundColor White
    Write-Host "  Admin Account     : $(if ($adminAcct) { $adminAcct } else { '(built-in)' })" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray

    if (-not (Confirm-Action "Proceed with deployment?")) {
        Write-Status "Cancelled." "INFO"; Pause-Screen; return
    }

    # ── Step 1: Schema ──
    Write-Section "Step 1: AD Schema Update"
    if ($script:HasWLAPSSchema) {
        Write-Status "Windows LAPS schema already present" "OK" "Skipping"
    } else {
        Write-Status "Running Update-LapsADSchema..." "RUN"
        try {
            Update-LapsADSchema -Verbose -ErrorAction Stop
            Write-Status "Schema updated" "OK"
            $script:HasWLAPSSchema = $true
        } catch {
            if ($_.Exception.Message -match "already exists|already been applied") {
                Write-Status "Schema already up to date" "OK"
                $script:HasWLAPSSchema = $true
            } else {
                Write-Status "Schema update failed: $($_.Exception.Message)" "ERROR"
                Write-Host "  Ensure you are running as Schema Admin." -ForegroundColor Yellow
                Pause-Screen; return
            }
        }
    }

    # ── Step 2: Permissions ──
    Write-Section "Step 2: OU Permissions"
    foreach ($op in @(
        @{ Cmd = { Set-LapsADComputerSelfPermission -Identity $targetOU -ErrorAction Stop }; Desc = "SELF write permission" },
        @{ Cmd = { Set-LapsADReadPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Read permission for $readGroup" },
        @{ Cmd = { Set-LapsADResetPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Reset permission for $readGroup" }
    )) {
        Write-Status "Setting $($op.Desc)..." "RUN"
        try {
            & $op.Cmd
            Write-Status $op.Desc "OK"
        } catch {
            if ($_.Exception.Message -match "already") { Write-Status "$($op.Desc) — already set" "OK" }
            else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
        }
    }

    # ── Step 3: GPO ──
    Write-Section "Step 3: GPO Creation & Configuration"
    $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Status "GPO '$gpoName' already exists — updating" "WARN"
    } else {
        New-GPO -Name $gpoName -Comment "Windows LAPS — deployed by Invoke-LAPSToolkit.ps1" | Out-Null
        Write-Status "GPO created: $gpoName" "OK"
    }

    $reg = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "BackupDirectory" -Type DWord -Value 2 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordComplexity" -Type DWord -Value 4 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordLength" -Type DWord -Value $pwdLength | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordAgeDays" -Type DWord -Value $pwdAge | Out-Null

    $encVal = if ($doEncrypt) { 1 } else { 0 }
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value $encVal | Out-Null
    if ($doEncrypt) {
        Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADPasswordEncryptionPrincipal" -Type String -Value $readGroup | Out-Null
    }
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PostAuthenticationActions" -Type DWord -Value 3 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PostAuthenticationResetDelay" -Type DWord -Value $postAuthH | Out-Null
    if ($adminAcct) {
        Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "AdministratorAccountName" -Type String -Value $adminAcct | Out-Null
    }
    Write-Status "GPO configured" "OK"

    # Link
    try {
        $gpoObj = Get-GPO -Name $gpoName
        $links = Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue
        if ($links.GpoLinks | Where-Object { $_.GpoId -eq $gpoObj.Id }) {
            Write-Status "GPO already linked to OU" "OK"
        } else {
            New-GPLink -Guid $gpoObj.Id -Target $targetOU -LinkEnabled Yes | Out-Null
            Write-Status "GPO linked to $targetOU" "OK"
        }
    } catch {
        Write-Status "Failed to link GPO: $($_.Exception.Message)" "ERROR"
    }

    # ── Step 4: Validate ──
    Write-Section "Step 4: Validation"
    $check = Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq "msLAPS-EncryptedPassword" } -ErrorAction SilentlyContinue
    Write-Status "Schema attributes" $(if ($check) { "OK" } else { "ERROR" })

    try {
        $r = Find-LapsADExtendedRights -Identity $targetOU -ErrorAction SilentlyContinue
        Write-Status "OU permissions" $(if ($r) { "OK" } else { "WARN" })
    } catch { Write-Status "OU permissions check" "WARN" }

    $g = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    Write-Status "GPO" $(if ($g) { "OK" } else { "ERROR" })

    Write-Host ""
    Write-Host "  Deployment complete!" -ForegroundColor Green
    Write-Host "  Next: gpupdate /force on a test machine, then check event log Microsoft-Windows-LAPS/Operational" -ForegroundColor Yellow

    Pause-Screen
}

# ██████████████████████████████████████████████████████████████████
#  3. MIGRATION
# ██████████████████████████████████████████████████████████████████

function Invoke-Migration {
    while ($true) {
        Write-Banner
        $choice = Show-Menu "Migration: Legacy LAPS → Windows LAPS" @(
            "Pre-migration assessment (readiness check)"
            "Schema update & prepare emulation mode"
            "Validate pilot machines"
            "Switch to Windows LAPS native mode"
            "Clean up Legacy LAPS"
            "Run all phases sequentially"
        ) -AllowBack

        switch ($choice) {
            "1" { Invoke-MigrationPreCheck }
            "2" { Invoke-MigrationSchemaEmulation }
            "3" { Invoke-MigrationValidatePilot }
            "4" { Invoke-MigrationSwitchNative }
            "5" { Invoke-MigrationCleanup }
            "6" { Invoke-MigrationAll }
            "0" { return }
            default { continue }
        }
    }
}

function Invoke-MigrationPreCheck {
    $targetOU = Read-Param "Target OU (DN)" -Mandatory

    Write-Banner
    Write-Section "Phase 1: Pre-Migration Assessment"

    # Legacy schema
    if ($script:HasLegacySchema) {
        Write-Status "Legacy LAPS schema present" "OK"
    } else {
        Write-Status "Legacy LAPS schema NOT found" "ERROR" "Nothing to migrate"
        Pause-Screen; return
    }

    # Windows LAPS schema
    if ($script:HasWLAPSSchema) {
        Write-Status "Windows LAPS schema present" "OK"
    } else {
        Write-Status "Windows LAPS schema NOT present" "INFO" "Will be added in Phase 2"
    }

    # GPO detection
    $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
    $detected = @()
    foreach ($gpo in $allGPOs) {
        try {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
            if ($report -match "AdmPwd" -and $report -match "Microsoft Services") { $detected += $gpo }
        } catch { }
    }
    if ($detected.Count -gt 0) {
        Write-Status "Legacy LAPS GPOs detected: $($detected.Count)" "OK"
        foreach ($g in $detected) { Write-Host "           → $($g.DisplayName)" -ForegroundColor DarkGray }
    } else {
        Write-Status "No Legacy LAPS GPOs detected" "WARN"
    }

    # Computers
    $pcs = Get-ADComputer -Filter * -SearchBase $targetOU -Properties "ms-Mcs-AdmPwd", "OperatingSystem", "Enabled" -ErrorAction SilentlyContinue
    $withPwd = @($pcs | Where-Object { $_.'ms-Mcs-AdmPwd' })
    $enabledPcs = @($pcs | Where-Object Enabled)
    $eligible = @($enabledPcs | Where-Object { $_.OperatingSystem -match "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025" })
    $notElig = $enabledPcs.Count - $eligible.Count

    Write-Status "Computers: $($pcs.Count) total, $($enabledPcs.Count) enabled" "INFO"
    Write-Status "With Legacy LAPS password: $($withPwd.Count)" $(if ($withPwd.Count -gt 0) { "OK" } else { "WARN" })
    Write-Status "OS eligible: $($eligible.Count)" "OK"
    if ($notElig -gt 0) {
        Write-Status "OS NOT eligible: $notElig" "WARN" "Need Legacy LAPS until upgraded"
    }

    # LAPS module & DFL
    Write-Status "LAPS module" $(if ($script:LAPSModuleAvailable) { "OK" } else { "WARN" }) $(if (-not $script:LAPSModuleAvailable) { "Required for next phases" })
    Write-Status "DFL: $($script:Domain.DomainMode)" $(if ($script:DFLSupportsEncryption) { "OK" } else { "WARN" }) $(if ($script:DFLSupportsEncryption) { "Encryption supported" } else { "No encryption" })

    # Verdict
    Write-Host ""
    $ready = $script:HasLegacySchema -and ($withPwd.Count -gt 0 -or $detected.Count -gt 0) -and $script:LAPSModuleAvailable
    if ($ready) {
        Write-Status "READY for migration" "OK" "→ Proceed to Phase 2"
    } else {
        Write-Status "NOT READY" "WARN"
        if (-not $script:LAPSModuleAvailable) { Write-Host "    - LAPS module missing" -ForegroundColor Yellow }
        if ($withPwd.Count -eq 0 -and $detected.Count -eq 0) { Write-Host "    - No Legacy LAPS found — deploy Windows LAPS directly" -ForegroundColor Yellow }
    }

    Write-Host ""
    Write-Host "  Tip: Use Quick Tools > [6] to check which machines have the Legacy CSE installed." -ForegroundColor DarkGray

    Pause-Screen
}

function Invoke-MigrationSchemaEmulation {
    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS module required" "ERROR"; Pause-Screen; return
    }

    $targetOU = Read-Param "Target OU (DN)" -Mandatory

    Write-Banner
    Write-Section "Phase 2: Schema Update & Emulation Mode"

    # Schema
    if ($script:HasWLAPSSchema) {
        Write-Status "Windows LAPS schema already present" "OK"
    } else {
        if (Confirm-Action "Update AD schema with Windows LAPS attributes?") {
            Write-Status "Running Update-LapsADSchema..." "RUN"
            try {
                Update-LapsADSchema -Verbose -ErrorAction Stop
                Write-Status "Schema updated" "OK"
                $script:HasWLAPSSchema = $true
            } catch {
                Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                Pause-Screen; return
            }
        } else { Pause-Screen; return }
    }

    # SELF permissions
    Write-Status "Setting SELF write permission on $targetOU..." "RUN"
    try {
        Set-LapsADComputerSelfPermission -Identity $targetOU -ErrorAction Stop
        Write-Status "SELF write permission set" "OK"
    } catch {
        if ($_.Exception.Message -match "already") { Write-Status "Already exists" "OK" }
        else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
    }

    Write-Host ""
    Write-Host "  ─── Emulation Mode Ready ───" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps to activate emulation mode:" -ForegroundColor Yellow
    Write-Host "  1. UNINSTALL the Legacy LAPS CSE (AdmPwd.dll MSI) from pilot machines" -ForegroundColor White
    Write-Host "  2. Windows LAPS (built into the OS) will take over automatically" -ForegroundColor White
    Write-Host "  3. It reads the existing Legacy LAPS GPO and writes to ms-Mcs-AdmPwd" -ForegroundColor White
    Write-Host ""
    Write-Host "  IMPORTANT: If the Legacy CSE is still installed, Windows LAPS will NOT activate!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  After uninstalling the CSE and running gpupdate, use Phase 3 to validate." -ForegroundColor DarkGray

    Pause-Screen
}

function Invoke-MigrationValidatePilot {
    $targetOU = Read-Param "Pilot OU (DN)" -Mandatory

    Write-Banner
    Write-Section "Phase 3: Pilot Validation"

    $props = @("Name", "Enabled", "OperatingSystem")
    if ($script:HasLegacySchema) { $props += "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" }
    if ($script:HasWLAPSSchema)  { $props += "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-PasswordExpirationTime" }

    $pcs = @(Get-ADComputer -Filter { Enabled -eq $true } -SearchBase $targetOU -Properties $props -ErrorAction SilentlyContinue)
    Write-Status "Enabled computers: $($pcs.Count)" "INFO"

    $results = @()
    foreach ($pc in $pcs) {
        $status = "No LAPS"
        if ($pc.'msLAPS-EncryptedPassword')  { $status = "Windows LAPS (Encrypted)" }
        elseif ($pc.'msLAPS-Password')       { $status = "Windows LAPS (Clear)" }
        elseif ($pc.'ms-Mcs-AdmPwd')         { $status = "Legacy LAPS / Emulation" }
        $results += [PSCustomObject]@{ Name = $pc.Name; OS = $pc.OperatingSystem; Status = $status }
    }

    $grouped = $results | Group-Object Status
    Write-Host ""
    foreach ($g in $grouped) {
        $color = switch ($g.Name) {
            "No LAPS"                     { "Red" }
            "Legacy LAPS / Emulation"     { "Yellow" }
            "Windows LAPS (Clear)"        { "DarkYellow" }
            "Windows LAPS (Encrypted)"    { "Green" }
            default { "White" }
        }
        Write-Host "  $($g.Name): $($g.Count)" -ForegroundColor $color
    }

    Write-Host ""
    foreach ($g in $grouped) {
        Write-Host "  ── $($g.Name) ──" -ForegroundColor DarkGray
        $g.Group | Select-Object -First 10 | ForEach-Object { Write-Host "     $($_.Name) ($($_.OS))" -ForegroundColor DarkGray }
        if ($g.Count -gt 10) { Write-Host "     ... and $($g.Count - 10) more" -ForegroundColor DarkGray }
    }

    $wlCount = ($results | Where-Object { $_.Status -match "Windows LAPS" }).Count
    $noCount = ($results | Where-Object { $_.Status -eq "No LAPS" }).Count
    Write-Host ""
    if ($wlCount -gt 0 -and $noCount -eq 0) {
        Write-Status "All computers covered" "OK" "Ready for Phase 4"
    } elseif ($wlCount -gt 0) {
        Write-Status "Mixed — some machines still without LAPS" "WARN"
    } else {
        Write-Status "No Windows LAPS passwords yet" "WARN" "Ensure Legacy CSE is uninstalled + gpupdate"
    }

    Pause-Screen
}

function Invoke-MigrationSwitchNative {
    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS module required" "ERROR"; Pause-Screen; return
    }

    $targetOU  = Read-Param "Target OU (DN)" -Mandatory
    $readGroup = Read-Param "Read/Reset group (DOMAIN\Group)" -Mandatory
    $gpoName   = Read-Param "GPO name" -Default "Windows LAPS Policy"
    $pwdLen    = [int](Read-Param "Password length" -Default "20")
    $pwdAge    = [int](Read-Param "Password age (days)" -Default "30")
    $postAuth  = [int](Read-Param "Post-auth delay (hours)" -Default "8")

    Write-Banner
    Write-Section "Phase 4: Switch to Native Mode"

    if (-not (Confirm-Action "Switch $targetOU to Windows LAPS native mode?")) {
        Pause-Screen; return
    }

    # Permissions
    foreach ($op in @(
        @{ Cmd = { Set-LapsADReadPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Read permission" },
        @{ Cmd = { Set-LapsADResetPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Reset permission" }
    )) {
        Write-Status "Setting $($op.Desc)..." "RUN"
        try { & $op.Cmd; Write-Status $op.Desc "OK" }
        catch {
            if ($_.Exception.Message -match "already") { Write-Status "$($op.Desc) — already set" "OK" }
            else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
        }
    }

    # GPO
    $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-GPO -Name $gpoName -Comment "Windows LAPS native — Invoke-LAPSToolkit.ps1" | Out-Null
        Write-Status "GPO created: $gpoName" "OK"
    } else { Write-Status "GPO '$gpoName' exists — updating" "INFO" }

    $reg = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $enc = if ($script:DFLSupportsEncryption) { 1 } else { 0 }

    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "BackupDirectory" -Type DWord -Value 2 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordComplexity" -Type DWord -Value 4 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordLength" -Type DWord -Value $pwdLen | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordAgeDays" -Type DWord -Value $pwdAge | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value $enc | Out-Null
    if ($enc) { Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADPasswordEncryptionPrincipal" -Type String -Value $readGroup | Out-Null }
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PostAuthenticationActions" -Type DWord -Value 3 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PostAuthenticationResetDelay" -Type DWord -Value $postAuth | Out-Null

    Write-Status "GPO configured (encryption=$($enc -eq 1))" "OK"

    # Link
    try {
        $gpoObj = Get-GPO -Name $gpoName
        $links = Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue
        if ($links.GpoLinks | Where-Object { $_.GpoId -eq $gpoObj.Id }) {
            Write-Status "GPO already linked" "OK"
        } else {
            New-GPLink -Guid $gpoObj.Id -Target $targetOU -LinkEnabled Yes | Out-Null
            Write-Status "GPO linked to $targetOU" "OK"
        }
    } catch { Write-Status "Link failed: $($_.Exception.Message)" "ERROR" }

    Write-Host ""
    Write-Host "  Native mode activated!" -ForegroundColor Green
    Write-Host "  Passwords will now be stored in msLAPS-EncryptedPassword." -ForegroundColor DarkGray
    Write-Host "  → Validate with Phase 3, then clean up with Phase 5." -ForegroundColor Yellow

    Pause-Screen
}

function Invoke-MigrationCleanup {
    $targetOU = Read-Param "Target OU (DN)" -Mandatory

    Write-Banner
    Write-Section "Phase 5: Legacy LAPS Cleanup"

    if (-not (Confirm-Action "Clean up Legacy LAPS in $targetOU ?")) {
        Pause-Screen; return
    }

    # Detect & unlink Legacy GPOs
    Write-Host ""
    Write-Host "  ── Legacy GPO Detection ──" -ForegroundColor Yellow

    $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
    $inheritance = Get-GPInheritance -Target $targetOU -ErrorAction SilentlyContinue
    $legacyLinked = @()

    foreach ($link in $inheritance.GpoLinks) {
        try {
            $report = Get-GPOReport -Guid $link.GpoId -ReportType Xml -ErrorAction SilentlyContinue
            if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                $gpoName = ($allGPOs | Where-Object { $_.Id -eq $link.GpoId }).DisplayName
                $legacyLinked += @{ Id = $link.GpoId; Name = $gpoName }
            }
        } catch { }
    }

    if ($legacyLinked.Count -gt 0) {
        foreach ($lg in $legacyLinked) {
            Write-Status "Found Legacy GPO: $($lg.Name)" "WARN"
            if (Confirm-Action "Unlink '$($lg.Name)' from $targetOU ?") {
                try {
                    Remove-GPLink -Guid $lg.Id -Target $targetOU -ErrorAction Stop
                    Write-Status "Unlinked: $($lg.Name)" "OK"
                } catch { Write-Status "Failed to unlink: $($_.Exception.Message)" "WARN" }
            }
        }
    } else {
        Write-Status "No Legacy LAPS GPOs linked to this OU" "OK"
    }

    # Clear Legacy attributes
    Write-Host ""
    Write-Host "  ── Legacy Attribute Cleanup ──" -ForegroundColor Yellow

    $pcsWithLegacy = @(Get-ADComputer -Filter * -SearchBase $targetOU `
        -Properties "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" -ErrorAction SilentlyContinue |
        Where-Object { $_.'ms-Mcs-AdmPwd' })

    if ($pcsWithLegacy.Count -gt 0) {
        Write-Status "$($pcsWithLegacy.Count) computers with Legacy attributes" "INFO"
        if (Confirm-Action "Clear Legacy LAPS attributes on these $($pcsWithLegacy.Count) computers?") {
            $cleared = 0
            foreach ($pc in $pcsWithLegacy) {
                try {
                    Set-ADComputer -Identity $pc -Clear 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' -ErrorAction Stop
                    $cleared++
                } catch {
                    Write-Status "Failed on $($pc.Name): $($_.Exception.Message)" "WARN"
                }
            }
            Write-Status "Cleared attributes on $cleared/$($pcsWithLegacy.Count) computers" "OK"
        }
    } else {
        Write-Status "No Legacy LAPS attributes to clear" "OK"
    }

    # Legacy ACE Cleanup
    Write-Host ""
    Write-Host "  ── Legacy LAPS ACE Cleanup ──" -ForegroundColor Yellow

    if (Confirm-Action "Scan for Legacy LAPS ACEs on OUs under $targetOU ?") {
        $schemaNC    = (Get-ADRootDSE).schemaNamingContext
        $guidAdmPwd  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwd" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID
        $guidExpiry  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwdExpirationTime" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID

        if (-not $guidAdmPwd) {
            Write-Status "Legacy LAPS schema attributes not found — nothing to scan" "INFO"
        } else {
            $guidAdmPwdGuid = [Guid]$guidAdmPwd
            $guidExpiryGuid = [Guid]$guidExpiry

            $allOUs = @($targetOU)
            $allOUs += (Get-ADOrganizationalUnit -SearchBase $targetOU -Filter * -SearchScope Subtree).DistinguishedName

            Write-Status "Scanning $($allOUs.Count) OUs for Legacy LAPS ACEs..." "RUN"

            $totalDirect = 0; $totalInherited = 0
            foreach ($ouDN in $allOUs) {
                $acl = Get-Acl -Path "AD:\$ouDN"
                $legacyACEs = $acl.Access | Where-Object {
                    $_.ObjectType -eq $guidAdmPwdGuid -or $_.ObjectType -eq $guidExpiryGuid
                }
                if ($legacyACEs.Count -eq 0) { continue }

                $directACEs    = $legacyACEs | Where-Object { -not $_.IsInherited }
                $inheritedACEs = $legacyACEs | Where-Object { $_.IsInherited }

                if ($directACEs.Count -gt 0) {
                    Write-Host "`n  [$($directACEs.Count) DIRECT] $ouDN" -ForegroundColor Yellow
                    $directACEs |
                        Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights,
                            @{ Name = 'Attribute'; Expression = {
                                if ($_.ObjectType -eq $guidAdmPwdGuid) { 'ms-Mcs-AdmPwd' }
                                elseif ($_.ObjectType -eq $guidExpiryGuid) { 'ms-Mcs-AdmPwdExpirationTime' }
                                else { $_.ObjectType }
                            }} |
                        Format-Table -AutoSize | Out-String | Write-Host
                    $totalDirect += $directACEs.Count
                }
                if ($inheritedACEs.Count -gt 0) {
                    Write-Host "  [$($inheritedACEs.Count) INHERITED] $ouDN" -ForegroundColor DarkGray
                    $totalInherited += $inheritedACEs.Count
                }
            }

            Write-Host ""
            Write-Host "  --- Summary ---" -ForegroundColor White
            Write-Host "    Direct ACEs (removable):      $totalDirect" -ForegroundColor Yellow
            Write-Host "    Inherited ACEs (from parent):  $totalInherited" -ForegroundColor DarkGray
            if ($totalInherited -gt 0) {
                Write-Host "    Inherited ACEs disappear automatically when direct ACEs on parent are removed." -ForegroundColor DarkGray
            }

            if ($totalDirect -gt 0 -and (Confirm-Action "Remove $totalDirect direct Legacy LAPS ACE(s)?")) {
                foreach ($ouDN in $allOUs) {
                    $acl = Get-Acl -Path "AD:\$ouDN"
                    $toRemove = $acl.Access | Where-Object {
                        ($_.ObjectType -eq $guidAdmPwdGuid -or $_.ObjectType -eq $guidExpiryGuid) -and -not $_.IsInherited
                    }
                    if ($toRemove.Count -gt 0) {
                        $toRemove | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
                        Set-Acl -Path "AD:\$ouDN" -AclObject $acl
                        Write-Status "Removed $($toRemove.Count) ACE(s) on $ouDN" "OK"
                    }
                }
            } elseif ($totalDirect -eq 0) {
                Write-Status "No direct Legacy LAPS ACEs found" "OK"
            }
        }
    }

    # Reminder
    Write-Host ""
    Write-Host "  ── Reminders ──" -ForegroundColor Yellow
    Write-Status "Uninstall the Legacy LAPS MSI (AdmPwd CSE) from all remaining clients" "INFO"
    Write-Host "  Options: SCCM / Intune app removal, GPO software uninstall, or manual" -ForegroundColor DarkGray
    Write-Host ""
    Write-Status "Legacy LAPS cleanup complete" "OK"

    Pause-Screen
}

function Invoke-MigrationAll {
    Write-Host "  Running all phases sequentially..." -ForegroundColor Yellow
    Write-Host ""

    Invoke-MigrationPreCheck
    if (-not (Confirm-Action "Continue to Phase 2?")) { return }
    Invoke-MigrationSchemaEmulation
    if (-not (Confirm-Action "Continue to Phase 3 (validate pilot)?")) { return }
    Invoke-MigrationValidatePilot
    if (-not (Confirm-Action "Continue to Phase 4 (switch to native)?")) { return }
    Invoke-MigrationSwitchNative
    if (-not (Confirm-Action "Continue to Phase 5 (cleanup)?")) { return }
    Invoke-MigrationCleanup
}

# ██████████████████████████████████████████████████████████████████
#  4. QUICK TOOLS
# ██████████████████████████████████████████████████████████████████

function Invoke-QuickTools {
    while ($true) {
        Write-Banner
        $choice = Show-Menu "Quick Tools" @(
            "Retrieve LAPS password for a computer"
            "Force password rotation (remote)"
            "Check LAPS event log (remote)"
            "Collect LAPS diagnostics (local)"
            "Audit OU extended rights"
            "Check Legacy CSE on remote machines"
            "Audit Legacy LAPS ACEs on OUs"
        ) -AllowBack

        switch ($choice) {
            "1" {
                $pc = Read-Param "Computer name" -Mandatory
                Write-Host ""
                try {
                    $pwd = Get-LapsADPassword -Identity $pc -AsPlainText -ErrorAction Stop
                    Write-Host "  Computer       : $($pwd.ComputerName)" -ForegroundColor White
                    Write-Host "  Account        : $($pwd.Account)" -ForegroundColor White
                    Write-Host "  Password       : $($pwd.Password)" -ForegroundColor Green
                    Write-Host "  Expiration     : $($pwd.ExpirationTimestamp)" -ForegroundColor White
                    Write-Host "  Source         : $($pwd.PasswordUpdateTime)" -ForegroundColor DarkGray
                } catch {
                    Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                    # Fallback to Legacy
                    if ($script:HasLegacySchema) {
                        try {
                            $legPwd = Get-ADComputer -Identity $pc -Properties "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" -ErrorAction Stop
                            if ($legPwd.'ms-Mcs-AdmPwd') {
                                Write-Host ""
                                Write-Status "Legacy LAPS password found:" "INFO"
                                Write-Host "  Password       : $($legPwd.'ms-Mcs-AdmPwd')" -ForegroundColor Green
                                $expiry = [datetime]::FromFileTime($legPwd.'ms-Mcs-AdmPwdExpirationTime')
                                Write-Host "  Expiration     : $expiry" -ForegroundColor White
                            }
                        } catch { }
                    }
                }
                Pause-Screen
            }
            "2" {
                $pc = Read-Param "Computer name" -Mandatory
                Write-Host ""
                try {
                    Reset-LapsPassword -Identity $pc -ErrorAction Stop
                    Write-Status "Password rotation triggered on $pc" "OK"
                } catch {
                    Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                    Write-Host "  Note: Reset-LapsPassword runs locally. Use Invoke-Command for remote." -ForegroundColor DarkGray
                    if (Confirm-Action "Try via Invoke-Command (PSRemoting)?") {
                        try {
                            Invoke-Command -ComputerName $pc -ScriptBlock { Reset-LapsPassword } -ErrorAction Stop
                            Write-Status "Password rotation triggered remotely on $pc" "OK"
                        } catch {
                            Write-Status "Remote execution failed: $($_.Exception.Message)" "ERROR"
                        }
                    }
                }
                Pause-Screen
            }
            "3" {
                $pc = Read-Param "Computer name" -Mandatory
                Write-Host ""
                try {
                    $events = Invoke-Command -ComputerName $pc -ScriptBlock {
                        Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 20 -ErrorAction SilentlyContinue
                    } -ErrorAction Stop
                    if ($events) {
                        $events | Format-Table TimeCreated, Id, Message -Wrap | Out-String | Write-Host
                    } else {
                        Write-Status "No LAPS events found on $pc" "INFO"
                    }
                } catch {
                    Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                }
                Pause-Screen
            }
            "4" {
                Write-Host ""
                try {
                    Get-LapsDiagnostics -ErrorAction Stop
                    Write-Status "Diagnostics collected" "OK"
                } catch {
                    Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                }
                Pause-Screen
            }
            "5" {
                $ou = Read-Param "OU distinguished name" -Mandatory
                Write-Host ""
                if ($script:LAPSModuleAvailable) {
                    try {
                        $rights = Find-LapsADExtendedRights -Identity $ou -ErrorAction Stop
                        if ($rights) {
                            foreach ($r in $rights) {
                                Write-Host "  OU: $($r.ObjectDN)" -ForegroundColor Cyan
                                Write-Host "  Holders: $($r.ExtendedRightHolders -join ', ')" -ForegroundColor White
                                Write-Host ""
                            }
                        } else {
                            Write-Status "No extended rights found on $ou" "WARN"
                        }
                    } catch {
                        Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                    }
                } else {
                    Write-Status "LAPS module required for this check" "ERROR"
                }
                Pause-Screen
            }
            "6" {
                $searchBase = Read-Param "Search base OU (DN)" -Mandatory
                Write-Host ""
                Write-Host "  Querying computers and checking Legacy CSE via PSRemoting..." -ForegroundColor DarkGray
                Write-Host "  (Requires WinRM/PSRemoting enabled on target machines)" -ForegroundColor DarkGray
                Write-Host ""

                try {
                    $dcList = (Get-ADDomainController -Filter *).Name
                    $adComputers = Get-ADComputer -Filter * -SearchBase $searchBase -Properties DistinguishedName |
                        Where-Object { $_.Name -notin $dcList }

                    $ouLookup = @{}
                    $adComputers | ForEach-Object {
                        $ouLookup[$_.Name] = $_.DistinguishedName -replace '^CN=[^,]+,'
                    }

                    $computers = $adComputers.Name
                    Write-Status "Found $($computers.Count) computers (DCs excluded)" "INFO"

                    if ($computers.Count -eq 0) {
                        Write-Status "No computers found in $searchBase" "WARN"
                    } else {
                        $results = Invoke-Command -ComputerName $computers -ScriptBlock {
                            [PSCustomObject]@{
                                Computer           = $env:COMPUTERNAME
                                LegacyCSEInstalled = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"
                            }
                        } -ErrorAction SilentlyContinue | Select-Object Computer, LegacyCSEInstalled

                        $reached     = @($results.Computer)
                        $unreachable = $computers | Where-Object { $_ -notin $reached }
                        $unreachable | ForEach-Object {
                            $results += [PSCustomObject]@{ Computer = $_; LegacyCSEInstalled = [char]0x26A0 + ' Unreachable' }
                        }

                        Write-Host ""
                        $results |
                            Select-Object Computer,
                                @{ Name = 'OU'; Expression = { $ouLookup[$_.Computer] } },
                                LegacyCSEInstalled |
                            Sort-Object OU, Computer |
                            ForEach-Object {
                                $color = switch ("$($_.LegacyCSEInstalled)") {
                                    'True'  { 'Green'  }
                                    'False' { 'Yellow' }
                                    default { 'Red'    }
                                }
                                Write-Host ("  {0,-20} {1,-55} " -f $_.Computer, $_.OU) -NoNewline
                                Write-Host $_.LegacyCSEInstalled -ForegroundColor $color
                            }

                        $cseCount     = @($results | Where-Object { "$($_.LegacyCSEInstalled)" -eq 'True' }).Count
                        $noCseCount   = @($results | Where-Object { "$($_.LegacyCSEInstalled)" -eq 'False' }).Count
                        $unreachCount = @($unreachable).Count
                        Write-Host ""
                        Write-Status "CSE installed: $cseCount | Not installed: $noCseCount | Unreachable: $unreachCount" "INFO"
                    }
                } catch {
                    Write-Status "Failed: $($_.Exception.Message)" "ERROR"
                }
                Pause-Screen
            }
            "7" {
                $rootOU = Read-Param "Root OU to scan (DN)" -Mandatory
                Write-Host ""

                $schemaNC    = (Get-ADRootDSE).schemaNamingContext
                $guidAdmPwd  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwd" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID
                $guidExpiry  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwdExpirationTime" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID

                if (-not $guidAdmPwd) {
                    Write-Status "Legacy LAPS schema attributes not found — nothing to scan" "INFO"
                    Pause-Screen; continue
                }

                $guidAdmPwdGuid = [Guid]$guidAdmPwd
                $guidExpiryGuid = [Guid]$guidExpiry

                $allOUs = @($rootOU)
                $allOUs += (Get-ADOrganizationalUnit -SearchBase $rootOU -Filter * -SearchScope Subtree).DistinguishedName

                Write-Status "Scanning $($allOUs.Count) OUs for Legacy LAPS ACEs..." "RUN"

                $totalDirect = 0; $totalInherited = 0
                foreach ($ouDN in $allOUs) {
                    $acl = Get-Acl -Path "AD:\$ouDN"
                    $legacyACEs = $acl.Access | Where-Object {
                        $_.ObjectType -eq $guidAdmPwdGuid -or $_.ObjectType -eq $guidExpiryGuid
                    }
                    if ($legacyACEs.Count -eq 0) { continue }

                    $directACEs    = $legacyACEs | Where-Object { -not $_.IsInherited }
                    $inheritedACEs = $legacyACEs | Where-Object { $_.IsInherited }

                    if ($directACEs.Count -gt 0) {
                        Write-Host "`n  [$($directACEs.Count) DIRECT] $ouDN" -ForegroundColor Yellow
                        $directACEs |
                            Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights,
                                @{ Name = 'Attribute'; Expression = {
                                    if ($_.ObjectType -eq $guidAdmPwdGuid) { 'ms-Mcs-AdmPwd' }
                                    elseif ($_.ObjectType -eq $guidExpiryGuid) { 'ms-Mcs-AdmPwdExpirationTime' }
                                    else { $_.ObjectType }
                                }} |
                            Format-Table -AutoSize | Out-String | Write-Host
                        $totalDirect += $directACEs.Count
                    }
                    if ($inheritedACEs.Count -gt 0) {
                        Write-Host "  [$($inheritedACEs.Count) INHERITED] $ouDN" -ForegroundColor DarkGray
                        $totalInherited += $inheritedACEs.Count
                    }
                }

                Write-Host ""
                Write-Host "  --- Summary ---" -ForegroundColor White
                Write-Host "    Direct ACEs (removable):      $totalDirect" -ForegroundColor Yellow
                Write-Host "    Inherited ACEs (from parent):  $totalInherited" -ForegroundColor DarkGray
                if ($totalInherited -gt 0) {
                    Write-Host "    Inherited ACEs disappear automatically when direct ACEs on parent are removed." -ForegroundColor DarkGray
                }
                if ($totalDirect -eq 0) {
                    Write-Status "No direct Legacy LAPS ACEs found" "OK"
                } else {
                    Write-Status "$totalDirect direct ACE(s) found — use Migration > Phase 5 to remove them" "WARN"
                }
                Pause-Screen
            }
            "0" { return }
            default { continue }
        }
    }
}

# ██████████████████████████████████████████████████████████████████
#  MAIN MENU LOOP
# ██████████████████████████████████████████████████████████████████

Initialize-Toolkit

while ($true) {
    Write-Banner

    # Status line
    $schemaStatus = @()
    if ($script:HasLegacySchema) { $schemaStatus += "Legacy" }
    if ($script:HasWLAPSSchema)  { $schemaStatus += "Windows LAPS" }
    if ($schemaStatus.Count -eq 0) { $schemaStatus = @("None") }

    Write-Host "  Schema : $($schemaStatus -join ' + ')" -ForegroundColor $(if ($script:HasWLAPSSchema) { "Green" } elseif ($script:HasLegacySchema) { "Yellow" } else { "Red" })
    Write-Host "  DFL    : $($script:Domain.DomainMode) $(if ($script:DFLSupportsEncryption) { '(encryption OK)' } else { '(no encryption)' })" -ForegroundColor $(if ($script:DFLSupportsEncryption) { "Green" } else { "Yellow" })
    Write-Host "  LAPS   : $(if ($script:LAPSModuleAvailable) { 'Module loaded' } else { 'Module NOT available' })" -ForegroundColor $(if ($script:LAPSModuleAvailable) { "Green" } else { "Yellow" })

    $choice = Show-Menu "Main Menu" @(
        "Assessment — Full audit of current LAPS state"
        "Deployment — Deploy Windows LAPS from scratch"
        "Migration  — Legacy LAPS → Windows LAPS (guided)"
        "Quick Tools — Password retrieval, rotation, diagnostics"
        "Exit"
    )

    switch ($choice) {
        "1" { Invoke-Assessment }
        "2" { Invoke-Deployment }
        "3" { Invoke-Migration }
        "4" { Invoke-QuickTools }
        "5" { Write-Host "  Bye!" -ForegroundColor Cyan; exit 0 }
        default { continue }
    }
}
