<#
.SYNOPSIS
    Legacy LAPS to Windows LAPS - Guided Migration Tool

.DESCRIPTION
    Provides a step-by-step migration from Legacy LAPS (MSI-based) to Windows LAPS:
    - Phase 1: Pre-migration assessment and readiness checks
    - Phase 2: Schema preparation and emulation mode setup
    - Phase 3: Pilot validation
    - Phase 4: Switch to Windows LAPS native mode
    - Phase 5: Legacy LAPS cleanup

    Each phase can be run independently with the -Phase parameter.

.NOTES
    Version:    1.0
    Author:     Tech-Blog
    Requires:   ActiveDirectory module, GroupPolicy module, LAPS module
    Run As:     Domain Admin (Schema Admin for Phase 2)

.EXAMPLE
    .\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase PreCheck
    .\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase SchemaAndEmulation
    .\Invoke-LAPSMigration.ps1 -TargetOU "OU=Pilot,OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase ValidatePilot
    .\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase SwitchToNative
    .\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -Phase CleanupLegacy
#>

#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Target OU distinguished name.")]
    [string]$TargetOU,

    [Parameter(HelpMessage = "AD group allowed to read/reset LAPS passwords (DOMAIN\\Group).")]
    [string]$ReadGroup,

    [Parameter(Mandatory = $true, HelpMessage = "Migration phase to execute.")]
    [ValidateSet("PreCheck", "SchemaAndEmulation", "ValidatePilot", "SwitchToNative", "CleanupLegacy", "All")]
    [string]$Phase,

    [Parameter(HelpMessage = "GPO name for Windows LAPS. Default: 'Windows LAPS Policy'.")]
    [string]$GPOName = "Windows LAPS Policy",

    [Parameter(HelpMessage = "Password length (default: 20).")]
    [ValidateRange(12, 64)]
    [int]$PasswordLength = 20,

    [Parameter(HelpMessage = "Password age in days (default: 30).")]
    [ValidateRange(1, 365)]
    [int]$PasswordAgeDays = 30,

    [Parameter(HelpMessage = "Post-authentication reset delay in hours (default: 8).")]
    [ValidateRange(1, 24)]
    [int]$PostAuthResetDelayHours = 8,

    [Parameter(HelpMessage = "Name of the Legacy LAPS GPO to detect/clean.")]
    [string]$LegacyGPOName
)

# ==================================================================
# Helpers
# ==================================================================

$ErrorActionPreference = 'Stop'

function Write-Section ([string]$Title) {
    Write-Host ""
    Write-Host " ================================================================" -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host " ================================================================" -ForegroundColor DarkCyan
}

function Write-Step ([string]$Message, [string]$Status, [string]$Detail = "") {
    switch ($Status) {
        "OK"      { Write-Host "  [OK]    " -ForegroundColor Green -NoNewline }
        "WARN"    { Write-Host "  [!!]    " -ForegroundColor Yellow -NoNewline }
        "ERROR"   { Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline }
        "INFO"    { Write-Host "  [~]     " -ForegroundColor DarkGray -NoNewline }
        "RUN"     { Write-Host "  [>>]    " -ForegroundColor Cyan -NoNewline }
        "SKIP"    { Write-Host "  [--]    " -ForegroundColor DarkGray -NoNewline }
        "PHASE"   { Write-Host "  [**]    " -ForegroundColor Magenta -NoNewline }
    }
    Write-Host $Message -ForegroundColor White -NoNewline
    if ($Detail) {
        Write-Host " — $Detail" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
}

function Write-PhaseHeader ([string]$PhaseNum, [string]$Title) {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║  Phase $PhaseNum: $Title$((' ' * (49 - $Title.Length - $PhaseNum.Length)))║" -ForegroundColor Magenta
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
}

# ==================================================================
# Banner
# ==================================================================

Write-Host ""
Write-Host "  Legacy LAPS → Windows LAPS Migration Tool" -ForegroundColor Cyan
Write-Host "  ============================================" -ForegroundColor DarkCyan
Write-Host ""

# ==================================================================
# Module Checks
# ==================================================================

try { Import-Module ActiveDirectory -ErrorAction Stop } catch {
    Write-Step "ActiveDirectory module not found" "ERROR" "Install RSAT"
    return
}

try { Import-Module GroupPolicy -ErrorAction Stop } catch {
    Write-Step "GroupPolicy module not found" "ERROR" "Install RSAT"
    return
}

$LAPSModuleAvailable = $false
try {
    Import-Module LAPS -ErrorAction Stop
    $LAPSModuleAvailable = $true
} catch { }

# Verify target OU
try {
    Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop | Out-Null
} catch {
    Write-Step "Target OU not found: $TargetOU" "ERROR"
    return
}

$domain = Get-ADDomain
$schemaNC = (Get-ADRootDSE).schemaNamingContext

# ██████████████████████████████████████████████████████████████████
# PHASE 1: PRE-CHECK
# ██████████████████████████████████████████████████████████████████

function Invoke-PreCheck {
    Write-PhaseHeader "1" "Pre-Migration Assessment"

    $readiness = @{
        LegacySchema    = $false
        LegacyGPO       = $false
        LegacyPasswords = 0
        WLAPSSchema     = $false
        OSReady         = 0
        OSNotReady      = 0
    }

    # Check Legacy LAPS schema
    $legacyAttr = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "ms-Mcs-AdmPwd" } -ErrorAction SilentlyContinue
    if ($legacyAttr) {
        Write-Step "Legacy LAPS schema present" "OK"
        $readiness.LegacySchema = $true
    } else {
        Write-Step "Legacy LAPS schema NOT found" "ERROR" "Nothing to migrate — deploy Windows LAPS directly"
        return $readiness
    }

    # Check Windows LAPS schema
    $wlapsAttr = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "msLAPS-Password" } -ErrorAction SilentlyContinue
    if ($wlapsAttr) {
        Write-Step "Windows LAPS schema present" "OK"
        $readiness.WLAPSSchema = $true
    } else {
        Write-Step "Windows LAPS schema NOT present" "INFO" "Will be added in Phase 2"
    }

    # Detect Legacy LAPS GPOs
    $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
    $detectedLegacyGPOs = @()
    foreach ($gpo in $allGPOs) {
        try {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
            if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                $detectedLegacyGPOs += $gpo
            }
        } catch { }
    }

    if ($detectedLegacyGPOs.Count -gt 0) {
        Write-Step "Legacy LAPS GPOs detected: $($detectedLegacyGPOs.Count)" "OK"
        foreach ($g in $detectedLegacyGPOs) {
            Write-Host "           → $($g.DisplayName)" -ForegroundColor DarkGray
        }
        $readiness.LegacyGPO = $true
    } else {
        Write-Step "No Legacy LAPS GPOs detected" "WARN" "Legacy LAPS may not be actively managed by GPO"
    }

    # Count computers with Legacy LAPS passwords
    $computers = Get-ADComputer -Filter * -SearchBase $TargetOU `
        -Properties "ms-Mcs-AdmPwd", "OperatingSystem", "OperatingSystemVersion", "Enabled" -ErrorAction SilentlyContinue

    $withLegacyPwd = @($computers | Where-Object { $_.'ms-Mcs-AdmPwd' })
    $enabled = @($computers | Where-Object Enabled)
    $readiness.LegacyPasswords = $withLegacyPwd.Count

    Write-Step "Computers in target OU: $($computers.Count) (enabled: $($enabled.Count))" "INFO"
    Write-Step "Computers with Legacy LAPS password: $($withLegacyPwd.Count)" $(if ($withLegacyPwd.Count -gt 0) { "OK" } else { "WARN" })

    # OS eligibility
    $eligible = 0
    $notEligible = 0
    foreach ($pc in ($computers | Where-Object Enabled)) {
        $os = $pc.OperatingSystem
        if ($os -match "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025") {
            $eligible++
        } else {
            $notEligible++
        }
    }
    $readiness.OSReady = $eligible
    $readiness.OSNotReady = $notEligible

    Write-Step "OS eligible for Windows LAPS: $eligible" "OK"
    if ($notEligible -gt 0) {
        Write-Step "OS NOT eligible: $notEligible" "WARN" "These machines will need Legacy LAPS until upgraded"
        $computers | Where-Object { $_.Enabled -and $_.OperatingSystem -notmatch "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025" } |
            Group-Object OperatingSystem | ForEach-Object {
                Write-Host "           → $($_.Name): $($_.Count)" -ForegroundColor DarkGray
            }
    }

    # LAPS module
    if ($LAPSModuleAvailable) {
        Write-Step "LAPS PowerShell module available" "OK"
    } else {
        Write-Step "LAPS PowerShell module NOT available" "WARN" "Required for Phase 2+"
    }

    # DFL
    $dfl = $domain.DomainMode
    if ($dfl -match "2016|2019|2022|2025") {
        Write-Step "DFL: $dfl — encryption supported" "OK"
    } else {
        Write-Step "DFL: $dfl — no encryption support" "WARN" "Passwords will be stored in clear text"
    }

    # Summary
    Write-Host ""
    Write-Host "  ─── Migration Readiness ───" -ForegroundColor Yellow
    $ready = $readiness.LegacySchema -and ($readiness.LegacyPasswords -gt 0 -or $readiness.LegacyGPO) -and $LAPSModuleAvailable
    if ($ready) {
        Write-Step "READY for migration" "OK" "Proceed with Phase 2: SchemaAndEmulation"
    } else {
        Write-Step "NOT READY for migration" "WARN"
        if (-not $readiness.LegacySchema) { Write-Host "    - Legacy LAPS schema not found" -ForegroundColor Yellow }
        if (-not $LAPSModuleAvailable) { Write-Host "    - LAPS PowerShell module missing (patch Windows)" -ForegroundColor Yellow }
        if ($readiness.LegacyPasswords -eq 0 -and -not $readiness.LegacyGPO) { Write-Host "    - No Legacy LAPS deployment found — deploy Windows LAPS directly" -ForegroundColor Yellow }
    }

    return $readiness
}

# ██████████████████████████████████████████████████████████████████
# PHASE 2: SCHEMA UPDATE & EMULATION MODE
# ██████████████████████████████████████████████████████████████████

function Invoke-SchemaAndEmulation {
    Write-PhaseHeader "2" "Schema Update & Emulation Mode"

    if (-not $LAPSModuleAvailable) {
        Write-Step "LAPS module required for this phase" "ERROR"
        return
    }

    # Update schema if needed
    $wlapsAttr = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "msLAPS-Password" } -ErrorAction SilentlyContinue
    if ($wlapsAttr) {
        Write-Step "Windows LAPS schema already present" "OK" "Skipping schema update"
    } else {
        if ($PSCmdlet.ShouldProcess("AD Schema", "Add Windows LAPS attributes")) {
            Write-Step "Updating AD schema with Windows LAPS attributes..." "RUN"
            try {
                Update-LapsADSchema -ErrorAction Stop
                Write-Step "Schema updated successfully" "OK"
            } catch {
                Write-Step "Schema update failed: $($_.Exception.Message)" "ERROR"
                return
            }
        }
    }

    # Set SELF permissions
    Write-Step "Setting SELF write permission on $TargetOU..." "RUN"
    try {
        Set-LapsADComputerSelfPermission -Identity $TargetOU -ErrorAction Stop
        Write-Step "SELF write permission configured" "OK"
    } catch {
        if ($_.Exception.Message -match "already") {
            Write-Step "SELF write permission already exists" "OK"
        } else {
            Write-Step "Failed: $($_.Exception.Message)" "ERROR"
            return
        }
    }

    Write-Host ""
    Write-Host "  ─── Emulation Mode ───" -ForegroundColor Yellow
    Write-Step "AD schema ready + SELF permissions set" "OK"
    Write-Host ""
    Write-Host "  How emulation mode works:" -ForegroundColor White
    Write-Host "  - The Legacy LAPS CSE (AdmPwd.dll) must be UNINSTALLED from pilot machines" -ForegroundColor DarkGray
    Write-Host "  - Once uninstalled, Windows LAPS (built into the OS) takes over automatically" -ForegroundColor DarkGray
    Write-Host "  - If no Windows LAPS GPO exists, it reads the Legacy LAPS GPO settings" -ForegroundColor DarkGray
    Write-Host "  - It writes passwords to the Legacy ms-Mcs-AdmPwd attribute" -ForegroundColor DarkGray
    Write-Host "  - IMPORTANT: If the Legacy CSE is still installed, Windows LAPS will NOT activate" -ForegroundColor Yellow
    Write-Host ""
    Write-Step "Next: Uninstall Legacy LAPS CSE on pilot machines, then run Phase 'ValidatePilot'" "INFO"
}

# ██████████████████████████████████████████████████████████████████
# PHASE 3: VALIDATE PILOT
# ██████████████████████████████████████████████████████████████████

function Invoke-ValidatePilot {
    Write-PhaseHeader "3" "Pilot Validation"

    Write-Host ""
    Write-Host "  Checking computers in $TargetOU for LAPS status..." -ForegroundColor DarkGray

    $properties = @("Name", "Enabled", "OperatingSystem")
    if ((Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "ms-Mcs-AdmPwd" } -ErrorAction SilentlyContinue)) {
        $properties += "ms-Mcs-AdmPwd"
        $properties += "ms-Mcs-AdmPwdExpirationTime"
    }
    if ((Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "msLAPS-Password" } -ErrorAction SilentlyContinue)) {
        $properties += "msLAPS-Password"
        $properties += "msLAPS-EncryptedPassword"
        $properties += "msLAPS-PasswordExpirationTime"
    }

    $computers = @(Get-ADComputer -Filter { Enabled -eq $true } -SearchBase $TargetOU `
        -Properties $properties -ErrorAction SilentlyContinue)

    Write-Step "Enabled computers found: $($computers.Count)" "INFO"

    $results = @()
    foreach ($pc in $computers) {
        $legacyPwd  = $pc.'ms-Mcs-AdmPwd'
        $wlapsPwd   = $pc.'msLAPS-Password'
        $wlapsEnc   = $pc.'msLAPS-EncryptedPassword'

        $status = "No LAPS"
        if ($wlapsEnc) { $status = "Windows LAPS (Encrypted)" }
        elseif ($wlapsPwd) { $status = "Windows LAPS (Clear)" }
        elseif ($legacyPwd) { $status = "Legacy LAPS / Emulation" }

        $results += [PSCustomObject]@{
            Name   = $pc.Name
            OS     = $pc.OperatingSystem
            Status = $status
        }
    }

    # Display summary
    $grouped = $results | Group-Object Status

    Write-Host ""
    foreach ($group in $grouped) {
        $color = switch ($group.Name) {
            "No LAPS"                     { "Red" }
            "Legacy LAPS / Emulation"     { "Yellow" }
            "Windows LAPS (Clear)"        { "DarkYellow" }
            "Windows LAPS (Encrypted)"    { "Green" }
            default                       { "White" }
        }
        Write-Host "  $($group.Name): $($group.Count)" -ForegroundColor $color
    }

    # Show first few computers per status
    Write-Host ""
    foreach ($group in $grouped) {
        Write-Host "  ── $($group.Name) ──" -ForegroundColor DarkGray
        $group.Group | Select-Object -First 10 | ForEach-Object {
            Write-Host "     $($_.Name) ($($_.OS))" -ForegroundColor DarkGray
        }
        if ($group.Count -gt 10) {
            Write-Host "     ... and $($group.Count - 10) more" -ForegroundColor DarkGray
        }
    }

    # Recommendation
    Write-Host ""
    $wlapsCount = ($results | Where-Object { $_.Status -match "Windows LAPS" }).Count
    $legacyCount = ($results | Where-Object { $_.Status -match "Legacy" }).Count
    $noCount = ($results | Where-Object { $_.Status -eq "No LAPS" }).Count

    if ($wlapsCount -gt 0 -and $noCount -eq 0) {
        Write-Step "All computers have LAPS passwords" "OK" "Ready for Phase 4: SwitchToNative"
    } elseif ($wlapsCount -gt 0) {
        Write-Step "Mixed state — some computers still missing LAPS" "WARN"
        Write-Host "  Run 'gpupdate /force' on machines without LAPS, check event logs." -ForegroundColor Yellow
    } else {
        Write-Step "No Windows LAPS passwords detected yet" "WARN"
        Write-Host "  Emulation mode may need time. Run 'gpupdate /force' on pilot machines." -ForegroundColor Yellow
        Write-Host "  Check event log: Microsoft-Windows-LAPS/Operational" -ForegroundColor Yellow
    }
}

# ██████████████████████████████████████████████████████████████████
# PHASE 4: SWITCH TO NATIVE MODE
# ██████████████████████████████████████████████████████████████████

function Invoke-SwitchToNative {
    Write-PhaseHeader "4" "Switch to Windows LAPS Native Mode"

    if (-not $ReadGroup) {
        Write-Step "-ReadGroup parameter is required for this phase" "ERROR"
        return
    }

    if (-not $LAPSModuleAvailable) {
        Write-Step "LAPS module required for this phase" "ERROR"
        return
    }

    $dfl = $domain.DomainMode
    $enableEnc = $dfl -match "2016|2019|2022|2025"

    if (-not $PSCmdlet.ShouldProcess("$TargetOU", "Switch to Windows LAPS native mode (new GPO, encryption=$enableEnc)")) {
        return
    }

    # Set read/reset permissions
    Write-Step "Configuring read permission for $ReadGroup..." "RUN"
    try {
        Set-LapsADReadPasswordPermission -Identity $TargetOU -AllowedPrincipals $ReadGroup -ErrorAction Stop
        Write-Step "Read permission set" "OK"
    } catch {
        if ($_.Exception.Message -match "already") { Write-Step "Read permission already exists" "OK" }
        else { Write-Step "Failed: $($_.Exception.Message)" "ERROR"; return }
    }

    Write-Step "Configuring reset permission for $ReadGroup..." "RUN"
    try {
        Set-LapsADResetPasswordPermission -Identity $TargetOU -AllowedPrincipals $ReadGroup -ErrorAction Stop
        Write-Step "Reset permission set" "OK"
    } catch {
        if ($_.Exception.Message -match "already") { Write-Step "Reset permission already exists" "OK" }
        else { Write-Step "Failed: $($_.Exception.Message)" "ERROR"; return }
    }

    # Create / update Windows LAPS GPO
    $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Step "GPO '$GPOName' already exists — updating" "INFO"
    } else {
        Write-Step "Creating GPO '$GPOName'..." "RUN"
        New-GPO -Name $GPOName -Comment "Windows LAPS native mode — deployed by Invoke-LAPSMigration.ps1" | Out-Null
        Write-Step "GPO created" "OK"
    }

    $regPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"

    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "BackupDirectory" -Type DWord -Value 2 | Out-Null
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordComplexity" -Type DWord -Value 4 | Out-Null
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordLength" -Type DWord -Value $PasswordLength | Out-Null
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordAgeDays" -Type DWord -Value $PasswordAgeDays | Out-Null

    $encValue = if ($enableEnc) { 1 } else { 0 }
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value $encValue | Out-Null
    if ($enableEnc) {
        Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "ADPasswordEncryptionPrincipal" -Type String -Value $ReadGroup | Out-Null
    }

    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PostAuthenticationActions" -Type DWord -Value 3 | Out-Null
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PostAuthenticationResetDelay" -Type DWord -Value $PostAuthResetDelayHours | Out-Null

    Write-Step "GPO configured with native Windows LAPS settings" "OK"
    Write-Step "Encryption: $enableEnc" $(if ($enableEnc) { "OK" } else { "WARN" })

    # Link GPO
    try {
        $existingLink = Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue
        $gpoObj = Get-GPO -Name $GPOName
        $alreadyLinked = $existingLink.GpoLinks | Where-Object { $_.GpoId -eq $gpoObj.Id }

        if ($alreadyLinked) {
            Write-Step "GPO already linked to $TargetOU" "OK"
        } else {
            New-GPLink -Guid $gpoObj.Id -Target $TargetOU -LinkEnabled Yes | Out-Null
            Write-Step "GPO linked to $TargetOU" "OK"
        }
    } catch {
        Write-Step "Failed to link GPO: $($_.Exception.Message)" "ERROR"
    }

    Write-Host ""
    Write-Host "  ─── Native Mode Activated ───" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Windows LAPS will now:" -ForegroundColor White
    Write-Host "  - Use its OWN GPO settings (not Legacy)" -ForegroundColor DarkGray
    Write-Host "  - Store passwords in msLAPS-EncryptedPassword (if encryption on)" -ForegroundColor DarkGray
    Write-Host "  - Stop writing to ms-Mcs-AdmPwd" -ForegroundColor DarkGray
    Write-Host ""
    Write-Step "Next: Validate with Phase 'ValidatePilot', then Phase 'CleanupLegacy'" "INFO"
}

# ██████████████████████████████████████████████████████████████████
# PHASE 5: CLEANUP LEGACY LAPS
# ██████████████████████████████████████████████████████████████████

function Invoke-CleanupLegacy {
    Write-PhaseHeader "5" "Legacy LAPS Cleanup"

    if (-not $PSCmdlet.ShouldProcess("$TargetOU", "Clean up Legacy LAPS (unlink GPO, clear attributes)")) {
        return
    }

    # 1. Find and unlink Legacy LAPS GPOs
    Write-Host ""
    Write-Host "  ── Legacy GPO Cleanup ──" -ForegroundColor Yellow

    if ($LegacyGPOName) {
        $legacyGpo = Get-GPO -Name $LegacyGPOName -ErrorAction SilentlyContinue
        if ($legacyGpo) {
            # Check if linked to target OU
            try {
                $links = Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue
                $linked = $links.GpoLinks | Where-Object { $_.GpoId -eq $legacyGpo.Id }
                if ($linked) {
                    Remove-GPLink -Guid $legacyGpo.Id -Target $TargetOU -ErrorAction Stop
                    Write-Step "Unlinked Legacy GPO '$LegacyGPOName' from $TargetOU" "OK"
                } else {
                    Write-Step "Legacy GPO '$LegacyGPOName' was not linked to $TargetOU" "INFO"
                }
            } catch {
                Write-Step "Failed to unlink Legacy GPO: $($_.Exception.Message)" "WARN"
            }
        } else {
            Write-Step "Legacy GPO '$LegacyGPOName' not found" "INFO"
        }
    } else {
        # Auto-detect Legacy LAPS GPOs linked to OU
        $allGPOs = Get-GPO -All -ErrorAction SilentlyContinue
        $inheritance = Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue

        foreach ($link in $inheritance.GpoLinks) {
            try {
                $report = Get-GPOReport -Guid $link.GpoId -ReportType Xml -ErrorAction SilentlyContinue
                if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                    $gpoName = ($allGPOs | Where-Object { $_.Id -eq $link.GpoId }).DisplayName
                    Write-Step "Detected Legacy LAPS GPO: $gpoName" "WARN"
                    Write-Host "           Use -LegacyGPOName '$gpoName' to unlink it" -ForegroundColor Yellow
                }
            } catch { }
        }
    }

    # 2. Clear Legacy LAPS attributes on computers
    Write-Host ""
    Write-Host "  ── Legacy Attribute Cleanup ──" -ForegroundColor Yellow

    $computers = @(Get-ADComputer -Filter * -SearchBase $TargetOU `
        -Properties "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" -ErrorAction SilentlyContinue |
        Where-Object { $_.'ms-Mcs-AdmPwd' })

    if ($computers.Count -gt 0) {
        Write-Step "Computers with Legacy LAPS attributes to clear: $($computers.Count)" "INFO"

        foreach ($pc in $computers) {
            try {
                Set-ADComputer -Identity $pc -Clear 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' -ErrorAction Stop
            } catch {
                Write-Step "Failed to clear attributes on $($pc.Name): $($_.Exception.Message)" "WARN"
            }
        }
        Write-Step "Legacy LAPS attributes cleared on $($computers.Count) computers" "OK"
    } else {
        Write-Step "No computers with Legacy LAPS attributes found" "OK" "Already clean"
    }

    # 3. Reminder about Legacy LAPS MSI
    Write-Host ""
    Write-Host "  ── Legacy LAPS CSE (MSI) ──" -ForegroundColor Yellow
    Write-Step "Remember to uninstall the Legacy LAPS MSI from all clients" "INFO"
    Write-Host "  Options:" -ForegroundColor DarkGray
    Write-Host "  - SCCM / Intune application removal" -ForegroundColor DarkGray
    Write-Host "  - GPO software uninstall" -ForegroundColor DarkGray
    Write-Host "  - Manual: Get-WmiObject Win32_Product | Where { `$_.Name -like '*LAPS*' } | Invoke-Method Uninstall" -ForegroundColor DarkGray

    Write-Host ""
    Write-Step "Legacy LAPS cleanup complete" "OK"
}

# ==================================================================
# Phase Router
# ==================================================================

switch ($Phase) {
    "PreCheck" {
        Invoke-PreCheck
    }
    "SchemaAndEmulation" {
        Invoke-SchemaAndEmulation
    }
    "ValidatePilot" {
        Invoke-ValidatePilot
    }
    "SwitchToNative" {
        Invoke-SwitchToNative
    }
    "CleanupLegacy" {
        Invoke-CleanupLegacy
    }
    "All" {
        $result = Invoke-PreCheck
        if ($result.LegacySchema -and $LAPSModuleAvailable) {
            Write-Host ""
            Write-Host "  Press Enter to continue to Phase 2, or Ctrl+C to abort..." -ForegroundColor Yellow
            Read-Host

            Invoke-SchemaAndEmulation

            Write-Host ""
            Write-Host "  Press Enter to validate pilot, or Ctrl+C to abort..." -ForegroundColor Yellow
            Read-Host

            Invoke-ValidatePilot

            Write-Host ""
            Write-Host "  Press Enter to switch to native mode, or Ctrl+C to abort..." -ForegroundColor Yellow
            Read-Host

            Invoke-SwitchToNative

            Write-Host ""
            Write-Host "  Press Enter to clean up Legacy LAPS, or Ctrl+C to abort..." -ForegroundColor Yellow
            Read-Host

            Invoke-CleanupLegacy
        }
    }
}

# ==================================================================
# Footer
# ==================================================================
Write-Host ""
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host "  Migration phase '$Phase' complete." -ForegroundColor Cyan
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host ""
