<#
.SYNOPSIS
    Windows LAPS - Automated Deployment Tool

.DESCRIPTION
    Automates the deployment of Windows LAPS in an Active Directory environment:
    - Updates the AD schema with Windows LAPS attributes
    - Configures SELF write permissions on target OUs
    - Delegates read/reset permissions to an admin group
    - Creates and links a Windows LAPS GPO with best-practice settings
    - Validates the deployment

.NOTES
    Version:    1.0
    Author:     Tech-Blog
    Requires:   ActiveDirectory module, GroupPolicy module, LAPS module, Schema Admin (for schema update)
    Run As:     Schema Admin + Domain Admin

.EXAMPLE
    .\Deploy-WindowsLAPS.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers"
    .\Deploy-WindowsLAPS.ps1 -TargetOU "OU=Servers,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Admins" -PasswordLength 24 -PasswordAgeDays 15
    .\Deploy-WindowsLAPS.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -SkipSchemaUpdate -SkipGPO
#>

#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Target OU distinguished name for LAPS deployment.")]
    [string]$TargetOU,

    [Parameter(Mandatory = $true, HelpMessage = "AD group allowed to read and reset LAPS passwords (DOMAIN\\Group format).")]
    [string]$ReadGroup,

    [Parameter(HelpMessage = "GPO name to create. Default: 'Windows LAPS Policy'.")]
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

    [Parameter(HelpMessage = "Enable password encryption (requires DFL 2016+). Default: true.")]
    [bool]$EnableEncryption = $true,

    [Parameter(HelpMessage = "Custom local admin account name. Leave empty for built-in administrator.")]
    [string]$AdminAccountName = "",

    [Parameter(HelpMessage = "Skip AD schema update (if already done).")]
    [switch]$SkipSchemaUpdate,

    [Parameter(HelpMessage = "Skip GPO creation (permissions only).")]
    [switch]$SkipGPO
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
    }
    Write-Host $Message -ForegroundColor White -NoNewline
    if ($Detail) {
        Write-Host " — $Detail" -ForegroundColor DarkGray
    } else {
        Write-Host ""
    }
}

# ==================================================================
# Banner
# ==================================================================

Write-Host ""
Write-Host "  Windows LAPS - Automated Deployment" -ForegroundColor Cyan
Write-Host "  =====================================" -ForegroundColor DarkCyan
Write-Host ""

# ==================================================================
# Pre-flight Checks
# ==================================================================
Write-Section "Pre-flight Checks"

# Modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Step "ActiveDirectory module" "OK"
} catch {
    Write-Step "ActiveDirectory module not found" "ERROR" "Install RSAT"
    return
}

try {
    Import-Module GroupPolicy -ErrorAction Stop
    Write-Step "GroupPolicy module" "OK"
} catch {
    Write-Step "GroupPolicy module not found" "ERROR" "Install RSAT"
    return
}

try {
    Import-Module LAPS -ErrorAction Stop
    Write-Step "LAPS module" "OK"
} catch {
    Write-Step "LAPS module not found" "ERROR" "Windows LAPS module is required (available on patched Windows 10/11/Server)"
    return
}

# Verify target OU exists
try {
    $ouObj = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
    Write-Step "Target OU exists" "OK" $TargetOU
} catch {
    Write-Step "Target OU not found" "ERROR" $TargetOU
    return
}

# Verify read group exists
try {
    $groupName = $ReadGroup -replace '^[^\\]+\\', ''
    $groupObj = Get-ADGroup -Identity $groupName -ErrorAction Stop
    Write-Step "Read/Reset group exists: $($groupObj.Name)" "OK" "SID: $($groupObj.SID)"
} catch {
    Write-Step "Group not found: $ReadGroup" "ERROR" "Create the group first"
    return
}

# DFL check for encryption
$domain = Get-ADDomain
$dfl = $domain.DomainMode
$dflSupportsEncryption = $dfl -match "2016|2019|2022|2025"

if ($EnableEncryption -and -not $dflSupportsEncryption) {
    Write-Step "DFL: $dfl — encryption NOT supported" "WARN" "Disabling encryption (requires DFL 2016+)"
    $EnableEncryption = $false
} else {
    Write-Step "DFL: $dfl" "OK" $(if ($dflSupportsEncryption) { "Encryption supported" } else { "Encryption not available" })
}

# Show config summary
Write-Host ""
Write-Host "  Configuration Summary:" -ForegroundColor Yellow
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Target OU            : $TargetOU" -ForegroundColor White
Write-Host "  Read/Reset Group     : $ReadGroup" -ForegroundColor White
Write-Host "  GPO Name             : $GPOName" -ForegroundColor White
Write-Host "  Password Length      : $PasswordLength" -ForegroundColor White
Write-Host "  Password Age (days)  : $PasswordAgeDays" -ForegroundColor White
Write-Host "  Post-Auth Delay (h)  : $PostAuthResetDelayHours" -ForegroundColor White
Write-Host "  Encryption           : $EnableEncryption" -ForegroundColor White
Write-Host "  Admin Account        : $(if ($AdminAccountName) { $AdminAccountName } else { '(built-in administrator)' })" -ForegroundColor White
Write-Host "  Schema Update        : $(if ($SkipSchemaUpdate) { 'SKIP' } else { 'YES' })" -ForegroundColor White
Write-Host "  GPO Creation         : $(if ($SkipGPO) { 'SKIP' } else { 'YES' })" -ForegroundColor White
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("Deploy Windows LAPS to $TargetOU", "Deploy Windows LAPS")) {
    Write-Step "Deployment cancelled by user." "INFO"
    return
}

# ==================================================================
# Step 1 — Schema Update
# ==================================================================
Write-Section "Step 1: AD Schema Update"

if ($SkipSchemaUpdate) {
    Write-Step "Schema update skipped per parameter" "SKIP"
    # Verify schema attributes exist
    $schemaNC = (Get-ADRootDSE).schemaNamingContext
    $wlapsCheck = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "msLAPS-Password" } -ErrorAction SilentlyContinue
    if ($wlapsCheck) {
        Write-Step "Windows LAPS schema attributes verified" "OK"
    } else {
        Write-Step "Windows LAPS schema attributes NOT found" "ERROR" "Run without -SkipSchemaUpdate"
        return
    }
} else {
    Write-Step "Running Update-LapsADSchema..." "RUN"
    try {
        Update-LapsADSchema -ErrorAction Stop
        Write-Step "AD schema updated successfully" "OK"
    } catch {
        if ($_.Exception.Message -match "already exists|already been applied") {
            Write-Step "Schema already up to date" "OK"
        } else {
            Write-Step "Schema update failed: $($_.Exception.Message)" "ERROR"
            Write-Host "  Make sure you are running as Schema Admin." -ForegroundColor Yellow
            return
        }
    }
}

# ==================================================================
# Step 2 — OU Permissions
# ==================================================================
Write-Section "Step 2: OU Permissions"

# SELF permission (computer writes its own password)
Write-Step "Setting SELF write permission on $TargetOU..." "RUN"
try {
    Set-LapsADComputerSelfPermission -Identity $TargetOU -ErrorAction Stop
    Write-Step "SELF write permission set" "OK"
} catch {
    if ($_.Exception.Message -match "already") {
        Write-Step "SELF write permission already exists" "OK"
    } else {
        Write-Step "Failed to set SELF permission: $($_.Exception.Message)" "ERROR"
        return
    }
}

# Read permission for admin group
Write-Step "Granting read permission to $ReadGroup..." "RUN"
try {
    Set-LapsADReadPasswordPermission -Identity $TargetOU -AllowedPrincipals $ReadGroup -ErrorAction Stop
    Write-Step "Read permission granted" "OK"
} catch {
    if ($_.Exception.Message -match "already") {
        Write-Step "Read permission already exists" "OK"
    } else {
        Write-Step "Failed to set read permission: $($_.Exception.Message)" "ERROR"
        return
    }
}

# Reset permission for admin group
Write-Step "Granting reset permission to $ReadGroup..." "RUN"
try {
    Set-LapsADResetPasswordPermission -Identity $TargetOU -AllowedPrincipals $ReadGroup -ErrorAction Stop
    Write-Step "Reset permission granted" "OK"
} catch {
    if ($_.Exception.Message -match "already") {
        Write-Step "Reset permission already exists" "OK"
    } else {
        Write-Step "Failed to set reset permission: $($_.Exception.Message)" "ERROR"
        return
    }
}

# ==================================================================
# Step 3 — GPO Creation & Configuration
# ==================================================================
Write-Section "Step 3: GPO Creation & Configuration"

if ($SkipGPO) {
    Write-Step "GPO creation skipped per parameter" "SKIP"
} else {
    # Check if GPO already exists
    $existingGPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Step "GPO '$GPOName' already exists" "WARN" "Updating settings"
        $gpo = $existingGPO
    } else {
        Write-Step "Creating GPO '$GPOName'..." "RUN"
        $gpo = New-GPO -Name $GPOName -Comment "Windows LAPS Policy — deployed by Deploy-WindowsLAPS.ps1"
        Write-Step "GPO created: $($gpo.DisplayName)" "OK" "GUID: $($gpo.Id)"
    }

    # Configure LAPS registry settings via GPO
    # Windows LAPS GPO settings are stored under:
    # HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS

    $regPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"

    # BackupDirectory: 2 = Active Directory, 1 = Azure AD, 0 = Disabled
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "BackupDirectory" -Type DWord -Value 2 | Out-Null
    Write-Step "BackupDirectory = Active Directory" "OK"

    # PasswordComplexity: 4 = Large+Small+Numbers+Specials
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordComplexity" -Type DWord -Value 4 | Out-Null
    Write-Step "PasswordComplexity = Large+Small+Numbers+Specials" "OK"

    # PasswordLength
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordLength" -Type DWord -Value $PasswordLength | Out-Null
    Write-Step "PasswordLength = $PasswordLength" "OK"

    # PasswordAgeDays
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PasswordAgeDays" -Type DWord -Value $PasswordAgeDays | Out-Null
    Write-Step "PasswordAgeDays = $PasswordAgeDays" "OK"

    # PasswordEncryptionEnabled
    $encValue = if ($EnableEncryption) { 1 } else { 0 }
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "ADPasswordEncryptionEnabled" -Type DWord -Value $encValue | Out-Null
    Write-Step "ADPasswordEncryptionEnabled = $EnableEncryption" "OK"

    # Password encrypted principal (decryptor group)
    if ($EnableEncryption) {
        Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "ADPasswordEncryptionPrincipal" -Type String -Value $ReadGroup | Out-Null
        Write-Step "ADPasswordEncryptionPrincipal = $ReadGroup" "OK"
    }

    # PostAuthenticationActions: 3 = Reset password + logoff, 1 = Reset password, 5 = Reset password + reboot
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PostAuthenticationActions" -Type DWord -Value 3 | Out-Null
    Write-Step "PostAuthenticationActions = Reset password + logoff" "OK"

    # PostAuthenticationResetDelay (in hours)
    Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "PostAuthenticationResetDelay" -Type DWord -Value $PostAuthResetDelayHours | Out-Null
    Write-Step "PostAuthenticationResetDelay = $PostAuthResetDelayHours hours" "OK"

    # Administrator account name
    if ($AdminAccountName) {
        Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "AdministratorAccountName" -Type String -Value $AdminAccountName | Out-Null
        Write-Step "AdministratorAccountName = $AdminAccountName" "OK"
    }

    # Link GPO to target OU
    Write-Step "Linking GPO to $TargetOU..." "RUN"
    try {
        $existingLink = Get-GPInheritance -Target $TargetOU -ErrorAction SilentlyContinue
        $alreadyLinked = $existingLink.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }

        if ($alreadyLinked) {
            Write-Step "GPO already linked to target OU" "OK"
        } else {
            New-GPLink -Guid $gpo.Id -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Step "GPO linked to $TargetOU" "OK"
        }
    } catch {
        Write-Step "Failed to link GPO: $($_.Exception.Message)" "ERROR"
    }
}

# ==================================================================
# Step 4 — Validation
# ==================================================================
Write-Section "Step 4: Validation"

# Verify schema
$schemaNC = (Get-ADRootDSE).schemaNamingContext
$wlapsCheck = Get-ADObject -SearchBase $schemaNC -Filter { lDAPDisplayName -eq "msLAPS-EncryptedPassword" } -ErrorAction SilentlyContinue
if ($wlapsCheck) {
    Write-Step "Schema attributes present" "OK"
} else {
    Write-Step "Schema attributes missing" "ERROR"
}

# Verify OU permissions
try {
    $rights = Find-LapsADExtendedRights -Identity $TargetOU -ErrorAction SilentlyContinue
    if ($rights) {
        Write-Step "Extended rights configured on OU" "OK"
    } else {
        Write-Step "No extended rights found on OU" "WARN"
    }
} catch {
    Write-Step "Could not verify OU permissions" "WARN"
}

# Verify GPO
if (-not $SkipGPO) {
    $gpoCheck = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($gpoCheck) {
        Write-Step "GPO '$GPOName' exists and configured" "OK"
    } else {
        Write-Step "GPO not found" "ERROR"
    }
}

# ==================================================================
# Done
# ==================================================================
Write-Host ""
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host "  Deployment complete!" -ForegroundColor Green
Write-Host " ================================================================" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Yellow
Write-Host "  1. Run 'gpupdate /force' on a test machine in $TargetOU" -ForegroundColor White
Write-Host "  2. Check event log: Microsoft-Windows-LAPS/Operational" -ForegroundColor White
Write-Host "  3. Retrieve password: Get-LapsADPassword -Identity 'TESTPC' -AsPlainText" -ForegroundColor White
Write-Host ""
