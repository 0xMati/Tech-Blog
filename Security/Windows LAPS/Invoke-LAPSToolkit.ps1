<#
.SYNOPSIS
    Windows LAPS Toolkit -- All-in-one Assessment, Deployment and Migration Tool

.DESCRIPTION
    Interactive menu-driven tool that consolidates all Windows LAPS operations:
      1. Assessment  -- Full audit of LAPS state (schema, GPOs, permissions, computer inventory)
      2. Deployment  -- Automated Windows LAPS deployment (schema, permissions, GPO)
      3. Migration   -- Guided Legacy LAPS to Windows LAPS migration (5 phases)
      4. Quick Tools -- Password retrieval, forced rotation, diagnostics

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
/_____/_/  |_/_/    /____/        Deployment and Migration

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
    if ($Detail) { Write-Host " -- $Detail" -ForegroundColor DarkGray }
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

function Read-OU ([string]$Label, [string]$Hint = "", [string]$Example = "", [switch]$AllowDomain) {
    Write-Host ""
    Write-Host "  $Label" -ForegroundColor Yellow
    if ($Hint) { Write-Host "  $Hint" -ForegroundColor DarkGray }
    if ($AllowDomain) {
        Write-Host "  Leave empty to target the entire domain: $($script:Domain.DistinguishedName)" -ForegroundColor DarkGray
    }
    if ($Example) { Write-Host "  Example: $Example" -ForegroundColor DarkGray }
    Write-Host ""
    $dn = Read-Host "  OU (distinguished name)"
    if (-not $dn -and $AllowDomain) { $dn = $script:Domain.DistinguishedName }
    if (-not $dn) { Write-Status "No OU specified." "ERROR"; return $null }
    if ($dn -eq $script:Domain.DistinguishedName) {
        Write-Status "Scope: entire domain" "OK"
        return $dn
    }
    try {
        Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop | Out-Null
        Write-Status "OU found: $dn" "OK"
        return $dn
    } catch {
        Write-Status "OU not found in Active Directory: $dn" "ERROR"
        return $null
    }
}

function Read-Group ([string]$Label, [string]$Hint = "") {
    Write-Host ""
    Write-Host "  $Label" -ForegroundColor Yellow
    if ($Hint) { Write-Host "  $Hint" -ForegroundColor DarkGray }
    Write-Host "  Format: DOMAIN\GroupName" -ForegroundColor DarkGray
    Write-Host "  Example: $($script:Domain.NetBIOSName)\LAPS-Admins" -ForegroundColor DarkGray
    Write-Host ""
    $grpInput = Read-Host "  Group"
    if (-not $grpInput) { Write-Status "No group specified." "ERROR"; return $null }
    $grpName = $grpInput -replace '^[^\\]+\\', ''
    try {
        Get-ADGroup -Identity $grpName -ErrorAction Stop | Out-Null
        Write-Status "Group found: $grpInput" "OK"
        return $grpInput
    } catch {
        Write-Status "Group not found in Active Directory: $grpInput" "ERROR"
        return $null
    }
}

function Read-Computer ([string]$Label, [string]$Hint = "") {
    Write-Host ""
    Write-Host "  $Label" -ForegroundColor Yellow
    if ($Hint) { Write-Host "  $Hint" -ForegroundColor DarkGray }
    Write-Host "  Enter the computer name (sAMAccountName without the trailing $)." -ForegroundColor DarkGray
    Write-Host ""
    $name = Read-Host "  Computer name"
    if (-not $name) { Write-Status "No computer specified." "ERROR"; return $null }
    try {
        $obj = Get-ADComputer -Identity $name -ErrorAction Stop
        Write-Status "Found: $($obj.Name) ($($obj.DNSHostName))" "OK"
        return $obj.Name
    } catch {
        Write-Host "  Computer '$name' not found in AD. Proceeding anyway." -ForegroundColor DarkYellow
        return $name
    }
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
    Write-Banner
    Write-Section "LAPS Assessment"
    Write-Host "  Full audit of your current LAPS deployment: schema, GPOs," -ForegroundColor DarkGray
    Write-Host "  permissions, and computer inventory with password status." -ForegroundColor DarkGray

    $searchBase = Read-OU -Label "Scope" -Hint "The OU to assess. Leave empty to scan the entire domain." -AllowDomain
    if (-not $searchBase) { $searchBase = $script:Domain.DistinguishedName }
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
        Write-Status "Windows LAPS schema attributes" "WARN" "Not present -- run Update-LapsADSchema -Verbose"
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

    # Map of Windows LAPS registry value names to friendly display names
    $lapsRegNames = @{
        'BackupDirectory'                   = 'Backup Directory'
        'PasswordComplexity'                = 'Password Complexity'
        'PasswordLength'                    = 'Password Length'
        'PasswordAgeDays'                   = 'Password Age (days)'
        'ADPasswordEncryptionEnabled'       = 'Encryption Enabled'
        'ADPasswordEncryptionPrincipal'     = 'Encryption Principal'
        'PostAuthenticationActions'          = 'Post-Auth Actions'
        'PostAuthenticationResetDelay'       = 'Post-Auth Delay (hours)'
        'AdministratorAccountName'           = 'Admin Account Name'
        'ADEncryptedPasswordHistorySize'    = 'Password History Size'
        'PasswordExpirationProtectionEnabled'= 'Expiration Protection'
        'AutomaticAccountManagementEnabled' = 'Auto Account Mgmt'
    }

    foreach ($gpo in $allGPOs) {
        try {
            $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction SilentlyContinue
            if (-not $report) { continue }

            # Detect Legacy LAPS GPO
            if ($report -match "AdmPwd" -and $report -match "Microsoft Services") {
                $legObj = [ordered]@{
                    Name = $gpo.DisplayName; Id = $gpo.Id.ToString()
                    Status = $gpo.GpoStatus.ToString(); Modified = $gpo.ModificationTime.ToString('yyyy-MM-dd HH:mm')
                    Created = $gpo.CreationTime.ToString('yyyy-MM-dd HH:mm')
                    LinkedOUs = ''
                }
                # Extract linked OUs from XML
                try {
                    $xml = [xml]$report
                    $ns = @{ gpo = 'http://www.microsoft.com/GroupPolicy/Settings' }
                    $links = $xml.GPO.LinksTo.SOMPath
                    if ($links) { $legObj.LinkedOUs = ($links -join '; ') }
                } catch { }
                $legacyGPOs += [PSCustomObject]$legObj
            }

            # Detect Windows LAPS GPO and parse settings
            if (($report -match "CurrentVersion\\LAPS" -or $report -match "CurrentVersion/LAPS" -or
                ($report -match "LAPS" -and $report -match "BackupDirectory")) -and
                ($report -notmatch "Microsoft Services.*AdmPwd" -or $report -match "BackupDirectory")) {

                $wlObj = [ordered]@{
                    Name = $gpo.DisplayName; Id = $gpo.Id.ToString()
                    Status = $gpo.GpoStatus.ToString(); Modified = $gpo.ModificationTime.ToString('yyyy-MM-dd HH:mm')
                    Created = $gpo.CreationTime.ToString('yyyy-MM-dd HH:mm')
                    LinkedOUs = ''
                }
                # Extract linked OUs
                try {
                    $xml = [xml]$report
                    $links = $xml.GPO.LinksTo.SOMPath
                    if ($links) { $wlObj.LinkedOUs = ($links -join '; ') }
                } catch { }
                # Parse registry values from GPO report
                try {
                    $regKey = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
                    $regValues = Get-GPRegistryValue -Guid $gpo.Id -Key $regKey -ErrorAction SilentlyContinue
                    foreach ($rv in $regValues) {
                        $friendly = if ($lapsRegNames.ContainsKey($rv.ValueName)) { $lapsRegNames[$rv.ValueName] } else { $rv.ValueName }
                        $wlObj[$friendly] = $rv.Value
                    }
                } catch { }
                # Fill missing settings with empty string for consistent CSV columns
                foreach ($fn in $lapsRegNames.Values) {
                    if (-not $wlObj.Contains($fn)) { $wlObj[$fn] = '' }
                }
                $wlapsGPOs += [PSCustomObject]$wlObj
            }
        } catch { }
    }

    if ($legacyGPOs.Count -gt 0) {
        Write-Status "Legacy LAPS GPOs: $($legacyGPOs.Count)" "INFO"
        foreach ($g in $legacyGPOs) {
            Write-Host "           -> $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray
            if ($g.LinkedOUs) { Write-Host "              Linked to: $($g.LinkedOUs)" -ForegroundColor DarkGray }
        }
    } else { Write-Status "No Legacy LAPS GPOs detected" "INFO" }

    if ($wlapsGPOs.Count -gt 0) {
        Write-Status "Windows LAPS GPOs: $($wlapsGPOs.Count)" "OK"
        foreach ($g in $wlapsGPOs) {
            Write-Host "           -> $($g.Name) (Modified: $($g.Modified))" -ForegroundColor DarkGray
            if ($g.LinkedOUs) { Write-Host "              Linked to: $($g.LinkedOUs)" -ForegroundColor DarkGray }
            $enc = $g.'Encryption Enabled'
            $dir = $g.'Backup Directory'
            $len = $g.'Password Length'
            $age = $g.'Password Age (days)'
            if ($dir -ne '') { Write-Host "              BackupDir=$dir  Encryption=$enc  Length=$len  Age=$age days" -ForegroundColor DarkGray }
        }
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
                            OU = $ou.DistinguishedName
                            Identity = $r.ExtendedRightHolders -join "; "
                        }
                    }
                }
            } catch { }
        }
        if ($ousWithRights.Count -gt 0) {
            Write-Status "OUs with LAPS extended rights: $($ousWithRights.Count)" "OK"
            $ousWithRights | Group-Object OU | ForEach-Object {
                Write-Host "           -> $($_.Name)" -ForegroundColor DarkGray
                foreach ($e in $_.Group) { Write-Host "              Holders: $($e.Identity)" -ForegroundColor DarkGray }
            }
        } else {
            Write-Status "No LAPS extended rights found" "WARN"
        }
    } else {
        Write-Status "LAPS module not available -- skipping detailed OU audit" "WARN"
    }

    # Scan ACLs for SELF write (LAPS computer self-permission) and Legacy ACEs
    $ouACLReport = @()
    # Get schema GUIDs for both Legacy and Windows LAPS attributes
    $guidLookup = @{}
    foreach ($attrName in @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
                             "ms-LAPS-Password", "ms-LAPS-EncryptedPassword",
                             "ms-LAPS-PasswordExpirationTime", "ms-LAPS-EncryptedPasswordHistory",
                             "ms-LAPS-EncryptedDSRMPassword", "ms-LAPS-EncryptedDSRMPasswordHistory")) {
        $obj = Get-ADObject -SearchBase $script:SchemaNC -Filter { name -eq $attrName } -Properties schemaIDGUID -ErrorAction SilentlyContinue
        if ($obj) { $guidLookup[([Guid]$obj.schemaIDGUID).ToString()] = $attrName }
    }

    if ($guidLookup.Count -gt 0) {
        Write-Host "  Scanning ACLs on $($OUs.Count) OUs for LAPS-related ACEs..." -ForegroundColor DarkGray
        foreach ($ou in $OUs) {
            try {
                $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    $objGuid = $ace.ObjectType.ToString()
                    if ($guidLookup.ContainsKey($objGuid)) {
                        $ouACLReport += [PSCustomObject]@{
                            OU                  = $ou.DistinguishedName
                            Identity            = $ace.IdentityReference.ToString()
                            Permission          = $ace.ActiveDirectoryRights.ToString()
                            AccessType          = $ace.AccessControlType.ToString()
                            Attribute           = $guidLookup[$objGuid]
                            IsLegacyAttr        = ($guidLookup[$objGuid] -match 'ms-Mcs-')
                            IsInherited         = $ace.IsInherited
                        }
                    }
                }
            } catch { }
        }
        if ($ouACLReport.Count -gt 0) {
            $legacyACECount = ($ouACLReport | Where-Object IsLegacyAttr).Count
            $wlapsACECount  = ($ouACLReport | Where-Object { -not $_.IsLegacyAttr }).Count
            Write-Status "LAPS ACEs found: $($ouACLReport.Count) total ($legacyACECount Legacy, $wlapsACECount Windows LAPS)" "INFO"
        }
    }

    # ── 5. Computer Inventory ──
    Write-Section "5. Computer Inventory and Password Status"

    $properties = @("Name", "OperatingSystem", "OperatingSystemVersion", "Enabled", "DistinguishedName", "LastLogonDate", "whenCreated", "Description")
    if ($script:HasLegacySchema) { $properties += "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime" }
    if ($script:HasWLAPSSchema)  { $properties += "msLAPS-PasswordExpirationTime", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword" }

    Write-Host "  Querying computers in $searchBase ..." -ForegroundColor DarkGray
    $computers = @(Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } -SearchBase $searchBase -Properties $properties -ErrorAction SilentlyContinue)
    Write-Host "  Found $($computers.Count) computer accounts." -ForegroundColor DarkGray

    $now = Get-Date
    $inventory = @()
    foreach ($pc in $computers) {
        $hasLegacy = $false; $hasWLAPS = $false; $hasWLAPSEnc = $false; $osOK = $false
        $hasHistory = $false; $hasDSRM = $false
        $legExpiry = $null; $wlExpiry = $null

        if ($script:HasLegacySchema -and $pc.'ms-Mcs-AdmPwd') { $hasLegacy = $true }
        if ($script:HasLegacySchema -and $pc.'ms-Mcs-AdmPwdExpirationTime') {
            try { $legExpiry = [datetime]::FromFileTime($pc.'ms-Mcs-AdmPwdExpirationTime') } catch { }
        }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-Password') { $hasWLAPS = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-EncryptedPassword') { $hasWLAPSEnc = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-EncryptedPasswordHistory') { $hasHistory = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-EncryptedDSRMPassword') { $hasDSRM = $true }
        if ($script:HasWLAPSSchema -and $pc.'msLAPS-PasswordExpirationTime') {
            try { $wlExpiry = [datetime]::FromFileTime($pc.'msLAPS-PasswordExpirationTime') } catch { }
        }

        if ($pc.OperatingSystem -match "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025") { $osOK = $true }

        $status = "No LAPS"
        if ($hasWLAPSEnc)  { $status = "Windows LAPS (Encrypted)" }
        elseif ($hasWLAPS) { $status = "Windows LAPS (Clear)" }
        elseif ($hasLegacy) { $status = "Legacy LAPS" }

        # Compute effective expiry and age
        $effectiveExpiry = if ($wlExpiry) { $wlExpiry } elseif ($legExpiry) { $legExpiry } else { $null }
        $isExpired = if ($effectiveExpiry) { $effectiveExpiry -lt $now } else { $null }
        $daysToExpiry = if ($effectiveExpiry) { [math]::Round(($effectiveExpiry - $now).TotalDays, 0) } else { $null }
        $isStale = ($isExpired -eq $true -and $daysToExpiry -ne $null -and $daysToExpiry -lt -90)
        $isDC = $pc.OperatingSystem -match "Server" -and $pc.DistinguishedName -match "OU=Domain Controllers"

        $inventory += [PSCustomObject]@{
            Name              = $pc.Name
            Enabled           = $pc.Enabled
            OS                = $pc.OperatingSystem
            OSVersion         = $pc.OperatingSystemVersion
            OSEligible        = $osOK
            IsDC              = $isDC
            Description       = $pc.Description
            OU                = ($pc.DistinguishedName -replace '^CN=[^,]+,', '')
            LAPSStatus        = $status
            LegacyPassword    = $hasLegacy
            WLAPSClearText    = $hasWLAPS
            WLAPSEncrypted    = $hasWLAPSEnc
            WLAPSHistory      = $hasHistory
            DSRM              = $hasDSRM
            LegacyExpiry      = if ($legExpiry) { $legExpiry.ToString('yyyy-MM-dd HH:mm') } else { '' }
            WLAPSExpiry       = if ($wlExpiry) { $wlExpiry.ToString('yyyy-MM-dd HH:mm') } else { '' }
            DaysToExpiry      = $daysToExpiry
            IsExpired         = $isExpired
            IsStale90d        = $isStale
            LastLogon         = if ($pc.LastLogonDate) { $pc.LastLogonDate.ToString('yyyy-MM-dd') } else { '' }
            AccountCreated    = if ($pc.whenCreated) { $pc.whenCreated.ToString('yyyy-MM-dd') } else { '' }
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

    $stale = ($inventory | Where-Object { $_.IsStale90d -eq $true }).Count
    if ($stale -gt 0) {
        Write-Host ""
        Write-Status "Stale passwords (90+ days expired): $stale" "WARN"
    }
    $withDSRM = ($inventory | Where-Object { $_.DSRM -eq $true }).Count
    if ($withDSRM -gt 0) {
        Write-Status "DSRM passwords managed: $withDSRM" "OK"
    }

    $nonElig = $inventory | Where-Object { -not $_.OSEligible -and $_.Enabled }
    if ($nonElig.Count -gt 0) {
        Write-Host ""
        Write-Status "Not eligible for Windows LAPS: $($nonElig.Count)" "WARN"
        $nonElig | Group-Object OS | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "           -> $($_.Name): $($_.Count)" -ForegroundColor DarkGray
        }
    }

    # ── 6. Summary ──
    Write-Section "6. Summary and Recommendations"
    Write-Host ""

    $hasLegGPO = $legacyGPOs.Count -gt 0
    $hasWGPO   = $wlapsGPOs.Count -gt 0

    if (-not $script:HasLegacySchema -and -not $script:HasWLAPSSchema) {
        Write-Status "NO LAPS deployment detected" "ERROR"
        Write-Host "  -> Deploy Windows LAPS from scratch using option [2] in the main menu" -ForegroundColor Yellow
    } elseif ($script:HasLegacySchema -and -not $script:HasWLAPSSchema) {
        Write-Status "LEGACY LAPS only -- migration recommended" "WARN"
        Write-Host "  -> Use option [3] in the main menu for guided migration" -ForegroundColor Yellow
    } elseif ($script:HasLegacySchema -and $hasLegGPO -and -not $hasWGPO) {
        Write-Status "Schema ready but still using Legacy GPO" "WARN"
        Write-Host "  -> Use option [3] to complete the migration" -ForegroundColor Yellow
    } elseif ($hasLegGPO -and $hasWGPO) {
        Write-Status "MIXED state -- both Legacy and Windows LAPS active" "WARN"
        Write-Host "  -> Use option [3] to finish transition and clean up Legacy" -ForegroundColor Yellow
    } elseif ($hasWGPO -and -not $hasLegGPO) {
        Write-Status "Windows LAPS deployed" "OK"
        if ($noLaps -gt 0) { Write-Host "  -> $noLaps computers still without LAPS -- check GPO scope" -ForegroundColor Yellow }
        if ($wlClear -gt 0) { Write-Host "  -> $wlClear computers with clear-text passwords -- enable encryption" -ForegroundColor Yellow }
    } else {
        Write-Status "Windows LAPS schema present but no GPO configured" "WARN"
        Write-Host "  -> Use option [2] to deploy" -ForegroundColor Yellow
    }

    # ── 7. CSV Export ──
    if ($exportCSV) {
        Write-Section "7. CSV Export"
        $dir = Join-Path (Get-Location) "LAPS-Assessment_$script:Timestamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        # Summary.csv -- global stats in one file
        $summaryData = [PSCustomObject][ordered]@{
            Domain                  = $script:Domain.DNSRoot
            DFL                     = $script:Domain.DomainMode
            EncryptionSupported     = $script:DFLSupportsEncryption
            LegacySchemaPresent     = $script:HasLegacySchema
            WindowsLAPSSchemaPresent= $script:HasWLAPSSchema
            LegacyGPOCount          = $legacyGPOs.Count
            WindowsLAPSGPOCount     = $wlapsGPOs.Count
            TotalComputers          = $inventory.Count
            EnabledComputers        = $enabled
            OSEligible              = $eligible
            NoLAPS                  = $noLaps
            LegacyLAPSOnly          = $legOnly
            WindowsLAPSClearText    = $wlClear
            WindowsLAPSEncrypted    = $wlEnc
            StalePasswords90d       = ($inventory | Where-Object { $_.IsStale90d -eq $true }).Count
            DSRMManaged             = ($inventory | Where-Object { $_.DSRM -eq $true }).Count
            OUsWithExtendedRights   = $ousWithRights.Count
            LegacyACEs              = if ($ouACLReport) { ($ouACLReport | Where-Object IsLegacyAttr).Count } else { 0 }
            WindowsLAPSACEs         = if ($ouACLReport) { ($ouACLReport | Where-Object { -not $_.IsLegacyAttr }).Count } else { 0 }
            AssessmentDate          = $now.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $summaryData | Export-Csv -Path (Join-Path $dir "Summary.csv") -NoTypeInformation -Encoding UTF8
        Write-Status "Summary.csv -- global assessment overview" "OK"

        if ($inventory.Count -gt 0) {
            $inventory | Export-Csv -Path (Join-Path $dir "Computers.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "Computers.csv -- $($inventory.Count) records, $((($inventory | Get-Member -MemberType NoteProperty).Count)) columns" "OK"
        }
        if ($legacyGPOs.Count -gt 0) {
            $legacyGPOs | Export-Csv -Path (Join-Path $dir "LegacyGPOs.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "LegacyGPOs.csv -- $($legacyGPOs.Count) GPOs with links and status" "OK"
        }
        if ($wlapsGPOs.Count -gt 0) {
            $wlapsGPOs | Export-Csv -Path (Join-Path $dir "WindowsLAPSGPOs.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "WindowsLAPSGPOs.csv -- $($wlapsGPOs.Count) GPOs with all LAPS settings" "OK"
        }
        if ($ousWithRights.Count -gt 0) {
            $ousWithRights | Export-Csv -Path (Join-Path $dir "OUExtendedRights.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "OUExtendedRights.csv -- LAPS extended rights holders per OU" "OK"
        }
        if ($ouACLReport -and $ouACLReport.Count -gt 0) {
            $ouACLReport | Export-Csv -Path (Join-Path $dir "OUPermissionsACL.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "OUPermissionsACL.csv -- $($ouACLReport.Count) LAPS ACEs (Legacy + Windows LAPS)" "OK"
        }
        Write-Host ""
        Write-Status "Exported to: $dir" "OK"
        Write-Host "           Files: Summary, Computers, GPOs, OU Permissions" -ForegroundColor DarkGray
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

    # ── STEP 1/4 ──
    Write-Host ""
    Write-Host "  ── STEP 1/4 : Target OU ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  The Organizational Unit where the computers managed by" -ForegroundColor DarkGray
    Write-Host "  LAPS are located. The GPO will be linked to this OU." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Example: OU=Workstations,DC=contoso,DC=com" -ForegroundColor DarkGray
    Write-Host ""
    $targetOU = Read-Param "Target OU (DN)" -Mandatory

    if (-not $targetOU) { Write-Status "No OU selected." "ERROR"; Pause-Screen; return }
    try { Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null }
    catch { Write-Status "OU not found: $targetOU" "ERROR"; Pause-Screen; return }
    Write-Status "Target OU: $targetOU" "OK"

    # ── STEP 2/4 ──
    Write-Host ""
    Write-Host "  ── STEP 2/4 : LAPS Admin Group ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  This Active Directory group will be granted:" -ForegroundColor DarkGray
    Write-Host "    - Read permission   : retrieve LAPS passwords from AD" -ForegroundColor DarkGray
    Write-Host "    - Reset permission  : force an immediate password rotation" -ForegroundColor DarkGray
    Write-Host "    - Decrypt permission: decrypt encrypted LAPS passwords" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Format: DOMAIN\GroupName" -ForegroundColor DarkGray
    Write-Host "  Example: $($script:Domain.NetBIOSName)\LAPS-Admins" -ForegroundColor DarkGray
    Write-Host ""
    $readGroup = Read-Param "Read/Reset group" -Mandatory

    if (-not $readGroup) { Write-Status "No group selected." "ERROR"; Pause-Screen; return }
    $grpName = $readGroup -replace '^[^\\]+\\', ''
    try { Get-ADGroup -Identity $grpName -ErrorAction Stop | Out-Null }
    catch { Write-Status "Group not found: $readGroup" "ERROR"; Pause-Screen; return }
    Write-Status "Admin group: $readGroup" "OK"

    # ── STEP 3/4 ──
    Write-Host ""
    Write-Host "  ── STEP 3/4 : GPO and Password Settings ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  A Group Policy Object will be created (or updated) and" -ForegroundColor DarkGray
    Write-Host "  linked to the target OU. Press Enter to accept defaults." -ForegroundColor DarkGray
    Write-Host ""

    $gpoName   = Read-Param "GPO name" -Default "Windows LAPS Policy"
    $pwdLength = [int](Read-Param "Password length (8-64)" -Default "20")
    $pwdAge    = [int](Read-Param "Password age in days (1-365)" -Default "30")
    $postAuthH = [int](Read-Param "Post-auth reset delay in hours (0-24, after password retrieval)" -Default "8")

    Write-Host ""
    Write-Host "  Optional -- Custom admin account name" -ForegroundColor DarkGray
    Write-Host "  Leave empty = LAPS manages the built-in Administrator (RID 500)." -ForegroundColor DarkGray
    Write-Host "  Specify a name only if you use a different local admin account." -ForegroundColor DarkGray
    $adminAcct = Read-Param "Custom admin account name (or Enter for built-in)"

    $doEncrypt = $script:DFLSupportsEncryption
    if (-not $doEncrypt) {
        Write-Host ""
        Write-Status "DFL does not support encryption -- passwords will be stored in clear text" "WARN"
        Write-Host "  Encryption requires Domain Functional Level 2016 or higher." -ForegroundColor DarkGray
    }

    # ── STEP 4/4 ──
    Write-Host ""
    Write-Host "  ── STEP 4/4 : Review and Confirm ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  Target OU         : $targetOU" -ForegroundColor White
    Write-Host "  Read/Reset Group  : $readGroup" -ForegroundColor White
    Write-Host "  GPO Name          : $gpoName" -ForegroundColor White
    Write-Host "  Password          : $pwdLength chars, rotate every $pwdAge days" -ForegroundColor White
    Write-Host "  Encryption        : $(if ($doEncrypt) { 'Yes (decryptor: ' + $readGroup + ')' } else { 'No (DFL < 2016)' })" -ForegroundColor White
    Write-Host "  Post-Auth         : Reset password + logoff after $postAuthH hours" -ForegroundColor White
    Write-Host "  Admin Account     : $(if ($adminAcct) { $adminAcct } else { 'Built-in Administrator (RID 500)' })" -ForegroundColor White
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan

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
            if ($_.Exception.Message -match "already") { Write-Status "$($op.Desc) -- already set" "OK" }
            else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
        }
    }

    # ── Step 3: GPO ──
    Write-Section "Step 3: GPO Creation and Configuration"
    $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Status "GPO '$gpoName' already exists -- updating" "WARN"
    } else {
        New-GPO -Name $gpoName -Comment "Windows LAPS -- deployed by Invoke-LAPSToolkit.ps1" | Out-Null
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
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADEncryptedPasswordHistorySize" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordExpirationProtectionEnabled" -Type DWord -Value 1 | Out-Null
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
        $choice = Show-Menu "Migration: Legacy LAPS -> Windows LAPS" @(
            "Pre-migration assessment (readiness check)"
            "Schema update and prepare emulation mode"
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
    Write-Banner
    Write-Section "Phase 1: Pre-Migration Assessment"
    Write-Host "  This phase checks your environment readiness for migrating from" -ForegroundColor DarkGray
    Write-Host "  Legacy LAPS (MSI-based) to Windows LAPS (built into the OS)." -ForegroundColor DarkGray
    Write-Host "  It scans: schema, GPOs, computer accounts, DFL, and LAPS module." -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Target OU" -Hint "The OU containing computers currently managed by Legacy LAPS." -Example "OU=Workstations,DC=contoso,DC=com" -AllowDomain
    if (-not $targetOU) { Pause-Screen; return }

    Write-Banner
    Write-Section "Phase 1: Pre-Migration Assessment"
    Write-Host "  Scope: $targetOU" -ForegroundColor White
    Write-Host ""

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
        foreach ($g in $detected) { Write-Host "           -> $($g.DisplayName)" -ForegroundColor DarkGray }
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
        Write-Status "READY for migration" "OK" "-> Proceed to Phase 2"
    } else {
        Write-Status "NOT READY" "WARN"
        if (-not $script:LAPSModuleAvailable) { Write-Host "    - LAPS module missing" -ForegroundColor Yellow }
        if ($withPwd.Count -eq 0 -and $detected.Count -eq 0) { Write-Host "    - No Legacy LAPS found -- deploy Windows LAPS directly" -ForegroundColor Yellow }
    }

    Write-Host ""
    Write-Host "  Tip: Use Quick Tools > [6] to check which machines have the Legacy CSE installed." -ForegroundColor DarkGray

    Pause-Screen
}

function Invoke-MigrationSchemaEmulation {
    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS module required" "ERROR"; Pause-Screen; return
    }

    Write-Banner
    Write-Section "Phase 2: Schema Update and Emulation Mode"
    Write-Host "  This phase extends the AD schema with Windows LAPS attributes and" -ForegroundColor DarkGray
    Write-Host "  grants SELF write permissions so that computers can update their own" -ForegroundColor DarkGray
    Write-Host "  password attributes. After this, uninstall the Legacy CSE from pilot" -ForegroundColor DarkGray
    Write-Host "  machines -- Windows LAPS will take over using the existing GPO." -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Target OU" -Hint "The OU that currently has Legacy LAPS deployed. SELF write permission will be set here." -Example "OU=Workstations,DC=contoso,DC=com"
    if (-not $targetOU) { Pause-Screen; return }

    Write-Banner
    Write-Section "Phase 2: Schema Update and Emulation Mode"
    Write-Host "  Target OU: $targetOU" -ForegroundColor White
    Write-Host ""

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
    Write-Banner
    Write-Section "Phase 3: Pilot Validation"
    Write-Host "  This phase scans computers in a target OU and shows which password" -ForegroundColor DarkGray
    Write-Host "  backend (Legacy, Emulation, or Windows LAPS native) each machine uses." -ForegroundColor DarkGray
    Write-Host "  Run this after uninstalling the Legacy CSE from pilot machines." -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Pilot OU" -Hint "The OU containing machines where you uninstalled the Legacy CSE." -Example "OU=Pilot,OU=Workstations,DC=contoso,DC=com"
    if (-not $targetOU) { Pause-Screen; return }

    Write-Banner
    Write-Section "Phase 3: Pilot Validation"
    Write-Host "  Scope: $targetOU" -ForegroundColor White
    Write-Host ""

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
        Write-Status "Mixed -- some machines still without LAPS" "WARN"
    } else {
        Write-Status "No Windows LAPS passwords yet" "WARN" "Ensure Legacy CSE is uninstalled + gpupdate"
    }

    Pause-Screen
}

function Invoke-MigrationSwitchNative {
    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS module required" "ERROR"; Pause-Screen; return
    }

    Write-Banner
    Write-Section "Phase 4: Switch to Native Mode"
    Write-Host "  This phase creates a dedicated Windows LAPS GPO, grants permissions" -ForegroundColor DarkGray
    Write-Host "  to a reader group, and links the GPO to the target OU." -ForegroundColor DarkGray
    Write-Host "  After this, machines will store their password in msLAPS-* attributes" -ForegroundColor DarkGray
    Write-Host "  instead of the old ms-Mcs-* attributes." -ForegroundColor DarkGray

    # STEP 1 -- Target OU
    Write-Host ""
    Write-Host "  ── STEP 1/4: Target OU ──" -ForegroundColor Cyan
    $targetOU = Read-OU -Label "Target OU" -Hint "The GPO will be linked here. All computers below will be affected." -Example "OU=Workstations,DC=contoso,DC=com"
    if (-not $targetOU) { Pause-Screen; return }

    # STEP 2 -- Admin group
    Write-Host ""
    Write-Host "  ── STEP 2/4: LAPS Admin Group ──" -ForegroundColor Cyan
    Write-Host "  This group will receive Read and Reset permissions on LAPS passwords." -ForegroundColor DarkGray
    $readGroup = Read-Group -Label "LAPS admin group" -Hint "Members of this group will be able to read and reset LAPS passwords."
    if (-not $readGroup) { Pause-Screen; return }

    # STEP 3 -- Password policy
    Write-Host ""
    Write-Host "  ── STEP 3/4: Password Policy ──" -ForegroundColor Cyan
    Write-Host "  Configure the password settings for the Windows LAPS GPO." -ForegroundColor DarkGray
    Write-Host ""
    $gpoName   = Read-Param "GPO display name" -Default "Windows LAPS Policy"
    $pwdLen    = [int](Read-Param "Password length (8-64)" -Default "20")
    $pwdAge    = [int](Read-Param "Password age in days (1-365)" -Default "30")
    $postAuth  = [int](Read-Param "Post-auth reset delay in hours (0-24)" -Default "8")

    # STEP 4 -- Recap and confirm
    Write-Host ""
    Write-Host "  ── STEP 4/4: Review ──" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Target OU      : $targetOU" -ForegroundColor White
    Write-Host "    Admin group    : $readGroup" -ForegroundColor White
    Write-Host "    GPO name       : $gpoName" -ForegroundColor White
    Write-Host "    Password length: $pwdLen" -ForegroundColor White
    Write-Host "    Password age   : $pwdAge days" -ForegroundColor White
    Write-Host "    Post-auth delay: $postAuth hours" -ForegroundColor White
    Write-Host "    Encryption     : $(if ($script:DFLSupportsEncryption) { 'Enabled' } else { 'Disabled (DFL too low)' })" -ForegroundColor White

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
            if ($_.Exception.Message -match "already") { Write-Status "$($op.Desc) -- already set" "OK" }
            else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
        }
    }

    # GPO
    $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-GPO -Name $gpoName -Comment "Windows LAPS native -- Invoke-LAPSToolkit.ps1" | Out-Null
        Write-Status "GPO created: $gpoName" "OK"
    } else { Write-Status "GPO '$gpoName' exists -- updating" "INFO" }

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
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "ADEncryptedPasswordHistorySize" -Type DWord -Value 0 | Out-Null
    Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName "PasswordExpirationProtectionEnabled" -Type DWord -Value 1 | Out-Null

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
    Write-Host "  -> Validate with Phase 3, then clean up with Phase 5." -ForegroundColor Yellow

    Pause-Screen
}

function Invoke-MigrationCleanup {
    Write-Banner
    Write-Section "Phase 5: Legacy LAPS Cleanup"
    Write-Host "  This phase removes Legacy LAPS artifacts:" -ForegroundColor DarkGray
    Write-Host "    - Unlinks Legacy LAPS GPOs from the target OU" -ForegroundColor DarkGray
    Write-Host "    - Clears ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime on computers" -ForegroundColor DarkGray
    Write-Host "    - Scans and optionally removes Legacy LAPS ACEs from OUs" -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Target OU" -Hint "All Legacy LAPS data (GPO links, attributes, ACEs) under this OU will be removed." -Example "OU=Workstations,DC=contoso,DC=com"
    if (-not $targetOU) { Pause-Screen; return }

    Write-Banner
    Write-Section "Phase 5: Legacy LAPS Cleanup"
    Write-Host "  Scope: $targetOU" -ForegroundColor White

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
            Write-Status "Legacy LAPS schema attributes not found -- nothing to scan" "INFO"
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
                Write-Host ""
                Write-Host "  Retrieve the current LAPS password stored in AD for a computer." -ForegroundColor DarkGray
                Write-Host "  Works with both Windows LAPS and Legacy LAPS." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The computer whose LAPS password you want to retrieve."
                if (-not $pc) { Pause-Screen; continue }
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
                Write-Host ""
                Write-Host "  Trigger an immediate password rotation on a remote computer." -ForegroundColor DarkGray
                Write-Host "  The machine must be online and reachable via PSRemoting." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The machine must be online and reachable."
                if (-not $pc) { Pause-Screen; continue }
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
                Write-Host ""
                Write-Host "  Read the last 20 events from the Microsoft-Windows-LAPS/Operational" -ForegroundColor DarkGray
                Write-Host "  event log on a remote machine (requires PSRemoting)." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The machine must be online and WinRM enabled."
                if (-not $pc) { Pause-Screen; continue }
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
                Write-Host "  Collect Windows LAPS diagnostic data from this machine." -ForegroundColor DarkGray
                Write-Host "  Output includes registry settings, event logs, and CSE status." -ForegroundColor DarkGray
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
                Write-Host ""
                Write-Host "  Shows which principals have LAPS extended rights on an OU." -ForegroundColor DarkGray
                Write-Host "  This tells you who can read or reset LAPS passwords." -ForegroundColor DarkGray
                $ou = Read-OU -Label "Target OU" -Hint "Extended rights (Read/Reset LAPS passwords) will be listed for all principals on this OU."
                if (-not $ou) { Pause-Screen; continue }
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
                Write-Host ""
                Write-Host "  Checks whether the Legacy LAPS CSE (AdmPwd.dll) is still installed" -ForegroundColor DarkGray
                Write-Host "  on remote computers. Uses PSRemoting (WinRM must be enabled)." -ForegroundColor DarkGray
                Write-Host "  Machines with the CSE still present will NOT activate Windows LAPS." -ForegroundColor DarkGray
                $searchBase = Read-OU -Label "Target OU" -Hint "All computers under this OU will be checked via PSRemoting (WinRM must be enabled)."
                if (-not $searchBase) { Pause-Screen; continue }
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
                Write-Host ""
                Write-Host "  Scans OUs for Legacy LAPS ACEs (ms-Mcs-AdmPwd permissions)." -ForegroundColor DarkGray
                Write-Host "  Shows direct vs inherited ACEs. Use Migration > Phase 5 to remove them." -ForegroundColor DarkGray
                $rootOU = Read-OU -Label "Root OU" -Hint "All child OUs will also be scanned recursively for Legacy LAPS ACEs (ms-Mcs-AdmPwd permissions)."
                if (-not $rootOU) { Pause-Screen; continue }
                Write-Host ""

                $schemaNC    = (Get-ADRootDSE).schemaNamingContext
                $guidAdmPwd  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwd" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID
                $guidExpiry  = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwdExpirationTime" } -Properties schemaIDGUID -ErrorAction SilentlyContinue).schemaIDGUID

                if (-not $guidAdmPwd) {
                    Write-Status "Legacy LAPS schema attributes not found -- nothing to scan" "INFO"
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
                    Write-Status "$totalDirect direct ACE(s) found -- use Migration > Phase 5 to remove them" "WARN"
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
        "Assessment -- Full audit of current LAPS state"
        "Deployment -- Deploy Windows LAPS from scratch"
        "Migration  -- Legacy LAPS -> Windows LAPS (guided)"
        "Quick Tools -- Password retrieval, rotation, diagnostics"
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
