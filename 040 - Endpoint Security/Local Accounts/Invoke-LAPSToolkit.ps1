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

$script:BoxW = 64  # inner width of all boxes

function Write-BoxTop    { Write-Host ("  +" + ("-" * $script:BoxW) + "+") -ForegroundColor DarkCyan }
function Write-BoxBottom { Write-Host ("  +" + ("-" * $script:BoxW) + "+") -ForegroundColor DarkCyan }
function Write-BoxEmpty  { Write-Host "  |" -ForegroundColor DarkCyan -NoNewline; Write-Host (" " * $script:BoxW) -NoNewline; Write-Host "|" -ForegroundColor DarkCyan }
function Write-BoxTitle ([string]$Title) {
    $side = [math]::Floor(($script:BoxW - $Title.Length - 2) / 2)
    $line = ("-" * $side) + " $Title " + ("-" * ($script:BoxW - $side - $Title.Length - 2))
    Write-Host "  +$line+" -ForegroundColor DarkCyan
}
function Write-BoxLine ([string]$Text, [string]$Color = "White") {
    $padded = $Text.PadRight($script:BoxW)
    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    Write-Host $padded -ForegroundColor $Color -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan
}

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-BoxTop
    Write-BoxLine "    __    ___    ____  _____" "Cyan"
    Write-BoxLine "   / /   /   |  / __ \/ ___/" "Cyan"
    # Line with 2 colors: need manual padding
    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $left = "  / /   / /| | / /_/ /\__ \"; $right = "  Windows LAPS Toolkit v1.1"
    Write-Host $left -ForegroundColor Cyan -NoNewline
    Write-Host $right.PadRight($script:BoxW - $left.Length) -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $left = " / /___/ ___ |/ ____/___/ /"; $right = "  Assessment | Deploy | Migrate"
    Write-Host $left -ForegroundColor Cyan -NoNewline
    Write-Host $right.PadRight($script:BoxW - $left.Length) -ForegroundColor DarkGray -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-BoxLine "/_____/_/  |_/_/    /____/" "Cyan"
    Write-BoxEmpty

    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $lbl = "  Domain : "; $val = "$($script:Domain.DNSRoot)"
    Write-Host $lbl -ForegroundColor DarkGray -NoNewline
    Write-Host $val.PadRight($script:BoxW - $lbl.Length) -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $lbl = "  Date   : "; $val = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host $lbl -ForegroundColor DarkGray -NoNewline
    Write-Host $val.PadRight($script:BoxW - $lbl.Length) -ForegroundColor White -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-BoxBottom
    Write-Host ""
}

function Write-Section ([string]$Title, [string]$Description = "") {
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Host "=" -ForegroundColor DarkCyan -NoNewline
    Write-Host ("=" * 62) -ForegroundColor DarkCyan
    Write-Host "   $Title" -ForegroundColor Cyan
    Write-Host "  " -NoNewline; Write-Host "=" -ForegroundColor DarkCyan -NoNewline
    Write-Host ("=" * 62) -ForegroundColor DarkCyan
    if ($Description) {
        Write-Host "  $Description" -ForegroundColor DarkGray
    }
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

function Show-Menu ([string]$Title, [string[]]$Options, [string[]]$Descriptions = @(), [switch]$AllowBack) {
    Write-Host ""
    Write-BoxTitle $Title
    Write-BoxEmpty

    for ($i = 0; $i -lt $Options.Count; $i++) {
        # Option line: colored number + white title
        Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
        $num = "   [$($i + 1)] "
        Write-Host $num -ForegroundColor Cyan -NoNewline
        Write-Host $Options[$i].PadRight($script:BoxW - $num.Length) -ForegroundColor White -NoNewline
        Write-Host "|" -ForegroundColor DarkCyan
        # Optional description line
        if ($i -lt $Descriptions.Count -and $Descriptions[$i]) {
            Write-BoxLine "        $($Descriptions[$i])" "DarkGray"
        }
    }

    if ($AllowBack) {
        Write-BoxEmpty
        Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
        $num = "   [0] "
        Write-Host $num -ForegroundColor DarkGray -NoNewline
        Write-Host "Back to main menu".PadRight($script:BoxW - $num.Length) -ForegroundColor DarkGray -NoNewline
        Write-Host "|" -ForegroundColor DarkCyan
    }

    Write-BoxBottom
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
    Write-Host "  Type 0 to cancel and return to the menu." -ForegroundColor DarkGray
    Write-Host ""
    $dn = Read-Host "  OU (distinguished name)"
    if ($dn -eq "0") { return "__CANCEL__" }
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
    Write-Host "  Type 0 to cancel and return to the menu." -ForegroundColor DarkGray
    Write-Host ""
    $grpInput = Read-Host "  Group"
    if ($grpInput -eq "0") { return "__CANCEL__" }
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
    Write-Host "  Type 0 to cancel and return to the menu." -ForegroundColor DarkGray
    Write-Host ""
    $name = Read-Host "  Computer name"
    if ($name -eq "0") { return "__CANCEL__" }
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

function Test-Cancelled ($Value) {
    return (-not $Value -or $Value -eq "__CANCEL__")
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
    Write-Section "LAPS Assessment" "Full audit of your LAPS deployment: schema, GPOs, permissions, and computers."
    Write-Host ""
    Write-Host "  This wizard will scan your Active Directory for:" -ForegroundColor DarkGray
    Write-Host "    - Legacy and Windows LAPS schema attributes" -ForegroundColor DarkGray
    Write-Host "    - Domain Functional Level (encryption support)" -ForegroundColor DarkGray
    Write-Host "    - Legacy and Windows LAPS GPOs with their settings" -ForegroundColor DarkGray
    Write-Host "    - OU permissions (SELF write, extended rights, ACEs)" -ForegroundColor DarkGray
    Write-Host "    - Full computer inventory with password status" -ForegroundColor DarkGray
    Write-Host "    - Optional CSV + HTML export" -ForegroundColor DarkGray

    $searchBase = Read-OU -Label "Scope" -Hint "The OU to assess. Leave empty to scan the entire domain." -AllowDomain
    if (Test-Cancelled $searchBase) { return }
    if (-not $searchBase) { $searchBase = $script:Domain.DistinguishedName }
    $exportCSV  = Confirm-Action "Export results to CSV and HTML?"

    Write-Banner
    Write-Section "LAPS Assessment" "Scope: $searchBase"

    # ── 1. Schema ──
    Write-Section "1/7  AD Schema Analysis" "Checking if Legacy and Windows LAPS schema attributes exist."

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
    Write-Section "2/7  Domain Functional Level" "DFL 2016+ is required for password encryption (CNG/DPAPI-NG)."
    $dfl = $script:Domain.DomainMode
    if ($script:DFLSupportsEncryption) {
        Write-Status "DFL: $dfl" "OK" "Password encryption supported"
    } else {
        Write-Status "DFL: $dfl" "WARN" "Encryption requires DFL 2016+"
    }

    # ── 3. GPOs ──
    Write-Section "3/7  GPO Detection" "Scanning all GPOs for Legacy (AdmPwd) and Windows LAPS registry settings."
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
    Write-Section "4/7  OU Permissions Audit" "Scanning extended rights and ACLs on OUs for LAPS-related permissions."
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
    Write-Section "5/7  Computer Inventory" "Querying all Windows computers and checking LAPS password status."

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
    Write-Host "  ── Overview ──" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Total Computers : " -ForegroundColor DarkGray -NoNewline; Write-Host $inventory.Count -ForegroundColor Cyan
    Write-Host "   Enabled         : " -ForegroundColor DarkGray -NoNewline; Write-Host $enabled -ForegroundColor White
    Write-Host "   OS eligible     : " -ForegroundColor DarkGray -NoNewline; Write-Host $eligible -ForegroundColor White
    Write-Host ""
    Write-Host "  ── LAPS Coverage (enabled) ──" -ForegroundColor Yellow
    Write-Host ""
    $total = [math]::Max($enabled, 1)
    # Visual bar chart
    foreach ($cat in @(
        @{ Label = "Encrypted"; Count = $wlEnc;  Color = "Green" },
        @{ Label = "Clear";     Count = $wlClear; Color = "Yellow" },
        @{ Label = "Legacy";    Count = $legOnly; Color = "DarkYellow" },
        @{ Label = "No LAPS";   Count = $noLaps;  Color = "Red" }
    )) {
        $barLen = [math]::Min([math]::Max([math]::Round($cat.Count / $total * 30), 0), 30)
        if ($cat.Count -gt 0 -and $barLen -eq 0) { $barLen = 1 }
        $bar = if ($barLen -gt 0) { [string][char]0x2588 * $barLen } else { "" }
        $pct = [math]::Round($cat.Count / $total * 100)
        Write-Host ("   {0,-12}" -f $cat.Label) -ForegroundColor DarkGray -NoNewline
        Write-Host $bar -ForegroundColor $cat.Color -NoNewline
        Write-Host " $($cat.Count) ($pct%)" -ForegroundColor White
    }

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
    Write-Section "6/7  Summary and Recommendations" "Overall LAPS posture and next steps."
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

    # ── 7. Export ──
    if ($exportCSV) {
        Write-Section "7/7  Export (CSV + HTML)" "Saving detailed reports for offline review and sharing."
        $dir = Join-Path (Get-Location) "LAPS-Assessment_$script:Timestamp"
        New-Item -ItemType Directory -Path $dir -Force | Out-Null

        # Summary.csv
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
        Write-Status "Summary.csv" "OK"

        if ($inventory.Count -gt 0) {
            $inventory | Export-Csv -Path (Join-Path $dir "Computers.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "Computers.csv -- $($inventory.Count) records" "OK"
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
            $ousWithRights | Export-Csv -Path (Join-Path $dir "OUExtendedRights.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "OUExtendedRights.csv" "OK"
        }
        if ($ouACLReport -and $ouACLReport.Count -gt 0) {
            $ouACLReport | Export-Csv -Path (Join-Path $dir "OUPermissionsACL.csv") -NoTypeInformation -Encoding UTF8
            Write-Status "OUPermissionsACL.csv" "OK"
        }

        # ── HTML Report ──
        $htmlPath = Join-Path $dir "LAPS-Assessment-Report.html"
        $staleCount = ($inventory | Where-Object { $_.IsStale90d -eq $true }).Count
        $dsrmCount  = ($inventory | Where-Object { $_.DSRM -eq $true }).Count

        Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

        # Helper: HTML-encode shorthand
        function HE ($s) { [System.Web.HttpUtility]::HtmlEncode("$s") }

        # Helper: build a sortable, scrollable HTML table from objects
        function ConvertTo-HtmlTable ($Data, $Id = "tbl", $MaxRows = 500) {
            if (-not $Data -or $Data.Count -eq 0) { return "<p class='empty'>No data.</p>" }
            $props = ($Data[0] | Get-Member -MemberType NoteProperty).Name
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append("<div class='table-wrap'><table id='$Id'>")
            [void]$sb.Append("<thead><tr>")
            foreach ($p in $props) { [void]$sb.Append("<th onclick='sortTable(this)'>$(HE $p) <span class='sort-arrow'></span></th>") }
            [void]$sb.Append("</tr></thead><tbody>")
            $rows = $Data | Select-Object -First $MaxRows
            foreach ($row in $rows) {
                [void]$sb.Append("<tr>")
                foreach ($p in $props) {
                    $v = "$($row.$p)"
                    $cls = ""
                    if ($v -eq "True")  { $cls = " class='val-true'" }
                    if ($v -eq "False") { $cls = " class='val-false'" }
                    if ($p -eq "LAPSStatus") {
                        $cls = switch -Wildcard ($v) {
                            "No LAPS"       { " class='badge badge-red'" }
                            "Legacy*"       { " class='badge badge-orange'" }
                            "*Clear*"       { " class='badge badge-yellow'" }
                            "*Encrypted*"   { " class='badge badge-green'" }
                            default         { "" }
                        }
                    }
                    [void]$sb.Append("<td$cls>$(HE $v)</td>")
                }
                [void]$sb.Append("</tr>")
            }
            [void]$sb.Append("</tbody></table></div>")
            if ($Data.Count -gt $MaxRows) { [void]$sb.Append("<p class='note'>Showing first $MaxRows of $($Data.Count) rows. See CSV for full data.</p>") }
            return $sb.ToString()
        }

        # Build KPI cards
        function Get-KpiHtml ($Label, $Value, $Color, $Icon) {
            return "<div class='kpi'><div class='kpi-icon'>$Icon</div><div class='kpi-value' style='color:$Color'>$Value</div><div class='kpi-label'>$Label</div></div>"
        }

        $kpiHtml = ""
        $kpiHtml += Get-KpiHtml "Total Computers" $($inventory.Count) "#4fc3f7" "&#x1F4BB;"
        $kpiHtml += Get-KpiHtml "Enabled" $enabled "#81c784" "&#x2705;"
        $kpiHtml += Get-KpiHtml "OS Eligible" $eligible "#81c784" "&#x1F7E2;"
        $kpiHtml += Get-KpiHtml "No LAPS" $noLaps $(if ($noLaps -gt 0) { "#ef5350" } else { "#81c784" }) "&#x26A0;"
        $kpiHtml += Get-KpiHtml "Legacy LAPS" $legOnly $(if ($legOnly -gt 0) { "#ffb74d" } else { "#81c784" }) "&#x1F4E6;"
        $kpiHtml += Get-KpiHtml "WLAPS Clear" $wlClear $(if ($wlClear -gt 0) { "#ffb74d" } else { "#81c784" }) "&#x1F513;"
        $kpiHtml += Get-KpiHtml "WLAPS Encrypted" $wlEnc "#81c784" "&#x1F512;"
        $kpiHtml += Get-KpiHtml "Stale (90d)" $staleCount $(if ($staleCount -gt 0) { "#ef5350" } else { "#81c784" }) "&#x23F0;"

        # Recommendations
        $recoHtml = ""
        if ($noLaps -gt 0) {
            $recoHtml += "<div class='reco reco-critical'><strong>CRITICAL:</strong> $noLaps enabled computer(s) have no LAPS password at all. Deploy Windows LAPS to protect them.</div>"
        }
        if (-not $script:HasWLAPSSchema) {
            $recoHtml += "<div class='reco reco-critical'><strong>CRITICAL:</strong> Windows LAPS schema is not present. Run <code>Update-LapsADSchema</code> as Schema Admin.</div>"
        }
        if ($wlClear -gt 0) {
            $recoHtml += "<div class='reco reco-warn'><strong>WARNING:</strong> $wlClear computer(s) store LAPS passwords in clear text. Enable encryption (requires DFL 2016+).</div>"
        }
        if ($legOnly -gt 0) {
            $recoHtml += "<div class='reco reco-warn'><strong>WARNING:</strong> $legOnly computer(s) still use Legacy LAPS. Plan migration to Windows LAPS.</div>"
        }
        if ($staleCount -gt 0) {
            $recoHtml += "<div class='reco reco-warn'><strong>WARNING:</strong> $staleCount computer(s) have passwords expired for 90+ days. Check GPO application.</div>"
        }
        if (-not $script:DFLSupportsEncryption) {
            $recoHtml += "<div class='reco reco-info'><strong>INFO:</strong> DFL ($($script:Domain.DomainMode)) does not support encryption. Raise to Windows Server 2016 DFL.</div>"
        }
        if (-not $recoHtml) {
            $recoHtml = "<div class='reco reco-ok'><strong>All clear!</strong> No critical findings.</div>"
        }

        # Environment info
        $envHtml = @"
<table class="info-table">
<tr><td>Domain</td><td><strong>$($script:Domain.DNSRoot)</strong></td></tr>
<tr><td>DFL</td><td>$($script:Domain.DomainMode) $(if ($script:DFLSupportsEncryption) { '<span class="tag tag-green">encryption OK</span>' } else { '<span class="tag tag-orange">no encryption</span>' })</td></tr>
<tr><td>Legacy Schema</td><td>$(if ($script:HasLegacySchema) { '<span class="tag tag-orange">Present</span>' } else { '<span class="tag tag-gray">Not present</span>' })</td></tr>
<tr><td>Windows LAPS Schema</td><td>$(if ($script:HasWLAPSSchema) { '<span class="tag tag-green">Present</span>' } else { '<span class="tag tag-red">Not present</span>' })</td></tr>
<tr><td>Legacy GPOs</td><td>$($legacyGPOs.Count)</td></tr>
<tr><td>Windows LAPS GPOs</td><td>$($wlapsGPOs.Count)</td></tr>
<tr><td>Assessment Date</td><td>$($now.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
</table>
"@

        $computersHtml = ConvertTo-HtmlTable $inventory "tblComputers"
        $gpoLegHtml    = ConvertTo-HtmlTable $legacyGPOs "tblLegGpo"
        $gpoWlHtml     = ConvertTo-HtmlTable $wlapsGPOs "tblWlGpo"
        $ouRightsHtml  = ConvertTo-HtmlTable $ousWithRights "tblOuRights"
        $ouAclHtml     = ConvertTo-HtmlTable $ouACLReport "tblOuAcl"

        # Coverage chart data (CSS bar chart)
        $total = [Math]::Max($inventory.Count, 1)
        $pctNoLaps = [math]::Round($noLaps / $total * 100, 1)
        $pctLeg    = [math]::Round($legOnly / $total * 100, 1)
        $pctClear  = [math]::Round($wlClear / $total * 100, 1)
        $pctEnc    = [math]::Round($wlEnc / $total * 100, 1)
        $pctOther  = [math]::Round((100 - $pctNoLaps - $pctLeg - $pctClear - $pctEnc), 1)
        if ($pctOther -lt 0) { $pctOther = 0 }

        $chartHtml = @"
<div class="chart-label">LAPS Coverage (enabled computers)</div>
<div class="stacked-bar">
$(if ($pctEnc -gt 0)    { "<div class='bar bar-green' style='width:${pctEnc}%' title='WLAPS Encrypted: $wlEnc'></div>" })
$(if ($pctClear -gt 0)  { "<div class='bar bar-yellow' style='width:${pctClear}%' title='WLAPS Clear: $wlClear'></div>" })
$(if ($pctLeg -gt 0)    { "<div class='bar bar-orange' style='width:${pctLeg}%' title='Legacy LAPS: $legOnly'></div>" })
$(if ($pctNoLaps -gt 0) { "<div class='bar bar-red' style='width:${pctNoLaps}%' title='No LAPS: $noLaps'></div>" })
$(if ($pctOther -gt 0)  { "<div class='bar bar-gray' style='width:${pctOther}%' title='Disabled/Other'></div>" })
</div>
<div class="chart-legend">
<span><span class="dot dot-green"></span> Encrypted ($wlEnc)</span>
<span><span class="dot dot-yellow"></span> Clear text ($wlClear)</span>
<span><span class="dot dot-orange"></span> Legacy ($legOnly)</span>
<span><span class="dot dot-red"></span> No LAPS ($noLaps)</span>
<span><span class="dot dot-gray"></span> Disabled/Other</span>
</div>
"@

        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LAPS Assessment Report - $($script:Domain.DNSRoot)</title>
<style>
  :root { --bg: #1e1e2e; --surface: #181825; --surface2: #313244; --text: #cdd6f4; --subtext: #a6adc8; --dim: #6c7086; --blue: #89b4fa; --green: #a6e3a1; --red: #f38ba8; --orange: #fab387; --yellow: #f9e2af; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: var(--bg); color: var(--text); padding: 30px 40px; line-height: 1.5; }
  h1 { color: var(--blue); font-size: 1.8em; margin-bottom: 2px; }
  .subtitle { color: var(--dim); margin-bottom: 25px; font-size: 0.9em; }
  h2 { color: var(--blue); font-size: 1.15em; margin: 0 0 12px 0; }
  .section { background: var(--surface); border-radius: 12px; padding: 22px 28px; margin-bottom: 18px; border: 1px solid var(--surface2); }

  /* KPI cards */
  .kpi-row { display: flex; gap: 14px; flex-wrap: wrap; margin: 8px 0; }
  .kpi { background: var(--surface2); border-radius: 10px; padding: 16px 20px; min-width: 130px; text-align: center; flex: 1; }
  .kpi-icon { font-size: 1.3em; margin-bottom: 2px; }
  .kpi-value { font-size: 2em; font-weight: 700; line-height: 1.1; }
  .kpi-label { color: var(--subtext); font-size: 0.8em; margin-top: 3px; }

  /* Stacked bar chart */
  .chart-label { color: var(--subtext); font-size: 0.85em; margin-bottom: 6px; font-weight: 600; }
  .stacked-bar { display: flex; height: 28px; border-radius: 6px; overflow: hidden; background: var(--surface2); }
  .bar { transition: width 0.3s; }
  .bar-green  { background: #a6e3a1; }
  .bar-yellow { background: #f9e2af; }
  .bar-orange { background: #fab387; }
  .bar-red    { background: #f38ba8; }
  .bar-gray   { background: #585b70; }
  .chart-legend { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px; font-size: 0.8em; color: var(--subtext); }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
  .dot-green  { background: #a6e3a1; } .dot-yellow { background: #f9e2af; }
  .dot-orange { background: #fab387; } .dot-red    { background: #f38ba8; } .dot-gray { background: #585b70; }

  /* Tags */
  .tag { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.82em; font-weight: 600; }
  .tag-green  { background: rgba(166,227,161,0.15); color: #a6e3a1; }
  .tag-orange { background: rgba(250,179,135,0.15); color: #fab387; }
  .tag-red    { background: rgba(243,139,168,0.15); color: #f38ba8; }
  .tag-gray   { background: rgba(108,112,134,0.15); color: #6c7086; }

  /* Badges in table cells */
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 0.82em; font-weight: 600; white-space: nowrap; }
  .badge-red    { background: rgba(243,139,168,0.18); color: #f38ba8; }
  .badge-orange { background: rgba(250,179,135,0.18); color: #fab387; }
  .badge-yellow { background: rgba(249,226,175,0.18); color: #f9e2af; }
  .badge-green  { background: rgba(166,227,161,0.18); color: #a6e3a1; }

  /* Recommendations */
  .reco { padding: 10px 16px; border-radius: 8px; margin-bottom: 8px; font-size: 0.88em; border-left: 4px solid; }
  .reco-critical { background: rgba(243,139,168,0.08); border-color: #f38ba8; }
  .reco-warn     { background: rgba(250,179,135,0.08); border-color: #fab387; }
  .reco-info     { background: rgba(137,180,250,0.08); border-color: #89b4fa; }
  .reco-ok       { background: rgba(166,227,161,0.08); border-color: #a6e3a1; }
  .reco code { background: var(--surface2); padding: 1px 6px; border-radius: 3px; font-size: 0.92em; }

  /* Info table */
  .info-table { border-collapse: collapse; margin: 6px 0; }
  .info-table td { padding: 5px 20px 5px 0; font-size: 0.9em; }
  .info-table td:first-child { color: var(--subtext); font-weight: 600; min-width: 170px; }

  /* Data tables */
  .table-wrap { overflow-x: auto; max-height: 600px; overflow-y: auto; border-radius: 8px; border: 1px solid var(--surface2); }
  table { width: 100%; border-collapse: collapse; font-size: 0.8em; white-space: nowrap; }
  th { background: var(--surface2); color: var(--blue); padding: 9px 12px; text-align: left; position: sticky; top: 0; cursor: pointer; user-select: none; z-index: 1; }
  th:hover { background: #3e3e56; }
  .sort-arrow { font-size: 0.7em; }
  td { padding: 6px 12px; border-bottom: 1px solid rgba(49,50,68,0.6); }
  tr:hover td { background: rgba(49,50,68,0.4); }
  .val-true  { color: var(--green); }
  .val-false { color: var(--dim); }
  .empty { color: var(--dim); font-style: italic; }
  .note { color: var(--dim); font-style: italic; font-size: 0.85em; }

  /* Filter input */
  .filter-row { margin-bottom: 10px; }
  .filter-input { background: var(--surface2); border: 1px solid rgba(108,112,134,0.3); color: var(--text); padding: 7px 14px; border-radius: 6px; width: 300px; font-size: 0.88em; outline: none; }
  .filter-input:focus { border-color: var(--blue); }
  .filter-input::placeholder { color: var(--dim); }

  /* Nav */
  .nav { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 22px; }
  .nav a { background: var(--surface2); color: var(--subtext); padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 0.82em; }
  .nav a:hover { color: var(--blue); background: #3e3e56; }

  .footer { color: var(--dim); font-size: 0.8em; margin-top: 30px; padding-top: 15px; border-top: 1px solid var(--surface2); }
</style>
</head>
<body>

<h1>LAPS Assessment Report</h1>
<p class="subtitle">$($script:Domain.DNSRoot) -- Generated $($now.ToString('yyyy-MM-dd HH:mm:ss'))</p>

<div class="nav">
<a href="#env">Environment</a>
<a href="#overview">Overview</a>
<a href="#reco">Recommendations</a>
<a href="#computers">Computers</a>
$(if ($legacyGPOs.Count -gt 0) { '<a href="#leggpo">Legacy GPOs</a>' })
$(if ($wlapsGPOs.Count -gt 0) { '<a href="#wlgpo">Windows LAPS GPOs</a>' })
$(if ($ousWithRights.Count -gt 0) { '<a href="#ourights">OU Rights</a>' })
$(if ($ouACLReport -and $ouACLReport.Count -gt 0) { '<a href="#ouacl">OU ACEs</a>' })
</div>

<div class="section" id="env">
<h2>Environment</h2>
$envHtml
</div>

<div class="section" id="overview">
<h2>Overview</h2>
<div class="kpi-row">$kpiHtml</div>
<div style="margin-top:16px">$chartHtml</div>
</div>

<div class="section" id="reco">
<h2>Recommendations</h2>
$recoHtml
</div>

<div class="section" id="computers">
<h2>Computer Inventory ($($inventory.Count))</h2>
<div class="filter-row"><input type="text" class="filter-input" placeholder="Filter computers..." onkeyup="filterTable(this, 'tblComputers')"></div>
$computersHtml
</div>

$(if ($legacyGPOs.Count -gt 0) { @"
<div class="section" id="leggpo">
<h2>Legacy LAPS GPOs ($($legacyGPOs.Count))</h2>
$gpoLegHtml
</div>
"@ })

$(if ($wlapsGPOs.Count -gt 0) { @"
<div class="section" id="wlgpo">
<h2>Windows LAPS GPOs ($($wlapsGPOs.Count))</h2>
$gpoWlHtml
</div>
"@ })

$(if ($ousWithRights.Count -gt 0) { @"
<div class="section" id="ourights">
<h2>OU Extended Rights ($($ousWithRights.Count))</h2>
$ouRightsHtml
</div>
"@ })

$(if ($ouACLReport -and $ouACLReport.Count -gt 0) { @"
<div class="section" id="ouacl">
<h2>OU LAPS ACEs ($($ouACLReport.Count))</h2>
$ouAclHtml
</div>
"@ })

<div class="footer">Generated by Invoke-LAPSToolkit.ps1 v1.1 -- $(HE $script:Domain.DNSRoot)</div>

<script>
function filterTable(input, tableId) {
  var filter = input.value.toLowerCase();
  var rows = document.getElementById(tableId).getElementsByTagName('tbody')[0].getElementsByTagName('tr');
  for (var i = 0; i < rows.length; i++) {
    rows[i].style.display = rows[i].textContent.toLowerCase().indexOf(filter) > -1 ? '' : 'none';
  }
}
function sortTable(th) {
  var table = th.closest('table');
  var idx = Array.from(th.parentNode.children).indexOf(th);
  var tbody = table.getElementsByTagName('tbody')[0];
  var rows = Array.from(tbody.rows);
  var asc = th.dataset.sort !== 'asc';
  rows.sort(function(a, b) {
    var av = a.cells[idx].textContent, bv = b.cells[idx].textContent;
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
  Array.from(th.parentNode.children).forEach(function(h) { h.dataset.sort = ''; h.querySelector('.sort-arrow').textContent = ''; });
  th.dataset.sort = asc ? 'asc' : 'desc';
  th.querySelector('.sort-arrow').textContent = asc ? ' \\u25B2' : ' \\u25BC';
}
</script>
</body>
</html>
"@

        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Status "LAPS-Assessment-Report.html" "OK"

        Write-Host ""
        Write-Status "Exported to: $dir" "OK"

        if (Confirm-Action "Open the HTML report in your browser?") {
            Start-Process $htmlPath
        }
    }

    Pause-Screen
}

# ██████████████████████████████████████████████████████████████████
#  2. DEPLOYMENT
# ██████████████████████████████████████████████████████████████████

function Invoke-Deployment {
    Write-Banner
    Write-Section "Windows LAPS Deployment" "Deploy Windows LAPS from scratch in 5 guided steps."
    Write-Host ""
    Write-Host "  This wizard will walk you through:" -ForegroundColor Yellow
    Write-Host "    Step 1  Prerequisites check (modules, schema, DFL)" -ForegroundColor DarkGray
    Write-Host "    Step 2  Target OU selection" -ForegroundColor DarkGray
    Write-Host "    Step 3  Permission groups (Readers + Resetters)" -ForegroundColor DarkGray
    Write-Host "    Step 4  GPO settings (all parameters with explanations)" -ForegroundColor DarkGray
    Write-Host "    Step 5  Review and deploy" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Type 0 at any prompt to cancel and return to the main menu." -ForegroundColor DarkGray

    # ── STEP 1/5 : Prerequisites ──
    Write-Host ""
    Write-Host "  ── STEP 1/5 : Prerequisites Check ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  Verifying that all required components are available" -ForegroundColor DarkGray
    Write-Host "  before starting the deployment." -ForegroundColor DarkGray
    Write-Host ""

    # LAPS module
    if ($script:LAPSModuleAvailable) {
        Write-Status "LAPS PowerShell module" "OK" "Loaded"
    } else {
        Write-Status "LAPS PowerShell module" "ERROR" "Not found -- install April 2023+ update"
        Pause-Screen; return
    }

    # Schema
    if ($script:HasWLAPSSchema) {
        Write-Status "Windows LAPS schema" "OK" "Already present -- will skip schema update"
    } else {
        Write-Status "Windows LAPS schema" "INFO" "Not present -- will be created during deployment"
    }

    # DFL / encryption
    if ($script:DFLSupportsEncryption) {
        Write-Status "DFL: $($script:Domain.DomainMode)" "OK" "Password encryption supported"
    } else {
        Write-Status "DFL: $($script:Domain.DomainMode)" "WARN" "Encryption requires DFL 2016+ -- passwords will be clear text"
    }

    # GroupPolicy module
    $gpModule = Get-Module -Name GroupPolicy -ErrorAction SilentlyContinue
    if ($gpModule -or (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Status "GroupPolicy module" "OK"
    } else {
        Write-Status "GroupPolicy module" "ERROR" "Required for GPO creation -- install RSAT"
        Pause-Screen; return
    }

    Write-Host ""
    Write-Status "Prerequisites OK -- proceeding to configuration" "OK"

    # ── STEP 2/5 : Target OU ──
    Write-Host ""
    Write-Host "  ── STEP 2/5 : Target OU ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  The Organizational Unit where the computers managed by" -ForegroundColor DarkGray
    Write-Host "  LAPS are located. The GPO will be linked to this OU." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Example: OU=Workstations,DC=contoso,DC=com" -ForegroundColor DarkGray
    Write-Host ""
    $targetOU = Read-Param "Target OU (DN)" -Mandatory

    if (-not $targetOU -or $targetOU -eq "0") { Write-Status "Cancelled." "INFO"; Pause-Screen; return }
    try { Get-ADOrganizationalUnit -Identity $targetOU -ErrorAction Stop | Out-Null }
    catch { Write-Status "OU not found: $targetOU" "ERROR"; Pause-Screen; return }
    Write-Status "Target OU: $targetOU" "OK"

    # ── STEP 3/5 : Permission Groups ──
    Write-Host ""
    Write-Host "  ── STEP 3/5 : Permission Groups ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  You need to specify AD groups that will receive LAPS" -ForegroundColor DarkGray
    Write-Host "  permissions. You can use the same group for both, or" -ForegroundColor DarkGray
    Write-Host "  separate groups for Read and Reset rights." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  [a] Password Readers" -ForegroundColor Yellow
    Write-Host "  Members can retrieve (read) LAPS passwords from AD." -ForegroundColor DarkGray
    Write-Host "  If encryption is enabled, this group is also the decryptor." -ForegroundColor DarkGray
    Write-Host "  Format: DOMAIN\GroupName   Example: CONTOSO\LAPS-Readers" -ForegroundColor DarkGray
    Write-Host ""
    $readGroup = Read-Param "Password Readers group" -Mandatory
    if (-not $readGroup -or $readGroup -eq "0") { Write-Status "Cancelled." "INFO"; Pause-Screen; return }
    $readGrpName = $readGroup -replace '^[^\\]+\\', ''
    try { Get-ADGroup -Identity $readGrpName -ErrorAction Stop | Out-Null }
    catch { Write-Status "Group not found: $readGroup" "ERROR"; Pause-Screen; return }
    Write-Status "Readers: $readGroup" "OK"

    Write-Host ""
    Write-Host "  [b] Password Resetters" -ForegroundColor Yellow
    Write-Host "  Members can force an immediate password rotation on any" -ForegroundColor DarkGray
    Write-Host "  computer in the target OU. Leave empty to use the same" -ForegroundColor DarkGray
    Write-Host "  group as Readers." -ForegroundColor DarkGray
    Write-Host ""
    $resetGroup = Read-Param "Password Resetters group (Enter = same as Readers)" -Default $readGroup
    $resetGrpName = $resetGroup -replace '^[^\\]+\\', ''
    try { Get-ADGroup -Identity $resetGrpName -ErrorAction Stop | Out-Null }
    catch { Write-Status "Group not found: $resetGroup" "ERROR"; Pause-Screen; return }
    if ($resetGroup -eq $readGroup) {
        Write-Status "Resetters: same as Readers ($resetGroup)" "OK"
    } else {
        Write-Status "Resetters: $resetGroup" "OK"
    }

    # ── STEP 4/5 : GPO Settings ──
    Write-Host ""
    Write-Host "  ── STEP 4/5 : GPO Settings ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  Configure all Windows LAPS Group Policy settings." -ForegroundColor DarkGray
    Write-Host "  Press Enter to accept each default (recommended)." -ForegroundColor DarkGray
    Write-Host ""

    $gpoName = Read-Param "GPO display name" -Default "Windows LAPS Policy"
    if ($gpoName -eq "0") { Write-Status "Cancelled." "INFO"; Pause-Screen; return }
    Write-Host ""

    Write-Host "  -- Backup Directory --" -ForegroundColor Yellow
    Write-Host "  Where the password is stored." -ForegroundColor DarkGray
    Write-Host "    0 = Disabled" -ForegroundColor DarkGray
    Write-Host "    1 = Azure AD only" -ForegroundColor DarkGray
    Write-Host "    2 = Active Directory" -ForegroundColor DarkGray
    $backupDir = [int](Read-Param "Backup Directory (0/1/2)" -Default "2")
    Write-Host ""

    Write-Host "  -- Password Complexity --" -ForegroundColor Yellow
    Write-Host "  Defines which characters the password includes." -ForegroundColor DarkGray
    Write-Host "    1 = Uppercase letters" -ForegroundColor DarkGray
    Write-Host "    2 = Uppercase + Lowercase" -ForegroundColor DarkGray
    Write-Host "    3 = Uppercase + Lowercase + Digits" -ForegroundColor DarkGray
    Write-Host "    4 = Uppercase + Lowercase + Digits + Special chars" -ForegroundColor DarkGray
    $pwdComplexity = [int](Read-Param "Password Complexity (1-4)" -Default "4")
    Write-Host ""

    Write-Host "  -- Password Length --" -ForegroundColor Yellow
    Write-Host "  Number of characters in the generated password (8-64)." -ForegroundColor DarkGray
    $pwdLength = [int](Read-Param "Password Length" -Default "20")
    Write-Host ""

    Write-Host "  -- Password Age --" -ForegroundColor Yellow
    Write-Host "  How often the password is rotated (1-365 days)." -ForegroundColor DarkGray
    $pwdAge = [int](Read-Param "Password Age (days)" -Default "30")
    Write-Host ""

    Write-Host "  -- Post-Authentication Actions --" -ForegroundColor Yellow
    Write-Host "  What happens after an admin uses the LAPS password." -ForegroundColor DarkGray
    Write-Host "    0 = Disabled (no action)" -ForegroundColor DarkGray
    Write-Host "    1 = Reset password" -ForegroundColor DarkGray
    Write-Host "    3 = Reset password + logoff" -ForegroundColor DarkGray
    Write-Host "    5 = Reset password + reboot" -ForegroundColor DarkGray
    $postAuthAction = [int](Read-Param "Post-Auth Action (0/1/3/5)" -Default "3")
    Write-Host ""

    Write-Host "  -- Post-Authentication Reset Delay --" -ForegroundColor Yellow
    Write-Host "  Hours to wait before the post-auth action triggers (0-24)." -ForegroundColor DarkGray
    $postAuthH = [int](Read-Param "Post-Auth Delay (hours)" -Default "8")
    Write-Host ""

    Write-Host "  -- Encrypted Password History Size --" -ForegroundColor Yellow
    Write-Host "  Number of previous encrypted passwords to keep (0-12)." -ForegroundColor DarkGray
    Write-Host "  Only works when encryption is enabled." -ForegroundColor DarkGray
    $historySize = [int](Read-Param "Password History Size" -Default "0")
    Write-Host ""

    Write-Host "  -- Password Expiration Protection --" -ForegroundColor Yellow
    Write-Host "  Prevents the computer from extending the expiry beyond the" -ForegroundColor DarkGray
    Write-Host "  policy-defined max age (protects against tampering)." -ForegroundColor DarkGray
    $expProtect = Read-Param "Expiration Protection (yes/no)" -Default "yes"
    $expProtectVal = if ($expProtect -match '^y') { 1 } else { 0 }
    Write-Host ""

    Write-Host "  -- Administrator Account Name --" -ForegroundColor Yellow
    Write-Host "  Leave empty = LAPS manages the built-in Administrator (RID 500)." -ForegroundColor DarkGray
    Write-Host "  Specify a name only if you use a custom local admin account." -ForegroundColor DarkGray
    $adminAcct = Read-Param "Custom admin account name (or Enter for built-in)"

    $doEncrypt = $script:DFLSupportsEncryption
    if (-not $doEncrypt) {
        Write-Host ""
        Write-Status "DFL does not support encryption -- passwords will be stored in clear text" "WARN"
    }

    # ── STEP 5/5 : Recap ──
    Write-Host ""
    Write-Host "  ── STEP 5/5 : Review and Confirm ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  Target OU             : $targetOU" -ForegroundColor White
    Write-Host "  Password Readers      : $readGroup" -ForegroundColor White
    Write-Host "  Password Resetters    : $resetGroup" -ForegroundColor White
    Write-Host "  GPO Name              : $gpoName" -ForegroundColor White
    Write-Host "  Backup Directory      : $backupDir $(switch($backupDir){ 0{'(Disabled)'} 1{'(Azure AD)'} 2{'(Active Directory)'} })" -ForegroundColor White
    Write-Host "  Password Complexity   : $pwdComplexity" -ForegroundColor White
    Write-Host "  Password Length       : $pwdLength chars" -ForegroundColor White
    Write-Host "  Password Age          : $pwdAge days" -ForegroundColor White
    Write-Host "  Encryption            : $(if ($doEncrypt) { 'Yes (decryptor: ' + $readGroup + ')' } else { 'No (DFL < 2016)' })" -ForegroundColor White
    Write-Host "  Post-Auth Action      : $postAuthAction" -ForegroundColor White
    Write-Host "  Post-Auth Delay       : $postAuthH hours" -ForegroundColor White
    Write-Host "  Password History      : $historySize" -ForegroundColor White
    Write-Host "  Expiration Protection : $(if ($expProtectVal) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
    Write-Host "  Admin Account         : $(if ($adminAcct) { $adminAcct } else { 'Built-in Administrator (RID 500)' })" -ForegroundColor White
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan

    if (-not (Confirm-Action "Proceed with deployment?")) {
        Write-Status "Cancelled." "INFO"; Pause-Screen; return
    }

    # ── Execute: Schema ──
    Write-Section "Deploying: AD Schema Update" "Adding Windows LAPS attributes to the AD schema."
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

    # ── Execute: Permissions ──
    Write-Section "Deploying: OU Permissions" "SELF write + Read + Reset permissions on the target OU."
    foreach ($op in @(
        @{ Cmd = { Set-LapsADComputerSelfPermission -Identity $targetOU -ErrorAction Stop }; Desc = "SELF write permission" },
        @{ Cmd = { Set-LapsADReadPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Read permission for $readGroup" },
        @{ Cmd = { Set-LapsADResetPasswordPermission -Identity $targetOU -AllowedPrincipals $resetGroup -ErrorAction Stop }; Desc = "Reset permission for $resetGroup" }
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

    # ── Execute: GPO ──
    Write-Section "Deploying: GPO Creation and Configuration" "Creating GPO with all LAPS registry settings."
    $existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGPO) {
        Write-Status "GPO '$gpoName' already exists -- updating" "WARN"
    } else {
        New-GPO -Name $gpoName -Comment "Windows LAPS -- deployed by Invoke-LAPSToolkit.ps1" | Out-Null
        Write-Status "GPO created: $gpoName" "OK"
    }
    # Brief pause to let SYSVOL/Registry.pol settle before writing settings
    Start-Sleep -Seconds 1

    $reg = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $gpoErrors = 0
    $gpoSettings = @(
        @{ Name = "BackupDirectory";                    Type = "DWord";  Value = $backupDir }
        @{ Name = "PasswordComplexity";                 Type = "DWord";  Value = $pwdComplexity }
        @{ Name = "PasswordLength";                     Type = "DWord";  Value = $pwdLength }
        @{ Name = "PasswordAgeDays";                    Type = "DWord";  Value = $pwdAge }
        @{ Name = "ADPasswordEncryptionEnabled";        Type = "DWord";  Value = $(if ($doEncrypt) { 1 } else { 0 }) }
        @{ Name = "PostAuthenticationActions";          Type = "DWord";  Value = $postAuthAction }
        @{ Name = "PostAuthenticationResetDelay";       Type = "DWord";  Value = $postAuthH }
        @{ Name = "ADEncryptedPasswordHistorySize";     Type = "DWord";  Value = $historySize }
        @{ Name = "PasswordExpirationProtectionEnabled"; Type = "DWord"; Value = $expProtectVal }
    )
    if ($doEncrypt) {
        $gpoSettings += @{ Name = "ADPasswordEncryptionPrincipal"; Type = "String"; Value = $readGroup }
    }
    if ($adminAcct) {
        $gpoSettings += @{ Name = "AdministratorAccountName"; Type = "String"; Value = $adminAcct }
    }

    foreach ($s in $gpoSettings) {
        $ok = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName $s.Name -Type $s.Type -Value $s.Value -ErrorAction Stop | Out-Null
                Write-Status "$($s.Name) = $($s.Value)" "OK"
                $ok = $true
                break
            } catch {
                if ($attempt -lt 3) {
                    Write-Status "$($s.Name): retry $attempt/3 (Registry.pol may be locked)..." "WARN"
                    Start-Sleep -Seconds 2
                } else {
                    Write-Status "$($s.Name): $($_.Exception.Message)" "ERROR"
                    $gpoErrors++
                }
            }
        }
    }

    if ($gpoErrors -gt 0) {
        Write-Host ""
        Write-Status "$gpoErrors GPO setting(s) failed." "ERROR"
        Write-Host "  Common causes:" -ForegroundColor Yellow
        Write-Host "    - Access denied: run as a GPO administrator (e.g. Group Policy Creator Owners)" -ForegroundColor DarkGray
        Write-Host "    - GPO was just created: SYSVOL replication may need a moment" -ForegroundColor DarkGray
        Write-Host "    - If the GPO was created by another account, you may not have edit rights" -ForegroundColor DarkGray
        Write-Host ""
        if (-not (Confirm-Action "Continue anyway? (settings that succeeded are applied)")) {
            Pause-Screen; return
        }
    } else {
        Write-Status "GPO configured with all settings" "OK"
    }

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

    # ── Validate ──
    Write-Section "Validation" "Verifying that schema, permissions, and GPO are all in place."
    $check = Get-ADObject -SearchBase $script:SchemaNC -Filter { lDAPDisplayName -eq "msLAPS-EncryptedPassword" } -ErrorAction SilentlyContinue
    Write-Status "Schema attributes" $(if ($check) { "OK" } else { "ERROR" })

    try {
        $r = Find-LapsADExtendedRights -Identity $targetOU -ErrorAction SilentlyContinue
        Write-Status "OU permissions" $(if ($r) { "OK" } else { "WARN" })
    } catch { Write-Status "OU permissions check" "WARN" }

    $g = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    Write-Status "GPO" $(if ($g) { "OK" } else { "ERROR" })

    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host "   Deployment complete!" -ForegroundColor Green
    Write-Host "  ────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Run  gpupdate /force  on a test machine" -ForegroundColor White
    Write-Host "    2. Check the LAPS event log:" -ForegroundColor White
    Write-Host "       Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 10" -ForegroundColor DarkGray
    Write-Host "    3. Retrieve the password:" -ForegroundColor White
    Write-Host "       Get-LapsADPassword -Identity 'PC01' -AsPlainText" -ForegroundColor DarkGray

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
        ) -Descriptions @(
            "Check schema, GPO, DFL, computers, and module availability"
            "Extend AD schema + set SELF write = emulation mode ready"
            "Verify passwords are rotated after Legacy CSE removal"
            "Create Windows LAPS GPO with encryption and permissions"
            "Remove Legacy GPOs, clear attributes, remove ACEs"
            "Execute phases 1-5 back to back with confirmation prompts"
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
    Write-Section "Phase 1: Pre-Migration Assessment" "Checks your environment readiness before migration."
    Write-Host ""
    Write-Host "  What this phase does:" -ForegroundColor Yellow
    Write-Host "    - Verifies Legacy LAPS schema attributes exist" -ForegroundColor DarkGray
    Write-Host "    - Detects Legacy LAPS GPOs" -ForegroundColor DarkGray
    Write-Host "    - Counts computers with Legacy passwords" -ForegroundColor DarkGray
    Write-Host "    - Checks OS eligibility for Windows LAPS" -ForegroundColor DarkGray
    Write-Host "    - Validates LAPS module and DFL" -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Target OU" -Hint "The OU containing computers currently managed by Legacy LAPS." -Example "OU=Workstations,DC=contoso,DC=com" -AllowDomain
    if (Test-Cancelled $targetOU) { Pause-Screen; return }

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
    # Computers (exclude service accounts like AzureADKerberos, AZUREADSSOACC that have no real OS)
    $pcs = Get-ADComputer -Filter * -SearchBase $targetOU -Properties "ms-Mcs-AdmPwd", "OperatingSystem", "Enabled" -ErrorAction SilentlyContinue
    $realPcs = @($pcs | Where-Object { $_.OperatingSystem })
    $svcAccounts = @($pcs | Where-Object { -not $_.OperatingSystem -and $_.Enabled })
    $withPwd = @($realPcs | Where-Object { $_.'ms-Mcs-AdmPwd' })
    $enabledPcs = @($realPcs | Where-Object Enabled)
    $eligible = @($enabledPcs | Where-Object { $_.OperatingSystem -match "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025" })
    $notElig = $enabledPcs.Count - $eligible.Count

    Write-Status "Computers: $($realPcs.Count) total, $($enabledPcs.Count) enabled" "INFO"
    if ($svcAccounts.Count -gt 0) {
        Write-Status "Excluded: $($svcAccounts.Count) service/system accounts (no OS)" "INFO" ($svcAccounts.Name -join ", ")
    }
    Write-Status "With Legacy LAPS password: $($withPwd.Count)" $(if ($withPwd.Count -gt 0) { "OK" } else { "WARN" })
    Write-Status "OS eligible: $($eligible.Count)" "OK"
    if ($notElig -gt 0) {
        Write-Status "OS NOT eligible: $notElig" "WARN" "These machines need Legacy LAPS until their OS is upgraded"
        $notEligPcs = @($enabledPcs | Where-Object { $_.OperatingSystem -notmatch "Windows 10|Windows 11|Server 2019|Server 2022|Server 2025" })
        $notEligPcs | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object {
            Write-Host "           -> $($_.Name): $($_.Count)" -ForegroundColor DarkGray
        }
        $notEligPcs | Select-Object -First 10 | ForEach-Object {
            Write-Host "              $($_.Name) ($($_.OperatingSystem))" -ForegroundColor DarkGray
        }
        if ($notEligPcs.Count -gt 10) {
            Write-Host "              ... and $($notEligPcs.Count - 10) more" -ForegroundColor DarkGray
        }
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
    Write-Host "  Tip: To check which machines still have the Legacy CSE (AdmPwd.dll)" -ForegroundColor DarkGray
    Write-Host "  installed, go back to the main menu > [4] Quick Tools > [6] Check Legacy CSE." -ForegroundColor DarkGray

    Pause-Screen
}

function Invoke-MigrationSchemaEmulation {
    if (-not $script:LAPSModuleAvailable) {
        Write-Status "LAPS module required" "ERROR"; Pause-Screen; return
    }

    Write-Banner
    Write-Section "Phase 2: Schema Update and Emulation Mode" "Extends AD schema and prepares for Legacy CSE removal."
    Write-Host ""
    Write-Host "  What this phase does:" -ForegroundColor Yellow
    Write-Host "    - Adds Windows LAPS schema attributes (ms-LAPS-*)" -ForegroundColor DarkGray
    Write-Host "    - Grants SELF write permissions on the target OU" -ForegroundColor DarkGray
    Write-Host "    - After this, uninstalling the Legacy CSE triggers emulation mode" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Emulation mode = Windows LAPS reads the Legacy GPO and writes" -ForegroundColor Cyan
    Write-Host "  to ms-Mcs-AdmPwd. Zero disruption, same tools, same permissions." -ForegroundColor Cyan

    $targetOU = Read-OU -Label "Target OU" -Hint "The OU that currently has Legacy LAPS deployed. SELF write permission will be set here." -Example "OU=Workstations,DC=contoso,DC=com"
    if (Test-Cancelled $targetOU) { Pause-Screen; return }

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
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host "   Emulation Mode Ready!" -ForegroundColor Green
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next steps to activate emulation mode:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    1. UNINSTALL the Legacy LAPS CSE (AdmPwd.dll MSI)" -ForegroundColor White
    Write-Host "       from pilot machines" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    2. Windows LAPS (built into the OS) takes over" -ForegroundColor White
    Write-Host "       automatically -- zero configuration needed" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    3. It reads the existing Legacy LAPS GPO and writes" -ForegroundColor White
    Write-Host "       to ms-Mcs-AdmPwd (same attribute, same tools)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  IMPORTANT:" -ForegroundColor Red -NoNewline
    Write-Host " If the Legacy CSE is still installed," -ForegroundColor White
    Write-Host "  Windows LAPS will NOT activate! Remove the CSE first." -ForegroundColor White
    Write-Host ""
    Write-Host "  After uninstalling the CSE + gpupdate, use" -ForegroundColor DarkGray -NoNewline
    Write-Host " Phase 3" -ForegroundColor Cyan -NoNewline
    Write-Host " to validate." -ForegroundColor DarkGray

    Pause-Screen
}

function Invoke-MigrationValidatePilot {
    Write-Banner
    Write-Section "Phase 3: Pilot Validation" "Verify that Windows LAPS took over after Legacy CSE removal."
    Write-Host ""
    Write-Host "  What this phase does:" -ForegroundColor Yellow
    Write-Host "    - Scans computers in a target OU" -ForegroundColor DarkGray
    Write-Host "    - Shows which backend each machine uses:" -ForegroundColor DarkGray
    Write-Host "      Legacy / Emulation / Windows LAPS Clear / Encrypted" -ForegroundColor DarkGray
    Write-Host "    - Confirms all pilot machines are covered" -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Pilot OU" -Hint "The OU containing machines where you uninstalled the Legacy CSE." -Example "OU=Pilot,OU=Workstations,DC=contoso,DC=com"
    if (Test-Cancelled $targetOU) { Pause-Screen; return }

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
    Write-Host "  ── Password Status Breakdown ──" -ForegroundColor Yellow
    Write-Host ""
    foreach ($g in $grouped) {
        $color = switch ($g.Name) {
            "No LAPS"                     { "Red" }
            "Legacy LAPS / Emulation"     { "Yellow" }
            "Windows LAPS (Clear)"        { "DarkYellow" }
            "Windows LAPS (Encrypted)"    { "Green" }
            default { "White" }
        }
        $bar = "█" * [math]::Min([math]::Max([math]::Round($g.Count / [math]::Max($results.Count,1) * 30), 1), 30)
        Write-Host "   $bar " -ForegroundColor $color -NoNewline
        Write-Host "$($g.Count) " -ForegroundColor White -NoNewline
        Write-Host $g.Name -ForegroundColor $color
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
    Write-Section "Phase 4: Switch to Native Mode" "Create a Windows LAPS GPO with full features and encryption."
    Write-Host ""
    Write-Host "  What this phase does:" -ForegroundColor Yellow
    Write-Host "    - Sets Reader and Resetter permissions on the target OU" -ForegroundColor DarkGray
    Write-Host "    - Creates a dedicated Windows LAPS GPO" -ForegroundColor DarkGray
    Write-Host "    - Configures all settings (encryption, complexity, post-auth, etc.)" -ForegroundColor DarkGray
    Write-Host "    - Links the GPO to the target OU" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  After this, machines will store passwords in msLAPS-EncryptedPassword" -ForegroundColor Cyan
    Write-Host "  instead of the old ms-Mcs-AdmPwd attribute." -ForegroundColor Cyan

    # STEP 1 -- Target OU
    Write-Host ""
    Write-Host "  ── STEP 1/5: Target OU ──" -ForegroundColor Cyan
    $targetOU = Read-OU -Label "Target OU" -Hint "The GPO will be linked here. All computers below will be affected." -Example "OU=Workstations,DC=contoso,DC=com"
    if (Test-Cancelled $targetOU) { Pause-Screen; return }

    # STEP 2 -- Permission Groups
    Write-Host ""
    Write-Host "  ── STEP 2/5: Permission Groups ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  You need to specify AD groups that will receive LAPS" -ForegroundColor DarkGray
    Write-Host "  permissions. You can use the same group for both, or" -ForegroundColor DarkGray
    Write-Host "  separate groups for Read and Reset rights." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  [a] Password Readers" -ForegroundColor Yellow
    Write-Host "  Members can retrieve (read) LAPS passwords from AD." -ForegroundColor DarkGray
    Write-Host "  If encryption is enabled, this group is also the decryptor." -ForegroundColor DarkGray
    Write-Host "  Format: DOMAIN\GroupName   Example: CONTOSO\LAPS-Readers" -ForegroundColor DarkGray
    Write-Host ""
    $readGroup = Read-Param "Password Readers group" -Mandatory
    if (-not $readGroup -or $readGroup -eq "0") { Write-Status "Cancelled." "INFO"; Pause-Screen; return }
    $readGrpName = $readGroup -replace '^[^\\]+\\', ''
    try { Get-ADGroup -Identity $readGrpName -ErrorAction Stop | Out-Null }
    catch { Write-Status "Group not found: $readGroup" "ERROR"; Pause-Screen; return }
    Write-Status "Readers: $readGroup" "OK"

    Write-Host ""
    Write-Host "  [b] Password Resetters" -ForegroundColor Yellow
    Write-Host "  Members can force an immediate password rotation on any" -ForegroundColor DarkGray
    Write-Host "  computer in the target OU. Leave empty to use the same" -ForegroundColor DarkGray
    Write-Host "  group as Readers." -ForegroundColor DarkGray
    Write-Host ""
    $resetGroup = Read-Param "Password Resetters group (Enter = same as Readers)" -Default $readGroup
    $resetGrpName = $resetGroup -replace '^[^\\]+\\', ''
    try { Get-ADGroup -Identity $resetGrpName -ErrorAction Stop | Out-Null }
    catch { Write-Status "Group not found: $resetGroup" "ERROR"; Pause-Screen; return }
    if ($resetGroup -eq $readGroup) {
        Write-Status "Resetters: same as Readers ($resetGroup)" "OK"
    } else {
        Write-Status "Resetters: $resetGroup" "OK"
    }

    # STEP 3 -- GPO Settings (full wizard matching Deployment)
    Write-Host ""
    Write-Host "  ── STEP 3/5: GPO Settings ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host "  Configure all Windows LAPS Group Policy settings." -ForegroundColor DarkGray
    Write-Host "  Press Enter to accept each default (recommended)." -ForegroundColor DarkGray
    Write-Host ""

    $gpoName = Read-Param "GPO display name" -Default "Windows LAPS Policy"
    if ($gpoName -eq "0") { Write-Status "Cancelled." "INFO"; Pause-Screen; return }
    Write-Host ""

    Write-Host "  -- Backup Directory --" -ForegroundColor Yellow
    Write-Host "  Where the password is stored." -ForegroundColor DarkGray
    Write-Host "    0 = Disabled" -ForegroundColor DarkGray
    Write-Host "    1 = Azure AD only" -ForegroundColor DarkGray
    Write-Host "    2 = Active Directory" -ForegroundColor DarkGray
    $backupDir = [int](Read-Param "Backup Directory (0/1/2)" -Default "2")
    Write-Host ""

    Write-Host "  -- Password Complexity --" -ForegroundColor Yellow
    Write-Host "  Defines which characters the password includes." -ForegroundColor DarkGray
    Write-Host "    1 = Uppercase letters" -ForegroundColor DarkGray
    Write-Host "    2 = Uppercase + Lowercase" -ForegroundColor DarkGray
    Write-Host "    3 = Uppercase + Lowercase + Digits" -ForegroundColor DarkGray
    Write-Host "    4 = Uppercase + Lowercase + Digits + Special chars" -ForegroundColor DarkGray
    $pwdComplexity = [int](Read-Param "Password Complexity (1-4)" -Default "4")
    Write-Host ""

    Write-Host "  -- Password Length --" -ForegroundColor Yellow
    Write-Host "  Number of characters in the generated password (8-64)." -ForegroundColor DarkGray
    $pwdLen = [int](Read-Param "Password Length" -Default "20")
    Write-Host ""

    Write-Host "  -- Password Age --" -ForegroundColor Yellow
    Write-Host "  How often the password is rotated (1-365 days)." -ForegroundColor DarkGray
    $pwdAge = [int](Read-Param "Password Age (days)" -Default "30")
    Write-Host ""

    Write-Host "  -- Post-Authentication Actions --" -ForegroundColor Yellow
    Write-Host "  What happens after an admin uses the LAPS password." -ForegroundColor DarkGray
    Write-Host "    0 = Disabled (no action)" -ForegroundColor DarkGray
    Write-Host "    1 = Reset password" -ForegroundColor DarkGray
    Write-Host "    3 = Reset password + logoff" -ForegroundColor DarkGray
    Write-Host "    5 = Reset password + reboot" -ForegroundColor DarkGray
    $postAuthAction = [int](Read-Param "Post-Auth Action (0/1/3/5)" -Default "3")
    Write-Host ""

    Write-Host "  -- Post-Authentication Reset Delay --" -ForegroundColor Yellow
    Write-Host "  Hours to wait before the post-auth action triggers (0-24)." -ForegroundColor DarkGray
    $postAuth = [int](Read-Param "Post-Auth Delay (hours)" -Default "8")
    Write-Host ""

    Write-Host "  -- Encrypted Password History Size --" -ForegroundColor Yellow
    Write-Host "  Number of previous encrypted passwords to keep (0-12)." -ForegroundColor DarkGray
    Write-Host "  Only works when encryption is enabled." -ForegroundColor DarkGray
    $historySize = [int](Read-Param "Password History Size" -Default "0")
    Write-Host ""

    Write-Host "  -- Password Expiration Protection --" -ForegroundColor Yellow
    Write-Host "  Prevents the computer from extending the expiry beyond the" -ForegroundColor DarkGray
    Write-Host "  policy-defined max age (protects against tampering)." -ForegroundColor DarkGray
    $expProtect = Read-Param "Expiration Protection (yes/no)" -Default "yes"
    $expProtectVal = if ($expProtect -match '^y') { 1 } else { 0 }
    Write-Host ""

    Write-Host "  -- Administrator Account Name --" -ForegroundColor Yellow
    Write-Host "  Leave empty = LAPS manages the built-in Administrator (RID 500)." -ForegroundColor DarkGray
    Write-Host "  Specify a name only if you use a custom local admin account." -ForegroundColor DarkGray
    $adminAcct = Read-Param "Custom admin account name (or Enter for built-in)"

    $doEncrypt = $script:DFLSupportsEncryption
    if (-not $doEncrypt) {
        Write-Host ""
        Write-Status "DFL does not support encryption -- passwords will be stored in clear text" "WARN"
    }

    # STEP 4 -- Recap and confirm
    Write-Host ""
    Write-Host "  ── STEP 4/5: Review ──" -ForegroundColor Cyan
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "    Target OU           : $targetOU" -ForegroundColor White
    Write-Host "    Password Readers    : $readGroup" -ForegroundColor White
    Write-Host "    Password Resetters  : $resetGroup" -ForegroundColor White
    Write-Host "    GPO Name            : $gpoName" -ForegroundColor White
    Write-Host "    Backup Directory    : $backupDir $(switch($backupDir){ 0{'(Disabled)'} 1{'(Azure AD)'} 2{'(Active Directory)'} })" -ForegroundColor White
    Write-Host "    Password Complexity : $pwdComplexity" -ForegroundColor White
    Write-Host "    Password Length     : $pwdLen chars" -ForegroundColor White
    Write-Host "    Password Age        : $pwdAge days" -ForegroundColor White
    Write-Host "    Encryption          : $(if ($doEncrypt) { 'Yes (decryptor: ' + $readGroup + ')' } else { 'No (DFL < 2016)' })" -ForegroundColor White
    Write-Host "    Post-Auth Action    : $postAuthAction" -ForegroundColor White
    Write-Host "    Post-Auth Delay     : $postAuth hours" -ForegroundColor White
    Write-Host "    Password History    : $historySize" -ForegroundColor White
    Write-Host "    Expiration Protection: $(if ($expProtectVal) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
    Write-Host "    Admin Account       : $(if ($adminAcct) { $adminAcct } else { 'Built-in Administrator (RID 500)' })" -ForegroundColor White
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkCyan

    if (-not (Confirm-Action "Switch $targetOU to Windows LAPS native mode?")) {
        Pause-Screen; return
    }

    # ── Execute: Permissions ──
    Write-Section "Deploying: OU Permissions" "Granting Read and Reset permissions to the specified groups."
    foreach ($op in @(
        @{ Cmd = { Set-LapsADReadPasswordPermission -Identity $targetOU -AllowedPrincipals $readGroup -ErrorAction Stop }; Desc = "Read permission ($readGroup)" },
        @{ Cmd = { Set-LapsADResetPasswordPermission -Identity $targetOU -AllowedPrincipals $resetGroup -ErrorAction Stop }; Desc = "Reset permission ($resetGroup)" }
    )) {
        Write-Status "Setting $($op.Desc)..." "RUN"
        try { & $op.Cmd; Write-Status $op.Desc "OK" }
        catch {
            if ($_.Exception.Message -match "already") { Write-Status "$($op.Desc) -- already set" "OK" }
            else { Write-Status "Failed: $($_.Exception.Message)" "ERROR"; Pause-Screen; return }
        }
    }

    # ── Execute: GPO Creation and Configuration ──
    Write-Section "Deploying: GPO Creation and Configuration" "Creating GPO with all LAPS registry settings + retry logic."
    $existing = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-GPO -Name $gpoName -Comment "Windows LAPS native -- Invoke-LAPSToolkit.ps1" | Out-Null
        Write-Status "GPO created: $gpoName" "OK"
    } else { Write-Status "GPO '$gpoName' exists -- updating" "INFO" }
    # Brief pause to let SYSVOL/Registry.pol settle before writing settings
    Start-Sleep -Seconds 1

    $reg = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $enc = if ($doEncrypt) { 1 } else { 0 }
    $gpoErrors = 0
    $gpoSettings = @(
        @{ Name = "BackupDirectory";                    Type = "DWord";  Value = $backupDir }
        @{ Name = "PasswordComplexity";                 Type = "DWord";  Value = $pwdComplexity }
        @{ Name = "PasswordLength";                     Type = "DWord";  Value = $pwdLen }
        @{ Name = "PasswordAgeDays";                    Type = "DWord";  Value = $pwdAge }
        @{ Name = "ADPasswordEncryptionEnabled";        Type = "DWord";  Value = $enc }
        @{ Name = "PostAuthenticationActions";          Type = "DWord";  Value = $postAuthAction }
        @{ Name = "PostAuthenticationResetDelay";       Type = "DWord";  Value = $postAuth }
        @{ Name = "ADEncryptedPasswordHistorySize";     Type = "DWord";  Value = $historySize }
        @{ Name = "PasswordExpirationProtectionEnabled"; Type = "DWord"; Value = $expProtectVal }
    )
    if ($enc) {
        $gpoSettings += @{ Name = "ADPasswordEncryptionPrincipal"; Type = "String"; Value = $readGroup }
    }
    if ($adminAcct) {
        $gpoSettings += @{ Name = "AdministratorAccountName"; Type = "String"; Value = $adminAcct }
    }

    foreach ($s in $gpoSettings) {
        $ok = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Set-GPRegistryValue -Name $gpoName -Key $reg -ValueName $s.Name -Type $s.Type -Value $s.Value -ErrorAction Stop | Out-Null
                Write-Status "$($s.Name) = $($s.Value)" "OK"
                $ok = $true
                break
            } catch {
                if ($attempt -lt 3) {
                    Write-Status "$($s.Name): retry $attempt/3 (Registry.pol may be locked)..." "WARN"
                    Start-Sleep -Seconds 2
                } else {
                    Write-Status "$($s.Name): $($_.Exception.Message)" "ERROR"
                    $gpoErrors++
                }
            }
        }
    }

    if ($gpoErrors -gt 0) {
        Write-Host ""
        Write-Status "$gpoErrors GPO setting(s) failed." "ERROR"
        Write-Host "  Common causes:" -ForegroundColor Yellow
        Write-Host "    - Access denied: run as a GPO administrator" -ForegroundColor DarkGray
        Write-Host "    - GPO was just created: SYSVOL replication may need a moment" -ForegroundColor DarkGray
        Write-Host ""
        if (-not (Confirm-Action "Continue anyway? (settings that succeeded are applied)")) {
            Pause-Screen; return
        }
    } else {
        Write-Status "GPO configured with all settings" "OK"
    }

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
    } catch { Write-Status "Link failed: $($_.Exception.Message)" "ERROR" }

    Write-Host ""
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host "   Native mode activated!" -ForegroundColor Green
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Passwords will now be stored in msLAPS-EncryptedPassword." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor Yellow
    Write-Host "    1. Run gpupdate /force on a test machine" -ForegroundColor White
    Write-Host "    2. Use Phase 3 to validate passwords are rotated" -ForegroundColor White
    Write-Host "    3. Then use Phase 5 to clean up Legacy LAPS artifacts" -ForegroundColor White

    Pause-Screen
}

function Invoke-MigrationCleanup {
    Write-Banner
    Write-Section "Phase 5: Legacy LAPS Cleanup" "Remove all Legacy LAPS artifacts from your environment."
    Write-Host ""
    Write-Host "  What this phase does:" -ForegroundColor Yellow
    Write-Host "    - Detects and unlinks Legacy LAPS GPOs" -ForegroundColor DarkGray
    Write-Host "    - Clears ms-Mcs-AdmPwd and ms-Mcs-AdmPwdExpirationTime values" -ForegroundColor DarkGray
    Write-Host "    - Scans and optionally removes Legacy LAPS ACEs from OUs" -ForegroundColor DarkGray
    Write-Host "    - Reminds you to uninstall the Legacy CSE MSI from clients" -ForegroundColor DarkGray

    $targetOU = Read-OU -Label "Target OU" -Hint "All Legacy LAPS data (GPO links, attributes, ACEs) under this OU will be removed." -Example "OU=Workstations,DC=contoso,DC=com"
    if (Test-Cancelled $targetOU) { Pause-Screen; return }

    Write-Banner
    Write-Section "Phase 5: Legacy LAPS Cleanup"
    Write-Host "  Scope: $targetOU" -ForegroundColor White

    if (-not (Confirm-Action "Clean up Legacy LAPS in $targetOU ?")) {
        Pause-Screen; return
    }

    # Detect & unlink Legacy GPOs
    Write-Host ""
    Write-Host "  ── Step 1/3: Legacy GPO Detection ──" -ForegroundColor Yellow
    Write-Host "  Scanning for Legacy LAPS GPOs linked to $targetOU" -ForegroundColor DarkGray

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
    Write-Host "  ── Step 2/3: Legacy Attribute Cleanup ──" -ForegroundColor Yellow
    Write-Host "  Clearing stale ms-Mcs-AdmPwd values on computer objects." -ForegroundColor DarkGray

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
    Write-Host "  ── Step 3/3: Legacy ACE Cleanup ──" -ForegroundColor Yellow
    Write-Host "  Scanning OUs for Legacy LAPS permission ACEs (ms-Mcs-AdmPwd)." -ForegroundColor DarkGray

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
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host "   Legacy LAPS cleanup complete!" -ForegroundColor Green
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Remaining manual step:" -ForegroundColor Yellow
    Write-Status "Uninstall the Legacy LAPS MSI (AdmPwd CSE) from all remaining clients" "INFO"
    Write-Host "    Options: SCCM / Intune app removal, GPO software uninstall, or manual" -ForegroundColor DarkGray

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
        ) -Descriptions @(
            "Read the current LAPS password from AD (Windows + Legacy)"
            "Trigger immediate password rotation via PSRemoting"
            "Read the last 20 LAPS events from a remote machine"
            "Gather registry, logs, and CSE info on this machine"
            "Show who can read/reset LAPS passwords on an OU"
            "PSRemoting scan: find machines with AdmPwd.dll installed"
            "Scan OUs for leftover Legacy LAPS permissions (ACEs)"
        ) -AllowBack

        switch ($choice) {
            "1" {
                Write-Host ""
                Write-Host "  ── Retrieve LAPS Password ──" -ForegroundColor Yellow
                Write-Host "  Reads the current LAPS password stored in AD for a computer." -ForegroundColor DarkGray
                Write-Host "  Works with both Windows LAPS and Legacy LAPS (fallback)." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The computer whose LAPS password you want to retrieve."
                if (Test-Cancelled $pc) { Pause-Screen; continue }
                Write-Host ""
                try {
                    $pwd = Get-LapsADPassword -Identity $pc -AsPlainText -ErrorAction Stop
                    Write-Host ""
                    Write-Host "  ────────────────────────────────────────" -ForegroundColor DarkCyan
                    Write-Host "  Computer       : " -ForegroundColor DarkGray -NoNewline; Write-Host $pwd.ComputerName -ForegroundColor Cyan
                    Write-Host "  Account        : " -ForegroundColor DarkGray -NoNewline; Write-Host $pwd.Account -ForegroundColor White
                    Write-Host "  Password       : " -ForegroundColor DarkGray -NoNewline; Write-Host $pwd.Password -ForegroundColor Green
                    Write-Host "  Expiration     : " -ForegroundColor DarkGray -NoNewline; Write-Host $pwd.ExpirationTimestamp -ForegroundColor Yellow
                    Write-Host "  Last Updated   : " -ForegroundColor DarkGray -NoNewline; Write-Host $pwd.PasswordUpdateTime -ForegroundColor DarkGray
                    Write-Host "  ────────────────────────────────────────" -ForegroundColor DarkCyan
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
                Write-Host "  ── Force Password Rotation ──" -ForegroundColor Yellow
                Write-Host "  Triggers an immediate password rotation on a remote computer." -ForegroundColor DarkGray
                Write-Host "  The machine must be online and reachable via PSRemoting (WinRM)." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The machine must be online and reachable."
                if (Test-Cancelled $pc) { Pause-Screen; continue }
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
                Write-Host "  ── LAPS Event Log ──" -ForegroundColor Yellow
                Write-Host "  Reads the last 20 events from Microsoft-Windows-LAPS/Operational" -ForegroundColor DarkGray
                Write-Host "  on a remote machine. Requires PSRemoting (WinRM) enabled." -ForegroundColor DarkGray
                $pc = Read-Computer -Label "Target computer" -Hint "The machine must be online and WinRM enabled."
                if (Test-Cancelled $pc) { Pause-Screen; continue }
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
                Write-Host "  ── LAPS Diagnostics ──" -ForegroundColor Yellow
                Write-Host "  Collects Windows LAPS diagnostic data from this machine." -ForegroundColor DarkGray
                Write-Host "  Includes registry settings, event logs, and CSE status." -ForegroundColor DarkGray
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
                Write-Host "  ── Audit OU Extended Rights ──" -ForegroundColor Yellow
                Write-Host "  Shows which principals have LAPS extended rights on an OU." -ForegroundColor DarkGray
                Write-Host "  This tells you who can read or reset LAPS passwords." -ForegroundColor DarkGray
                $ou = Read-OU -Label "Target OU" -Hint "Extended rights (Read/Reset LAPS passwords) will be listed for all principals on this OU."
                if (Test-Cancelled $ou) { Pause-Screen; continue }
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
                Write-Host "  ── Check Legacy CSE (Remote) ──" -ForegroundColor Yellow
                Write-Host "  Checks whether the Legacy LAPS CSE (AdmPwd.dll) is still installed" -ForegroundColor DarkGray
                Write-Host "  on remote computers via PSRemoting (WinRM must be enabled)." -ForegroundColor DarkGray
                Write-Host "  Machines with the CSE still present will NOT activate Windows LAPS." -ForegroundColor DarkGray
                $searchBase = Read-OU -Label "Target OU" -Hint "All computers under this OU will be checked via PSRemoting (WinRM must be enabled)."
                if (Test-Cancelled $searchBase) { Pause-Screen; continue }
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
                Write-Host "  ── Audit Legacy LAPS ACEs ──" -ForegroundColor Yellow
                Write-Host "  Scans OUs for Legacy LAPS ACEs (ms-Mcs-AdmPwd permissions)." -ForegroundColor DarkGray
                Write-Host "  Shows direct vs inherited ACEs. Use Migration > Phase 5 to remove." -ForegroundColor DarkGray
                $rootOU = Read-OU -Label "Root OU" -Hint "All child OUs will also be scanned recursively for Legacy LAPS ACEs (ms-Mcs-AdmPwd permissions)."
                if (Test-Cancelled $rootOU) { Pause-Screen; continue }
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

    # -- Environment Dashboard --
    Write-BoxTitle "Environment"

    # Schema
    $schemaLabel = "None"; $schemaColor = "Red"
    if ($script:HasLegacySchema -and $script:HasWLAPSSchema) { $schemaLabel = "Legacy + Windows LAPS"; $schemaColor = "Green" }
    elseif ($script:HasWLAPSSchema)  { $schemaLabel = "Windows LAPS"; $schemaColor = "Green" }
    elseif ($script:HasLegacySchema) { $schemaLabel = "Legacy only"; $schemaColor = "Yellow" }
    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $lbl = "  Schema            : "
    Write-Host $lbl -ForegroundColor DarkGray -NoNewline
    Write-Host $schemaLabel.PadRight($script:BoxW - $lbl.Length) -ForegroundColor $schemaColor -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    # DFL
    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $lbl = "  DFL               : "; $dfl = "$($script:Domain.DomainMode)"
    $suf = if ($script:DFLSupportsEncryption) { " (encryption OK)" } else { " (no encryption)" }
    $sufColor = if ($script:DFLSupportsEncryption) { "Green" } else { "Yellow" }
    Write-Host $lbl -ForegroundColor DarkGray -NoNewline
    Write-Host $dfl -ForegroundColor White -NoNewline
    Write-Host $suf.PadRight($script:BoxW - $lbl.Length - $dfl.Length) -ForegroundColor $sufColor -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    # Module
    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $lbl = "  LAPS Module       : "
    $modLabel = if ($script:LAPSModuleAvailable) { "Loaded" } else { "NOT available" }
    $modColor = if ($script:LAPSModuleAvailable) { "Green" } else { "Yellow" }
    Write-Host $lbl -ForegroundColor DarkGray -NoNewline
    Write-Host $modLabel.PadRight($script:BoxW - $lbl.Length) -ForegroundColor $modColor -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-BoxBottom

    # -- Actions --
    Write-Host ""
    Write-BoxTitle "Actions"
    Write-BoxEmpty

    # Menu items: number (Cyan) + title (White) on line 1, description (DarkGray) on line 2
    $menuItems = @(
        @{ N = "1"; Title = "Assessment";  Desc = "Full audit of current LAPS state" },
        @{ N = "2"; Title = "Deployment";  Desc = "Deploy Windows LAPS from scratch" },
        @{ N = "3"; Title = "Migration";   Desc = "Legacy LAPS -> Windows LAPS (guided)" },
        @{ N = "4"; Title = "Quick Tools"; Desc = "Password retrieval, rotation, diagnostics" }
    )

    foreach ($item in $menuItems) {
        # Title line
        Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
        $num = "   [$($item.N)]  "; $title = $item.Title
        Write-Host $num -ForegroundColor Cyan -NoNewline
        Write-Host $title.PadRight($script:BoxW - $num.Length) -ForegroundColor White -NoNewline
        Write-Host "|" -ForegroundColor DarkCyan
        # Desc line
        Write-BoxLine "        $($item.Desc)" "DarkGray"
    }

    Write-BoxEmpty

    Write-Host "  |" -ForegroundColor DarkCyan -NoNewline
    $num = "   [Q]  "; $title = "Exit"
    Write-Host $num -ForegroundColor DarkGray -NoNewline
    Write-Host $title.PadRight($script:BoxW - $num.Length) -ForegroundColor DarkGray -NoNewline
    Write-Host "|" -ForegroundColor DarkCyan

    Write-BoxBottom
    Write-Host ""

    $choice = Read-Host "  Select an option"

    switch ($choice) {
        "1" { Invoke-Assessment }
        "2" { Invoke-Deployment }
        "3" { Invoke-Migration }
        "4" { Invoke-QuickTools }
        { $_ -eq '5' -or $_ -eq 'Q' -or $_ -eq 'q' } { Write-Host ""; Write-Host "  Bye!" -ForegroundColor Cyan; exit 0 }
        default { continue }
    }
}
