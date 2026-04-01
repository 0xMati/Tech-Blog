 <#
    .SYNOPSIS
    Removes or lists orphaned SIDs from Active Directory objects.

    .DESCRIPTION
    This script scans Active Directory objects for access control entries (ACEs) that reference
    SIDs which no longer resolve to an existing account. It uses a single LDAP query with Subtree
    scope for better performance and includes proper error handling.

    By default, only orphaned SIDs belonging to the current domain are detected.
    Use -IncludeTrustedDomains to also detect orphaned SIDs from trusted (external) domains.

    .PARAMETER SearchBase
    Specifies the starting point for the scan. Use "All" for the entire forest or provide a
    specific DN like "OU=Users,DC=example,DC=com".

    .PARAMETER List
    Lists the orphaned SIDs found without making any changes (report mode).
    Mutually exclusive with -Remove.

    .PARAMETER Remove
    Removes the orphaned SIDs from the ACLs.
    Mutually exclusive with -List.

    .PARAMETER IncludeTrustedDomains
    If specified, the script will also detect orphaned SIDs from trusted domains,
    not just the current domain. Any unresolved SID will be flagged.

    .PARAMETER LogPath
    Path to the transcript log file. Defaults to "C:\temp\RemoveOrphanedSID-AD-V2.txt".

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List
    Lists all orphaned SIDs in the entire forest (report only).

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Remove
    Removes orphaned SIDs from the specified OU.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -IncludeTrustedDomains
    Lists all orphaned SIDs including those from trusted domains.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Remove -WhatIf
    Shows what would be changed without actually altering the ACLs.

    .LINK
    www.alitajran.com/remove-orphaned-sids/

    .NOTES
    Written by: ALI TAJRAN
    Website:    www.alitajran.com
    LinkedIn:   linkedin.com/in/alitajran

    .CHANGELOG
    V1.00, 01/27/2025 - Initial version
    V2.00, 03/31/2026 - Major rework: single LDAP query, error handling,
                         trusted domain support, SupportsShouldProcess,
                         progress bar, summary report
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'List')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [string]$SearchBase,

    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch]$Remove,

    [switch]$IncludeTrustedDomains,

    [string]$LogPath = "C:\temp\RemoveOrphanedSID-AD-V2.txt"
)

# ── Initialisation ──────────────────────────────────────────────────────────
try {
    $Forest = Get-ADRootDSE -ErrorAction Stop
}
catch {
    Write-Error "Unable to contact Active Directory: $_"
    return
}

$ForestDN = $Forest.rootDomainNamingContext

try {
    $DomainSID = (Get-ADDomain -Identity $ForestDN -ErrorAction Stop).DomainSID.ToString()
}
catch {
    Write-Error "Unable to retrieve domain SID for '$ForestDN': $_"
    return
}

# Ensure log directory exists
$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Start-Transcript -Path $LogPath -Append -Force

# Determine search base
if ($SearchBase -eq "All") {
    $TargetDN = $ForestDN
    Write-Host "Scanning the entire forest: $ForestDN" -ForegroundColor Cyan
}
else {
    $TargetDN = $SearchBase
    Write-Host "Scanning: $TargetDN" -ForegroundColor Cyan
}

if ($IncludeTrustedDomains) {
    Write-Host "Mode: including orphaned SIDs from trusted domains" -ForegroundColor Cyan
}
else {
    Write-Host "Mode: current domain SIDs only (SID prefix $DomainSID)" -ForegroundColor Cyan
}

# ── Trust reachability check (when -IncludeTrustedDomains) ──────────────────
if ($IncludeTrustedDomains) {
    Write-Host "`nChecking trust reachability..." -ForegroundColor Cyan

    try {
        $trusts = Get-ADTrust -Filter * -Properties securityIdentifier -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to enumerate trusts: $_"
        $trusts = @()
    }

    if ($trusts) {
        $trustResults = @()
        foreach ($trust in $trusts) {
            $tName = $trust.Name
            $tSID  = if ($trust.securityIdentifier) { $trust.securityIdentifier.ToString() } else { "(no SID)" }
            $tDir  = $trust.Direction.ToString()

            # Test reachability: try Get-ADDomain first, fallback to nltest /dsgetdc
            # Get-ADDomain may fail on outbound-only trusts (no permission to query remote AD)
            # nltest /dsgetdc uses the DC locator — same mechanism AD uses for SID resolution
            $reachable = $false
            try {
                $null = Get-ADDomain -Identity $tName -ErrorAction Stop
                $reachable = $true
            }
            catch {
                try {
                    $nlResult = nltest /dsgetdc:$tName 2>&1
                    if ($LASTEXITCODE -eq 0) { $reachable = $true }
                }
                catch { }
            }

            $trustResults += [PSCustomObject]@{
                Name      = $tName
                SID       = $tSID
                Direction = $tDir
                Reachable = $reachable
            }
        }

        # Display trust reachability table
        $colT = 28; $colS = 48; $colD = 14; $colR = 12
        $sepT = "+" + ("-" * ($colT + $colS + $colD + $colR + 5)) + "+"
        Write-Host "`n$sepT" -ForegroundColor Gray
        Write-Host ("| {0,-$colT} {1,-$colS} {2,-$colD} {3,-$colR}|" -f "TRUST", "SID", "DIRECTION", "STATUS") -ForegroundColor Gray
        Write-Host $sepT -ForegroundColor Gray

        foreach ($t in $trustResults) {
            $statusText  = if ($t.Reachable) { "Reachable" } else { "Unreachable" }
            $statusColor = if ($t.Reachable) { "Green" } else { "Red" }
            Write-Host ("| {0,-$colT} {1,-$colS} {2,-$colD} " -f $t.Name, $t.SID, $t.Direction) -ForegroundColor White -NoNewline
            Write-Host ("{0,-$colR}|" -f $statusText) -ForegroundColor $statusColor
        }
        Write-Host $sepT -ForegroundColor Gray

        $unreachable = @($trustResults | Where-Object { -not $_.Reachable })
        if ($unreachable.Count -gt 0) {
            Write-Host ""
            Write-Host "WARNING: $($unreachable.Count) trust(s) unreachable!" -ForegroundColor Red
            Write-Host "SIDs from unreachable trusts may appear as false positives." -ForegroundColor Yellow
            Write-Host "Unreachable:" -ForegroundColor Yellow
            foreach ($u in $unreachable) {
                Write-Host "  - $($u.Name) ($($u.SID))" -ForegroundColor Yellow
            }
            Write-Host ""
            $confirm = Read-Host "Continue anyway? (Y/N)"
            if ($confirm -notmatch '^[Yy]') {
                Write-Host "Aborted by user." -ForegroundColor Red
                Stop-Transcript
                return
            }
        }
        else {
            Write-Host "`nAll trusts are reachable." -ForegroundColor Green
        }
    }
    else {
        Write-Host "No trusts found." -ForegroundColor Yellow
    }
}

# ── Collect all objects in a single LDAP query ──────────────────────────────
Write-Host "`nRetrieving AD objects from '$TargetDN' ..." -ForegroundColor Cyan

try {
    $ADObjects = @(Get-ADObject -LDAPFilter "(objectClass=*)" -SearchBase $TargetDN -SearchScope Subtree -ErrorAction Stop)
}
catch {
    Write-Error "Failed to query AD objects under '$TargetDN': $_"
    Stop-Transcript
    return
}

$TotalObjects = $ADObjects.Count
Write-Host "Found $TotalObjects objects to analyse.`n" -ForegroundColor Cyan

# ── Counters ────────────────────────────────────────────────────────────────
$ObjectsScanned   = 0
$ObjectsWithError = 0
$OrphanedACEsFound   = 0
$OrphanedACEsRemoved = 0
$ObjectsModified  = 0
$OrphanedResults  = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── Well-known SID prefixes (never orphaned) ───────────────────────────────
# S-1-0   Null Authority
# S-1-1   World Authority (Everyone)
# S-1-2   Local Authority
# S-1-3   Creator Authority
# S-1-5-32 BUILTIN domain (Account Operators, Administrators, etc.)
# S-1-5-1 through S-1-5-20  well-known identities (Network, Interactive, etc.)
$WellKnownPrefixes = @(
    'S-1-0', 'S-1-1', 'S-1-2', 'S-1-3', 'S-1-5-32'
)
$WellKnownExact = @(
    'S-1-5-1', 'S-1-5-2', 'S-1-5-3', 'S-1-5-4', 'S-1-5-6',
    'S-1-5-7', 'S-1-5-8', 'S-1-5-9', 'S-1-5-10', 'S-1-5-11',
    'S-1-5-12', 'S-1-5-13', 'S-1-5-14', 'S-1-5-15', 'S-1-5-17',
    'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
)

function Test-WellKnownSID {
    param ([string]$SIDValue)
    if ($SIDValue -in $WellKnownExact) { return $true }
    foreach ($prefix in $WellKnownPrefixes) {
        if ($SIDValue -like "$prefix*") { return $true }
    }
    return $false
}

# ── Helper: test if an ACE references an orphaned SID ──────────────────────
function Test-OrphanedACE {
    param (
        [System.DirectoryServices.ActiveDirectoryAccessRule]$ACE
    )

    $identity = $ACE.IdentityReference

    if ($IncludeTrustedDomains) {
        # Unresolved SID (still a SecurityIdentifier, not an NTAccount), excluding well-known SIDs
        if ($identity -is [System.Security.Principal.SecurityIdentifier]) {
            return -not (Test-WellKnownSID $identity.Value)
        }
        return $false
    }
    else {
        # Only flag SIDs belonging to the current domain
        return ($identity.Value -like "$DomainSID*")
    }
}

# ── Main processing loop ───────────────────────────────────────────────────
foreach ($obj in $ADObjects) {
    $ObjectsScanned++
    $dn = $obj.DistinguishedName

    # Progress bar
    if ($TotalObjects -gt 0) {
        $pct = [math]::Min(100, [int](($ObjectsScanned / $TotalObjects) * 100))
        Write-Progress -Activity "Scanning ACLs" -Status "$ObjectsScanned / $TotalObjects" `
            -PercentComplete $pct -CurrentOperation $dn
    }

    # Read ACL
    try {
        $acl = Get-ACL -Path "AD:$dn" -ErrorAction Stop
    }
    catch {
        Write-Warning "Cannot read ACL on '$dn': $_"
        $ObjectsWithError++
        continue
    }

    $modified = $false
    $orphansOnThisObject = @()

    foreach ($ace in $acl.Access) {
        if (Test-OrphanedACE -ACE $ace) {
            $sid = $ace.IdentityReference.Value
            $OrphanedACEsFound++

            if ($sid -notin $orphansOnThisObject) {
                $orphansOnThisObject += $sid
                $sidOrigin = if ($sid -like "$DomainSID*") { "Current Domain" } else { "Trusted Domain" }
                $OrphanedResults.Add([PSCustomObject]@{
                    SID    = $sid
                    Object = $dn
                    ACEs   = 0
                    Origin = $sidOrigin
                })
            }
            # Increment ACE count for this SID/Object pair
            ($OrphanedResults | Where-Object { $_.SID -eq $sid -and $_.Object -eq $dn }).ACEs++

            if ($Remove) {
                if ($PSCmdlet.ShouldProcess($dn, "Remove orphaned ACE for SID $sid")) {
                    try {
                        $acl.RemoveAccessRuleSpecific($ace)
                        $modified = $true
                        $OrphanedACEsRemoved++
                    }
                    catch {
                        Write-Warning "Failed to remove ACE for SID $sid on '$dn': $_"
                        $ObjectsWithError++
                    }
                }
            }
        }
    }

    # Write back modified ACL
    if ($modified) {
        try {
            Set-ACL -Path "AD:$dn" -AclObject $acl -ErrorAction Stop
            Write-Host "Orphaned SID(s) removed on $dn" -ForegroundColor Red
            $ObjectsModified++
        }
        catch {
            Write-Warning "Failed to write ACL on '$dn': $_"
            $ObjectsWithError++
        }
    }
}

Write-Progress -Activity "Scanning ACLs" -Completed

# ── Orphaned SIDs detail ────────────────────────────────────────────────────
if ($OrphanedResults.Count -gt 0) {
    $currentDomainResults = $OrphanedResults | Where-Object { $_.Origin -eq "Current Domain" }
    $trustedDomainResults = $OrphanedResults | Where-Object { $_.Origin -eq "Trusted Domain" }

    foreach ($section in @(
        @{ Label = "CURRENT DOMAIN"; Color = "Yellow"; Data = $currentDomainResults },
        @{ Label = "TRUSTED DOMAINS"; Color = "Magenta"; Data = $trustedDomainResults }
    )) {
        if ($section.Data -and @($section.Data).Count -gt 0) {
            $sectionACEs = ($section.Data | Measure-Object -Property ACEs -Sum).Sum
            Write-Host ("`n+---ORPHANED SIDs: {0} ({1} ACEs)---" -f $section.Label, $sectionACEs).PadRight(73, '-') -NoNewline
            Write-Host "+" -ForegroundColor $section.Color

            $groupedBySID = $section.Data | Group-Object -Property SID | Sort-Object -Property @{Expression={$_.Group | Measure-Object -Property ACEs -Sum | Select-Object -ExpandProperty Sum}; Descending=$true}
            foreach ($group in $groupedBySID) {
                $totalACEs = ($group.Group | Measure-Object -Property ACEs -Sum).Sum
                Write-Host ("  SID: {0}  ({1} ACEs on {2} objects)" -f $group.Name, $totalACEs, $group.Count) -ForegroundColor Cyan
                foreach ($entry in $group.Group) {
                    Write-Host ("    -> {0} ({1} ACEs)" -f $entry.Object, $entry.ACEs) -ForegroundColor Gray
                }
                Write-Host ""
            }
            Write-Host "+------------------------------------------------------------------------+" -ForegroundColor $section.Color
        }
    }
}
else {
    Write-Host "`nNo orphaned SIDs found." -ForegroundColor Green
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host "`n+======================================+" -ForegroundColor Cyan
Write-Host   "|           SUMMARY REPORT             |" -ForegroundColor Cyan
Write-Host   "+======================================+" -ForegroundColor Cyan
Write-Host   "| Objects scanned   : $($ObjectsScanned.ToString().PadLeft(15)) |" -ForegroundColor Cyan
$currentDomainACEs = if ($OrphanedResults.Count -gt 0) { ($OrphanedResults | Where-Object { $_.Origin -eq 'Current Domain' } | Measure-Object -Property ACEs -Sum).Sum } else { 0 }
$trustedDomainACEs = if ($OrphanedResults.Count -gt 0) { ($OrphanedResults | Where-Object { $_.Origin -eq 'Trusted Domain' } | Measure-Object -Property ACEs -Sum).Sum } else { 0 }
if (-not $currentDomainACEs) { $currentDomainACEs = 0 }
if (-not $trustedDomainACEs) { $trustedDomainACEs = 0 }
Write-Host   "| Orphaned ACEs     : $($OrphanedACEsFound.ToString().PadLeft(15)) |" -ForegroundColor $(if ($OrphanedACEsFound -gt 0) { 'Yellow' } else { 'Green' })
Write-Host   "|   Current domain  : $($currentDomainACEs.ToString().PadLeft(15)) |" -ForegroundColor $(if ($currentDomainACEs -gt 0) { 'Yellow' } else { 'Green' })
Write-Host   "|   Trusted domains : $($trustedDomainACEs.ToString().PadLeft(15)) |" -ForegroundColor $(if ($trustedDomainACEs -gt 0) { 'Magenta' } else { 'Green' })
Write-Host   "| ACEs removed      : $($OrphanedACEsRemoved.ToString().PadLeft(15)) |" -ForegroundColor $(if ($OrphanedACEsRemoved -gt 0) { 'Red' } else { 'Green' })
Write-Host   "| Objects modified  : $($ObjectsModified.ToString().PadLeft(15)) |" -ForegroundColor $(if ($ObjectsModified -gt 0) { 'Red' } else { 'Green' })
Write-Host   "| Errors            : $($ObjectsWithError.ToString().PadLeft(15)) |" -ForegroundColor $(if ($ObjectsWithError -gt 0) { 'Red' } else { 'Green' })
Write-Host   "+======================================+" -ForegroundColor Cyan

# ── Domain SID reference table ──────────────────────────────────────────────
$separator = "+" + ("-" * 98) + "+"
$colType = 14
$colName = 28
$colSID  = 48
$colDir  = 14

Write-Host "`n$separator" -ForegroundColor Gray
Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "TYPE", "NAME", "SID", "DIRECTION") -ForegroundColor Gray
Write-Host $separator -ForegroundColor Gray

# Current domain
$currentDomain = Get-ADDomain -ErrorAction SilentlyContinue
if ($currentDomain) {
    Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Current Domain", $currentDomain.NetBIOSName, $currentDomain.DomainSID, "-") -ForegroundColor White
}

# Other domains in the forest
try {
    $forestObj = Get-ADForest -ErrorAction Stop
    foreach ($domainName in $forestObj.Domains) {
        if ($currentDomain -and $domainName -eq $currentDomain.DNSRoot) { continue }
        try {
            $d = Get-ADDomain -Identity $domainName -ErrorAction Stop
            Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Forest Domain", $d.NetBIOSName, $d.DomainSID, "-") -ForegroundColor DarkCyan
        }
        catch {
            Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Forest Domain", $domainName, "(unreachable)", "-") -ForegroundColor DarkYellow
        }
    }
}
catch {
    Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Forest", "(Unable to enumerate)", "", "") -ForegroundColor DarkYellow
}

# Trusted domains
Write-Host $separator -ForegroundColor Gray
try {
    $trusts = Get-ADTrust -Filter * -Properties securityIdentifier -ErrorAction Stop
    if ($trusts) {
        foreach ($trust in $trusts) {
            $tName = $trust.Name
            $tSID  = if ($trust.securityIdentifier) { $trust.securityIdentifier.ToString() } else { "(no SID)" }
            $tDir  = $trust.Direction.ToString()
            Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Trust", $tName, $tSID, $tDir) -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Trust", "(No trusts found)", "", "") -ForegroundColor Green
    }
}
catch {
    Write-Host ("| {0,-$colType} {1,-$colName} {2,-$colSID} {3,-$colDir}|" -f "Trust", "(Unable to enumerate)", "", "") -ForegroundColor DarkYellow
}

Write-Host $separator -ForegroundColor Gray

Stop-Transcript

Write-Host "`nTranscript saved to: $LogPath" -ForegroundColor Gray
