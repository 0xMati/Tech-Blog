 <#
    .SYNOPSIS
    Removes or lists orphaned SIDs from Active Directory objects.

    .DESCRIPTION
    This script scans Active Directory objects for access control entries (ACEs) that reference
    SIDs which no longer resolve to an existing account. It uses a single LDAP query with Subtree
    scope for better performance and includes proper error handling.

    By default, orphaned SIDs belonging to any domain in the current forest are detected.
    Use -IncludeTrustedDomains to also detect orphaned SIDs from trusted (external) domains.
    Use -ObjectType to limit scanning to OUs or containers only (much faster on large directories).

    .PARAMETER SearchBase
    Specifies the starting point for the scan. Use "All" to scan the current domain
    (or the entire forest when combined with -ForestWide), or provide a specific DN
    like "OU=Users,DC=example,DC=com".

    .PARAMETER List
    Lists the orphaned SIDs found without making any changes (report mode).
    Mutually exclusive with -Remove.

    .PARAMETER Remove
    Removes the orphaned SIDs from the ACLs.
    Mutually exclusive with -List.

    .PARAMETER ObjectType
    Filter the type of objects to scan. Default is 'All'.
    - All            : scan every AD object (slow on large directories)
    - OUOnly         : scan only Organizational Units (fastest, covers most delegation ACLs)
    - ContainersOnly : scan OUs, Containers, builtin and domain objects

    .PARAMETER ForestWide
    When used with -SearchBase "All", scans the entire forest (starting from the root
    domain) instead of only the current domain.

    .PARAMETER IncludeTrustedDomains
    If specified, the script will also detect orphaned SIDs from trusted domains,
    not just the current forest. Any unresolved SID will be flagged.

    .PARAMETER LogPath
    Path to the transcript log file. Defaults to "C:\temp\RemoveOrphanedSID-AD-V2.txt".

    .PARAMETER ExportCsvPath
    Optional path to export orphaned SID results to CSV.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List
    Lists orphaned SIDs in the current domain (report only).

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -ObjectType OUOnly
    Lists orphaned SIDs scanning only OUs in the current domain (much faster).

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -ForestWide
    Lists orphaned SIDs across the entire forest.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Remove
    Removes orphaned SIDs from the specified OU.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -IncludeTrustedDomains
    Lists all orphaned SIDs including those from trusted domains.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=example,DC=com" -Remove -WhatIf
    Shows what would be changed without actually altering the ACLs.

    .EXAMPLE
    .\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -ObjectType OUOnly -ExportCsvPath "C:\temp\OrphanedSIDs.csv"
    Lists orphaned SIDs and exports detailed results to CSV.

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
    V2.10, 04/14/2026 - Fix: use current domain (not forest root) for SID detection
                         Add: -ObjectType (All/OUOnly/ContainersOnly) for performance
                         Add: -ForestWide switch
                         Fix: collect all forest domain SIDs (child domains)
                         Fix: ACL read errors on DNs with special characters
    V2.11, 04/23/2026 - Fix: ACL provider path must use AD:\ prefix (not AD:)
                         Add: GUID-based ACL fallback for problematic DN parsing
    V2.12, 04/23/2026 - Improve: reduce transcript noise and summarize GUID fallback usage
                         Improve: trust reachability check without terminating errors
                         Add: optional CSV export (-ExportCsvPath)
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

    [ValidateSet('All', 'OUOnly', 'ContainersOnly')]
    [string]$ObjectType = 'All',

    [switch]$ForestWide,

    [switch]$IncludeTrustedDomains,

    [string]$LogPath = "C:\temp\RemoveOrphanedSID-AD-V2.txt",

    [string]$ExportCsvPath
)

function Write-Section {
    param([string]$Title)
    Write-Host "" 
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host ("  " + $Title) -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}

function Write-Step {
    param(
        [string]$Label,
        [string]$Value
    )
    Write-Host ("[" + $Label + "] " + $Value) -ForegroundColor Gray
}

# ── Initialisation ──────────────────────────────────────────────────────────
Write-Section "PHASE 1 - INITIALIZATION"

try {
    $RootDSE = Get-ADRootDSE -ErrorAction Stop
}
catch {
    Write-Error "Unable to contact Active Directory: $_"
    return
}

$CurrentDomainDN = $RootDSE.defaultNamingContext
$ForestDN        = $RootDSE.rootDomainNamingContext

# Get current domain SID
try {
    $currentDomainObj = Get-ADDomain -ErrorAction Stop
    $DomainSID = $currentDomainObj.DomainSID.ToString()
}
catch {
    Write-Error "Unable to retrieve current domain information: $_"
    return
}

# Collect all domain SIDs in the forest (current + child/parent domains)
$AllForestDomainSIDs = [System.Collections.Generic.List[string]]::new()
$AllForestDomainSIDs.Add($DomainSID)
try {
    $forestObj = Get-ADForest -ErrorAction Stop
    foreach ($domainName in $forestObj.Domains) {
        if ($domainName -eq $currentDomainObj.DNSRoot) { continue }
        try {
            $d = Get-ADDomain -Identity $domainName -ErrorAction Stop
            $AllForestDomainSIDs.Add($d.DomainSID.ToString())
        }
        catch {
            Write-Warning "Unable to retrieve SID for forest domain '$domainName': $_"
        }
    }
}
catch {
    Write-Warning "Unable to enumerate forest domains: $_. Only current domain SID will be used."
}

# Ensure log directory exists
$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Start-Transcript -Path $LogPath -Append -Force

# Determine search base
if ($SearchBase -eq "All") {
    if ($ForestWide) {
        $TargetDN = $ForestDN
        Write-Host "Scanning the entire forest: $ForestDN" -ForegroundColor Cyan
    }
    else {
        $TargetDN = $CurrentDomainDN
        Write-Host "Scanning the current domain: $CurrentDomainDN" -ForegroundColor Cyan
    }
}
else {
    $TargetDN = $SearchBase
    Write-Host "Scanning: $TargetDN" -ForegroundColor Cyan
}

Write-Step -Label "Target" -Value $TargetDN
Write-Step -Label "Object filter" -Value $ObjectType
Write-Step -Label "Known forest SIDs" -Value $AllForestDomainSIDs.Count

if ($IncludeTrustedDomains) {
    Write-Step -Label "Mode" -Value "Including trusted domains"
}
else {
    Write-Step -Label "Mode" -Value "Forest domain SIDs only"
}

$TrustLookupFallbackCount = 0

# ── Trust reachability check (when -IncludeTrustedDomains) ──────────────────
if ($IncludeTrustedDomains) {
    Write-Section "PHASE 2 - TRUST REACHABILITY CHECK"
    Write-Step -Label "Action" -Value "Checking trust reachability"

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
                $domainProbe = Get-ADDomain -Identity $tName -ErrorAction Stop 2>$null
                if ($domainProbe) {
                    $reachable = $true
                }
            }
            catch {
                $TrustLookupFallbackCount++
                try {
                    $null = nltest /dsgetdc:$tName 2>$null
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
            Write-Host "All trusts are reachable." -ForegroundColor Green
        }

        if ($TrustLookupFallbackCount -gt 0) {
            Write-Host "Info: nltest fallback used for $TrustLookupFallbackCount trust lookup(s)." -ForegroundColor DarkYellow
        }
    }
    else {
        Write-Host "No trusts found." -ForegroundColor Yellow
    }
}

# ── Collect all objects in a single LDAP query ──────────────────────────────
Write-Section "PHASE 3 - OBJECT DISCOVERY"
Write-Step -Label "LDAP target" -Value $TargetDN

$LDAPFilter = switch ($ObjectType) {
    'OUOnly'         { '(objectClass=organizationalUnit)' }
    'ContainersOnly' { '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain)(objectClass=domainDNS))' }
    default          { '(objectClass=*)' }
}

Write-Step -Label "LDAP filter" -Value $LDAPFilter

try {
    $ADObjects = @(Get-ADObject -LDAPFilter $LDAPFilter -SearchBase $TargetDN -SearchScope Subtree -ErrorAction Stop)
}
catch {
    Write-Error "Failed to query AD objects under '$TargetDN': $_"
    Stop-Transcript
    return
}

$TotalObjects = $ADObjects.Count
Write-Step -Label "Objects found" -Value $TotalObjects

Write-Section "PHASE 4 - ACL ANALYSIS"
Write-Step -Label "Action" -Value "Scanning ACLs and identifying orphaned SID ACEs"

# ── Counters ────────────────────────────────────────────────────────────────
$ObjectsScanned   = 0
$ObjectsWithError = 0
$OrphanedACEsFound   = 0
$OrphanedACEsRemoved = 0
$ObjectsModified  = 0
$GuidFallbackCount = 0
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
        # Only flag unresolved SIDs belonging to any domain in the current forest
        if ($identity -is [System.Security.Principal.SecurityIdentifier]) {
            $sidValue = $identity.Value
            foreach ($forestSID in $AllForestDomainSIDs) {
                if ($sidValue.StartsWith($forestSID)) { return $true }
            }
        }
        return $false
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

    # Read ACL. Prefer AD provider path, fallback to GUID binding for tricky DNs.
    $aclWriteMode = 'Provider'
    $aclProviderPath = "AD:\$dn"
    $adsiEntry = $null
    $providerReadError = $null
    $acl = $null
    try {
        $acl = Get-Acl -LiteralPath $aclProviderPath -ErrorAction Stop
    }
    catch {
        $providerReadError = $_
    }

    if (-not $acl) {
        try {
            $guidPath = "LDAP://<GUID=$($obj.ObjectGUID)>"
            $adsiEntry = [ADSI]$guidPath
            $acl = $adsiEntry.ObjectSecurity
            $aclWriteMode = 'Guid'
            $GuidFallbackCount++
        }
        catch {
            if ($providerReadError) {
                Write-Warning "Cannot read ACL on '$dn'. Provider error: $providerReadError. GUID fallback error: $_"
            }
            else {
                Write-Warning "Cannot read ACL on '$dn': $_"
            }
            $ObjectsWithError++
            continue
        }
    }

    # Enumerate ACEs safely (some ACEs may have corrupt/unsupported formats)
    $aceList = $null
    try {
        $aceList = @($acl.Access)
    }
    catch {
        Write-Warning "Cannot enumerate ACEs on '$dn': $_"
        $ObjectsWithError++
        continue
    }

    $modified = $false
    $orphansOnThisObject = @()

    foreach ($ace in $aceList) {
        try { $isOrphaned = Test-OrphanedACE -ACE $ace } catch { continue }
        if ($isOrphaned) {
            $sid = $ace.IdentityReference.Value
            $OrphanedACEsFound++

            if ($sid -notin $orphansOnThisObject) {
                $orphansOnThisObject += $sid
                $sidOrigin = "Trusted Domain"
                if ($sid.StartsWith($DomainSID)) { $sidOrigin = "Current Domain" }
                elseif ($AllForestDomainSIDs | Where-Object { $sid.StartsWith($_) }) { $sidOrigin = "Forest Domain" }
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
            if ($aclWriteMode -eq 'Provider') {
                Set-Acl -LiteralPath $aclProviderPath -AclObject $acl -ErrorAction Stop
            }
            else {
                $adsiEntry.ObjectSecurity = $acl
                $adsiEntry.CommitChanges()
            }
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
    $forestDomainResults  = $OrphanedResults | Where-Object { $_.Origin -eq "Forest Domain" }
    $trustedDomainResults = $OrphanedResults | Where-Object { $_.Origin -eq "Trusted Domain" }

    foreach ($section in @(
        @{ Label = "CURRENT DOMAIN"; Color = "Yellow"; Data = $currentDomainResults },
        @{ Label = "FOREST DOMAINS (child/parent)"; Color = "DarkCyan"; Data = $forestDomainResults },
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

# Optional CSV export
if ($ExportCsvPath) {
    try {
        $exportDir = Split-Path -Path $ExportCsvPath -Parent
        if ($exportDir -and -not (Test-Path -Path $exportDir)) {
            New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        }

        $OrphanedResults |
            Select-Object SID, Object, ACEs, Origin |
            Sort-Object Origin, SID, Object |
            Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8

        Write-Host "CSV export saved to: $ExportCsvPath" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Failed to export CSV to '$ExportCsvPath': $_"
    }
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host "`n+======================================+" -ForegroundColor Cyan
Write-Host   "|           SUMMARY REPORT             |" -ForegroundColor Cyan
Write-Host   "+======================================+" -ForegroundColor Cyan
Write-Host   "| Objects scanned   : $($ObjectsScanned.ToString().PadLeft(15)) |" -ForegroundColor Cyan
$currentDomainACEs = if ($OrphanedResults.Count -gt 0) { ($OrphanedResults | Where-Object { $_.Origin -eq 'Current Domain' } | Measure-Object -Property ACEs -Sum).Sum } else { 0 }
$forestDomainACEs  = if ($OrphanedResults.Count -gt 0) { ($OrphanedResults | Where-Object { $_.Origin -eq 'Forest Domain' } | Measure-Object -Property ACEs -Sum).Sum } else { 0 }
$trustedDomainACEs = if ($OrphanedResults.Count -gt 0) { ($OrphanedResults | Where-Object { $_.Origin -eq 'Trusted Domain' } | Measure-Object -Property ACEs -Sum).Sum } else { 0 }
if (-not $currentDomainACEs) { $currentDomainACEs = 0 }
if (-not $forestDomainACEs)  { $forestDomainACEs  = 0 }
if (-not $trustedDomainACEs) { $trustedDomainACEs = 0 }
Write-Host   "| Orphaned ACEs     : $($OrphanedACEsFound.ToString().PadLeft(15)) |" -ForegroundColor $(if ($OrphanedACEsFound -gt 0) { 'Yellow' } else { 'Green' })
Write-Host   "|   Current domain  : $($currentDomainACEs.ToString().PadLeft(15)) |" -ForegroundColor $(if ($currentDomainACEs -gt 0) { 'Yellow' } else { 'Green' })
Write-Host   "|   Forest domains  : $($forestDomainACEs.ToString().PadLeft(15)) |" -ForegroundColor $(if ($forestDomainACEs -gt 0) { 'DarkCyan' } else { 'Green' })
Write-Host   "|   Trusted domains : $($trustedDomainACEs.ToString().PadLeft(15)) |" -ForegroundColor $(if ($trustedDomainACEs -gt 0) { 'Magenta' } else { 'Green' })
Write-Host   "| ACEs removed      : $($OrphanedACEsRemoved.ToString().PadLeft(15)) |" -ForegroundColor $(if ($OrphanedACEsRemoved -gt 0) { 'Red' } else { 'Green' })
Write-Host   "| Objects modified  : $($ObjectsModified.ToString().PadLeft(15)) |" -ForegroundColor $(if ($ObjectsModified -gt 0) { 'Red' } else { 'Green' })
Write-Host   "| GUID fallback used: $($GuidFallbackCount.ToString().PadLeft(15)) |" -ForegroundColor $(if ($GuidFallbackCount -gt 0) { 'DarkYellow' } else { 'Green' })
Write-Host   "| Errors            : $($ObjectsWithError.ToString().PadLeft(15)) |" -ForegroundColor $(if ($ObjectsWithError -gt 0) { 'Red' } else { 'Green' })
Write-Host   "+======================================+" -ForegroundColor Cyan

Write-Host "`nHow to read this summary:" -ForegroundColor Cyan
Write-Host "- Objects scanned: total AD objects analyzed." -ForegroundColor Gray
Write-Host "- Orphaned ACEs: ACL entries referencing unresolved SIDs." -ForegroundColor Gray
Write-Host "- Current/Forest/Trusted domains: where those unresolved SIDs come from." -ForegroundColor Gray
Write-Host "- ACEs removed / Objects modified: changes applied (0 in -List mode)." -ForegroundColor Gray
Write-Host "- GUID fallback used: objects read via GUID method when provider path failed." -ForegroundColor Gray
Write-Host "- Errors: objects that could not be processed." -ForegroundColor Gray

Write-Section "PHASE 5 - EXECUTION RESULT"
if ($ObjectsWithError -gt 0) {
    Write-Host "Result: PARTIAL (completed with errors)" -ForegroundColor Red
    Write-Step -Label "Interpretation" -Value "Some objects could not be processed. Review warnings and rerun if needed."
}
elseif ($OrphanedACEsFound -gt 0) {
    Write-Host "Result: ACTION REQUIRED" -ForegroundColor Yellow
    Write-Step -Label "Interpretation" -Value "Orphaned ACEs were detected. Validate results, then run -Remove -WhatIf before remediation."
}
else {
    Write-Host "Result: CLEAN" -ForegroundColor Green
    Write-Step -Label "Interpretation" -Value "No orphaned ACEs detected in scanned scope."
}

# ── Domain SID reference table ──────────────────────────────────────────────
$separator = "+" + ("-" * 98) + "+"
$colType = 14
$colName = 28
$colSID  = 48
$colDir  = 14

Write-Host "`nHow to read the domain/trust table:" -ForegroundColor Cyan
Write-Host "- Forest Domain = domains that belong to the same forest." -ForegroundColor Gray
Write-Host "- Trust = trust relationships returned by Get-ADTrust." -ForegroundColor Gray
Write-Host "- A child domain may appear in BOTH sections (this is expected)." -ForegroundColor Gray

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

Write-Section "COMPLETED"
Write-Step -Label "Transcript" -Value $LogPath
if ($ExportCsvPath) {
    Write-Step -Label "CSV export" -Value $ExportCsvPath
}
