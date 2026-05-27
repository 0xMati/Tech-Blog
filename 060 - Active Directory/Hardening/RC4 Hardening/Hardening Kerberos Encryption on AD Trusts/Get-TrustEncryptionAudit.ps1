<#
.SYNOPSIS
    Audits the Kerberos encryption posture of every trust visible from the
    local Active Directory domain.

.DESCRIPTION
    Enumerates all Trusted Domain Objects (TDOs) via Get-ADTrust, reads the
    attributes that drive cross-realm ticket encryption, and classifies each
    trust as one of:

        AES-only   -> msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256)
        Mixed      -> includes both RC4 and AES
        RC4-only   -> only RC4 enabled
        Legacy-DES -> any DES bit set (DES-CBC-CRC or DES-CBC-MD5)
        Unset      -> attribute is 0 or absent
                      (interpreted as RC4 by older clients, ambiguous by KB5021131)

    For each trust, the script prints:
        - Name, direction, type, intra-forest flag
        - The msDS-SupportedEncryptionTypes value in hex + decoded flags
        - The trustAttributes value in hex + decoded flags
        - The whenChanged date of the TDO (proxy for last password rotation)
        - A classification label with a status emoji

    The script is READ-ONLY. It never modifies anything. Use the remediation
    procedure described in the companion article to actually fix the trusts.

.PARAMETER Server
    Optional. Domain Controller to query. Defaults to the DC discovered by
    the AD PowerShell module.

.PARAMETER ExportCsv
    Optional. Path to a CSV file. If specified, the full audit dataset is
    exported in addition to the console output.

.PARAMETER ExportJson
    Optional. Path to a JSON file. If specified, the full audit dataset is
    exported in addition to the console output.

.PARAMETER IncludeIntraForest
    Optional switch. By default, intra-forest trusts (parent/child,
    shortcut) are included. Set to $false explicitly to hide them.

.EXAMPLE
    .\Get-TrustEncryptionAudit.ps1

    Runs the audit against the current domain and prints a sorted table.

.EXAMPLE
    .\Get-TrustEncryptionAudit.ps1 -Server dc01.corp.lab -ExportCsv .\trusts.csv

    Queries a specific DC and exports the result to CSV.

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell).
    Requires read access on the TDOs (any authenticated user typically has it,
    but some attributes may be restricted by ACLs in hardened environments).

    See companion article:
    Hardening Kerberos Encryption on AD Trusts.md
#>

[CmdletBinding()]
param(
    [string]   $Server,
    [string]   $ExportCsv,
    [string]   $ExportJson,
    [bool]     $IncludeIntraForest = $true
)

#region helpers -----------------------------------------------------------

# Bit flags for msDS-SupportedEncryptionTypes (MS-KILE)
$EncTypeFlags = [ordered]@{
    0x01 = 'DES-CBC-CRC'
    0x02 = 'DES-CBC-MD5'
    0x04 = 'RC4-HMAC'
    0x08 = 'AES128-CTS-HMAC-SHA1-96'
    0x10 = 'AES256-CTS-HMAC-SHA1-96'
    0x20 = 'AES256-CTS-HMAC-SHA1-96-SK' # session key only, post-CVE-2022-37966
}

# Bit flags for trustAttributes (MS-ADTS section 6.1.6.7.9)
$TrustAttrFlags = [ordered]@{
    0x00000001 = 'NON_TRANSITIVE'
    0x00000002 = 'UPLEVEL_ONLY'
    0x00000004 = 'QUARANTINED_DOMAIN'
    0x00000008 = 'FOREST_TRANSITIVE'
    0x00000010 = 'CROSS_ORGANIZATION'
    0x00000020 = 'WITHIN_FOREST'
    0x00000040 = 'TREAT_AS_EXTERNAL'
    0x00000080 = 'USES_RC4_ENCRYPTION'
    0x00000100 = 'USES_AES_KEYS'                # GUI "supports AES" checkbox
    0x00000200 = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
    0x00000400 = 'PIM_TRUST'
    0x00000800 = 'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION'
}

# trustType numeric -> friendly name (MS-ADTS section 6.1.6.7.15)
$TrustTypeMap = @{
    1 = 'Downlevel (NT4)'
    2 = 'AD'
    3 = 'MIT (Kerberos realm)'
    4 = 'DCE (legacy)'
}

# trustDirection -> friendly name
$TrustDirMap = @{
    0 = 'Disabled'
    1 = 'Inbound'
    2 = 'Outbound'
    3 = 'Bidirectional'
}

function ConvertFrom-BitMask {
    param(
        [int]    $Value,
        [object] $FlagMap
    )
    if ($null -eq $Value -or $Value -eq 0) { return @() }
    $hit = @()
    foreach ($entry in $FlagMap.GetEnumerator()) {
        $bit = [int]$entry.Key
        if (($Value -band $bit) -eq $bit) { $hit += $entry.Value }
    }
    return $hit
}

function Get-EncTypeClass {
    param([int] $EncBits)

    if ($null -eq $EncBits -or $EncBits -eq 0) { return 'Unset' }

    $hasDES = ($EncBits -band 0x03) -ne 0
    $hasRC4 = ($EncBits -band 0x04) -ne 0
    $hasAES = ($EncBits -band 0x18) -ne 0

    if ($hasDES) { return 'Legacy-DES' }
    if ($hasRC4 -and $hasAES) { return 'Mixed' }
    if ($hasRC4) { return 'RC4-only' }
    if ($hasAES) { return 'AES-only' }
    return 'Unknown'
}

function Get-ClassEmoji {
    param([string] $Class)
    switch ($Class) {
        'AES-only'   { '[OK]' ; break }
        'Mixed'      { '[!!]' ; break }
        'RC4-only'   { '[XX]' ; break }
        'Legacy-DES' { '[XX]' ; break }
        'Unset'      { '[??]' ; break }
        default      { '[??]' }
    }
}

# Plain-English meaning of each classification, used in the legend.
# Kept short (~80 chars) so the console output does not wrap awkwardly.
$ClassMeaning = [ordered]@{
    'AES-only'   = 'AES128+AES256 declared. Verify trust password rotated since (LastChange).'
    'Mixed'      = 'RC4 still allowed alongside AES. Remove RC4 bit and rotate trust password.'
    'RC4-only'   = 'Every referral encrypted in RC4-HMAC-MD5. Crackable offline. Fix urgently.'
    'Legacy-DES' = 'DES bit still present. Should not exist in 2026. Set to 0x18 and rotate.'
    'Unset'      = 'Attribute is 0 / absent. Behaves like RC4-only for cross-realm. Set to 0x18 and rotate.'
    'Unknown'    = 'Bits set that are not recognized by the script. Inspect manually.'
}

#endregion ---------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "The ActiveDirectory PowerShell module is required. Install RSAT-AD-PowerShell."
}
Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{}
if ($Server) { $adParams.Server = $Server }

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host " Trust Encryption Audit" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " WHAT THIS SCRIPT DOES" -ForegroundColor Yellow
Write-Host "   Reads msDS-SupportedEncryptionTypes and trustAttributes on every Trusted"
Write-Host "   Domain Object (TDO) visible from the local domain. Classifies each trust"
Write-Host "   by its DECLARED encryption posture at the directory level."
Write-Host ""
Write-Host " WHAT THIS SCRIPT DOES *NOT* DO" -ForegroundColor Yellow
Write-Host "   - It does NOT read the KDC GPO 'Network security: Configure encryption types"
Write-Host "     allowed for Kerberos' (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\"
Write-Host "     Policies\System\Kerberos\Parameters\SupportedEncryptionTypes). That value"
Write-Host "     controls which SESSION KEYS the KDC is willing to issue. A trust can be"
Write-Host "     [OK] here AND still negotiate RC4 sessions if the GPO is stuck at 0x1C."
Write-Host "   - It does NOT inspect supplementalCredentials, so it cannot confirm that"
Write-Host "     AES KEYS ARE ACTUALLY MATERIALIZED. An attribute set to 0x18 without a"
Write-Host "     subsequent trust password rotation still has RC4-only keys in practice."
Write-Host "   - It reads only the LOCAL side. The remote-side TDO has its own attribute"
Write-Host "     and must be audited from a DC of that domain."
Write-Host ""
Write-Host " A FULLY HARDENED TRUST REQUIRES THREE THINGS:" -ForegroundColor Yellow
Write-Host "   1. msDS-SupportedEncryptionTypes = 0x18 on BOTH TDOs       (this script)"
Write-Host "   2. Trust password rotated AFTER the attribute change       (whenChanged hint)"
Write-Host "   3. KDC GPO SupportedEncryptionTypes = 0x80000018 on DCs    (manual check)"
Write-Host "      -> Verify with: Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\"
Write-Host "         CurrentVersion\Policies\System\Kerberos\Parameters' -Name SupportedEncryptionTypes"
Write-Host ""
Write-Host "--------------------------------------------------------------------------" -ForegroundColor Cyan

try {
    $domainInfo = Get-ADDomain @adParams -ErrorAction Stop
    Write-Host (" Local domain   : {0}" -f $domainInfo.DNSRoot)
    $serverLabel = if ($adParams.Server) { $adParams.Server } else { 'auto' }
    Write-Host (" Queried server : {0}" -f $serverLabel)
}
catch {
    Write-Warning "Could not query the local AD domain: $($_.Exception.Message)"
}
Write-Host ""

# Get every trust we can see, with all the attributes we care about
$props = @(
    'msDS-SupportedEncryptionTypes',
    'trustAttributes',
    'trustType',
    'trustDirection',
    'whenChanged',
    'whenCreated',
    'flatName',
    'trustPartner'
)

try {
    $trusts = Get-ADTrust -Filter * -Properties $props @adParams -ErrorAction Stop
}
catch {
    throw "Get-ADTrust failed: $($_.Exception.Message)"
}

if ($IncludeIntraForest -eq $false) {
    $trusts = $trusts | Where-Object { -not $_.IntraForest }
}

if (-not $trusts -or $trusts.Count -eq 0) {
    Write-Host "No trusts found in this domain." -ForegroundColor Yellow
    return
}

$results = foreach ($t in $trusts) {
    $encInt   = [int]($t.'msDS-SupportedEncryptionTypes')
    $attrInt  = [int]$t.trustAttributes

    $encFlags  = ConvertFrom-BitMask -Value $encInt  -FlagMap $EncTypeFlags
    $attrFlags = ConvertFrom-BitMask -Value $attrInt -FlagMap $TrustAttrFlags

    $class = Get-EncTypeClass -EncBits $encInt

    [pscustomobject]@{
        Trust          = $t.Name
        Direction      = $TrustDirMap[[int]$t.trustDirection]
        TrustType      = $TrustTypeMap[[int]$t.trustType]
        IntraForest    = [bool]$t.IntraForest
        Transitive     = ($attrInt -band 0x08) -eq 0x08 -or (($attrInt -band 0x01) -eq 0)
        EncBitsHex     = '0x{0:X}' -f $encInt
        EncFlags       = ($encFlags  -join ', ')
        AttrBitsHex    = '0x{0:X}' -f $attrInt
        AttrFlags      = ($attrFlags -join ', ')
        Classification = $class
        Status         = Get-ClassEmoji -Class $class
        LastChange     = $t.whenChanged
        Created        = $t.whenCreated
        FlatName       = $t.flatName
        Partner        = $t.trustPartner
    }
}

# Sort: worst first
$rank = @{ 'Legacy-DES'=0; 'RC4-only'=1; 'Mixed'=2; 'Unset'=3; 'AES-only'=4; 'Unknown'=5 }
$sorted = $results | Sort-Object @{ Expression = { $rank[$_.Classification] } }, Trust

# ---- Main table: encryption posture per trust --------------------------
Write-Host "[1/4] Encryption posture (msDS-SupportedEncryptionTypes on each TDO)" -ForegroundColor Cyan
Write-Host "      Reading: each row = one trust seen from the LOCAL side."
Write-Host "      EncBitsHex is the raw bitmask. EncFlags is the human-readable decoding."
Write-Host "      LastChange = whenChanged on the TDO. A recent date is a proxy for a recent trust password rotation."
Write-Host ""

$sorted |
    Select-Object Trust, Direction, TrustType, IntraForest,
                  EncBitsHex, EncFlags, Classification, Status, LastChange |
    Format-Table -AutoSize -Wrap

# ---- Trust attributes table -------------------------------------------
Write-Host ""
Write-Host "[2/4] Trust attribute flags (trustAttributes on each TDO)" -ForegroundColor Cyan
Write-Host "      Independent from encryption. Tells you the type and topology of the trust:"
Write-Host "      FOREST_TRANSITIVE = forest trust, WITHIN_FOREST = intra-forest (parent/child or shortcut),"
Write-Host "      PIM_TRUST = Red Forest / ESAE pattern, USES_AES_KEYS = the GUI 'supports AES' checkbox (declarative only)."
Write-Host ""

$sorted |
    Select-Object Trust, AttrBitsHex, AttrFlags |
    Format-Table -AutoSize -Wrap

# ---- Summary by classification ----------------------------------------
Write-Host ""
Write-Host "[3/4] Summary by classification" -ForegroundColor Cyan
Write-Host ""

$sorted | Group-Object Classification | Sort-Object @{ Expression = { $rank[$_.Name] } } |
    ForEach-Object {
        $emoji = Get-ClassEmoji -Class $_.Name
        '   {0,-12} {1,3}  {2}' -f $_.Name, $_.Count, $emoji
    } | Write-Host

Write-Host ""
Write-Host "   Legend:" -ForegroundColor DarkCyan
Write-Host "      [OK] AES-only       Best state at the attribute level (verify rotation, see notes below)"
Write-Host "      [!!] Mixed          RC4 still allowed alongside AES"
Write-Host "      [XX] RC4-only       Every referral is RC4-encrypted"
Write-Host "      [XX] Legacy-DES     DES bit still present"
Write-Host "      [??] Unset          Attribute is 0 / absent -> behaves like RC4-only for cross-realm purposes"
Write-Host ""

foreach ($cls in ($sorted.Classification | Sort-Object -Unique)) {
    if ($ClassMeaning.Contains($cls)) {
        Write-Host ("   {0,-12} : {1}" -f $cls, $ClassMeaning[$cls]) -ForegroundColor DarkGray
    }
}

# ---- Actionable list --------------------------------------------------
Write-Host ""
$bad = $sorted | Where-Object {
    $_.Classification -in @('Legacy-DES','RC4-only','Mixed','Unset')
}
if ($bad) {
    Write-Host "[4/4] Trusts that need attention (sorted worst-first)" -ForegroundColor Yellow
    Write-Host "      For each one: see the Remediation procedure in the companion article."
    Write-Host "      The two-step fix is ALWAYS: (1) set msDS-SupportedEncryptionTypes = 0x18, then (2) rotate the trust password."
    Write-Host "      Attribute change without rotation = false sense of security (AES keys are not generated)."
    Write-Host ""
    $bad |
        Select-Object Trust, Classification, EncBitsHex, EncFlags, LastChange |
        Format-Table -AutoSize -Wrap
} else {
    Write-Host "[4/4] All trusts are AES-only at the attribute level." -ForegroundColor Green
    Write-Host "      Reminder: this is the DECLARATIVE state. To confirm the AES keys are actually"
    Write-Host "      materialized in supplementalCredentials, do a runtime check:"
    Write-Host "          klist purge ; Test-Path \\<DC-of-remote-trust>\sysvol ; klist"
    Write-Host "      The referral ticket (krbtgt/REMOTE @ LOCAL) must show KerbTicket Encryption Type = AES-256."
    Write-Host "      Also check: GPO 'Network security: Configure encryption types allowed for Kerberos'"
    Write-Host "      on the Domain Controllers OU should be 0x80000018 (not 0x8000001C) to block RC4 session keys."
}

# Exports
if ($ExportCsv) {
    $sorted | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host ("CSV exported : {0}" -f (Resolve-Path -LiteralPath $ExportCsv).Path) -ForegroundColor DarkGray
}

if ($ExportJson) {
    $sorted | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ExportJson -Encoding UTF8
    Write-Host ("JSON exported: {0}" -f (Resolve-Path -LiteralPath $ExportJson).Path) -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Scope reminders:" -ForegroundColor DarkGray
Write-Host "   - This audit shows only the LOCAL side of each trust. Each TDO has a twin on the remote side"
Write-Host "     with its own msDS-SupportedEncryptionTypes. Run this script on the remote side to compare."
Write-Host "   - The script reads only the ATTRIBUTE. It does not inspect supplementalCredentials, so it cannot"
Write-Host "     tell whether AES keys are actually materialized. A trust showing [OK] with a very old LastChange"
Write-Host "     may still be issuing RC4 referrals if the password has not been rotated since the attribute change."
Write-Host "   - To confirm session-level encryption, do a runtime klist test from a client (see the article's labs)."
Write-Host ""
