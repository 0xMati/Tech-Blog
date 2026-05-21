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
    foreach ($k in $FlagMap.Keys) {
        if (($Value -band $k) -eq $k) { $hit += $FlagMap[$k] }
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

# Console output
$sorted |
    Select-Object Trust, Direction, TrustType, IntraForest,
                  EncBitsHex, EncFlags, Classification, Status, LastChange |
    Format-Table -AutoSize -Wrap

Write-Host ""
Write-Host "Trust attribute flags per trust:" -ForegroundColor Cyan
$sorted |
    Select-Object Trust, AttrBitsHex, AttrFlags |
    Format-Table -AutoSize -Wrap

# Summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$sorted | Group-Object Classification | Sort-Object Name |
    ForEach-Object {
        $emoji = Get-ClassEmoji -Class $_.Name
        '{0,-12} {1,3}  {2}' -f $_.Name, $_.Count, $emoji
    } | Write-Host

# Highlight the actionable items
$bad = $sorted | Where-Object {
    $_.Classification -in @('Legacy-DES','RC4-only','Mixed','Unset')
}
if ($bad) {
    Write-Host ""
    Write-Host "Trusts that need attention:" -ForegroundColor Yellow
    $bad |
        Select-Object Trust, Classification, EncBitsHex, EncFlags, LastChange |
        Format-Table -AutoSize -Wrap
} else {
    Write-Host ""
    Write-Host "All trusts are AES-only. Nice." -ForegroundColor Green
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
Write-Host "Remember: this audit shows only the LOCAL side of each trust." -ForegroundColor DarkGray
Write-Host "Run the same script on the remote side to compare both TDOs." -ForegroundColor DarkGray
Write-Host ""
