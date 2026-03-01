# Modules\10-MATI-Config.ps1
#requires -Version 5.1

<#
    MATI - Microsoft Active Directory Threat Inspector
    Module 10 - AD Configuration

    - Can run standalone or from 00-MATI-Runner.ps1
    - Collects:
        * Forest & domain configuration
        * AD tombstone lifetime
        * AD schema version
        * SYSVOL replication type (FRS vs DFSR) per domain
        * Domain controllers and OS versions
        * AD trusts
    - Exports:
        * Outputs\Output_*\CSV\MATI_AD_Config_Domains.csv
        * Outputs\Output_*\CSV\MATI_AD_Config_DomainControllers.csv
        * Outputs\Output_*\CSV\MATI_AD_Config_Trusts.csv
    - Adds findings to $Global:Findings:
        * MATI-CONFIG-001 : Domain functional level outdated
        * MATI-CONFIG-002 : Forest functional level outdated
        * MATI-CONFIG-003 : AD Recycle Bin not enabled
        * MATI-CONFIG-004 : Tombstone lifetime not defined or too low
        * MATI-CONFIG-005 : SYSVOL still using FRS / unknown replication
        * MATI-CONFIG-006 : Domain controllers running legacy OS versions
        * MATI-CONFIG-010 : Inter-forest trust without SID filtering
        * MATI-CONFIG-011 : Inter-forest trust without selective authentication
#>

param(
    [string]$OutputRoot
)

# --------------------------------------------------------------------
# 1. Standalone vs runner mode & centralized output folders
# --------------------------------------------------------------------

# Determine if we run standalone (no global findings array yet)
if (-not $Global:Findings) {
    $Global:Findings = @()
    $Standalone = $true
} else {
    $Standalone = $false
}

# Resolve MATI root directory (parent of Modules)
$MatiRoot    = Split-Path $PSScriptRoot -Parent
$OutputsBase = Join-Path $MatiRoot "Outputs"

New-Item -ItemType Directory -Path $OutputsBase -Force | Out-Null

# If no OutputRoot was provided (standalone), create one under .\Outputs
if (-not $OutputRoot) {
    $Date       = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputRoot = Join-Path $OutputsBase "Output_$Date"
}

$CsvDir = Join-Path $OutputRoot "CSV"

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $CsvDir     -Force | Out-Null

Write-Host "[10-MATI-Config] Output root : $OutputRoot" -ForegroundColor DarkGray

# --------------------------------------------------------------------
# 2. Load common finding model (New-Finding) & AD module
# --------------------------------------------------------------------
$commonPath = Join-Path $MatiRoot "Common\Finding.ps1"
if (-not (Test-Path $commonPath)) {
    Write-Error "[10-MATI-Config] Common file not found: $commonPath"
    return
}

. $commonPath

# Ensure ActiveDirectory module is available (in case of standalone execution)
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "[10-MATI-Config] ActiveDirectory module not found. Install RSAT (AD DS and LDS tools)."
    return
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error ("[10-MATI-Config] Failed to import ActiveDirectory module: {0}" -f $_.Exception.Message)
    return
}

# --------------------------------------------------------------------
# 3. Forest-level information (forest, schema, Recycle Bin, tombstone)
# --------------------------------------------------------------------
Write-Host "[10-MATI-Config] Collecting forest-level information..." -ForegroundColor Yellow

try {
    $forest = Get-ADForest -ErrorAction Stop
}
catch {
    Write-Error ("[10-MATI-Config] Failed to query forest: {0}" -f $_.Exception.Message)
    return
}

# RootDSE
try {
    $rootDse = Get-ADRootDSE -ErrorAction Stop
}
catch {
    Write-Error ("[10-MATI-Config] Failed to query RootDSE: {0}" -f $_.Exception.Message)
    return
}

# Recycle Bin status (robust method with optional feature)
$recycleBinEnabled = $false
try {
    $rbFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop

    if ($rbFeature -and $rbFeature.EnabledScopes -and $rbFeature.EnabledScopes.Count -gt 0) {
        $recycleBinEnabled = $true
    }
}
catch {
    Write-Warning ("[10-MATI-Config] Failed to query 'Recycle Bin Feature': {0}" -f $_.Exception.Message)
    # If this fails, we keep $recycleBinEnabled = $false and rely on the finding to be conservative
}

# Tombstone lifetime (forest-wide)
$tombstoneLifetime = $null
try {
    $configNC   = $rootDse.ConfigurationNamingContext
    $dirSvcDn   = "CN=Directory Service,CN=Windows NT,CN=Services,{0}" -f $configNC
    $dirSvc     = Get-ADObject -Identity $dirSvcDn -Partition $configNC -Properties tombstoneLifetime -ErrorAction Stop
    $tombstoneLifetime = $dirSvc.tombstoneLifetime
}
catch {
    Write-Warning ("[10-MATI-Config] Failed to query tombstoneLifetime: {0}" -f $_.Exception.Message)
}

# Schema version (forest-wide)
$schemaVersion = $null
try {
    $schemaNC = $rootDse.SchemaNamingContext
    $schemaObj = Get-ADObject -Identity $schemaNC -Partition $schemaNC -Properties objectVersion -ErrorAction Stop
    if ($schemaObj.objectVersion) {
        $schemaVersion = [int]$schemaObj.objectVersion
    }
}
catch {
    Write-Warning ("[10-MATI-Config] Failed to query schema version: {0}" -f $_.Exception.Message)
}

# --------------------------------------------------------------------
# 4. Domain configuration (per domain)
# --------------------------------------------------------------------
Write-Host "[10-MATI-Config] Collecting domain configuration..." -ForegroundColor Yellow

$domains = @()
foreach ($domainName in $forest.Domains) {
    try {
        $domain = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $domains += $domain
    }
    catch {
        Write-Error ("[10-MATI-Config] Failed to query domain {0}: {1}" -f $domainName, $_.Exception.Message)
    }
}

# For each domain, determine SYSVOL replication type (FRS vs DFSR)
function Get-SysvolReplicationType {
    param(
        [string]$PdcEmulator,
        [string]$DomainDns
    )

    $replication = "Unknown"

    if (-not $PdcEmulator) {
        return $replication
    }

    try {
        $domainRootDse = Get-ADRootDSE -Server $PdcEmulator -ErrorAction Stop
        $domainNC      = $domainRootDse.defaultNamingContext
        $sysContainer  = "CN=System,{0}" -f $domainNC

        $dfsr = Get-ADObject -LDAPFilter "(objectClass=msDFSR-GlobalSettings)" -SearchBase $sysContainer -Server $PdcEmulator -ErrorAction SilentlyContinue

        if ($dfsr) {
            $replication = "DFSR"
        } else {
            # If DFSR global settings are not found, assume legacy FRS/unknown
            $replication = "FRSOrUnknown"
        }
    }
    catch {
        Write-Warning ("[10-MATI-Config] Failed to determine SYSVOL replication for domain {0} using PDC {1}: {2}" -f $DomainDns, $PdcEmulator, $_.Exception.Message)
    }

    return $replication
}

$domainConfig = foreach ($d in $domains) {

    $sysvolReplication = Get-SysvolReplicationType -PdcEmulator $d.PDCEmulator -DomainDns $d.DNSRoot

    [PSCustomObject]@{
        ForestName           = $forest.Name
        DomainDNS            = $d.DNSRoot
        DomainNetBIOS        = $d.NetBIOSName
        DomainMode           = [string]$d.DomainMode
        ForestMode           = [string]$forest.ForestMode
        RecycleBinEnabled    = $recycleBinEnabled
        TombstoneLifetimeDays = $tombstoneLifetime
        SchemaVersion        = $schemaVersion
        SysvolReplication    = $sysvolReplication
        PDCEmulator          = $d.PDCEmulator
        RIDMaster            = $d.RIDMaster
        InfrastructureMaster = $d.InfrastructureMaster
        DomainSID            = $d.DomainSID.Value
    }
}

$domainsCsvPath = Join-Path $CsvDir "MATI_AD_Config_Domains.csv"
$domainConfig | Export-Csv -Path $domainsCsvPath -NoTypeInformation -Encoding UTF8
Write-Host "[10-MATI-Config] Domains configuration CSV: $domainsCsvPath" -ForegroundColor Green

# --------------------------------------------------------------------
# 5. Findings: forest & domain functional levels, Recycle Bin, tombstone, SYSVOL
# --------------------------------------------------------------------
# Define what we consider "modern enough"
$allowedDomainModes = @(
    'Windows2012R2Domain',
    'Windows2016Domain',
    'Windows2019Domain',
    'Windows2022Domain'
)

$allowedForestModes = @(
    'Windows2012R2Forest',
    'Windows2016Forest',
    'Windows2019Forest',
    'Windows2022Forest'
)

# Forest functional level outdated
if ($allowedForestModes -notcontains ([string]$forest.ForestMode)) {
    $Global:Findings += New-Finding `
        -Id "MATI-CONFIG-002" `
        -Category "Config" `
        -Severity "Medium" `
        -Title "Forest functional level is outdated" `
        -Description ("Forest {0} is running at functional level {1}, which is below recommended security baselines." -f $forest.Name, $forest.ForestMode) `
        -Remediation "Plan to upgrade all domain controllers to a supported Windows Server version and raise the forest functional level to at least Windows Server 2012 R2 (or higher as per your security baseline)." `
        -ObjectDN $forest.RootDomain `
        -Domain $forest.RootDomain `
        -Source "10-MATI-Config" `
        -Details ("ForestName={0}; ForestMode={1}" -f $forest.Name, $forest.ForestMode)
}

# Domain functional level outdated
foreach ($d in $domains) {
    if ($allowedDomainModes -notcontains ([string]$d.DomainMode)) {
        $Global:Findings += New-Finding `
            -Id "MATI-CONFIG-001" `
            -Category "Config" `
            -Severity "Medium" `
            -Title "Domain functional level is outdated" `
            -Description ("Domain {0} is running at functional level {1}, which is below recommended security baselines." -f $d.DNSRoot, $d.DomainMode) `
            -Remediation "Plan to upgrade all domain controllers in this domain to a supported Windows Server version and raise the domain functional level to at least Windows Server 2012 R2 (or higher as per your security baseline)." `
            -ObjectDN $d.DistinguishedName `
            -Domain $d.DNSRoot `
            -Source "10-MATI-Config" `
            -Details ("DomainDNS={0}; DomainMode={1}; ForestMode={2}" -f $d.DNSRoot, $d.DomainMode, $forest.ForestMode)
    }
}

# AD Recycle Bin not enabled
if (-not $recycleBinEnabled) {
    $Global:Findings += New-Finding `
        -Id "MATI-CONFIG-003" `
        -Category "Config" `
        -Severity "Medium" `
        -Title "AD Recycle Bin is not enabled" `
        -Description ("The Active Directory Recycle Bin is not enabled for forest {0}, which makes object recovery more complex and risky." -f $forest.Name) `
        -Remediation "Evaluate and plan enabling the Active Directory Recycle Bin to improve object recovery capabilities and reduce the impact of accidental deletions." `
        -ObjectDN $forest.RootDomain `
        -Domain $forest.RootDomain `
        -Source "10-MATI-Config" `
        -Details ("ForestName={0}; RecycleBinEnabled={1}" -f $forest.Name, $recycleBinEnabled)
}

# Tombstone lifetime not defined or too low
if ($null -eq $tombstoneLifetime) {
    $Global:Findings += New-Finding `
        -Id "MATI-CONFIG-004" `
        -Category "Config" `
        -Severity "Medium" `
        -Title "Tombstone lifetime is not explicitly defined" `
        -Description ("The tombstoneLifetime attribute is not explicitly defined in the forest {0}. Relying on legacy default values may lead to unexpected replication and recovery behavior." -f $forest.Name) `
        -Remediation "Define an explicit tombstoneLifetime value (in days) that aligns with your backup, replication, and recovery strategy (commonly 60–180 days)." `
        -ObjectDN $configNC `
        -Domain $forest.RootDomain `
        -Source "10-MATI-Config" `
        -Details ("ForestName={0}; TombstoneLifetimeDays=<not set>" -f $forest.Name)
}
elseif ($tombstoneLifetime -lt 60) {
    $Global:Findings += New-Finding `
        -Id "MATI-CONFIG-004" `
        -Category "Config" `
        -Severity "Medium" `
        -Title "Tombstone lifetime is lower than recommended" `
        -Description ("The tombstone lifetime in forest {0} is set to {1} days, which is lower than common security and recovery recommendations (>= 60 days)." -f $forest.Name, $tombstoneLifetime) `
        -Remediation "Review and adjust tombstoneLifetime to align with your backup, replication, and recovery strategy (commonly 60–180 days)." `
        -ObjectDN $configNC `
        -Domain $forest.RootDomain `
        -Source "10-MATI-Config" `
        -Details ("ForestName={0}; TombstoneLifetimeDays={1}" -f $forest.Name, $tombstoneLifetime)
}

# SYSVOL replication still using FRS / unknown (per domain)
foreach ($d in $domains) {
    $domainRow = $domainConfig | Where-Object { $_.DomainDNS -eq $d.DNSRoot }
    if ($domainRow -and $domainRow.SysvolReplication -eq 'FRSOrUnknown') {
        $Global:Findings += New-Finding `
            -Id "MATI-CONFIG-005" `
            -Category "Config" `
            -Severity "High" `
            -Title "SYSVOL may still be using FRS replication" `
            -Description ("Domain {0} appears to be using FRS or an unknown mechanism for SYSVOL replication. FRS is deprecated and should be migrated to DFSR." -f $d.DNSRoot) `
            -Remediation "Verify SYSVOL replication mode for this domain and, if FRS is still in use, plan a migration to DFSR as per Microsoft guidance." `
            -ObjectDN $d.DistinguishedName `
            -Domain $d.DNSRoot `
            -Source "10-MATI-Config" `
            -Details ("DomainDNS={0}; SysvolReplication={1}; PDCEmulator={2}" -f $d.DNSRoot, $domainRow.SysvolReplication, $d.PDCEmulator)
    }
}

# --------------------------------------------------------------------
# 6. Domain controllers & OS versions
# --------------------------------------------------------------------
Write-Host "[10-MATI-Config] Collecting domain controllers information..." -ForegroundColor Yellow

$dcRawList = @()

foreach ($d in $domains) {
    try {
        $dcs = Get-ADDomainController -Filter * -Server $d.DNSRoot -ErrorAction Stop
        $dcRawList += $dcs
    }
    catch {
        Write-Warning ("[10-MATI-Config] Failed to enumerate domain controllers for domain {0}: {1}" -f $d.DNSRoot, $_.Exception.Message)
    }
}

$dcConfig = foreach ($dc in $dcRawList) {
    [PSCustomObject]@{
        DomainDNS              = $dc.Domain
        Name                   = $dc.HostName
        IPv4Address            = $dc.IPv4Address
        Site                   = $dc.Site
        OperatingSystem        = $dc.OperatingSystem
        OperatingSystemVersion = $dc.OperatingSystemVersion
        IsGlobalCatalog        = $dc.IsGlobalCatalog
        ComputerObjectDN       = $dc.ComputerObjectDN
    }
}

if ($dcConfig.Count -gt 0) {
    $dcCsvPath = Join-Path $CsvDir "MATI_AD_Config_DomainControllers.csv"
    $dcConfig | Export-Csv -Path $dcCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[10-MATI-Config] Domain controllers CSV: $dcCsvPath" -ForegroundColor Green
}

# Findings on DC OS versions
foreach ($dc in $dcRawList) {
    $os = $dc.OperatingSystem
    if (-not $os) { continue }

    $severity = $null
    if ($os -like "*2008*") {
        $severity = "Critical"
    }
    elseif ($os -like "*2012*") {
        $severity = "High"
    }

    if ($severity) {
        $Global:Findings += New-Finding `
            -Id "MATI-CONFIG-006" `
            -Category "Config" `
            -Severity $severity `
            -Title "Domain controller running legacy OS version" `
            -Description ("Domain controller {0} in domain {1} is running {2}, which is legacy or close to end-of-support and should be upgraded." -f $dc.HostName, $dc.Domain, $os) `
            -Remediation "Plan to upgrade this domain controller to a supported Windows Server version aligned with your forest and domain functional level targets." `
            -ObjectDN $dc.ComputerObjectDN `
            -Domain $dc.Domain `
            -Source "10-MATI-Config" `
            -Details ("DomainDNS={0}; DC={1}; OperatingSystem={2}; OperatingSystemVersion={3}; Severity={4}" -f $dc.Domain, $dc.HostName, $dc.OperatingSystem, $dc.OperatingSystemVersion, $severity)
    }
}

# --------------------------------------------------------------------
# 7. Trusts configuration & findings
# --------------------------------------------------------------------
Write-Host "[10-MATI-Config] Collecting trusts..." -ForegroundColor Yellow

$trusts = @()
try {
    $trusts = Get-ADTrust -Filter * -ErrorAction Stop
}
catch {
    Write-Warning ("[10-MATI-Config] Failed to query trusts: {0}" -f $_.Exception.Message)
}

if ($trusts.Count -gt 0) {

    $trustsConfig = foreach ($t in $trusts) {
        [PSCustomObject]@{
            Name                    = $t.Name
            Source                  = $t.Source
            Target                  = $t.Target
            Direction               = $t.Direction
            TrustType               = $t.TrustType
            ForestTransitive        = $t.ForestTransitive
            IntraForest             = $t.IntraForest
            SIDFilteringQuarantined = $t.SIDFilteringQuarantined
            SelectiveAuthentication = $t.SelectiveAuthentication
        }
    }

    $trustsCsvPath = Join-Path $CsvDir "MATI_AD_Config_Trusts.csv"
    $trustsConfig | Export-Csv -Path $trustsCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[10-MATI-Config] Trusts configuration CSV: $trustsCsvPath" -ForegroundColor Green

    foreach ($t in $trusts) {

        # Skip disabled trusts if any
        if ($t.Direction -eq 'Disabled') { continue }

        # We only care about inter-forest / external-like trusts for these findings
        $isInterForest = -not $t.IntraForest

        # Inter-forest trust without SID filtering (SIDFilteringQuarantined is False or null)
        if ($isInterForest -and -not $t.SIDFilteringQuarantined) {
            $Global:Findings += New-Finding `
                -Id "MATI-CONFIG-010" `
                -Category "Config" `
                -Severity "High" `
                -Title "Inter-forest trust without SID filtering" `
                -Description ("Inter-forest or external trust from {0} to {1} does not have SID filtering enabled, which may allow SIDHistory abuse across the trust." -f $t.Source, $t.Target) `
                -Remediation "Enable SID filtering on this trust unless there is a specific and documented requirement not to. Review cross-forest/group SIDHistory usage and harden trusts accordingly." `
                -ObjectDN $t.Name `
                -Domain $t.Source `
                -Source "10-MATI-Config" `
                -Details ("Source={0}; Target={1}; TrustType={2}; Direction={3}; IntraForest={4}; SIDFilteringQuarantined={5}" -f $t.Source, $t.Target, $t.TrustType, $t.Direction, $t.IntraForest, $t.SIDFilteringQuarantined)
        }

        # Inter-forest trust without selective authentication
        if ($isInterForest -and -not $t.SelectiveAuthentication) {
            $Global:Findings += New-Finding `
                -Id "MATI-CONFIG-011" `
                -Category "Config" `
                -Severity "Medium" `
                -Title "Inter-forest trust without selective authentication" `
                -Description ("Inter-forest or external trust from {0} to {1} does not use selective authentication, increasing the exposure of resources to the trusted domain." -f $t.Source, $t.Target) `
                -Remediation "Review the need for this trust and consider enabling selective authentication to restrict which users and groups from the trusted domain can access resources." `
                -ObjectDN $t.Name `
                -Domain $t.Source `
                -Source "10-MATI-Config" `
                -Details ("Source={0}; Target={1}; TrustType={2}; Direction={3}; IntraForest={4}; SelectiveAuthentication={5}" -f $t.Source, $t.Target, $t.TrustType, $t.Direction, $t.IntraForest, $t.SelectiveAuthentication)
        }
    }
}
else {
    Write-Host "[10-MATI-Config] No trusts found." -ForegroundColor DarkGray
}

Write-Host "[10-MATI-Config] Module completed." -ForegroundColor Cyan
