#requires -Version 5.1
<#
40-MATI-StaleObjectsAndOS.ps1  (MATI – Microsoft Active Directory Threat Inspector)
Module 40 – Stale Objects & OS Inventory

Findings implémentés :

  STALE (LastLogonTimestamp / whenCreated)
  ---------------------------------------
  - MATI-STALE-001 – Stale user accounts (agrégé par domaine)
      * Seuils :
          >=  90 jours → Medium
          >= 180 jours → High
          >= 365 jours → Critical
      * Basé sur LastLogonTimestamp
        - Si vide/0 : fallback sur whenCreated (compte "jamais connecté")

  - MATI-STALE-002 – Stale computer accounts (agrégé par domaine)
      * Même logique / mêmes seuils que pour les users

  OS Inventory & Risk (Domain Controllers / Servers / Workstations)
  -----------------------------------------------------------------
  - MATI-OS-001 – Domain Controllers running unsupported/legacy OS
  - MATI-OS-002 – Member servers running unsupported/legacy OS
  - MATI-OS-003 – Workstations running unsupported/legacy OS

  Règles OS (approximation raisonnable, ajustable si besoin) :
    Critical (EoL) :
      - Windows Server 2008 / 2008 R2
      - Windows Server 2012 / 2012 R2
      - Windows 7 / 8 / 8.1

    High (bientôt EoL) :
      - Windows Server 2019

    Medium (ancien mais supporté) :
      - Windows Server 2016
      - Windows 10

    OK (pas de finding) :
      - Windows Server 2022+
      - Windows 11
      - etc.

Outputs CSV (un par type) :
  - CSV\MATI_AD_Stale_Users.csv
  - CSV\MATI_AD_Stale_Computers.csv
  - CSV\MATI_AD_OS_DomainControllers.csv
  - CSV\MATI_AD_OS_Servers.csv
  - CSV\MATI_AD_OS_Workstations.csv
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$moduleTag = '[40-MATI-StaleObjectsAndOS]'
Write-Host "$moduleTag Output root : $OutputRoot" -ForegroundColor Cyan

# --------------------------------------------------------------------
# Dossiers CSV
# --------------------------------------------------------------------
$csvRoot = Join-Path -Path $OutputRoot -ChildPath 'CSV'
if (-not (Test-Path -Path $csvRoot)) {
    New-Item -Path $csvRoot -ItemType Directory | Out-Null
}

# --------------------------------------------------------------------
# Chargement du modèle de finding commun
# --------------------------------------------------------------------
$findingLibPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Common\Finding.ps1'
if (Test-Path -Path $findingLibPath) {
    . $findingLibPath
} else {
    Write-Warning "$moduleTag Common finding library not found at $findingLibPath"
    return
}

# --------------------------------------------------------------------
# ActiveDirectory module
# --------------------------------------------------------------------
try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}
catch {
    Write-Error "$moduleTag Failed to load ActiveDirectory module: $($_.Exception.Message)"
    return
}

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

# Conversion LastLogonTimestamp -> [DateTime] (UTC)
function Convert-MatiLastLogonTimestampToDate {
    param(
        [nullable[long]]$LastLogonTimestamp,
        [datetime]$WhenCreated
    )

    if ($LastLogonTimestamp -ne $null -and $LastLogonTimestamp -ne 0) {
        try {
            return [DateTime]::FromFileTimeUtc([int64]$LastLogonTimestamp)
        } catch {
            # Valeur corrompue / invalide -> fallback whenCreated
        }
    }

    return $WhenCreated
}

# Catégorie de "stale" en fonction du nombre de jours
function Get-MatiStaleBucket {
    param(
        [nullable[int]]$Days
    )

    if ($Days -eq $null) { return 'None' }
    if ($Days -ge 365)   { return '>=365' }
    if ($Days -ge 180)   { return '>=180' }
    if ($Days -ge 90)    { return '>=90' }
    return 'None'
}

# Catégorie OS (Server / Workstation)
function Get-MatiOsCategory {
    param(
        [string]$OperatingSystem
    )

    if ([string]::IsNullOrEmpty($OperatingSystem)) { return $null }

    $os = $OperatingSystem.ToLower()

    if ($os -like '*server*') {
        return 'Server'
    }

    if ($os -like '*windows*') {
        return 'Workstation'
    }

    return $null
}

# Niveau de risque OS (Critical / High / Medium / $null)
function Get-MatiOsRiskLevel {
    param(
        [string]$OperatingSystem
    )

    if ([string]::IsNullOrEmpty($OperatingSystem)) { return $null }

    $os = $OperatingSystem.ToLower()

    # Domaines critiques / EoL
    if ($os -like '*2008*')      { return 'Critical' }
    if ($os -like '*2012*')      { return 'Critical' }
    if ($os -like '*windows 7*') { return 'Critical' }
    if ($os -like '*windows 8*') { return 'Critical' }   # 8 / 8.1

    # Proche EoL
    if ($os -like '*2019*')      { return 'High' }

    # Ancien mais supporté (à affiner si besoin)
    if ($os -like '*2016*')      { return 'Medium' }
    if ($os -like '*windows 10*'){ return 'Medium' }

    # 2022 / 2025 / Windows 11 / autres récents -> pas de finding
    return $null
}

# Renvoie une sévérité globale (Critical > High > Medium) à partir de compteurs
function Get-MatiMaxSeverityFromCounts {
    param(
        [int]$CriticalCount,
        [int]$HighCount,
        [int]$MediumCount
    )

    if ($CriticalCount -gt 0) { return 'Critical' }
    if ($HighCount     -gt 0) { return 'High' }
    if ($MediumCount   -gt 0) { return 'Medium' }
    return $null
}

$now = Get-Date

# --------------------------------------------------------------------
# Collections globales du module
# --------------------------------------------------------------------
$findings         = @()

$staleUsers       = @()
$staleComputers   = @()

$osDCs            = @()
$osServers        = @()
$osWorkstations   = @()

# --------------------------------------------------------------------
# Forest & domaines
# --------------------------------------------------------------------
try {
    $forest  = Get-ADForest -ErrorAction Stop
    $domains = @()
    foreach ($domName in $forest.Domains) {
        try {
            $domains += Get-ADDomain -Identity $domName -ErrorAction Stop
        } catch {
            Write-Warning ("{0} Failed to query domain {1}: {2}" -f $moduleTag, $domName, $_.Exception.Message)
        }
    }
} catch {
    Write-Error "$moduleTag Failed to query forest: $($_.Exception.Message)"
    return
}

foreach ($domain in $domains) {
    $domainName  = $domain.DNSRoot
    $searchBase  = $domain.DistinguishedName

    Write-Host "$moduleTag Processing domain $domainName..." -ForegroundColor Cyan

    # --------------------------
    # Récupération des DCs (DNs)
    # --------------------------
    $dcs    = @()
    $dcDNs  = @()

    try {
        $dcs = Get-ADDomainController -Filter * -Server $domainName -ErrorAction Stop
        $dcDNs = $dcs.ComputerObjectDN
    } catch {
        Write-Warning ("{0} Failed to query domain controllers for {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    # --------------------------
    # Utilisateurs (stale)
    # --------------------------
    $users = @()
    try {
        $users = Get-ADUser -Filter * -SearchBase $searchBase -SearchScope Subtree -Server $domainName `
            -Properties LastLogonTimestamp, whenCreated, Enabled -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query users in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($u in $users) {
        $lastLogonDate = Convert-MatiLastLogonTimestampToDate -LastLogonTimestamp $u.LastLogonTimestamp -WhenCreated $u.whenCreated
        $days = $null

        if ($lastLogonDate -ne $null) {
            $days = [int]([Math]::Floor(($now - $lastLogonDate).TotalDays))
            if ($days -lt 0) { $days = 0 }  # Skew horloge
        }

        $bucket = Get-MatiStaleBucket -Days $days
        if ($bucket -eq 'None') {
            continue  # On n'exporte dans le CSV que les comptes >= 90 jours
        }

        $staleUsers += [pscustomobject]@{
            DomainDNS          = $domainName
            SamAccountName     = $u.SamAccountName
            DistinguishedName  = $u.DistinguishedName
            Enabled            = $u.Enabled
            WhenCreated        = $u.whenCreated
            LastLogonTimestamp = $u.LastLogonTimestamp
            LastLogonDate      = $lastLogonDate
            LastActivityDays   = $days
            StaleBucket        = $bucket
        }
    }

    # --------------------------
    # Computers (stale + OS)
    # --------------------------
    $computers = @()
    try {
        $computers = Get-ADComputer -Filter * -SearchBase $searchBase -SearchScope Subtree -Server $domainName `
            -Properties LastLogonTimestamp, whenCreated, Enabled, OperatingSystem, OperatingSystemVersion -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query computers in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($c in $computers) {
        $isDC = $false
        if ($dcDNs -contains $c.DistinguishedName) {
            $isDC = $true
        }

        # --- Stale logic ---
        $lastLogonDate = Convert-MatiLastLogonTimestampToDate -LastLogonTimestamp $c.LastLogonTimestamp -WhenCreated $c.whenCreated
        $days = $null

        if ($lastLogonDate -ne $null) {
            $days = [int]([Math]::Floor(($now - $lastLogonDate).TotalDays))
            if ($days -lt 0) { $days = 0 }
        }

        $bucket = Get-MatiStaleBucket -Days $days
        if ($bucket -ne 'None') {
            $staleComputers += [pscustomobject]@{
                DomainDNS          = $domainName
                Name               = $c.Name
                SamAccountName     = $c.SamAccountName
                DistinguishedName  = $c.DistinguishedName
                Enabled            = $c.Enabled
                WhenCreated        = $c.whenCreated
                LastLogonTimestamp = $c.LastLogonTimestamp
                LastLogonDate      = $lastLogonDate
                LastActivityDays   = $days
                StaleBucket        = $bucket
                IsDomainController = $isDC
            }
        }

        # --- OS inventory ---
        $os           = $c.OperatingSystem
        $osVersion    = $c.OperatingSystemVersion
        $osCategory   = Get-MatiOsCategory -OperatingSystem $os
        $osRisk       = Get-MatiOsRiskLevel -OperatingSystem $os

        if ($isDC) {
            $osDCs += [pscustomobject]@{
                DomainDNS         = $domainName
                Name              = $c.Name
                DistinguishedName = $c.DistinguishedName
                OperatingSystem   = $os
                OperatingSystemVersion = $osVersion
                OsRiskLevel       = $osRisk
            }
        } elseif ($osCategory -eq 'Server') {
            $osServers += [pscustomobject]@{
                DomainDNS         = $domainName
                Name              = $c.Name
                DistinguishedName = $c.DistinguishedName
                OperatingSystem   = $os
                OperatingSystemVersion = $osVersion
                OsRiskLevel       = $osRisk
            }
        } elseif ($osCategory -eq 'Workstation') {
            $osWorkstations += [pscustomobject]@{
                DomainDNS         = $domainName
                Name              = $c.Name
                DistinguishedName = $c.DistinguishedName
                OperatingSystem   = $os
                OperatingSystemVersion = $osVersion
                OsRiskLevel       = $osRisk
            }
        }
    }
}

# --------------------------------------------------------------------
# Findings STALE – agrégés par domaine
# --------------------------------------------------------------------

# 1) MATI-STALE-001 – Users
$staleUsersByDomain = $staleUsers | Group-Object DomainDNS
foreach ($grp in $staleUsersByDomain) {
    $dom   = $grp.Name
    $items = $grp.Group

    $countTotal = $items.Count
    $count90    = ($items | Where-Object { $_.StaleBucket -eq '>=90' }).Count
    $count180   = ($items | Where-Object { $_.StaleBucket -eq '>=180' }).Count
    $count365   = ($items | Where-Object { $_.StaleBucket -eq '>=365' }).Count

    # Détermination de la sévérité à partir du bucket le plus sévère
    $severity = Get-MatiMaxSeverityFromCounts -CriticalCount $count365 -HighCount $count180 -MediumCount $count90
    if (-not $severity) { continue }

    $details = "Users90d={0}; Users180d={1}; Users365d={2}; TotalStaleUsers={3}" -f $count90, $count180, $count365, $countTotal

    $findings += New-Finding `
        -Id 'MATI-STALE-001' `
        -Category 'StaleObjects' `
        -Severity $severity `
        -Title 'Stale user accounts detected' `
        -Description ("Domain {0} contains user accounts that have been inactive (based on LastLogonTimestamp / creation date) for 90 days or more. Stale accounts increase the attack surface and should be reviewed and cleaned up." -f $dom) `
        -Remediation "Review stale user accounts, disable those no longer needed, and consider implementing automatic lifecycle / deprovisioning processes to reduce long-lived inactive identities." `
        -ObjectDN $dom `
        -Domain $dom `
        -Source '40-MATI-StaleObjectsAndOS' `
        -Details $details
}

# 2) MATI-STALE-002 – Computers
$staleComputersByDomain = $staleComputers | Group-Object DomainDNS
foreach ($grp in $staleComputersByDomain) {
    $dom   = $grp.Name
    $items = $grp.Group

    $countTotal = $items.Count
    $count90    = ($items | Where-Object { $_.StaleBucket -eq '>=90' }).Count
    $count180   = ($items | Where-Object { $_.StaleBucket -eq '>=180' }).Count
    $count365   = ($items | Where-Object { $_.StaleBucket -eq '>=365' }).Count

    $severity = Get-MatiMaxSeverityFromCounts -CriticalCount $count365 -HighCount $count180 -MediumCount $count90
    if (-not $severity) { continue }

    $details = "Computers90d={0}; Computers180d={1}; Computers365d={2}; TotalStaleComputers={3}" -f $count90, $count180, $count365, $countTotal

    $findings += New-Finding `
        -Id 'MATI-STALE-002' `
        -Category 'StaleObjects' `
        -Severity $severity `
        -Title 'Stale computer accounts detected' `
        -Description ("Domain {0} contains computer accounts that have been inactive (based on LastLogonTimestamp / creation date) for 90 days or more. Stale machine accounts increase attack surface and complicate inventory and patch management." -f $dom) `
        -Remediation "Review stale computer accounts, remove obsolete machines from Active Directory, and align with CMDB / inventory sources to keep the environment clean." `
        -ObjectDN $dom `
        -Domain $dom `
        -Source '40-MATI-StaleObjectsAndOS' `
        -Details $details
}

# --------------------------------------------------------------------
# Findings OS – agrégés par domaine & type
# --------------------------------------------------------------------

# MATI-OS-001 – Domain Controllers
$osDCsByDomain = $osDCs | Where-Object { $_.OsRiskLevel } | Group-Object DomainDNS
foreach ($grp in $osDCsByDomain) {
    $dom   = $grp.Name
    $items = $grp.Group

    $crit = ($items | Where-Object { $_.OsRiskLevel -eq 'Critical' }).Count
    $high = ($items | Where-Object { $_.OsRiskLevel -eq 'High' }).Count
    $med  = ($items | Where-Object { $_.OsRiskLevel -eq 'Medium' }).Count

    $severity = Get-MatiMaxSeverityFromCounts -CriticalCount $crit -HighCount $high -MediumCount $med
    if (-not $severity) { continue }

    $total = $items.Count
    $details = "DCsCritical={0}; DCsHigh={1}; DCsMedium={2}; TotalDCsAtRisk={3}" -f $crit, $high, $med, $total

    $findings += New-Finding `
        -Id 'MATI-OS-001' `
        -Category 'OSInventory' `
        -Severity $severity `
        -Title 'Domain Controllers running unsupported or legacy Windows versions' `
        -Description ("Domain {0} has domain controllers running unsupported or legacy Windows versions. Outdated DC OS versions increase the risk of missing security hardening, vulnerabilities, and incompatibility with modern Kerberos and security features." -f $dom) `
        -Remediation "Plan to upgrade domain controllers to a supported and current Windows Server release. Prioritize DCs running EoL OS, and validate forest/domain functional levels and application compatibility during the migration." `
        -ObjectDN $dom `
        -Domain $dom `
        -Source '40-MATI-StaleObjectsAndOS' `
        -Details $details
}

# MATI-OS-002 – Member servers
$osServersByDomain = $osServers | Where-Object { $_.OsRiskLevel } | Group-Object DomainDNS
foreach ($grp in $osServersByDomain) {
    $dom   = $grp.Name
    $items = $grp.Group

    $crit = ($items | Where-Object { $_.OsRiskLevel -eq 'Critical' }).Count
    $high = ($items | Where-Object { $_.OsRiskLevel -eq 'High' }).Count
    $med  = ($items | Where-Object { $_.OsRiskLevel -eq 'Medium' }).Count

    $severity = Get-MatiMaxSeverityFromCounts -CriticalCount $crit -HighCount $high -MediumCount $med
    if (-not $severity) { continue }

    $total = $items.Count
    $details = "ServersCritical={0}; ServersHigh={1}; ServersMedium={2}; TotalServersAtRisk={3}" -f $crit, $high, $med, $total

    $findings += New-Finding `
        -Id 'MATI-OS-002' `
        -Category 'OSInventory' `
        -Severity $severity `
        -Title 'Member servers running unsupported or legacy Windows versions' `
        -Description ("Domain {0} has member servers running unsupported or legacy Windows versions. These systems are more exposed to vulnerabilities and may not benefit from modern security controls and hardening baselines." -f $dom) `
        -Remediation "Identify critical workloads on legacy servers, plan OS upgrades or migrations, and decommission obsolete systems. Prioritize servers exposed to the internet or hosting critical services." `
        -ObjectDN $dom `
        -Domain $dom `
        -Source '40-MATI-StaleObjectsAndOS' `
        -Details $details
}

# MATI-OS-003 – Workstations
$osWorkstationsByDomain = $osWorkstations | Where-Object { $_.OsRiskLevel } | Group-Object DomainDNS
foreach ($grp in $osWorkstationsByDomain) {
    $dom   = $grp.Name
    $items = $grp.Group

    $crit = ($items | Where-Object { $_.OsRiskLevel -eq 'Critical' }).Count
    $high = ($items | Where-Object { $_.OsRiskLevel -eq 'High' }).Count
    $med  = ($items | Where-Object { $_.OsRiskLevel -eq 'Medium' }).Count

    $severity = Get-MatiMaxSeverityFromCounts -CriticalCount $crit -HighCount $high -MediumCount $med
    if (-not $severity) { continue }

    $total = $items.Count
    $details = "WorkstationsCritical={0}; WorkstationsHigh={1}; WorkstationsMedium={2}; TotalWorkstationsAtRisk={3}" -f $crit, $high, $med, $total

    $findings += New-Finding `
        -Id 'MATI-OS-003' `
        -Category 'OSInventory' `
        -Severity $severity `
        -Title 'Workstations running unsupported or legacy Windows versions' `
        -Description ("Domain {0} has workstations running unsupported or legacy Windows versions. Legacy client OS increase the likelihood of endpoint compromise, especially if used for privileged access or exposed to internet browsing and email." -f $dom) `
        -Remediation "Plan a workstation refresh program to migrate endpoints to supported OS versions, enforce hardening baselines, and align with your endpoint management / compliance strategy." `
        -ObjectDN $dom `
        -Domain $dom `
        -Source '40-MATI-StaleObjectsAndOS' `
        -Details $details
}

# --------------------------------------------------------------------
# Export CSV
# --------------------------------------------------------------------
try {
    if ($staleUsers.Count -gt 0) {
        $pathUsers = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_Stale_Users.csv'
        $staleUsers |
            Sort-Object DomainDNS, LastActivityDays, SamAccountName |
            Export-Csv -Path $pathUsers -NoTypeInformation -Encoding UTF8
        Write-Host "$moduleTag Stale users CSV: $pathUsers" -ForegroundColor Green
    }

    if ($staleComputers.Count -gt 0) {
        $pathComputers = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_Stale_Computers.csv'
        $staleComputers |
            Sort-Object DomainDNS, LastActivityDays, Name |
            Export-Csv -Path $pathComputers -NoTypeInformation -Encoding UTF8
        Write-Host "$moduleTag Stale computers CSV: $pathComputers" -ForegroundColor Green
    }

    if ($osDCs.Count -gt 0) {
        $pathOsDc = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_OS_DomainControllers.csv'
        $osDCs |
            Sort-Object DomainDNS, Name |
            Export-Csv -Path $pathOsDc -NoTypeInformation -Encoding UTF8
        Write-Host "$moduleTag OS inventory (DCs) CSV: $pathOsDc" -ForegroundColor Green
    }

    if ($osServers.Count -gt 0) {
        $pathOsServers = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_OS_Servers.csv'
        $osServers |
            Sort-Object DomainDNS, Name |
            Export-Csv -Path $pathOsServers -NoTypeInformation -Encoding UTF8
        Write-Host "$moduleTag OS inventory (Servers) CSV: $pathOsServers" -ForegroundColor Green
    }

    if ($osWorkstations.Count -gt 0) {
        $pathOsWorkstations = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_OS_Workstations.csv'
        $osWorkstations |
            Sort-Object DomainDNS, Name |
            Export-Csv -Path $pathOsWorkstations -NoTypeInformation -Encoding UTF8
        Write-Host "$moduleTag OS inventory (Workstations) CSV: $pathOsWorkstations" -ForegroundColor Green
    }
} catch {
    Write-Warning "$moduleTag Failed to export CSV files: $($_.Exception.Message)"
}

Write-Host "$moduleTag Module completed." -ForegroundColor Cyan

# Le runner récupère ce que renvoie le module et l'ajoute à $Global:Findings
return ,$findings
