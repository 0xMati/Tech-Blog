#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Outil de surveillance de la santé Active Directory (réplication, services, connectivité, FSMO).

.DESCRIPTION
    Invoke-ADHealthCheck auto-découvre tous les contrôleurs de domaine du domaine courant
    (ou d'un domaine cible) puis exécute une série de contrôles :

        - Réplication            : repadmin /replsummary + détection des échecs par DC
        - Services critiques     : NTDS, DNS, KDC, Netlogon, DFSR, W32Time, ADWS
        - Connectivité / DC      : ping LDAP/Kerberos, dcdiag (tests ciblés), canal sécurisé (nltest)
        - Rôles FSMO             : localisation + accessibilité de chaque détenteur
        - Synchro horaire        : décalage réel mesuré via w32tm (seuils WARN/FAIL)
        - Stockage               : espace libre C: et volume NTDS.dit + taille de la base
        - Journal Directory Svc  : erreurs critiques récentes (1311, 2042, lingering, USN rollback...)

    Restitution :
        - Console couleur (OK / WARN / FAIL)
        - Rapport HTML
        - Log CSV horodaté
        - Alerte email SMTP (uniquement si au moins un WARN/FAIL, configurable)

    Conçu pour PowerShell 5.1 et une exécution en tâche planifiée.

.PARAMETER DomainName
    FQDN du domaine à contrôler. Par défaut : domaine de la machine d'exécution.

.PARAMETER OutputPath
    Dossier de sortie des rapports HTML/CSV. Par défaut : sous-dossier .\Reports.

.PARAMETER SendEmail
    Active l'envoi d'un email de synthèse.

.PARAMETER EmailOnlyOnIssue
    Avec -SendEmail, n'envoie l'email que si au moins un WARN ou FAIL est détecté. (Défaut : $true)

.PARAMETER SmtpServer
    Serveur SMTP relais.

.PARAMETER SmtpPort
    Port SMTP. Défaut : 25.

.PARAMETER From
    Adresse expéditeur.

.PARAMETER To
    Adresse(s) destinataire(s).

.PARAMETER UseSsl
    Utilise TLS pour l'envoi SMTP.

.PARAMETER DcDiagTests
    Liste des tests dcdiag à exécuter par DC. Défaut : Connectivity, Replications, Advertising,
    FsmoCheck, Services, SysVolCheck, NetLogons, KccEvent.

.PARAMETER DiskFreeWarnGB
    Seuil d'espace disque libre (Go) sous lequel un WARN est levé. Défaut : 10.

.PARAMETER DiskFreeFailGB
    Seuil d'espace disque libre (Go) sous lequel un FAIL est levé. Défaut : 3.

.PARAMETER TimeOffsetWarnSec
    Décalage horaire (s) au-delà duquel un WARN est levé. Défaut : 5.

.PARAMETER TimeOffsetFailSec
    Décalage horaire (s) au-delà duquel un FAIL est levé. Défaut : 60.

.PARAMETER EventLookbackHours
    Fenêtre (heures) d'analyse du journal Directory Service. Défaut : 24.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1
    Exécution simple, sortie console + HTML + CSV dans .\Reports.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -SendEmail -SmtpServer relay.contoso.com -From ad-monitor@contoso.com -To soc@contoso.com
    Exécution avec alerte email en cas de problème détecté.

.NOTES
    Pré-requis : RSAT AD DS Tools (module ActiveDirectory, repadmin, dcdiag, nltest),
    compte avec droits de lecture sur AD et accès réseau aux DC.
#>
[CmdletBinding()]
param(
    [string]   $DomainName = $env:USERDNSDOMAIN,
    [string]   $OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Reports'),

    [switch]   $SendEmail,
    [bool]     $EmailOnlyOnIssue = $true,
    [string]   $SmtpServer,
    [int]      $SmtpPort = 25,
    [string]   $From,
    [string[]] $To,
    [switch]   $UseSsl,

    [string[]] $DcDiagTests = @(
        'Connectivity', 'Replications', 'Advertising', 'FsmoCheck',
        'Services', 'SysVolCheck', 'NetLogons', 'KccEvent'
    ),

    # Seuils des contrôles complémentaires
    [int]      $DiskFreeWarnGB  = 10,   # WARN si espace libre < ce seuil
    [int]      $DiskFreeFailGB  = 3,    # FAIL si espace libre < ce seuil
    [int]      $TimeOffsetWarnSec = 5,  # WARN si décalage horaire (W32Time) dépasse ce seuil
    [int]      $TimeOffsetFailSec = 60, # FAIL si décalage horaire dépasse ce seuil
    [int]      $EventLookbackHours = 24 # Fenêtre d'analyse du journal Directory Service
)

# ------------------------------------------------------------------------------------
#  Initialisation
# ------------------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$script:Results   = New-Object System.Collections.Generic.List[object]
$script:StartTime = Get-Date
$Timestamp        = $script:StartTime.ToString('yyyyMMdd_HHmmss')

# Services critiques à vérifier sur chaque DC.
# DFSR -> SYSVOL moderne ; NtFrs présent uniquement sur d'anciens environnements (vérifié si existant).
$CriticalServices = @(
    @{ Name = 'NTDS';     Display = 'AD DS (NTDS)' }
    @{ Name = 'DNS';      Display = 'DNS Server' }
    @{ Name = 'Kdc';      Display = 'Kerberos KDC' }
    @{ Name = 'Netlogon'; Display = 'Netlogon' }
    @{ Name = 'DFSR';     Display = 'DFS Replication (SYSVOL)' }
    @{ Name = 'W32Time';  Display = 'Windows Time' }
    @{ Name = 'ADWS';     Display = 'AD Web Services' }
)

if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# ------------------------------------------------------------------------------------
#  Helpers
# ------------------------------------------------------------------------------------
function Add-Result {
    param(
        [Parameter(Mandatory)][string] $DC,
        [Parameter(Mandatory)][string] $Category,
        [Parameter(Mandatory)][string] $Check,
        [Parameter(Mandatory)][ValidateSet('OK', 'WARN', 'FAIL', 'INFO')][string] $Status,
        [string] $Detail = ''
    )
    $script:Results.Add([pscustomobject]@{
        Time     = (Get-Date).ToString('s')
        DC       = $DC
        Category = $Category
        Check    = $Check
        Status   = $Status
        Detail   = $Detail
    })
}

function Write-StatusLine {
    param(
        [string] $DC,
        [string] $Category,
        [string] $Check,
        [string] $Status,
        [string] $Detail
    )
    $color = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Gray' }
    }
    $line = '{0,-22} {1,-14} {2,-26} [{3}]' -f $DC, $Category, $Check, $Status
    Write-Host $line -ForegroundColor $color
    if ($Detail -and $Status -ne 'OK') {
        Write-Host ('  -> {0}' -f $Detail) -ForegroundColor DarkGray
    }
}

function Record {
    # Enregistre + affiche en une passe.
    param($DC, $Category, $Check, $Status, $Detail = '')
    Add-Result -DC $DC -Category $Category -Check $Check -Status $Status -Detail $Detail
    Write-StatusLine -DC $DC -Category $Category -Check $Check -Status $Status -Detail $Detail
}

function Invoke-External {
    # Exécute un exécutable externe et capture stdout (string array). Ne lève pas d'exception.
    param([string] $FilePath, [string[]] $Arguments)
    try {
        $out = & $FilePath @Arguments 2>&1
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = ($out | Out-String) }
    }
    catch {
        return [pscustomobject]@{ ExitCode = -1; Output = $_.Exception.Message }
    }
}

# ------------------------------------------------------------------------------------
#  En-tête console
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '===========================================================' -ForegroundColor Cyan
Write-Host '  AD Health Check' -ForegroundColor Cyan
Write-Host ('  Domaine : {0}' -f $DomainName) -ForegroundColor Cyan
Write-Host ('  Début   : {0}' -f $script:StartTime) -ForegroundColor Cyan
Write-Host '===========================================================' -ForegroundColor Cyan
Write-Host ''

# ------------------------------------------------------------------------------------
#  1. Découverte du domaine et des DC
# ------------------------------------------------------------------------------------
try {
    $Domain = Get-ADDomain -Identity $DomainName
    $DomainControllers = Get-ADDomainController -Filter * -Server $DomainName |
        Sort-Object HostName
}
catch {
    Write-Host "ERREUR: impossible d'interroger le domaine '$DomainName'. $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Record -DC '(domaine)' -Category 'Discovery' -Check 'DC découverts' -Status 'INFO' `
       -Detail ('{0} DC : {1}' -f $DomainControllers.Count, ($DomainControllers.HostName -join ', '))

# ------------------------------------------------------------------------------------
#  2. Rôles FSMO : localisation + accessibilité
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '--- Rôles FSMO ---' -ForegroundColor White
try {
    $forest = Get-ADForest -Server $DomainName
    $fsmo = [ordered]@{
        'Schema Master'          = $forest.SchemaMaster
        'Domain Naming Master'   = $forest.DomainNamingMaster
        'PDC Emulator'           = $Domain.PDCEmulator
        'RID Master'             = $Domain.RIDMaster
        'Infrastructure Master'  = $Domain.InfrastructureMaster
    }
    foreach ($role in $fsmo.Keys) {
        $holder = $fsmo[$role]
        if ([string]::IsNullOrWhiteSpace($holder)) {
            Record -DC '(forêt/domaine)' -Category 'FSMO' -Check $role -Status 'FAIL' -Detail 'Détenteur introuvable'
            continue
        }
        # Test d'accessibilité du détenteur (LDAP).
        $reachable = $false
        try { $reachable = [bool](Get-ADDomainController -Identity $holder -Server $holder) } catch { $reachable = $false }
        if ($reachable) {
            Record -DC $holder -Category 'FSMO' -Check $role -Status 'OK' -Detail "Détenteur : $holder"
        }
        else {
            Record -DC $holder -Category 'FSMO' -Check $role -Status 'FAIL' -Detail "Détenteur injoignable : $holder"
        }
    }
}
catch {
    Record -DC '(forêt)' -Category 'FSMO' -Check 'Lecture FSMO' -Status 'FAIL' -Detail $_.Exception.Message
}

# ------------------------------------------------------------------------------------
#  3. Réplication globale : repadmin /replsummary
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '--- Réplication (replsummary) ---' -ForegroundColor White
$repSummary = Invoke-External -FilePath 'repadmin.exe' -Arguments @('/replsummary', $DomainName)
if ($repSummary.ExitCode -ne 0 -and [string]::IsNullOrWhiteSpace($repSummary.Output)) {
    Record -DC '(domaine)' -Category 'Replication' -Check 'replsummary' -Status 'FAIL' -Detail 'repadmin a échoué (RSAT installé ?)'
}
else {
    # Repère les lignes avec des échecs : colonnes "fails/total".
    $hadFailure = $false
    foreach ($l in ($repSummary.Output -split "`r?`n")) {
        if ($l -match '\s(\d+)\s*/\s*(\d+)\s+(\d+)') {
            $fails = [int]$Matches[1]
            $pct   = [int]$Matches[3]
            if ($fails -gt 0 -or $pct -gt 0) {
                $hadFailure = $true
                Record -DC ($l.Trim() -replace '\s{2,}', ' ') -Category 'Replication' -Check 'replsummary' `
                       -Status 'FAIL' -Detail 'Échecs de réplication détectés'
            }
        }
    }
    if (-not $hadFailure) {
        Record -DC '(domaine)' -Category 'Replication' -Check 'replsummary' -Status 'OK' -Detail 'Aucun échec de réplication'
    }
}

# ------------------------------------------------------------------------------------
#  4. Contrôles par DC
# ------------------------------------------------------------------------------------
foreach ($dc in $DomainControllers) {
    $dcName = $dc.HostName
    Write-Host ''
    Write-Host ('=== {0} ===' -f $dcName) -ForegroundColor White

    # 4a. Joignabilité réseau de base
    $online = Test-Connection -ComputerName $dcName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $online) {
        Record -DC $dcName -Category 'Connectivity' -Check 'Ping' -Status 'FAIL' -Detail 'DC injoignable (ICMP) — contrôles suivants ignorés'
        continue
    }
    Record -DC $dcName -Category 'Connectivity' -Check 'Ping' -Status 'OK'

    # 4b. Ports critiques LDAP(389) et Kerberos(88)
    foreach ($p in @(@{Port=389;Name='LDAP'}, @{Port=88;Name='Kerberos'}, @{Port=445;Name='SMB/SYSVOL'})) {
        $tcp = Test-NetConnection -ComputerName $dcName -Port $p.Port -WarningAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) {
            Record -DC $dcName -Category 'Connectivity' -Check ("Port {0} ({1})" -f $p.Port, $p.Name) -Status 'OK'
        }
        else {
            Record -DC $dcName -Category 'Connectivity' -Check ("Port {0} ({1})" -f $p.Port, $p.Name) -Status 'FAIL' -Detail 'Port fermé/filtré'
        }
    }

    # 4c. Services critiques
    try {
        $svcList = Get-Service -ComputerName $dcName -ErrorAction Stop
    }
    catch {
        $svcList = $null
        Record -DC $dcName -Category 'Services' -Check 'Interrogation services' -Status 'FAIL' -Detail $_.Exception.Message
    }
    if ($svcList) {
        foreach ($svc in $CriticalServices) {
            $found = $svcList | Where-Object { $_.Name -eq $svc.Name }
            if (-not $found) {
                # DFSR/ADWS absents = INFO (ancien env. ou rôle non installé) sauf cœur AD.
                $isCore = $svc.Name -in @('NTDS', 'Netlogon', 'Kdc')
                Record -DC $dcName -Category 'Services' -Check $svc.Display `
                       -Status ($(if ($isCore) { 'FAIL' } else { 'INFO' })) -Detail 'Service non présent'
                continue
            }
            if ($found.Status -eq 'Running') {
                Record -DC $dcName -Category 'Services' -Check $svc.Display -Status 'OK'
            }
            else {
                Record -DC $dcName -Category 'Services' -Check $svc.Display -Status 'FAIL' -Detail ("État : {0}" -f $found.Status)
            }
        }
    }

    # 4d. Canal sécurisé (nltest /sc_query)
    $sc = Invoke-External -FilePath 'nltest.exe' -Arguments @("/sc_query:$($Domain.DNSRoot)", "/server:$dcName")
    if ($sc.Output -match 'NERR_Success|Success') {
        Record -DC $dcName -Category 'SecureChannel' -Check 'nltest /sc_query' -Status 'OK'
    }
    else {
        Record -DC $dcName -Category 'SecureChannel' -Check 'nltest /sc_query' -Status 'FAIL' `
               -Detail (($sc.Output -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 1))
    }

    # 4e. Réplication détaillée du DC (repadmin /showrepl)
    $showrepl = Invoke-External -FilePath 'repadmin.exe' -Arguments @('/showrepl', $dcName, '/csv')
    if ($showrepl.Output -match 'Number of Failures|,\s*\d+\s*,\s*\d+\s*,') {
        $replFails = 0
        foreach ($row in ($showrepl.Output -split "`r?`n")) {
            $cols = $row -split ','
            # Format CSV showrepl : ...,Number of Failures,Last Failure Time,Last Success Time,Last Failure Status
            if ($cols.Count -ge 12) {
                $nf = 0
                if ([int]::TryParse(($cols[8] -replace '"',''), [ref]$nf) -and $nf -gt 0) { $replFails += $nf }
            }
        }
        if ($replFails -gt 0) {
            Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'FAIL' -Detail ("$replFails échec(s) de réplication sortante")
        }
        else {
            Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'OK'
        }
    }
    else {
        Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'WARN' -Detail 'Sortie repadmin non exploitable'
    }

    # 4f. dcdiag (tests ciblés)
    $ddArgs = @("/s:$dcName")
    foreach ($t in $DcDiagTests) { $ddArgs += "/test:$t" }
    $dcdiag = Invoke-External -FilePath 'dcdiag.exe' -Arguments $ddArgs
    foreach ($t in $DcDiagTests) {
        # dcdiag affiche "passed test <Test>" ou "failed test <Test>".
        if ($dcdiag.Output -match ("(?im)passed test\s+$([regex]::Escape($t))")) {
            Record -DC $dcName -Category 'DCDiag' -Check $t -Status 'OK'
        }
        elseif ($dcdiag.Output -match ("(?im)failed test\s+$([regex]::Escape($t))")) {
            Record -DC $dcName -Category 'DCDiag' -Check $t -Status 'FAIL' -Detail 'dcdiag : test échoué'
        }
        else {
            Record -DC $dcName -Category 'DCDiag' -Check $t -Status 'WARN' -Detail 'Résultat dcdiag indéterminé'
        }
    }

    # 4g. Synchronisation horaire (W32Time) : décalage réel mesuré
    $w32 = Invoke-External -FilePath 'w32tm.exe' -Arguments @('/stripchart', "/computer:$dcName", '/samples:1', '/dataonly')
    $offsetSec = $null
    foreach ($line in ($w32.Output -split "`r?`n")) {
        # Format attendu : "<heure>, +0.0012345s" (ou -). Tolère la virgule décimale.
        if ($line -match '([+-]?\d+[.,]\d+)\s*s\b') {
            $offsetSec = [math]::Abs([double]($Matches[1] -replace ',', '.'))
            break
        }
    }
    if ($null -eq $offsetSec) {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'WARN' -Detail 'Décalage non mesurable (w32tm)'
    }
    elseif ($offsetSec -ge $TimeOffsetFailSec) {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'FAIL' -Detail ("Décalage {0:N3}s (>= {1}s)" -f $offsetSec, $TimeOffsetFailSec)
    }
    elseif ($offsetSec -ge $TimeOffsetWarnSec) {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'WARN' -Detail ("Décalage {0:N3}s (>= {1}s)" -f $offsetSec, $TimeOffsetWarnSec)
    }
    else {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'OK' -Detail ("Décalage {0:N3}s" -f $offsetSec)
    }

    # 4h. Espace disque + présence/volume NTDS.dit (via WMI/CIM distant)
    try {
        # Localisation de la base NTDS via registre distant.
        $ditPath = $null
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $dcName)
            $key = $reg.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters')
            if ($key) { $ditPath = $key.GetValue('DSA Database file') }
            if ($key) { $key.Close() }
            $reg.Close()
        } catch { $ditPath = $null }

        $ditDrive = if ($ditPath -and $ditPath -match '^([A-Za-z]):') { $Matches[1] } else { 'C' }

        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $dcName `
                    -Filter 'DriveType=3' -ErrorAction Stop
        $sysAndDit = $disks | Where-Object { $_.DeviceID -in @('C:', "$($ditDrive):") } | Sort-Object DeviceID -Unique
        foreach ($d in $sysAndDit) {
            $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
            $check  = "Espace libre $($d.DeviceID)"
            if ($freeGB -lt $DiskFreeFailGB) {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'FAIL' -Detail ("{0} GB libres (< {1} GB)" -f $freeGB, $DiskFreeFailGB)
            }
            elseif ($freeGB -lt $DiskFreeWarnGB) {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'WARN' -Detail ("{0} GB libres (< {1} GB)" -f $freeGB, $DiskFreeWarnGB)
            }
            else {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'OK' -Detail ("{0} GB libres" -f $freeGB)
            }
        }

        # Taille du fichier NTDS.dit (informatif).
        if ($ditPath) {
            $uncDit = '\\{0}\{1}' -f $dcName, ($ditPath -replace '^([A-Za-z]):', '$1$')
            if (Test-Path -LiteralPath $uncDit) {
                $ditSizeGB = [math]::Round((Get-Item -LiteralPath $uncDit).Length / 1GB, 2)
                Record -DC $dcName -Category 'Storage' -Check 'NTDS.dit' -Status 'INFO' -Detail ("{0} ({1} GB)" -f $ditPath, $ditSizeGB)
            }
            else {
                Record -DC $dcName -Category 'Storage' -Check 'NTDS.dit' -Status 'INFO' -Detail ("Chemin : {0} (accès UNC indisponible)" -f $ditPath)
            }
        }
    }
    catch {
        Record -DC $dcName -Category 'Storage' -Check 'Espace disque' -Status 'WARN' -Detail $_.Exception.Message
    }

    # 4i. Journal Directory Service : erreurs récentes (réplication, USN rollback, etc.)
    # IDs clés : 1311 (KCC topology), 2042 (réplication > tombstone), 1388/1988 (objets lingering),
    #            2103/467 (USN rollback / corruption base), 1645 (SPN/Kerberos).
    $criticalDsIds = @(1311, 2042, 1388, 1988, 2103, 467, 1645, 1865)
    try {
        $since = (Get-Date).AddHours(-1 * $EventLookbackHours)
        $dsEvents = Get-WinEvent -ComputerName $dcName -ErrorAction Stop -FilterHashtable @{
            LogName   = 'Directory Service'
            Level     = @(1, 2)   # 1=Critical, 2=Error
            StartTime = $since
        }
        $relevant = $dsEvents | Where-Object { $_.Id -in $criticalDsIds }
        if (-not $relevant -or $relevant.Count -eq 0) {
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'OK' -Detail ("Aucune erreur critique sur {0}h" -f $EventLookbackHours)
        }
        else {
            $grouped = $relevant | Group-Object Id | Sort-Object Count -Descending
            $summary = ($grouped | ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', '
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'FAIL' -Detail ("Erreurs : {0}" -f $summary)
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'OK' -Detail ("Aucune erreur critique sur {0}h" -f $EventLookbackHours)
        }
        else {
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'WARN' -Detail $_.Exception.Message
        }
    }
}

# ------------------------------------------------------------------------------------
#  5. Synthèse
# ------------------------------------------------------------------------------------
$nOK   = ($script:Results | Where-Object Status -eq 'OK').Count
$nWarn = ($script:Results | Where-Object Status -eq 'WARN').Count
$nFail = ($script:Results | Where-Object Status -eq 'FAIL').Count
$hasIssue = ($nWarn -gt 0 -or $nFail -gt 0)
$globalStatus = if ($nFail -gt 0) { 'FAIL' } elseif ($nWarn -gt 0) { 'WARN' } else { 'OK' }

Write-Host ''
Write-Host '===========================================================' -ForegroundColor Cyan
Write-Host ('  Synthèse : OK={0}  WARN={1}  FAIL={2}  -> {3}' -f $nOK, $nWarn, $nFail, $globalStatus) `
    -ForegroundColor $(switch ($globalStatus) { 'OK' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} })
Write-Host '===========================================================' -ForegroundColor Cyan

# ------------------------------------------------------------------------------------
#  6. Export CSV
# ------------------------------------------------------------------------------------
$csvPath = Join-Path $OutputPath ("ADHealth_{0}.csv" -f $Timestamp)
$script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host ("CSV  : {0}" -f $csvPath) -ForegroundColor Gray

# ------------------------------------------------------------------------------------
#  7. Export HTML
# ------------------------------------------------------------------------------------
# HttpUtility peut ne pas être chargé en PS 5.1 par défaut : charger avant usage.
try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch {}
function Encode-Html {
    param([string] $Text)
    if ($null -eq $Text) { return '' }
    try { return [System.Web.HttpUtility]::HtmlEncode($Text) }
    catch { return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') }
}

$statusBadge = {
    param($s)
    $cls = switch ($s) { 'OK' {'ok'} 'WARN' {'warn'} 'FAIL' {'fail'} default {'info'} }
    "<span class='badge $cls'>$s</span>"
}

$rows = foreach ($r in $script:Results) {
    "<tr class='{0}'><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>" -f `
        $r.Status.ToLower(), $r.Time, (Encode-Html $r.DC),
        $r.Category, (Encode-Html $r.Check),
        (& $statusBadge $r.Status), (Encode-Html $r.Detail)
}

$html = @"
<!DOCTYPE html>
<html lang='fr'><head><meta charset='utf-8'>
<title>AD Health Check - $DomainName - $Timestamp</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f7f9;color:#222}
 h1{font-size:20px;margin-bottom:4px}
 .meta{color:#666;font-size:13px;margin-bottom:16px}
 .summary{display:flex;gap:12px;margin:16px 0}
 .card{padding:10px 18px;border-radius:8px;font-weight:600;color:#fff}
 .card.ok{background:#2e8b57}.card.warn{background:#d9a300}.card.fail{background:#c0392b}
 table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}
 th,td{padding:7px 10px;border-bottom:1px solid #eee;font-size:13px;text-align:left}
 th{background:#34495e;color:#fff;position:sticky;top:0}
 tr.fail{background:#fdecea}tr.warn{background:#fff7e0}
 .badge{padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700}
 .badge.ok{background:#2e8b57}.badge.warn{background:#d9a300}.badge.fail{background:#c0392b}.badge.info{background:#7f8c8d}
</style></head><body>
<h1>AD Health Check &mdash; $DomainName</h1>
<div class='meta'>Exécuté le $($script:StartTime) &bull; Durée : $([int]((Get-Date) - $script:StartTime).TotalSeconds)s &bull; Statut global : <b>$globalStatus</b></div>
<div class='summary'>
 <div class='card ok'>OK : $nOK</div>
 <div class='card warn'>WARN : $nWarn</div>
 <div class='card fail'>FAIL : $nFail</div>
</div>
<table><thead><tr><th>Heure</th><th>DC</th><th>Catégorie</th><th>Contrôle</th><th>Statut</th><th>Détail</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
</body></html>
"@

$htmlPath = Join-Path $OutputPath ("ADHealth_{0}.html" -f $Timestamp)
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host ("HTML : {0}" -f $htmlPath) -ForegroundColor Gray

# ------------------------------------------------------------------------------------
#  8. Alerte email
# ------------------------------------------------------------------------------------
if ($SendEmail) {
    if (-not $SmtpServer -or -not $From -or -not $To) {
        Write-Host 'Email non envoyé : SmtpServer / From / To requis avec -SendEmail.' -ForegroundColor Yellow
    }
    elseif ($EmailOnlyOnIssue -and -not $hasIssue) {
        Write-Host 'Email non envoyé : aucun problème détecté (EmailOnlyOnIssue).' -ForegroundColor Gray
    }
    else {
        $subject = "[AD Health][$globalStatus] $DomainName - OK=$nOK WARN=$nWarn FAIL=$nFail"
        $mailParams = @{
            SmtpServer  = $SmtpServer
            Port        = $SmtpPort
            From        = $From
            To          = $To
            Subject     = $subject
            Body        = $html
            BodyAsHtml  = $true
            Attachments = $csvPath
            UseSsl      = [bool]$UseSsl
            ErrorAction = 'Stop'
        }
        try {
            Send-MailMessage @mailParams
            Write-Host ("Email envoyé à : {0}" -f ($To -join ', ')) -ForegroundColor Gray
        }
        catch {
            Write-Host ("Échec envoi email : {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }
}

# ------------------------------------------------------------------------------------
#  9. Code de sortie (utile pour la tâche planifiée / monitoring)
# ------------------------------------------------------------------------------------
switch ($globalStatus) {
    'FAIL' { exit 2 }
    'WARN' { exit 1 }
    default { exit 0 }
}
