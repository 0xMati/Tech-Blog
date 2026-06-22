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

.PARAMETER MailMethod
    Méthode d'envoi du rapport : 'Smtp' (Send-MailMessage, relais on-prem ou Direct Send EXO)
    ou 'Graph' (Microsoft Graph sendMail, app + certificat, recommandé pour EXO). Défaut : Smtp.

.PARAMETER TenantId
    (MailMethod Graph) ID de tenant Entra ID.

.PARAMETER ClientId
    (MailMethod Graph) App (client) ID de l'app registration disposant de la permission Mail.Send.

.PARAMETER CertThumbprint
    (MailMethod Graph) Empreinte du certificat d'authentification de l'app (store CurrentUser/LocalMachine).
    Méthode recommandée. Fournir CertThumbprint OU ClientSecret.

.PARAMETER ClientSecret
    (MailMethod Graph) Client secret de l'app, en SecureString. Alternative au certificat
    (moins sûr : à stocker chiffré, ex. DPAPI / Credential Manager). Fournir CertThumbprint OU ClientSecret.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1
    Exécution simple, sortie console + HTML + CSV dans .\Reports.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -SendEmail -SmtpServer relay.contoso.com -From ad-monitor@contoso.com -To soc@contoso.com
    Exécution avec alerte email (SMTP) en cas de problème détecté.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -SendEmail -MailMethod Graph -TenantId <tid> -ClientId <appid> -CertThumbprint <tp> -From ad-monitor@contoso.com -To soc@contoso.com
    Exécution avec envoi du rapport via Microsoft Graph (EXO, sans SMTP).

.NOTES
    Pré-requis : RSAT AD DS Tools (module ActiveDirectory, repadmin, dcdiag, nltest),
    compte avec droits de lecture sur AD et accès réseau aux DC.
    Pour MailMethod Graph : modules Microsoft.Graph.Authentication et Microsoft.Graph.Users.Actions,
    app registration Entra ID avec permission applicative Mail.Send et un certificat.
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

    # Méthode d'envoi du rapport
    [ValidateSet('Smtp', 'Graph')]
    [string]   $MailMethod = 'Smtp',
    [string]   $TenantId,        # MailMethod Graph
    [string]   $ClientId,        # MailMethod Graph
    [string]   $CertThumbprint,  # MailMethod Graph (auth par certificat - recommandé)
    [System.Security.SecureString] $ClientSecret,  # MailMethod Graph (auth par client secret)

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

function Send-GraphMailReport {
    # Envoie le rapport via Microsoft Graph. Auth par certificat (recommandé) OU client secret.
    param(
        [Parameter(Mandatory)][string]   $TenantId,
        [Parameter(Mandatory)][string]   $ClientId,
        [string]                         $CertThumbprint,
        [System.Security.SecureString]   $ClientSecret,
        [Parameter(Mandatory)][string]   $From,
        [Parameter(Mandatory)][string[]] $To,
        [Parameter(Mandatory)][string]   $Subject,
        [Parameter(Mandatory)][string]   $HtmlBody,
        [string]                         $AttachmentPath
    )
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users.Actions  -ErrorAction Stop

    # Connexion : certificat prioritaire, sinon client secret.
    if ($CertThumbprint) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId `
            -CertificateThumbprint $CertThumbprint -NoWelcome -ErrorAction Stop
    }
    elseif ($ClientSecret) {
        $cred = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome -ErrorAction Stop
    }
    else {
        throw 'Send-GraphMailReport : fournir -CertThumbprint ou -ClientSecret.'
    }

    try {
        $message = @{
            subject      = $Subject
            body         = @{ contentType = 'HTML'; content = $HtmlBody }
            toRecipients = @($To | ForEach-Object { @{ emailAddress = @{ address = $_ } } })
        }
        if ($AttachmentPath -and (Test-Path -LiteralPath $AttachmentPath)) {
            $bytes = [System.IO.File]::ReadAllBytes($AttachmentPath)
            $message.attachments = @(@{
                '@odata.type' = '#microsoft.graph.fileAttachment'
                name          = (Split-Path -Path $AttachmentPath -Leaf)
                contentType   = 'text/csv'
                contentBytes  = [System.Convert]::ToBase64String($bytes)
            })
        }
        Send-MgUserMail -UserId $From -Message $message -SaveToSentItems:$false -ErrorAction Stop
    }
    finally {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}

# ------------------------------------------------------------------------------------
#  En-tête console
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '===========================================================' -ForegroundColor Cyan
Write-Host '  AD Health Check' -ForegroundColor Cyan
Write-Host ('  Domain : {0}' -f $DomainName) -ForegroundColor Cyan
Write-Host ('  Start  : {0}' -f $script:StartTime) -ForegroundColor Cyan
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
    Write-Host "ERROR: unable to query domain '$DomainName'. $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Record -DC '(domain)' -Category 'Discovery' -Check 'DCs discovered' -Status 'INFO' `
       -Detail ('{0} DCs: {1}' -f $DomainControllers.Count, ($DomainControllers.HostName -join ', '))

# ------------------------------------------------------------------------------------
#  2. Rôles FSMO : localisation + accessibilité
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '--- FSMO Roles ---' -ForegroundColor White
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
            Record -DC '(forest/domain)' -Category 'FSMO' -Check $role -Status 'FAIL' -Detail 'Role holder not found'
            continue
        }
        # Test d'accessibilité du détenteur (LDAP).
        $reachable = $false
        try { $reachable = [bool](Get-ADDomainController -Identity $holder -Server $holder) } catch { $reachable = $false }
        if ($reachable) {
            Record -DC $holder -Category 'FSMO' -Check $role -Status 'OK' -Detail "Holder: $holder"
        }
        else {
            Record -DC $holder -Category 'FSMO' -Check $role -Status 'FAIL' -Detail "Holder unreachable: $holder"
        }
    }
}
catch {
    Record -DC '(forest)' -Category 'FSMO' -Check 'FSMO read' -Status 'FAIL' -Detail $_.Exception.Message
}

# ------------------------------------------------------------------------------------
#  3. Réplication globale : repadmin /replsummary
# ------------------------------------------------------------------------------------
Write-Host ''
Write-Host '--- Replication (replsummary) ---' -ForegroundColor White
$repSummary = Invoke-External -FilePath 'repadmin.exe' -Arguments @('/replsummary', $DomainName)
if ($repSummary.ExitCode -ne 0 -and [string]::IsNullOrWhiteSpace($repSummary.Output)) {
    Record -DC '(domain)' -Category 'Replication' -Check 'replsummary' -Status 'FAIL' -Detail 'repadmin failed (RSAT installed?)'
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
                       -Status 'FAIL' -Detail 'Replication failures detected'
            }
        }
    }
    if (-not $hadFailure) {
        Record -DC '(domain)' -Category 'Replication' -Check 'replsummary' -Status 'OK' -Detail 'No replication failures'
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
        Record -DC $dcName -Category 'Connectivity' -Check 'Ping' -Status 'FAIL' -Detail 'DC unreachable (ICMP) — remaining checks skipped'
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
            Record -DC $dcName -Category 'Connectivity' -Check ("Port {0} ({1})" -f $p.Port, $p.Name) -Status 'FAIL' -Detail 'Port closed/filtered'
        }
    }

    # 4c. Services critiques
    try {
        $svcList = Get-Service -ComputerName $dcName -ErrorAction Stop
    }
    catch {
        $svcList = $null
        Record -DC $dcName -Category 'Services' -Check 'Service query' -Status 'FAIL' -Detail $_.Exception.Message
    }
    if ($svcList) {
        foreach ($svc in $CriticalServices) {
            $found = $svcList | Where-Object { $_.Name -eq $svc.Name }
            if (-not $found) {
                # DFSR/ADWS absents = INFO (ancien env. ou rôle non installé) sauf cœur AD.
                $isCore = $svc.Name -in @('NTDS', 'Netlogon', 'Kdc')
                Record -DC $dcName -Category 'Services' -Check $svc.Display `
                       -Status ($(if ($isCore) { 'FAIL' } else { 'INFO' })) -Detail 'Service not present'
                continue
            }
            if ($found.Status -eq 'Running') {
                Record -DC $dcName -Category 'Services' -Check $svc.Display -Status 'OK'
            }
            else {
                Record -DC $dcName -Category 'Services' -Check $svc.Display -Status 'FAIL' -Detail ("State: {0}" -f $found.Status)
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
            Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'FAIL' -Detail ("$replFails outbound replication failure(s)")
        }
        else {
            Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'OK'
        }
    }
    else {
        Record -DC $dcName -Category 'Replication' -Check 'showrepl' -Status 'WARN' -Detail 'repadmin output not parseable'
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
            Record -DC $dcName -Category 'DCDiag' -Check $t -Status 'FAIL' -Detail 'dcdiag: test failed'
        }
        else {
            Record -DC $dcName -Category 'DCDiag' -Check $t -Status 'WARN' -Detail 'dcdiag result indeterminate'
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
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'WARN' -Detail 'Offset not measurable (w32tm)'
    }
    elseif ($offsetSec -ge $TimeOffsetFailSec) {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'FAIL' -Detail ("Offset {0:N3}s (>= {1}s)" -f $offsetSec, $TimeOffsetFailSec)
    }
    elseif ($offsetSec -ge $TimeOffsetWarnSec) {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'WARN' -Detail ("Offset {0:N3}s (>= {1}s)" -f $offsetSec, $TimeOffsetWarnSec)
    }
    else {
        Record -DC $dcName -Category 'TimeSync' -Check 'W32Time offset' -Status 'OK' -Detail ("Offset {0:N3}s" -f $offsetSec)
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
            $check  = "Free space $($d.DeviceID)"
            if ($freeGB -lt $DiskFreeFailGB) {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'FAIL' -Detail ("{0} GB free (< {1} GB)" -f $freeGB, $DiskFreeFailGB)
            }
            elseif ($freeGB -lt $DiskFreeWarnGB) {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'WARN' -Detail ("{0} GB free (< {1} GB)" -f $freeGB, $DiskFreeWarnGB)
            }
            else {
                Record -DC $dcName -Category 'Storage' -Check $check -Status 'OK' -Detail ("{0} GB free" -f $freeGB)
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
                Record -DC $dcName -Category 'Storage' -Check 'NTDS.dit' -Status 'INFO' -Detail ("Path: {0} (UNC access unavailable)" -f $ditPath)
            }
        }
    }
    catch {
        Record -DC $dcName -Category 'Storage' -Check 'Disk space' -Status 'WARN' -Detail $_.Exception.Message
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
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'OK' -Detail ("No critical errors in last {0}h" -f $EventLookbackHours)
        }
        else {
            $grouped = $relevant | Group-Object Id | Sort-Object Count -Descending
            $summary = ($grouped | ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ', '
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'FAIL' -Detail ("Errors: {0}" -f $summary)
        }
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') {
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'OK' -Detail ("No critical errors in last {0}h" -f $EventLookbackHours)
        }
        else {
            Record -DC $dcName -Category 'EventLog' -Check 'Directory Service' -Status 'WARN' -Detail $_.Exception.Message
        }
    }
}

# ------------------------------------------------------------------------------------
#  5. Synthèse
# ------------------------------------------------------------------------------------
$nOK   = @($script:Results | Where-Object { $_.Status -eq 'OK' }).Count
$nWarn = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
$nFail = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$hasIssue = ($nWarn -gt 0 -or $nFail -gt 0)
$globalStatus = if ($nFail -gt 0) { 'FAIL' } elseif ($nWarn -gt 0) { 'WARN' } else { 'OK' }

Write-Host ''
Write-Host '===========================================================' -ForegroundColor Cyan
Write-Host ('  Summary : OK={0}  WARN={1}  FAIL={2}  -> {3}' -f $nOK, $nWarn, $nFail, $globalStatus) `
    -ForegroundColor $(switch ($globalStatus) { 'OK' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} })
Write-Host '===========================================================' -ForegroundColor Cyan

# ------------------------------------------------------------------------------------
#  6. Export CSV
# ------------------------------------------------------------------------------------
$csvPath = Join-Path $OutputPath ("ADHealth_{0}.csv" -f $Timestamp)
$script:Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host ("CSV  : {0}" -f $csvPath) -ForegroundColor Gray

# ------------------------------------------------------------------------------------
#  7. Export HTML (modern report)
# ------------------------------------------------------------------------------------
# HttpUtility peut ne pas être chargé en PS 5.1 par défaut : charger avant usage.
try { Add-Type -AssemblyName System.Web -ErrorAction Stop } catch {}
function Encode-Html {
    param([string] $Text)
    if ($null -eq $Text) { return '' }
    try { return [System.Web.HttpUtility]::HtmlEncode($Text) }
    catch { return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;') }
}

function Get-StatusMeta {
    param([string] $Status)
    switch ($Status) {
        'OK'   { return @{ cls = 'ok';   icon = '&#10003;'; label = 'OK' } }
        'WARN' { return @{ cls = 'warn'; icon = '&#9888;';  label = 'WARN' } }
        'FAIL' { return @{ cls = 'fail'; icon = '&#10007;'; label = 'FAIL' } }
        default { return @{ cls = 'info'; icon = '&#8505;';  label = 'INFO' } }
    }
}

$total       = $script:Results.Count
$score       = if ($total -gt 0) { [math]::Round(($nOK / $total) * 100) } else { 100 }
$durationSec = [int]((Get-Date) - $script:StartTime).TotalSeconds
$dcCount     = @($script:Results | Where-Object { $_.Category -eq 'Discovery' }).Count
$dcGroups    = $script:Results | Group-Object DC | Sort-Object Name
$nDC         = @($dcGroups).Count
$accent      = switch ($globalStatus) { 'OK' {'#22c55e'} 'WARN' {'#f59e0b'} 'FAIL' {'#ef4444'} }
$accent2     = switch ($globalStatus) { 'OK' {'#16a34a'} 'WARN' {'#d97706'} 'FAIL' {'#dc2626'} }

# Donut ring geometry (r=54 => circumference ~339.3)
$circ = [math]::Round(2 * [math]::PI * 54, 1)
$dash = [math]::Round($circ * (1 - ($score / 100)), 1)

# --- Per-DC overview cards ---
$dcCards = foreach ($g in $dcGroups) {
    $dcName = $g.Name
    $dOK = @($g.Group | Where-Object { $_.Status -eq 'OK' }).Count
    $dW  = @($g.Group | Where-Object { $_.Status -eq 'WARN' }).Count
    $dF  = @($g.Group | Where-Object { $_.Status -eq 'FAIL' }).Count
    $dStatus = if ($dF -gt 0) { 'fail' } elseif ($dW -gt 0) { 'warn' } else { 'ok' }
    @"
<div class='dccard $dStatus'>
  <div class='dccard-top'><span class='dot $dStatus'></span><span class='dcname'>$(Encode-Html $dcName)</span></div>
  <div class='dccard-stats'>
    <span class='pill ok'>&#10003; $dOK</span>
    <span class='pill warn'>&#9888; $dW</span>
    <span class='pill fail'>&#10007; $dF</span>
  </div>
</div>
"@
}

# Build email-safe 2-column rows (tables render reliably in OWA/Outlook, grid/flex do not)
$dcCards = @($dcCards)
$dcRows  = ''
for ($i = 0; $i -lt $dcCards.Count; $i += 2) {
    $c1 = $dcCards[$i]
    $c2 = if ($i + 1 -lt $dcCards.Count) { $dcCards[$i + 1] } else { '' }
    $dcRows += "<tr><td width='50%' valign='top' style='padding:6px;'>$c1</td><td width='50%' valign='top' style='padding:6px;'>$c2</td></tr>`n"
}

# --- Detailed table grouped by DC ---
$tableSections = foreach ($g in $dcGroups) {
    $dcName = $g.Name
    $dF = @($g.Group | Where-Object { $_.Status -eq 'FAIL' }).Count
    $dW = @($g.Group | Where-Object { $_.Status -eq 'WARN' }).Count
    $hdrStatus = if ($dF -gt 0) { 'fail' } elseif ($dW -gt 0) { 'warn' } else { 'ok' }
    "<tr class='group-row $hdrStatus'><td colspan='5'><span class='dot $hdrStatus'></span>$(Encode-Html $dcName)</td></tr>"
    foreach ($r in $g.Group) {
        $m = Get-StatusMeta $r.Status
        $tShort = if ($r.Time -match 'T(\d{2}:\d{2}:\d{2})') { $Matches[1] } else { $r.Time }
        @"
<tr class='$($m.cls)'>
  <td class='c-time'>$tShort</td>
  <td class='c-cat'><span class='cat'>$(Encode-Html $r.Category)</span></td>
  <td class='c-check'>$(Encode-Html $r.Check)</td>
  <td class='c-status'><span class='badge $($m.cls)'>$($m.icon) $($m.label)</span></td>
  <td class='c-detail'>$(Encode-Html $r.Detail)</td>
</tr>
"@
    }
}

$runDate = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss')

$html = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>AD Health Check - $DomainName</title>
<style>
 :root { --accent: $accent; --accent2: $accent2; }
 * { box-sizing: border-box; }
 body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0;
        background: #0b1120; color: #e2e8f0; -webkit-font-smoothing: antialiased; }
 .wrap { max-width: 1100px; margin: 0 auto; padding: 28px 20px 60px; }

 /* Header */
 .hero { position: relative; border-radius: 16px; padding: 18px 26px; overflow: hidden;
         background: linear-gradient(135deg, #111827 0%, #1e293b 60%, #0f172a 100%);
         border: 1px solid rgba(148,163,184,.15);
         box-shadow: 0 14px 36px rgba(0,0,0,.4); }
 .hero::before { content: ''; position: absolute; top: -60%; right: -10%; width: 360px; height: 360px;
                 background: radial-gradient(circle, var(--accent) 0%, transparent 70%); opacity: .16; }
 .hero-grid { position: relative; display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
 .hero-text h1 { margin: 0; font-size: 21px; font-weight: 700; letter-spacing: .3px; }
 .hero-text .domain { color: var(--accent); font-weight: 700; }
 .hero-meta { color: #94a3b8; font-size: 12.5px; margin-top: 6px; line-height: 1.5; }
 .hero-meta b { color: #cbd5e1; }
 .gstatus { display: inline-flex; align-items: center; gap: 7px; margin-top: 10px;
            padding: 5px 14px; border-radius: 999px; font-weight: 800; font-size: 12.5px;
            letter-spacing: .4px; text-transform: uppercase;
            background: var(--accent); color: #07111f;
            box-shadow: 0 6px 18px -6px var(--accent); }

 /* Donut */
 .ring-wrap { position: relative; width: 104px; height: 104px; flex-shrink: 0; }
 .ring-wrap svg { transform: rotate(-90deg); }
 .ring-center { position: absolute; inset: 0; display: flex; flex-direction: column;
                align-items: center; justify-content: center; }
 .ring-center .pct { font-size: 23px; font-weight: 800; color: #f1f5f9; }
 .ring-center .lbl { font-size: 9px; letter-spacing: 1.5px; color: #94a3b8; text-transform: uppercase; }

 /* KPI cards */
 .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 22px 0 6px; }
 .kpi { background: linear-gradient(160deg, #1e293b, #131c2e); border: 1px solid rgba(148,163,184,.12);
        border-radius: 16px; padding: 18px 20px; position: relative; overflow: hidden; }
 .kpi .num { font-size: 30px; font-weight: 800; line-height: 1; }
 .kpi .cap { font-size: 12px; color: #94a3b8; margin-top: 8px; letter-spacing: .4px; text-transform: uppercase; }
 .kpi .bar { position: absolute; left: 0; top: 0; bottom: 0; width: 5px; border-radius: 16px 0 0 16px; }
 .kpi.ok .num { color: #4ade80; } .kpi.ok .bar { background: #22c55e; }
 .kpi.warn .num { color: #fbbf24; } .kpi.warn .bar { background: #f59e0b; }
 .kpi.fail .num { color: #f87171; } .kpi.fail .bar { background: #ef4444; }
 .kpi.tot .num { color: #60a5fa; } .kpi.tot .bar { background: #3b82f6; }

 /* Section titles */
 .sec-title { font-size: 13px; letter-spacing: 1.4px; text-transform: uppercase;
              color: #94a3b8; margin: 34px 4px 14px; font-weight: 700; }

 /* DC overview */
 .dcgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px,1fr)); gap: 12px; }
 .dccard { background: linear-gradient(160deg, #1b2538, #131b2b); border: 1px solid rgba(148,163,184,.12);
           border-radius: 14px; padding: 14px 16px; border-left: 4px solid #334155; }
 .dccard.ok { border-left-color: #22c55e; } .dccard.warn { border-left-color: #f59e0b; }
 .dccard.fail { border-left-color: #ef4444; }
 .dccard-top { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
 .dcname { font-weight: 600; font-size: 13.5px; color: #e2e8f0; word-break: break-all; }
 .dccard-stats { display: flex; gap: 6px; }
 .pill { font-size: 12px; font-weight: 700; padding: 3px 9px; border-radius: 8px; }
 .pill.ok { background: rgba(34,197,94,.15); color: #4ade80; }
 .pill.warn { background: rgba(245,158,11,.15); color: #fbbf24; }
 .pill.fail { background: rgba(239,68,68,.15); color: #f87171; }
 .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
 .dot.ok { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
 .dot.warn { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
 .dot.fail { background: #ef4444; box-shadow: 0 0 8px #ef4444; }

 /* Table */
 .tablecard { background: #111a2b; border: 1px solid rgba(148,163,184,.12); border-radius: 16px;
              overflow: hidden; box-shadow: 0 16px 40px rgba(0,0,0,.35); }
 table { border-collapse: collapse; width: 100%; }
 thead th { background: #0d1626; color: #94a3b8; text-align: left; font-size: 11px;
            letter-spacing: 1px; text-transform: uppercase; padding: 13px 16px;
            border-bottom: 1px solid rgba(148,163,184,.15); position: sticky; top: 0; }
 tbody td { padding: 11px 16px; font-size: 13px; border-bottom: 1px solid rgba(148,163,184,.07); }
 tbody tr.ok:hover td { background: rgba(148,163,184,.05); }
 .group-row td { background: #0e1a2c !important; font-weight: 700; font-size: 13.5px; color: #e2e8f0;
                 letter-spacing: .3px; padding: 12px 16px; }
 .group-row td .dot { margin-right: 9px; vertical-align: middle; }
 /* Row emphasis by status */
 tr.fail td { background: rgba(239,68,68,.12); }
 tr.fail td.c-time { box-shadow: inset 4px 0 0 #ef4444; }
 tr.fail td.c-detail { color: #fecaca; font-weight: 600; }
 tr.warn td { background: rgba(245,158,11,.10); }
 tr.warn td.c-time { box-shadow: inset 4px 0 0 #f59e0b; }
 tr.warn td.c-detail { color: #fde68a; font-weight: 600; }
 .c-time { color: #64748b; font-variant-numeric: tabular-nums; white-space: nowrap; }
 .cat { font-size: 11px; padding: 2px 8px; border-radius: 6px; background: rgba(96,165,250,.12);
        color: #93c5fd; font-weight: 600; }
 .c-check { color: #cbd5e1; }
 .c-detail { color: #94a3b8; }
 .badge { display: inline-flex; align-items: center; gap: 5px; padding: 4px 11px; border-radius: 999px;
          font-size: 11px; font-weight: 800; letter-spacing: .5px; text-transform: uppercase; }
 .badge.ok { background: rgba(34,197,94,.14); color: #4ade80; box-shadow: inset 0 0 0 1px rgba(34,197,94,.35); }
 .badge.warn { background: #f59e0b; color: #3a2606; box-shadow: 0 0 0 1px rgba(245,158,11,.5); }
 .badge.fail { background: #ef4444; color: #fff; box-shadow: 0 2px 10px -2px #ef4444; }
 .badge.info { background: #475569; color: #e2e8f0; }

 .foot { text-align: center; color: #475569; font-size: 12px; margin-top: 30px; }
 @media (max-width: 620px) { .kpis { grid-template-columns: repeat(2,1fr); } .hero-grid { gap: 20px; } }
</style></head><body>
<div class='wrap'>

  <div class='hero'>
    <table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'><tr>
      <td width='124' valign='middle' style='padding-right:24px;'>
        <div class='ring-wrap'>
          <svg width='104' height='104' viewBox='0 0 130 130'>
            <defs>
              <linearGradient id='rg' x1='0%' y1='0%' x2='100%' y2='100%'>
                <stop offset='0%' stop-color='$accent'/><stop offset='100%' stop-color='$accent2'/>
              </linearGradient>
            </defs>
            <circle cx='65' cy='65' r='54' fill='none' stroke='rgba(148,163,184,.15)' stroke-width='11'/>
            <circle cx='65' cy='65' r='54' fill='none' stroke='url(#rg)' stroke-width='11'
                    stroke-linecap='round' stroke-dasharray='$circ' stroke-dashoffset='$dash'/>
          </svg>
          <div class='ring-center'><span class='pct'>$score%</span><span class='lbl'>Health</span></div>
        </div>
      </td>
      <td valign='middle'>
        <div class='hero-text'>
          <h1>AD Health Check &mdash; <span class='domain'>$(Encode-Html $DomainName)</span></h1>
          <div class='hero-meta'>
            Run: <b>$runDate</b> &bull; Duration: <b>$durationSec s</b> &bull;
            DCs: <b>$nDC</b> &bull; Checks: <b>$total</b>
          </div>
          <span class='gstatus'>&#9679; Global status: $globalStatus</span>
        </div>
      </td>
    </tr></table>
  </div>

  <table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='margin:22px 0 6px;border-collapse:collapse;'><tr>
    <td width='25%' valign='top' style='padding:7px;'><div class='kpi ok'><div class='bar'></div><div class='num'>$nOK</div><div class='cap'>Passed</div></div></td>
    <td width='25%' valign='top' style='padding:7px;'><div class='kpi warn'><div class='bar'></div><div class='num'>$nWarn</div><div class='cap'>Warnings</div></div></td>
    <td width='25%' valign='top' style='padding:7px;'><div class='kpi fail'><div class='bar'></div><div class='num'>$nFail</div><div class='cap'>Failures</div></div></td>
    <td width='25%' valign='top' style='padding:7px;'><div class='kpi tot'><div class='bar'></div><div class='num'>$total</div><div class='cap'>Total checks</div></div></td>
  </tr></table>

  <div class='sec-title'>Domain Controllers overview</div>
  <table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>
$dcRows
  </table>

  <div class='sec-title'>Detailed results</div>
  <div class='tablecard'>
    <table>
      <thead><tr>
        <th>Time</th><th>Category</th><th>Check</th><th>Status</th><th>Detail</th>
      </tr></thead>
      <tbody>
$($tableSections -join "`n")
      </tbody>
    </table>
  </div>

  <div class='foot'>Generated by Invoke-ADHealthCheck.ps1 &bull; $runDate</div>
</div>
</body></html>
"@

$htmlPath = Join-Path $OutputPath ("ADHealth_{0}.html" -f $Timestamp)
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host ("HTML : {0}" -f $htmlPath) -ForegroundColor Gray

# ------------------------------------------------------------------------------------
#  8. Alerte email
# ------------------------------------------------------------------------------------
if ($SendEmail) {
    $subject = "[AD Health][$globalStatus] $DomainName - OK=$nOK WARN=$nWarn FAIL=$nFail"

    # Validation des prérequis selon la méthode d'envoi.
    $missing = @()
    if (-not $From) { $missing += 'From' }
    if (-not $To)   { $missing += 'To' }
    if ($MailMethod -eq 'Smtp') {
        if (-not $SmtpServer) { $missing += 'SmtpServer' }
    }
    else { # Graph
        if (-not $TenantId) { $missing += 'TenantId' }
        if (-not $ClientId) { $missing += 'ClientId' }
        if (-not $CertThumbprint -and -not $ClientSecret) { $missing += 'CertThumbprint ou ClientSecret' }
    }

    if ($missing.Count -gt 0) {
        Write-Host ("Email non envoyé : paramètre(s) requis manquant(s) pour MailMethod '{0}' : {1}." -f $MailMethod, ($missing -join ', ')) -ForegroundColor Yellow
    }
    elseif ($EmailOnlyOnIssue -and -not $hasIssue) {
        Write-Host 'Email non envoyé : aucun problème détecté (EmailOnlyOnIssue).' -ForegroundColor Gray
    }
    elseif ($MailMethod -eq 'Graph') {
        try {
            Send-GraphMailReport -TenantId $TenantId -ClientId $ClientId `
                -CertThumbprint $CertThumbprint -ClientSecret $ClientSecret `
                -From $From -To $To -Subject $subject -HtmlBody $html
            Write-Host ("Email (Graph) envoyé à : {0}" -f ($To -join ', ')) -ForegroundColor Gray
        }
        catch {
            Write-Host ("Échec envoi email (Graph) : {0}" -f $_.Exception.Message) -ForegroundColor Red
        }
    }
    else { # Smtp
        $mailParams = @{
            SmtpServer  = $SmtpServer
            Port        = $SmtpPort
            From        = $From
            To          = $To
            Subject     = $subject
            Body        = $html
            BodyAsHtml  = $true
            UseSsl      = [bool]$UseSsl
            ErrorAction = 'Stop'
        }
        try {
            Send-MailMessage @mailParams
            Write-Host ("Email (SMTP) envoyé à : {0}" -f ($To -join ', ')) -ForegroundColor Gray
        }
        catch {
            Write-Host ("Échec envoi email (SMTP) : {0}" -f $_.Exception.Message) -ForegroundColor Red
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
