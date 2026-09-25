# DFSR - Authoritative and Non-Authoritative Restore
🗓️ Published: 2025-11-12

Ever had that “oh no, SYSVOL disappeared” moment? 😅  
Whether your domain controller decided to play hide-and-seek with `NETLOGON` or you just need to bring one DC back in line, these PowerShell scripts are here to save your day.  
Both are 100% PowerShell 5.1-compatible and follow Microsoft’s official steps — just with a geeky twist. 🧠💻  

> ℹ️ **Prerequisites & assumptions**
> - Your SYSVOL is already migrated from **FRS to DFSR**. If you’re still on FRS (rare in 2026, but it happens on very old domains), run `dfsrmig /getmigrationstate` first and complete the migration before using these scripts — they only operate on the DFSR replication topology.
> - You have a **fresh backup of SYSVOL** on the DC you intend to keep as the source of truth. For authoritative restore, also export `C:\Windows\SYSVOL_DFSR\domain\Policies` (GPOs) and `\scripts` (NETLOGON) on that DC before starting, and ideally take a System State backup of the PRIMARY DC.
> - The scripts use `Domain.GetCurrentDomain()` and target **the current domain only**. In a multi-domain forest, run them once per domain that owns a broken SYSVOL.

---

## Read-Only Preflight: Subscription, Content and Events

Before changing either flag, distinguish an AD configuration problem from a DFSR initialization or content problem. Inspect the subscription through the target DC's own directory view rather than assuming its computer account lives in the default OU:

```powershell
Import-Module ActiveDirectory

$targetName = 'dc02.corp.example'
$targetDc = Get-ADDomainController -Identity $targetName -Server $targetName -ErrorAction Stop
$subscriptionDn = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,$($targetDc.ComputerObjectDN)"

Get-ADObject -Identity $subscriptionDn -Server $targetDc.HostName `
    -Properties 'msDFSR-Enabled', 'msDFSR-Options', 'msDFSR-RootPath', 'msDFSR-StagingPath' `
    -ErrorAction Stop |
    Select-Object DistinguishedName, 'msDFSR-Enabled', 'msDFSR-Options',
                  'msDFSR-RootPath', 'msDFSR-StagingPath'

repadmin.exe /showrepl $targetDc.HostName
```

Use the actual root path when backing up or inspecting SYSVOL; deployments do not all use the same historical `SYSVOL_DFSR` path. Repeat the subscription read from the DCs involved in a change to confirm AD convergence before expecting DFSR to consume it.

`msDFSR-Options = 1` requests primary initialization for the authoritative procedure. It is not a permanent role, a content-health check or evidence that this replica is the best source. Choose the authoritative copy from verified policy/script contents and backups, not merely its FSMO role or flag value. If only one DC needs repair and a healthy partner exists, use non-authoritative synchronization without changing the healthy peers.

Inspect the **DFS Replication** log, not just the System log:

```powershell
$windowStart = (Get-Date).AddHours(-4)

Get-WinEvent -ComputerName $targetDc.HostName -FilterHashtable @{
    LogName = 'DFS Replication'
    Id = 4114, 4614, 4604, 4602, 2213, 4012
    StartTime = $windowStart
} -ErrorAction Stop |
    Select-Object TimeCreated, Id, MachineName, RecordId, Message
```

| Event | Meaning for this workflow |
|---|---|
| 4114 | SYSVOL replication has been disabled for the subscription; required before re-enabling it |
| 4614 | SYSVOL is initialized locally but waiting for initial replication; not a completion signal |
| 4604 | SYSVOL initial synchronization completed on a non-authoritative member |
| 4602 | SYSVOL initialized as the primary member in the authoritative procedure |
| 2213 | Replication paused after an unexpected shutdown; investigate the event's recovery instructions |
| 4012 | Content-freshness protection stopped replication; assess the offline history and source before repair |

For non-authoritative recovery, verify a **new 4114** after disabling the subscription, then the **4614/4604** initialization sequence after re-enabling it. For authoritative recovery, verify **4114 then 4602 on the chosen primary** before allowing the other members to complete their non-authoritative initialization. Old events from an earlier attempt do not satisfy these checkpoints.

`dfsrdiag pollad` asks DFSR to reload its AD configuration; it does not replicate that configuration between DCs or prove content synchronization. A running service, an empty instantaneous replication-state display, or a fixed sleep is not equivalent to a completed initial sync. After the required events, validate shares, representative GPO/script contents and backlog against the intended partner.

The required sequence is documented in [Microsoft's DFSR SYSVOL synchronization procedure](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization). Resolve ordinary [AD replication failures](Troubleshooting%20Active%20Directory%20Replication%20-%20repadmin,%20dcdiag,%20DNS,%20RPC,%20Time%20and%20Kerberos.md) before using DFSR reinitialization to address a file-replication problem.

---

## Non-Authoritative Restore (DFSR)

Use this when **a DC’s SYSVOL is out of sync** and needs to **pull a fresh copy** from a healthy partner.  
This tells DFSR: “Hey, I’m broken, please replicate SYSVOL back to me.”

```powershell
<# 
Non-Authoritative SYSVOL restore (DFSR) — robust bind
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$DCName,

    [switch]$SkipSafetyPrompt
)

function Write-Step($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok($m){ Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err($m){ Write-Host "[X] $m" -ForegroundColor Red }

# 0) Elevation check
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Err "Run PowerShell as Administrator (elevated)."
    exit 1
}

# 1) Derive the computer CN (strip FQDN if provided)
$ServerCN = ($DCName -split '\.')[0]
Write-Step "Target DC (CN): $ServerCN"

# 2) Resolve the DC computer object's DN (handles unusual OUs)
try {
    $root = [ADSI]"LDAP://RootDSE"
    $domainDN = $root.defaultNamingContext
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=computer)(|(dNSHostName=$DCName)(name=$ServerCN)))"
    $searcher.PageSize = 1000
    $res = $searcher.FindOne()

    if (-not $res) {
        Write-Err "Computer object for '$DCName' was not found in the domain. Check the name."
        exit 1
    }

    $computerDN = $res.Properties["distinguishedname"][0]
    Write-Step "Computer DN: $computerDN"
}
catch {
    Write-Err "Failed to resolve computer DN: $($_.Exception.Message)"
    exit 1
}

# 3) Build the DFSR SYSVOL Subscription DN using the resolved computer DN
#    Expected under: CN=DFSR-LocalSettings,<ComputerDN>
$dfsrLocalSettingsDn = "CN=DFSR-LocalSettings,$computerDN"
$sysvolSubDn         = "CN=SYSVOL Subscription,CN=Domain System Volume,$dfsrLocalSettingsDn"

# 4) Bind to SYSVOL Subscription
try {
    $sysvolSub = [ADSI]("LDAP://$ServerCN/$sysvolSubDn")
    $null = $sysvolSub.Properties["msDFSR-Enabled"] # touch to validate
    Write-Ok "Bound to: $sysvolSubDn"
}
catch {
    Write-Err "Could not bind SYSVOL Subscription at:`n  $sysvolSubDn"
    Write-Warn "Either this DC does not use DFSR for SYSVOL, or SYSVOL hasn't been initialized."
    exit 1
}

# 5) Service helpers via sc.exe (no WinRM required)
function Stop-DFSRService {
    param([string]$Computer)
    Write-Step "Stopping DFSR on $Computer..."
    & sc.exe "\\$Computer" stop dfsr | Out-Null
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 2
        $q = sc.exe "\\$Computer" query dfsr 2>$null
        if (($q | Where-Object {$_ -match "STATE"}) -match "STOPPED") { Write-Ok "DFSR stopped on $Computer."; return }
    } while ((Get-Date) -lt $deadline)
    throw "Could not confirm DFSR is stopped on $Computer."
}
function Start-DFSRService {
    param([string]$Computer)
    Write-Step "Starting DFSR on $Computer..."
    & sc.exe "\\$Computer" start dfsr | Out-Null
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 2
        $q = sc.exe "\\$Computer" query dfsr 2>$null
        if (($q | Where-Object {$_ -match "STATE"}) -match "RUNNING") { Write-Ok "DFSR running on $Computer."; return }
    } while ((Get-Date) -lt $deadline)
    throw "Could not confirm DFSR is running on $Computer."
}
function Invoke-OnTarget {
    param([string]$Computer, [scriptblock]$ScriptBlock)
    if ($Computer -ieq $env:COMPUTERNAME) { & $ScriptBlock; return 0 }
    try { Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ErrorAction Stop | Out-Null; return 0 } catch { return 1 }
}

function Wait-SysvolEvent {
    param([string]$Computer, [int]$EventId, [datetime]$Since, [int]$TimeoutSeconds = 900)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $eventErrors = @()
        $phaseEvents = @(Get-WinEvent -ComputerName $Computer -FilterHashtable @{
            LogName = 'DFS Replication'
            Id = $EventId
            StartTime = $Since
        } -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
        if (@($eventErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }).Count) {
            throw "Cannot verify DFSR events on $Computer."
        }
        if ($phaseEvents | Where-Object { $_.ToXml() -match 'SYSVOL' }) { return }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "No new SYSVOL event $EventId on $Computer; stop at this phase."
}

if (-not $PSCmdlet.ShouldProcess($ServerCN, 'Reinitialize DFSR SYSVOL non-authoritatively')) { return }

if (-not $SkipSafetyPrompt) {
    Write-Warn "This will perform a NON-AUTHORITATIVE SYSVOL restore on $ServerCN."
    $ans = Read-Host "Continue? (Y/N)"
    if ($ans -notin @('Y','y')) { Write-Err "Cancelled."; exit 1 }
}

try {
    Stop-DFSRService -Computer $ServerCN

    $disableStarted = Get-Date
    Write-Step "Setting msDFSR-Enabled = FALSE on $ServerCN..."
    $sysvolSub.Put("msDFSR-Enabled", $false)
    $sysvolSub.SetInfo()
    Write-Ok "msDFSR-Enabled = FALSE applied."

    & repadmin.exe /syncall $ServerCN $domainDN /deP
    if ($LASTEXITCODE -ne 0) { throw 'AD replication of the disabled subscription failed.' }
    Start-DFSRService -Computer $ServerCN

    Write-Step "Forcing 'dfsrdiag pollad' on $ServerCN..."
    $rc = Invoke-OnTarget -Computer $ServerCN -ScriptBlock {
        dfsrdiag.exe pollad | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'dfsrdiag pollad failed.' }
    }
    if ($rc -ne 0) { throw "Could not run 'dfsrdiag pollad' on $ServerCN." }
    Wait-SysvolEvent -Computer $ServerCN -EventId 4114 -Since $disableStarted

    $enableStarted = Get-Date
    Write-Step "Re-enabling subscription (msDFSR-Enabled = TRUE) on $ServerCN..."
    $sysvolSub.Put("msDFSR-Enabled", $true)
    $sysvolSub.SetInfo()
    Write-Ok "msDFSR-Enabled = TRUE applied."

    & repadmin.exe /syncall $ServerCN $domainDN /deP
    if ($LASTEXITCODE -ne 0) { throw 'AD replication of the enabled subscription failed.' }
    Write-Step "Polling AD again on $ServerCN..."
    $rc = Invoke-OnTarget -Computer $ServerCN -ScriptBlock {
        dfsrdiag.exe pollad | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'dfsrdiag pollad failed.' }
    }
    if ($rc -ne 0) { throw "Second pollad failed on $ServerCN." }
    Wait-SysvolEvent -Computer $ServerCN -EventId 4604 -Since $enableStarted

    Write-Ok "SYSVOL initial synchronization reported event 4604 on $ServerCN. Validate content, shares and backlog."
}
catch {
    Write-Err "Failure: $($_.Exception.Message)"
    exit 1
}

Write-Step "Follow-ups:"
Write-Host "  dfsrdiag ReplicationState"
Write-Host "  dfsrdiag backlog /rgname:`"Domain System Volume`" /rfname:`"SYSVOL Share`" /smem:<HealthyDC> /rmem:$ServerCN"
Write-Host "  repadmin /showrepl $ServerCN"
Write-Host "  net share"
```

## Authoritative Restore (DFSR)

Use this when **this DC’s SYSVOL is correct** and must **overwrite all others.**
This marks the DC as “Primary” for SYSVOL (msDFSR-Options = 1).

```powershell
<#
DFSR SYSVOL – Authoritative Orchestrator (Microsoft sequence compliant)
PowerShell 5.1 only – no PS7 features.

What this script does (strict sequence):
  1) Set DFSR StartupType=Manual + STOP DFSR on ALL DCs
  2) On PRIMARY DC:  msDFSR-Enabled=FALSE, msDFSR-Options=1
  3) On OTHER DCs:   msDFSR-Enabled=FALSE
  4) Force AD replication (repadmin /syncall /AdeP)
  5) START DFSR on PRIMARY only  (expect Event 4114 on PRIMARY)
  6) On PRIMARY:     msDFSR-Enabled=TRUE
  7) Force AD replication
    8) On PRIMARY:     dfsrdiag pollad (require Event 4602)
  9) START DFSR on OTHER DCs     (expect Event 4114 on each)
 10) On OTHER DCs:   msDFSR-Enabled=TRUE
 11) On OTHER DCs:   dfsrdiag pollad
 12) Set DFSR StartupType=Automatic on ALL DCs

Reference: Microsoft Learn – Force authoritative and non-authoritative synchronization for DFSR-replicated SYSVOL.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$PrimaryDC,          # NetBIOS or FQDN of the DC that will be PRIMARY (authoritative)
    [switch]$SkipSafetyPrompt
)

function WStep($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function WOk($m){ Write-Host "[OK] $m" -ForegroundColor Green }
function WWarn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function WErr($m){ Write-Host "[X] $m" -ForegroundColor Red }

# --- Elevation check ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    WErr "Run PowerShell as Administrator."
    exit 1
}

# --- Enumerate DCs without AD module (uses .NET) ---
function Get-AllDCNames {
    try {
        $dcs = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
        return $dcs | ForEach-Object { $_.Name }  # FQDNs
    } catch {
        WErr "Failed to enumerate DCs: $($_.Exception.Message)"
        exit 1
    }
}

# --- Service control via sc.exe (no WinRM required) ---
function Set-DFSR-Startup {
    param([string]$Computer,[ValidateSet("auto","demand")] [string]$Mode)
    WStep "[$Computer] Set DFSR StartupType -> $Mode"
    & sc.exe "\\$Computer" config dfsr start= $Mode | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "[$Computer] Failed to set DFSR startup type." }
}
function Stop-DFSR {
    param([string]$Computer)
    WStep "[$Computer] Stop DFSR"
    & sc.exe "\\$Computer" stop dfsr | Out-Null
    $deadline=(Get-Date).AddMinutes(2)
    do {
        Start-Sleep 2
        $q = sc.exe "\\$Computer" query dfsr 2>$null
        if (($q | Where-Object {$_ -match "STATE"}) -match "STOPPED"){ WOk "[$Computer] DFSR stopped"; return }
    } while((Get-Date) -lt $deadline)
    throw "[$Computer] Unable to confirm DFSR stopped."
}
function Start-DFSR {
    param([string]$Computer)
    WStep "[$Computer] Start DFSR"
    & sc.exe "\\$Computer" start dfsr | Out-Null
    $deadline=(Get-Date).AddMinutes(2)
    do {
        Start-Sleep 2
        $q = sc.exe "\\$Computer" query dfsr 2>$null
        if (($q | Where-Object {$_ -match "STATE"}) -match "RUNNING"){ WOk "[$Computer] DFSR running"; return }
    } while((Get-Date) -lt $deadline)
    throw "[$Computer] Unable to confirm DFSR running."
}

# --- Verified remote 'dfsrdiag pollad' ---
function Try-PollAD {
    param([string]$Computer)
    $poll = {
        dfsrdiag.exe pollad | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'dfsrdiag pollad failed.' }
    }
    if (($Computer -split '\.')[0] -ieq $env:COMPUTERNAME) { & $poll; return }
    Invoke-Command -ComputerName $Computer -ScriptBlock $poll -ErrorAction Stop | Out-Null
    WOk "[$Computer] dfsrdiag pollad executed"
}

function Wait-SysvolEvent {
    param([string]$Computer, [int]$EventId, [datetime]$Since, [int]$TimeoutSeconds = 900)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $eventErrors = @()
        $phaseEvents = @(Get-WinEvent -ComputerName $Computer -FilterHashtable @{
            LogName = 'DFS Replication'
            Id = $EventId
            StartTime = $Since
        } -ErrorAction SilentlyContinue -ErrorVariable eventErrors)
        if (@($eventErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' }).Count) {
            throw "Cannot verify DFSR events on $Computer."
        }
        if ($phaseEvents | Where-Object { $_.ToXml() -match 'SYSVOL' }) { return }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    throw "No new SYSVOL event $EventId on $Computer; stop at this phase."
}

# --- Resolve Computer DN and bind SYSVOL Subscription robustly ---
function Get-SysvolSubscriptionADSI {
    param([string]$ComputerNameOrFQDN)
    $cn = ($ComputerNameOrFQDN -split '\.')[0]
    $root = [ADSI]("LDAP://$primaryFQDN/RootDSE")
    $domainDN = $root.defaultNamingContext

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]("LDAP://$primaryFQDN/$domainDN")
    $searcher.Filter = "(&(objectClass=computer)(|(dNSHostName=$ComputerNameOrFQDN)(name=$cn)))"
    $searcher.PageSize = 1000
    $res = $searcher.FindOne()
    if (-not $res) { throw "Computer object not found for $ComputerNameOrFQDN" }
    $computerDN = $res.Properties["distinguishedname"][0]

    $dfsrLocal = "CN=DFSR-LocalSettings,$computerDN"
    $domainSysVol = "CN=Domain System Volume,$dfsrLocal"
    $sysvolSub = "CN=SYSVOL Subscription,$domainSysVol"

    $adsi = [ADSI]("LDAP://$primaryFQDN/$sysvolSub")
    # touch a property to validate bind
    $null = $adsi.Properties["msDFSR-Enabled"]
    return $adsi
}

# --- Gather DCs and fix PRIMARY selection/exclusion (short-name safe) ---
$allDCs = @(Get-AllDCNames)
$primaryShort = ($PrimaryDC -split '\.')[0]
$primaryFQDN  = $allDCs | Where-Object { ($_ -split '\.')[0] -ieq $primaryShort } | Select-Object -First 1

if (-not $primaryFQDN) {
    WErr "PrimaryDC '$PrimaryDC' not found among domain controllers."
    WErr "DCs discovered: $($allDCs -join ', ')"
    exit 1
}

# Exclude PRIMARY from others by comparing short names
$otherDCs = @($allDCs | Where-Object { ($_ -split '\.')[0] -ne ($primaryFQDN -split '\.')[0] })
$domainDN = [string]([ADSI]("LDAP://$primaryFQDN/RootDSE")).defaultNamingContext

WStep "PRIMARY DC     : $primaryFQDN"
WStep "OTHER DCs count: $($otherDCs.Count)"

if (-not $PSCmdlet.ShouldProcess(($allDCs -join ', '), "Reinitialize DFSR SYSVOL using $primaryFQDN as primary")) { return }

if (-not $SkipSafetyPrompt) {
    WWarn "This will perform an AUTHORITATIVE SYSVOL restore per Microsoft guidance."
    WWarn "PRIMARY: $primaryFQDN  |  OTHERS: $($otherDCs -join ', ')"
    $ans = Read-Host "Continue? (Y/N)"
    if ($ans -notin @('Y','y')) { WErr "Cancelled."; exit 1 }
}

try {
    # 1) Set StartupType=Manual + STOP DFSR on ALL DCs
    foreach ($dc in $allDCs) { Set-DFSR-Startup -Computer $dc -Mode demand }
    foreach ($dc in $allDCs) { Stop-DFSR -Computer $dc }

    $disableStarted = Get-Date
    # 2) PRIMARY: msDFSR-Enabled=FALSE, msDFSR-Options=1
    $adsiPrimary = Get-SysvolSubscriptionADSI -ComputerNameOrFQDN $primaryFQDN
    WStep "[PRIMARY] Set msDFSR-Enabled=FALSE"
    $adsiPrimary.Put("msDFSR-Enabled",$false); $adsiPrimary.SetInfo()
    WStep "[PRIMARY] Set msDFSR-Options=1 (Primary/Authoritative)"
    $adsiPrimary.Put("msDFSR-Options",1); $adsiPrimary.SetInfo()

    # 3) OTHERS: msDFSR-Enabled=FALSE
    foreach ($dc in $otherDCs) {
        $adsi = Get-SysvolSubscriptionADSI -ComputerNameOrFQDN $dc
        WStep "[$dc] Set msDFSR-Enabled=FALSE"
        $adsi.Put("msDFSR-Enabled",$false); $adsi.SetInfo()
    }

    # 4) Force AD replication throughout the domain
    WStep "Replicating SYSVOL configuration from $primaryFQDN..."
    & repadmin.exe /syncall $primaryFQDN $domainDN /deP
    if ($LASTEXITCODE -ne 0) { throw 'AD replication of disabled subscriptions failed.' }

    # 5) START DFSR on PRIMARY only (expect Event 4114)
    Start-DFSR -Computer $primaryFQDN
    Wait-SysvolEvent -Computer $primaryFQDN -EventId 4114 -Since $disableStarted

    # 6) PRIMARY: msDFSR-Enabled=TRUE
    $primaryEnableStarted = Get-Date
    WStep "[PRIMARY] Set msDFSR-Enabled=TRUE"
    $adsiPrimary.Put("msDFSR-Enabled",$true); $adsiPrimary.SetInfo()

    # 7) Force AD replication
    WStep "Replicating the primary subscription change..."
    & repadmin.exe /syncall $primaryFQDN $domainDN /deP
    if ($LASTEXITCODE -ne 0) { throw 'AD replication of the primary subscription failed.' }

    # 8) PRIMARY: dfsrdiag pollad (require Event 4602)
    WStep "[PRIMARY] dfsrdiag pollad"
    Try-PollAD -Computer $primaryFQDN
    Wait-SysvolEvent -Computer $primaryFQDN -EventId 4602 -Since $primaryEnableStarted

    # 9) START DFSR on OTHER DCs (expect Event 4114)
    foreach ($dc in $otherDCs) {
        Start-DFSR -Computer $dc
        Wait-SysvolEvent -Computer $dc -EventId 4114 -Since $disableStarted
    }

    # 10) OTHERS: msDFSR-Enabled=TRUE
    $othersEnableStarted = Get-Date
    foreach ($dc in $otherDCs) {
        $adsi = Get-SysvolSubscriptionADSI -ComputerNameOrFQDN $dc
        WStep "[$dc] Set msDFSR-Enabled=TRUE"
        $adsi.Put("msDFSR-Enabled",$true); $adsi.SetInfo()
    }

    & repadmin.exe /syncall $primaryFQDN $domainDN /deP
    if ($LASTEXITCODE -ne 0) { throw 'AD replication of the other subscriptions failed.' }

    # 11) OTHERS: dfsrdiag pollad
    foreach ($dc in $otherDCs) {
        WStep "[$dc] dfsrdiag pollad"
        Try-PollAD -Computer $dc
        Wait-SysvolEvent -Computer $dc -EventId 4604 -Since $othersEnableStarted
    }

    # 12) Restore StartupType=Automatic on ALL DCs
    foreach ($dc in $allDCs) { Set-DFSR-Startup -Computer $dc -Mode auto }

    WOk  "Authoritative sequence completed successfully."
    WStep "Events confirmed: 4602 on PRIMARY, 4604 on other members. Validate SYSVOL/NETLOGON shares, contents and backlog."
}
catch {
    WErr "Failure during authoritative sequence: $($_.Exception.Message)"
    WWarn "Preserve the current phase and subscription states. Do not restart all members or rerun blindly."
    exit 1
}
```

## Quick Verification Commands

```powershell
$sendingDc = 'dc01.corp.example'
$receivingDc = 'dc02.corp.example'

dfsrdiag.exe ReplicationState
dfsrdiag.exe backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:$sendingDc /rmem:$receivingDc
repadmin.exe /showrepl $receivingDc
net.exe share
```

## ⚠️ Recovery if the script crashes mid-run

The authoritative script sets the DFSR service `StartupType=Manual` on every DC at step 1 and restores `Automatic` only at step 12. A failed phase can leave services stopped or subscriptions disabled. **Do not start every DC or rerun the complete script automatically.** First record the last completed phase, each subscription's state and the new events on the chosen primary and other members.

```powershell
Get-Service DFSR | Select-Object Name, Status, StartType
Get-WinEvent -FilterHashtable @{
    LogName = 'DFS Replication'
    StartTime = (Get-Date).AddHours(-4)
} -MaxEvents 50 | Select-Object TimeCreated, Id, Message
```

Use the preflight query to inspect AD state as well. Correct the failure and resume the documented phase with the intended primary/member ordering. Restore Automatic startup only when the recovery sequence permits it. The scripts now stop when an event cannot be verified; their 15-minute event timeout is an operational stop condition, not proof that a large SYSVOL can never take longer to synchronize.

Remote execution requires access to service control, the DFS Replication event log and WinRM for `dfsrdiag pollad`. Validate those paths before changing subscriptions. If a required remote path is unavailable, use the Microsoft procedure locally on the affected DCs rather than bypassing the checks.

## 📚 References

- [Force authoritative and non-authoritative synchronization for DFSR-replicated SYSVOL](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization)
- [Migrate SYSVOL replication from FRS to DFSR (`dfsrmig`)](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/migrate-sysvol-replication-from-frs-to-dfsr)
- [DFSR event reference (4114 / 4602 / 4604)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc758302(v=ws.10))

