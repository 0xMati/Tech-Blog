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
    $sysvolSub = [ADSI]("LDAP://$sysvolSubDn")  # throws if missing
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
    Write-Warn "Could not confirm DFSR is stopped on $Computer (continuing)."
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
    Write-Warn "Could not confirm DFSR is running on $Computer (continuing)."
}
function Invoke-OnTarget {
    param([string]$Computer, [scriptblock]$ScriptBlock)
    if ($Computer -ieq $env:COMPUTERNAME) { & powershell.exe -NoProfile -Command $ScriptBlock; return $LASTEXITCODE }
    try { Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ErrorAction Stop | Out-Null; return 0 } catch { return 1 }
}

if (-not $SkipSafetyPrompt) {
    Write-Warn "This will perform a NON-AUTHORITATIVE SYSVOL restore on $ServerCN."
    $ans = Read-Host "Continue? (Y/N)"
    if ($ans -notin @('Y','y')) { Write-Err "Cancelled."; exit 1 }
}

try {
    Stop-DFSRService -Computer $ServerCN

    Write-Step "Setting msDFSR-Enabled = FALSE on $ServerCN..."
    $sysvolSub.Put("msDFSR-Enabled", $false)
    $sysvolSub.SetInfo()
    Write-Ok "msDFSR-Enabled = FALSE applied."

    Start-DFSRService -Computer $ServerCN

    Write-Step "Forcing 'dfsrdiag pollad' on $ServerCN..."
    $rc = Invoke-OnTarget -Computer $ServerCN -ScriptBlock { dfsrdiag.exe pollad }
    if ($rc -ne 0) { Write-Warn "Could not run 'dfsrdiag pollad' remotely. That's OK; DFSR will pick up shortly." }

    Start-Sleep -Seconds 5

    Write-Step "Re-enabling subscription (msDFSR-Enabled = TRUE) on $ServerCN..."
    $sysvolSub.Put("msDFSR-Enabled", $true)
    $sysvolSub.SetInfo()
    Write-Ok "msDFSR-Enabled = TRUE applied."

    Write-Step "Polling AD again on $ServerCN..."
    $rc = Invoke-OnTarget -Computer $ServerCN -ScriptBlock { dfsrdiag.exe pollad }
    if ($rc -ne 0) { Write-Warn "Second pollad could not run remotely." }

    Write-Ok "Non-authoritative restore completed on $ServerCN. Check DFSR log (IDs 4602/4604) and backlog."
}
catch {
    Write-Err "Failure: $($_.Exception.Message)"
    exit 1
}

Write-Step "Follow-ups:"
Write-Host "  dfsrdiag ReplicationState"
Write-Host "  dfsrdiag backlog /rgname:`"Domain System Volume`" /rfname:`"SYSVOL Share`" /smem:$ServerCN /partner:<OtherDC>"
Write-Host "  repadmin /syncall /AdeP"
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
  8) On PRIMARY:     dfsrdiag pollad (expect Event 4602/4604)
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
    WWarn "[$Computer] Unable to confirm DFSR stopped (continuing)."
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
    WWarn "[$Computer] Unable to confirm DFSR running (continuing)."
}

# --- Best-effort remote 'dfsrdiag pollad' (WinRM if available) ---
function Try-PollAD {
    param([string]$Computer)
    if ($Computer -ieq $env:COMPUTERNAME) { & dfsrdiag.exe pollad; return }
    try {
        Invoke-Command -ComputerName $Computer -ScriptBlock { dfsrdiag.exe pollad } -ErrorAction Stop | Out-Null
        WOk "[$Computer] dfsrdiag pollad executed"
    } catch {
        WWarn "[$Computer] Couldn't run 'dfsrdiag pollad' remotely (WinRM disabled?). Run it locally if needed."
    }
}

# --- Resolve Computer DN and bind SYSVOL Subscription robustly ---
function Get-SysvolSubscriptionADSI {
    param([string]$ComputerNameOrFQDN)
    $cn = ($ComputerNameOrFQDN -split '\.')[0]
    $root = [ADSI]"LDAP://RootDSE"
    $domainDN = $root.defaultNamingContext

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = [ADSI]("LDAP://$domainDN")
    $searcher.Filter = "(&(objectClass=computer)(|(dNSHostName=$ComputerNameOrFQDN)(name=$cn)))"
    $searcher.PageSize = 1000
    $res = $searcher.FindOne()
    if (-not $res) { throw "Computer object not found for $ComputerNameOrFQDN" }
    $computerDN = $res.Properties["distinguishedname"][0]

    $dfsrLocal = "CN=DFSR-LocalSettings,$computerDN"
    $domainSysVol = "CN=Domain System Volume,$dfsrLocal"
    $sysvolSub = "CN=SYSVOL Subscription,$domainSysVol"

    $adsi = [ADSI]("LDAP://$sysvolSub")
    # touch a property to validate bind
    $null = $adsi.Properties["msDFSR-Enabled"]
    return $adsi
}

# --- Gather DCs and fix PRIMARY selection/exclusion (short-name safe) ---
$allDCs = Get-AllDCNames   # ex: ["MM-DC1.domain.com","MM-DC2.domain.com","MM-DC3.domain.com"]
$primaryShort = ($PrimaryDC -split '\.')[0]
$primaryFQDN  = $allDCs | Where-Object { ($_ -split '\.')[0] -ieq $primaryShort } | Select-Object -First 1

if (-not $primaryFQDN) {
    WErr "PrimaryDC '$PrimaryDC' not found among domain controllers."
    WErr "DCs discovered: $($allDCs -join ', ')"
    exit 1
}

# Exclude PRIMARY from others by comparing short names
$otherDCs = $allDCs | Where-Object { ($_ -split '\.')[0] -ne ($primaryFQDN -split '\.')[0] }

WStep "PRIMARY DC     : $primaryFQDN"
WStep "OTHER DCs count: $($otherDCs.Count)"

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
    WStep "Forcing AD replication (repadmin /syncall /AdeP)…"
    & repadmin.exe /syncall /AdeP | Out-Null

    # 5) START DFSR on PRIMARY only (expect Event 4114)
    Start-DFSR -Computer $primaryFQDN
    WWarn "[PRIMARY] Expect Event 4114 in 'DFS Replication' log."

    # 6) PRIMARY: msDFSR-Enabled=TRUE
    WStep "[PRIMARY] Set msDFSR-Enabled=TRUE"
    $adsiPrimary.Put("msDFSR-Enabled",$true); $adsiPrimary.SetInfo()

    # 7) Force AD replication
    WStep "Forcing AD replication again…"
    & repadmin.exe /syncall /AdeP | Out-Null

    # 8) PRIMARY: dfsrdiag pollad (expect Event 4602/4604)
    WStep "[PRIMARY] dfsrdiag pollad"
    Try-PollAD -Computer $primaryFQDN
    WWarn "[PRIMARY] Expect Event 4602/4604 (initialization) in 'DFS Replication' log."

    # 9) START DFSR on OTHER DCs (expect Event 4114)
    foreach ($dc in $otherDCs) { Start-DFSR -Computer $dc }
    WWarn "[OTHERS] Expect Event 4114 after service start."

    # 10) OTHERS: msDFSR-Enabled=TRUE
    foreach ($dc in $otherDCs) {
        $adsi = Get-SysvolSubscriptionADSI -ComputerNameOrFQDN $dc
        WStep "[$dc] Set msDFSR-Enabled=TRUE"
        $adsi.Put("msDFSR-Enabled",$true); $adsi.SetInfo()
    }

    # 11) OTHERS: dfsrdiag pollad
    foreach ($dc in $otherDCs) {
        WStep "[$dc] dfsrdiag pollad"
        Try-PollAD -Computer $dc
    }

    # 12) Restore StartupType=Automatic on ALL DCs
    foreach ($dc in $allDCs) { Set-DFSR-Startup -Computer $dc -Mode auto }

    WOk  "Authoritative sequence completed successfully."
    WStep "Verify: Event 4602/4604 on PRIMARY then on others; SYSVOL/NETLOGON shares present; dfsrdiag backlog ~ 0."
}
catch {
    WErr "Failure during authoritative sequence: $($_.Exception.Message)"
    WWarn "Check AD/DFSR health, event logs, and retry if needed."
    exit 1
}
```

## Quick Verification Commands

```powershell
# Check DFSR state
dfsrdiag ReplicationState

# Check backlog (example) — run from a DC, comparing with another DC as partner
dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:$env:COMPUTERNAME /partner:<OtherDC>

# Force AD replication
#   /A = sync all naming contexts
#   /d = display DSA (server) names instead of GUIDs
#   /e = cross-site (enterprise-wide)
#   /P = push changes outward from this DC
repadmin /syncall /AdeP

# Verify SYSVOL and NETLOGON shares are advertised again
net share
```

## ⚠️ Recovery if the script crashes mid-run

The authoritative script sets the DFSR service `StartupType=Manual` on every DC at step 1 and restores `Automatic` only at step 12. If the script aborts in between (network glitch, AD bind error, Ctrl+C…), DFSR will **not auto-start at next reboot** on the affected DCs. Re-enable it manually:

```powershell
# Run on each DC that did not reach step 12
sc.exe config dfsr start= auto
sc.exe start dfsr
```

Then verify with `dfsrdiag ReplicationState` and `net share` that SYSVOL/NETLOGON are advertised again before declaring the incident closed.

## 📚 References

- [Force authoritative and non-authoritative synchronization for DFSR-replicated SYSVOL](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/force-authoritative-non-authoritative-synchronization)
- [Migrate SYSVOL replication from FRS to DFSR (`dfsrmig`)](https://learn.microsoft.com/troubleshoot/windows-server/group-policy/migrate-sysvol-replication-from-frs-to-dfsr)
- [DFSR event reference (4114 / 4602 / 4604)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc758302(v=ws.10))

