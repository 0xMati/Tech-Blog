# Audit and Enforcement for LDAP Signing
🗓️ Published: 2025-12-03

## Introduction

This note covers a safe, two-step rollout to **LDAP Signing** in Active Directory. When LDAP messages aren’t signed, a man-in-the-middle can alter or forge traffic; requiring signing blocks those tampering paths. We’ll first audit and fix clients, then enforce.

## Phase 1 — Server-side posture check (DC settings for LDAP Signing)

The snippet below audits **LDAP Signing** on your Domain Controllers by reading the server policy backing value:
`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`
- `2 = Require` (**target**)
- `1 = None/Negotiate` (not enforced)
- `0 = None` (legacy / not recommended)

It shows a colored table and a per-DC summary. CSV export is present but commented out.

> PowerShell 5.1 • No parameters • DC list embedded

```powershell
<#
Audit LDAP Signing (server-side) on Domain Controllers
- PowerShell 5.1
- Embedded DC list (no parameters)
- Read-only via WinRM
- Colors + per-DC summary
- CSV export block commented (optional)

DC security option (GPO UI):
  Domain controller: LDAP server signing requirements
Registry mapping:
  HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity (DWORD)
    0=None, 1=Negotiate (None/Not defined in GPO UI), 2=Require
#>

cls

# --- Embedded DC list (edit if needed) ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Remote probe: read LDAPServerIntegrity ---
$remoteScript = {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
  $name = 'LDAPServerIntegrity'
  $raw  = $null
  if (Test-Path $path) {
    try { $raw = (Get-ItemProperty -Path $path -ErrorAction Stop).$name } catch { $raw = $null }
  }

  # Derive Effective string
  $effective = switch ($raw) {
    2 { 'Require' }
    1 { 'Negotiate' }
    0 { 'None' }
    $null { 'NotConfigured' }
    default { "Unknown($raw)" }
  }

  # Compliance scoring
  $status = switch ($effective) {
    'Require'        { 'Compliant' }
    'Negotiate'      { 'Warning'   }
    'None'           { 'Failed'    }
    'NotConfigured'  { 'Failed'    }
    default          { 'Warning'   }
  }

  [pscustomobject]@{
    Computer   = $env:COMPUTERNAME
    Effective  = $effective
    Raw        = $(if($raw -ne $null){[string]$raw}else{'(absent)'})
    Status     = $status
    RegPath    = $path
    RegValue   = $name
  }
}

# --- Collect ---
$rows = @()
foreach ($dc in $dcs) {
  try {
    $rows += Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ErrorAction Stop
  } catch {
    $rows += [pscustomobject]@{
      Computer  = $dc
      Effective = 'Unreachable/AccessDenied'
      Raw       = '(n/a)'
      Status    = 'Failed'
      RegPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
      RegValue  = 'LDAPServerIntegrity'
    }
  }
}

# --- Pretty colored table ---
Write-Host ""
Write-Host "=== LDAP Signing (server) audit ===" -ForegroundColor Cyan
$header = "{0,-18} {1,-13} {2,-8} {3,-10} {4}" -f 'Computer','Effective','Raw','Status','RegistryPath\Value'
Write-Host $header -ForegroundColor Gray
Write-Host ('-' * ($header.Length + 20)) -ForegroundColor DarkGray

foreach ($r in ($rows | Sort-Object Computer)) {
  $color = if ($r.Status -eq 'Compliant') { 'Green' } elseif ($r.Status -eq 'Failed') { 'Red' } else { 'Yellow' }
  $line  = "{0,-18} {1,-13} {2,-8} {3,-10} {4}\{5}" -f $r.Computer,$r.Effective,$r.Raw,$r.Status,$r.RegPath,$r.RegValue
  Write-Host $line -ForegroundColor $color
}

# --- Summary per DC ---
Write-Host ""
Write-Host "=== Summary per DC ===" -ForegroundColor Cyan
$summary = $rows | Group-Object Computer | ForEach-Object {
  $c   = $_.Name
  $sts = @($_.Group | ForEach-Object { $_.Status })
  [pscustomobject]@{
    Computer  = $c
    Compliant = (@($sts | Where-Object { $_ -eq 'Compliant' })).Count
    Warning   = (@($sts | Where-Object { $_ -eq 'Warning'   })).Count
    Failed    = (@($sts | Where-Object { $_ -eq 'Failed'    })).Count
  }
}
$summary | Sort-Object Computer | Format-Table -AutoSize

# --- Optional CSV export (commented) ---
<#
$ts = (Get-Date -Format 'yyyyMMdd_HHmmss')
$out = Join-Path $PWD ("LDAPSigning_Server_Audit_{0}.csv" -f $ts)
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $out
Write-Host ("CSV export -> {0}" -f $out) -ForegroundColor Cyan
#>
```

### Increase Logs verbosity to track LDAP Signing Events

- Increase Logs verbosity
  - Enable LDAP interface diagnostics to see these consistently:
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics → “16 LDAP Interface Events” = 5 (REG_DWORD).

**You can check LDAP Diagnostics Logs settings and RegKey value on DC with this script:**
```powershell
<#
Check "16 LDAP Interface Events" = 5 on Domain Controllers
- PowerShell 5.1
- Embedded DC list (no parameters)
- Read-only via WinRM
- Colored output + per-DC summary

Registry:
HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics
  "16 LDAP Interface Events" (REG_DWORD)
Target value: 5
#>

cls

# --- Embedded DC list ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Remote probe (runs on each DC) ---
$remoteScript = {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
  $name = '16 LDAP Interface Events'

  $raw  = $null
  if (Test-Path $path) {
    try { $raw = (Get-ItemProperty -Path $path -ErrorAction Stop)."$name" } catch { $raw = $null }
  }

  # Derive status
  $effective = if ($raw -ne $null) { [string]$raw } else { '(absent)' }
  $status =
    if ($raw -eq 5) { 'Compliant' }
    elseif ($raw -eq $null) { 'Failed' }
    else { 'Warning' }  # present but not 5

  [pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Path     = $path
    Name     = $name
    Raw      = $effective
    Status   = $status
  }
}

# --- Collect ---
$rows = @()
foreach ($dc in $dcs) {
  try {
    $rows += Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ErrorAction Stop
  } catch {
    $rows += [pscustomobject]@{
      Computer = $dc
      Path     = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
      Name     = '16 LDAP Interface Events'
      Raw      = '(unreachable)'
      Status   = 'Failed'
    }
  }
}

# --- Pretty colored table ---
Write-Host ""
Write-Host '=== LDAP Interface Events level (target = 5) ===' -ForegroundColor Cyan
$header = "{0,-18} {1,-8} {2,-10} {3}" -f 'Computer','Raw','Status','RegistryPath\Name'
Write-Host $header -ForegroundColor Gray
Write-Host ('-' * ($header.Length + 20)) -ForegroundColor DarkGray

foreach ($r in ($rows | Sort-Object Computer)) {
  $color = if ($r.Status -eq 'Compliant') { 'Green' } elseif ($r.Status -eq 'Failed') { 'Red' } else { 'Yellow' }
  $line  = "{0,-18} {1,-8} {2,-10} {3}\{4}" -f $r.Computer, $r.Raw, $r.Status, $r.Path, $r.Name
  Write-Host $line -ForegroundColor $color
}

# --- Summary per DC ---
Write-Host ""
Write-Host "=== Summary per DC ===" -ForegroundColor Cyan
$summary = $rows | Group-Object Computer | ForEach-Object {
  $c   = $_.Name
  $sts = @($_.Group | ForEach-Object { $_.Status })
  [pscustomobject]@{
    Computer  = $c
    Compliant = (@($sts | Where-Object { $_ -eq 'Compliant' })).Count
    Warning   = (@($sts | Where-Object { $_ -eq 'Warning'   })).Count
    Failed    = (@($sts | Where-Object { $_ -eq 'Failed'    })).Count
  }
}
$summary | Sort-Object Computer | Format-Table -AutoSize
```

**If you need to change LDAP Diagnostics Logs settings and RegKey '16 LDAP Interface Events' value to '5' on DC, use this script:**
```powershell
<#
Set "16 LDAP Interface Events" = 5 on Domain Controllers
- PowerShell 5.1
- Embedded DC list (no parameters)
- Creates the Diagnostics key if missing
- Colored output + before/after + summary
#>

cls

# --- Embedded DC list ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Target registry ---
$Path    = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
$Name    = '16 LDAP Interface Events'
$Desired = 5   # REG_DWORD

# --- Remote setter (runs on each DC) ---
$remoteScript = {
  param([string]$Path,[string]$Name,[int]$Desired)

  function Get-RegValue {
    param([string]$P,[string]$N)
    if (Test-Path -Path $P) {
      try { (Get-ItemProperty -Path $P -ErrorAction Stop).$N } catch { $null }
    } else { $null }
  }

  $before = Get-RegValue -P $Path -N $Name

  # Ensure key exists
  try { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null } catch {}

  # Set value
  $setOK = $true
  try {
    if ($before -ne $Desired) {
      New-ItemProperty -Path $Path -Name $Name -Value $Desired -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    } else {
      # already desired: still enforce to be safe
      New-ItemProperty -Path $Path -Name $Name -Value $Desired -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    }
  } catch {
    $setOK = $false
    $errMsg = $_.Exception.Message
  }

  $after = Get-RegValue -P $Path -N $Name

  $status = if ($setOK -and ($after -eq $Desired)) { 'Success' } else { 'Failed' }
  $note   = if ($status -eq 'Failed') { $errMsg } else { '' }

  [pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Path     = $Path
    Name     = $Name
    Before   = $(if($before -ne $null){[string]$before}else{'(absent)'})
    After    = $(if($after  -ne $null){[string]$after }else{'(absent)'})
    Desired  = [string]$Desired
    Status   = $status
    Note     = $note
  }
}

# --- Execute on all DCs ---
$results = @()
foreach ($dc in $dcs) {
  try {
    $results += Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ArgumentList $Path,$Name,$Desired -ErrorAction Stop
  } catch {
    $results += [pscustomobject]@{
      Computer = $dc
      Path     = $Path
      Name     = $Name
      Before   = '(n/a)'
      After    = '(n/a)'
      Desired  = [string]$Desired
      Status   = 'Failed'
      Note     = "Unreachable/AccessDenied: $($_.Exception.Message)"
    }
  }
}

# --- Pretty colored output ---
Write-Host ""
Write-Host '=== Set "16 LDAP Interface Events" to 5 ===' -ForegroundColor Cyan
$header = "{0,-18} {1,-10} {2,-10} {3,-8} {4}" -f 'Computer','Before','After','Status','RegistryPath\Name'
Write-Host $header -ForegroundColor Gray
Write-Host ('-' * ($header.Length + 20)) -ForegroundColor DarkGray

foreach ($r in ($results | Sort-Object Computer)) {
  $color = if ($r.Status -eq 'Success') { 'Green' } else { 'Red' }
  $line  = "{0,-18} {1,-10} {2,-10} {3,-8} {4}\{5}" -f $r.Computer,$r.Before,$r.After,$r.Status,$r.Path,$r.Name
  Write-Host $line -ForegroundColor $color
  if ($r.Note) { Write-Host ("  -> " + $r.Note) -ForegroundColor DarkYellow }
}

# --- Summary ---
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$ok = (@($results | Where-Object { $_.Status -eq 'Success' })).Count
$ko = (@($results | Where-Object { $_.Status -ne 'Success' })).Count
[pscustomobject]@{ Success=$ok; Failed=$ko } | Format-Table -AutoSize
```

---

## Phase 2 — LDAP-Signing Events Monitor

This monitor maps who still performs **unsigned LDAP binds** and who still uses **simple bind** (with or without TLS) before you enforce *Require*.

### What it collects (Directory Service on DCs)
- **2886** — DC is **not** requiring signing (advisory).
- **2887** — Count of **unsigned / simple** binds (summary).
- **2888** — **Details** for **unsigned** binds (who/where).
- **2889** — **Details** for **simple** binds (who/where).

> Why include simple bind?  
> When you switch DCs to **Require**, **unsigned SASL** and **simple bind in clear (389, no TLS)** are **blocked**.  
> **Simple bind over LDAPS (636)** continues to work, but you should prefer **SASL-signed** where possible.

### How to check results
2. Inspect 2887 (volume), 2888/2889 (sources: hosts/accounts).
3. Fix apps: move to **SASL-signed** or **LDAPS (636)** with valid DC certs (ideally with **CBT**).
4. Re-run until unsigned/simple noise disappears → then enforce **Require**.

### PS Script to Track LDAP Signing Events on DC

```powershell
<#
LDAP Signing — Events Monitor (Directory Service 2886–2889)
- PowerShell 5.1
- No parameters: embedded DC list + configurable lookback
- Colors + per-DC and per-Event summaries
- CSV export block commented (optional)

Log/Provider:
  Log:      "Applications and Services Logs\Directory Service"
  Provider: Microsoft-Windows-ActiveDirectory_DomainService

Event IDs (cheat sheet):
  2886 = DC does NOT require signing (advisory/reminder)
  2887 = Count of unsigned/simple binds (summary)
  2888 = Details about unsigned binds (who/where)
  2889 = Details about simple binds (who/where)

Tip: Increase verbosity if needed on each DC
  HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics
  "16 LDAP Interface Events" (REG_DWORD) = 2..5
#>

cls

# --- Configuration (edit here) ---
$LookbackHours   = 168     # last 7 days
$ShowTopSections = $false  # set $true to print "Top Clients / Top Accounts"
$TopN            = 10
$OutDir          = Join-Path $PWD ("LDAPSigning_Monitor_{0:yyyyMMdd_HHmmss}" -f (Get-Date))

# --- Embedded DC list ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Event IDs of interest ---
$EventIds = 2886,2887,2888,2889

# --- Remote query payload (runs on each DC) ---
$remoteScript = {
  param([int]$Hours,[int[]]$Ids)

  $start = (Get-Date).AddHours(-1 * $Hours)
  $fh = @{
    ProviderName = 'Microsoft-Windows-ActiveDirectory_DomainService'
    Id           = $Ids
    StartTime    = $start
    LogName      = 'Directory Service'
  }

  function Parse-Event {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)

    $msg = $null
    try { $msg = $ev.FormatDescription() } catch { $msg = $null }

    # Try to extract hints (best-effort: event templates differ by build)
    $clientIp = $null
    $account  = $null
    if ($msg) {
      $ipMatch = [regex]::Match($msg, '(?<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)')
      if ($ipMatch.Success) { $clientIp = $ipMatch.Groups['ip'].Value }

      $upnMatch = [regex]::Match($msg, '(?<upn>[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})')
      if ($upnMatch.Success) { $account = $upnMatch.Groups['upn'].Value }
      if (-not $account) {
        $samMatch = [regex]::Match($msg, '(?<sam>\b[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+\b)')
        if ($samMatch.Success) { $account = $samMatch.Groups['sam'].Value }
      }
    }

    [pscustomobject]@{
      DC          = $env:COMPUTERNAME
      TimeCreated = $ev.TimeCreated
      EventId     = $ev.Id
      Level       = $ev.LevelDisplayName
      ClientIP    = $(if($clientIp){$clientIp}else{'(n/a)'})
      Account     = $(if($account){$account}else{'(n/a)'})
      Message     = $(if($msg){$msg}else{'(message unavailable)'})
    }
  }

  $out = New-Object System.Collections.Generic.List[object]

  # Quiet read; zero events is NOT an error
  $events = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue
  if ($events) {
    foreach ($e in $events) { $out.Add( (Parse-Event -ev $e) ) | Out-Null }
  }

  $out
}

# --- Collect from all DCs ---
$all = @()
foreach ($dc in $dcs) {
  try {
    $all += Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ArgumentList $LookbackHours, $EventIds -ErrorAction Stop
  } catch {
    $all += [pscustomobject]@{
      DC          = $dc
      TimeCreated = Get-Date
      EventId     = '(n/a)'
      Level       = 'Error'
      ClientIP    = '(n/a)'
      Account     = '(n/a)'
      Message     = "Unreachable/AccessDenied: $($_.Exception.Message)"
    }
  }
}

# --- Color map by EventId ---
function Get-Color {
  param([string]$id)
  switch ($id) {
    '2886' { return 'Yellow' }  # advisory
    '2887' { return 'Yellow' }  # unsigned/simple count
    '2888' { return 'Red' }     # unsigned details
    '2889' { return 'Red' }     # simple details
    default { return 'Magenta' }
  }
}

# --- Main table (colored rows) ---
Write-Host ""
Write-Host ("=== LDAP Signing Events (last {0} hours) ===" -f $LookbackHours) -ForegroundColor Cyan
$header = "{0,-16} {1,-19} {2,-6} {3,-10} {4,-15} {5,-28} {6}" -f 'DC','TimeCreated','ID','Level','ClientIP','Account','Message (truncated)'
Write-Host $header -ForegroundColor Gray
Write-Host ('-' * ($header.Length + 30)) -ForegroundColor DarkGray

$anyRows = $false
foreach ($row in ($all | Sort-Object TimeCreated)) {
  $anyRows = $true
  $color   = Get-Color -id ($row.EventId.ToString())
  $msg     = $row.Message
  if ($msg -and $msg.Length -gt 120) { $msg = $msg.Substring(0,120) + '...' }
  $line = "{0,-16} {1,-19:yyyy-MM-dd HH:mm:ss} {2,-6} {3,-10} {4,-15} {5,-28} {6}" -f `
          $row.DC, $row.TimeCreated, $row.EventId, $row.Level, $row.ClientIP, $row.Account, $msg
  Write-Host $line -ForegroundColor $color
}
if (-not $anyRows) {
  Write-Host "(no LDAP-signing events found in the selected window)" -ForegroundColor DarkGray
}

# --- Optional Top sections ---
if ($ShowTopSections -and $all.Count -gt 0) {
  Write-Host ""
  Write-Host ("=== Top Clients (by ClientIP) — Top {0} ===" -f $TopN) -ForegroundColor Cyan
  $topIp = $all |
    Where-Object { $_.EventId -in $EventIds } |
    Group-Object ClientIP |
    ForEach-Object { [pscustomobject]@{ ClientIP=$_.Name; Count=$_.Count } } |
    Sort-Object Count -Descending |
    Select-Object -First $TopN
  if ($topIp) { $topIp | Format-Table -AutoSize } else { Write-Host "(none)" -ForegroundColor DarkGray }

  Write-Host ""
  Write-Host ("=== Top Accounts — Top {0} ===" -f $TopN) -ForegroundColor Cyan
  $topAcct = $all |
    Where-Object { $_.EventId -in $EventIds } |
    Group-Object Account |
    ForEach-Object { [pscustomobject]@{ Account=$_.Name; Count=$_.Count } } |
    Sort-Object Count -Descending |
    Select-Object -First $TopN
  if ($topAcct) { $topAcct | Format-Table -AutoSize } else { Write-Host "(none)" -ForegroundColor DarkGray }
}

# --- Summaries ---
Write-Host ""
Write-Host "=== Summary by DC ===" -ForegroundColor Cyan
$byDc = $all | Where-Object { $_.EventId -in $EventIds } | Group-Object DC | ForEach-Object {
  $name = $_.Name
  $s2886 = (@($_.Group | Where-Object {$_.EventId -eq 2886})).Count
  $s2887 = (@($_.Group | Where-Object {$_.EventId -eq 2887})).Count
  $s2888 = (@($_.Group | Where-Object {$_.EventId -eq 2888})).Count
  $s2889 = (@($_.Group | Where-Object {$_.EventId -eq 2889})).Count
  [pscustomobject]@{
    DC     = $name
    E2886  = $s2886
    E2887  = $s2887
    E2888  = $s2888
    E2889  = $s2889
    Total  = $s2886 + $s2887 + $s2888 + $s2889
  }
}
if ($byDc) { $byDc | Sort-Object DC | Format-Table -AutoSize } else { Write-Host "(no data)" -ForegroundColor DarkGray }

Write-Host ""
Write-Host "=== Summary by EventId ===" -ForegroundColor Cyan
$byId = $all | Where-Object { $_.EventId -in $EventIds } | Group-Object EventId | ForEach-Object {
  [pscustomobject]@{ EventId = $_.Name; Count = $_.Count }
}
if ($byId) { $byId | Sort-Object EventId | Format-Table -AutoSize } else { Write-Host "(no data)" -ForegroundColor DarkGray }

# --- Optional CSV exports (COMMENTED) ---
<#
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$all  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'LDAPSigning_Events_Detail.csv')
if ($byDc) { $byDc | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'LDAPSigning_Events_SummaryByDC.csv') }
if ($byId) { $byId | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'LDAPSigning_Events_SummaryByEventId.csv') }
Write-Host ("CSV exports -> {0}" -f $OutDir) -ForegroundColor Cyan
#>

Write-Host ""
Write-Host "Legend: 2886=DC not requiring signing; 2887=unsigned/simple count; 2888=unsigned details; 2889=simple details" -ForegroundColor Gray
```

## Phase 3 — Enforcement (Require)

Once unsigned/simple bind sources are remediated or acceptably exceptioned, enforce **LDAP Signing** on DCs.

### Target settings (GPO)
- **Domain Controllers (server side)**
  - Path: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
  - Setting: **Domain controller: LDAP server signing requirements** → **Require**
- **Domain Members / App hosts (client side, recommended)**
  - Path: `Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options`
  - Setting: **Domain member: LDAP client signing requirements** → **Require**

> Registry mapping (reference):
> - Server: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity`  
>   `2 = Require`, `1 = None/Negotiate`, `0 = None`
> - Client: `HKLM\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity`  
>   `2 = Require`, `1 = Negotiate`, `0 = None`

### Rollout plan

1. **Scope**: link the server-side GPO to the **Domain Controllers OU** only.  
2. **Change window**: plan a maintenance window; applying *Require* can block legacy clients.
3. **Order**
   - Keep your **audit monitor** running (Events 2886–2889).
   - Enforce **client-side “Require”** on key member servers first (where feasible).
   - Enforce **server-side “Require”** on a **pilot DC** (site with limited blast radius).
   - Validate, then roll to all DCs (site by site).
4. **Communication**: notify app owners that **unsigned SASL** and **simple bind in clear (389)** will be rejected.

### What breaks / what keeps working
- **Blocked**: SASL **unsigned** binds (389), **simple bind** in clear (389 without TLS).
- **Still works**: **SASL-signed** binds (Negotiate/Kerberos) and **simple bind over LDAPS (636)**.  

### Validation
- **Directory Service** log on DCs:
  - Expect **2886** to disappear after GPO refresh (DC now requires signing).
  - Residual **2888/2889** should drop to zero; any new entries indicate clients to fix.

### Backout (if needed)
- Revert DC policy to **None/Not defined** (or set `LDAPServerIntegrity = 1`) on the DC OU, force GPUpdate.  
  Keep the monitor running to re-assess unsigned/simple volumes before a new attempt.




