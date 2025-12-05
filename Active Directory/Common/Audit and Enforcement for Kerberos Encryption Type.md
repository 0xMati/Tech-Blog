# Audit and Enforcement for Kerberos Encryption Type
🗓️ Published: 2025-12-03

**Understand and manage change in cve-2022-37966**
https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d

## Kerberos encryption — what changed and why (KB5021131, CVE-2022-37966)

### Understand Ticket vs. Session key (two different things)
- **Kerberos ticket** (TGT or service ticket): issued by the KDC (domain controller) and **encrypted with the long-term key** of the recipient  
  - TGT → encrypted with the **krbtgt** account key  
  - Service ticket → encrypted with the **service/machine** account key  
  - The Security events **4768/4769** expose the **ticket encryption type** (e.g., AES256, AES128, RC4).
- **Session key**: a **temporary symmetric key** *inside* the ticket, shared between client and service, used to protect the live Kerberos exchanges (AP-REQ/AP-REP, etc.).

> If an account only has RC4 available, you typically end up with **RC4 tickets** and **RC4 session keys**.  
> If the account has AES and the KDC prefers it, you get **AES tickets** and **AES session keys**.

---

### What KB5021131 changed
Microsoft hardened Kerberos so that environments naturally move away from RC4:
- The KDC **prefers AES** for **session keys** when an account doesn’t explicitly define supported types.
- The new KDC default switch (`DefaultDomainSupportedEncTypes`) lets you **lock** the domain default to **AES-only**, closing the “RC4-by-omission” gap.
- Together, these changes make it easier to converge to **AES-only** for both **ticket encryption** and **session keys**.

---

### `msDS-SupportedEncryptionTypes` (per-account)
This AD attribute tells the KDC which ciphers an individual **account** (user, service, or machine) supports.
- Common values:
  - **24** (`0x18`) = **AES128 + AES256** (target)
  - **4** (`0x`) = **RC4_HMAC_MD5** (Legacy)
  - **0** or **absent** = historically ambiguous (often allowed RC4 in practice), but with patch AES by default
- **Important**: after changing the attribute from RC4 to allow AES, you must **refresh the secret** so the KDC can mint AES keys for that account:
  - User/service: change the **password** (and update the app)
  - Machine (`$`): **reset machine password** (e.g., `Reset-ComputerMachinePassword` / `netdom resetpwd`)
  - gMSA: rotates **automatically**

---

### `DefaultDomainSupportedEncTypes` (domain-wide KDC baseline)
This is a **KDC registry setting** that defines the default **encryption types** the KDC assumes for **accounts that do not have** `msDS-SupportedEncryptionTypes` set.  
- With the patch, by default it will use AES
- you can use it to **force AES-only defaults** (e.g., `0x18`) after being sure that RC4 is not used anymore, so “unset” accounts don’t silently fall back to RC4.

---

### Why all of this matters
- **RC4-HMAC** is weaker and enables downgrade/legacy paths.  
- **AES128/256** is the modern baseline. Moving to AES reduces your attack surface and aligns with current security guidance.
 
---

## Why SPN-bearing accounts matter most
- An **SPN (Service Principal Name)** marks a service identity (e.g., `HTTP/`, `MSSQLSvc/`, `CIFS/`, `LDAP/`, `HOST/`).  
- When a client accesses a service, the KDC issues a **service ticket** (event **4769**) **encrypted with the long-term key of the SPN account**.  
- If that SPN account is **RC4-only** (e.g., `msDS-SupportedEncryptionTypes = 0x4` or never rotated since AES), the ticket will be **RC4**, regardless of modern defaults.  
- Regular user accounts **without SPNs** don’t receive service tickets and don’t drive your 4769 RC4 volume.

**Action:** prioritize **accounts with SPNs** (service accounts, machine accounts `…$`, prefer **gMSA**):
1. Set **`msDS-SupportedEncryptionTypes = 24`** (AES128+AES256).  
2. **Refresh the secret** (password change / machine password reset; gMSA rotates automatically).  
3. Re-test apps and confirm **4769** shows **0x12/0x11** (AES256/AES128) and **no 0x17 (RC4)**.

---

### How to get to AES-only (practical path)
1. **Fix accounts**: set `msDS-SupportedEncryptionTypes = 24` (AES128+AES256) and **refresh their secret** (password/machine reset; gMSA rotates by itself).  
2. **Harden clients**: GPO **Network security: Configure encryption types allowed for Kerberos** → **allow only AES128/AES256**.  
3. **Lock the default** (optional, recommended): set KDC `DefaultDomainSupportedEncTypes = 0x18` (AES-only) so undefined accounts don’t drift to RC4.  
4. **Validate**: watch Security **4768/4769** → expect **0x12/0x11 (AES256/AES128)** and eliminate **0x17 (RC4)**; your RC4 share should trend to **0%**.

> Tip: A rise in AES in 4768/4769 confirms **ticket** encryption is now AES; because the same capability drives the **session key** choice, you’re also eliminating RC4 from the live session crypto.


## Check KDC default 

Here we verify the domain-wide KDC default used when an account has no msDS-SupportedEncryptionTypes.
The script reads DefaultDomainSupportedEncTypes on each DC, decodes AES128/256/RC4/DES bits, and flags anything that isn’t AES-only.

```powershell
<#
KDC default (DefaultDomainSupportedEncTypes) — audit on DCs
- PowerShell 5.1
- No parameters: embedded DC list below
- Reads the registry on each DC, decodes bits, assigns a clear status and prints colored output

Meaning:
  DefaultDomainSupportedEncTypes (DWORD bitmask under HKLM\SYSTEM\CurrentControlSet\Services\Kdc)
    0x10 = AES256
    0x08 = AES128
    0x04 = RC4-HMAC
    0x01 = DES (obsolete)

Status logic:
  - Compliant (AES-only default)
      key present AND AES128+AES256 set (0x18) AND RC4/DES NOT set
  - Warning (AES default, not enforced)
      key ABSENT  -> post-KB5021131 KDC typically prefers AES by default, but not locked
  - Warning (Mixed or RC4 allowed)
      key present but RC4 bit set OR AES bits not both present
  - Failed
      DC unreachable / error

Color map:
  - Green    = Compliant (AES-only default)
  - Yellow   = Warning (AES default, not enforced)
  - DarkYellow = Warning (Mixed or RC4 allowed)
  - Red      = Failed
#>

cls

# --- Embedded DC list ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Remote payload executed on each DC ---
$remote = {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
  $name = 'DefaultDomainSupportedEncTypes'
  $raw  = $null
  if (Test-Path $path) {
    try { $raw = (Get-ItemProperty -Path $path -ErrorAction Stop).$name } catch { $raw = $null }
  }

  function Decode($v){
    if ($v -eq $null) { return '(absent)' }
    $flags = @()
    if (($v -band 0x10) -ne 0) { $flags += 'AES256' }
    if (($v -band 0x08) -ne 0) { $flags += 'AES128' }
    if (($v -band 0x04) -ne 0) { $flags += 'RC4' }
    if (($v -band 0x01) -ne 0) { $flags += 'DES' }
    if ($flags.Count -eq 0) { return ("0x{0:X} (no known bits)" -f $v) }
    return ("0x{0:X} [{1}]" -f $v, ($flags -join ',')) 
  }

  function Get-Status($v){
    if ($null -eq $v) { return 'Warning (AES default, not enforced)' }  # default prefers AES post-KB5021131, but not locked
    $hasAES = (($v -band 0x18) -eq 0x18)  # AES128 + AES256 both set
    $hasRC4 = (($v -band 0x04) -ne 0)
    $hasDES = (($v -band 0x01) -ne 0)
    if ($hasAES -and -not $hasRC4 -and -not $hasDES) { return 'Compliant (AES-only default)' }
    return 'Warning (Mixed or RC4 allowed)'
  }

  [pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Raw      = $(if($raw -ne $null){$raw}else{'(absent)'})
    Decoded  = Decode $raw
    Status   = Get-Status $raw
    RegPath  = "$path\$name"
  }
}

# --- Collect results ---
$rows = @()
foreach($dc in $dcs){
  try {
    $rows += Invoke-Command -ComputerName $dc -ScriptBlock $remote -ErrorAction Stop
  }
  catch {
    $rows += [pscustomobject]@{
      Computer = $dc
      Raw      = '(n/a)'
      Decoded  = '(error)'
      Status   = 'Failed'
      RegPath  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
    }
  }
}

# --- Colored table output ---
Write-Host ""
Write-Host "=== KDC default (DefaultDomainSupportedEncTypes) ===" -ForegroundColor Cyan
$header = "{0,-24} {1,-10} {2,-28} {3,-30} {4}" -f 'Computer','Raw','Decoded','Status','Registry Path'
Write-Host $header -ForegroundColor Gray
Write-Host ('-' * ($header.Length + 30)) -ForegroundColor DarkGray

function RowColor($status){
  switch -regex ($status) {
    '^Compliant' { return 'Green' }
    '^Warning \(AES default, not enforced\)' { return 'Yellow' }
    '^Warning \(Mixed or RC4 allowed\)' { return 'DarkYellow' }
    '^Failed' { return 'Red' }
    default { return 'Magenta' }
  }
}

foreach($r in ($rows | Sort-Object Computer)){
  $color = RowColor $r.Status
  $raw   = if($r.Raw -is [int]) { ('0x{0:X}' -f $r.Raw) } else { $r.Raw }
  $line  = "{0,-24} {1,-10} {2,-28} {3,-30} {4}" -f $r.Computer, $raw, $r.Decoded, $r.Status, $r.RegPath
  Write-Host $line -ForegroundColor $color
}

# --- Summary ---
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$summary = $rows | Group-Object Status | ForEach-Object {
  [pscustomobject]@{ Status = $_.Name; Count = $_.Count }
} | Sort-Object Status
$summary | Format-Table -AutoSize
```

## Kerberos Encryption Configuration Account Audit

Use this PowerShell audit to inventory all AD users, computers, and service accounts, classify their msDS-SupportedEncryptionTypes with KB5021131-aware logic (AES present / Unset / RC4-only), and spotlight SPN-bearing service principals that most urgently need remediation. It also prints a clear, colorized summary and optional CSV exports.

```powershell
<#
Kerberos Encryption Configuration Audit — Accounts only (KB5021131 aware)
- PowerShell 5.1 + RSAT ActiveDirectory
- Classifies accounts by msDS-SupportedEncryptionTypes:
    * Compliant  : AES128 (0x08) and/or AES256 (0x10) present
    * Warning    : (absent/0) — Unset; post-KB5021131 the KDC tends to prefer AES by default,
                   but it’s safer to make capability explicit over time (24 = 0x18)
    * Failed     : RC4-only (0x04 and no AES), DES-only, or no AES bits while other legacy bits set
- Output split: accounts WITH SPN (service principals) vs WITHOUT SPN
- Color summary + optional CSV exports (commented)

Remediation tips:
- Set msDS-SupportedEncryptionTypes = 24 (0x18 = AES128+AES256)
- Refresh the secret after change:
    * User/Service: change password (and update the app)
    * Machine`$: Reset-ComputerMachinePassword / netdom resetpwd
    * gMSA: rotates automatically
#>

cls
Import-Module ActiveDirectory

function EncFlagsToText {
  param([Nullable[int]]$v)
  if ($null -eq $v) { return '(absent/0)' }
  $flags = @()
  if (($v -band 0x01) -ne 0) { $flags += 'DES-CBC-CRC' }
  if (($v -band 0x02) -ne 0) { $flags += 'DES-CBC-MD5' }
  if (($v -band 0x04) -ne 0) { $flags += 'RC4-HMAC' }
  if (($v -band 0x08) -ne 0) { $flags += 'AES128' }
  if (($v -band 0x10) -ne 0) { $flags += 'AES256' }
  if ($flags.Count -eq 0) { return '(none/unknown)' }
  return ($flags -join ',')
}

function Get-ObjType {
  param([string]$cls)
  if ($cls -eq 'computer') { return 'Computer$' }
  return 'User/Service'
}

function Is-Enabled {
  param([int]$uac)
  # ACCOUNTDISABLE (0x0002)
  return ((($uac -band 0x0002) -eq 0) -and ($uac -ne $null))
}

function Classify-Enc {
  param([Nullable[int]]$v)
  # AES bits
  $hasAES128 = ($v -ne $null) -and (($v -band 0x08) -ne 0)
  $hasAES256 = ($v -ne $null) -and (($v -band 0x10) -ne 0)
  $hasAES    = $hasAES128 -or $hasAES256

  if ($v -eq $null -or $v -eq 0) { return 'Warning (Unset/0)' }           # post-KB5021131 often AES by default, but not explicit
  if ($hasAES) { return 'Compliant (AES present)' }

  # No AES bits set but some legacy bits are
  $hasRC4 = ($v -band 0x04) -ne 0
  $hasDES = (($v -band 0x01) -ne 0) -or (($v -band 0x02) -ne 0)

  if ($hasRC4 -and -not $hasAES) { return 'Failed (RC4-only/No AES)' }
  if ($hasDES  -and -not $hasAES) { return 'Failed (DES-only/No AES)' }

  return 'Failed (No AES)'
}

Write-Host "=== Accounts Kerberos Encryption Capability (per msDS-SupportedEncryptionTypes) ===" -ForegroundColor Cyan

$attrs = 'sAMAccountName','objectClass','userAccountControl','msDS-SupportedEncryptionTypes','servicePrincipalName'
$all   = Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer))' -Properties $attrs

$rows = foreach($a in $all) {
  $v = $a.'msDS-SupportedEncryptionTypes'
  [pscustomobject]@{
    Name    = $a.sAMAccountName
    Object  = Get-ObjType $a.objectClass
    Enabled = Is-Enabled ([int]$a.userAccountControl)
    EncHex  = $(if($v -ne $null){ '0x{0:X}' -f $v } else { '(absent/0)' })
    Flags   = EncFlagsToText $v
    HasSPN  = [bool]($a.servicePrincipalName)
    Status  = Classify-Enc $v
  }
}

# WITH SPN (services) — highest impact first
$withSpn = $rows | Where-Object { $_.HasSPN -eq $true } | Sort-Object Status, Object, Name
# WITHOUT SPN
$noSpn   = $rows | Where-Object { $_.HasSPN -eq $false } | Sort-Object Status, Object, Name

# Pretty sections
if ($withSpn -and $withSpn.Count -gt 0) {
  Write-Host "`n--- Accounts WITH SPN (service principals) ---" -ForegroundColor Yellow
  $withSpn | Format-Table -AutoSize Name, Object, Enabled, EncHex, Flags, Status
} else {
  Write-Host "`n(no accounts with SPN found)" -ForegroundColor DarkGray
}

if ($noSpn -and $noSpn.Count -gt 0) {
  Write-Host "`n--- Accounts WITHOUT SPN ---" -ForegroundColor Yellow
  $noSpn | Format-Table -AutoSize Name, Object, Enabled, EncHex, Flags, Status
} else {
  Write-Host "`n(no accounts without SPN found)" -ForegroundColor DarkGray
}

# Color summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$tot = $rows.Count
$fail = (@($rows | Where-Object { $_.Status -like 'Failed*' })).Count
$warn = (@($rows | Where-Object { $_.Status -like 'Warning*' })).Count
$ok   = (@($rows | Where-Object { $_.Status -like 'Compliant*' })).Count

Write-Host ("Total accounts   : {0}" -f $tot) -ForegroundColor Gray
Write-Host ("Compliant (AES)  : {0}" -f $ok)   -ForegroundColor Green
Write-Host ("Warning (Unset)  : {0}" -f $warn) -ForegroundColor Yellow
Write-Host ("Failed (No AES)  : {0}" -f $fail) -ForegroundColor Red

Write-Host "`nRemediation tips:" -ForegroundColor Yellow
Write-Host " - Prefer explicit AES: set msDS-SupportedEncryptionTypes = 24 (0x18 = AES128+AES256)" -ForegroundColor Yellow
Write-Host " - Refresh secrets after change:" -ForegroundColor Yellow
Write-Host "     * User/Service: change password (and update the app)" -ForegroundColor Yellow
Write-Host "     * Machine`$: Reset-ComputerMachinePassword / netdom resetpwd" -ForegroundColor Yellow
Write-Host "     * gMSA: rotates automatically" -ForegroundColor Yellow

# Optional CSV exports (commented)
<#
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$rows   | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $PWD ("Kerb_AllAccounts_{0}.csv" -f $stamp))
$withSpn| Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $PWD ("Kerb_WithSPN_{0}.csv" -f $stamp))
$noSpn  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $PWD ("Kerb_NoSPN_{0}.csv" -f $stamp))
Write-Host ("CSV exports -> {0}" -f (Resolve-Path .)) -ForegroundColor Cyan
#>
```

## Kerberos Encryption Event Logs Audit

Use this script to scan each DC’s Security log for 4768/4769 and produce a breakdown of ticket encryption types (AES256/128 vs RC4), plus “Top RC4” by account, client IP, and DC. It’s a quick, RSAT/WinRM-based way to verify your move toward AES-only in real traffic.

```powershell
<#
Kerberos Ticket Encryption Audit (4768/4769)
- PS 5.1, no modules required (runs from a workstation with RSAT/WinRM)
- Collects on each DC (embedded list) for a lookback window (hours)
- Pretty tables + optional CSV exports (commented)
#>

cls

# --- Config ---
$LookbackHours = 24   # last 1 days
$OutDir = Join-Path $PWD ("Krb_Audit_{0:yyyyMMdd_HHmmss}" -f (Get-Date))

# Domain Controllers (edit)
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Remote collector for 4768 (TGT) + 4769 (Service ticket) ---
$remote = {
  param([int]$Hours)
  $since = (Get-Date).AddHours(-1 * $Hours)
  $fh = @{
    LogName      = 'Security'
    Id           = 4768,4769
    StartTime    = $since
    ProviderName = 'Microsoft-Windows-Security-Auditing'
  }

  function Parse {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)
    $msg = $null
    try { $msg = $ev.FormatDescription() } catch { $msg = $null }

    # Extract common fields defensively
    $ip   = $null
    $acct = $null
    if ($msg) {
      $mIp = [regex]::Match($msg,'Client Address:\s*(?<v>\S+)')
      if ($mIp.Success) { $ip = $mIp.Groups['v'].Value }

      $mAc = [regex]::Match($msg,'Account Name:\s*(?<v>.+)')
      if ($mAc.Success) { $acct = $mAc.Groups['v'].Value.Trim() }
      if (-not $acct) {
        $mAc2 = [regex]::Match($msg,'TargetUserName:\s*(?<v>.+)')
        if ($mAc2.Success) { $acct = $mAc2.Groups['v'].Value.Trim() }
      }
    }

    # Encryption type (hex code expected at the end of many templates)
    $enc = $null
    if ($msg) {
      $mEnc = [regex]::Match($msg,'Ticket Encryption Type:\s*(?<v>0x[0-9A-Fa-f]+)')
      if ($mEnc.Success) { $enc = $mEnc.Groups['v'].Value.ToLower() }
    }

    [pscustomobject]@{
      DC        = $env:COMPUTERNAME
      Time      = $ev.TimeCreated
      EventId   = $ev.Id
      Account   = $(if($acct){$acct}else{'(n/a)'})
      ClientIP  = $(if($ip){$ip}else{'(n/a)'})
      EncHex    = $(if($enc){$enc}else{'(unknown)'})
    }
  }

  $list = New-Object System.Collections.Generic.List[object]
  $evts = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue
  if ($evts) { foreach($e in $evts){ $list.Add( (Parse $e) ) | Out-Null } }
  $list
}

# --- Collect everywhere ---
$raw = @()
foreach($dc in $dcs){
  try   { $raw += Invoke-Command -ComputerName $dc -ScriptBlock $remote -ArgumentList $LookbackHours -ErrorAction Stop }
  catch { $raw += [pscustomobject]@{ DC=$dc; Time=Get-Date; EventId='(n/a)'; Account='(n/a)'; ClientIP='(n/a)'; EncHex='(unreachable)' } }
}

# --- Map enc types ---
function EncLabel($hex){
  switch ($hex) {
    '0x12' { 'AES256-CTS-HMAC-SHA1-96' }
    '0x11' { 'AES128-CTS-HMAC-SHA1-96' }
    '0x17' { 'RC4-HMAC' }
    default { 'UNKNOWN' }
  }
}

$all = $raw | Select-Object DC,Time,EventId,Account,ClientIP,
  @{n='EncType';e={ EncLabel $_.EncHex }}

# --- Global breakdown ---
Write-Host "`n=== Kerberos Ticket Encryption Breakdown (events 4768/4769) ===" -ForegroundColor Cyan
$break = $all | Group-Object EncType | ForEach-Object {
  [pscustomobject]@{ Type=$_.Name; Events=$_.Count }
} | Sort-Object Events -Descending
$tot = ($break | Measure-Object Events -Sum).Sum
$break | Select-Object Type,Events,
  @{n='%';e={[math]::Round(100*($_.Events/$tot),2)}} | Format-Table -AutoSize

# --- Top RC4 by Account / ClientIP / DC ---
$rc4 = $all | Where-Object { $_.EncType -eq 'RC4-HMAC' }

Write-Host "`n=== Top RC4 Accounts ===" -ForegroundColor Cyan
$rc4 | Group-Object Account | ForEach-Object {
  [pscustomobject]@{ Account=$_.Name; Events=$_.Count }
} | Sort-Object Events -Descending | Format-Table -AutoSize

Write-Host "`n=== Top RC4 Client IPs ===" -ForegroundColor Cyan
$rc4 | Group-Object ClientIP | ForEach-Object {
  [pscustomobject]@{ ClientIP=$_.Name; Events=$_.Count }
} | Sort-Object Events -Descending | Format-Table -AutoSize

Write-Host "`n=== Domain Controllers contacted (RC4-HMAC) ===" -ForegroundColor Cyan
$rc4 | Group-Object DC | ForEach-Object {
  [pscustomobject]@{ DC=$_.Name; Events=$_.Count }
} | Sort-Object Events -Descending | Format-Table -AutoSize

# --- Optional CSV exports ---
<#
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$all    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'All_Tickets.csv')
$break  | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'Breakdown.csv')
$rc4    | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'RC4_Events.csv')
#>
```


**Updated Script**

> Powershell 7 required !

```powershell
<#
Kerberos Ticket Encryption Audit (4768/4769) — PS7
- DCs list embedded (no input file)
- Parallel collection (ForEach-Object -Parallel) without passing a scriptblock variable
- Console breakdown + Top RC4 by Account/IP/DC
- Optional CSV export via -ExportCsv
#>

param(
  [int]$Hours = 24,
  [switch]$ExportCsv,
  [int]$ThrottleLimit = 8,
  [string]$OutDir = $(Join-Path $PWD ("Krb_Audit_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

cls

# --- Domain Controllers (edit here) ---
$DCs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Event IDs ---
$EventIds = 4768,4769

# --- Map enc types to labels ---
function Get-EncLabel {
  param([string]$v)
  if (-not $v) { return 'UNKNOWN' }

  # Accept hex ("0x12") or decimal ("18")
  $hex =
    if ($v -match '^0x[0-9A-Fa-f]+$') { $v.ToLower() }
    elseif ($v -match '^\d+$')        { ('0x{0:X}' -f [int]$v).ToLower() }
    else                               { $null }

  if (-not $hex) { return 'UNKNOWN' }

  switch ($hex) {
    '0x12' { 'AES256-CTS-HMAC-SHA1-96' } # 18
    '0x11' { 'AES128-CTS-HMAC-SHA1-96' } # 17
    '0x17' { 'RC4-HMAC' }                # 23
    default { 'UNKNOWN' }
  }
}

Write-Host "Collecting events from DCs (last $Hours hours)..." -ForegroundColor Cyan

# --- Collect in parallel (inline remote logic) ---
$all = $DCs | ForEach-Object -Parallel {
  $dc = $_
  try {
    Invoke-Command -ComputerName $dc -ScriptBlock {
      param([int]$Hours,[int[]]$Ids)
      $since = (Get-Date).AddHours(-1 * $Hours)
      $fh = @{
        LogName      = 'Security'
        Id           = $Ids
        StartTime    = $since
        ProviderName = 'Microsoft-Windows-Security-Auditing'
      }

      function Parse-One {
        param([System.Diagnostics.Eventing.Reader.EventRecord]$ev)
        $xml = [xml]$ev.ToXml()

        $get = {
          param($name)
          ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $name }).'#text'
        }

        $encRaw = & $get 'TicketEncryptionType'
        $acct   = (& $get 'TargetUserName'); if (-not $acct) { $acct = (& $get 'Account Name') }
        $ip     = (& $get 'ClientAddress');  if (-not $ip)  { $ip   = (& $get 'IpAddress') }
        if ($ip) { $ip = $ip.Replace('::ffff:','') }

        [pscustomobject]@{
          DC        = $env:COMPUTERNAME
          Time      = $ev.TimeCreated
          EventId   = $ev.Id
          Account   = $(if($acct){$acct}else{'(n/a)'})
          ClientIP  = $(if($ip){$ip}else{'(n/a)'})
          EncHex    = $(if($encRaw){$encRaw}else{'(unknown)'})
          EncType   = $null
        }
      }

      $out = New-Object System.Collections.Generic.List[object]
      $evts = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue
      if ($evts) {
        foreach($e in $evts){ $out.Add( (Parse-One $e) ) | Out-Null }
      }
      $out
    } -ArgumentList $using:Hours, $using:EventIds -ErrorAction Stop
  } catch {
    [pscustomobject]@{
      DC        = $dc
      Time      = Get-Date
      EventId   = '(n/a)'
      Account   = '(n/a)'
      ClientIP  = '(n/a)'
      EncHex    = '(unreachable)'
      EncType   = $null
    }
  }
} -ThrottleLimit $ThrottleLimit

# Flatten potential nested enumerables
$flat = foreach($chunk in $all){ if ($chunk -is [System.Collections.IEnumerable]) { $chunk } else { ,$chunk } }

# Fill EncType labels
$flat | ForEach-Object { $_.EncType = Get-EncLabel $_.EncHex }

# --- Console: Global breakdown ---
Write-Host "`n=== Kerberos Ticket Encryption Breakdown (4768/4769) ===" -ForegroundColor Cyan
$break = $flat | Group-Object EncType | ForEach-Object {
  [pscustomobject]@{ Type=$_.Name; Events=$_.Count }
} | Sort-Object Events -Descending
$tot = ($break | Measure-Object Events -Sum).Sum
if ($tot -gt 0) {
  $break | Select-Object Type,Events,
    @{n='%';e={[math]::Round(100*($_.Events/$tot),2)}} | Format-Table -AutoSize
} else {
  Write-Host "(no events found)" -ForegroundColor DarkGray
}

# --- Console: Top RC4 ---
$rc4 = $flat | Where-Object { $_.EncType -eq 'RC4-HMAC' }

Write-Host "`n=== Top RC4 Accounts ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object Account |
    Sort-Object Count -Descending |
    Select-Object @{n='Account';e={$_.Name}}, @{n='Events';e={$_.Count}} -First 20 |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

Write-Host "`n=== Top RC4 Client IPs ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object ClientIP |
    Sort-Object Count -Descending |
    Select-Object @{n='ClientIP';e={$_.Name}}, @{n='Events';e={$_.Count}} -First 20 |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

Write-Host "`n=== Domain Controllers contacted (RC4-HMAC) ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object DC |
    Sort-Object Count -Descending |
    Select-Object @{n='DC';e={$_.Name}}, @{n='Events';e={$_.Count}} |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

# --- Optional CSV exports ---
if ($ExportCsv) {
  if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

  $flat  | Select-Object DC,Time,EventId,Account,ClientIP,EncHex,EncType |
           Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'All_Tickets.csv')

  $break | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'Breakdown.csv')

  if ($rc4) {
    $rc4 | Select-Object DC,Time,EventId,Account,ClientIP,EncHex,EncType |
           Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'RC4_Events.csv')
  }

  Write-Host ("`nCSV exports -> {0}" -f $OutDir) -ForegroundColor Cyan
}
```

- Usage for CSV Export : .\DC_KRB_ETYPE.ps1 -Hours 24 -ExportCsv
- Example for Folder targeting, changing default hours and manage parallelism : .\DC_KRB_ETYPE.ps1 -Hours 48 -ExportCsv -OutDir "C:\Temp\Krb_Audit" -ThrottleLimit 12

![](assets/Audit%20and%20Enforcement%20for%20Kerberos%20Encryption%20Type/2025-12-05-10-25-22.png)