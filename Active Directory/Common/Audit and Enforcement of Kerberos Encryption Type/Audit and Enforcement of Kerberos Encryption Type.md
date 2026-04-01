# Audit and Enforcement of Kerberos Encryption Type
Published: 2025-12-03

Microsoft hardened Kerberos with KB5021131 to reduce the legacy RC4 paths that many Active Directory environments had been carrying for years. The change is tied to CVE-2022-37966 and matters because a domain can look healthy on paper while still issuing RC4 tickets in real traffic.

Microsoft reference:
https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d

## Why this topic matters

Kerberos encryption posture is not just a registry setting on domain controllers.

You have to look at three layers together:

1. The KDC default used when an account does not explicitly declare supported encryption types.
2. The encryption capability declared on users, computers, service accounts, and SPN-bearing identities.
3. The encryption type that is actually observed in live 4768 and 4769 traffic.

If you only check one of those layers, you can easily think you are ready for AES-only enforcement while RC4 is still being used by service tickets, legacy clients, or stale account secrets.

## Ticket encryption vs session key

These two concepts are often mixed together.

- A Kerberos ticket is encrypted with the long-term key of the ticket recipient.
  - TGTs are encrypted with the `krbtgt` key.
  - Service tickets are encrypted with the key of the service or computer account.
- The session key is a temporary key carried inside the ticket and used by the client and service during the Kerberos exchange.

In practice, if the target account only has RC4 material available, you often end up with RC4 for both the ticket and the session key. If AES is available and preferred, you should see AES in the ticket events and in the live session path.

## What KB5021131 changed

KB5021131 changed the default Kerberos behavior so that patched domain controllers prefer AES more aggressively.

The practical impacts are:

- AES is preferred for session keys when supported encryption types are not explicitly defined on the account.
- `DefaultDomainSupportedEncTypes` lets you lock the domain-wide KDC default to AES-only instead of relying on implicit behavior.
- Unset accounts are less likely to drift into RC4 by omission, but that does not remove the need to audit real traffic.

The important nuance is that the patch does not magically create AES keys for an account that never refreshed its secret after enabling AES support.

## The two controls that matter most

### `msDS-SupportedEncryptionTypes`

This is the per-account declaration that tells the KDC what the identity supports.

Common values:

- `0x18` = AES128 + AES256
- `0x04` = RC4 only
- `0` or absent = unset, historically ambiguous, now less dangerous after KB5021131 but still not ideal for long-term enforcement

After changing the attribute, the secret must be refreshed so the KDC can actually mint AES keys:

- user or traditional service account: change the password
- computer account: reset the machine password
- gMSA: rotation is automatic

### `DefaultDomainSupportedEncTypes`

This is the domain controller registry baseline under:

`HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes`

It defines the default encryption types used when `msDS-SupportedEncryptionTypes` is not set on the account.

For an AES-only target state, the value you ultimately want is usually:

- `0x18` = AES128 + AES256 only

But you should only enforce that after auditing both account configuration and live Kerberos traffic.

## Why SPN-bearing accounts are the highest priority

SPN-bearing accounts drive service ticket encryption.

That means they are usually the first place to investigate when 4769 still shows RC4.

Prioritize:

- traditional service accounts
- computer accounts hosting services
- gMSAs and sMSAs
- any account tied to `HTTP/`, `MSSQLSvc/`, `CIFS/`, `LDAP/`, `HOST/`, and similar SPNs

If these identities are still RC4-only, the domain can remain operational while silently issuing weak service tickets.

## Companion script

The companion script in this folder consolidates the full audit into one PowerShell file:

- [Invoke-KerberosEncryptionAudit.ps1](Invoke-KerberosEncryptionAudit.ps1)

It performs all of the following in one run:

1. Audits `DefaultDomainSupportedEncTypes` on each domain controller.
2. Inventories users, computers, and managed service accounts for `msDS-SupportedEncryptionTypes`.
3. Prioritizes SPN-bearing and service identities that still allow RC4 or do not explicitly declare AES.
4. Collects 4768 and 4769 from domain controllers for a configurable lookback window.
5. Breaks down ticket encryption types across TGT and TGS traffic.
6. Highlights RC4 requestors and RC4 target services.
7. Flags avoidable RC4 TGS events where client, service, and DC all advertised AES capability.
8. Generates a clean HTML report, a JSON report, and optional CSV exports.

## How to run it

Basic run:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1
```

Run against the last 48 hours and open the report automatically:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -Hours 48 -OpenReport
```

Run with CSV exports:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -Hours 48 -ExportCsv
```

Run against a specific DC subset:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -DomainControllers MM-DC1.mathiasmotron.com,MM-DC2.mathiasmotron.com
```

## What the report tells you

The HTML report is designed to answer four questions quickly.

### 1. Is the KDC default already locked to AES-only?

If not, the report shows which DCs still allow mixed or implicit behavior.

### 2. Which identities still block AES-only enforcement?

The report highlights priority accounts, with emphasis on SPN-bearing identities and service accounts.

### 3. Is RC4 still present in live Kerberos traffic?

The report summarizes ticket encryption for both TGT and TGS events, not just account configuration.

### 4. Is the remaining RC4 avoidable?

The report surfaces RC4 TGS cases where client, service, and domain controller all appear to support AES. Those are often the fastest wins.

## Recommended migration path

Use this order.

1. Audit the KDC default, account posture, and real ticket traffic.
2. Fix SPN-bearing accounts first.
3. Refresh the relevant secrets so AES keys actually exist.
4. Re-run the audit until RC4 is gone or fully understood.
5. Lock `DefaultDomainSupportedEncTypes` to `0x18`.
6. Restrict client Kerberos encryption types to AES128 and AES256 only.

## Common mistakes to avoid

- Setting `msDS-SupportedEncryptionTypes` without rotating the secret afterward.
- Looking only at account configuration and ignoring 4768 and 4769.
- Treating absent values as fully remediated just because KB5021131 improved the default.
- Enforcing AES-only on the KDC before identifying the SPN-bearing accounts still tied to RC4.

## Practical takeaway

If your goal is to enforce AES-only Kerberos safely, you need evidence from both configuration and live traffic.

That is exactly what the companion script in this folder is built to provide.
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

**Updated Script**

> Powershell 7 required !

```powershell
<#
Kerberos Ticket Encryption Audit (4768/4769) — PowerShell 7

- DCs list embedded (no input file)
- Parallel collection (ForEach-Object -Parallel)
- Distinguish TGT (4768) vs TGS (4769)
- Track Requestor Account AND Target Service (ServiceName + ServiceSid) for TGS
- Console breakdown:
  - Breakdown by TicketType + EncType
  - Global breakdown all tickets
  - UNKNOWN enc types breakdown (0xffffffff => UNKNOWN (no ticket/failed ticket))
  - RC4 by TicketType
  - Top RC4 Requestor Accounts
  - Top RC4 Target Services (TGS)
  - Top RC4 Client IPs
  - DCs contacted for RC4
  - ALERT: TGT using RC4-HMAC
- AD enrichment (if ActiveDirectory module available):
  - For RC4 Requestor Accounts → pwdLastSet, lastLogonDate, msDS-SupportedEncryptionTypes, PreAuthNotRequired
  - For RC4 Target Services (TGS) → résolution par SID (objectSid) en priorité, fallback SPN, fallback samAccountName = ServiceName
- New:
  - ClientSupportsAES / DCSupportsAES / ServiceHasAESKeys
  - RC4ChosenWhileAESAvailable = True si RC4 TGS alors que client, DC et service supportent AES
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
    '0x12'       { 'AES256-CTS-HMAC-SHA1-96' }           # 18
    '0x11'       { 'AES128-CTS-HMAC-SHA1-96' }           # 17
    '0x17'       { 'RC4-HMAC' }                          # 23
    '0xffffffff' { 'UNKNOWN (no ticket/failed ticket)' } # failures / no cipher
    default      { 'UNKNOWN' }
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

        $encRaw    = & $get 'TicketEncryptionType'
        $acct      = (& $get 'TargetUserName'); if (-not $acct) { $acct = (& $get 'Account Name') }
        $ip        = (& $get 'ClientAddress');  if (-not $ip)  { $ip   = (& $get 'IpAddress') }
        if ($ip) { $ip = $ip.Replace('::ffff:','') }

        # Ticket type: TGT vs TGS
        $ticketType = switch ($ev.Id) {
          4768 { 'TGT' }
          4769 { 'TGS' }
          default { 'UNKNOWN' }
        }

        # Target service/SPN (only meaningful for TGS)
        $svcName   = (& $get 'ServiceName')
        $svcSid    = (& $get 'ServiceSid')

        # Enriched Kerberos info (patch RC4)
        $svcKeys    = (& $get 'ServiceAvailableKeys')
        $clientKeys = (& $get 'ClientAdvertizedEncryptionTypes')
        $dcEncTypes = (& $get 'DCSupportedEncryptionTypes')

        [pscustomobject]@{
          DC         = $env:COMPUTERNAME
          Time       = $ev.TimeCreated
          EventId    = $ev.Id
          TicketType = $ticketType
          Account    = $(if($acct){$acct}else{'(n/a)'})  # Requestor (user/computer)
          Service    = $(if($ticketType -eq 'TGS' -and $svcName){$svcName}else{'(n/a)'}) # Target service display (ServiceName)
          ServiceSid = $(if($ticketType -eq 'TGS' -and $svcSid){$svcSid}else{$null})     # Target account SID
          ClientIP   = $(if($ip){$ip}else{'(n/a)'})
          EncHex     = $(if($encRaw){$encRaw}else{'(unknown)'})
          EncType    = $null

          ServiceAvailableKeys        = $svcKeys
          ClientAdvertizedEncryption  = $clientKeys
          DCSupportedEncryptionTypes  = $dcEncTypes

          ClientSupportsAES           = $false
          ServiceHasAESKeys           = $false
          DCSupportsAES               = $false
          RC4ChosenWhileAESAvailable  = $false
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
      DC         = $dc
      Time       = Get-Date
      EventId    = '(n/a)'
      TicketType = 'UNKNOWN'
      Account    = '(n/a)'
      Service    = '(n/a)'
      ServiceSid = $null
      ClientIP   = '(n/a)'
      EncHex     = '(unreachable)'
      EncType    = $null

      ServiceAvailableKeys        = $null
      ClientAdvertizedEncryption  = $null
      DCSupportedEncryptionTypes  = $null

      ClientSupportsAES           = $false
      ServiceHasAESKeys           = $false
      DCSupportsAES               = $false
      RC4ChosenWhileAESAvailable  = $false
    }
  }
} -ThrottleLimit $ThrottleLimit

# Flatten potential nested enumerables
$flat = foreach($chunk in $all){
  if ($chunk -is [System.Collections.IEnumerable]) { $chunk } else { ,$chunk }
}

# Fill EncType labels
$flat | ForEach-Object { $_.EncType = Get-EncLabel $_.EncHex }

# Compute AES support flags + RC4ChosenWhileAESAvailable
$flat | ForEach-Object {
  # bool "support AES" based on strings
  if ($_.ClientAdvertizedEncryption -match 'AES') {
    $_.ClientSupportsAES = $true
  }
  if ($_.ServiceAvailableKeys -match 'AES') {
    $_.ServiceHasAESKeys = $true
  }
  if ($_.DCSupportedEncryptionTypes -match 'AES') {
    $_.DCSupportsAES = $true
  }

  # RC4 choisi alors que AES dispo partout (TGS uniquement)
  if ($_.EncType -eq 'RC4-HMAC' -and $_.TicketType -eq 'TGS') {
    if ($_.ClientSupportsAES -and $_.ServiceHasAESKeys -and $_.DCSupportsAES) {
      $_.RC4ChosenWhileAESAvailable = $true
    }
  }
}

# --- Global breakdown by TicketType + EncType ---
Write-Host "`n=== Kerberos Ticket Encryption Breakdown by Ticket Type ===" -ForegroundColor Cyan
$breakByType = $flat |
  Group-Object TicketType, EncType |
  ForEach-Object {
    [pscustomobject]@{
      TicketType = $_.Group[0].TicketType
      EncType    = $_.Group[0].EncType
      Events     = $_.Count
    }
  } | Sort-Object TicketType, EncType

if ($breakByType) {
  $breakByType | Format-Table -AutoSize
} else {
  Write-Host "(no events found)" -ForegroundColor DarkGray
}

# --- Global breakdown (all tickets combined) ---
Write-Host "`n=== Global Kerberos Ticket Encryption Breakdown (4768/4769 combined) ===" -ForegroundColor Cyan
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

# --- UNKNOWN EncTypes details (voir les valeurs brutes) ---
Write-Host "`n=== UNKNOWN EncTypes details ===" -ForegroundColor Cyan
$unknown = $flat | Where-Object { $_.EncType -like 'UNKNOWN*' }
if ($unknown) {
  $unknown | Group-Object EncHex |
    Sort-Object Count -Descending |
    Select-Object @{n='EncHex';e={$_.Name}}, @{n='Events';e={$_.Count}} |
    Format-Table -AutoSize
} else {
  Write-Host "(none)" -ForegroundColor DarkGray
}

# --- RC4 views ---

$rc4 = $flat | Where-Object { $_.EncType -eq 'RC4-HMAC' }

Write-Host "`n=== RC4 Events by Ticket Type (TGT vs TGS) ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object TicketType |
    Sort-Object Count -Descending |
    Select-Object @{n='TicketType';e={$_.Name}}, @{n='Events';e={$_.Count}} |
    Format-Table -AutoSize
} else {
  Write-Host "(none)" -ForegroundColor DarkGray
}

# --- ALERT: TGT using RC4 (devrait être extrêmement rare) ---
Write-Host "`n=== ALERTS: TGT using RC4-HMAC ===" -ForegroundColor Red
$tgtRc4 = $flat | Where-Object { $_.TicketType -eq 'TGT' -and $_.EncType -eq 'RC4-HMAC' }
if ($tgtRc4) {
  $tgtRc4 |
    Group-Object Account |
    Sort-Object Count -Descending |
    Select-Object @{n='Account';e={$_.Name}}, @{n='Events';e={$_.Count}} |
    Format-Table -AutoSize
} else {
  Write-Host "No TGT using RC4 detected (expected in modern, hardened environments)." -ForegroundColor DarkGreen
}

# --- Top RC4 Requestor Accounts (who is asking for RC4 tickets) ---
Write-Host "`n=== Top RC4 Requestor Accounts ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object Account |
    Sort-Object Count -Descending |
    Select-Object @{n='Account';e={$_.Name}}, @{n='Events';e={$_.Count}} -First 20 |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

# --- Top RC4 Target Services (TGS only) ---
Write-Host "`n=== Top RC4 Target Services (TGS only) ===" -ForegroundColor Cyan
$rc4Tgs = $rc4 | Where-Object { $_.TicketType -eq 'TGS' }
if ($rc4Tgs) {
  $rc4Tgs | Group-Object Service |
    Sort-Object Count -Descending |
    Select-Object @{n='Service(SPN)';e={$_.Name}}, @{n='Events';e={$_.Count}} -First 20 |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

# --- Top RC4 Client IPs ---
Write-Host "`n=== Top RC4 Client IPs ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object ClientIP |
    Sort-Object Count -Descending |
    Select-Object @{n='ClientIP';e={$_.Name}}, @{n='Events';e={$_.Count}} -First 20 |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

# --- DCs contacted (RC4-HMAC) ---
Write-Host "`n=== Domain Controllers contacted (RC4-HMAC) ===" -ForegroundColor Cyan
if ($rc4) {
  $rc4 | Group-Object DC |
    Sort-Object Count -Descending |
    Select-Object @{n='DC';e={$_.Name}}, @{n='Events';e={$_.Count}} |
    Format-Table -AutoSize
} else { Write-Host "(none)" -ForegroundColor DarkGray }

# --- RC4 TGS: AES capabilities (visuel) ---
Write-Host "`n=== RC4 TGS – AES capabilities (Client / Service / DC) ===" -ForegroundColor Cyan
if ($rc4Tgs) {
  $rc4Tgs |
    Select-Object Time,Account,Service,
                  ClientSupportsAES,
                  ServiceHasAESKeys,
                  DCSupportsAES,
                  RC4ChosenWhileAESAvailable |
    Format-Table -AutoSize
} else {
  Write-Host "(no RC4 TGS events)" -ForegroundColor DarkGray
}

# --- AD enrichment for RC4 accounts & services ---
$adModuleLoaded = $false
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $adModuleLoaded = $true
} catch {
  Write-Host "`n[WARN] ActiveDirectory module not available. Skipping AD enrichment." -ForegroundColor Yellow
}

$rc4AccountDetails = @()
$rc4ServiceDetails = @()

if ($adModuleLoaded -and $rc4) {

  function Get-AdPrincipalSummary {
    param(
      [string]$Identity
    )

    if (-not $Identity -or $Identity -eq '(n/a)' -or $Identity -eq '(unreachable)') {
      return $null
    }

    $obj = $null
    $objType = $null

    # 1) Si c'est un UPN, on essaie d'abord userPrincipalName
    if ($Identity -like '*@*') {
      try {
        $obj = Get-ADUser -Filter "userPrincipalName -eq '$Identity'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        $objType = 'user'
      } catch {
        $obj = $null
      }
    }

    # 2) Si rien trouvé ou ce n'était pas un UPN, on essaie la résolution classique
    if (-not $obj) {
      try {
        $obj = Get-ADUser -Identity $Identity -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        $objType = 'user'
      } catch {
        try {
          $obj = Get-ADComputer -Identity $Identity -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
          $objType = 'computer'
        } catch {
          try {
            $obj = Get-ADServiceAccount -Identity $Identity -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
            $objType = 'serviceAccount'
          } catch {
            $obj = $null
          }
        }
      }
    }

    if (-not $obj) { return $null }

    # Convert pwdLastSet to DateTime if present
    $pwdLastSetDate = $null
    if ($obj.pwdLastSet -and $obj.pwdLastSet -is [long] -and $obj.pwdLastSet -ne 0) {
      $pwdLastSetDate = [DateTime]::FromFileTime($obj.pwdLastSet)
    }

    # Pre-auth not required flag (0x400000)
    $preAuthNotRequired = $false
    if ($obj.userAccountControl) {
      $preAuthNotRequired = (($obj.userAccountControl -band 0x400000) -ne 0)
    }

    [pscustomobject]@{
      Identity                    = $Identity
      ObjectClass                 = $objType
      Name                        = $obj.Name
      SamAccountName              = $obj.SamAccountName
      DistinguishedName           = $obj.DistinguishedName
      msDS_SupportedEncryptionTypes = $obj.'msDS-SupportedEncryptionTypes'
      pwdLastSet                  = $pwdLastSetDate
      lastLogonDate               = $obj.lastLogonDate
      PreAuthNotRequired          = $preAuthNotRequired
      SPNs                        = $(if ($obj.servicePrincipalName) { $obj.servicePrincipalName -join '; ' } else { $null })
    }
  }

  function Get-AdServiceFromTarget {
    param(
      [string]$ServiceSid,
      [string]$ServiceSpn
    )

    $obj = $null

    # 1) Priorité : résolution par SID (objectSid)
    if ($ServiceSid) {
      try {
        $obj = Get-ADUser -Filter "objectSid -eq '$ServiceSid'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
      } catch {
        $obj = $null
      }

      if (-not $obj) {
        try {
          $obj = Get-ADComputer -Filter "objectSid -eq '$ServiceSid'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        } catch {
          $obj = $null
        }
      }

      if (-not $obj) {
        try {
          $obj = Get-ADServiceAccount -Filter "objectSid -eq '$ServiceSid'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        } catch {
          $obj = $null
        }
      }
    }

    # 2) Fallback : résolution par SPN exact (servicePrincipalName)
    if (-not $obj -and $ServiceSpn) {
      try {
        $obj = Get-ADObject -LDAPFilter ("(servicePrincipalName={0})" -f $ServiceSpn) -Properties objectClass,SamAccountName,DistinguishedName,pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
      } catch {
        $obj = $null
      }
    }

    # 3) Fallback : résolution par samAccountName = ServiceSpn (ton cas : svc.fake)
    if (-not $obj -and $ServiceSpn) {
      try {
        $obj = Get-ADUser -Filter "samAccountName -eq '$ServiceSpn'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
      } catch {
        $obj = $null
      }

      if (-not $obj) {
        try {
          $obj = Get-ADComputer -Filter "samAccountName -eq '$ServiceSpn'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        } catch {
          $obj = $null
        }
      }

      if (-not $obj) {
        try {
          $obj = Get-ADServiceAccount -Filter "samAccountName -eq '$ServiceSpn'" -Properties pwdLastSet,msDS-SupportedEncryptionTypes,lastLogonDate,userAccountControl,servicePrincipalName
        } catch {
          $obj = $null
        }
      }
    }

    if (-not $obj) { return $null }

    $pwdLastSetDate = $null
    if ($obj.pwdLastSet -and $obj.pwdLastSet -is [long] -and $obj.pwdLastSet -ne 0) {
      $pwdLastSetDate = [DateTime]::FromFileTime($obj.pwdLastSet)
    }

    $preAuthNotRequired = $false
    if ($obj.userAccountControl) {
      $preAuthNotRequired = (($obj.userAccountControl -band 0x400000) -ne 0)
    }

    [pscustomobject]@{
      ServiceSid                  = $ServiceSid
      ServiceSpn                  = $ServiceSpn
      ObjectClass                 = $obj.objectClass
      Name                        = $obj.Name
      SamAccountName              = $obj.SamAccountName
      DistinguishedName           = $obj.DistinguishedName
      msDS_SupportedEncryptionTypes = $obj.'msDS-SupportedEncryptionTypes'
      pwdLastSet                  = $pwdLastSetDate
      lastLogonDate               = $obj.lastLogonDate
      PreAuthNotRequired          = $preAuthNotRequired
      SPNs                        = $(if ($obj.servicePrincipalName) { $obj.servicePrincipalName -join '; ' } else { $null })
    }
  }

  Write-Host "`n=== Requestor Accounts for RC4 TGS ===" -ForegroundColor Cyan
  $rc4AccountNames = $rc4 |
    Select-Object -ExpandProperty Account -Unique |
    Where-Object { $_ -and $_ -ne '(n/a)' -and $_ -ne '(unreachable)' }

  foreach ($name in $rc4AccountNames) {
    $detail = Get-AdPrincipalSummary -Identity $name
    if ($detail) { $rc4AccountDetails += $detail }
  }

  if ($rc4AccountDetails) {
    $rc4AccountDetails |
      Sort-Object ObjectClass, SamAccountName |
      Select-Object ObjectClass,SamAccountName,msDS_SupportedEncryptionTypes,pwdLastSet,lastLogonDate,PreAuthNotRequired |
      Format-Table -AutoSize
  } else {
    Write-Host "(no AD details resolved for RC4 accounts)" -ForegroundColor DarkGray
  }

  Write-Host "`n=== Target Services that offered RC4 TGS (from ServiceSid/SPN) ===" -ForegroundColor Cyan
  $rc4ServiceTargets = $rc4Tgs |
    Select-Object ServiceSid, Service -Unique

  foreach ($t in $rc4ServiceTargets) {
    $detail = Get-AdServiceFromTarget -ServiceSid $t.ServiceSid -ServiceSpn $t.Service
    if ($detail) { $rc4ServiceDetails += $detail }
  }

  if ($rc4ServiceDetails) {
    $rc4ServiceDetails |
      Sort-Object SamAccountName |
      Select-Object ServiceSid,ServiceSpn,SamAccountName,msDS_SupportedEncryptionTypes,pwdLastSet,lastLogonDate,PreAuthNotRequired |
      Format-Table -AutoSize
  } else {
    Write-Host "(no AD details resolved for RC4 target services)" -ForegroundColor DarkGray
  }
}

# --- Optional CSV exports ---
if ($ExportCsv) {
  if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
  }

  $flat  | Select-Object DC,Time,EventId,TicketType,Account,Service,ServiceSid,ClientIP,EncHex,EncType,
                          ServiceAvailableKeys,ClientAdvertizedEncryption,DCSupportedEncryptionTypes,
                          ClientSupportsAES,ServiceHasAESKeys,DCSupportsAES,RC4ChosenWhileAESAvailable |
           Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'All_Tickets.csv')

  $breakByType | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'Breakdown_By_TicketType.csv')
  $break       | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'Breakdown_Global.csv')

  if ($rc4) {
    $rc4 | Select-Object DC,Time,EventId,TicketType,Account,Service,ServiceSid,ClientIP,EncHex,EncType,
                         ServiceAvailableKeys,ClientAdvertizedEncryption,DCSupportedEncryptionTypes,
                         ClientSupportsAES,ServiceHasAESKeys,DCSupportsAES,RC4ChosenWhileAESAvailable |
           Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'RC4_Events.csv')
  }

  if ($adModuleLoaded -and $rc4AccountDetails) {
    $rc4AccountDetails |
      Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'RC4_Accounts_AD.csv')
  }

  if ($adModuleLoaded -and $rc4ServiceDetails) {
    $rc4ServiceDetails |
      Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $OutDir 'RC4_Services_AD.csv')
  }

  Write-Host ("`nCSV exports -> {0}" -f $OutDir) -ForegroundColor Cyan
}

```

- Usage for CSV Export : .\DC_KRB_ETYPE.ps1 -Hours 24 -ExportCsv
- Example for Folder targeting, changing default hours and manage parallelism : .\DC_KRB_ETYPE.ps1 -Hours 48 -ExportCsv -OutDir "C:\Temp\Krb_Audit" -ThrottleLimit 12

| File name                       | Scope                  | What it contains                                                                                                                                                                               | Primary usage                                                                        |
| ------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **All_Tickets.csv**             | All Kerberos tickets   | One row per Kerberos ticket (4768 = TGT, 4769 = TGS). Includes requester account, target service, encryption type, client IP, DC, and AES capability indicators (client, service, DC).         | Detailed forensic analysis, advanced filtering, pivot tables, Power BI ingestion     |
| **Breakdown_By_TicketType.csv** | Aggregated statistics  | Aggregated counts of Kerberos tickets grouped by **Ticket Type (TGT/TGS)** and **Encryption Type**.                                                                                            | High-level analysis of encryption usage split between TGT and TGS                    |
| **Breakdown_Global.csv**        | Aggregated statistics  | Global Kerberos encryption usage across all tickets, regardless of ticket type.                                                                                                                | Executive summary, reporting, and security posture overview                          |
| **RC4_Events.csv**              | RC4-only tickets       | Only Kerberos tickets encrypted with **RC4-HMAC**, enriched with AES capability indicators and client/service/DC context.                                                                      | Operational remediation list, identification of avoidable RC4 usage                  |
| **RC4_Accounts_AD.csv**         | RC4 requestor accounts | Active Directory details for accounts **requesting RC4 tickets** (users, computers, service accounts), including password age, last logon, encryption settings, and pre-authentication status. | Identify legacy or misconfigured client accounts requesting weak Kerberos encryption |
| **RC4_Services_AD.csv**         | RC4 service accounts   | Active Directory details for **services issuing RC4 TGS tickets**, including `msDS-SupportedEncryptionTypes`, password age, SPNs, and account type.                                            | Primary remediation dataset to migrate service accounts from RC4 to AES              |


![](assets/Audit%20and%20Enforcement%20for%20Kerberos%20Encryption%20Type/2026-01-29-14-00-36.png)

![](assets/Audit%20and%20Enforcement%20for%20Kerberos%20Encryption%20Type/2026-01-29-14-01-05.png)