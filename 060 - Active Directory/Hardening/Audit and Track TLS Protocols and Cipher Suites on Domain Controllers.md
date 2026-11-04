# Audit and Track TLS Protocols and Cipher Suites on Domain Controllers
🗓️ Published: 2026-01-29

## Overview

While Kerberos encryption is often a primary focus when hardening Active Directory, **TLS usage on Domain Controllers is frequently overlooked**.

Domain Controllers use **Schannel** for services such as LDAPS and for outbound TLS connections made by applications that use this Windows security provider. Depending on the software installed, this can also include cloud agents, monitoring tools, and application integrations.

This article introduces a **PowerShell 7 auditing approach** to **observe TLS protocols and cipher suites reported in successful Schannel handshakes** on Domain Controllers.

The goal is not configuration enforcement, but **visibility and evidence-based security assessment**.

---

## Why This Matters

Security baselines and hardening guides often define:
- Allowed TLS protocol versions
- Allowed cipher suites

However, in real-world environments:
- Legacy applications may still negotiate older protocols
- Third-party agents may not behave as expected
- Cloud services may progressively introduce TLS 1.3
- Documentation rarely reflects actual runtime behavior

Without visibility, disabling protocols or cipher suites becomes risky.

**Auditing first is mandatory.**

---

## How TLS Works on Domain Controllers

**Schannel** is the Windows Security Support Provider that implements TLS for applications using it. Its responsibilities include:
- TLS protocol negotiation
- Cipher suite selection
- Certificate validation

Other TLS implementations used by applications are outside the scope of this audit.

Schannel event **36880**, written to the **System event log**, describes a successful client or server handshake. Available fields depend on the Windows version and event payload. The script reads protocol and cipher suite information, and retains key exchange, target name, and certificate fields when present.

---

## Prerequisite: Enable Schannel Verbose Logging

This audit collects Schannel event **36880**, not failed handshake events.

The following configuration includes informational and success events, as well as errors and warnings:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
  EventLogging (DWORD) = 7
```

According to [Microsoft's Schannel logging documentation](https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings#schannel-logging), levels `4`, `5`, `6`, and `7` include informational and success events. Level `7` includes all documented event categories; it is not a guarantee of exactly one event per connection or handshake.

The script provided in this article:
- Checks the configured logging level on each DC and reports registry or remoting failures
- Optionally sets `EventLogging = 7` on DCs whose configuration does not include success events
- Saves the previous settings locally before making any change, then exits without collecting events

> ⚠️ **Restart and observation window:** Microsoft states that a reboot is required after changing the logging level. The script does not reboot DCs. Schedule controlled restarts, allow a representative observation period, then run the collection again and decline further configuration changes. Enabling logging does not reconstruct past events. Reading the registry alone does not prove that the configured level is already active.
>
> ⚠️ **Volume impact:** Additional logging can accelerate System log rotation and overwrite events needed for this or other investigations. Size the log and/or arrange event forwarding for the observation period. An optional size change is `wevtutil sl System /ms:524288000` (500 MiB); record the previous size before changing it. The script does not resize the log or verify retention.

### Restore the Previous Logging Configuration

If you accept the script's configuration prompt, it creates `Schannel_EventLogging_Before.clixml` in the output directory **before** attempting registry writes. Keep this file and review the reported write failures. An existing backup at the same path is not overwritten.

After collection, restore the recorded values, including the absence of the value when it was originally absent. Do not blindly set every DC to `1`. Use only the backup from your own preparation run, review any intervening configuration or policy changes, and schedule controlled restarts after restoration as well.

Replace the example path below with the backup path printed by the script.

```powershell
$previous = Import-Clixml -LiteralPath 'C:\Audit\Schannel_EventLogging_Before.clixml' -ErrorAction Stop
foreach ($entry in $previous) {
    Invoke-Command -ComputerName $entry.DC -ScriptBlock {
        param([bool]$WasSet, [int]$PreviousValue)
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
        if ($WasSet) {
            New-ItemProperty -Path $path -Name 'EventLogging' -Value $PreviousValue `
                -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        else {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($key.GetValueNames() -contains 'EventLogging') {
                Remove-ItemProperty -Path $path -Name 'EventLogging' -ErrorAction Stop
            }
        }
    } -ArgumentList ([bool]$entry.EventLoggingSet), ([int]$entry.EventLogging) -ErrorAction Stop
}
```

---

## Events Used for the Audit

The primary event used is:

- **Event ID:** 36880  
- **Log:** System  
- **Source:** Schannel  

The parser expects a `UserData/EventXML` payload with nonempty `Protocol` and `CipherSuite` fields. It preserves `ExchangeStrength`, `Type`, `TargetName`, and certificate subject fields when present. Unsupported payloads and missing required fields are reported as parsing failures rather than silently counted as valid observations.

> **Cipher suite name mapping:** the script includes a small illustrative lookup table. Unknown identifiers are retained and displayed as `UNKNOWN (...)`; consult the [IANA TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4). A name in the table does not mean that a suite is supported or enabled on a particular Windows release.

> **Key exchange interpretation:** `ExchangeStrength` is retained as reported, without a weak/strong verdict. A key length is not an equivalent security strength: RSA and elliptic-curve key sizes cannot be assessed with a common `< 128` threshold. Missing or zero values are not sufficient to classify a connection. See Microsoft's [connection information structure](https://learn.microsoft.com/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo) for the distinction between cipher strength and key exchange length.

---

## Script Capabilities

The PowerShell 7 script implements the following logic:

### Domain Controller Scope
- Domain Controllers explicitly defined
- Remote execution via PowerShell Remoting

### Parallel Collection
- Uses `ForEach-Object -Parallel`
- Efficient even with multiple DCs

### TLS Visibility
- TLS protocol values reported in collected events, including unrecognized values
- Cipher suites resolved to human-readable names
- TLS 1.3 observations where supported by the OS and reported by the event payload; Schannel supports TLS 1.3 starting with Windows Server 2022 ([Microsoft documentation](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-))

### Observation Quality
- Per-DC collection status: events collected, no matching events, partial parsing, parsing failure, or collection failure
- Detection of explicitly reported legacy protocols (TLS 1.0 / 1.1 / SSL)
- Separate reporting of unrecognized protocol values; no inference that missing observations prove a protocol is disabled

### Endpoint Awareness
- Grouping of target names when supplied by the event, retaining the reported client/server `Type` separately
- No guaranteed identification of inbound LDAPS clients, remote IP addresses, or originating processes

---

## CSV Export

The script supports CSV export for offline analysis:

```
.\SchannelAuditing.ps1 -ExportCsv
```

Generated files:
- `Schannel_LoggingStatus.csv`
- `Schannel_CollectionStatus.csv`
- `Schannel_36880_AllEvents.csv`
- `Breakdown_Protocol.csv`
- `Breakdown_CipherSuite.csv`
- `Top_Targets.csv`

Empty event or breakdown datasets produce empty CSV files. The status files distinguish an empty observation set from a collection failure. CSV exports and the logging backup may contain infrastructure names and certificate subjects; protect them accordingly.

### HTML Report

Use `-HTMLReport` to generate a standalone `Schannel_TLS_Report.html`:

```powershell
.\SchannelAuditing.ps1 -HTMLReport
.\SchannelAuditing.ps1 -HTMLReport -ExportCsv -OutDir 'C:\AuditTLS'
```

The report includes:
- A summary of parsed handshake events, DCs with observations, legacy observations, and unrecognized protocol values
- Per-DC collection coverage, including empty queries, failures, and parsing errors
- Global and per-DC TLS protocol distributions with counts and percentages
- Global and per-DC cipher suite breakdowns
- The top 30 reported target groups globally and the top 10 per DC, with the displayed limits stated explicitly
- Expandable DC details, collection diagnostics, and interpretation guidance

The report works offline without JavaScript, external fonts, or chart libraries, and includes a print layout. Counts describe events, not unique connections or clients. No compliance or weak/strong cryptographic verdict is generated.

Both export switches are independent and can be combined. By default, output goes into a timestamped `TLS_Audit_yyyyMMdd_HHmmss` subdirectory of the current PowerShell working directory (`$PWD`), not necessarily the script directory. `-OutDir` overrides that location. Protect the HTML report like the CSV files: it can contain infrastructure names and error details.

If you accept the logging preparation prompt, the script saves the configuration backup and exits; neither report format is generated during that preparation run.

---

## What This Script Is Not

This tool does **not enforce** TLS configuration or cipher suite ordering.

Collection reads the remote registry and System log without changing TLS configuration. Accepting the separate preparation prompt **does modify the remote registry**. Optional exports and the preparation backup write local files.

This is not a complete TLS inventory or a compliance verdict. Event 36880 covers successful Schannel handshakes, not failed negotiations or other TLS libraries. Long-lived connections, the observation period, logging activation, and log retention all limit what can be observed. `TargetName` is not a reliable source-client inventory.

Review logging volume, permissions, change control, and output handling before production use.

---

## Conclusion

Successful Schannel handshake events provide useful evidence for TLS hardening, within the limits of the collection and observation period. Combine them with application inventories and, where needed, targeted network traces before disabling protocols or cipher suites.

---

## PowerShell Script

Edit the DC list before running the script. It does not automatically reboot any server.


```powershell
#requires -Version 7.0
<#
TLS / Schannel Cipher Audit on Domain Controllers
-------------------------------------------------
- Check configured Schannel success logging on each DC
- Optionally back up previous settings, set EventLogging = 7, and exit
- Collect System / Schannel / 36880 events in parallel across DCs for the last X hours
- Produce console reporting on:
    * Protocol (TLS 1.0/1.1/1.2/1.3, SSL, etc.)
    * CipherSuite (hex + readable name when known)
    * ExchangeStrength as reported, without a security-strength verdict
    * Reported target names (not an inbound-client inventory)
- Report collection and parsing failures separately from empty observations
- Independent CSV and standalone HTML exports

Prerequisites:
- PowerShell 7 on the admin machine
- PowerShell Remoting enabled to the DCs
- Administrative rights on DCs
- Logging activated after the required reboot, with a representative observation window
#>

param(
    [ValidateScript({ $_ -gt 0 })]
    [int]$Hours = 24,
    [ValidateScript({ $_ -gt 0 })]
    [int]$ThrottleLimit = 8,
    [switch]$ExportCsv,
    [switch]$HTMLReport,
    [string]$OutDir = (Join-Path $PWD ("TLS_Audit_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

Clear-Host
Write-Host "=== TLS / Schannel Cipher Audit on Domain Controllers ===" -ForegroundColor Cyan
Write-Host "Time window: last $Hours hours" -ForegroundColor Gray

# --- Domain Controllers (edit here if needed) ---
$DCs = @(
    'MM-DC1.mathiasmotron.com',
    'MM-DC2.mathiasmotron.com',
    'MM-DC3.mathiasmotron.com'
)

if (-not $DCs -or $DCs.Count -eq 0) {
    throw "No DCs defined in the `$DCs list."
}

# --- Helper: map cipher suite hex -> human-readable name (extended with TLS 1.3) ---
function Get-TlsCipherName {
    param(
        [string]$CipherHex
    )

    if ([string]::IsNullOrWhiteSpace($CipherHex)) {
        return "UNKNOWN"
    }

    $CipherHex = $CipherHex.Trim()
    [uint16]$cipherId = 0

    # Numeric-only input is decimal; use 0x for unambiguous hexadecimal input.
    $hex =
        if ($CipherHex -match '^0x[0-9A-Fa-f]{1,4}$') {
            '0x{0:x4}' -f [Convert]::ToUInt16($CipherHex.Substring(2), 16)
        }
        elseif ($CipherHex -match '^[0-9]+$' -and [uint16]::TryParse($CipherHex, [ref]$cipherId)) {
            '0x{0:x4}' -f $cipherId
        }
        elseif ($CipherHex -match '^[0-9A-Fa-f]{1,4}$') {
            '0x{0:x4}' -f [Convert]::ToUInt16($CipherHex, 16)
        }
        else {
            return "UNKNOWN ($CipherHex)"
        }

    switch ($hex) {
        # TLS 1.2 (ECDHE + AES-GCM)
        '0xc02f' { 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' }   # 49199
        '0xc030' { 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' }   # 49200
        '0xc02b' { 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' } # 49195
        '0xc02c' { 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384' } # 49196
        '0x009c' { 'TLS_RSA_WITH_AES_128_GCM_SHA256' }         # 156
        '0x009d' { 'TLS_RSA_WITH_AES_256_GCM_SHA384' }         # 157

        # TLS 1.3 cipher suites
        '0x1301' { 'TLS_AES_128_GCM_SHA256' }
        '0x1302' { 'TLS_AES_256_GCM_SHA384' }
        '0x1303' { 'TLS_CHACHA20_POLY1305_SHA256' }

        # Older examples (CBC / 3DES)
        '0x0035' { 'TLS_RSA_WITH_AES_256_CBC_SHA' }            # 53
        '0x002f' { 'TLS_RSA_WITH_AES_128_CBC_SHA' }            # 47
        '0x000a' { 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' }           # 10

        default  { "UNKNOWN ($hex)" }
    }
}

function Get-TlsProtocolCategory {
    param([string]$Protocol)

    if ($Protocol -eq 'TLS 1.3') { return 'tls13' }
    if ($Protocol -eq 'TLS 1.2') { return 'tls12' }
    if ($Protocol -in @('TLS 1.0','TLS 1.1','SSL 3.0','SSL 2.0')) { return 'legacy' }
    return 'unknown'
}

function ConvertTo-TlsHtmlReport {
    param(
        [object[]]$Events,
        [object[]]$LoggingStatus,
        [object[]]$CollectionStatus,
        [string[]]$DomainControllers,
        [object[]]$ProtocolByDc,
        [object[]]$ProtocolBreakdown,
        [object[]]$CipherBreakdown,
        [object[]]$Targets,
        [int]$Hours
    )

    function ConvertTo-HtmlText {
        param([object]$Text)
        [System.Net.WebUtility]::HtmlEncode([string]$Text)
    }

    function ConvertTo-ReportTable {
        param(
            [object[]]$Rows,
            [System.Collections.IDictionary]$Columns
        )
        if (@($Rows).Count -eq 0) {
            return '<p class="empty">No usable observations available for this view.</p>'
        }
        $head = foreach ($column in $Columns.Keys) {
            "<th scope='col'>$(ConvertTo-HtmlText $Columns[$column])</th>"
        }
        $body = foreach ($row in $Rows) {
            $cells = foreach ($column in $Columns.Keys) {
                "<td>$(ConvertTo-HtmlText $row.$column)</td>"
            }
            "<tr>$($cells -join '')</tr>"
        }
        "<div class='table-wrap' tabindex='0' aria-label='Scrollable data table'><table><thead><tr>$($head -join '')</tr></thead><tbody>$($body -join '')</tbody></table></div>"
    }

    function ConvertTo-ProtocolBar {
        param([object[]]$Rows, [long]$Total)
        if ($Total -eq 0) {
            return '<p class="empty">No usable observations; protocol usage cannot be assessed.</p>'
        }
        $bars = foreach ($row in $Rows) {
            $percent = (100.0 * $row.Events / $Total).ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
            $category = Get-TlsProtocolCategory $row.Protocol
            @"
<div class="protocol-row">
<div class="protocol-label"><span><i class="dot $category" aria-hidden="true"></i>$(ConvertTo-HtmlText $row.Protocol)</span> <span><strong>$($row.Events)</strong> <small>$percent%</small></span></div>
<div class="track" aria-hidden="true"><div class="fill $category" style="width:$percent%"></div></div>
</div>
"@
        }
        $bars -join ''
    }

    $total = @($Events).Count
    $observedDcs = @($CollectionStatus | Where-Object { $_.EventsParsed -gt 0 }).Count
    $reviewDcs = @($CollectionStatus | Where-Object { $_.Status -ne 'Collected' }).Count
    $loggingReview = @($LoggingStatus | Where-Object {
        $_.RegistryCheck -ne 'Succeeded' -or -not $_.SuccessLoggingConfigured
    }).Count
    [long]$legacyCount = ($ProtocolBreakdown | Where-Object {
        (Get-TlsProtocolCategory $_.Protocol) -eq 'legacy'
    } | Measure-Object Events -Sum).Sum
    [long]$unknownCount = ($ProtocolBreakdown | Where-Object {
        (Get-TlsProtocolCategory $_.Protocol) -eq 'unknown'
    } | Measure-Object Events -Sum).Sum
    $legacyDisplay = if ($total -gt 0) { [string]$legacyCount } else { 'Not assessed' }
    $unknownDisplay = if ($total -gt 0) { [string]$unknownCount } else { 'Not assessed' }

    $notices = @(
        if ($total -eq 0) {
            '<div class="notice danger"><strong>No usable observations.</strong> Review collection status below. Protocol usage cannot be assessed from this run.</div>'
        }
        elseif ($reviewDcs -gt 0) {
            "<div class='notice warn'><strong>Collection needs review on $reviewDcs DC(s).</strong> Empty queries, failed collections, and parsing failures are distinct states. Totals include only successfully parsed events.</div>"
        }
        else {
            '<div class="notice info"><strong>Every DC returned parsed observations.</strong> This confirms collection results, not complete log retention or TLS compliance.</div>'
        }
        if ($legacyCount -gt 0) {
            "<div class='notice warn'><strong>$legacyCount legacy protocol observation(s).</strong> Review the affected DCs and applications before planning changes.</div>"
        }
        if ($unknownCount -gt 0) {
            "<div class='notice warn'><strong>$unknownCount unrecognized protocol value(s).</strong> Raw values are retained; they are not classified as modern or legacy.</div>"
        }
        if ($loggingReview -gt 0) {
            "<div class='notice warn'><strong>Logging configuration needs review on $loggingReview DC(s).</strong> See the registry results and diagnostics in the DC details.</div>"
        }
    )

    $coverageRows = foreach ($dc in $DomainControllers) {
        $status = $CollectionStatus | Where-Object DC -eq $dc | Select-Object -First 1
        if ($null -eq $status) { throw "Missing collection status for $dc" }
        [pscustomobject]@{
            DC          = $dc
            Status      = $status.Status
            EventsRead  = if ($null -eq $status.EventsRead) { 'Not available' } else { $status.EventsRead }
            Parsed      = $status.EventsParsed
            ParseErrors = $status.ParseErrors
        }
    }
    $coverageHtml = ConvertTo-ReportTable -Rows @($coverageRows) -Columns ([ordered]@{
        DC='Domain controller'; Status='Collection status'; EventsRead='Events read'; Parsed='Events parsed'; ParseErrors='Parsing errors'
    })
    $protocolHtml = ConvertTo-ProtocolBar -Rows $ProtocolBreakdown -Total $total
    $cipherHtml = ConvertTo-ReportTable -Rows $CipherBreakdown -Columns ([ordered]@{
        CipherSuiteName='Cipher suite'; Events='Events'
    })
    $targetColumns = [ordered]@{
        DC='Domain controller'; Type='Reported type'; TargetName='Reported target'; Protocol='Protocol'; CipherSuiteName='Cipher suite'; Events='Events'
    }
    $targetHtml = ConvertTo-ReportTable -Rows @($Targets | Select-Object -First 30) -Columns $targetColumns
    $targetShown = [math]::Min(30, @($Targets).Count)

    $dcLinks = @()
    $dcSections = @()
    $index = 0
    foreach ($dc in $DomainControllers) {
        $index++
        $dcText = ConvertTo-HtmlText $dc
        $dcLinks += "<a href='#dc-$index'>$dcText</a>"
        $status = $CollectionStatus | Where-Object DC -eq $dc | Select-Object -First 1
        $logging = $LoggingStatus | Where-Object DC -eq $dc | Select-Object -First 1
        if ($null -eq $logging) { throw "Missing logging status for $dc" }
        $dcEvents = @($Events | Where-Object DC -eq $dc)
        $dcProtocols = @($ProtocolByDc | Where-Object DC -eq $dc)
        $dcProtocolHtml = ConvertTo-ProtocolBar -Rows $dcProtocols -Total $dcEvents.Count
        $dcCiphers = @($dcEvents | Group-Object CipherSuiteName | ForEach-Object {
            [pscustomobject]@{ CipherSuiteName=$_.Name; Events=$_.Count }
        } | Sort-Object Events -Descending)
        $dcCipherHtml = ConvertTo-ReportTable -Rows $dcCiphers -Columns ([ordered]@{
            CipherSuiteName='Cipher suite'; Events='Events'
        })
        $dcTargets = @($Targets | Where-Object DC -eq $dc)
        $dcTargetHtml = ConvertTo-ReportTable -Rows @($dcTargets | Select-Object -First 10) -Columns ([ordered]@{
            Type='Reported type'; TargetName='Reported target'; Protocol='Protocol'; CipherSuiteName='Cipher suite'; Events='Events'
        })
        $dcTargetShown = [math]::Min(10, $dcTargets.Count)
        $statusClass = switch ($status.Status) {
            'Collected' { 'collected' }
            'NoEvents' { 'unknown' }
            'Partial' { 'legacy' }
            default { 'failed' }
        }
        $loggingText = if ($logging.RegistryCheck -ne 'Succeeded') {
            'Registry check failed; configured logging level is unknown.'
        }
        elseif (-not $logging.EventLoggingSet) {
            'EventLogging is not explicitly set; success logging is not configured.'
        }
        else {
            "Configured EventLogging: $($logging.EventLogging). Success logging configured: $($logging.SuccessLoggingConfigured)."
        }
        $diagnostics = @($logging.ErrorMessage, $status.ErrorMessage) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $diagnosticHtml = if ($diagnostics) {
            "<details class='diagnostics'><summary>Collection / registry diagnostics</summary><pre>$(ConvertTo-HtmlText ($diagnostics -join [Environment]::NewLine))</pre></details>"
        }
        else { '' }
        $readText = if ($null -eq $status.EventsRead) { 'Not available' } else { [string]$status.EventsRead }
        $dcSections += @"
<details class="dc-panel" id="dc-$index" open>
<summary><span class="dc-name">$dcText</span><span class="badge $statusClass">$(ConvertTo-HtmlText $status.Status)</span><span class="dc-count">$($dcEvents.Count) parsed events</span></summary>
<div class="dc-content">
<p class="dc-meta">Read: $readText &nbsp; / &nbsp; Parsed: $($status.EventsParsed) &nbsp; / &nbsp; Parsing errors: $($status.ParseErrors)</p>
<p class="muted">$(ConvertTo-HtmlText $loggingText) Activation after reboot and log retention are not verified.</p>
$diagnosticHtml
<div class="two-col"><div><h4>Protocol distribution</h4>$dcProtocolHtml</div><div><h4>Cipher suites</h4>$dcCipherHtml</div></div>
<h4>Reported targets</h4><p class="muted">Showing $dcTargetShown of $($dcTargets.Count) target groups, ranked by event count. These are not unique clients.</p>
$dcTargetHtml
</div></details>
"@
    }

    $generated = [datetime]::UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", [Globalization.CultureInfo]::InvariantCulture)
    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TLS activity on domain controllers</title>
<style>
:root{color-scheme:light;--ink:#172b43;--muted:#52647a;--line:#dde5ef;--teal:#087f77;--blue:#3566c5;--amber:#a75a0a;--red:#af3541}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:20px}body{margin:0;background:#f2f5fa;color:var(--ink);font:15px/1.6 "Segoe UI",Arial,sans-serif}
.hero{background:linear-gradient(115deg,#11263f,#173b50);color:#fff;padding:44px max(24px,calc((100vw - 1200px)/2));border-bottom:5px solid #32b7a3}
.eyebrow{font-size:12px;letter-spacing:2px;font-weight:700;color:#9bded5;text-transform:uppercase}h1{font-size:clamp(28px,4vw,42px);line-height:1.2;letter-spacing:-1px;margin:12px 0}
.hero p{color:#d0dfed;margin:10px 0}.meta{display:flex;flex-wrap:wrap;gap:8px 24px;font-size:13px}.container{max-width:1248px;margin:auto;padding:28px 24px 48px}
nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 24px}nav a,.dc-links a{color:var(--ink);background:#fff;text-decoration:none;border:1px solid var(--line);border-radius:8px;padding:8px 14px;font-weight:600;font-size:13px}
a:hover{border-color:var(--teal);color:var(--teal)}a:focus-visible,summary:focus-visible,.table-wrap:focus-visible{outline:3px solid var(--blue);outline-offset:3px}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:24px}.metric{background:#fff;border:1px solid var(--line);border-radius:12px;padding:20px;border-top:3px solid var(--blue)}
.metric:nth-child(2){border-top-color:var(--teal)}.metric:nth-child(3){border-top-color:var(--amber)}.metric:nth-child(4){border-top-color:#74839a}
.metric-label{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:700}.metric-value{font-size:32px;font-weight:750;line-height:1.3;margin:8px 0;overflow-wrap:anywhere}.metric small{color:var(--muted)}
.notice{padding:14px 18px;border:1px solid var(--line);border-left-width:4px;border-radius:8px;margin:12px 0;background:#fff}.notice strong{display:block}.info{border-left-color:var(--blue)}.warn{border-left-color:var(--amber);background:#fffaf0}.danger{border-left-color:var(--red);background:#fff5f5}
section{margin-top:32px}h2{font-size:23px;letter-spacing:-.4px;margin:0 0 8px}h3{font-size:18px;margin:0 0 18px}h4{font-size:15px;margin:18px 0 12px}.muted{color:var(--muted);font-size:13px}.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:24px;min-width:0}
.two-col{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:24px}.global-grid{margin-top:24px}.protocol-row{margin:18px 0}.protocol-label{display:flex;justify-content:space-between;align-items:baseline;gap:16px;margin-bottom:7px;overflow-wrap:anywhere}.protocol-label small{color:var(--muted);margin-left:8px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px}.track{height:9px;background:#edf1f7;border-radius:6px;overflow:hidden}.fill{height:100%;border-radius:6px}.tls13{background:#087f77}.tls12{background:#3566c5}.legacy{background:#a75a0a}.unknown{background:#74839a}
.legend{display:flex;flex-wrap:wrap;gap:8px 20px;font-size:12px;color:var(--muted);margin-top:20px}.table-wrap{overflow:auto;max-width:100%;border:1px solid var(--line);border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:13px}th{background:#f5f8fc;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.4px;color:#52647a}th,td{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}td{overflow-wrap:anywhere;min-width:80px}tbody tr:last-child td{border-bottom:0}tbody tr:nth-child(even){background:#fafcfe}
.empty{background:#f5f8fc;border:1px dashed #cbd6e5;padding:20px;border-radius:8px;color:var(--muted);font-size:14px}.dc-links{display:flex;flex-wrap:wrap;gap:8px;margin:20px 0}.dc-panel{background:#fff;border:1px solid var(--line);border-radius:12px;margin:16px 0;overflow:hidden}
.dc-panel>summary{cursor:pointer;padding:18px 22px;background:#f9fbfe;overflow-wrap:anywhere}.dc-name{font-weight:700;margin-right:14px}.dc-count{color:var(--muted);font-size:13px;margin-left:12px}.badge{display:inline-block;font-size:11px;font-weight:700;padding:3px 9px;border-radius:5px;color:#fff;vertical-align:middle}.collected{background:#087f77}.failed{background:#af3541}.badge.unknown{background:#52647a}
.dc-content{padding:0 24px 24px}.dc-meta{font-size:13px;font-weight:600}.diagnostics{background:#fff8ee;border-radius:8px;padding:12px 16px;margin:16px 0}.diagnostics summary{cursor:pointer;font-weight:600;font-size:13px}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 Consolas,monospace}
.limits{background:#e8eef6;border-radius:12px;padding:24px}.limits li{margin:8px 0}.footer{margin-top:28px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
@media(max-width:850px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.two-col{grid-template-columns:minmax(0,1fr)}}
@media(max-width:480px){.container{padding:20px 14px}.hero{padding:30px 18px}.metrics{gap:10px}.metric{padding:14px}.metric-value{font-size:25px}.card,.dc-content,.limits{padding:18px}.dc-panel>summary{padding:16px}.dc-count{display:block;margin-left:0;margin-top:8px}}
@media print{body{background:#fff;font-size:10pt}.hero{background:#fff;color:#172b43;padding:0 0 16px}.hero p,.eyebrow{color:#52647a}.container{padding:16px 0;max-width:none}nav,.dc-links{display:none}.metrics{gap:8px}.metric,.card,.dc-panel{box-shadow:none}.two-col{display:block}.table-wrap{overflow:visible}table{table-layout:fixed}td,th{overflow-wrap:anywhere}.dc-panel::details-content{content-visibility:visible}.diagnostics::details-content{content-visibility:visible}summary{list-style:none}h2,h3,h4{break-after:avoid}.metric,.protocol-row{break-inside:avoid}.notice,.limits{background:#fff}.hero,section{break-inside:auto}}
</style>
</head>
<body>
<header class="hero"><div class="eyebrow">Active Directory / Schannel observations</div>
<h1>TLS activity on domain controllers</h1><p>Understand what was observed, on which DC, and where the evidence needs review.</p>
<div class="meta"><span>Generated: $generated</span><span>Requested lookback: $Hours hour(s), evaluated on each DC</span><span>System / Schannel / Event 36880</span></div></header>
<main class="container">
<nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#coverage">Collection coverage</a><a href="#protocols">Protocols &amp; ciphers</a><a href="#controllers">By domain controller</a><a href="#targets">Reported targets</a><a href="#limits">How to interpret</a></nav>
<section id="overview"><h2>At a glance</h2><p class="muted">Only successfully parsed handshake events contribute to the distributions below.</p>
<div class="metrics">
<div class="metric"><div class="metric-label">Parsed handshake events</div><div class="metric-value" data-metric="events">$total</div><small>Not unique connections or clients</small></div>
<div class="metric"><div class="metric-label">DCs with observations</div><div class="metric-value" data-metric="controllers">$observedDcs / $($DomainControllers.Count)</div><small>A DC with data can still have parsing errors</small></div>
<div class="metric"><div class="metric-label">Legacy observations</div><div class="metric-value" data-metric="legacy">$legacyDisplay</div><small>TLS 1.0 / 1.1 and SSL 2.0 / 3.0</small></div>
<div class="metric"><div class="metric-label">Unrecognized protocol</div><div class="metric-value" data-metric="unknown">$unknownDisplay</div><small>Not classified as modern or legacy</small></div>
</div>
$($notices -join '')
</section>
<section id="coverage"><h2>Collection coverage</h2><p class="muted">Collected = all returned events parsed. Partial = some rejected. ParseFailed = none parsed. NoEvents = no matching events. Failed = query or remoting error. None of these states certifies full retention.</p><div class="card">$coverageHtml</div></section>
<section id="protocols"><h2>Protocols &amp; cipher suites</h2><p class="muted">Protocol percentages use all $total parsed events as the denominator, including unrecognized protocol values.</p>
<div class="two-col global-grid"><div class="card"><h3>Protocol distribution</h3>$protocolHtml<div class="legend"><span><i class="dot tls13"></i>TLS 1.3</span><span><i class="dot tls12"></i>TLS 1.2</span><span><i class="dot legacy"></i>Legacy</span><span><i class="dot unknown"></i>Unrecognized</span></div></div>
<div class="card"><h3>Cipher suites</h3>$cipherHtml<p class="muted">Names describe observations, not a cryptographic compliance assessment. Unmapped identifiers remain visible as UNKNOWN.</p></div></div></section>
<section id="controllers"><h2>By domain controller</h2><p class="muted">Expand or collapse each DC. Protocol percentages are calculated within that DC's parsed events.</p><div class="dc-links">$($dcLinks -join '')</div>$($dcSections -join '')</section>
<section id="targets"><h2>Reported target names</h2><p class="muted">Showing $targetShown of $(@($Targets).Count) target groups, ranked by event count. Groups retain DC, reported type, target, protocol, and cipher suite. Use -ExportCsv to export all target groups; display limits do not change event totals.</p>
<div class="notice info"><strong>These are not an inbound LDAPS client inventory.</strong> A reported client type describes the DC acting as a TLS client. A target name is not necessarily a remote IP or an originating process.</div><div class="card">$targetHtml</div></section>
<section id="limits" class="limits"><h2>How to interpret this report</h2><ul>
<li>Only successful Schannel handshake events are included. Failed negotiations and other TLS implementations are outside this report.</li>
<li>A protocol not observed is not proven disabled or unused. No observations means no assessment, not a clean result.</li>
<li>Registry values show configured logging. Required reboots and complete System log retention are not verified.</li>
<li>The requested lookback is not proof of continuous coverage; long-lived connections may not produce a handshake in that window.</li>
<li>ExchangeStrength is not evaluated against a generic weak/strong threshold. No overall TLS compliance verdict is issued.</li>
</ul></section>
<footer class="footer">Standalone report / no external resources / generated from collected observations. Treat infrastructure names and diagnostic messages as sensitive operational data.</footer>
</main></body></html>
"@
}

# --- PHASE 1: Check EventLogging on each DC ---
Write-Host "`n[PHASE 1] Checking Schannel EventLogging level on each DC" -ForegroundColor Cyan

$schannelKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

$loggingStatus = @()

foreach ($dc in $DCs) {
    Write-Host " - $($dc): checking..." -ForegroundColor Gray
    try {
        $result = Invoke-Command -ComputerName $dc -ScriptBlock {
            param($schKey, $name)
            $key = Get-Item -LiteralPath $schKey -ErrorAction Stop
            $exists = $key.GetValueNames() -contains 'EventLogging'
            $value = $null
            if ($exists) {
                if ($key.GetValueKind('EventLogging') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
                    throw 'EventLogging is not a DWORD; review the registry configuration.'
                }
                $value = [int]$key.GetValue('EventLogging')
                if ($value -lt 0 -or $value -gt 7) {
                    throw "Unsupported EventLogging value: $value"
                }
            }

            [pscustomobject]@{
                DC                       = $name
                RegistryCheck            = 'Succeeded'
                EventLoggingSet          = $exists
                EventLogging             = $value
                SuccessLoggingConfigured = $exists -and (($value -band 4) -ne 0)
                ErrorMessage             = $null
            }
        } -ArgumentList $schannelKey, $dc -ErrorAction Stop

        $loggingStatus += $result
    }
    catch {
        Write-Warning "Unable to check logging on $($dc): $($_.Exception.Message)"
        $loggingStatus += [pscustomobject]@{
            DC                       = $dc
            RegistryCheck            = 'Failed'
            EventLoggingSet          = $null
            EventLogging             = $null
            SuccessLoggingConfigured = $null
            ErrorMessage             = $_.Exception.Message
        }
    }
}

Write-Host "`nSchannel EventLogging summary:" -ForegroundColor Cyan
$loggingStatus |
    Select-Object DC,RegistryCheck,EventLoggingSet,EventLogging,SuccessLoggingConfigured,ErrorMessage |
    Format-Table -AutoSize

$toFix = @($loggingStatus |
    Where-Object { $_.RegistryCheck -eq 'Succeeded' -and -not $_.SuccessLoggingConfigured })

if ($toFix.Count -gt 0) {
    Write-Warning 'Some DCs are not configured to log informational and success events.'
    $toFix | Select-Object DC,EventLoggingSet,EventLogging | Format-Table -AutoSize

    $answer = Read-Host "`nBack up previous settings and set EventLogging=7? Collection will NOT run; reboots are required. (Y/N)"
    if ($answer -match '^(y|yes|o|oui)$') {
        New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop | Out-Null
        $backupPath = Join-Path $OutDir 'Schannel_EventLogging_Before.clixml'
        $toFix |
            Select-Object DC,EventLoggingSet,EventLogging |
            Export-Clixml -LiteralPath $backupPath -NoClobber -ErrorAction Stop
        Write-Host "Previous settings saved to: $backupPath" -ForegroundColor Cyan

        foreach ($entry in $toFix) {
            $dc = $entry.DC
            Write-Host " -> Setting EventLogging=7 on $($dc)..." -ForegroundColor Gray
            try {
                Invoke-Command -ComputerName $dc -ScriptBlock {
                    param($schKey, $wasSet, $previousValue)
                    $key = Get-Item -LiteralPath $schKey -ErrorAction Stop
                    $exists = $key.GetValueNames() -contains 'EventLogging'
                    if ($exists -ne $wasSet -or
                        ($exists -and ($key.GetValueKind('EventLogging') -ne [Microsoft.Win32.RegistryValueKind]::DWord -or
                                       $key.GetValue('EventLogging') -ne $previousValue))) {
                        throw 'EventLogging changed since the check; refusing to overwrite it.'
                    }
                    New-ItemProperty -Path $schKey -Name 'EventLogging' -Value 7 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                } -ArgumentList $schannelKey, $entry.EventLoggingSet, $entry.EventLogging -ErrorAction Stop

                Write-Host "    EventLogging=7 written on $dc; reboot required." -ForegroundColor Yellow
            }
            catch {
                Write-Warning "Failed to set EventLogging on $($dc): $($_.Exception.Message)"
            }
        }
        Write-Warning 'Preparation ended without collection. Review failures, schedule controlled reboots, allow an observation period, then rerun the audit.'
        return
    }
    else {
        Write-Host "   (Registry has NOT been modified.)" -ForegroundColor DarkYellow
    }
}

Write-Warning 'Configured values do not prove active logging or complete retention. Missing events do not prove that a protocol is disabled or unused.'

# --- PHASE 2: Collect Schannel 36880 events in parallel ---
Write-Host "`n[PHASE 2] Collecting System / Schannel / 36880 events from DCs..." -ForegroundColor Cyan

$collection = @($DCs | ForEach-Object -Parallel {
    $dc = $_
    try {
        Invoke-Command -ComputerName $dc -ScriptBlock {
            param([int]$Hours, [string]$name)

            $since = (Get-Date).AddHours(-1 * $Hours)
            $fh = @{
                LogName      = 'System'
                Id           = 36880
                StartTime    = $since
                ProviderName = 'Schannel'
            }

            try {
                $events = @(Get-WinEvent -FilterHashtable $fh -ErrorAction Stop)
            }
            catch {
                if (($_.FullyQualifiedErrorId -split ',')[0] -eq 'NoMatchingEventsFound') {
                    $events = @()
                }
                else {
                    throw
                }
            }

            $list = New-Object System.Collections.Generic.List[object]
            $parseErrors = New-Object System.Collections.Generic.List[string]
            foreach ($ev in $events) {
                try {
                    $xml = [xml]$ev.ToXml()
                    $nodes = $xml.SelectNodes("/*[local-name()='Event']/*[local-name()='UserData']/*[local-name()='EventXML']/*")
                    if ($nodes.Count -eq 0) {
                        throw 'Unsupported event payload: expected UserData/EventXML.'
                    }
                    $fields = @{}
                    foreach ($node in $nodes) {
                        $fields[$node.LocalName] = $node.InnerText
                    }
                    if ([string]::IsNullOrWhiteSpace($fields['Protocol']) -or
                        [string]::IsNullOrWhiteSpace($fields['CipherSuite'])) {
                        throw 'Required Protocol or CipherSuite field is missing or empty.'
                    }
                    $list.Add([pscustomobject]@{
                        DC                    = $name
                        Time                  = $ev.TimeCreated
                        RecordId              = $ev.RecordId
                        EventId               = $ev.Id
                        Level                 = $ev.LevelDisplayName
                        Protocol              = $fields['Protocol'].Trim()
                        CipherSuiteHex        = $fields['CipherSuite'].Trim()
                        ExchangeStrength      = $fields['ExchangeStrength']
                        Type                  = $fields['Type']
                        TargetName            = $fields['TargetName']
                        LocalCertSubjectName  = $fields['LocalCertSubjectName']
                        RemoteCertSubjectName = $fields['RemoteCertSubjectName']
                    })
                }
                catch {
                    $parseErrors.Add("Record $($ev.RecordId): $($_.Exception.Message)")
                }
            }

            [pscustomobject]@{
                DC           = $name
                Status       = if ($events.Count -eq 0) { 'NoEvents' }
                               elseif ($list.Count -eq 0) { 'ParseFailed' }
                               elseif ($parseErrors.Count -gt 0) { 'Partial' }
                               else { 'Collected' }
                EventsRead   = $events.Count
                EventsParsed = $list.Count
                ParseErrors  = $parseErrors.Count
                ErrorMessage = $parseErrors -join '; '
                Events       = $list.ToArray()
            }
        } -ArgumentList $using:Hours, $dc -ErrorAction Stop
    }
    catch {
        [pscustomobject]@{
            DC           = $dc
            Status       = 'Failed'
            EventsRead   = $null
            EventsParsed = 0
            ParseErrors  = 0
            ErrorMessage = $_.Exception.Message
            Events       = @()
        }
    }
} -ThrottleLimit $ThrottleLimit)

Write-Host "`n=== Collection status per DC ===" -ForegroundColor Cyan
$collectionStatus = @($collection | Select-Object DC,Status,EventsRead,EventsParsed,ParseErrors,ErrorMessage)
$collectionStatus | Format-Table -AutoSize -Wrap
foreach ($result in $collectionStatus | Where-Object { $_.Status -in @('Failed','ParseFailed','Partial') }) {
    Write-Warning "$($result.DC): $($result.Status) - $($result.ErrorMessage)"
}

$eventsAll = @($collection | ForEach-Object { $_.Events })
if ($eventsAll.Count -eq 0) {
    Write-Warning 'No usable handshake observations. See per-DC status; no conclusion about protocol usage can be drawn.'
}

# Add human-readable cipher suite name
foreach ($e in $eventsAll) {
    $e | Add-Member -NotePropertyName CipherSuiteName -NotePropertyValue (Get-TlsCipherName -CipherHex $e.CipherSuiteHex) -Force
}

# --- Reporting: Protocol per DC ---
Write-Host "`n=== Protocol breakdown per DC ===" -ForegroundColor Cyan
$byDcProto = @($eventsAll |
    Group-Object DC,Protocol |
    ForEach-Object {
        [pscustomobject]@{
            DC       = $_.Group[0].DC
            Protocol = if ($_.Group[0].Protocol) { $_.Group[0].Protocol } else { '(n/a)' }
            Events   = $_.Count
        }
    } |
    Sort-Object DC,Protocol)

if ($byDcProto) {
    $byDcProto | Format-Table -AutoSize
}
else {
    Write-Host "(no usable events)" -ForegroundColor DarkGray
}

# --- Global Protocol breakdown ---
Write-Host "`n=== Global Protocol breakdown ===" -ForegroundColor Cyan
$byProto = @($eventsAll |
    Group-Object Protocol |
    ForEach-Object {
        [pscustomobject]@{
            Protocol = if ($_.Name) { $_.Name } else { '(n/a)' }
            Events   = $_.Count
        }
    } |
    Sort-Object Events -Descending)

$totalProto = ($byProto | Measure-Object Events -Sum).Sum
if ($totalProto -gt 0) {
    $byProto |
        Select-Object Protocol,Events,
            @{n='%';e={[math]::Round(100 * ($_.Events / $totalProto), 2)}} |
        Format-Table -AutoSize
}
else {
    Write-Host "(no usable events)" -ForegroundColor DarkGray
}

# --- Global CipherSuite breakdown ---
Write-Host "`n=== Global CipherSuite breakdown ===" -ForegroundColor Cyan
$byCipher = @($eventsAll |
    Group-Object CipherSuiteName |
    ForEach-Object {
        [pscustomobject]@{
            CipherSuiteName = $_.Name
            Events          = $_.Count
        }
    } |
    Sort-Object Events -Descending)

if ($byCipher) {
    $byCipher | Select-Object CipherSuiteName,Events -First 30 | Format-Table -AutoSize
    if ($byCipher.Count -gt 30) {
        Write-Host "... (only top 30 cipher suites displayed)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "(no usable cipher information)" -ForegroundColor DarkGray
}

# --- Legacy protocols (TLS 1.0 / 1.1 / SSL) ---
Write-Host "`n=== Legacy protocols (TLS 1.0 / 1.1 / SSL) ===" -ForegroundColor Yellow
$legacy = @($eventsAll |
    Where-Object {
        (Get-TlsProtocolCategory $_.Protocol) -eq 'legacy'
    })

if ($legacy) {
    $legacy |
        Group-Object DC,Protocol |
        ForEach-Object {
            [pscustomobject]@{
                DC       = $_.Group[0].DC
                Protocol = $_.Group[0].Protocol
                Events   = $_.Count
            }
        } |
        Sort-Object DC,Protocol |
        Format-Table -AutoSize
}
elseif ($eventsAll.Count -eq 0) {
    Write-Host "Legacy protocol assessment unavailable: no usable observations." -ForegroundColor Yellow
}
else {
    Write-Host "No legacy protocol names found in the usable observations. This does not prove they are disabled or unused." -ForegroundColor Yellow
}

$unknownProtocol = @($eventsAll | Where-Object {
    (Get-TlsProtocolCategory $_.Protocol) -eq 'unknown'
})
if ($unknownProtocol.Count -gt 0) {
    Write-Warning "$($unknownProtocol.Count) observation(s) have unrecognized protocol values; they are not classified as modern or legacy."
    $unknownProtocol | Group-Object DC,Protocol | Select-Object Name,Count | Format-Table -AutoSize
}

# --- Reported target names ---
Write-Host "`n=== Reported target names (not an inbound-client inventory) ===" -ForegroundColor Cyan
$byTarget = @($eventsAll |
    Where-Object { $_.TargetName } |
    Group-Object DC,Type,TargetName,Protocol,CipherSuiteName |
    ForEach-Object {
        [pscustomobject]@{
            DC              = $_.Group[0].DC
            Type            = $_.Group[0].Type
            TargetName      = $_.Group[0].TargetName
            Protocol        = if ($_.Group[0].Protocol) { $_.Group[0].Protocol } else { '(n/a)' }
            CipherSuiteName = $_.Group[0].CipherSuiteName
            Events          = $_.Count
        }
    } |
    Sort-Object Events -Descending)

if ($byTarget) {
    $byTarget |
        Select-Object DC,Type,TargetName,Protocol,CipherSuiteName,Events -First 30 |
        Format-Table -AutoSize
    if ($byTarget.Count -gt 30) {
        Write-Host "... (only top 30 target groups displayed)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "(no TargetName information available)" -ForegroundColor DarkGray
}

# --- Optional exports ---
if ($ExportCsv -or $HTMLReport) {
    New-Item -ItemType Directory -Force -Path $OutDir -ErrorAction Stop | Out-Null
}

if ($ExportCsv) {
    $loggingStatus |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Schannel_LoggingStatus.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $collectionStatus |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Schannel_CollectionStatus.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $eventsAll |
        Select-Object DC,Time,RecordId,EventId,Level,Protocol,
                      CipherSuiteHex,CipherSuiteName,
                      ExchangeStrength,Type,TargetName,
                      LocalCertSubjectName,RemoteCertSubjectName |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Schannel_36880_AllEvents.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $byProto |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Breakdown_Protocol.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $byCipher |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Breakdown_CipherSuite.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    $byTarget |
        Export-Csv -LiteralPath (Join-Path $OutDir 'Top_Targets.csv') -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

    Write-Host "`nCSV files exported to: $OutDir" -ForegroundColor Cyan
}

if ($HTMLReport) {
    $report = ConvertTo-TlsHtmlReport -Events $eventsAll -LoggingStatus $loggingStatus `
        -CollectionStatus $collectionStatus -DomainControllers $DCs `
        -ProtocolByDc @($byDcProto) -ProtocolBreakdown @($byProto) `
        -CipherBreakdown @($byCipher) -Targets @($byTarget) -Hours $Hours
    $reportPath = Join-Path $OutDir 'Schannel_TLS_Report.html'
    Set-Content -LiteralPath $reportPath -Value $report -Encoding UTF8 -ErrorAction Stop
    Write-Host "`nHTML report exported to: $reportPath" -ForegroundColor Cyan
}

Write-Host "`n=== Collection/reporting finished; review per-DC status and observation limits. No compliance verdict. ===" -ForegroundColor Cyan
```

![](<./assets/Audit and Track TLS Protocols and Cipher Suites on Domain Controllers/2026-01-29-16-00-11.png>)

The screenshot above illustrates an earlier script version; the corrected script's output differs. It is not a validation run of the corrected script.

---

## References

- [Schannel event 36880 (archived Microsoft documentation)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786445(v=ws.11)#event-id-36880-an-ssl-client-or-server-handshake-completed-successfully)
- [Schannel registry settings and logging levels](https://learn.microsoft.com/windows-server/security/tls/tls-registry-settings#schannel-logging)
- [TLS protocol version support in Schannel](https://learn.microsoft.com/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)
- [Schannel connection information and key lengths](https://learn.microsoft.com/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo)
- [IANA TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
- [TLS cipher suites in Windows](https://learn.microsoft.com/windows/win32/secauthn/cipher-suites-in-schannel)
