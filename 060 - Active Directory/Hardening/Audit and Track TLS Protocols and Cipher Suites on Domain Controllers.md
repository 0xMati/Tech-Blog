# Audit and Track TLS Protocols and Cipher Suites on Domain Controllers
🗓️ Published: 2026-01-29

## Overview

While Kerberos encryption is often a primary focus when hardening Active Directory, **TLS usage on Domain Controllers is frequently overlooked**.

Domain Controllers rely heavily on **Schannel** for TLS communications, both inbound and outbound, including:
- LDAPS
- ADFS and federation scenarios
- Azure / Microsoft cloud agents
- Monitoring and security tooling
- Application integrations

This article introduces a **PowerShell 7 auditing approach** to **observe, analyze, and track TLS protocols and cipher suites actually used by Domain Controllers**, based on **real Schannel events**.

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

On Windows, TLS is implemented via **Schannel**, the Security Support Provider responsible for:
- TLS protocol negotiation
- Cipher suite selection
- Certificate validation

When **Schannel event logging** is enabled at a verbose level, Windows emits detailed events describing:
- TLS protocol version
- Cipher suite negotiated
- Key exchange strength
- Remote endpoint involved

These events are written to the **System event log**.

---

## Prerequisite: Enable Schannel Verbose Logging

TLS auditing relies on Schannel event **36880**.

This requires the following registry value on Domain Controllers:

```
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
  EventLogging (DWORD) = 7
```

This enables **verbose Schannel logging**.

The script provided in this article:
- Checks the current logging level on each DC
- Optionally enables verbose logging remotely if missing

> ⚠️ **Volume impact:** `EventLogging = 7` is the most verbose level and generates **one event per TLS handshake** on the System log. On busy DCs this can mean **thousands of events per hour**, accelerating log rotation and potentially overwriting other System events. Recommended approach:
>
> 1. Enable verbose logging only for the duration of the audit (e.g., 24 – 72 hours).
> 2. Optionally increase the System log max size (`wevtutil sl System /ms:524288000` = 500 MB).
> 3. Revert after collection: delete the `EventLogging` value (or set it back to `1`, the default).
>
> ```powershell
> # Revert after audit (run on each DC, or via Invoke-Command)
> Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
>                     -Name 'EventLogging' -ErrorAction SilentlyContinue
> ```

---

## Events Used for the Audit

The primary event used is:

- **Event ID:** 36880  
- **Log:** System  
- **Source:** Schannel  

This event provides, among others:
- `Protocol` (TLS 1.2, TLS 1.3, etc.)
- `CipherSuite` (hexadecimal identifier)
- `ExchangeStrength`
- `TargetName`
- Certificate information

> **Cipher suite name mapping:** the script includes a small built-in lookup table covering the most common modern suites (ECDHE-AES-GCM for TLS 1.2 and the three standard TLS 1.3 suites). Unknown suites are displayed as `UNKNOWN (0xXXXX)` — cross-reference them with the [IANA TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) for exhaustive coverage.

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
- TLS protocol versions actually negotiated
- Cipher suites resolved to human-readable names
- TLS 1.2 and TLS 1.3 supported

### Security Analysis
- Detection of legacy protocols (TLS 1.0 / 1.1 / SSL)
- Detection of weak key exchange strengths

### Endpoint Awareness
- Identification of remote services talking TLS with DCs

---

## CSV Export

The script supports CSV export for offline analysis:

```
.\SchannelAuditing.ps1 -ExportCsv
```

Generated files:
- `Schannel_36880_AllEvents.csv`
- `Breakdown_Protocol.csv`
- `Breakdown_CipherSuite.csv`
- `Top_Targets.csv`

---

## What This Script Is Not

This tool does **not enforce** TLS configuration or cipher suite ordering.

It is intentionally:
- Read-only
- Safe for production
- Audit-focused

---

## Conclusion

TLS security on Domain Controllers is **observable, measurable, and auditable**.
Before enforcing TLS hardening, **measure real usage**.

---

## Powershell Script

>> Edit your DCs list !


```powershell
#requires -Version 7.0
<#
TLS / Schannel Cipher Audit on Domain Controllers
-------------------------------------------------
- Check TLS tracing level (Schannel EventLogging = 7) on each DC
- Optionally set EventLogging = 7 remotely if missing or not verbose
- Collect System / Schannel / 36880 events in parallel across DCs for the last X hours
- Produce console reporting on:
    * Protocol (TLS 1.0/1.1/1.2/1.3, SSL, etc.)
    * CipherSuite (hex + readable name when known)
    * ExchangeStrength
    * Top TLS endpoints (TargetName / Protocol / CipherSuite)
- Optional CSV export for further analysis

Prerequisites:
- PowerShell 7 on the admin machine
- PowerShell Remoting enabled to the DCs
- Administrative rights on DCs
#>

param(
    [int]$Hours = 24,
    [int]$ThrottleLimit = 8,
    [switch]$ExportCsv,
    [string]$OutDir = (Join-Path $PWD ("TLS_Audit_{0:yyyyMMdd_HHmmss}" -f (Get-Date)))
)

cls
Write-Host "=== TLS / Schannel Cipher Audit on Domain Controllers ===" -ForegroundColor Cyan
Write-Host "Time window: last $Hours hours" -ForegroundColor Gray

# --- Domain Controllers (edit here if needed) ---
$DCs = @(
    'MM-DC1.mathiasmotron.com',
    'MM-DC2.mathiasmotron.com',
    'MM-DC3.mathiasmotron.com'
)

if (-not $DCs -or $DCs.Count -eq 0) {
    Write-Error "No DCs defined in the `$DCs list."
    return
}

# --- Helper: map cipher suite hex -> human-readable name (extended with TLS 1.3) ---
function Get-TlsCipherName {
    param(
        [string]$CipherHex
    )

    if (-not $CipherHex) {
        return "UNKNOWN"
    }

    # Normalize input: "0xc030" / "C030" / "49168"
    $hex =
        if ($CipherHex -match '^0x[0-9A-Fa-f]+$') {
            $CipherHex.ToLower()
        }
        elseif ($CipherHex -match '^[0-9]+$') {
            # Decimal -> hex
            ('0x{0:X4}' -f [int]$CipherHex).ToLower()
        }
        elseif ($CipherHex -match '^[0-9A-Fa-f]+$') {
            ('0x{0}' -f $CipherHex).ToLower()
        }
        else {
            $CipherHex
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

# --- PHASE 1: Check EventLogging on each DC ---
Write-Host "`n[PHASE 1] Checking Schannel EventLogging level on each DC" -ForegroundColor Cyan

$schannelKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

$loggingStatus = @()

foreach ($dc in $DCs) {
    Write-Host " - $($dc): checking..." -ForegroundColor Gray
    try {
        $result = Invoke-Command -ComputerName $dc -ScriptBlock {
            param($schKey)
            $value       = $null
            $exists      = $false
            $isVerbose   = $false

            if (Test-Path $schKey) {
                try {
                    $reg = Get-ItemProperty -Path $schKey -Name 'EventLogging' -ErrorAction SilentlyContinue
                    if ($reg -ne $null -and $reg.EventLogging -ne $null) {
                        $value = [int]$reg.EventLogging
                        $exists = $true
                        if ($value -eq 7) {
                            $isVerbose = $true
                        }
                    }
                } catch {
                    # handled below
                }
            }

            [pscustomobject]@{
                DC              = $env:COMPUTERNAME
                Reachable       = $true
                EventLoggingSet = $exists
                EventLogging    = $(if ($exists) { $value } else { $null })
                IsVerbose       = $isVerbose
            }
        } -ArgumentList $schannelKey -ErrorAction Stop

        $loggingStatus += $result
    }
    catch {
        Write-Host "   ❌ Unable to contact $($dc): $($_.Exception.Message)" -ForegroundColor Red
        $loggingStatus += [pscustomobject]@{
            DC              = $dc
            Reachable       = $false
            EventLoggingSet = $false
            EventLogging    = $null
            IsVerbose       = $false
        }
    }
}

Write-Host "`nSchannel EventLogging summary:" -ForegroundColor Cyan
$loggingStatus |
    Select-Object DC,Reachable,EventLoggingSet,EventLogging,
        @{n='Status';e={
            if (-not $_.Reachable) { 'UNREACHABLE' }
            elseif ($_.IsVerbose)  { 'OK (7 - verbose)' }
            elseif ($_.EventLoggingSet) { "NON-VERBOSE ($($_.EventLogging))" }
            else { 'NOT CONFIGURED' }
        }} |
    Format-Table -AutoSize

$toFix = $loggingStatus |
    Where-Object { $_.Reachable -and -not $_.IsVerbose }

if ($toFix) {
    Write-Host "`nWARNING: some DCs do not have EventLogging=7 (verbose)." -ForegroundColor Yellow
    $toFix | Select-Object DC,EventLoggingSet,EventLogging | Format-Table -AutoSize

    $answer = Read-Host "`nDo you want to set EventLogging=7 (verbose) on these DCs? (Y/N)"
    if ($answer -match '^(y|yes|o|oui)$') {
        foreach ($entry in $toFix) {
            $dc = $entry.DC
            Write-Host " -> Setting EventLogging=7 on $($dc)..." -ForegroundColor Gray
            try {
                Invoke-Command -ComputerName $dc -ScriptBlock {
                    param($schKey)
                    if (-not (Test-Path $schKey)) {
                        New-Item -Path $schKey -Force | Out-Null
                    }
                    New-ItemProperty -Path $schKey -Name 'EventLogging' -Value 7 -PropertyType DWord -Force | Out-Null
                } -ArgumentList $schannelKey -ErrorAction Stop

                Write-Host "    ✅ EventLogging=7 set on $($dc)" -ForegroundColor Green
            }
            catch {
                Write-Host "    ❌ Failed to set EventLogging on $($dc): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "   (Registry has NOT been modified.)" -ForegroundColor DarkYellow
    }
}
else {
    Write-Host "`nAll DCs already have EventLogging=7 (verbose)." -ForegroundColor Green
}

# --- PHASE 2: Collect Schannel 36880 events in parallel ---
Write-Host "`n[PHASE 2] Collecting System / Schannel / 36880 events from DCs..." -ForegroundColor Cyan

$all = $DCs | ForEach-Object -Parallel {
    $dc = $_
    try {
        Invoke-Command -ComputerName $dc -ScriptBlock {
            param([int]$Hours)

            $since = (Get-Date).AddHours(-1 * $Hours)
            $fh = @{
                LogName      = 'System'
                Id           = 36880     # TLS client/server details
                StartTime    = $since
                ProviderName = 'Schannel'
            }

            function Parse-SchEvent {
                param(
                    [System.Diagnostics.Eventing.Reader.EventRecord]$Event
                )

                $xml = [xml]$Event.ToXml()

                # Extract fields from UserData/EventXML (namespace LSA_NS)
                $type                  = $null
                $protocol              = $null
                $cipherSuite           = $null
                $exchangeStrength      = $null
                $targetName            = $null
                $localCertSubjectName  = $null
                $remoteCertSubjectName = $null

                try {
                    # In most cases direct access works even with the namespace
                    $ud = $xml.Event.UserData.EventXML
                    if ($ud -ne $null) {
                        $type                  = $ud.Type
                        $protocol              = $ud.Protocol
                        $cipherSuite           = $ud.CipherSuite
                        $exchangeStrength      = $ud.ExchangeStrength
                        $targetName            = $ud.TargetName
                        $localCertSubjectName  = $ud.LocalCertSubjectName
                        $remoteCertSubjectName = $ud.RemoteCertSubjectName
                    }
                }
                catch {
                    # Fallback with XmlNamespaceManager could be added here if needed
                }

                [pscustomobject]@{
                    DC                    = $env:COMPUTERNAME
                    Time                  = $Event.TimeCreated
                    EventId               = $Event.Id
                    Level                 = $Event.LevelDisplayName
                    Protocol              = $protocol
                    CipherSuiteHex        = $cipherSuite
                    ExchangeStrength      = $exchangeStrength
                    Type                  = $type
                    TargetName            = $targetName
                    LocalCertSubjectName  = $localCertSubjectName
                    RemoteCertSubjectName = $remoteCertSubjectName
                }
            }

            $list = New-Object System.Collections.Generic.List[object]
            $events = Get-WinEvent -FilterHashtable $fh -ErrorAction SilentlyContinue
            if ($events) {
                foreach ($ev in $events) {
                    $list.Add( (Parse-SchEvent -Event $ev) ) | Out-Null
                }
            }

            $list
        } -ArgumentList $using:Hours -ErrorAction Stop
    }
    catch {
        # DC unreachable during event collection
        [pscustomobject]@{
            DC                    = $dc
            Time                  = Get-Date
            EventId               = '(n/a)'
            Level                 = 'Error'
            Protocol              = $null
            CipherSuiteHex        = '(unreachable)'
            ExchangeStrength      = $null
            Type                  = $null
            TargetName            = $null
            LocalCertSubjectName  = $null
            RemoteCertSubjectName = $null
        }
    }
} -ThrottleLimit $ThrottleLimit

# Flatten collection
$eventsAll = foreach ($chunk in $all) {
    if ($chunk -is [System.Collections.IEnumerable]) { $chunk } else { ,$chunk }
}

if (-not $eventsAll -or $eventsAll.Count -eq 0) {
    Write-Host "`nNo Schannel 36880 events found in the selected time window." -ForegroundColor Yellow
    return
}

# Add human-readable cipher suite name
foreach ($e in $eventsAll) {
    if ($e.CipherSuiteHex -and $e.CipherSuiteHex -ne '(unreachable)') {
        $e | Add-Member -NotePropertyName CipherSuiteName -NotePropertyValue (Get-TlsCipherName -CipherHex $e.CipherSuiteHex) -Force
    }
    else {
        $e | Add-Member -NotePropertyName CipherSuiteName -NotePropertyValue 'UNKNOWN' -Force
    }
}

# --- Reporting: Protocol per DC ---
Write-Host "`n=== Protocol breakdown per DC ===" -ForegroundColor Cyan
$byDcProto = $eventsAll |
    Where-Object { $_.CipherSuiteHex -ne '(unreachable)' } |
    Group-Object DC,Protocol |
    ForEach-Object {
        [pscustomobject]@{
            DC       = $_.Group[0].DC
            Protocol = if ($_.Group[0].Protocol) { $_.Group[0].Protocol } else { '(n/a)' }
            Events   = $_.Count
        }
    } |
    Sort-Object DC,Protocol

if ($byDcProto) {
    $byDcProto | Format-Table -AutoSize
}
else {
    Write-Host "(no usable events)" -ForegroundColor DarkGray
}

# --- Global Protocol breakdown ---
Write-Host "`n=== Global Protocol breakdown ===" -ForegroundColor Cyan
$byProto = $eventsAll |
    Where-Object { $_.CipherSuiteHex -ne '(unreachable)' } |
    Group-Object Protocol |
    ForEach-Object {
        [pscustomobject]@{
            Protocol = if ($_.Name) { $_.Name } else { '(n/a)' }
            Events   = $_.Count
        }
    } |
    Sort-Object Events -Descending

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
$byCipher = $eventsAll |
    Where-Object { $_.CipherSuiteHex -ne '(unreachable)' } |
    Group-Object CipherSuiteName |
    ForEach-Object {
        [pscustomobject]@{
            CipherSuiteName = $_.Name
            Events          = $_.Count
        }
    } |
    Sort-Object Events -Descending

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
$legacy = $eventsAll |
    Where-Object {
        $_.Protocol -in @('TLS 1.0','TLS 1.1','SSL 3.0','SSL 2.0')
    }

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
else {
    Write-Host "No TLS 1.0 / 1.1 / SSL events detected in the selected time window. (Good news.)" -ForegroundColor Green
}

# --- Weak ExchangeStrength (< 128 bits) ---
Write-Host "`n=== Connections with weak ExchangeStrength (< 128 bits) ===" -ForegroundColor Yellow
$weakExch = $eventsAll |
    Where-Object {
        $_.ExchangeStrength -and [int]$_.ExchangeStrength -lt 128
    }

if ($weakExch) {
    $weakExch |
        Select-Object DC,Time,Protocol,CipherSuiteName,ExchangeStrength,TargetName -First 50 |
        Format-Table -AutoSize
    if ($weakExch.Count -gt 50) {
        Write-Host "... (only first 50 records displayed)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "No connections with ExchangeStrength < 128 bits detected." -ForegroundColor Green
}

# --- Top TLS endpoints (TargetName) ---
Write-Host "`n=== Top TLS endpoints (TargetName / Protocol / CipherSuite) ===" -ForegroundColor Cyan
$byTarget = $eventsAll |
    Where-Object { $_.CipherSuiteHex -ne '(unreachable)' -and $_.TargetName } |
    Group-Object TargetName,Protocol,CipherSuiteName |
    ForEach-Object {
        [pscustomobject]@{
            TargetName      = $_.Group[0].TargetName
            Protocol        = if ($_.Group[0].Protocol) { $_.Group[0].Protocol } else { '(n/a)' }
            CipherSuiteName = $_.Group[0].CipherSuiteName
            Events          = $_.Count
        }
    } |
    Sort-Object Events -Descending

if ($byTarget) {
    $byTarget |
        Select-Object TargetName,Protocol,CipherSuiteName,Events -First 30 |
        Format-Table -AutoSize
    if ($byTarget.Count -gt 30) {
        Write-Host "... (only top 30 endpoints displayed)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "(no TargetName information available)" -ForegroundColor DarkGray
}

# --- Optional CSV export ---
if ($ExportCsv) {
    if (-not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    }

    $eventsAll |
        Select-Object DC,Time,EventId,Level,Protocol,
                      CipherSuiteHex,CipherSuiteName,
                      ExchangeStrength,Type,TargetName,
                      LocalCertSubjectName,RemoteCertSubjectName |
        Export-Csv -Path (Join-Path $OutDir 'Schannel_36880_AllEvents.csv') -NoTypeInformation -Encoding UTF8

    $byProto |
        Export-Csv -Path (Join-Path $OutDir 'Breakdown_Protocol.csv') -NoTypeInformation -Encoding UTF8

    $byCipher |
        Export-Csv -Path (Join-Path $OutDir 'Breakdown_CipherSuite.csv') -NoTypeInformation -Encoding UTF8

    if ($byTarget) {
        $byTarget |
            Export-Csv -Path (Join-Path $OutDir 'Top_Targets.csv') -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`nCSV files exported to: $OutDir" -ForegroundColor Cyan
}

Write-Host "`n=== TLS / Schannel audit completed ===" -ForegroundColor Cyan
```

![](<./assets/Audit and Track TLS Protocols and Cipher Suites on Domain Controllers/2026-01-29-16-00-11.png>)

![](<./assets/Audit and Track TLS Protocols and Cipher Suites on Domain Controllers/2026-01-29-16-00-34.png>)

---

## References

- [Schannel events (Microsoft Learn)](https://learn.microsoft.com/windows/win32/secauthn/schannel-events)
- [Manage TLS — Schannel registry entries](https://learn.microsoft.com/windows-server/security/tls/manage-tls)
- [IANA TLS Cipher Suite Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
- [TLS cipher suites in Windows](https://learn.microsoft.com/windows/win32/secauthn/cipher-suites-in-schannel)
