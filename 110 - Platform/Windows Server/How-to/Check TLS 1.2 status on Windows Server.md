---
title: "Check TLS 1.2 status on Windows Server"
date: 2025-09-30
---

# Check TLS 1.2 status on Windows Server

## PowerShell Script

### Why TLS 1.2 matters
TLS 1.2 is the minimum you should target for modern Windows workloads and Microsoft cloud endpoints. Older protocol versions (TLS 1.0/1.1) are deprecated and often blocked by security baselines and compliance rules.

### What you actually need to check
On Windows there are two layers: the OS crypto stack (SChannel) and the app runtime (for Entra ID Connect, that’s .NET Framework). It’s not enough to flip a registry key—you also want .NET to prefer strong protocols/suites and to confirm a real handshake works.

### What this script does
The script prints the SChannel state for TLS 1.2 (client/server), reads the .NET “strong crypto” flags, and performs a real TLS 1.2 handshake against login.microsoftonline.com. Run it in PowerShell 5.1 x64 to mirror Entra ID Connect’s runtime. Console-only output—perfect for quick audits or post-hardening validation.

---

## Context

```powershell
#requires -Version 5.1
param(
  [string]$TargetHost = 'login.microsoftonline.com'
)
cls
$ErrorActionPreference = 'Stop'

function Get-SChannelTls12Status {
  param([ValidateSet('Client','Server')]$Role)

  $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$Role"
  $exists = Test-Path $p
  $Enabled = $null; $DisabledByDefault = $null; $effective = $null

  if ($exists) {
    $v = Get-ItemProperty $p -ErrorAction SilentlyContinue
    $Enabled = $v.Enabled
    $DisabledByDefault = $v.DisabledByDefault

    # Any non-zero Enabled value (including 0xFFFFFFFF) means Enabled
    $enabledNonZero = $false
    try { $enabledNonZero = ([int64]$Enabled) -ne 0 } catch { $enabledNonZero = $false }

    if ($enabledNonZero -and ([int64]$DisabledByDefault) -eq 0) {
      $effective = 'Enabled'
    }
    elseif (([int64]$Enabled) -eq 0 -or ([int64]$DisabledByDefault) -eq 1) {
      $effective = 'Disabled'
    }
    else {
      $effective = 'OS default (partial/missing values)'
    }
  }
  else {
    $effective = 'OS default (no explicit key)'
  }

  [pscustomobject]@{
    Role              = $Role
    Path              = $p
    Exists            = $exists
    Enabled           = $Enabled
    DisabledByDefault = $DisabledByDefault
    Effective         = $effective
  }
}

function Get-DotNetCryptoFlags {
  $keys = @(
    'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
  )
  foreach ($k in $keys) {
    if (Test-Path $k) {
      $v = Get-ItemProperty $k -ErrorAction SilentlyContinue
      [pscustomobject]@{
        Path                     = $k
        SchUseStrongCrypto       = $v.SchUseStrongCrypto
        SystemDefaultTlsVersions = $v.SystemDefaultTlsVersions
      }
    } else {
      [pscustomobject]@{
        Path                     = $k
        SchUseStrongCrypto       = $null
        SystemDefaultTlsVersions = $null
      }
    }
  }
}

function Test-Tls12Handshake {
  param([string]$TargetHost)
  $result = [ordered]@{
    Target       = $TargetHost
    Success      = $false
    Negotiated   = $null
    CipherSuite  = $null
    Error        = $null
    DurationMs   = $null
  }

  $tcp = $null; $ssl = $null
  $sw = [Diagnostics.Stopwatch]::StartNew()
  try {
    $tcp = New-Object Net.Sockets.TcpClient
    $tcp.Connect($TargetHost, 443)

    # Simplified cert validation (accept all) - validates protocol negotiation, not certificate trust
    $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
    $ssl.AuthenticateAsClient(
      $TargetHost,
      $null,
      [System.Security.Authentication.SslProtocols]::Tls12,
      $false
    )

    $sw.Stop()
    $result.Success    = $true
    $result.Negotiated = "$($ssl.SslProtocol)"
    try { $result.CipherSuite = "$($ssl.NegotiatedCipherSuite)" } catch { $result.CipherSuite = $null }
  } catch {
    $sw.Stop()
    $result.Error = $_.Exception.Message
  } finally {
    if ($ssl) { $ssl.Dispose() }
    if ($tcp) { $tcp.Dispose() }
  }

  $result.DurationMs = [int]$sw.ElapsedMilliseconds
  [pscustomobject]$result
}

# -------- Console report --------
Write-Host "=== TLS 1.2 - Quick report ===" -ForegroundColor Cyan
Write-Host ("Process: PowerShell {0} (x64:{1})" -f $PSVersionTable.PSVersion, [Environment]::Is64BitProcess)
Write-Host ("SecurityProtocol (process) : {0}" -f [Net.ServicePointManager]::SecurityProtocol)
Write-Host ""

Write-Host "1) SChannel (OS level) - TLS 1.2" -ForegroundColor Yellow
$sch = @(
  Get-SChannelTls12Status -Role Client
  Get-SChannelTls12Status -Role Server
)
$sch | Format-Table Role,Exists,Enabled,DisabledByDefault,Effective -AutoSize
Write-Host ""

Write-Host "2) .NET Framework flags" -ForegroundColor Yellow
Get-DotNetCryptoFlags | Format-Table Path,SchUseStrongCrypto,SystemDefaultTlsVersions -AutoSize
Write-Host ""

Write-Host ("3) Real TLS 1.2 handshake to {0}:443" -f $TargetHost) -ForegroundColor Yellow
Test-Tls12Handshake -TargetHost $TargetHost | Format-List
```

![](<./assets/Check TLS 1.2 status on Windows Server/2025-09-30-14-21-27.png>)

## AD FS and WAP: identify the tested TLS hop

The script above is a quick local configuration and **outbound TLS 1.2 negotiation** check. Its default destination is a Microsoft sign-in endpoint, not the local AD FS listener. Success against that destination does not establish that an external browser can authenticate through WAP.

| Connection being investigated | TLS client | TLS server |
|---|---|---|
| External browser to the federation proxy | Browser | WAP |
| WAP to the federation service | WAP | AD FS |
| Direct intranet browser to federation | Browser | AD FS |
| AD FS or an agent connecting to a cloud endpoint | The originating service/process | The selected cloud endpoint |

One Windows server can act as a TLS client and a TLS server at the same time. Check the Schannel **Client** or **Server** policy for the actual hop. .NET Framework preferences apply to relevant applications using that runtime; they are not a universal control for every Windows TLS consumer or every HTTP.sys listener.

### What the current probe does and does not validate

- It forces **TLS 1.2** for one connection from this PowerShell process. It does not enumerate all protocols or cipher suites the destination accepts.
- Its certificate callback deliberately accepts every certificate, and revocation checking is not enabled. `Success = True` therefore does **not** validate hostname, trust chain or revocation. It is not a model for application certificate validation.
- A failed handshake can reflect the probing client's OS/runtime, cipher overlap, DNS, route, SNI, intermediary or destination. It is not automatically proof that TLS 1.2 is disabled on the server.
- The .NET Framework runtime may not expose `NegotiatedCipherSuite`; an empty value is not proof that no cipher was negotiated.
- The registry `Effective` column is a heuristic, not a full resolver of OS defaults. Inspect the raw values: **missing/null settings are not explicit zero values**. For absent or partial configuration, check the installed OS defaults and actual application behavior.

For federation tests, retain the real DNS hostname and SNI. An IP-address URL can select another binding and cannot validate the intended DNS identity. A node-specific route test must preserve the federation hostname and normal certificate validation. The PowerShell process's route and proxy context can also differ from those of the WAP or AD FS service.

AD FS requirements do not support terminating federation TLS at the load balancer. A successful handshake with an intermediary says nothing by itself about its separate backend connection. See the [EPA and channel-binding note](../../../070%20-%20ADFS/Concepts/AD%20FS%20Extended%20Protection%20and%20Channel%20Binding.md) for the related authentication constraints.

### Interpret Schannel events in their actual role

Read the event text and XML, not just the ID. A **36880** event saying "A TLS client handshake completed successfully" describes an outbound client connection. If its target is a telemetry endpoint, it is not evidence of inbound AD FS traffic. Keep machine, process/context where available, target and time together.

![Historical Schannel 36880 event explicitly identifying a TLS client handshake](<./assets/Check TLS 1.2 status on Windows Server/historical-schannel-tls-client-event.png>)

*Historical event capture with connection-specific fields removed. The message identifies a TLS client handshake; the displayed protocol and cipher describe that connection, not every protocol accepted by an AD FS listener.*

This additional Windows PowerShell 5.1 example reads only recent local System/Schannel events. It does not change the logging level and refuses a truncated result:

```powershell
$endTime = Get-Date
$startTime = $endTime.AddMinutes(-10)
$schannelEvents = @()
try {
  $schannelEvents = @(Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Schannel'
    StartTime = $startTime
    EndTime = $endTime
  } -MaxEvents 201 -ErrorAction Stop)
}
catch {
  if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
if ($schannelEvents.Count -gt 200) {
  throw 'More than 200 events: narrow the interval before drawing conclusions.'
}
$schannelEvents | Sort-Object TimeCreated |
  Select-Object TimeCreated, MachineName, Id, RecordId, Message
```

These messages are for local investigation and can contain endpoint names or other sensitive context. No events can mean that the selected events were not emitted or retained, the wrong node/window was queried, or the application uses another TLS stack. It is not proof that TLS is unused or secure.

If extra Schannel logging is needed, record whether `EventLogging` existed and its exact value, use the documented logging level for a bounded reproduction, and account for the documented restart requirement. Restore the previous value or absence afterward. Informational logging can be noisy and is not a complete per-connection inventory on every Windows release.

### Keep historical hardening recipes version-scoped

Do not copy old SSL 3.0, RC4 or DHE registry bundles, IIS Crypto presets or hexadecimal key-length values into an AD FS farm as a single repair. Check the exact OS-supported policy, effective cipher configuration and dependent clients. For example, hexadecimal `0x320` is decimal **800**, not a 2048-bit requirement.

An external scanner observes the endpoint it reaches. Its grade does not inspect WAP-to-AD FS traffic, outbound dependencies or all load-balanced nodes. Verify intended protocol/cipher availability and real sign-in paths after a targeted change, with a recorded return path.

The existing [TLS audit and enforcement guide](../../../060%20-%20Active%20Directory/Hardening/Audit%20and%20Enforcement%20for%20TLS%20SSL%20Schannel%20and%20.NET%20Strong%20Crypto.md) and [domain-controller TLS observation guide](../../../060%20-%20Active%20Directory/Hardening/Audit%20and%20Track%20TLS%20Protocols%20and%20Cipher%20Suites%20on%20Domain%20Controllers.md) cover the broader work. Their host role and observation scope still matter when applying the same reasoning to federation servers.

## References

- [Microsoft Learn: Schannel TLS registry settings](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)
- [Microsoft Learn: Enable Schannel event logging](https://learn.microsoft.com/en-us/troubleshoot/developer/webapps/iis/health-diagnostic-performance/enable-schannel-event-logging)
- [Microsoft Learn: AD FS certificate, network and load-balancer requirements](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-requirements)