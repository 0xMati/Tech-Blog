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