# Audit and Enforcement for TLS SSL Schannel and .NET Strong Crypto
🗓️ Published: 2025-12-03

## Introduction

This PowerShell 5.1 script audits Schannel TLS/SSL settings (TLS 1.0/1.1/1.2 for Server & Client roles) and .NET Strong Crypto on a fixed list of domain controllers. It’s read-only: perfect for security assessments before enforcing remediation via GPO.

**What it does**

- Reads registry keys for Schannel protocols and derives an Effective state (Enabled / Disabled / NotConfigured / Mixed).
- Checks .NET SystemDefaultTlsVersions and SchUseStrongCrypto (x64 + WOW6432Node).
- Adds a per-item Compliance status (Compliant / Warning / Failed), prints a colored view, and a summary per DC.

**Why it’s useful**
- Quickly confirms if TLS 1.0/1.1 are still permitted and TLS 1.2 is explicit.
- Highlights legacy .NET defaults that can break when disabling old TLS versions.

**Prereqs**
- Windows PowerShell 5.1
- PowerShell Remoting enabled to the DCs
- Run as an account with remote registry read permissions on the DCs

**Usage**
- Edit the embedded $dcs list, then run the script from an admin PowerShell session.
- Remediation is not performed here—apply via GPO (Registry GPP) once the audit is green.

## PS Script

```powershell
<#
Audit TLS/SSL Schannel (TLS 1.0/1.1/1.2 – Server & Client) + .NET Strong Crypto
- PowerShell 5.1
- Embedded DC list
- Pretty tables + compliance status + colored output
- Read-only (no changes) — remediation via GPO
#>
cls
# --- Embedded DC list ---
$dcs = @(
  'MM-DC1.mathiasmotron.com',
  'MM-DC2.mathiasmotron.com',
  'MM-DC3.mathiasmotron.com'
)

# --- Include .NET Strong Crypto checks (advisory) ---
$IncludeDotNet = $true

# --- Remote script executed on each DC (reads local registry only) ---
$remoteScript = {
  param([bool]$IncludeDotNetInner)

  function Get-RegValueLocal {
    param([string]$Path,[string]$Name)
    if (Test-Path -Path $Path) {
      try   { (Get-ItemProperty -Path $Path -ErrorAction Stop).$Name }
      catch { $null }
    } else { $null }
  }

  $results = New-Object System.Collections.Generic.List[object]

  # Collect Schannel protocol states for TLS 1.0/1.1/1.2 (Server & Client)
  $protocols = @('TLS 1.0','TLS 1.1','TLS 1.2')
  $roles     = @('Server','Client')
  foreach ($proto in $protocols) {
    foreach ($role in $roles) {
      $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\Protocols\$proto\$role"
      $enabled           = Get-RegValueLocal -Path $base -Name 'Enabled'
      $disabledByDefault = Get-RegValueLocal -Path $base -Name 'DisabledByDefault'

      # Derive effective state
      # - Enabled=1                          => Enabled
      # - Enabled=0 AND DisabledByDefault=1 => Disabled
      # - Keys absent                        => NotConfigured (OS defaults apply)
      # - Any other combination              => Mixed/Custom (e.g., 0xFFFFFFFF)
      $effective = 'NotConfigured'
      if ($enabled -eq 1) {
        $effective = 'Enabled'
      } elseif ($enabled -eq 0 -and $disabledByDefault -eq 1) {
        $effective = 'Disabled'
      } elseif (($enabled -ne $null) -or ($disabledByDefault -ne $null)) {
        $effective = 'Mixed/Custom'
      }

      $results.Add([pscustomobject]@{
        ComputerName       = $env:COMPUTERNAME
        Category           = 'Schannel'
        Protocol           = $proto
        Role               = $role
        Enabled            = $(if($enabled -ne $null){$enabled}else{'(absent)'})
        DisabledByDefault  = $(if($disabledByDefault -ne $null){$disabledByDefault}else{'(absent)'})
        EffectiveState     = $effective
        Path               = $base
        Key                = ''
        Value              = ''
      })
    }
  }

  # Collect .NET Strong Crypto advisory settings (x64 + WOW6432Node)
  if ($IncludeDotNetInner) {
    $dotNetPaths = @(
      'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727',
      'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727',
      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )
    $keys = @('SystemDefaultTlsVersions','SchUseStrongCrypto')
    foreach ($p in $dotNetPaths) {
      foreach ($k in $keys) {
        $val = Get-RegValueLocal -Path $p -Name $k
        $results.Add([pscustomobject]@{
          ComputerName       = $env:COMPUTERNAME
          Category           = '.NET'
          Protocol           = '(n/a)'
          Role               = '(n/a)'
          Enabled            = '(n/a)'
          DisabledByDefault  = '(n/a)'
          EffectiveState     = '(n/a)'
          Path               = $p
          Key                = $k
          Value              = $(if($val -ne $null){$val}else{'(absent)'})
        })
      }
    }
  }

  return $results
}

# --- Execute against each DC ---
$raw = @()
foreach ($dc in $dcs) {
  try {
    $out = Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ArgumentList $IncludeDotNet -ErrorAction Stop
    $raw += $out
  } catch {
    $raw += [pscustomobject]@{
      ComputerName       = $dc
      Category           = 'ERROR'
      Protocol           = '(n/a)'
      Role               = '(n/a)'
      Enabled            = '(n/a)'
      DisabledByDefault  = '(n/a)'
      EffectiveState     = 'Unreachable/AccessDenied'
      Path               = '(n/a)'
      Key                = '(n/a)'
      Value              = '(n/a)'
      Error              = $_.Exception.Message
    }
  }
}

# --- Compliance evaluation ---
# Rules:
# - Schannel TLS 1.0/1.1: Disabled => Compliant ; Enabled => Failed ; else Warning
# - Schannel TLS 1.2    : Enabled  => Compliant ; Disabled => Failed ; else Warning
# - .NET (advisory)     : Value==1 => Compliant ; else Warning
# - ERROR               : Failed
$withStatus = foreach ($r in $raw) {
  $status = 'Warning'
  if ($r.Category -eq 'Schannel') {
    if ($r.Protocol -in @('TLS 1.0','TLS 1.1')) {
      if     ($r.EffectiveState -eq 'Disabled') { $status = 'Compliant' }
      elseif ($r.EffectiveState -eq 'Enabled')  { $status = 'Failed' }
      else  { $status = 'Warning' }
    } elseif ($r.Protocol -eq 'TLS 1.2') {
      if     ($r.EffectiveState -eq 'Enabled')  { $status = 'Compliant' }
      elseif ($r.EffectiveState -eq 'Disabled') { $status = 'Failed' }
      else  { $status = 'Warning' }
    } else {
      $status = 'Warning'
    }
  } elseif ($r.Category -eq '.NET') {
    if ($r.Value -eq 1) { $status = 'Compliant' } else { $status = 'Warning' }
  } elseif ($r.Category -eq 'ERROR') {
    $status = 'Failed'
  }
  [pscustomobject]@{
    ComputerName       = $r.ComputerName
    Category           = $r.Category
    Protocol           = $r.Protocol
    Role               = $r.Role
    Enabled            = $r.Enabled
    DisabledByDefault  = $r.DisabledByDefault
    EffectiveState     = $r.EffectiveState
    Path               = $r.Path
    Key                = $r.Key
    Value              = $r.Value
    Status             = $status
  }
}

# ------------------------------
# Pretty tabular output section
# ------------------------------

# 1) Schannel table (clear headers)
Write-Host ""
Write-Host "=== Schannel compliance (per protocol/role) ===" -ForegroundColor Cyan
$schannelTable = $withStatus |
  Where-Object {$_.Category -eq 'Schannel'} |
  Sort-Object ComputerName, Protocol, Role |
  Select-Object `
    @{Label='Computer';Expression={$_.ComputerName}}, `
    @{Label='Protocol';Expression={$_.Protocol}}, `
    @{Label='Role';Expression={$_.Role}}, `
    @{Label='Enabled';Expression={$_.Enabled}}, `
    @{Label='DisabledByDefault';Expression={$_.DisabledByDefault}}, `
    @{Label='Effective';Expression={$_.EffectiveState}}, `
    @{Label='Status';Expression={$_.Status}}, `
    @{Label='RegPath';Expression={$_.Path}}

$schannelTable | Format-Table -AutoSize

# 2) .NET table (advisory)
Write-Host ""
Write-Host "=== .NET Strong Crypto (advisory) ===" -ForegroundColor Cyan
$dotnetTable = $withStatus |
  Where-Object {$_.Category -eq '.NET'} |
  Sort-Object ComputerName, Path, Key |
  Select-Object `
    @{Label='Computer';Expression={$_.ComputerName}}, `
    @{Label='.NET Path';Expression={$_.Path}}, `
    @{Label='Key';Expression={$_.Key}}, `
    @{Label='Value';Expression={$_.Value}}, `
    @{Label='Status';Expression={$_.Status}}

$dotnetTable | Format-Table -AutoSize

# 3) Colored compliance view (quick read)
Write-Host ""
Write-Host "=== Colored compliance view ==="
$sorted = $withStatus | Sort-Object Category, ComputerName, Protocol, Role, Key
foreach ($o in $sorted) {
  $color = 'Yellow'
  if     ($o.Status -eq 'Compliant') { $color = 'Green' }
  elseif ($o.Status -eq 'Failed')    { $color = 'Red'   }

  if ($o.Category -eq 'Schannel') {
    $label = ("{0} | {1} | {2} | Enabled={3} DisabledByDefault={4} | Effective={5}" -f `
              $o.ComputerName,$o.Protocol,$o.Role,$o.Enabled,$o.DisabledByDefault,$o.EffectiveState)
  } elseif ($o.Category -eq '.NET') {
    $label = ("{0} | .NET | {1} | {2}={3}" -f $o.ComputerName,$o.Path,$o.Key,$o.Value)
  } else {
    $third = if ($o.Error) { $o.Error } else { $o.EffectiveState }
    $label = ("{0} | {1} | {2}" -f $o.ComputerName,$o.Category,$third)
  }

  Write-Host ("[{0}] {1}" -f $o.Status,$label) -ForegroundColor $color
}

# 4) Summary per DC (Schannel only)
Write-Host ""
Write-Host "=== Summary per DC (Schannel only) ===" -ForegroundColor Cyan
$summary = $withStatus |
  Where-Object {$_.Category -eq 'Schannel'} |
  Group-Object ComputerName |
  ForEach-Object {
    $comp = $_.Name
    $ok   = ($_.Group | Where-Object {$_.Status -eq 'Compliant'}).Count
    $wrn  = ($_.Group | Where-Object {$_.Status -eq 'Warning'}).Count
    $ko   = ($_.Group | Where-Object {$_.Status -eq 'Failed'}).Count
    [pscustomobject]@{ ComputerName=$comp; Compliant=$ok; Warning=$wrn; Failed=$ko }
  }

$summary | Format-Table -AutoSize

# (Optional) CSV export
# $csv = Join-Path (Get-Location) ("TLS_Audit_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date))
# $withStatus | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
# Write-Host ("Export CSV -> {0}" -f $csv) -ForegroundColor Cyan
```

## Remediation with GPO

