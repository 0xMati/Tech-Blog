# Engine\Invoke-MATICollectors.ps1
# MATIv2 - Collector orchestrator
# Determines which collectors are needed based on active rules,
# executes them, and populates the DataCache.

function Invoke-MATICollectors {
    <#
    .SYNOPSIS
        Runs only the collectors required by the active rules (lazy loading).
    .PARAMETER EngineContext
        The engine context hashtable from Initialize-MATIEngine.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    Write-Host "=== Phase 1: Data Collection ===" -ForegroundColor Cyan

    # ------------------------------------------------------------------
    # 1. Determine required collectors from rules dependencies
    # ------------------------------------------------------------------
    $requiredCollectors = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    foreach ($rule in $EngineContext.Rules) {
        foreach ($dep in $rule.Collectors) {
            $null = $requiredCollectors.Add($dep)
        }
    }

    Write-Host "  Required collectors: $($requiredCollectors -join ', ')" -ForegroundColor DarkGray

    # ------------------------------------------------------------------
    # 2. Execute each required collector
    # ------------------------------------------------------------------
    $config  = $EngineContext.Config
    $allCollectors = $EngineContext.Collectors

    foreach ($collectorName in $requiredCollectors) {
        if (-not $allCollectors.ContainsKey($collectorName)) {
            Write-Warning "  [!] Collector '$collectorName' referenced by rules but not found - skipping"
            continue
        }

        $collector = $allCollectors[$collectorName]
        $funcName  = $collector.Function
        $filePath  = $collector.FilePath

        Write-Host "  [>] Running collector: $collectorName ..." -ForegroundColor DarkGray -NoNewline
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            # Dot-source the collector file to ensure the function is available in scope
            . $filePath
            # Call the collector function, passing config for thresholds/properties
            $data = & $funcName -Config $config
            $EngineContext.DataCache[$collectorName] = $data

            $sw.Stop()
            $count = if ($data -is [array]) { $data.Count } elseif ($data) { 1 } else { 0 }
            Write-Host " OK ($count objects, $($sw.ElapsedMilliseconds)ms)" -ForegroundColor Green
        }
        catch {
            $sw.Stop()
            Write-Warning "  [!] Collector '$collectorName' failed: $($_.Exception.Message)"
            $EngineContext.DataCache[$collectorName] = @()
        }
    }

    Write-Host "  Data collection complete.`n" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 3. Probe DC connectivity (requires DCInfo collector to have run)
    # ------------------------------------------------------------------
    if ($EngineContext.DataCache.ContainsKey('DCInfo') -and $EngineContext.DataCache['DCInfo']) {
        Write-Host "  Probing DC connectivity..." -ForegroundColor DarkGray
        foreach ($dc in $EngineContext.DataCache['DCInfo']) {
            $status   = 'Unreachable'
            $latency  = $null
            $errorMsg = $null
            try {
                $ping = Test-Connection -TargetName $dc.HostName -Count 1 -TimeoutSeconds 2 -ErrorAction Stop
                if ($ping.Status -eq 'Success') {
                    $status  = 'Reachable'
                    $latency = [math]::Round($ping.Latency, 1)
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
            }

            # Also test LDAP port 389
            $ldapOk = $false
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $result = $tcp.BeginConnect($dc.HostName, 389, $null, $null)
                $connected = $result.AsyncWaitHandle.WaitOne(2000, $false)
                if ($connected -and $tcp.Connected) { $ldapOk = $true }
                $tcp.Close()
            }
            catch { }

            if ($status -eq 'Reachable' -and $ldapOk) {
                $connectivity = 'OK'
            }
            elseif ($status -eq 'Reachable' -and -not $ldapOk) {
                $connectivity = 'ICMP only (LDAP unreachable)'
            }
            else {
                $connectivity = 'Unreachable'
            }

            $EngineContext.DCConnectivity.Add([PSCustomObject]@{
                Name            = $dc.Name
                HostName        = $dc.HostName
                Domain          = $dc.Domain
                IPv4Address     = $dc.IPv4Address
                Site            = $dc.Site
                OperatingSystem = $dc.OperatingSystem
                IsGlobalCatalog = $dc.IsGlobalCatalog
                IsReadOnly      = $dc.IsReadOnly
                Status          = $connectivity
                LatencyMs       = $latency
                Error           = $errorMsg
            })

            $icon = if ($connectivity -eq 'OK') { '[+]' } else { '[!]' }
            $color = if ($connectivity -eq 'OK') { 'Green' } else { 'Yellow' }
            $latStr = if ($null -ne $latency) { " (${latency}ms)" } else { '' }
            Write-Host "  $icon DC: $($dc.HostName) - $connectivity$latStr" -ForegroundColor $color
        }
        Write-Host ""
    }
}
