# Collectors\Get-MATILegacyProtocolAudit.ps1
# MATIv2 - Collects Kerberos encryption (4768/4769) and NTLM logon (4624)
#           events from DCs via WinRM, returns aggregated summaries.

function Get-MATILegacyProtocolAudit {
    <#
    .SYNOPSIS
        Queries DC Security event logs for Kerberos ticket encryption types
        (RC4 vs AES breakdown) and NTLM logon events (NTLMv1 vs v2).
        Aggregation is performed on each DC to minimise network traffic.
    .OUTPUTS
        [hashtable] with keys:
          Kerberos  — encryption breakdown, top RC4 accounts/services/IPs
          NTLM      — v1/v2 breakdown, top accounts/workstations/IPs
          Errors    — DCs that could not be contacted
          AuditHours — number of hours audited
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $hours = 24
    $topN  = 15
    if ($Config.Thresholds.EventLogAudit) {
        if ($Config.Thresholds.EventLogAudit.Hours) { $hours = $Config.Thresholds.EventLogAudit.Hours }
        if ($Config.Thresholds.EventLogAudit.TopN)  { $topN  = $Config.Thresholds.EventLogAudit.TopN  }
    }

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $errors = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Global accumulators ---
    $krbTotals = @{
        TGT_AES256 = 0; TGT_AES128 = 0; TGT_RC4 = 0; TGT_Failed = 0; TGT_Other = 0
        TGS_AES256 = 0; TGS_AES128 = 0; TGS_RC4 = 0; TGS_Failed = 0; TGS_Other = 0
    }
    $rc4TGTAccounts  = @{}
    $rc4TGSServices  = @{}
    $rc4ClientIPs    = @{}
    $rc4DCs          = @{}
    $failedAccounts  = @{}
    $otherEncTypes   = @{}

    $ntlmV1Total = 0
    $ntlmV2Total = 0
    $ntlmAccounts     = @{}
    $ntlmWorkstations = @{}
    $ntlmIPs          = @{}
    $ntlmDCs          = @{}
    $ntlmV1Accounts     = @{}
    $ntlmV1Workstations = @{}
    $ntlmV1IPs          = @{}
    $ntlmV2Accounts     = @{}
    $ntlmV2Workstations = @{}
    $ntlmV2IPs          = @{}

    # ---------------------------------------------------------------
    # Remote scriptblock — executed on each DC via Invoke-Command.
    # Does all parsing on the remote side and returns only aggregates.
    # ---------------------------------------------------------------
    $remoteBlock = {
        param([int]$AuditHours)

        $since = (Get-Date).AddHours(-$AuditHours)
        $result = @{
            DC = $env:COMPUTERNAME
            # Kerberos
            TGT_AES256 = 0; TGT_AES128 = 0; TGT_RC4 = 0; TGT_Failed = 0; TGT_Other = 0
            TGS_AES256 = 0; TGS_AES128 = 0; TGS_RC4 = 0; TGS_Failed = 0; TGS_Other = 0
            RC4TGTAccounts = @{}
            RC4TGSServices = @{}
            RC4ClientIPs   = @{}
            FailedAccounts = @{}
            OtherEncTypes  = @{}
            # NTLM
            NTLMv1 = 0; NTLMv2 = 0
            NTLMAccounts     = @{}
            NTLMWorkstations = @{}
            NTLMIPs          = @{}
            NTLMv1Accounts     = @{}
            NTLMv1Workstations = @{}
            NTLMv1IPs          = @{}
            NTLMv2Accounts     = @{}
            NTLMv2Workstations = @{}
            NTLMv2IPs          = @{}
        }

        # ---------- Kerberos 4768 / 4769 ----------
        try {
            $krbEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4768, 4769
                StartTime = $since
            } -ErrorAction SilentlyContinue

            foreach ($ev in $krbEvents) {
                $xml = [xml]$ev.ToXml()
                $encRaw  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
                $account = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $service = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
                $ip      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $status  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Status' }).'#text'
                if ($ip) { $ip = $ip -replace '::ffff:', '' }

                $prefix = if ($ev.Id -eq 4768) { 'TGT' } else { 'TGS' }

                switch ($encRaw) {
                    '0x12' { $result["${prefix}_AES256"]++ }
                    '0x11' { $result["${prefix}_AES128"]++ }
                    '0x17' {
                        $result["${prefix}_RC4"]++
                        if ($prefix -eq 'TGT' -and $account) {
                            if (-not $result.RC4TGTAccounts.ContainsKey($account)) { $result.RC4TGTAccounts[$account] = 0 }
                            $result.RC4TGTAccounts[$account]++
                        }
                        if ($prefix -eq 'TGS' -and $service) {
                            if (-not $result.RC4TGSServices.ContainsKey($service)) { $result.RC4TGSServices[$service] = 0 }
                            $result.RC4TGSServices[$service]++
                        }
                        if ($ip) {
                            if (-not $result.RC4ClientIPs.ContainsKey($ip)) { $result.RC4ClientIPs[$ip] = 0 }
                            $result.RC4ClientIPs[$ip]++
                        }
                    }
                    default {
                        # Status 0x0 = success. Any other status = failed auth (no ticket issued, encryption type is meaningless)
                        if ($status -and $status -ne '0x0') {
                            $result["${prefix}_Failed"]++
                            if ($account) {
                                if (-not $result.FailedAccounts.ContainsKey($account)) { $result.FailedAccounts[$account] = 0 }
                                $result.FailedAccounts[$account]++
                            }
                        } else {
                            $result["${prefix}_Other"]++
                            $encLabel = if ($encRaw) { $encRaw } else { '(empty)' }
                            if (-not $result.OtherEncTypes.ContainsKey($encLabel)) { $result.OtherEncTypes[$encLabel] = 0 }
                            $result.OtherEncTypes[$encLabel]++
                        }
                    }
                }
            }
        } catch { }

        # ---------- NTLM 4624 (XPath filters for NtLmSsp at source → ~90% data reduction) ----------
        try {
            $msWindow = [long]($AuditHours * 3600 * 1000)
            $ntlmXml  = @"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">
*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= $msWindow]]
 and EventData[Data[@Name='LogonProcessName']='NtLmSsp ']]
</Select></Query></QueryList>
"@
            $ntlmEvents = Get-WinEvent -FilterXml $ntlmXml -ErrorAction SilentlyContinue

            foreach ($ev in $ntlmEvents) {
                $xml = [xml]$ev.ToXml()

                $lmPkg  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LmPackageName' }).'#text'
                $acct   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                $ws     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                $ip     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'

                $isV1 = $false
                if ($lmPkg -match 'V1|v1') { $result.NTLMv1++; $isV1 = $true }
                elseif ($lmPkg -match 'V2|v2') { $result.NTLMv2++ }
                else { $result.NTLMv2++ }   # default bucket

                # Per-version prefix for hashtable keys
                $vPrefix = if ($isV1) { 'NTLMv1' } else { 'NTLMv2' }

                if ($acct) {
                    if (-not $result.NTLMAccounts.ContainsKey($acct)) { $result.NTLMAccounts[$acct] = 0 }
                    $result.NTLMAccounts[$acct]++
                    if (-not $result."${vPrefix}Accounts".ContainsKey($acct)) { $result."${vPrefix}Accounts"[$acct] = 0 }
                    $result."${vPrefix}Accounts"[$acct]++
                }
                if ($ws) {
                    if (-not $result.NTLMWorkstations.ContainsKey($ws)) { $result.NTLMWorkstations[$ws] = 0 }
                    $result.NTLMWorkstations[$ws]++
                    if (-not $result."${vPrefix}Workstations".ContainsKey($ws)) { $result."${vPrefix}Workstations"[$ws] = 0 }
                    $result."${vPrefix}Workstations"[$ws]++
                }
                if ($ip) {
                    if (-not $result.NTLMIPs.ContainsKey($ip)) { $result.NTLMIPs[$ip] = 0 }
                    $result.NTLMIPs[$ip]++
                    if (-not $result."${vPrefix}IPs".ContainsKey($ip)) { $result."${vPrefix}IPs"[$ip] = 0 }
                    $result."${vPrefix}IPs"[$ip]++
                }
            }
        } catch { }

        $result
    }

    # ---------------------------------------------------------------
    # Collect all DCs across all forest domains
    # ---------------------------------------------------------------
    $dcMap = [ordered]@{} # HostName -> DomainDNS
    foreach ($domainDns in $forest.Domains) {
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $dcs) {
                $dcMap[$dc.HostName] = $domainDns
            }
        } catch {
            $errors.Add([PSCustomObject]@{ Domain = $domainDns; DC = '(all)'; Error = $_.Exception.Message })
        }
    }

    if ($dcMap.Count -eq 0) {
        Write-Host "    [!] No DCs found — skipping event log audit" -ForegroundColor Yellow
        return @{
            Kerberos   = @{ Totals = $krbTotals; TotalTGT = 0; TotalTGS = 0; TotalAll = 0
                            AESCount = 0; RC4Count = 0; FailedCount = 0; OtherCount = 0
                            AESPercent = 0; RC4Percent = 0; FailedPercent = 0; OtherPercent = 0
                            TopRC4TGTAccounts = @(); TopRC4TGSServices = @(); TopRC4ClientIPs = @(); TopRC4DCs = @()
                            TopFailedAccounts = @(); OtherEncTypes = @() }
            NTLM       = @{ TotalEvents = 0; NTLMv1Count = 0; NTLMv2Count = 0
                            NTLMv1Percent = 0; NTLMv2Percent = 0
                            TopAccounts = @(); TopWorkstations = @(); TopIPs = @(); TopDCs = @()
                            TopV1Accounts = @(); TopV1Workstations = @(); TopV1IPs = @()
                            TopV2Accounts = @(); TopV2Workstations = @(); TopV2IPs = @() }
            AuditHours = $hours
            Errors     = @($errors)
        }
    }

    # ---------------------------------------------------------------
    # Query all DCs in parallel via single Invoke-Command
    # WinRM fans out to all targets simultaneously (ThrottleLimit 8)
    # ---------------------------------------------------------------
    $dcHostNames = @($dcMap.Keys)
    Write-Host "    [>] Querying events on $($dcHostNames.Count) DCs in parallel (last ${hours}h)..." -ForegroundColor DarkGray

    $remoteErrors = $null
    $rawResults   = @()
    try {
        $rawResults = @(Invoke-Command -ComputerName $dcHostNames `
            -ScriptBlock $remoteBlock -ArgumentList $hours `
            -ErrorAction SilentlyContinue -ErrorVariable remoteErrors `
            -ThrottleLimit 8)
    } catch {
        Write-Host "    [!] Invoke-Command failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Capture per-DC errors from ErrorVariable
    if ($remoteErrors) {
        foreach ($re in $remoteErrors) {
            $failedDC = if ($re.TargetObject) { "$($re.TargetObject)" } else { 'Unknown' }
            $failedDomain = if ($failedDC -and $dcMap.Contains($failedDC)) { $dcMap[$failedDC] } else { '?' }
            $errors.Add([PSCustomObject]@{ Domain = $failedDomain; DC = $failedDC; Error = $re.Exception.Message })
        }
    }

    # ---------------------------------------------------------------
    # Aggregate results and report per-DC status
    # ---------------------------------------------------------------
    $processedDCs = @{}
    foreach ($dcResult in $rawResults) {
        # Invoke-Command adds PSComputerName to deserialized results
        $dcHost = "$($dcResult.PSComputerName)"
        if (-not $dcHost -and $dcResult.DC) {
            # Fallback: match short COMPUTERNAME to FQDN
            $dcHost = $dcHostNames | Where-Object { $_ -like "$($dcResult.DC).*" } | Select-Object -First 1
        }
        if (-not $dcHost) { continue }
        $processedDCs[$dcHost] = $true

        # --- Kerberos aggregation ---
        foreach ($k in @('TGT_AES256','TGT_AES128','TGT_RC4','TGT_Failed','TGT_Other',
                         'TGS_AES256','TGS_AES128','TGS_RC4','TGS_Failed','TGS_Other')) {
            $krbTotals[$k] += [int]$dcResult[$k]
        }
        if ($dcResult.RC4TGTAccounts) {
            foreach ($entry in $dcResult.RC4TGTAccounts.GetEnumerator()) {
                if (-not $rc4TGTAccounts.ContainsKey($entry.Key)) { $rc4TGTAccounts[$entry.Key] = 0 }
                $rc4TGTAccounts[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.RC4TGSServices) {
            foreach ($entry in $dcResult.RC4TGSServices.GetEnumerator()) {
                if (-not $rc4TGSServices.ContainsKey($entry.Key)) { $rc4TGSServices[$entry.Key] = 0 }
                $rc4TGSServices[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.RC4ClientIPs) {
            foreach ($entry in $dcResult.RC4ClientIPs.GetEnumerator()) {
                if (-not $rc4ClientIPs.ContainsKey($entry.Key)) { $rc4ClientIPs[$entry.Key] = 0 }
                $rc4ClientIPs[$entry.Key] += $entry.Value
            }
        }
        $dcRc4 = [int]$dcResult['TGT_RC4'] + [int]$dcResult['TGS_RC4']
        if ($dcRc4 -gt 0) { $rc4DCs[$dcHost] = $dcRc4 }
        if ($dcResult.FailedAccounts) {
            foreach ($entry in $dcResult.FailedAccounts.GetEnumerator()) {
                if (-not $failedAccounts.ContainsKey($entry.Key)) { $failedAccounts[$entry.Key] = 0 }
                $failedAccounts[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.OtherEncTypes) {
            foreach ($entry in $dcResult.OtherEncTypes.GetEnumerator()) {
                if (-not $otherEncTypes.ContainsKey($entry.Key)) { $otherEncTypes[$entry.Key] = 0 }
                $otherEncTypes[$entry.Key] += $entry.Value
            }
        }

        # --- NTLM aggregation ---
        $ntlmV1Total += [int]$dcResult.NTLMv1
        $ntlmV2Total += [int]$dcResult.NTLMv2
        if ($dcResult.NTLMAccounts) {
            foreach ($entry in $dcResult.NTLMAccounts.GetEnumerator()) {
                if (-not $ntlmAccounts.ContainsKey($entry.Key)) { $ntlmAccounts[$entry.Key] = 0 }
                $ntlmAccounts[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMWorkstations) {
            foreach ($entry in $dcResult.NTLMWorkstations.GetEnumerator()) {
                if (-not $ntlmWorkstations.ContainsKey($entry.Key)) { $ntlmWorkstations[$entry.Key] = 0 }
                $ntlmWorkstations[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMIPs) {
            foreach ($entry in $dcResult.NTLMIPs.GetEnumerator()) {
                if (-not $ntlmIPs.ContainsKey($entry.Key)) { $ntlmIPs[$entry.Key] = 0 }
                $ntlmIPs[$entry.Key] += $entry.Value
            }
        }
        # Per-version aggregation (v1)
        if ($dcResult.NTLMv1Accounts) {
            foreach ($entry in $dcResult.NTLMv1Accounts.GetEnumerator()) {
                if (-not $ntlmV1Accounts.ContainsKey($entry.Key)) { $ntlmV1Accounts[$entry.Key] = 0 }
                $ntlmV1Accounts[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMv1Workstations) {
            foreach ($entry in $dcResult.NTLMv1Workstations.GetEnumerator()) {
                if (-not $ntlmV1Workstations.ContainsKey($entry.Key)) { $ntlmV1Workstations[$entry.Key] = 0 }
                $ntlmV1Workstations[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMv1IPs) {
            foreach ($entry in $dcResult.NTLMv1IPs.GetEnumerator()) {
                if (-not $ntlmV1IPs.ContainsKey($entry.Key)) { $ntlmV1IPs[$entry.Key] = 0 }
                $ntlmV1IPs[$entry.Key] += $entry.Value
            }
        }
        # Per-version aggregation (v2)
        if ($dcResult.NTLMv2Accounts) {
            foreach ($entry in $dcResult.NTLMv2Accounts.GetEnumerator()) {
                if (-not $ntlmV2Accounts.ContainsKey($entry.Key)) { $ntlmV2Accounts[$entry.Key] = 0 }
                $ntlmV2Accounts[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMv2Workstations) {
            foreach ($entry in $dcResult.NTLMv2Workstations.GetEnumerator()) {
                if (-not $ntlmV2Workstations.ContainsKey($entry.Key)) { $ntlmV2Workstations[$entry.Key] = 0 }
                $ntlmV2Workstations[$entry.Key] += $entry.Value
            }
        }
        if ($dcResult.NTLMv2IPs) {
            foreach ($entry in $dcResult.NTLMv2IPs.GetEnumerator()) {
                if (-not $ntlmV2IPs.ContainsKey($entry.Key)) { $ntlmV2IPs[$entry.Key] = 0 }
                $ntlmV2IPs[$entry.Key] += $entry.Value
            }
        }
        $dcNtlm = [int]$dcResult.NTLMv1 + [int]$dcResult.NTLMv2
        if ($dcNtlm -gt 0) { $ntlmDCs[$dcHost] = $dcNtlm }

        # Per-DC status line
        $kTotal = [int]$dcResult.TGT_AES256 + [int]$dcResult.TGT_AES128 + [int]$dcResult.TGT_RC4 + [int]$dcResult.TGT_Failed + [int]$dcResult.TGT_Other +
                  [int]$dcResult.TGS_AES256 + [int]$dcResult.TGS_AES128 + [int]$dcResult.TGS_RC4 + [int]$dcResult.TGS_Failed + [int]$dcResult.TGS_Other
        $nTotal = [int]$dcResult.NTLMv1 + [int]$dcResult.NTLMv2
        Write-Host "    [+] $dcHost — Krb: $kTotal, NTLM: $nTotal" -ForegroundColor Green
    }

    # Report DCs that didn't return results
    foreach ($dcHost in $dcHostNames) {
        if (-not $processedDCs.ContainsKey($dcHost)) {
            Write-Host "    [!] $dcHost — FAILED (no results)" -ForegroundColor Red
            $alreadyErrored = $errors | Where-Object { $_.DC -eq $dcHost }
            if (-not $alreadyErrored) {
                $errors.Add([PSCustomObject]@{ Domain = $dcMap[$dcHost]; DC = $dcHost; Error = 'No response received' })
            }
        }
    }

    # ---------------------------------------------------------------
    # Helper: convert hashtable to sorted top-N list
    # ---------------------------------------------------------------
    function ConvertTo-TopN {
        param([hashtable]$Hash, [int]$N)
        if (-not $Hash -or $Hash.Count -eq 0) { return @() }
        $Hash.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First $N |
            ForEach-Object { [PSCustomObject]@{ Name = $_.Key; Count = $_.Value } }
    }

    # ---------------------------------------------------------------
    # Build Kerberos summary
    # ---------------------------------------------------------------
    $totalTGT = $krbTotals.TGT_AES256 + $krbTotals.TGT_AES128 + $krbTotals.TGT_RC4 + $krbTotals.TGT_Failed + $krbTotals.TGT_Other
    $totalTGS = $krbTotals.TGS_AES256 + $krbTotals.TGS_AES128 + $krbTotals.TGS_RC4 + $krbTotals.TGS_Failed + $krbTotals.TGS_Other
    $totalAES = $krbTotals.TGT_AES256 + $krbTotals.TGT_AES128 + $krbTotals.TGS_AES256 + $krbTotals.TGS_AES128
    $totalRC4 = $krbTotals.TGT_RC4 + $krbTotals.TGS_RC4
    $totalFailed = $krbTotals.TGT_Failed + $krbTotals.TGS_Failed
    $totalOther  = $krbTotals.TGT_Other + $krbTotals.TGS_Other
    $totalAll = $totalTGT + $totalTGS

    $aesPercent = if ($totalAll -gt 0) { [math]::Round(100 * $totalAES / $totalAll, 1) } else { 0 }
    $rc4Percent = if ($totalAll -gt 0) { [math]::Round(100 * $totalRC4 / $totalAll, 1) } else { 0 }
    $failedPercent = if ($totalAll -gt 0) { [math]::Round(100 * $totalFailed / $totalAll, 1) } else { 0 }
    $otherPercent  = if ($totalAll -gt 0) { [math]::Round(100 * $totalOther / $totalAll, 1) } else { 0 }

    $kerberos = @{
        Totals     = $krbTotals
        TotalTGT   = $totalTGT
        TotalTGS   = $totalTGS
        TotalAll   = $totalAll
        AESCount   = $totalAES
        RC4Count   = $totalRC4
        FailedCount  = $totalFailed
        OtherCount   = $totalOther
        AESPercent = $aesPercent
        RC4Percent = $rc4Percent
        FailedPercent = $failedPercent
        OtherPercent  = $otherPercent
        TopRC4TGTAccounts = @(ConvertTo-TopN $rc4TGTAccounts $topN)
        TopRC4TGSServices = @(ConvertTo-TopN $rc4TGSServices $topN)
        TopRC4ClientIPs   = @(ConvertTo-TopN $rc4ClientIPs   $topN)
        TopRC4DCs         = @(ConvertTo-TopN $rc4DCs          $topN)
        TopFailedAccounts = @(ConvertTo-TopN $failedAccounts $topN)
        OtherEncTypes     = @(ConvertTo-TopN $otherEncTypes  $topN)
    }

    # ---------------------------------------------------------------
    # Build NTLM summary
    # ---------------------------------------------------------------
    $ntlmTotal = $ntlmV1Total + $ntlmV2Total
    $v1Percent = if ($ntlmTotal -gt 0) { [math]::Round(100 * $ntlmV1Total / $ntlmTotal, 1) } else { 0 }
    $v2Percent = if ($ntlmTotal -gt 0) { [math]::Round(100 * $ntlmV2Total / $ntlmTotal, 1) } else { 0 }

    $ntlm = @{
        TotalEvents    = $ntlmTotal
        NTLMv1Count    = $ntlmV1Total
        NTLMv2Count    = $ntlmV2Total
        NTLMv1Percent  = $v1Percent
        NTLMv2Percent  = $v2Percent
        TopAccounts      = @(ConvertTo-TopN $ntlmAccounts      $topN)
        TopWorkstations  = @(ConvertTo-TopN $ntlmWorkstations  $topN)
        TopIPs           = @(ConvertTo-TopN $ntlmIPs           $topN)
        TopDCs           = @(ConvertTo-TopN $ntlmDCs           $topN)
        TopV1Accounts      = @(ConvertTo-TopN $ntlmV1Accounts      $topN)
        TopV1Workstations  = @(ConvertTo-TopN $ntlmV1Workstations  $topN)
        TopV1IPs           = @(ConvertTo-TopN $ntlmV1IPs           $topN)
        TopV2Accounts      = @(ConvertTo-TopN $ntlmV2Accounts      $topN)
        TopV2Workstations  = @(ConvertTo-TopN $ntlmV2Workstations  $topN)
        TopV2IPs           = @(ConvertTo-TopN $ntlmV2IPs           $topN)
    }

    # ---------------------------------------------------------------
    # Return
    # ---------------------------------------------------------------
    @{
        Kerberos   = $kerberos
        NTLM       = $ntlm
        AuditHours = $hours
        Errors     = @($errors)
    }
}
