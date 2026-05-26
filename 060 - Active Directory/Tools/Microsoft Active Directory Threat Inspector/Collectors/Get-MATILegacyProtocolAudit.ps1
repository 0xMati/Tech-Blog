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
    $rc4TGSAccounts  = @{}
    $rc4ClientIPs    = @{}
    $rc4DCs          = @{}
    $failedAccounts  = @{}
    $otherEncTypes   = @{}
    $kdcStrongKeyWarnings = [System.Collections.Generic.List[PSCustomObject]]::new()

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
            RC4TGSAccounts = @{}
            RC4ClientIPs   = @{}
            FailedAccounts = @{}
            OtherEncTypes  = @{}
            KdcStrongKeyWarnings = @()
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
                        if ($prefix -eq 'TGS' -and $account) {
                            if (-not $result.RC4TGSAccounts.ContainsKey($account)) { $result.RC4TGSAccounts[$account] = 0 }
                            $result.RC4TGSAccounts[$account]++
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

        # ---------- KDC strong-key warnings (System / Kdcsvc 42) ----------
        try {
            $kdcEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = 42
                StartTime = $since
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.ProviderName -match 'Kdcsvc|Kerberos-Key-Distribution-Center'
            }

            foreach ($ev in $kdcEvents) {
                $message = $ev.Message
                $account = $null
                if ($message -match 'account:\s*([^\.\r\n]+)') {
                    $account = $matches[1].Trim()
                }

                $result.KdcStrongKeyWarnings += [PSCustomObject]@{
                    Account   = $account
                    EventId   = $ev.Id
                    Provider  = $ev.ProviderName
                    TimeCreated = $ev.TimeCreated
                    Message   = $message
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
    $domainKerberos = @{}

    function Get-OrCreateKerberosDomainBucket {
        param([string]$DomainName)

        if (-not $domainKerberos.ContainsKey($DomainName)) {
            $domainKerberos[$DomainName] = @{
                Domain = $DomainName
                TGT_AES256 = 0; TGT_AES128 = 0; TGT_RC4 = 0; TGT_Failed = 0; TGT_Other = 0
                TGS_AES256 = 0; TGS_AES128 = 0; TGS_RC4 = 0; TGS_Failed = 0; TGS_Other = 0
                KdcStrongKeyWarnings = [System.Collections.Generic.List[PSCustomObject]]::new()
            }
        }

        return $domainKerberos[$DomainName]
    }

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
        $dcDomain = $dcMap[$dcHost]
        $domainBucket = if ($dcDomain) { Get-OrCreateKerberosDomainBucket -DomainName $dcDomain } else { $null }

        # --- Kerberos aggregation ---
        foreach ($k in @('TGT_AES256','TGT_AES128','TGT_RC4','TGT_Failed','TGT_Other',
                         'TGS_AES256','TGS_AES128','TGS_RC4','TGS_Failed','TGS_Other')) {
            $krbTotals[$k] += [int]$dcResult[$k]
            if ($domainBucket) { $domainBucket[$k] += [int]$dcResult[$k] }
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
        if ($dcResult.RC4TGSAccounts) {
            foreach ($entry in $dcResult.RC4TGSAccounts.GetEnumerator()) {
                if (-not $rc4TGSAccounts.ContainsKey($entry.Key)) { $rc4TGSAccounts[$entry.Key] = 0 }
                $rc4TGSAccounts[$entry.Key] += $entry.Value
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
        if ($dcResult.KdcStrongKeyWarnings) {
            foreach ($warning in @($dcResult.KdcStrongKeyWarnings)) {
                $warningObject = [PSCustomObject]@{
                    Domain      = $dcDomain
                    DC          = $dcHost
                    Account     = $warning.Account
                    EventId     = $warning.EventId
                    Provider    = $warning.Provider
                    TimeCreated = $warning.TimeCreated
                    Message     = $warning.Message
                }

                $kdcStrongKeyWarnings.Add($warningObject)
                if ($domainBucket) { $domainBucket.KdcStrongKeyWarnings.Add($warningObject) }
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
        TopRC4TGSAccounts = @(ConvertTo-TopN $rc4TGSAccounts $topN)
        TopRC4ClientIPs   = @(ConvertTo-TopN $rc4ClientIPs   $topN)
        TopRC4DCs         = @(ConvertTo-TopN $rc4DCs          $topN)
        TopFailedAccounts = @(ConvertTo-TopN $failedAccounts $topN)
        OtherEncTypes     = @(ConvertTo-TopN $otherEncTypes  $topN)
        RC4AccountDetails = @()
        RC4ServiceDetails = @()
        KdcStrongKeyWarnings = @($kdcStrongKeyWarnings)
        ByDomain = @()
    }

    foreach ($domainEntry in $domainKerberos.GetEnumerator() | Sort-Object Key) {
        $domainTotals = $domainEntry.Value
        $domainTotalTGT = $domainTotals.TGT_AES256 + $domainTotals.TGT_AES128 + $domainTotals.TGT_RC4 + $domainTotals.TGT_Failed + $domainTotals.TGT_Other
        $domainTotalTGS = $domainTotals.TGS_AES256 + $domainTotals.TGS_AES128 + $domainTotals.TGS_RC4 + $domainTotals.TGS_Failed + $domainTotals.TGS_Other
        $domainAESCount = $domainTotals.TGT_AES256 + $domainTotals.TGT_AES128 + $domainTotals.TGS_AES256 + $domainTotals.TGS_AES128
        $domainRC4Count = $domainTotals.TGT_RC4 + $domainTotals.TGS_RC4
        $domainFailedCount = $domainTotals.TGT_Failed + $domainTotals.TGS_Failed
        $domainOtherCount = $domainTotals.TGT_Other + $domainTotals.TGS_Other
        $domainTotalAll = $domainTotalTGT + $domainTotalTGS

        $kerberos.ByDomain += [PSCustomObject]@{
            Domain                  = $domainTotals.Domain
            TGT_AES256              = $domainTotals.TGT_AES256
            TGT_AES128              = $domainTotals.TGT_AES128
            TGT_RC4                 = $domainTotals.TGT_RC4
            TGT_Failed              = $domainTotals.TGT_Failed
            TGT_Other               = $domainTotals.TGT_Other
            TGS_AES256              = $domainTotals.TGS_AES256
            TGS_AES128              = $domainTotals.TGS_AES128
            TGS_RC4                 = $domainTotals.TGS_RC4
            TGS_Failed              = $domainTotals.TGS_Failed
            TGS_Other               = $domainTotals.TGS_Other
            TotalTGT                = $domainTotalTGT
            TotalTGS                = $domainTotalTGS
            TotalAll                = $domainTotalAll
            AESCount                = $domainAESCount
            RC4Count                = $domainRC4Count
            FailedCount             = $domainFailedCount
            OtherCount              = $domainOtherCount
            AESPercent              = if ($domainTotalAll -gt 0) { [math]::Round(100 * $domainAESCount / $domainTotalAll, 1) } else { 0 }
            RC4Percent              = if ($domainTotalAll -gt 0) { [math]::Round(100 * $domainRC4Count / $domainTotalAll, 1) } else { 0 }
            FailedPercent           = if ($domainTotalAll -gt 0) { [math]::Round(100 * $domainFailedCount / $domainTotalAll, 1) } else { 0 }
            OtherPercent            = if ($domainTotalAll -gt 0) { [math]::Round(100 * $domainOtherCount / $domainTotalAll, 1) } else { 0 }
            KdcStrongKeyWarningCount = @($domainTotals.KdcStrongKeyWarnings).Count
            KdcStrongKeyWarnings    = @($domainTotals.KdcStrongKeyWarnings)
        }
    }

    # ---------------------------------------------------------------
    # AD enrichment for RC4 accounts and services
    # ---------------------------------------------------------------
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "    [>] Enriching RC4 accounts/services with AD details..." -ForegroundColor DarkGray

        function Get-MATIEncFlags {
            param([Nullable[int]]$v)
            if ($null -eq $v -or $v -eq 0) { return '(unset)' }
            $flags = @()
            if (($v -band 0x01) -ne 0) { $flags += 'DES-CBC-CRC' }
            if (($v -band 0x02) -ne 0) { $flags += 'DES-CBC-MD5' }
            if (($v -band 0x04) -ne 0) { $flags += 'RC4-HMAC' }
            if (($v -band 0x08) -ne 0) { $flags += 'AES128' }
            if (($v -band 0x10) -ne 0) { $flags += 'AES256' }
            if ($flags.Count -eq 0) { return "0x$($v.ToString('X'))" }
            return ($flags -join ', ')
        }

        function Resolve-MATIAdPrincipal {
            param([string]$Identity)
            if (-not $Identity -or $Identity -eq '(n/a)') { return $null }
            $props = 'pwdLastSet','msDS-SupportedEncryptionTypes','lastLogonDate','userAccountControl','servicePrincipalName'
            $obj = $null; $objClass = $null
            # Try UPN first
            if ($Identity -like '*@*') {
                try { $obj = Get-ADUser -Filter "userPrincipalName -eq '$Identity'" -Properties $props -ErrorAction Stop; $objClass = 'user' } catch {}
            }
            if (-not $obj) { try { $obj = Get-ADUser -Identity $Identity -Properties $props -ErrorAction Stop; $objClass = 'user' } catch {} }
            if (-not $obj) { try { $obj = Get-ADComputer -Identity $Identity -Properties $props -ErrorAction Stop; $objClass = 'computer' } catch {} }
            if (-not $obj) { try { $obj = Get-ADServiceAccount -Identity $Identity -Properties $props -ErrorAction Stop; $objClass = 'gMSA' } catch {} }
            if (-not $obj) { return $null }

            $encVal = $obj.'msDS-SupportedEncryptionTypes'
            $hasAES = ($encVal -ne $null) -and ((($encVal -band 0x08) -ne 0) -or (($encVal -band 0x10) -ne 0))
            $preAuth = if ($obj.userAccountControl) { (($obj.userAccountControl -band 0x400000) -ne 0) } else { $false }
            $pwdDate = $null
            if ($obj.pwdLastSet -and $obj.pwdLastSet -is [long] -and $obj.pwdLastSet -ne 0) {
                $pwdDate = [DateTime]::FromFileTime($obj.pwdLastSet)
            }

            [PSCustomObject]@{
                Name                = $obj.SamAccountName
                ObjectClass         = $objClass
                EncValue            = if ($encVal -ne $null) { $encVal } else { 0 }
                EncFlags            = Get-MATIEncFlags $encVal
                HasAES              = $hasAES
                PwdLastSet          = $pwdDate
                LastLogon           = $obj.lastLogonDate
                PreAuthNotRequired  = $preAuth
                HasSPN              = [bool]($obj.servicePrincipalName)
            }
        }

        # Enrich unique RC4 accounts (TGT + TGS requestors)
        $uniqueAccts = @()
        foreach ($a in $kerberos.TopRC4TGTAccounts) { $uniqueAccts += $a.Name }
        foreach ($a in $kerberos.TopRC4TGSAccounts) { $uniqueAccts += $a.Name }
        $uniqueAccts = $uniqueAccts | Select-Object -Unique | Where-Object { $_ -and $_ -ne '(n/a)' }
        foreach ($acctName in $uniqueAccts) {
            $detail = Resolve-MATIAdPrincipal -Identity $acctName
            if ($detail) { $kerberos.RC4AccountDetails += $detail }
        }

        # Enrich unique RC4 target services
        $uniqueSvcs = @()
        foreach ($s in $kerberos.TopRC4TGSServices) { $uniqueSvcs += $s.Name }
        $uniqueSvcs = $uniqueSvcs | Select-Object -Unique | Where-Object { $_ -and $_ -ne '(n/a)' }
        foreach ($svcName in $uniqueSvcs) {
            $detail = Resolve-MATIAdPrincipal -Identity $svcName
            if ($detail) { $kerberos.RC4ServiceDetails += $detail }
        }

        Write-Host "    [+] AD enrichment done — $($kerberos.RC4AccountDetails.Count) accounts, $($kerberos.RC4ServiceDetails.Count) services" -ForegroundColor Green
    } catch {
        Write-Host "    [!] AD enrichment skipped: $($_.Exception.Message)" -ForegroundColor Yellow
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
