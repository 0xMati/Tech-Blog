# Reporters\Export-MATICsv.ps1
# MATIv2 - CSV reporter

function Export-MATICsv {
    <#
    .SYNOPSIS
        Exports findings and collected data to CSV files.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    $csvDir    = $EngineContext.CsvDir
    $timestamp = $EngineContext.Timestamp
    $findings  = $EngineContext.Findings
    $dataCache = $EngineContext.DataCache
    $filePrefix = if ($EngineContext.Config['_ReportFilePrefix']) { $EngineContext.Config['_ReportFilePrefix'] } else { 'MATI_' }

    # ------------------------------------------------------------------
    # 1. Global findings CSV
    # ------------------------------------------------------------------
    $findingsForCsv = $findings | ForEach-Object {
        $detailsText = ($_.Details.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        $detailsJson = if ($_.Details -and $_.Details.Count -gt 0) {
            try {
                $_.Details | ConvertTo-Json -Compress -Depth 10
            } catch {
                ''
            }
        } else { '' }

        [PSCustomObject]@{
            Id          = $_.Id
            Category    = $_.Category
            Severity    = $_.Severity
            Title       = $_.Title
            Description = $_.Description
            Remediation = $_.Remediation
            ObjectDN    = $_.ObjectDN
            Domain      = $_.Domain
            RuleFile    = $_.RuleFile
            Weight      = $_.Weight
            Details     = $detailsText
            DetailsJson = $detailsJson
            Timestamp   = $_.Timestamp
        }
    }

    $findingsPath = Join-Path $csvDir "${filePrefix}Findings_$timestamp.csv"
    if ($findingsForCsv) {
        $findingsForCsv | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
    }

    # ------------------------------------------------------------------
    # 2. Raw data CSVs (one per collector that returned data)
    # ------------------------------------------------------------------
    # Helper: flatten objects for CSV — convert non-scalar properties to strings
    function ConvertTo-CsvSafe {
        param([Parameter(ValueFromPipeline)][PSObject]$InputObject)
        process {
            if ($null -eq $InputObject) { return }
            $flat = [ordered]@{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $val = $prop.Value
                if ($null -eq $val) {
                    $flat[$prop.Name] = ''
                }
                elseif ($val -is [string] -or $val -is [int] -or $val -is [long] -or
                        $val -is [double] -or $val -is [bool] -or $val -is [datetime]) {
                    $flat[$prop.Name] = $val
                }
                elseif ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                    $flat[$prop.Name] = ($val | ForEach-Object { "$_" }) -join '; '
                }
                else {
                    $flat[$prop.Name] = "$val"
                }
            }
            [PSCustomObject]$flat
        }
    }

    foreach ($collectorName in $dataCache.Keys) {
        # Skip LegacyProtocolAudit — handled separately below
        if ($collectorName -eq 'LegacyProtocolAudit') { continue }

        $data = $dataCache[$collectorName]

        if ($data -is [hashtable]) {
            # Collector returned a hashtable with multiple datasets
            foreach ($subKey in $data.Keys) {
                $subData = @($data[$subKey] | Where-Object { $null -ne $_ })
                if ($subData.Count -gt 0 -and $subData[0] -is [PSCustomObject]) {
                    $subPath = Join-Path $csvDir "${filePrefix}${collectorName}_${subKey}.csv"
                    try {
                        $subData | ConvertTo-CsvSafe | Export-Csv -Path $subPath -NoTypeInformation -Encoding UTF8
                    } catch {
                        Write-Warning "    CSV export failed for ${collectorName}/${subKey}: $($_.Exception.Message)"
                    }
                }
            }
        }
        elseif ($data -is [array]) {
            $validData = @($data | Where-Object { $null -ne $_ })
            if ($validData.Count -gt 0) {
                $dataPath = Join-Path $csvDir "${filePrefix}${collectorName}.csv"
                try {
                    $validData | ConvertTo-CsvSafe | Export-Csv -Path $dataPath -NoTypeInformation -Encoding UTF8
                } catch {
                    Write-Warning "    CSV export failed for ${collectorName}: $($_.Exception.Message)"
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # 3. Legacy Protocol Audit CSVs (Kerberos + NTLM event-log analysis)
    # ------------------------------------------------------------------
    $audit = $dataCache['LegacyProtocolAudit']
    if ($audit) {
        $prefix = "${filePrefix}ProtocolAudit"

        # Kerberos breakdown summary
        $krb = $audit.Kerberos
        if ($krb) {
            $krbSummary = [PSCustomObject]@{
                AuditHours   = $audit.AuditHours
                TotalTickets = $krb.TotalAll
                AES_Total    = $krb.AESCount
                RC4_Total    = $krb.RC4Count
                AES_Percent  = $krb.AESPercent
                RC4_Percent  = $krb.RC4Percent
                TGT_AES256   = $krb.Totals.TGT_AES256
                TGT_AES128   = $krb.Totals.TGT_AES128
                TGT_RC4      = $krb.Totals.TGT_RC4
                TGT_Failed   = $krb.Totals.TGT_Failed
                TGT_Other    = $krb.Totals.TGT_Other
                TGS_AES256   = $krb.Totals.TGS_AES256
                TGS_AES128   = $krb.Totals.TGS_AES128
                TGS_RC4      = $krb.Totals.TGS_RC4
                TGS_Failed   = $krb.Totals.TGS_Failed
                TGS_Other    = $krb.Totals.TGS_Other
                Failed_Total = $krb.FailedCount
                Other_Total  = $krb.OtherCount
            }
            @($krbSummary) | Export-Csv -Path (Join-Path $csvDir "${prefix}_Kerberos_Summary.csv") -NoTypeInformation -Encoding UTF8

            # Top RC4 TGT accounts
            if ($krb.TopRC4TGTAccounts -and $krb.TopRC4TGTAccounts.Count -gt 0) {
                $krb.TopRC4TGTAccounts | Export-Csv -Path (Join-Path $csvDir "${prefix}_RC4_TGT_Accounts.csv") -NoTypeInformation -Encoding UTF8
            }
            # Top RC4 TGS services
            if ($krb.TopRC4TGSServices -and $krb.TopRC4TGSServices.Count -gt 0) {
                $krb.TopRC4TGSServices | Export-Csv -Path (Join-Path $csvDir "${prefix}_RC4_TGS_Services.csv") -NoTypeInformation -Encoding UTF8
            }
            # Top RC4 client IPs
            if ($krb.TopRC4ClientIPs -and $krb.TopRC4ClientIPs.Count -gt 0) {
                $krb.TopRC4ClientIPs | Export-Csv -Path (Join-Path $csvDir "${prefix}_RC4_ClientIPs.csv") -NoTypeInformation -Encoding UTF8
            }
            # Top RC4 DCs
            if ($krb.TopRC4DCs -and $krb.TopRC4DCs.Count -gt 0) {
                $krb.TopRC4DCs | Export-Csv -Path (Join-Path $csvDir "${prefix}_RC4_DCs.csv") -NoTypeInformation -Encoding UTF8
            }
            # Top Failed auth accounts
            if ($krb.TopFailedAccounts -and $krb.TopFailedAccounts.Count -gt 0) {
                $krb.TopFailedAccounts | Export-Csv -Path (Join-Path $csvDir "${prefix}_Kerberos_FailedAccounts.csv") -NoTypeInformation -Encoding UTF8
            }
            # Unknown encryption types breakdown
            if ($krb.OtherEncTypes -and $krb.OtherEncTypes.Count -gt 0) {
                $krb.OtherEncTypes | Export-Csv -Path (Join-Path $csvDir "${prefix}_Kerberos_OtherEncTypes.csv") -NoTypeInformation -Encoding UTF8
            }
        }

        # NTLM summary
        $ntlm = $audit.NTLM
        if ($ntlm) {
            $ntlmSummary = [PSCustomObject]@{
                AuditHours    = $audit.AuditHours
                TotalEvents   = $ntlm.TotalEvents
                NTLMv1_Count  = $ntlm.NTLMv1Count
                NTLMv2_Count  = $ntlm.NTLMv2Count
                NTLMv1_Pct    = $ntlm.NTLMv1Percent
                NTLMv2_Pct    = $ntlm.NTLMv2Percent
            }
            @($ntlmSummary) | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLM_Summary.csv") -NoTypeInformation -Encoding UTF8

            if ($ntlm.TopAccounts -and $ntlm.TopAccounts.Count -gt 0) {
                $ntlm.TopAccounts | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLM_Accounts.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopWorkstations -and $ntlm.TopWorkstations.Count -gt 0) {
                $ntlm.TopWorkstations | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLM_Workstations.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopIPs -and $ntlm.TopIPs.Count -gt 0) {
                $ntlm.TopIPs | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLM_IPs.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopDCs -and $ntlm.TopDCs.Count -gt 0) {
                $ntlm.TopDCs | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLM_DCs.csv") -NoTypeInformation -Encoding UTF8
            }
            # Per-version CSVs
            if ($ntlm.TopV1Accounts -and $ntlm.TopV1Accounts.Count -gt 0) {
                $ntlm.TopV1Accounts | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv1_Accounts.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopV1Workstations -and $ntlm.TopV1Workstations.Count -gt 0) {
                $ntlm.TopV1Workstations | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv1_Workstations.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopV1IPs -and $ntlm.TopV1IPs.Count -gt 0) {
                $ntlm.TopV1IPs | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv1_IPs.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopV2Accounts -and $ntlm.TopV2Accounts.Count -gt 0) {
                $ntlm.TopV2Accounts | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv2_Accounts.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopV2Workstations -and $ntlm.TopV2Workstations.Count -gt 0) {
                $ntlm.TopV2Workstations | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv2_Workstations.csv") -NoTypeInformation -Encoding UTF8
            }
            if ($ntlm.TopV2IPs -and $ntlm.TopV2IPs.Count -gt 0) {
                $ntlm.TopV2IPs | Export-Csv -Path (Join-Path $csvDir "${prefix}_NTLMv2_IPs.csv") -NoTypeInformation -Encoding UTF8
            }
        }
    }
}
