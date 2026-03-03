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

    # ------------------------------------------------------------------
    # 1. Global findings CSV
    # ------------------------------------------------------------------
    $findingsForCsv = $findings | ForEach-Object {
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
            Details     = ($_.Details.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
            Timestamp   = $_.Timestamp
        }
    }

    $findingsPath = Join-Path $csvDir "MATI_Findings_$timestamp.csv"
    if ($findingsForCsv) {
        $findingsForCsv | Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
    }

    # ------------------------------------------------------------------
    # 2. Raw data CSVs (one per collector that returned data)
    # ------------------------------------------------------------------
    foreach ($collectorName in $dataCache.Keys) {
        # Skip LegacyProtocolAudit — handled separately below
        if ($collectorName -eq 'LegacyProtocolAudit') { continue }

        $data = $dataCache[$collectorName]

        if ($data -is [hashtable]) {
            # Collector returned a hashtable with multiple datasets
            foreach ($subKey in $data.Keys) {
                $subData = @($data[$subKey])
                if ($subData.Count -gt 0 -and $subData[0] -is [PSCustomObject]) {
                    $subPath = Join-Path $csvDir "MATI_${collectorName}_${subKey}.csv"
                    $subData | Export-Csv -Path $subPath -NoTypeInformation -Encoding UTF8
                }
            }
        }
        elseif ($data -is [array] -and $data.Count -gt 0) {
            $dataPath = Join-Path $csvDir "MATI_${collectorName}.csv"
            $data | Export-Csv -Path $dataPath -NoTypeInformation -Encoding UTF8
        }
    }

    # ------------------------------------------------------------------
    # 3. Legacy Protocol Audit CSVs (Kerberos + NTLM event-log analysis)
    # ------------------------------------------------------------------
    $audit = $dataCache['LegacyProtocolAudit']
    if ($audit) {
        $prefix = "MATI_ProtocolAudit"

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
                TGT_Unknown  = $krb.Totals.TGT_Unknown
                TGS_AES256   = $krb.Totals.TGS_AES256
                TGS_AES128   = $krb.Totals.TGS_AES128
                TGS_RC4      = $krb.Totals.TGS_RC4
                TGS_Unknown  = $krb.Totals.TGS_Unknown
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
        }
    }
}
