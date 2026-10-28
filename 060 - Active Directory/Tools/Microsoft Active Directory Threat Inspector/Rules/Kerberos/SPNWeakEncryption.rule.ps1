# Rules\Kerberos\SPNWeakEncryption.rule.ps1
# ORADAD: vuln_kerberos_properties_encryption
# Flags service accounts (SPN) with weak or missing encryption types.

@{
    Id          = 'MATI-KERB-010'
    Title       = 'Service account with weak Kerberos encryption type'
    Severity    = 'Medium'
    Description = "A service account with SPN explicitly advertises weak Kerberos encryption types, or does not explicitly advertise AES and therefore requires runtime verification. Explicit DES/RC4-only configuration is treated as a stronger signal than an unset attribute."
    Remediation = "If msDS-SupportedEncryptionTypes is explicitly weak, move the account to AES-capable encryption types and rotate its secret. If the attribute is unset, verify recent 4769 activity before changing the account, then set msDS-SupportedEncryptionTypes explicitly if needed."
    Collectors  = @('KerberosConfig', 'LegacyProtocolAudit')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-supported-encryption-types'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $domainBuckets = @{}
        $rc4ServiceSIDs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $rc4ServiceAccounts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($svc in @($Data.LegacyProtocolAudit.Kerberos.RC4ServiceObservations)) {
            if ($svc.SID) { $null = $rc4ServiceSIDs.Add([string]$svc.SID) }
            if ($svc.Name -and $svc.Domain) { $null = $rc4ServiceAccounts.Add("$($svc.Domain)|$($svc.Name)") }
        }

        foreach ($spnAccount in $Data.KerberosConfig.SPNAccounts) {
            if (-not $spnAccount.Enabled) { continue }
            # Skip krbtgt accounts — their encryption is handled by KERB-008
            if ($spnAccount.SamAccountName -like 'krbtgt*') { continue }

            $encTypes = $spnAccount.SupportedEncryptionTypes
            if ($encTypes -eq 0) { $encTypes = $null }
            $hasExplicitAES = ($null -ne $encTypes) -and (($encTypes -band 0x18) -ne 0)
            $hasExplicitWeakOnly = ($null -ne $encTypes) -and (-not $hasExplicitAES)
            $observedRc4ServiceTicket = ($spnAccount.SID -and $rc4ServiceSIDs.Contains([string]$spnAccount.SID)) -or
                $rc4ServiceAccounts.Contains("$($spnAccount.Domain)|$($spnAccount.SamAccountName)")
            $observationComplete = $Data.LegacyProtocolAudit.Kerberos.RC4ServiceObservationsComplete -eq $true

            if ($hasExplicitWeakOnly -or $null -eq $encTypes) {
                $encDisplay = if ($null -eq $encTypes) { 'Not set (verification required)' } else { "0x$($encTypes.ToString('X'))" }
                $classification = if ($hasExplicitWeakOnly) {
                    if ($observedRc4ServiceTicket) { 'ExplicitWeakObservedRC4' } else { 'ExplicitWeakNoObservedRC4' }
                } else {
                    if ($observedRc4ServiceTicket) { 'UnsetObservedRC4' } else { 'UnsetNoObservedRC4' }
                }
                if (-not $observedRc4ServiceTicket -and -not $observationComplete) {
                    $classification = if ($hasExplicitWeakOnly) { 'ExplicitWeakObservationIncomplete' } else { 'UnsetObservationIncomplete' }
                }
                $severity = switch ($classification) {
                    'ExplicitWeakObservedRC4' { 'High' }
                    'ExplicitWeakNoObservedRC4' { 'Medium' }
                    'ExplicitWeakObservationIncomplete' { 'Medium' }
                    'UnsetObservedRC4' { 'Medium' }
                    default { 'Informational' }
                }

                $key = "$($spnAccount.Domain)|$classification"
                if (-not $domainBuckets.ContainsKey($key)) {
                    $domainBuckets[$key] = @{
                        Domain   = $spnAccount.Domain
                        Severity = $severity
                        Classification = $classification
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $domainBuckets[$key].Count++
                if ($domainBuckets[$key].Examples.Count -lt 10) {
                    $suffix = if ($observedRc4ServiceTicket) { 'RC4 observed' } elseif ($observationComplete) { 'no RC4 observed in the audit window' } else { 'RC4 observation incomplete' }
                    $domainBuckets[$key].Examples.Add("$($spnAccount.SamAccountName) ($encDisplay, $suffix)")
                }
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $findings += @{
                Severity = $bucket.Severity
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    Classification        = $bucket.Classification
                    WeakEncryptionSPNCount = "$($bucket.Count)"
                    Examples               = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}
