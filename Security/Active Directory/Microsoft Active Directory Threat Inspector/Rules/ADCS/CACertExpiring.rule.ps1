# Rules\ADCS\CACertExpiring.rule.ps1
# Flags CA certificates that are expired or expiring soon.

@{
    Id          = 'MATI-ADCS-009'
    Title       = 'CA certificate expired or expiring soon'
    Severity    = 'High'
    Description = "A Certificate Authority's root or issuing certificate is expired or will expire within 180 days. An expired CA certificate means no new certificates can be issued, and certificate chain validation will fail for all subordinate certificates."
    Remediation = "Renew the CA certificate before expiration. For root CAs, re-issue the root certificate. For subordinate CAs, submit a renewal request to the parent CA."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: S-CertificateExpired', 'ANSSI: vuln_adcs_expired_cert')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($ca in $Data.CertificateServices.CASecurityInfo) {
            if ($null -eq $ca.CertExpiresInDays) { continue }

            if ($ca.CertExpiresInDays -le 0) {
                $findings += @{
                    ObjectDN = $ca.CAName
                    Domain   = 'Forest'
                    Severity = 'Critical'
                    Details  = @{
                        CAName        = $ca.CAName
                        CertExpiry    = "$($ca.CertExpiry)"
                        DaysRemaining = $ca.CertExpiresInDays
                        Status        = 'EXPIRED'
                    }
                }
            }
            elseif ($ca.CertExpiresInDays -le ($Config.Thresholds.CACertExpiryWarningDays ?? 180)) {
                $sev = if ($ca.CertExpiresInDays -le 30) { 'High' } else { 'Medium' }
                $findings += @{
                    ObjectDN = $ca.CAName
                    Domain   = 'Forest'
                    Severity = $sev
                    Details  = @{
                        CAName        = $ca.CAName
                        CertExpiry    = "$($ca.CertExpiry)"
                        DaysRemaining = $ca.CertExpiresInDays
                        Status        = 'Expiring soon'
                    }
                }
            }
        }
        return $findings
    }
}
