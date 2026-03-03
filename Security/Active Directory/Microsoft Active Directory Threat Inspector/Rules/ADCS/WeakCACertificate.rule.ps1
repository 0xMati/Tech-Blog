# Rules\ADCS\WeakCACertificate.rule.ps1
# Flags Certificate Authorities with weak certificate algorithms or short key lengths.

@{
    Id          = 'MATI-ADCS-004'
    Title       = 'Certificate Authority using weak algorithm or key length'
    Severity    = 'Medium'
    Description = "A Certificate Authority is using a weak signing algorithm (SHA1, MD5) or has a key length shorter than 2048 bits. Weak algorithms are vulnerable to collision attacks, and short keys can be factored by modern hardware."
    Remediation = "Renew the CA certificate with SHA256 or higher and a minimum 2048-bit RSA key (4096 recommended). Plan a CA certificate migration if needed."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: A-WeakRSARootCert, A-SHA1RootCert', 'ANSSI: vuln_adcs_weak_cert')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        $weakAlgorithms = @('SHA1', 'MD5', 'MD4', 'MD2')

        foreach ($ca in $Data.CertificateServices.EnrollmentServices) {
            $issues = @()

            # Check signing algorithm
            if ($ca.CertAlgorithm) {
                foreach ($weak in $weakAlgorithms) {
                    if ($ca.CertAlgorithm -match $weak) {
                        $issues += "WeakAlgorithm=$($ca.CertAlgorithm)"
                        break
                    }
                }
            }

            # Check key length
            if ($ca.CertKeyLength -and $ca.CertKeyLength -lt 2048) {
                $issues += "ShortKey=$($ca.CertKeyLength)bits"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $ca.DistinguishedName
                    Domain   = $ca.Domain
                    Details  = @{
                        CAName               = $ca.Name
                        CertificateAlgorithm = "$($ca.CertAlgorithm)"
                        KeyLength            = "$($ca.CertKeyLength)"
                        Issues               = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}
