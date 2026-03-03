# Rules\ADCS\ESC8_HttpEnrollment.rule.ps1
# Flags certificate enrollment via HTTP without Extended Protection for Authentication (ESC8).

@{
    Id          = 'MATI-ADCS-003'
    Title       = 'Certificate enrollment via HTTP (ESC8)'
    Severity    = 'High'
    Description = "A Certificate Authority has HTTP enrollment enabled (Certificate Enrollment Web Service or CES). Without NTLM relay protections (EPA), an attacker can relay NTLM authentication from a Domain Controller to the CA web enrollment endpoint and request a certificate as the DC, achieving full domain compromise."
    Remediation = "Disable HTTP enrollment or enable Extended Protection for Authentication (EPA) on the IIS enrollment endpoint. Prefer HTTPS-only enrollment with EPA set to 'Required'."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: A-CertEnrollHttp', 'SpecterOps: ESC8')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        # Flag CAs with HTTP enrollment (ESC8 is a CA-level vulnerability)
        foreach ($ca in $Data.CertificateServices.EnrollmentServices) {
            if ($ca.HasHttpEnrollment) {
                $findings += @{
                    ObjectDN = $ca.DistinguishedName
                    Domain   = $ca.Domain
                    Details  = @{
                        CAName          = $ca.Name
                        CAHostname      = $ca.DNSHostName
                        HasHttpEnroll   = 'True'
                        ESC             = 'ESC8'
                    }
                }
            }
        }
        return $findings
    }
}
