# Rules\ADCS\ESC6_EditfSAN.rule.ps1
# Flags CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.

@{
    Id          = 'MATI-ADCS-007'
    Title       = 'CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled (ESC6)'
    Severity    = 'Critical'
    Description = "The Certificate Authority permits request-supplied Subject Alternative Names through EDITF_ATTRIBUTESUBJECTALTNAME2. This is a dangerous CA-wide setting, but impersonation also depends on enrollment permissions, authentication EKUs, approval/signature requirements and effective certificate mapping. It does not make every template automatically exploitable; strong mapping and ESC9 chains must be assessed separately."
    Remediation = "Disable the flag on the CA: certutil -config 'CA\CAName' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. Then restart the CertSvc service."
    Collectors  = @('CertificateServices')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/security-best-practices')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($ca in $Data.CertificateServices.CASecurityInfo) {
            if ($ca.EditfSANEnabled -eq $true) {
                $findings += @{
                    ObjectDN = $ca.CAName
                    Domain   = 'Forest'
                    Details  = @{
                        CAName             = $ca.CAName
                        DNSHostName        = $ca.DNSHostName
                        EDITF_SAN_Enabled  = 'True'
                    }
                }
            }
        }
        return $findings
    }
}
