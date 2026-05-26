# Rules\ADCS\ESC6_EditfSAN.rule.ps1
# Flags CAs with EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.

@{
    Id          = 'MATI-ADCS-007'
    Title       = 'CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled (ESC6)'
    Severity    = 'Critical'
    Description = "The Certificate Authority has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled. This flag allows any certificate requestor to specify an arbitrary Subject Alternative Name (SAN) in their request, regardless of the template settings. This effectively makes ALL templates vulnerable to ESC1-style attacks."
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
