# Rules\ADCS\ESC7_ManageCA.rule.ps1
# Flags CAs where low-privileged principals have ManageCA/WriteDACL rights.

@{
    Id          = 'MATI-ADCS-008'
    Title       = 'CA management rights granted to low-privileged principal (ESC7)'
    Severity    = 'Critical'
    Description = "A low-privileged principal has WriteDACL, WriteOwner, or GenericAll on the Certificate Authority AD object. This allows the attacker to grant themselves certificate enrollment rights, enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag, or modify CA security settings to escalate privileges."
    Remediation = "Remove dangerous ACEs from the CA enrollment service AD object. Only Domain Admins, Enterprise Admins, and Cert Publishers should have management rights on the CA."
    Collectors  = @('CertificateServices')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/security-best-practices')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($ca in $Data.CertificateServices.CASecurityInfo) {
            if ($ca.LowPrivManageCA) {
                $findings += @{
                    ObjectDN = $ca.CAName
                    Domain   = 'Forest'
                    Details  = @{
                        CAName          = $ca.CAName
                        DNSHostName     = $ca.DNSHostName
                        LowPrivManageCA = 'True'
                    }
                }
            }
        }
        return $findings
    }
}
