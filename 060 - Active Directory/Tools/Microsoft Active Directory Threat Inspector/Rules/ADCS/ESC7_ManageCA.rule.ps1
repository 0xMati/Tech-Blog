# Rules\ADCS\ESC7_ManageCA.rule.ps1
# Flags CAs where low-privileged principals have ManageCA/WriteDACL rights.

@{
    Id          = 'MATI-ADCS-008'
    Title       = 'CA management rights granted to low-privileged principal (ESC7)'
    Severity    = 'Critical'
    Description = "The CA service security descriptor grants Manage CA or Issue and Manage Certificates to a broad low-privileged group. These CA permissions are distinct from the ACL of the enrollment service object in Active Directory. Review effective permissions, deny ACEs and role separation."
    Remediation = "Review the Security tab in the Certification Authority console and remove broad low-privileged grants of Manage CA and Issue and Manage Certificates. Assign these permissions only to dedicated authorized CA administrators and certificate managers."
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
                        SecuritySource  = 'CA service security descriptor'
                        ManagementACEs  = ($ca.ManagementACEs | ForEach-Object { "$($_.SID): ManageCA=$($_.ManageCA), ManageCertificates=$($_.ManageCertificates)" }) -join '; '
                    }
                }
            }
        }
        return $findings
    }
}
