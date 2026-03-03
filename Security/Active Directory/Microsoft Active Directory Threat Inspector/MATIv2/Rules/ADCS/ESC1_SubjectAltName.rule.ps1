# Rules\ADCS\ESC1_SubjectAltName.rule.ps1
# Flags certificate templates allowing requestor-defined Subject Alternative Name (ESC1).

@{
    Id          = 'MATI-ADCS-001'
    Title       = 'Certificate template allows requestor to specify SAN (ESC1)'
    Severity    = 'Critical'
    Description = "A certificate template allows the enrollee to supply a Subject Alternative Name (SAN), can be used for authentication, and is enrollable by low-privileged users. An attacker can request a certificate with a Domain Admin SAN and use it to authenticate as that admin."
    Remediation = "Remove the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag from the template (uncheck 'Supply in the request' on the Subject Name tab). If SAN is required, enable manager approval."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: A-CertTempCustomSubject', 'SpecterOps: ESC1')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($tmpl in $Data.CertificateServices.Templates) {
            if ($tmpl.ESC1) {
                $findings += @{
                    ObjectDN = $tmpl.DistinguishedName
                    Domain   = $tmpl.Domain
                    Details  = @{
                        TemplateName            = $tmpl.Name
                        DisplayName             = $tmpl.DisplayName
                        EnrolleeSuppliesSubject = 'True'
                        IsAuthTemplate          = "$($tmpl.IsAuthTemplate)"
                        LowPrivEnrollment       = "$($tmpl.LowPrivEnrollment)"
                        ManagerApproval         = "$($tmpl.ManagerApproval)"
                        ESC                     = 'ESC1'
                    }
                }
            }
        }
        return $findings
    }
}
