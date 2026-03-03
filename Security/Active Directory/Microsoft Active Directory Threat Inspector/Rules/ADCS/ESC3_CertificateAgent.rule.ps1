# Rules\ADCS\ESC3_CertificateAgent.rule.ps1
# Flags certificate templates that allow enrollment agent (certificate request agent).

@{
    Id          = 'MATI-ADCS-006'
    Title       = 'Certificate template allows enrollment agent (ESC3)'
    Severity    = 'Critical'
    Description = "A published certificate template has the Certificate Request Agent OID (1.3.6.1.4.1.311.20.2.1) in its EKU and allows low-privileged enrollment without manager approval. An enrollment agent certificate can be used to request certificates on behalf of other users, including domain admins."
    Remediation = "Restrict enrollment agent template enrollment to highly privileged groups only. Enable manager approval (CT_FLAG_PEND_ALL_REQUESTS). Configure enrollment agent restrictions on the CA."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: A-CertTempAgent', 'SpecterOps: ESC3')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($tmpl in $Data.CertificateServices.Templates) {
            if (-not $tmpl.IsPublished) { continue }
            if (-not $tmpl.IsCertRequestAgent) { continue }
            if (-not $tmpl.LowPrivEnrollment) { continue }
            if ($tmpl.ManagerApproval) { continue }

            $findings += @{
                ObjectDN = $tmpl.DistinguishedName
                Domain   = 'Forest'
                Details  = @{
                    TemplateName      = $tmpl.Name
                    DisplayName       = $tmpl.DisplayName
                    LowPrivEnrollment = 'Yes'
                    ManagerApproval   = 'No'
                    PublishedOn       = ($tmpl.PublishedOnCAs -join ', ')
                }
            }
        }
        return $findings
    }
}
