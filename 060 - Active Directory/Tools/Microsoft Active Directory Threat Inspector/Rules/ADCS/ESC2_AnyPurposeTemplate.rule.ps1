# Rules\ADCS\ESC2_AnyPurposeTemplate.rule.ps1
# Flags certificate templates with Any Purpose EKU or no EKU (SubCA).

@{
    Id          = 'MATI-ADCS-005'
    Title       = 'Certificate template with Any Purpose or no EKU (ESC2)'
    Severity    = 'Critical'
    Description = "A published certificate template has the 'Any Purpose' EKU or no EKU defined, combined with low-privileged enrollment rights and no manager approval. This allows any enrolled certificate to be used for any purpose including client authentication, code signing, and more."
    Remediation = "Remove the 'Any Purpose' OID (2.5.29.37.0) from the template and specify explicit EKUs. If the template is a SubCA template, restrict enrollment to highly privileged accounts only and require manager approval."
    Collectors  = @('CertificateServices')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/security-best-practices')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($tmpl in $Data.CertificateServices.Templates) {
            if (-not $tmpl.IsPublished) { continue }
            if (-not $tmpl.IsAnyPurpose) { continue }
            if (-not $tmpl.LowPrivEnrollment) { continue }
            if ($tmpl.ManagerApproval) { continue }

            $findings += @{
                ObjectDN = $tmpl.DistinguishedName
                Domain   = 'Forest'
                Details  = @{
                    TemplateName        = $tmpl.Name
                    DisplayName         = $tmpl.DisplayName
                    EKUs                = if ($tmpl.EKUs.Count -eq 0) { 'None (SubCA-like)' } else { ($tmpl.EKUs -join ', ') }
                    LowPrivEnrollment   = 'Yes'
                    ManagerApproval     = 'No'
                    PublishedOn         = ($tmpl.PublishedOnCAs -join ', ')
                }
            }
        }
        return $findings
    }
}
