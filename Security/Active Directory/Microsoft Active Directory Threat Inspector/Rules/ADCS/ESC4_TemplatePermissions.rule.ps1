# Rules\ADCS\ESC4_TemplatePermissions.rule.ps1
# Flags certificate templates editable by low-privileged users (ESC4).

@{
    Id          = 'MATI-ADCS-002'
    Title       = 'Certificate template editable by low-privileged users (ESC4)'
    Severity    = 'Critical'
    Description = "A certificate template can be modified (full control, write permissions) by low-privileged users such as Domain Users, Domain Computers, Everyone, or Authenticated Users. An attacker can modify the template to enable ESC1 (custom SAN) and request a certificate as any user."
    Remediation = "Remove write/modify permissions from the template ACL for low-privileged groups. Only CA Admins and Enterprise Admins should have write access to certificate templates."
    Collectors  = @('CertificateServices')
    References  = @('PingCastle: A-CertTempAnyone', 'SpecterOps: ESC4')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        foreach ($tmpl in $Data.CertificateServices.Templates) {
            if ($tmpl.LowPrivFullControl -and $tmpl.IsPublished) {
                $findings += @{
                    ObjectDN = $tmpl.DistinguishedName
                    Domain   = $tmpl.Domain
                    Details  = @{
                        TemplateName       = $tmpl.Name
                        DisplayName        = $tmpl.DisplayName
                        LowPrivFullControl = "$($tmpl.LowPrivFullControl)"
                        ESC                = 'ESC4'
                    }
                }
            }
        }
        return $findings
    }
}
