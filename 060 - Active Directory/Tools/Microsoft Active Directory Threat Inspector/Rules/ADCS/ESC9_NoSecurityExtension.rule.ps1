# Rules\ADCS\ESC9_NoSecurityExtension.rule.ps1
# Flags published low-privileged authentication templates that omit the SID security extension.

@{
    Id          = 'MATI-ADCS-010'
    Title       = 'Certificate template omits SID security extension (ESC9)'
    Severity    = 'High'
    Description = "A published authentication template enrollable by low-privileged principals is configured with CT_FLAG_NO_SECURITY_EXTENSION. Certificates issued from this template omit the SID security extension used for strong certificate mapping, which reintroduces certificate impersonation paths depending on DC binding mode or CA SAN handling."
    Remediation = "Remove CT_FLAG_NO_SECURITY_EXTENSION from the template. If that behavior is required for a compatibility exception, restrict enrollment rights tightly and ensure DCs enforce strong certificate binding."
    Collectors  = @('CertificateServices', 'ProtocolConfig')
    References  = @(
        'https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template'
        'https://support.microsoft.com/help/5014754'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        $dcProtocol = @($Data.ProtocolConfig.DCProtocolSettings | Where-Object {
            $_.WinRMAccessible -and $null -ne $_.StrongCertificateBindingEnforcement
        })
        $weakBindingDCs = @($dcProtocol | Where-Object { $_.StrongCertificateBindingEnforcement -lt 2 })
        $fullBindingDCs = @($dcProtocol | Where-Object { $_.StrongCertificateBindingEnforcement -eq 2 })
        $esc6CAs = @($Data.CertificateServices.CASecurityInfo | Where-Object { $_.EditfSANEnabled -eq $true } | Select-Object -ExpandProperty CAName)

        $bindingSummary = 'Unknown'
        if ($weakBindingDCs.Count -gt 0) {
            $bindingSummary = "WeakOrCompatibility: $((@($weakBindingDCs | Select-Object -ExpandProperty DCName | Sort-Object -Unique) -join ', '))"
        }
        elseif ($fullBindingDCs.Count -gt 0) {
            $bindingSummary = 'FullEnforcementObserved'
        }

        foreach ($tmpl in $Data.CertificateServices.Templates) {
            $authorizedSignatures = 0
            if ($null -ne $tmpl.AuthorizedSignatures) {
                $authorizedSignatures = [int]$tmpl.AuthorizedSignatures
            }

            if (-not $tmpl.NoSecurityExtension) { continue }
            if (-not $tmpl.IsAuthTemplate) { continue }
            if (-not $tmpl.LowPrivEnrollment) { continue }
            if (-not $tmpl.IsPublished) { continue }
            if ($tmpl.ManagerApproval) { continue }
            if ($authorizedSignatures -gt 0) { continue }

            $exploitability = 'Additional prerequisites required'
            if ($esc6CAs.Count -gt 0) {
                $exploitability = 'Strong chain present with ESC6-capable CA'
            }
            elseif ($weakBindingDCs.Count -gt 0) {
                $exploitability = 'Weak or compatibility KDC binding observed'
            }

            $findings += @{
                ObjectDN = $tmpl.DistinguishedName
                Domain   = 'Forest'
                Details  = @{
                    TemplateName              = $tmpl.Name
                    DisplayName               = $tmpl.DisplayName
                    PublishedOnCAs            = ($tmpl.PublishedOnCAs -join '; ')
                    NoSecurityExtension       = 'True'
                    StrongBindingSummary      = $bindingSummary
                    ESC6CapableCAs            = if ($esc6CAs.Count -gt 0) { $esc6CAs -join '; ' } else { '' }
                    ExploitabilityContext     = $exploitability
                    ESC                       = 'ESC9'
                }
            }
        }

        return $findings
    }
}