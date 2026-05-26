# Rules\ADCS\ESC10_WeakCertificateMapping.rule.ps1
# Flags DCs that allow weak Schannel UPN certificate mapping while low-privileged auth templates exist.

@{
    Id          = 'MATI-ADCS-011'
    Title       = 'Domain Controller allows weak Schannel UPN certificate mapping (ESC10)'
    Severity    = 'High'
    Description = "A Domain Controller is configured with Schannel certificate mapping methods that include UPN mapping (CertificateMappingMethods bit 0x4). If low-privileged users can enroll in a client-authentication certificate template, this creates the classic ESC10 exposure for LDAPS and other Schannel-backed authentication paths."
    Remediation = "Set CertificateMappingMethods to the hardened value recommended by Microsoft, typically 0x18, and review any low-privileged client-authentication templates that could be used in certificate impersonation chains."
    Collectors  = @('CertificateServices', 'ProtocolConfig')
    References  = @(
        'https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication'
        'https://support.microsoft.com/help/5014754'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        if (-not $Data.CertificateServices.IsADCSDeployed) { return $findings }

        $candidateTemplates = @($Data.CertificateServices.Templates | Where-Object {
            $authorizedSignatures = if ($null -ne $_.AuthorizedSignatures) { [int]$_.AuthorizedSignatures } else { 0 }
            $_.IsPublished -and $_.IsAuthTemplate -and $_.LowPrivEnrollment -and -not $_.ManagerApproval -and $authorizedSignatures -eq 0
        })
        if ($candidateTemplates.Count -eq 0) { return $findings }

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($null -eq $dc.CertificateMappingMethods) { continue }
            if (($dc.CertificateMappingMethods -band 0x4) -eq 0) { continue }

            $templateNames = @($candidateTemplates | Select-Object -ExpandProperty Name | Sort-Object -Unique)
            $sampleTemplates = ($templateNames | Select-Object -First 5) -join '; '

            $findings += @{
                ObjectDN = $dc.HostName
                Domain   = $dc.Domain
                Details  = @{
                    DCName                         = $dc.DCName
                    HostName                       = $dc.HostName
                    CertificateMappingMethods      = "0x$(([int]$dc.CertificateMappingMethods).ToString('X'))"
                    IncludesUPNMapping             = 'True'
                    StrongCertificateBinding       = if ($null -ne $dc.StrongCertificateBindingEnforcement) { $dc.StrongCertificateBindingEnforcement } else { 'Unknown' }
                    CandidateTemplateCount         = $templateNames.Count
                    CandidateTemplates             = $sampleTemplates
                    ESC                            = 'ESC10'
                }
            }
        }

        return $findings
    }
}