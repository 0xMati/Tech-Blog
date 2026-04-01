# Rules\Hardening\LegacyDCEncryption.rule.ps1
# Flags DCs not supporting AES encryption.

@{
    Id          = 'MATI-HARD-016'
    Title       = 'Domain Controller does not support AES encryption'
    Severity    = 'Informational'
    Description = "This control distinguishes an explicitly weak DC computer account configuration from an unset attribute that only requires verification. Recent RC4 service ticket activity targeting the DC raises confidence; attribute-only null or zero values are not treated as proof that the KDC cannot issue AES tickets."
    Remediation = "If a DC computer account explicitly lacks AES and recent RC4 service tickets target that DC, update msDS-SupportedEncryptionTypes to include AES128 and AES256, then rotate the machine account secret. If the attribute is unset or no runtime evidence exists, verify recent 4769 traffic to the DC before treating it as a true issue."
    Collectors  = @('DCInfo', 'LegacyProtocolAudit')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-supported-encryption-types')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $observedRc4DcTargets = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($svc in @($Data.LegacyProtocolAudit.Kerberos.TopRC4TGSServices)) {
            if ($svc.Name) { $null = $observedRc4DcTargets.Add("$($svc.Name)") }
        }

        foreach ($svc in @($Data.LegacyProtocolAudit.Kerberos.RC4ServiceDetails)) {
            if ($svc.Name) { $null = $observedRc4DcTargets.Add("$($svc.Name)") }
        }

        foreach ($dc in $Data.DCInfo) {
            $encTypes = $dc.SupportedEncryptionTypes
            $hasExplicitAES = ($null -ne $encTypes) -and (($encTypes -band 0x18) -ne 0)
            if ($hasExplicitAES) { continue }

            $dcShortName = if ($dc.HostName -and $dc.HostName -match '^([^\.]+)') { $Matches[1] } else { $dc.Name }
            $observedRc4 = $observedRc4DcTargets.Contains("$($dc.Name)$") -or
                           $observedRc4DcTargets.Contains("$dcShortName`$") -or
                           $observedRc4DcTargets.Contains("$($dc.Name)") -or
                           $observedRc4DcTargets.Contains("$dcShortName")

            $classification = if ($null -eq $encTypes -or $encTypes -eq 0) {
                if ($observedRc4) { 'UnsetObservedRC4' } else { 'UnsetNoObservedRC4' }
            } else {
                if ($observedRc4) { 'ExplicitWeakObservedRC4' } else { 'ExplicitWeakNoObservedRC4' }
            }

            $severity = switch ($classification) {
                'ExplicitWeakObservedRC4' { 'High' }
                'ExplicitWeakNoObservedRC4' { 'Medium' }
                'UnsetObservedRC4' { 'Medium' }
                default { 'Informational' }
            }

            $supportedEncLabel = if ($null -eq $encTypes) { 'Not set' } elseif ($encTypes -eq 0) { '0x0' } else { "0x$($encTypes.ToString('X'))" }
            $findings += @{
                Severity = $severity
                ObjectDN = $dc.DistinguishedName
                Domain   = $dc.Domain
                Details  = @{
                    DCName                  = $dc.Name
                    HostName                = $dc.HostName
                    OperatingSystem         = "$($dc.OperatingSystem)"
                    SupportedEncryption     = $supportedEncLabel
                    ExplicitAESSupported    = 'False'
                    AuditWindowHours        = if ($Data.LegacyProtocolAudit.AuditHours) { $Data.LegacyProtocolAudit.AuditHours } else { '(unknown)' }
                    RC4ObservedAgainstDC    = "$observedRc4"
                    EvaluationStatus        = switch ($classification) {
                        'ExplicitWeakObservedRC4' { 'Explicit weak setting with RC4 service tickets observed' }
                        'ExplicitWeakNoObservedRC4' { 'Explicit weak setting, but no RC4 service tickets observed in current audit window' }
                        'UnsetObservedRC4' { 'Attribute unset and RC4 service tickets observed' }
                        default { 'Attribute-only verification required' }
                    }
                }
            }
        }
        return $findings
    }
}
