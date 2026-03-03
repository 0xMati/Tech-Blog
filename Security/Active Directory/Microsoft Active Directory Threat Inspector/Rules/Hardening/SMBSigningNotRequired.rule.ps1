# Rules\Hardening\SMBSigningNotRequired.rule.ps1
# Flags DCs where SMB signing is not required.

@{
    Id          = 'MATI-HARD-020'
    Title       = 'SMB signing not required on Domain Controller'
    Severity    = 'High'
    Description = "SMB signing is not required on one or more Domain Controllers. Without mandatory SMB signing, attackers can perform SMB relay attacks and intercept or modify SMB traffic."
    Remediation = "Enable 'Microsoft network server: Digitally sign communications (always)' via GPO on all DCs. Also enable for clients: 'Microsoft network client: Digitally sign communications (always)'."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: A-SMBSigning', 'ANSSI: vuln_smb_signing')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($null -eq $dc.SMBServerSigning -or $dc.SMBServerSigning -ne 1) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName            = $dc.DCName
                        SMBServerSigning  = if ($dc.SMBServerSigning -eq 1) { 'Required' }
                                            elseif ($dc.SMBServerSigning -eq 0) { 'Not Required' }
                                            else { 'Not configured' }
                    }
                }
            }
        }
        return $findings
    }
}
