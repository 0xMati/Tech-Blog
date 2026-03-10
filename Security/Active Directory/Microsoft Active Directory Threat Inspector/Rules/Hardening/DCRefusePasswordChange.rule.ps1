# Rules\Hardening\DCRefusePasswordChange.rule.ps1
# Flags DCs that refuse computer password changes. [PingCastle: A-DCRefuseComputerPwdChange]

@{
    Id          = 'MATI-HARD-046'
    Title       = 'Domain Controller refuses computer password change'
    Severity    = 'High'
    Description = "One or more Domain Controllers have the registry value 'RefusePasswordChange' set to 1 under HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters. This prevents computers from rotating their machine account passwords, leaving stale credentials that can be exploited for lateral movement or credential theft."
    Remediation = "Remove or set to 0 the RefusePasswordChange registry value on all Domain Controllers. Ensure the domain allows regular machine account password rotation (default every 30 days)."
    Collectors  = @('DCInfo')
    References  = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/disable-machine-account-password')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.DCInfo) {
            if ($dc.RefusePasswordChange -eq 1) {
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName               = $dc.Name
                        HostName             = $dc.HostName
                        RefusePasswordChange = '1 (Enabled)'
                        Issue                = 'Machine account password changes are refused by this DC'
                    }
                }
            }
        }
        return $findings
    }
}
