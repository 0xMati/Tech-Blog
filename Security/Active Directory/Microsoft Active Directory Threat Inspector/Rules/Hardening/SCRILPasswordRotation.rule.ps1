# Rules\Hardening\SCRILPasswordRotation.rule.ps1
# Flags when smart card required accounts may have predictable password hashes.

@{
    Id          = 'MATI-HARD-029'
    Title       = 'SCRIL password rotation not enabled for smart card accounts'
    Severity    = 'Medium'
    Description = "The domain attribute msDS-ExpirePasswordsOnSmartCardOnlyAccounts is not enabled. Accounts with the 'Smart card is required for interactive logon' (SCRIL) flag have their password set to a random but fixed value. Without rotation, these password hashes remain static and can be used in pass-the-hash attacks."
    Remediation = "Enable password rotation for SCRIL accounts by setting msDS-ExpirePasswordsOnSmartCardOnlyAccounts to TRUE on the domain object. This requires Windows Server 2016 domain functional level or higher. The KRBTGT-derived password will then be rotated according to the domain password policy."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/scril')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($domainInfo in @($Data.SecurityConfig.SCRILRotation)) {
            if ($domainInfo.ExpirePasswordsOnSCOnly -ne $true) {
                $findings += @{
                    ObjectDN = $domainInfo.DomainDN
                    Domain   = $domainInfo.Domain
                    Details  = @{
                        Domain = $domainInfo.Domain
                        msDS_ExpirePasswordsOnSmartCardOnlyAccounts = if ($null -eq $domainInfo.ExpirePasswordsOnSCOnly) { '(not set)' } else { [string]$domainInfo.ExpirePasswordsOnSCOnly }
                        SCRILAccountCount = $domainInfo.SCRILAccountCount
                    }
                }
            }
        }
        return $findings
    }
}
