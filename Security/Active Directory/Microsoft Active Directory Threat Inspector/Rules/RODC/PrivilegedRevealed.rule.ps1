# Rules\RODC\PrivilegedRevealed.rule.ps1
# Flags privileged accounts whose passwords are cached on an RODC.

@{
    Id          = 'MATI-RODC-001'
    Title       = 'Privileged account password cached on RODC'
    Severity    = 'Critical'
    Description = "A privileged account (AdminCount=1) has had its password cached (revealed) on a Read-Only Domain Controller. If the RODC is physically compromised (common in branch offices), the attacker obtains the privileged account's password hash."
    Remediation = "Reset the password of the revealed privileged account immediately. Ensure the RODC Denied Replication Group includes all privileged groups. Review the RODC Password Replication Policy."
    Collectors  = @('RODCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/read-only-domain-controller-planning')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.RODCInfo.RevealedPrivileged) {
            $findings += @{
                ObjectDN = $entry.RevealedDN
                Domain   = $entry.Domain
                Details  = @{
                    RODCName     = $entry.RODCName
                    RevealedUser = $entry.RevealedUser
                    IsPrivileged = 'True'
                }
            }
        }
        return $findings
    }
}
