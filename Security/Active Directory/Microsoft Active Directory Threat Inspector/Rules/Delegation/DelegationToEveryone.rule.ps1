# Rules\Delegation\DelegationToEveryone.rule.ps1
# Flags delegation granted to Everyone or Authenticated Users. [PingCastle: P-DelegationEveryone]

@{
    Id          = 'MATI-DELEG-007'
    Title       = 'Delegation granted to Everyone or Authenticated Users'
    Severity    = 'Critical'
    Description = "An account with constrained or unconstrained delegation has been configured but the delegation target or the account itself is accessible to Everyone or Authenticated Users. This represents a critical security risk as any authenticated user could potentially exploit the delegation."
    Remediation = "Review and restrict delegation settings. Ensure only dedicated service accounts with strong passwords have delegation configured, and limit delegation targets to specific services."
    Collectors  = @('KerberosConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        # Everyone (S-1-1-0) and Authenticated Users (S-1-5-11) should never have delegation
        $dangerousSIDs = @('S-1-1-0', 'S-1-5-7', 'S-1-5-11')
        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            $sid = $acct.SID
            if ($sid -in $dangerousSIDs) {
                $findings += @{
                    ObjectDN = $acct.DistinguishedName
                    Domain   = $acct.Domain
                    Details  = @{
                        AccountName  = $acct.SamAccountName
                        AccountSID   = $sid
                        Unconstrained = "$($acct.TrustedForDelegation)"
                        Constrained   = "$($acct.TrustedToAuthForDelegation)"
                        Issue         = 'Delegation configured on Everyone-like principal'
                    }
                }
            }
        }
        return $findings
    }
}
