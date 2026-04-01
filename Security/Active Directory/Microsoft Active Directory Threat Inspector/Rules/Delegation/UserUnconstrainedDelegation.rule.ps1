# Rules\Delegation\UserUnconstrainedDelegation.rule.ps1
# Flags user accounts with unconstrained delegation.

@{
    Id          = 'MATI-DELEG-004'
    Title       = 'Unconstrained delegation on user account'
    Severity    = 'Critical'
    Description = "A user account has unconstrained delegation enabled (TrustedForDelegation). Any service running under this account will cache TGTs of connecting users. User accounts with unconstrained delegation are especially dangerous because they can be compromised through password attacks."
    Remediation = "Remove the TrustedForDelegation flag from the user account. Migrate to constrained delegation or RBCD."
    Collectors  = @('KerberosConfig')
    References  = @('https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-kerberos-delegation')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            if (-not $acct.TrustedForDelegation) { continue }
            if (-not $acct.Enabled) { continue }
            if ($acct.ObjectClass -ne 'user') { continue }

            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    AccountName          = $acct.SamAccountName
                    Enabled              = "$($acct.Enabled)"
                    TrustedForDelegation = 'True'
                }
            }
        }
        return $findings
    }
}
