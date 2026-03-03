# Rules\Kerberos\UnconstrainedDelegation.rule.ps1
# Flags non-DC accounts with unconstrained Kerberos delegation.

@{
    Id          = 'MATI-KERB-006'
    Title       = 'Unconstrained Kerberos delegation on non-DC account'
    Severity    = 'High'
    Description = "A user or computer account that is not a domain controller has unconstrained Kerberos delegation configured. This account can receive and store TGTs of users who authenticate to it, allowing an attacker who compromises this server to impersonate any user."
    Remediation = "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation (RBCD). If not possible, add the account to the 'Protected Users' group or set 'Account is sensitive and cannot be delegated'."
    Collectors  = @('KerberosConfig')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($account in $Data.KerberosConfig.DelegationAccounts) {
            if (-not $account.TrustedForDelegation) { continue }
            if (-not $account.Enabled) { continue }

            # Exclude DCs (they legitimately have unconstrained delegation)
            $isDC = $account.DistinguishedName -match 'OU=Domain Controllers'
            if ($isDC) { continue }

            $findings += @{
                ObjectDN = $account.DistinguishedName
                Domain   = $account.Domain
                Details  = @{
                    SamAccountName       = $account.SamAccountName
                    ObjectClass          = $account.ObjectClass
                    TrustedForDelegation = 'True'
                    OperatingSystem      = "$($account.OperatingSystem)"
                }
            }
        }
        return $findings
    }
}
