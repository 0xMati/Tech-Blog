# Rules\Delegation\DelegationToNonExistent.rule.ps1
# Flags constrained delegation to non-existing targets. [PingCastle: P-UnkownDelegation]

@{
    Id          = 'MATI-DELEG-008'
    Title       = 'Constrained delegation to non-existing target'
    Severity    = 'High'
    Description = "An account has constrained delegation (msDS-AllowedToDelegateTo) configured to a service whose host cannot be resolved in DNS or Active Directory. This may indicate a stale delegation entry from a decommissioned server, or a potential attack vector where an attacker could register the missing hostname to intercept delegated authentication."
    Remediation = "Remove the stale delegation target from msDS-AllowedToDelegateTo. If the target service has been decommissioned, un-configure the delegation entirely."
    Collectors  = @('KerberosConfig', 'ComputerAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Build set of known computer names and hostnames
        $knownHosts = @{}
        foreach ($comp in $Data.ComputerAccounts) {
            $name = $comp.SamAccountName -replace '\$$', ''
            $knownHosts[$name.ToLower()] = $true
            if ($comp.DNSHostName) { $knownHosts[$comp.DNSHostName.ToLower()] = $true }
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            foreach ($spn in $acct.AllowedToDelegateTo) {
                $parts = $spn -split '/'
                if ($parts.Count -lt 2) { continue }
                $targetHost = ($parts[1] -split ':')[0].ToLower()

                if (-not $knownHosts.ContainsKey($targetHost)) {
                    $findings += @{
                        ObjectDN = $acct.DistinguishedName
                        Domain   = $acct.Domain
                        Details  = @{
                            AccountName      = $acct.SamAccountName
                            DelegationTarget = $spn
                            MissingHost      = $targetHost
                            Issue            = 'Delegation target host not found in AD'
                        }
                    }
                }
            }
        }
        return $findings
    }
}
