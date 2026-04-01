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

        # Build set of known computer names, hostnames, and published SPN targets.
        $knownHosts = @{}
        $knownSpns = @{}

        foreach ($comp in $Data.ComputerAccounts) {
            $name = $comp.SamAccountName -replace '\$$', ''
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $knownHosts[$name.ToLower()] = $true
            }

            if ($comp.DNSHostName) {
                $dnsName = $comp.DNSHostName.ToLower()
                $knownHosts[$dnsName] = $true

                $shortDnsName = ($dnsName -split '\.', 2)[0]
                if (-not [string]::IsNullOrWhiteSpace($shortDnsName)) {
                    $knownHosts[$shortDnsName] = $true
                }
            }

            foreach ($spn in @($comp.ServicePrincipalName)) {
                if ([string]::IsNullOrWhiteSpace($spn)) { continue }

                $normalizedSpn = $spn.ToLower()
                $knownSpns[$normalizedSpn] = $true

                $spnParts = $normalizedSpn -split '/'
                if ($spnParts.Count -ge 2) {
                    $spnHost = ($spnParts[1] -split ':')[0]
                    if (-not [string]::IsNullOrWhiteSpace($spnHost)) {
                        $knownHosts[$spnHost] = $true

                        $shortSpnHost = ($spnHost -split '\.', 2)[0]
                        if (-not [string]::IsNullOrWhiteSpace($shortSpnHost)) {
                            $knownHosts[$shortSpnHost] = $true
                        }
                    }
                }
            }
        }

        foreach ($account in @($Data.KerberosConfig.SPNAccounts)) {
            foreach ($spn in @($account.ServicePrincipalName)) {
                if ([string]::IsNullOrWhiteSpace($spn)) { continue }

                $normalizedSpn = $spn.ToLower()
                $knownSpns[$normalizedSpn] = $true

                $spnParts = $normalizedSpn -split '/'
                if ($spnParts.Count -ge 2) {
                    $spnHost = ($spnParts[1] -split ':')[0]
                    if (-not [string]::IsNullOrWhiteSpace($spnHost)) {
                        $knownHosts[$spnHost] = $true

                        $shortSpnHost = ($spnHost -split '\.', 2)[0]
                        if (-not [string]::IsNullOrWhiteSpace($shortSpnHost)) {
                            $knownHosts[$shortSpnHost] = $true
                        }
                    }
                }
            }
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            foreach ($spn in $acct.AllowedToDelegateTo) {
                if ([string]::IsNullOrWhiteSpace($spn)) { continue }

                $normalizedTargetSpn = $spn.ToLower()
                if ($knownSpns.ContainsKey($normalizedTargetSpn)) { continue }

                $parts = $normalizedTargetSpn -split '/'
                if ($parts.Count -lt 2) { continue }
                $targetHost = ($parts[1] -split ':')[0]

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
