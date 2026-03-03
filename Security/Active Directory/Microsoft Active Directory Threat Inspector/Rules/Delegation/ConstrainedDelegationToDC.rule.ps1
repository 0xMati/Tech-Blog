# Rules\Delegation\ConstrainedDelegationToDC.rule.ps1
# Flags accounts with constrained delegation targeting a DC service.

@{
    Id          = 'MATI-DELEG-001'
    Title       = 'Constrained delegation targeting a Domain Controller'
    Severity    = 'Critical'
    Description = "An account has constrained delegation (msDS-AllowedToDelegateTo) configured to a service running on a Domain Controller. Compromising this account allows impersonation of any user to the targeted DC service, potentially leading to full domain compromise."
    Remediation = "Remove the constrained delegation to the DC service. If delegation is required, use Resource-Based Constrained Delegation (RBCD) with strict controls instead."
    Collectors  = @('KerberosConfig', 'DCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Build a set of DC hostnames and SPNs
        $dcHostNames = @{}
        foreach ($dc in $Data.DCInfo) {
            $dcHostNames[$dc.HostName.ToLower()] = $true
            $dcHostNames[$dc.Name.ToLower()]     = $true
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            if ($acct.AllowedToDelegateTo.Count -eq 0) { continue }
            foreach ($spn in $acct.AllowedToDelegateTo) {
                # Extract host from SPN (service/host or service/host:port)
                $parts = $spn -split '/'
                if ($parts.Count -lt 2) { continue }
                $targetHost = ($parts[1] -split ':')[0].ToLower()

                if ($dcHostNames.ContainsKey($targetHost)) {
                    $findings += @{
                        ObjectDN = $acct.DistinguishedName
                        Domain   = $acct.Domain
                        Details  = @{
                            AccountName         = $acct.SamAccountName
                            DelegationTarget    = $spn
                            TargetDC            = $targetHost
                            ProtocolTransition  = "$($acct.TrustedToAuthForDelegation)"
                        }
                    }
                }
            }
        }
        return $findings
    }
}
