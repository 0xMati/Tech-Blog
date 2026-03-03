# Rules\Delegation\ProtocolTransitionToDC.rule.ps1
# Flags accounts with protocol transition delegation (T2A4D) to DC services.

@{
    Id          = 'MATI-DELEG-002'
    Title       = 'Protocol transition delegation targeting a Domain Controller'
    Severity    = 'Critical'
    Description = "An account has both protocol transition (TrustedToAuthForDelegation) and constrained delegation to a Domain Controller service. This allows the account to obtain a TGS for any user (including Domain Admins) to the targeted DC service, without requiring the user's password or TGT."
    Remediation = "Remove the TrustedToAuthForDelegation flag from the account or remove the DC service from the AllowedToDelegateTo list. Consider using RBCD instead."
    Collectors  = @('KerberosConfig', 'DCInfo')
    References  = @('ANSSI: vuln_delegation_t2a4d', 'PingCastle: P-DelegationT2A4D')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $dcHostNames = @{}
        foreach ($dc in $Data.DCInfo) {
            $dcHostNames[$dc.HostName.ToLower()] = $true
            $dcHostNames[$dc.Name.ToLower()]     = $true
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            if (-not $acct.TrustedToAuthForDelegation) { continue }
            if ($acct.AllowedToDelegateTo.Count -eq 0) { continue }

            foreach ($spn in $acct.AllowedToDelegateTo) {
                $parts = $spn -split '/'
                if ($parts.Count -lt 2) { continue }
                $targetHost = ($parts[1] -split ':')[0].ToLower()

                if ($dcHostNames.ContainsKey($targetHost)) {
                    $findings += @{
                        ObjectDN = $acct.DistinguishedName
                        Domain   = $acct.Domain
                        Details  = @{
                            AccountName        = $acct.SamAccountName
                            DelegationTarget   = $spn
                            TargetDC           = $targetHost
                            ProtocolTransition = 'True'
                        }
                    }
                }
            }
        }
        return $findings
    }
}
