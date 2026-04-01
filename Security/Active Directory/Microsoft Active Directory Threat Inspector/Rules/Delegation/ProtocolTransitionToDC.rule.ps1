# Rules\Delegation\ProtocolTransitionToDC.rule.ps1
# Flags accounts with protocol transition delegation (T2A4D) to DC services.

@{
    Id          = 'MATI-DELEG-002'
    Title       = 'Protocol transition delegation targeting a Domain Controller'
    Severity    = 'Critical'
    Description = "An account has both protocol transition (TrustedToAuthForDelegation) and constrained delegation to a Domain Controller service. This is the more dangerous delegation variant because the account can request service tickets on behalf of users to a Tier 0 target without first receiving the user's Kerberos TGT."
    Remediation = "Remove the TrustedToAuthForDelegation flag from the account or remove the Domain Controller service from the AllowedToDelegateTo list. Prefer designs that avoid delegation into Tier 0, and use RBCD with strict scoping where delegation is unavoidable."
    Collectors  = @('KerberosConfig', 'DCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $dcHostMap = @{}
        $seenMatches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($dc in $Data.DCInfo) {
            $dcNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            if ($dc.HostName) {
                $null = $dcNames.Add("$($dc.HostName)")
                $shortHost = ($dc.HostName -split '\.')[0]
                if ($shortHost) { $null = $dcNames.Add($shortHost) }
            }
            if ($dc.Name) {
                $null = $dcNames.Add("$($dc.Name)")
                $shortName = ($dc.Name -split '\.')[0]
                if ($shortName) { $null = $dcNames.Add($shortName) }
            }

            foreach ($name in $dcNames) {
                $dcHostMap[$name] = $dc
            }
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            if (-not $acct.TrustedToAuthForDelegation) { continue }
            if ($acct.AllowedToDelegateTo.Count -eq 0) { continue }

            foreach ($spn in $acct.AllowedToDelegateTo) {
                if (-not $spn) { continue }
                $parts = $spn -split '/'
                if ($parts.Count -lt 2) { continue }
                $targetHost = ($parts[1] -split ':')[0]
                if (-not $targetHost) { continue }

                $targetDc = $dcHostMap[$targetHost]
                if (-not $targetDc) {
                    $targetShortHost = ($targetHost -split '\.')[0]
                    if ($targetShortHost) { $targetDc = $dcHostMap[$targetShortHost] }
                }

                if ($targetDc) {
                    $matchKey = "$($acct.DistinguishedName)|$spn"
                    if (-not $seenMatches.Add($matchKey)) { continue }

                    $findings += @{
                        ObjectDN = $acct.DistinguishedName
                        Domain   = $acct.Domain
                        Details  = @{
                            AccountName        = $acct.SamAccountName
                            AccountType        = $acct.ObjectClass
                            DelegationTarget   = $spn
                            TargetDC           = $targetDc.Name
                            TargetDCHostName   = $targetDc.HostName
                            ProtocolTransition = 'True'
                            RiskContext        = 'Protocol transition enables more direct impersonation into Tier 0'
                        }
                    }
                }
            }
        }
        return $findings
    }
}
