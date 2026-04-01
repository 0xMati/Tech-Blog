# Rules\Delegation\ConstrainedDelegationToDC.rule.ps1
# Flags accounts with constrained delegation targeting a DC service.

@{
    Id          = 'MATI-DELEG-001'
    Title       = 'Constrained delegation targeting a Domain Controller'
    Severity    = 'High'
    Description = "An account has constrained delegation (msDS-AllowedToDelegateTo) configured to a service hosted on a Domain Controller. This creates a direct delegation path into Tier 0. The abuse path is typically less immediate than protocol transition, but compromise of the delegated account can still allow impersonation to sensitive DC services."
    Remediation = "Remove the constrained delegation target pointing to the Domain Controller service. If delegation is required, redesign it away from Tier 0 targets and prefer Resource-Based Constrained Delegation (RBCD) with strict scoping."
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
                            ProtocolTransition = "$($acct.TrustedToAuthForDelegation)"
                            RiskContext        = 'Delegation path to Tier 0 service on a Domain Controller'
                        }
                    }
                }
            }
        }
        return $findings
    }
}
