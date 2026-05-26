# Rules\Delegation\RBCDBackdoor.rule.ps1
# Resource-Based Constrained Delegation (RBCD) configured on computer objects.
# RBCD allows a principal to impersonate any user to the target service.
# Attackers who gain write access to msDS-AllowedToActOnBehalfOfOtherIdentity
# can silently add their own machine account and achieve S4U2Proxy abuse.

@{
    Id          = 'MATI-DELEG-005'
    Title       = 'Resource-Based Constrained Delegation (RBCD) Configured'
    Severity    = 'High'
    Description = 'One or more computer objects have msDS-AllowedToActOnBehalfOfOtherIdentity populated, ' +
                  'enabling Resource-Based Constrained Delegation. This is a powerful delegation and a common ' +
                  'attack vector (RBCD abuse / S4U2Proxy). Verify every entry is intentional.'
    Remediation = 'Review each RBCD configuration. Remove unauthorized entries with: ' +
                  'Set-ADComputer <target> -PrincipalsAllowedToDelegateToAccount $null. ' +
                  'Limit who can write to this attribute via ACL hardening.'
    Collectors  = @('ComputerAccounts', 'DCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')

    Condition = {
        param($Data, $Config)
        $computers = $Data['ComputerAccounts']
        if (-not $computers) { return $null }
        $dcDNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($dc in @($Data.DCInfo)) {
            if ($dc.DistinguishedName) {
                $null = $dcDNs.Add($dc.DistinguishedName)
            }
        }

        $findings = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($comp in $computers) {
            if (-not $comp.AllowedToActOnBehalf) { continue }

            # Decode the security descriptor to find who is allowed
            $sd = $comp.AllowedToActOnBehalf
            $allowedNames = @()
            if ($sd -is [System.DirectoryServices.ActiveDirectorySecurity]) {
                $allowedNames = @($sd.Access | ForEach-Object { $_.IdentityReference.ToString() })
            } elseif ($sd) {
                $allowedNames = @("(populated - binary SD)")
            }

            $isDomainController = $dcDNs.Contains($comp.DistinguishedName)

            $findings.Add(@{
                Severity    = if ($isDomainController) { 'Critical' } else { 'High' }
                Description = "Computer '$($comp.SamAccountName)' has RBCD configured. " +
                              "Allowed principals: $($allowedNames -join ', ')"
                ObjectDN    = $comp.DistinguishedName
                Domain      = $comp.Domain
                Details     = @{
                    Computer          = $comp.SamAccountName
                    IsDC              = "$isDomainController"
                    AllowedPrincipals = ($allowedNames -join '; ')
                }
            })
        }

        if ($findings.Count -gt 0) { return $findings }
        return $null
    }
}
