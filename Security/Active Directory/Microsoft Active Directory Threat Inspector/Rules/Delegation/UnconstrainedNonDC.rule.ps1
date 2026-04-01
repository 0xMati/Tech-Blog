# Rules\Delegation\UnconstrainedNonDC.rule.ps1
# Flags non-DC accounts with unconstrained delegation (extends existing KERB-005).

@{
    Id          = 'MATI-DELEG-003'
    Title       = 'Unconstrained delegation on non-DC computer account'
    Severity    = 'Critical'
    Description = "A computer account that is not a Domain Controller has unconstrained delegation enabled. Any user that authenticates to this server will have their TGT cached on the machine, enabling an attacker to steal Kerberos tickets and impersonate any user including Domain Admins."
    Remediation = "Remove the TrustedForDelegation flag from the computer account. Migrate to constrained delegation or RBCD. Domain Controllers are excluded because they inherently require unconstrained delegation."
    Collectors  = @('KerberosConfig', 'DCInfo')
    References  = @('https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-kerberos-delegation')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Build DC DN set
        $dcDNs = @{}
        foreach ($dc in $Data.DCInfo) {
            $dcDNs[$dc.DistinguishedName] = $true
        }

        foreach ($acct in $Data.KerberosConfig.DelegationAccounts) {
            if (-not $acct.TrustedForDelegation) { continue }
            if (-not $acct.Enabled) { continue }
            if ($acct.ObjectClass -ne 'computer') { continue }
            # Exclude DCs
            if ($dcDNs.ContainsKey($acct.DistinguishedName)) { continue }

            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    AccountName          = $acct.SamAccountName
                    OperatingSystem      = "$($acct.OperatingSystem)"
                    TrustedForDelegation = 'True'
                }
            }
        }
        return $findings
    }
}
