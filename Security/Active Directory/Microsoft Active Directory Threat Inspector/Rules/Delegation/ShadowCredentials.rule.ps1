# Rules\Delegation\ShadowCredentials.rule.ps1
# Detects objects with msDS-KeyCredentialLink populated.
# Shadow Credentials is an attack technique where an adversary writes
# a public key to this attribute, then requests a TGT using PKINIT,
# effectively taking over the account without knowing the password.

@{
    Id          = 'MATI-DELEG-006'
    Title       = 'Shadow Credentials (KeyCredentialLink) Detected'
    Severity    = 'High'
    Description = 'One or more AD objects have msDS-KeyCredentialLink populated. While this attribute is ' +
                  'legitimately used by Windows Hello for Business (WHfB) and Azure AD device registration, ' +
                  'unauthorized entries indicate the Shadow Credentials attack (CVE-2021-42278/42287 chain). ' +
                  'Every entry should be validated against known WHfB enrollment.'
    Remediation = 'Audit each KeyCredentialLink entry. For non-WHfB entries, clear the attribute: ' +
                  'Set-ADUser/Computer <target> -Clear msDS-KeyCredentialLink. ' +
                  'Restrict write access to this attribute to authorized principals only.'
    Collectors  = @('ComputerAccounts', 'UserAccounts')
    References  = @(
        'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'
        'https://attack.mitre.org/techniques/T1556/006/'
    )

    Condition = {
        param($Data, $Config)
        $findings = [System.Collections.Generic.List[hashtable]]::new()

        # Check computers
        foreach ($comp in @($Data['ComputerAccounts'])) {
            if (-not $comp.KeyCredentialLink -or @($comp.KeyCredentialLink).Count -eq 0) { continue }
            # Skip DCs (they may have legitimate PKINIT entries)
            if ($comp.IsDomainController) { continue }

            $findings.Add(@{
                Severity    = 'High'
                Description = "Computer '$($comp.SamAccountName)' has $(@($comp.KeyCredentialLink).Count) " +
                              "KeyCredentialLink entry(ies). Verify this is from legitimate WHfB/device enrollment."
                ObjectDN    = $comp.DistinguishedName
                Domain      = $comp.Domain
                Details     = @{
                    Object      = $comp.SamAccountName
                    ObjectClass = 'computer'
                    Entries     = @($comp.KeyCredentialLink).Count
                }
            })
        }

        # Check users
        foreach ($user in @($Data['UserAccounts'])) {
            if (-not $user.KeyCredentialLink -or @($user.KeyCredentialLink).Count -eq 0) { continue }

            $findings.Add(@{
                Severity    = 'High'
                Description = "User '$($user.SamAccountName)' has $(@($user.KeyCredentialLink).Count) " +
                              "KeyCredentialLink entry(ies). Verify this is from legitimate WHfB enrollment."
                ObjectDN    = $user.DistinguishedName
                Domain      = $user.Domain
                Details     = @{
                    Object      = $user.SamAccountName
                    ObjectClass = 'user'
                    Entries     = @($user.KeyCredentialLink).Count
                }
            })
        }

        if ($findings.Count -gt 0) { return $findings }
        return $null
    }
}
