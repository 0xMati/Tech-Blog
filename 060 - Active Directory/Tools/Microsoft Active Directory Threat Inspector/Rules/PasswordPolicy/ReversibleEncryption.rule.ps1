# Rules\PasswordPolicy\ReversibleEncryption.rule.ps1
# Flags password policies with reversible encryption enabled.

@{
    Id          = 'MATI-PWD-003'
    Title       = 'Reversible encryption enabled in password policy'
    Severity    = 'Critical'
    Description = "A password policy (default or Fine-Grained) has reversible encryption enabled. This stores passwords in a form that can be decrypted to plaintext, effectively negating the protection of password hashing."
    Remediation = "Disable reversible encryption in all password policies. If an application requires it, use a dedicated service account and apply the FGPP only to that account."
    Collectors  = @('PasswordPolicy')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Check default policies
        foreach ($policy in $Data.PasswordPolicy.DefaultPolicies) {
            if ($policy.ReversibleEncryption) {
                $findings += @{
                    ObjectDN = $policy.Domain
                    Domain   = $policy.Domain
                    Details  = @{
                        PolicyType           = 'Default Domain Policy'
                        ReversibleEncryption = 'Enabled'
                    }
                }
            }
        }

        # Check FGPPs
        foreach ($fgpp in $Data.PasswordPolicy.FineGrainedPolicies) {
            if ($fgpp.ReversibleEncryption) {
                $findings += @{
                    ObjectDN = $fgpp.DistinguishedName
                    Domain   = $fgpp.Domain
                    Details  = @{
                        PolicyType           = "FGPP: $($fgpp.Name)"
                        ReversibleEncryption = 'Enabled'
                        Precedence           = "$($fgpp.Precedence)"
                    }
                }
            }
        }
        return $findings
    }
}
