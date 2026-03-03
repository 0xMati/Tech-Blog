# Rules\PasswordPolicy\WeakDefaultPolicy.rule.ps1
# Flags default domain password policies that are too weak.

@{
    Id          = 'MATI-PWD-001'
    Title       = 'Weak default domain password policy'
    Severity    = 'High'
    Description = "The default domain password policy does not meet recommended security standards. A minimum password length of 12 characters (or more) is recommended. Complexity should be enabled and the password history should contain at least 24 entries."
    Remediation = "Increase the minimum password length to at least 12 characters. Enable password complexity and set the history count to 24 or more via the Default Domain Policy GPO."
    Collectors  = @('PasswordPolicy')
    References  = @('PingCastle: A-MinPwdLen', 'ANSSI: vuln_password_policy')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $minLen = $Config.Thresholds.MinPasswordLength
        if (-not $minLen) { $minLen = 12 }

        foreach ($policy in $Data.PasswordPolicy.DefaultPolicies) {
            $issues = @()
            if ($policy.MinPasswordLength -lt $minLen) {
                $issues += "MinLength=$($policy.MinPasswordLength) (expected >=$minLen)"
            }
            if (-not $policy.ComplexityEnabled) {
                $issues += "Complexity=Disabled"
            }
            if ($policy.PasswordHistoryCount -lt 24) {
                $issues += "History=$($policy.PasswordHistoryCount) (expected >=24)"
            }
            if ($policy.ReversibleEncryption) {
                $issues += "ReversibleEncryption=Enabled"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $policy.Domain
                    Domain   = $policy.Domain
                    Details  = @{
                        MinPasswordLength   = "$($policy.MinPasswordLength)"
                        ComplexityEnabled   = "$($policy.ComplexityEnabled)"
                        PasswordHistory     = "$($policy.PasswordHistoryCount)"
                        ReversibleEncryption = "$($policy.ReversibleEncryption)"
                        Issues              = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}
