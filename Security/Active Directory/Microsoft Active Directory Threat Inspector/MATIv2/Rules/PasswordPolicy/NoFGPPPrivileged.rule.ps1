# Rules\PasswordPolicy\NoFGPPPrivileged.rule.ps1
# Flags domains without a Fine-Grained Password Policy for privileged accounts.

@{
    Id          = 'MATI-PWD-002'
    Title       = 'No Fine-Grained Password Policy for privileged accounts'
    Severity    = 'Medium'
    Description = "No Fine-Grained Password Policy (FGPP) is applied to privileged accounts or groups. Without a stricter FGPP, privileged accounts use the default domain password policy, which is typically insufficient for high-value targets."
    Remediation = "Create a Fine-Grained Password Policy with stricter settings (minimum 16 characters, 1-day max age, lockout protection) and apply it to Domain Admins and Enterprise Admins groups."
    Collectors  = @('PasswordPolicy')
    References  = @('PingCastle: A-NoFGPP', 'ANSSI: vuln_privileged_members_password')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($policy in $Data.PasswordPolicy.DefaultPolicies) {
            $domainFGPPs = @($Data.PasswordPolicy.FineGrainedPolicies |
                Where-Object { $_.Domain -eq $policy.Domain })

            if ($domainFGPPs.Count -eq 0) {
                $findings += @{
                    ObjectDN = $policy.Domain
                    Domain   = $policy.Domain
                    Details  = @{
                        FGPPCount = '0'
                        DefaultMinLength = "$($policy.MinPasswordLength)"
                        Recommendation = 'Create FGPP for privileged groups with MinLength >= 16'
                    }
                }
            }
        }
        return $findings
    }
}
