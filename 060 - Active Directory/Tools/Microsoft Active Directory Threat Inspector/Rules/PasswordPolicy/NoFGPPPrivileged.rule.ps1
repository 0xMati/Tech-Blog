# Rules\PasswordPolicy\NoFGPPPrivileged.rule.ps1
# Flags domains without a Fine-Grained Password Policy for privileged accounts.

@{
    Id          = 'MATI-PWD-002'
    Title       = 'No Fine-Grained Password Policy for privileged accounts'
    Severity    = 'Medium'
    Description = "No Fine-Grained Password Policy (FGPP) is applied to privileged accounts or groups. Without a stricter FGPP, privileged accounts use the default domain password policy, which is typically insufficient for high-value targets."
    Remediation = "Apply a dedicated Fine-Grained Password Policy to privileged accounts or their security groups. Use a long password minimum and appropriate lockout controls. Verify each account's resultant policy, including nested group membership and PSO precedence."
    Collectors  = @('PasswordPolicy', 'PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#fine_grained_pswd_policy_mgmt')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($policy in $Data.PasswordPolicy.DefaultPolicies) {
            $uncovered = @($Data.PrivilegedAccounts.Accounts | Where-Object {
                $_.Domain -eq $policy.Domain -and $_.Enabled -and -not $_.ResultantPasswordPolicy
            })

            if ($uncovered.Count -gt 0) {
                $findings += @{
                    ObjectDN = $policy.Domain
                    Domain   = $policy.Domain
                    Details  = @{
                        UncoveredPrivilegedAccounts = "$($uncovered.Count)"
                        Examples = ($uncovered.SamAccountName | Select-Object -First 10) -join '; '
                        DefaultMinLength = "$($policy.MinPasswordLength)"
                        Recommendation = 'Create FGPP for privileged groups with MinLength >= 16'
                    }
                }
            }
        }
        return $findings
    }
}
