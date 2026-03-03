# Rules\Hardening\AuditPolicyInsufficient.rule.ps1
# Flags DCs where critical audit subcategories are not configured.

@{
    Id          = 'MATI-HARD-023'
    Title       = 'Insufficient audit policy on Domain Controller'
    Severity    = 'Medium'
    Description = "Critical audit subcategories are not configured for success and/or failure auditing on one or more Domain Controllers. Without proper auditing, security incidents cannot be detected or investigated."
    Remediation = "Configure Advanced Audit Policy via GPO to audit at minimum: Logon/Logoff (Success+Failure), Account Logon (Success+Failure), Account Management (Success+Failure), Directory Service Access (Success+Failure), Policy Change (Success), Privilege Use (Failure), System (Success+Failure)."
    Collectors  = @('ProtocolConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Critical subcategories that should have at least Success auditing
        $requiredSubcategories = @(
            'Credential Validation',
            'Logon',
            'Logoff',
            'Special Logon',
            'User Account Management',
            'Computer Account Management',
            'Security Group Management',
            'Directory Service Changes',
            'Audit Policy Change',
            'Authentication Policy Change'
        )

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if (-not $dc.AuditPolicySub -or $dc.AuditPolicySub.Count -eq 0) { continue }

            $missingAudits = @()
            foreach ($subcat in $requiredSubcategories) {
                $setting = $dc.AuditPolicySub[$subcat]
                if (-not $setting -or $setting -eq 'No Auditing') {
                    $missingAudits += $subcat
                }
            }

            if ($missingAudits.Count -gt 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.DCName
                        MissingAudits   = ($missingAudits -join ', ')
                        MissingCount    = $missingAudits.Count
                    }
                }
            }
        }
        return $findings
    }
}
