# Rules\GPO\AuditPolicyNotConfigured.rule.ps1
# Flags domains where no audit policy is configured via GPO for Domain Controllers.

@{
    Id          = 'MATI-GPO-001'
    Title       = 'Audit policy not configured on Domain Controllers'
    Severity    = 'High'
    Description = "No audit policy is configured via GPO for Domain Controllers. Without audit policies, security events such as logon failures, privilege use, and object access are not recorded, making incident detection and forensics impossible."
    Remediation = "Configure Advanced Audit Policy via GPO linked to the Domain Controllers OU. Enable at minimum: Account Logon, Account Management, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege Use, System events."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $auditPolicy = $domainData.AuditPolicy

            if (-not $auditPolicy -or $auditPolicy.Count -eq 0) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue = "No audit policy configured via GPO for Domain Controllers"
                    }
                }
            }
        }
        return $findings
    }
}
