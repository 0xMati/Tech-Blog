# Rules\Config\TrustAccountPasswordAge.rule.ps1
# ORADAD: vuln_trusts_accounts
# Flags trust accounts whose passwords have not been rotated.

@{
    Id          = 'MATI-CONFIG-024'
    Title       = 'Trust account password too old'
    Severity    = 'High'
    Description = "A trust account (INTERDOMAIN_TRUST_ACCOUNT) has a password that has not been rotated for an extended period. Trust account passwords should be automatically renewed by the system. An old trust password may indicate a broken trust relationship or an orphan trust account that should be removed."
    Remediation = "Verify the trust relationship is still functional. If the trust is no longer needed, remove it along with the trust account. If the trust is active, reset the trust password from both sides using 'netdom trust /reset' or re-create the trust. Investigate why automatic rotation stopped."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/entra/identity/domain-services/check-health'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($trust in $Data.SecurityConfig.TrustAccounts) {
            if ($trust.PasswordAgeDays -le 180) { continue }

            $sev = if ($trust.PasswordAgeDays -gt 365) { 'Critical' }
                   elseif ($trust.PasswordAgeDays -gt 180) { 'High' }
                   else { 'Medium' }

            $findings += @{
                ObjectDN = $trust.DistinguishedName
                Domain   = $trust.Domain
                Severity = $sev
                Details  = @{
                    SamAccountName  = $trust.SamAccountName
                    PasswordLastSet = "$($trust.PasswordLastSet)"
                    PasswordAgeDays = "$($trust.PasswordAgeDays)"
                }
            }
        }
        return $findings
    }
}
