# Rules\StaleObjects\MSAPasswordAge.rule.ps1
# ORADAD: vuln_password_change_msa_no_change_90
# Flags standalone Managed Service Accounts (sMSA) with old passwords.

@{
    Id          = 'MATI-STALE-005'
    Title       = 'Managed Service Account password not rotated (>90 days)'
    Severity    = 'Medium'
    Description = "A standalone Managed Service Account (sMSA) has a password older than 90 days. Unlike Group Managed Service Accounts (gMSA) which rotate passwords automatically based on their interval, standalone MSAs may fail to rotate if the host machine is offline or has issues. An MSA with an old password may indicate a broken automatic rotation or an orphaned account."
    Remediation = "Check if the MSA is still in use. If the host is offline, the password will rotate when the host comes back online. If the MSA is orphaned, remove it. For active MSAs, reset the password with 'Reset-ADServiceAccountPassword'. Consider migrating standalone MSAs to gMSAs for more reliable password management."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($msa in $Data.SecurityConfig.MSAAccounts) {
            if ($msa.PasswordAgeDays -le 90) { continue }

            $sev = if ($msa.PasswordAgeDays -gt 365) { 'High' }
                   elseif ($msa.PasswordAgeDays -gt 180) { 'Medium' }
                   else { 'Low' }

            $findings += @{
                ObjectDN = $msa.DistinguishedName
                Domain   = $msa.Domain
                Severity = $sev
                Details  = @{
                    SamAccountName  = $msa.SamAccountName
                    PasswordLastSet = "$($msa.PasswordLastSet)"
                    PasswordAgeDays = "$($msa.PasswordAgeDays)"
                    Description     = "$($msa.Description)"
                }
            }
        }
        return $findings
    }
}
