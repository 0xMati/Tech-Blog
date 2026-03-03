# Rules\Hardening\PwdNeverExpiresAll.rule.ps1
# Flags high count of non-privileged accounts with PasswordNeverExpires.

@{
    Id          = 'MATI-HARD-025'
    Title       = 'Excessive accounts with non-expiring passwords'
    Severity    = 'Medium'
    Description = "A significant number of enabled user accounts have the PasswordNeverExpires flag set. Passwords that never expire increase the window for credential compromise through brute-force, password spraying, or credential stuffing."
    Remediation = "Review all accounts with PasswordNeverExpires and remove the flag where possible. For service accounts, migrate to Group Managed Service Accounts (gMSA) which rotate passwords automatically."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: S-PwdNeverExpires', 'ANSSI: vuln_password_never_expires')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Group by domain and report count
        $byDomain = $Data.SecurityConfig.PwdNeverExpiresAll | Group-Object Domain
        foreach ($group in $byDomain) {
            $nonPriv = @($group.Group | Where-Object { $_.AdminCount -ne 1 })
            if ($nonPriv.Count -gt 10) {
                $sev = if ($nonPriv.Count -gt 50) { 'High' } elseif ($nonPriv.Count -gt 25) { 'Medium' } else { 'Low' }
                $findings += @{
                    ObjectDN = $group.Name
                    Domain   = $group.Name
                    Severity = $sev
                    Details  = @{
                        TotalPwdNeverExpires = $nonPriv.Count
                        SampleAccounts       = ($nonPriv | Select-Object -First 10 -ExpandProperty SamAccountName) -join ', '
                    }
                }
            }
        }
        return $findings
    }
}
