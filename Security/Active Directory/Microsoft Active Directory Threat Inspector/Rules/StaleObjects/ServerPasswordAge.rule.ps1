# Rules\StaleObjects\ServerPasswordAge.rule.ps1
# ORADAD: vuln_password_change_server_no_change_90
# Flags enabled non-DC server computer accounts with old passwords.

@{
    Id          = 'MATI-STALE-003'
    Title       = 'Server computer account password not rotated (>90 days)'
    Severity    = 'Medium'
    Description = "An enabled server computer account has not changed its machine password for more than 90 days. By default, Windows automatically rotates machine passwords every 30 days. An old password may indicate a broken secure channel, a powered-off or decommissioned server, or a rogue computer account."
    Remediation = "Investigate the affected servers. If the server is no longer in use, disable or delete the account. If active, check the Netlogon service and secure channel with 'nltest /sc_verify'. Consider running 'Reset-ComputerMachinePassword' on the affected machine."
    Collectors  = @('ComputerAccounts')
    References  = @(
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $now = Get-Date
        $domainBuckets = @{}

        foreach ($comp in $Data.ComputerAccounts) {
            if (-not $comp.Enabled) { continue }
            if ($comp.IsDomainController) { continue }  # DCs handled by CONFIG-017

            # Filter: only "Server" OS (not workstations)
            $os = $comp.OperatingSystem
            if (-not $os) { continue }
            $isServer = $os -match 'Server'
            if (-not $isServer) { continue }

            $pwdAge = if ($comp.PasswordLastSet) { ($now - $comp.PasswordLastSet).Days } else { 9999 }
            if ($pwdAge -le 90) { continue }

            $severity = if ($pwdAge -gt 365) { 'High' }
                        elseif ($pwdAge -gt 180) { 'Medium' }
                        else { 'Medium' }

            $key = "$($comp.Domain)|$severity"
            if (-not $domainBuckets.ContainsKey($key)) {
                $domainBuckets[$key] = @{
                    Domain   = $comp.Domain
                    Severity = $severity
                    Count    = 0
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }
            $domainBuckets[$key].Count++
            if ($domainBuckets[$key].Examples.Count -lt 5) {
                $domainBuckets[$key].Examples.Add("$($comp.SamAccountName) ($pwdAge days, $os)")
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $findings += @{
                Severity = $bucket.Severity
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    StaleServerCount = "$($bucket.Count)"
                    Severity         = $bucket.Severity
                    Examples         = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}
