# Rules\PrivilegedAccounts\ServiceInDA.rule.ps1
# Flags service accounts (SPN set) that are members of privileged groups.

@{
    Id          = 'MATI-ADMIN-012'
    Title       = 'Service account in privileged group'
    Severity    = 'High'
    Description = "A user account with a Service Principal Name (SPN) is a direct or indirect member of a privileged group (Domain Admins, Enterprise Admins, etc.). Service accounts with SPNs are vulnerable to Kerberoasting, and if they are also domain admins, a successful Kerberoast attack directly yields domain admin credentials."
    Remediation = "Remove the service account from privileged groups. Use a dedicated admin account (without SPN) for administration. Migrate to Group Managed Service Accounts (gMSA) where possible."
    Collectors  = @('KerberosConfig', 'PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Build set of privileged account DNs
        $privDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($acct in $Data.PrivilegedAccounts.Accounts) {
            $null = $privDNs.Add($acct.DistinguishedName)
        }

        # Check SPN accounts against privileged set
        foreach ($spnAcct in $Data.KerberosConfig.SPNAccounts) {
            if (-not $spnAcct.Enabled) { continue }
            if ($spnAcct.SamAccountName -eq 'krbtgt') { continue }
            if (-not $privDNs.Contains($spnAcct.DistinguishedName)) { continue }

            $findings += @{
                ObjectDN = $spnAcct.DistinguishedName
                Domain   = $spnAcct.Domain
                Details  = @{
                    AccountName = $spnAcct.SamAccountName
                    SPN         = ($spnAcct.ServicePrincipalName | Select-Object -First 3) -join '; '
                    AdminCount  = $spnAcct.AdminCount
                    Description = "$($spnAcct.Description)"
                }
            }
        }
        return $findings
    }
}
