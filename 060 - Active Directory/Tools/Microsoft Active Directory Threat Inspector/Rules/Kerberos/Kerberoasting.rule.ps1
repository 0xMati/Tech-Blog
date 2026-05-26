# Rules\Kerberos\Kerberoasting.rule.ps1
# Flags service accounts with SPNs vulnerable to Kerberoasting.

@{
    Id          = 'MATI-KERB-003'
    Title       = 'Service account vulnerable to Kerberoasting'
    Severity    = 'Medium'
    Description = "A user account with a Service Principal Name (SPN) can be targeted by a Kerberoasting attack. An authenticated attacker can request a service ticket (TGS) and attempt to crack the password offline. The risk is elevated if the account is privileged (adminCount=1)."
    Remediation = "Use gMSA (Group Managed Service Accounts) instead of user accounts with SPNs. If not possible, ensure the password is highly complex (25+ characters) and configure AES-only encryption."
    Collectors  = @('KerberosConfig')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($account in $Data.KerberosConfig.SPNAccounts) {
            if ($account._ASREPRoastable) { continue }  # Handled by separate rule
            if (-not $account.Enabled) { continue }
            if ($account.ServicePrincipalName.Count -eq 0) { continue }

            $severity = if ($account.AdminCount -eq 1) { 'High' } else { 'Medium' }

            $findings += @{
                Severity = $severity
                ObjectDN = $account.DistinguishedName
                Domain   = $account.Domain
                Details  = @{
                    SamAccountName = $account.SamAccountName
                    SPNCount       = "$($account.ServicePrincipalName.Count)"
                    SPNs           = ($account.ServicePrincipalName | Select-Object -First 5) -join '; '
                    AdminCount     = "$($account.AdminCount)"
                    EncTypes       = "$($account.SupportedEncryptionTypes)"
                }
            }
        }
        return $findings
    }
}
