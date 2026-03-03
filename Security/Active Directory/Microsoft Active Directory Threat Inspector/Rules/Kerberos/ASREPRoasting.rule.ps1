# Rules\Kerberos\ASREPRoasting.rule.ps1
# Flags accounts with Kerberos pre-authentication disabled (AS-REP Roasting).

@{
    Id          = 'MATI-KERB-005'
    Title       = 'Account vulnerable to AS-REP Roasting'
    Severity    = 'High'
    Description = "An account has the 'Do not require Kerberos preauthentication' (DONT_REQUIRE_PREAUTH) flag enabled. An attacker can request an AS-REP for this account without authenticating and attempt to crack the password offline. This is more dangerous than Kerberoasting because no prior authentication is required."
    Remediation = "Disable the 'Do not require Kerberos preauthentication' option on the account via: Set-ADAccountControl -Identity <user> -DoesNotRequirePreAuth `$false"
    Collectors  = @('KerberosConfig')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($account in $Data.KerberosConfig.SPNAccounts) {
            if (-not $account._ASREPRoastable) { continue }
            if (-not $account.Enabled) { continue }

            $severity = if ($account.AdminCount -eq 1) { 'Critical' } else { 'High' }

            $findings += @{
                Severity = $severity
                ObjectDN = $account.DistinguishedName
                Domain   = $account.Domain
                Details  = @{
                    SamAccountName        = $account.SamAccountName
                    DoesNotRequirePreAuth = 'True'
                    AdminCount            = "$($account.AdminCount)"
                }
            }
        }
        return $findings
    }
}
