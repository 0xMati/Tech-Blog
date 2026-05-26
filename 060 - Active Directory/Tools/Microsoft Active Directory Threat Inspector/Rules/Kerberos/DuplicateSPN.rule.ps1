# Rules\Kerberos\DuplicateSPN.rule.ps1
# Flags duplicate Service Principal Names that break Kerberos authentication.

@{
    Id          = 'MATI-KERB-007'
    Title       = 'Duplicate Service Principal Name (SPN) detected'
    Severity    = 'High'
    Description = "The same SPN is registered on multiple accounts. Duplicate SPNs cause Kerberos authentication failures because the KDC cannot determine which account's key to use for ticket encryption."
    Remediation = "Identify the correct owner for each duplicate SPN using 'setspn -X' and remove the incorrect registrations with 'setspn -D'."
    Collectors  = @('KerberosConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/spn-and-upn-uniqueness')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dup in $Data.KerberosConfig.DuplicateSPNs) {
            $accountNames = ($dup.Accounts | ForEach-Object { $_.SamAccountName }) -join ', '
            $findings += @{
                ObjectDN = $dup.SPN
                Domain   = $dup.Accounts[0].Domain
                Details  = @{
                    SPN           = $dup.SPN
                    Count         = $dup.Count
                    RegisteredOn  = $accountNames
                }
            }
        }
        return $findings
    }
}
