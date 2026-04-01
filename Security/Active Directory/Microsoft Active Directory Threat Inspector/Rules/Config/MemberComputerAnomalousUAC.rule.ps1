# Rules\Config\MemberComputerAnomalousUAC.rule.ps1
# Flags enabled non-DC computer accounts with anomalous account-type UAC flags.

@{
    Id          = 'MATI-CONFIG-033'
    Title       = 'Member computer with anomalous UserAccountControl'
    Severity    = 'High'
    Description = "An enabled non-domain-controller computer object has account-type UserAccountControl flags that do not match a normal member computer. This can indicate an incorrectly modified machine object, a malformed join state, or an object prepared for abuse."
    Remediation = "Review the affected computer object and restore the expected account type. Member computers should normally use WORKSTATION_TRUST_ACCOUNT and should not carry SERVER_TRUST_ACCOUNT, INTERDOMAIN_TRUST_ACCOUNT, or NORMAL_ACCOUNT flags."
    Collectors  = @('ComputerAccounts')
    References  = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $NORMAL_ACCOUNT = 0x0200
        $INTERDOMAIN_TRUST_ACCOUNT = 0x0800
        $WORKSTATION_TRUST_ACCOUNT = 0x1000
        $SERVER_TRUST_ACCOUNT = 0x2000

        foreach ($computer in $Data.ComputerAccounts) {
            if (-not $computer.Enabled) { continue }
            if ($computer.IsDomainController) { continue }

            $uac = $computer.UserAccountControl
            if ($null -eq $uac) { continue }

            $issues = @()
            if ($uac -band $SERVER_TRUST_ACCOUNT) {
                $issues += 'Has SERVER_TRUST_ACCOUNT (0x2000)'
            }
            if ($uac -band $INTERDOMAIN_TRUST_ACCOUNT) {
                $issues += 'Has INTERDOMAIN_TRUST_ACCOUNT (0x0800)'
            }
            if ($uac -band $NORMAL_ACCOUNT) {
                $issues += 'Has NORMAL_ACCOUNT (0x0200)'
            }
            if (-not ($uac -band $WORKSTATION_TRUST_ACCOUNT)) {
                $issues += 'Missing WORKSTATION_TRUST_ACCOUNT (0x1000)'
            }

            if ($issues.Count -eq 0) { continue }

            $findings += @{
                ObjectDN = $computer.DistinguishedName
                Domain   = $computer.Domain
                Details  = @{
                    ComputerName        = $computer.SamAccountName
                    DNSHostName         = $computer.DNSHostName
                    UserAccountControl  = "0x$($uac.ToString('X'))"
                    Issues              = ($issues -join '; ')
                }
            }
        }

        return $findings
    }
}