# Rules\Hardening\ReversibleEncryptionUser.rule.ps1
# Flags user accounts with reversible encryption flag (UAC 0x80). [PingCastle: S-Reversible]

@{
    Id          = 'MATI-HARD-040'
    Title       = 'User account with reversible encryption enabled'
    Severity    = 'High'
    Description = "One or more user accounts have the ENCRYPTED_TEXT_PASSWORD_ALLOWED flag (UAC bit 0x80) set. This stores passwords in a reversible format, allowing an attacker with database access to recover clear-text passwords."
    Remediation = "Clear the 'Store password using reversible encryption' option on affected accounts. Ensure no application requires this setting. Review GPO settings that may enforce this."
    Collectors  = @('UserAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($user in $Data.UserAccounts) {
            if (-not $user.Enabled) { continue }
            $uac = [int]$user.UserAccountControl
            if ($uac -band 0x80) {
                $findings += @{
                    ObjectDN = $user.DistinguishedName
                    Domain   = ($user.DistinguishedName -replace '^.*?,DC=','DC=' -replace ',DC=','.' -replace '^DC=','')
                    Details  = @{
                        AccountName = $user.SamAccountName
                        UAC         = "0x$($uac.ToString('X'))"
                        Flag        = 'ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x80)'
                    }
                }
            }
        }
        return $findings
    }
}
