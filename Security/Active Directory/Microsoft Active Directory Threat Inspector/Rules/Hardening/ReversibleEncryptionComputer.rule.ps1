# Rules\Hardening\ReversibleEncryptionComputer.rule.ps1
# Flags computer accounts with reversible encryption. [PingCastle: S-C-Reversible]

@{
    Id          = 'MATI-HARD-041'
    Title       = 'Computer account with reversible encryption enabled'
    Severity    = 'High'
    Description = "One or more computer accounts have the ENCRYPTED_TEXT_PASSWORD_ALLOWED flag (UAC bit 0x80) set. This is extremely unusual for computers and indicates potential misconfiguration or tampering."
    Remediation = "Clear the reversible encryption flag on the computer accounts. Investigate why this was set."
    Collectors  = @('ComputerAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($comp in $Data.ComputerAccounts) {
            if (-not $comp.Enabled) { continue }
            $uac = [int]$comp.UserAccountControl
            if ($uac -band 0x80) {
                $findings += @{
                    ObjectDN = $comp.DistinguishedName
                    Domain   = ($comp.DistinguishedName -replace '^.*?,DC=','DC=' -replace ',DC=','.' -replace '^DC=','')
                    Details  = @{
                        AccountName = $comp.SamAccountName
                        UAC         = "0x$($uac.ToString('X'))"
                        Flag        = 'ENCRYPTED_TEXT_PASSWORD_ALLOWED (0x80)'
                    }
                }
            }
        }
        return $findings
    }
}
