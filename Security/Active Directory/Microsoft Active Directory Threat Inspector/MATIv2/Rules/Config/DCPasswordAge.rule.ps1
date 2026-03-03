# Rules\Config\DCPasswordAge.rule.ps1
# Flags DCs with computer account passwords that haven't been renewed.

@{
    Id          = 'MATI-CONFIG-017'
    Title       = 'Domain Controller computer password too old'
    Severity    = 'High'
    Description = "A Domain Controller's computer account password has not been rotated for an extended period. DC computer passwords should rotate automatically every 30 days. An old password may indicate a broken secure channel or a DC that has been offline."
    Remediation = "Investigate why the DC machine password has not rotated. Check the Netlogon secure channel, verify the DC can reach AD. Consider resetting the computer password with 'Reset-ComputerMachinePassword' or 'netdom resetpwd'."
    Collectors  = @('DCInfo')
    References  = @('PingCastle: S-PwdLastSet-DC', 'ANSSI: vuln_dc_password_age')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $maxDays = 60  # DC machine passwords should rotate every 30 days

        foreach ($dc in $Data.DCInfo) {
            if ($dc.PasswordAgeDays -gt $maxDays) {
                $sev = if ($dc.PasswordAgeDays -gt 180) { 'Critical' }
                       elseif ($dc.PasswordAgeDays -gt 90) { 'High' }
                       else { 'Medium' }
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Severity = $sev
                    Details  = @{
                        DCName          = $dc.Name
                        PasswordLastSet = "$($dc.PasswordLastSet)"
                        PasswordAgeDays = $dc.PasswordAgeDays
                    }
                }
            }
        }
        return $findings
    }
}
