# Rules\Kerberos\KrbtgtPasswordAge.rule.ps1
# Flags KRBTGT accounts with old passwords.

@{
    Id          = 'MATI-KERB-001'
    Title       = 'KRBTGT password too old'
    Severity    = 'High'
    Description = "The KRBTGT account password has not been changed for more than 180 days. The KRBTGT account is used to sign all Kerberos tickets (TGT). An old password increases the exploitation window of a Golden Ticket if the hash is compromised."
    Remediation = "Perform a KRBTGT password rotation (twice with at least a 10-12 hour interval between rotations to allow replication). Use the Microsoft script Reset-KrbtgtKeyInteractive.ps1."
    Collectors  = @('KerberosConfig')
    Condition   = {
        param($Data, $Config)
        $maxAge = $Config.Thresholds.KrbtgtPasswordMaxAge
        $findings = @()

        foreach ($krbtgt in $Data.KerberosConfig.KrbtgtAccounts) {
            if ($krbtgt.PasswordAgeDays -gt $maxAge) {
                $findings += @{
                    ObjectDN = $krbtgt.DistinguishedName
                    Domain   = $krbtgt.Domain
                    Details  = @{
                        PasswordAgeDays = "$($krbtgt.PasswordAgeDays)"
                        PasswordLastSet = "$($krbtgt.PasswordLastSet)"
                        MaxAge          = "$maxAge days"
                    }
                }
            }
        }
        return $findings
    }
}
