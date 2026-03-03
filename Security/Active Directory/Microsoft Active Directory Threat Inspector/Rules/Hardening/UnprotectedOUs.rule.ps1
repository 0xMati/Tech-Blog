# Rules\Hardening\UnprotectedOUs.rule.ps1
# Flags OUs not protected from accidental deletion.

@{
    Id          = 'MATI-HARD-010'
    Title       = 'Organizational Unit not protected from accidental deletion'
    Severity    = 'Low'
    Description = "One or more Organizational Units are not protected from accidental deletion. Accidental deletion of OUs can cause significant operational disruption, including loss of GPO links and object organization."
    Remediation = "Enable accidental deletion protection: Set-ADOrganizationalUnit -Identity '<OU_DN>' -ProtectedFromAccidentalDeletion `$true"
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: P-UnprotectedOU', 'ANSSI: vuln_unprotected_ou')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $ous = $Data.SecurityConfig.UnprotectedOUs
        if ($ous.Count -gt 0) {
            # Group by domain for cleaner reporting
            $byDomain = $ous | Group-Object -Property Domain
            foreach ($group in $byDomain) {
                $findings += @{
                    ObjectDN = $group.Name
                    Domain   = $group.Name
                    Details  = @{
                        UnprotectedOUCount = "$($group.Count)"
                        Examples           = ($group.Group | Select-Object -First 5 |
                            ForEach-Object { $_.Name }) -join ', '
                    }
                }
            }
        }
        return $findings
    }
}
