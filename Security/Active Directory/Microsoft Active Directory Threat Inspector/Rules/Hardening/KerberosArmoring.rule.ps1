# Rules\Hardening\KerberosArmoring.rule.ps1
# Flags domains where Kerberos armoring (FAST) is not enforced.

@{
    Id          = 'MATI-HARD-015'
    Title       = 'Kerberos armoring (FAST) not configured'
    Severity    = 'Medium'
    Description = "Kerberos Flexible Authentication Secure Tunneling (FAST/Armoring) is not configured. Kerberos armoring protects AS-REQ exchanges, preventing offline password attacks and pre-authentication downgrade attacks. Requires domain functional level 2012 or higher."
    Remediation = "Configure Kerberos armoring via GPO: Computer Configuration > Policies > Administrative Templates > System > KDC > KDC support for claims, compound authentication and Kerberos armoring. Set to 'Supported' or 'Always provide claims'."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($item in $Data.SecurityConfig.KerberosArmoring) {
            if ($item.ArmoringPossible -and -not $item.ArmoringEnforced) {
                $findings += @{
                    ObjectDN = $item.Domain
                    Domain   = $item.Domain
                    Details  = @{
                        DomainFunctionalLevel = "$($item.DomainFunctionalLevel)"
                        ArmoringPossible      = "$($item.ArmoringPossible)"
                        Recommendation        = 'Enable Kerberos armoring via GPO'
                    }
                }
            }
        }
        return $findings
    }
}
