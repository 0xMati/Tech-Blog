# Rules\RODC\AllowedGroupPrivileged.rule.ps1
# Flags Allowed RODC Password Replication Group containing privileged accounts.

@{
    Id          = 'MATI-RODC-002'
    Title       = 'Allowed RODC replication group contains privileged account'
    Severity    = 'Critical'
    Description = "The 'Allowed RODC Password Replication Group' contains a privileged account (AdminCount=1). This allows the RODC to cache the password of a privileged account, negating the security benefit of the RODC model."
    Remediation = "Remove the privileged account from the Allowed RODC Password Replication Group. Only non-privileged accounts that authenticate at the RODC site should be allowed."
    Collectors  = @('RODCInfo')
    References  = @('ANSSI: vuln_rodc_allowed_group', 'PingCastle: P-RODCAllowedGroup')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.RODCInfo.AllowedGroupIssues) {
            $findings += @{
                ObjectDN = $entry.MemberDN
                Domain   = $entry.Domain
                Details  = @{
                    MemberName   = $entry.MemberName
                    IsPrivileged = 'True'
                    Group        = 'Allowed RODC Password Replication Group'
                }
            }
        }
        return $findings
    }
}
