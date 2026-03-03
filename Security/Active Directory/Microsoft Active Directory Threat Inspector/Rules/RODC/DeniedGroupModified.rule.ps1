# Rules\RODC\DeniedGroupModified.rule.ps1
# Flags Denied RODC Password Replication Group missing default members.

@{
    Id          = 'MATI-RODC-003'
    Title       = 'Denied RODC replication group is missing default members'
    Severity    = 'High'
    Description = "The 'Denied RODC Password Replication Group' is missing one or more default members (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, or krbtgt). Removing these defaults allows their passwords to be potentially cached on RODCs."
    Remediation = "Restore all default members to the Denied RODC Password Replication Group. Never remove privileged groups from this deny list."
    Collectors  = @('RODCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/read-only-domain-controller-planning')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.RODCInfo.DeniedGroupIssues) {
            $findings += @{
                ObjectDN = $entry.Domain
                Domain   = $entry.Domain
                Details  = @{
                    MissingSIDs  = ($entry.MissingSIDs -join '; ')
                    MissingCount = "$($entry.MissingCount)"
                    Group        = 'Denied RODC Password Replication Group'
                }
            }
        }
        return $findings
    }
}
