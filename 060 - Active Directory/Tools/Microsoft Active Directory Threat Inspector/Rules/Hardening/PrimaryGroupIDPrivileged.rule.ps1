# Rules\Hardening\PrimaryGroupIDPrivileged.rule.ps1
# ORADAD: vuln_primary_group_id_1000
# Flags accounts with PrimaryGroupID set to a privileged group (RID < 1000).

@{
    Id          = 'MATI-HARD-035'
    Title       = 'Account with privileged PrimaryGroupID (RID < 1000)'
    Severity    = 'High'
    Description = "One or more accounts have their PrimaryGroupID set to a built-in or privileged group (RID below 1000). The default PrimaryGroupID is 513 (Domain Users) for users and 515 (Domain Computers) for computers. A PrimaryGroupID pointing to Domain Admins (512), Enterprise Admins (519), or another privileged group is a well-known persistence technique and privilege escalation vector."
    Remediation = "Reset the PrimaryGroupID to the default value (513 for users, 515 for computers, 516 for DCs). Investigate why it was changed — this is often an indicator of compromise."
    Collectors  = @('UserAccounts', 'ComputerAccounts')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        # Well-known privileged RIDs < 1000 (excluding 513=Domain Users, 514=Domain Guests, 515=Domain Computers, 516=Domain Controllers)
        $defaultUserRID = 513
        $defaultComputerRID = 515
        $defaultDCRID = 516
        $privilegedRIDs = @(512, 518, 519, 520) # DA, SA, EA, Group Policy Creator Owners
        $builtinRIDs = @(544, 548, 549, 550, 551) # Administrators, Account Ops, Server Ops, Print Ops, Backup Ops

        foreach ($user in $Data.UserAccounts) {
            $pgid = $user.PrimaryGroupID
            if ($null -eq $pgid) { continue }
            if ($pgid -eq $defaultUserRID) { continue }
            if ($pgid -lt 1000 -and $pgid -in ($privilegedRIDs + $builtinRIDs)) {
                $findings += @{
                    ObjectDN = $user.DistinguishedName
                    Domain   = $user.Domain
                    Details  = @{
                        SamAccountName = $user.SamAccountName
                        PrimaryGroupID = "$pgid"
                        ObjectType     = 'User'
                        Risk           = 'Privileged group membership via PrimaryGroupID'
                    }
                }
            }
        }
        foreach ($comp in $Data.ComputerAccounts) {
            $pgid = $comp.PrimaryGroupID
            if ($null -eq $pgid) { continue }
            if ($pgid -in @($defaultComputerRID, $defaultDCRID, 521)) { continue } # 521 = RODC
            if ($pgid -lt 1000 -and $pgid -in ($privilegedRIDs + $builtinRIDs)) {
                $findings += @{
                    ObjectDN = $comp.DistinguishedName
                    Domain   = $comp.Domain
                    Details  = @{
                        SamAccountName = $comp.SamAccountName
                        PrimaryGroupID = "$pgid"
                        ObjectType     = 'Computer'
                        Risk           = 'Privileged group membership via PrimaryGroupID'
                    }
                }
            }
        }
        return $findings
    }
}
