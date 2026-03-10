# Rules\Hardening\PrimaryGroupIDModified.rule.ps1
# ORADAD: vuln_primary_group_id_nochange
# Flags accounts whose PrimaryGroupID differs from the expected default.

@{
    Id          = 'MATI-HARD-036'
    Title       = 'Account with non-default PrimaryGroupID'
    Severity    = 'Medium'
    Description = "One or more accounts have a PrimaryGroupID that differs from the expected default (513 for users, 515 for computers, 516 for DCs, 521 for RODCs). Even when not set to a privileged group, a modified PrimaryGroupID is abnormal and may indicate misconfiguration or an attempted attack. The primary group membership is hidden from standard group enumeration tools, making it a stealth persistence mechanism."
    Remediation = "Reset the PrimaryGroupID to the default value. For users: 513 (Domain Users). For computers: 515 (Domain Computers). For DCs: 516 (Domain Controllers). Investigate the reason for the change."
    Collectors  = @('UserAccounts', 'ComputerAccounts')
    References  = @(
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($user in $Data.UserAccounts) {
            $pgid = $user.PrimaryGroupID
            if ($null -eq $pgid) { continue }
            # Default for user = 513 (Domain Users), 514 (Domain Guests for Guest)
            if ($pgid -notin @(513, 514)) {
                $findings += @{
                    ObjectDN = $user.DistinguishedName
                    Domain   = $user.Domain
                    Details  = @{
                        SamAccountName = $user.SamAccountName
                        PrimaryGroupID = "$pgid"
                        ExpectedDefault = '513 (Domain Users)'
                        ObjectType     = 'User'
                    }
                }
            }
        }
        foreach ($comp in $Data.ComputerAccounts) {
            $pgid = $comp.PrimaryGroupID
            if ($null -eq $pgid) { continue }
            # Default for computers = 515, DCs = 516, RODCs = 521
            if ($pgid -notin @(515, 516, 521)) {
                $findings += @{
                    ObjectDN = $comp.DistinguishedName
                    Domain   = $comp.Domain
                    Details  = @{
                        SamAccountName  = $comp.SamAccountName
                        PrimaryGroupID  = "$pgid"
                        ExpectedDefault = '515 (Domain Computers) / 516 (Domain Controllers) / 521 (RODCs)'
                        ObjectType      = 'Computer'
                    }
                }
            }
        }
        return $findings
    }
}
