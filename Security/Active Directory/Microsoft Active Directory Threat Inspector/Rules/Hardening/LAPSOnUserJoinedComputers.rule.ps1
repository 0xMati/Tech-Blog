# Rules\Hardening\LAPSOnUserJoinedComputers.rule.ps1
# Flags LAPS passwords readable on user-joined computers. [PingCastle: A-LAPS-Joined-Computers]

@{
    Id          = 'MATI-HARD-047'
    Title       = 'LAPS password potentially retrievable from user-joined computers'
    Severity    = 'Medium'
    Description = "Computers joined to the domain by non-privileged users (via MachineAccountQuota) may have LAPS passwords that can be read by the joining user. When a user uses their MachineAccountQuota to join a machine, they become the creator-owner and may retain read access to LAPS attributes, enabling them to retrieve the local administrator password."
    Remediation = "Set ms-Mcs-AdmPwdExpirationTime and ms-Mcs-AdmPwd read permissions explicitly to only designated LAPS administrators. Set MachineAccountQuota to 0 and use a delegated join process instead. Review computer object owners and reset them to Domain Admins."
    Collectors  = @('ComputerAccounts', 'SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview'
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Only check if MachineAccountQuota > 0 somewhere
        $hasQuota = $false
        foreach ($maq in $Data.SecurityConfig.MachineAccountQuotas) {
            if ([int]$maq.Quota -gt 0) { $hasQuota = $true; break }
        }
        if (-not $hasQuota) { return $findings }

        # Check if any LAPS deployment exists
        $lapsDeployed = $false
        foreach ($info in $Data.SecurityConfig.LAPSInfo) {
            if ($info.Coverage -gt 0) { $lapsDeployed = $true; break }
        }
        if (-not $lapsDeployed) { return $findings }

        # Flag the condition: MachineAccountQuota > 0 AND LAPS is deployed
        foreach ($maq in $Data.SecurityConfig.MachineAccountQuotas) {
            if ([int]$maq.Quota -gt 0) {
                $findings += @{
                    ObjectDN = $maq.Domain
                    Domain   = $maq.Domain
                    Details  = @{
                        MachineAccountQuota = $maq.Quota
                        Issue               = "MachineAccountQuota=$($maq.Quota) with LAPS deployed — user-joined computers may expose LAPS passwords to the joining user"
                    }
                }
            }
        }
        return $findings
    }
}
