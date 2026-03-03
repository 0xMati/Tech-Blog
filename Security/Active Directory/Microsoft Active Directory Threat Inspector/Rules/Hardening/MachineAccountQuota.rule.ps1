# Rules\Hardening\MachineAccountQuota.rule.ps1
# Flags domains where ms-DS-MachineAccountQuota is not zero.

@{
    Id          = 'MATI-HARD-003'
    Title       = 'MachineAccountQuota allows users to join computers'
    Severity    = 'High'
    Description = "The ms-DS-MachineAccountQuota attribute is not set to 0. By default it is set to 10, allowing any authenticated user to join up to 10 computers to the domain. Attacker-joined computers can be used for RBCD attacks and lateral movement."
    Remediation = "Set ms-DS-MachineAccountQuota to 0: Set-ADDomain -Identity <domain> -Replace @{'ms-DS-MachineAccountQuota'=0}. Delegate computer join permissions to specific admin accounts."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: S-ADRegistration', 'ANSSI: vuln_machineaccountquota')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $maxQuota = $Config.Thresholds.MaxMachineAccountQuota
        if ($null -eq $maxQuota) { $maxQuota = 0 }

        foreach ($item in $Data.SecurityConfig.MachineAccountQuotas) {
            if ($item.MachineAccountQuota -gt $maxQuota) {
                $findings += @{
                    ObjectDN = $item.Domain
                    Domain   = $item.Domain
                    Details  = @{
                        CurrentQuota    = "$($item.MachineAccountQuota)"
                        RecommendedMax  = "$maxQuota"
                    }
                }
            }
        }
        return $findings
    }
}
