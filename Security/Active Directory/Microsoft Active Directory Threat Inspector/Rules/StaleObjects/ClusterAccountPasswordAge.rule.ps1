# Rules\StaleObjects\ClusterAccountPasswordAge.rule.ps1
# ORADAD: vuln_password_change_cluster_no_change_3years
# Flags cluster virtual computer objects with very old passwords.

@{
    Id          = 'MATI-STALE-004'
    Title       = 'Cluster account password not rotated (>3 years)'
    Severity    = 'Medium'
    Description = "A Failover Cluster virtual computer object (VCO) has a machine password older than 3 years. Cluster VCOs do not rotate their passwords automatically like regular workstations. However, extremely old passwords may indicate decommissioned clusters that were not properly cleaned up, or orphaned cluster objects."
    Remediation = "Verify whether the cluster is still active. If decommissioned, remove the cluster computer account. If still active, consider resetting the cluster computer password using cluster management tools. Review cluster lifecycle management processes."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/failover-clustering/prestage-cluster-adds'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $thresholdDays = 1095  # 3 years

        foreach ($cluster in $Data.SecurityConfig.ClusterAccounts) {
            if ($cluster.PasswordAgeDays -le $thresholdDays) { continue }

            $sev = if ($cluster.PasswordAgeDays -gt 2190) { 'High' }   # > 6 years
                   else { 'Medium' }

            $findings += @{
                ObjectDN = $cluster.DistinguishedName
                Domain   = $cluster.Domain
                Severity = $sev
                Details  = @{
                    SamAccountName  = $cluster.SamAccountName
                    PasswordLastSet = "$($cluster.PasswordLastSet)"
                    PasswordAgeDays = "$($cluster.PasswordAgeDays)"
                    Description     = "$($cluster.Description)"
                }
            }
        }
        return $findings
    }
}
