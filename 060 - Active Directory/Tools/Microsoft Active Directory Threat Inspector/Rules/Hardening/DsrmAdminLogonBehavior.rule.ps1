# Rules\Hardening\DsrmAdminLogonBehavior.rule.ps1
# Flags DCs where the DSRM (Directory Services Restore Mode) administrator account
# is allowed to authenticate over the network - a stealthy Tier 0 persistence vector.

@{
    Id          = 'MATI-HARD-048'
    Title       = 'DSRM administrator network logon allowed on Domain Controller'
    Severity    = 'High'
    Description = "The DSRM (Directory Services Restore Mode) local administrator account on a Domain Controller is permitted to authenticate over the network (DsrmAdminLogonBehavior = 2). The DSRM account password is rarely rotated and not managed by AD, so an attacker who recovers it (e.g. from a backup or via a synced password) gains a persistent local-administrator foothold on the DC that survives domain credential resets. DsrmAdminLogonBehavior = 1 only permits DSRM logon while the AD DS service is stopped; a value of 2 permits it at all times and is the dangerous configuration."
    Remediation = "Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior to 0 (console-only, default) or at most 1 (only when AD DS is stopped) on all Domain Controllers. Avoid 2. Ensure the DSRM password is rotated regularly and stored securely, and monitor Event ID 4794 (DSRM password set)."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-dsrm-administrator-password',
        'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # 2 = DSRM admin can always log on over the network (persistence risk).
            if ($dc.DsrmAdminLogonBehavior -eq 2) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName                 = $dc.DCName
                        DsrmAdminLogonBehavior = '2 (network logon always allowed)'
                    }
                }
            }
        }
        return $findings
    }
}
