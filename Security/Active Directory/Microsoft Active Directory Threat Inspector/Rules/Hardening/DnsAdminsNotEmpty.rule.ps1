# Rules\Hardening\DnsAdminsNotEmpty.rule.ps1
# Flags DnsAdmins group with members.

@{
    Id          = 'MATI-HARD-014'
    Title       = 'DnsAdmins group is not empty'
    Severity    = 'High'
    Description = "The DnsAdmins group has members. Members of this group can load arbitrary DLLs on Domain Controllers through the DNS service (ServerLevelPluginDll), which runs as SYSTEM. This is a well-known privilege escalation path to Domain Admin."
    Remediation = "Empty the DnsAdmins group. Use a dedicated privileged access model for DNS administration if needed."
    Collectors  = @('DNSConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/networking/dns/troubleshoot/dns-server-troubleshooting')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if ($Data.DNSConfig.DnsAdmins.Count -gt 0) {
            # Group by domain
            $byDomain = $Data.DNSConfig.DnsAdmins | Group-Object -Property Domain
            foreach ($group in $byDomain) {
                $findings += @{
                    ObjectDN = "DnsAdmins ($($group.Name))"
                    Domain   = $group.Name
                    Details  = @{
                        MemberCount = "$($group.Count)"
                        Members     = ($group.Group | ForEach-Object { $_.MemberSAM }) -join ', '
                    }
                }
            }
        }
        return $findings
    }
}
