# Rules\GPO\WsusHTTP.rule.ps1
# Flags domains where WSUS is configured over HTTP instead of HTTPS via GPO.

@{
    Id          = 'MATI-GPO-010'
    Title       = 'WSUS configured over HTTP via GPO'
    Severity    = 'High'
    Description = "Windows Server Update Services (WSUS) is configured to use HTTP instead of HTTPS in GPO settings. Attackers on the network can intercept WSUS traffic and inject malicious updates, achieving code execution on all machines in the domain including DCs."
    Remediation = "Configure WSUS to use HTTPS by setting the WUServer and WUStatusServer GPO registry values to HTTPS URLs (https://wsus.domain.com:8531). Enable SSL on the WSUS server."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $wsusEntries = $registryPolicies | Where-Object {
                $_.Key -eq 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -and
                $_.ValueName -eq 'WUServer'
            }

            foreach ($entry in $wsusEntries) {
                if ($entry.Data -match '^http://') {
                    $findings += @{
                        ObjectDN = $domainDns
                        Domain   = $domainDns
                        Details  = @{
                            Issue    = "WSUS configured over HTTP (not HTTPS)"
                            GPO      = "$($entry.GPO)"
                            LinkedTo = "$($entry.LinkedTo)"
                            WUServer = "$($entry.Data)"
                        }
                    }
                }
            }
        }
        return $findings
    }
}
