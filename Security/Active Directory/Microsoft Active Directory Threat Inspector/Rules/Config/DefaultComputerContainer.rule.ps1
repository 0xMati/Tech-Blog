# Rules\Config\DefaultComputerContainer.rule.ps1
# Checks if the default computer container has been redirected from CN=Computers.

@{
    Id          = 'MATI-CONFIG-021'
    Title       = 'Default computer container not redirected'
    Severity    = 'Medium'
    Description = "New domain-joined computers land in the default CN=Computers container, which is not an OU and cannot have Group Policy linked to it. These machines receive no hardening GPO until manually moved, creating a window of exposure."
    Remediation = "Create a staging/quarantine OU and redirect the default computer container using: redircmp ""OU=Quarantine,DC=domain,DC=com"". See https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers"
    References  = @(
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers'
    )
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dom in $Data.DomainInfo.Domains) {
            $defaultCN = "CN=Computers,$($dom.DistinguishedName)"
            if ($dom.ComputersContainer -eq $defaultCN) {
                $findings += @{
                    ObjectDN = $dom.ComputersContainer
                    Domain   = $dom.DNSRoot
                    Details  = @{
                        CurrentContainer = $dom.ComputersContainer
                        Expected         = 'Should be redirected to a dedicated OU (e.g. via redircmp)'
                    }
                }
            }
        }
        return $findings
    }
}
