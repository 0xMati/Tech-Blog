# Rules\Config\DefaultUserContainer.rule.ps1
# Checks if the default user container has been redirected from CN=Users.

@{
    Id          = 'MATI-CONFIG-022'
    Title       = 'Default user container not redirected'
    Severity    = 'Medium'
    Description = "New user accounts created without specifying a target OU land in the default CN=Users container, which is not an OU and cannot have Group Policy linked to it. These users receive no user-level GPO hardening until manually moved."
    Remediation = "Create a staging OU and redirect the default user container using: redirusr ""OU=Quarantine,DC=domain,DC=com"". See https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers"
    References  = @(
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers'
    )
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dom in $Data.DomainInfo.Domains) {
            $defaultCN = "CN=Users,$($dom.DistinguishedName)"
            if ($dom.UsersContainer -eq $defaultCN) {
                $findings += @{
                    ObjectDN = $dom.UsersContainer
                    Domain   = $dom.DNSRoot
                    Details  = @{
                        CurrentContainer = $dom.UsersContainer
                        Expected         = 'Should be redirected to a dedicated OU (e.g. via redirusr)'
                    }
                }
            }
        }
        return $findings
    }
}
