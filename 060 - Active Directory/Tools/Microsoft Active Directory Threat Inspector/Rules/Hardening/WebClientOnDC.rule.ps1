# Rules\Hardening\WebClientOnDC.rule.ps1
# Flags DCs with WebClient service running.

@{
    Id          = 'MATI-HARD-013'
    Title       = 'WebClient service running on Domain Controller'
    Severity    = 'High'
    Description = "The WebClient service (WebDAV) is running on a Domain Controller. This enables attackers to coerce NTLM authentication via the WebDAV protocol and relay it to LDAPS or AD CS endpoints for privilege escalation (PetitPotam-style attacks)."
    Remediation = "Disable the WebClient service on all Domain Controllers: Set-Service -Name WebClient -StartupType Disabled -Status Stopped"
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-webclient-service')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.SecurityConfig.DCServices) {
            if ($dc.WebClientStatus -eq 'Running') {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.DCName
                        WebClientStatus = 'Running'
                    }
                }
            }
        }
        return $findings
    }
}
