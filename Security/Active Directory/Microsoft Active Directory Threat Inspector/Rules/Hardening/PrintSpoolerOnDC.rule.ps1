# Rules\Hardening\PrintSpoolerOnDC.rule.ps1
# Flags DCs with Print Spooler service running.

@{
    Id          = 'MATI-HARD-012'
    Title       = 'Print Spooler service running on Domain Controller'
    Severity    = 'High'
    Description = "The Print Spooler service is running on a Domain Controller. This service exposes DCs to PrinterBug/SpoolSample attacks, which can coerce NTLM authentication from the DC to an attacker-controlled server, enabling relay attacks or credential theft."
    Remediation = "Disable the Print Spooler service on all Domain Controllers: Set-Service -Name Spooler -StartupType Disabled -Status Stopped"
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-print-spooler')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.SecurityConfig.DCServices) {
            if ($dc.SpoolerStatus -eq 'Running') {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName        = $dc.DCName
                        SpoolerStatus = 'Running'
                    }
                }
            }
        }
        return $findings
    }
}
