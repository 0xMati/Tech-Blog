# Rules\Hardening\LSASSNotProtected.rule.ps1
# Flags DCs where LSASS is not running as a Protected Process Light (PPL).

@{
    Id          = 'MATI-HARD-033'
    Title       = 'LSASS not running as Protected Process (RunAsPPL) on Domain Controller'
    Severity    = 'High'
    Description = "LSASS is not configured to run as a Protected Process Light (PPL) on a Domain Controller. RunAsPPL prevents non-protected processes from reading LSASS memory or injecting code into it, blocking most credential theft tools (Mimikatz, procdump, etc.) from dumping credentials."
    Remediation = "Enable LSASS protection via GPO or registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD). Test in audit mode first. On Windows Server 2022+, this can also be configured via 'Local Security Authority protection' in Windows Security settings."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # RunAsPPL: 0 or $null = not enabled, 1 = enabled
            if ($null -eq $dc.RunAsPPL -or $dc.RunAsPPL -eq 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName   = $dc.DCName
                        RunAsPPL = switch ($dc.RunAsPPL) {
                            0       { 'Disabled' }
                            $null   { 'Not configured (disabled)' }
                            default { $dc.RunAsPPL }
                        }
                    }
                }
            }
        }
        return $findings
    }
}
