# Rules\Hardening\LSASSNotProtected.rule.ps1
# Flags DCs where LSASS is not running as a Protected Process Light (PPL).

@{
    Id          = 'MATI-HARD-033'
    Title       = 'LSASS not running as Protected Process (RunAsPPL) on Domain Controller'
    Severity    = 'High'
    Description = "LSASS is not configured with the expected Protected Process Light (PPL) setting on a Domain Controller. For Windows Server, this rule expects RunAsPPL=1 (enabled with UEFI lock). RunAsPPL prevents non-protected processes from reading LSASS memory or injecting code into it, blocking most credential theft tools (Mimikatz, procdump, etc.) from dumping credentials."
    Remediation = "Enable LSASS protection on Domain Controllers via GPO or registry with HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD, enabled with UEFI lock). A value of 2 means enabled without UEFI lock and is not treated as compliant by this rule for Windows Server. Test in audit mode first and validate plugin compatibility before deployment."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($null -eq $dc.RunAsPPL -or $dc.RunAsPPL -eq 0 -or $dc.RunAsPPL -eq 2) {
                $severity = if ($dc.RunAsPPL -eq 2) { 'Medium' } else { 'High' }
                $findings += @{
                    Severity = $severity
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName   = $dc.DCName
                        RunAsPPL = switch ($dc.RunAsPPL) {
                            0       { 'Disabled' }
                            $null   { 'Not configured (disabled)' }
                            2       { 'Enabled without UEFI lock (not treated as compliant on Windows Server)' }
                            default { "$($dc.RunAsPPL)" }
                        }
                        Expected = 'RunAsPPL = 1 (enabled with UEFI lock)'
                    }
                }
            }
        }
        return $findings
    }
}
