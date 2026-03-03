# Rules\Hardening\LMHashStored.rule.ps1
# Flags DCs where LM hash storage is not disabled.

@{
    Id          = 'MATI-HARD-022'
    Title       = 'LM hash storage not disabled on Domain Controller'
    Severity    = 'High'
    Description = "LM hash storage is not explicitly disabled on one or more Domain Controllers. LM hashes are trivially crackable and provide an easy path to credential compromise."
    Remediation = "Set NoLMHash = 1 via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change = Enabled. Note: On Windows Vista/2008+ this is disabled by default, but should be explicitly set."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: A-LMHashAuthorized', 'ANSSI: vuln_lm_hash')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($null -ne $dc.NoLMHash -and $dc.NoLMHash -eq 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName  = $dc.DCName
                        NoLMHash = 'Disabled (LM hashes are stored)'
                    }
                }
            }
        }
        return $findings
    }
}
