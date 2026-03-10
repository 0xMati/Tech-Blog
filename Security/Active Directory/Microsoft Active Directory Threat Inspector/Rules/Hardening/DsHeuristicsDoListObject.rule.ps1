# Rules\Hardening\DsHeuristicsDoListObject.rule.ps1
# Flags DoListObject mode enabled in dsHeuristics. [PingCastle: P-DsHeuristicsDoListObject]

@{
    Id          = 'MATI-HARD-042'
    Title       = 'DoListObject mode enabled in dsHeuristics'
    Severity    = 'Medium'
    Description = "The dsHeuristics flags enable the 'List Object' mode (character 3 = '1'). When enabled, this changes the default security model: object visibility becomes controlled by the LIST_OBJECT right rather than LIST_CONTENTS. Enabling this without careful ACL review can break applications and hide objects from administrators."
    Remediation = "Unless explicitly required by policy, set the 3rd character of dsHeuristics back to '0'. Ensure that LIST_OBJECT ACEs are correctly configured if this mode is in use."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $dsh = $Data.SecurityConfig.DsHeuristics
        if ([string]::IsNullOrEmpty($dsh)) { return $findings }
        if ($dsh.Length -ge 3 -and $dsh[2] -eq '1') {
            $findings += @{
                ObjectDN = 'CN=Directory Service,CN=Windows NT,CN=Services,<Configuration>'
                Domain   = 'Forest'
                Details  = @{
                    DsHeuristics   = $dsh
                    Character3     = $dsh[2]
                    Issue          = 'DoListObject mode is enabled'
                }
            }
        }
        return $findings
    }
}
