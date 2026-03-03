# Rules\Config\LegacyDC.rule.ps1
# Flags domain controllers running legacy/unsupported OS.

@{
    Id          = 'MATI-CONFIG-005'
    Title       = 'Domain controller running legacy OS'
    Severity    = 'Critical'
    Description = "One or more domain controllers are running a legacy or unsupported operating system. These DCs pose a high risk as they no longer receive security patches."
    Remediation = "Migrate domain controllers to Windows Server 2022 or later. Decommission legacy DCs."
    Collectors  = @('DCInfo')
    Condition   = {
        param($Data, $Config)
        $legacyOS = $Config.Thresholds.LegacyOS
        $findings = @()

        foreach ($dc in $Data.DCInfo) {
            $os = $dc.OperatingSystem
            if (-not $os) { continue }

            $severity = $null
            foreach ($pattern in $legacyOS.Critical) {
                if ($os -match [regex]::Escape($pattern)) { $severity = 'Critical'; break }
            }
            if (-not $severity) {
                foreach ($pattern in $legacyOS.High) {
                    if ($os -match [regex]::Escape($pattern)) { $severity = 'High'; break }
                }
            }

            if ($severity) {
                $findings += @{
                    Severity = $severity
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.Name
                        OperatingSystem = $os
                        Site            = $dc.Site
                    }
                }
            }
        }
        return $findings
    }
}
