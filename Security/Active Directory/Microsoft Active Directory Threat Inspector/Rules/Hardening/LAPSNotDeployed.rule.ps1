# Rules\Hardening\LAPSNotDeployed.rule.ps1
# Flags environments where LAPS is not deployed or coverage is low.

@{
    Id          = 'MATI-HARD-017'
    Title       = 'LAPS not deployed or insufficient coverage'
    Severity    = 'High'
    Description = "Local Administrator Password Solution (LAPS) is not deployed or covers less than 80% of member computers. Without LAPS, local admin passwords may be shared or never rotated, enabling lateral movement."
    Remediation = "Deploy Windows LAPS (or legacy Microsoft LAPS) to all domain-joined workstations and member servers. Use GPO to configure password rotation policy."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: A-NoLaps / S-NoLaps', 'ANSSI: vuln_laps_not_installed')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($info in $Data.SecurityConfig.LAPSInfo) {
            if (-not $info.HasLegacyLapsSchema -and -not $info.HasWindowsLapsSchema) {
                $findings += @{
                    ObjectDN = $info.Domain
                    Domain   = $info.Domain
                    Severity = 'High'
                    Details  = @{
                        Issue            = 'LAPS schema not deployed'
                        LegacyLaps       = 'Not installed'
                        WindowsLaps      = 'Not installed'
                        TotalComputers   = $info.TotalComputers
                    }
                }
            }
            elseif ($info.CoveragePercent -lt ($Config.Thresholds.LAPSMinCoverage ?? 80) -and $info.TotalComputers -gt 0) {
                $sev = if ($info.CoveragePercent -lt 20) { 'High' } else { 'Medium' }
                $findings += @{
                    ObjectDN = $info.Domain
                    Domain   = $info.Domain
                    Severity = $sev
                    Details  = @{
                        Coverage         = "$($info.CoveragePercent)%"
                        TotalComputers   = $info.TotalComputers
                        WithLAPS         = ($info.LapsLegacyCount + $info.LapsWindowsCount)
                        WithoutLAPS      = $info.NoLapsCount
                    }
                }
            }
        }
        return $findings
    }
}
