# Rules\StaleObjects\LegacyOS.rule.ps1
# Flags computers and servers running legacy/unsupported operating systems.

@{
    Id          = 'MATI-OS-001'
    Title       = 'Computers running legacy operating system'
    Severity    = 'High'
    Description = "Domain member computers are running a legacy or end-of-life operating system. These machines no longer receive security updates and represent a prime entry point for attackers."
    Remediation = "Migrate computers to a supported operating system (Windows Server 2022+, Windows 11). Network-isolate machines that cannot be migrated immediately."
    Collectors  = @('ComputerAccounts')
    Condition   = {
        param($Data, $Config)
        $legacyOS = $Config.Thresholds.LegacyOS
        $findings = @()

        # Aggregate by domain + severity
        $domainBuckets = @{}

        foreach ($comp in $Data.ComputerAccounts) {
            if (-not $comp.Enabled) { continue }
            if ($comp.IsDomainController) { continue }  # DCs handled by MATI-CONFIG-005

            $os = $comp.OperatingSystem
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
            if (-not $severity) {
                foreach ($pattern in $legacyOS.Medium) {
                    if ($os -match [regex]::Escape($pattern)) { $severity = 'Medium'; break }
                }
            }

            if ($severity) {
                $key = "$($comp.Domain)|$severity"
                if (-not $domainBuckets.ContainsKey($key)) {
                    $domainBuckets[$key] = @{
                        Domain   = $comp.Domain
                        Severity = $severity
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $domainBuckets[$key].Count++
                if ($domainBuckets[$key].Examples.Count -lt 5) {
                    $domainBuckets[$key].Examples.Add("$($comp.SamAccountName) ($os)")
                }
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $findings += @{
                Severity = $bucket.Severity
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    LegacyOSCount = "$($bucket.Count)"
                    Severity      = $bucket.Severity
                    Examples      = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}
