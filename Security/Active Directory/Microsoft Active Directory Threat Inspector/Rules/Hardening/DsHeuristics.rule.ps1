# Rules\Hardening\DsHeuristics.rule.ps1
# Flags dangerous dsHeuristics settings.

@{
    Id          = 'MATI-HARD-004'
    Title       = 'Dangerous dsHeuristics settings detected'
    Severity    = 'High'
    Description = "The dsHeuristics attribute on the Directory Service object contains dangerous settings. Key flags: character 3 (fLDAPBlockAnonOps) should not be '2' (allows anonymous LDAP), character 7 (fDoListObject) may expose listing, character 16 (AdminSDExMask) should be '0' to keep AdminSDHolder protection active for all built-in groups."
    Remediation = "Review and correct the dsHeuristics value on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration. Set character 3 to '0' or '1', and character 16 to '0'."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5', 'KB5008383 (CVE-2021-42291): chars 28-29 must be 11')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $dsh = $Data.SecurityConfig.DsHeuristics
        if ([string]::IsNullOrEmpty($dsh)) {
            # Empty dsHeuristics → chars 28-29 not set → KB5008383 enforcement not active
            $findings += @{
                ObjectDN = 'CN=Directory Service,CN=Windows NT,CN=Services'
                Domain   = (Get-ADForest -ErrorAction SilentlyContinue).RootDomain
                Details  = @{
                    DsHeuristics = '(not set)'
                    Issues       = 'KB5008383 / CVE-2021-42291 enforcement not configured (chars 28-29 absent — should be 11)'
                }
            }
            return $findings
        }

        $issues = @()

        # Character 3 (index 2): fLDAPBlockAnonOps - '2' allows anonymous LDAP
        if ($dsh.Length -ge 3 -and $dsh[2] -eq '2') {
            $issues += 'Anonymous LDAP allowed (char 3 = 2)'
        }

        # Character 16 (index 15): AdminSDExMask - non-zero disables protection for some groups
        if ($dsh.Length -ge 16 -and $dsh[15] -ne '0') {
            $issues += "AdminSDHolder protection partially disabled (char 16 = $($dsh[15]))"
        }

        # Character 19 (index 18): fAllowLDAPTraffic - '1' may weaken security
        if ($dsh.Length -ge 19 -and $dsh[18] -eq '1') {
            $issues += 'Insecure LDAP traffic allowed (char 19 = 1)'
        }

        # Characters 28-29 (index 27-28): KB5008383 / CVE-2021-42291 enforcement
        # char 28 = AuthZ verification, char 29 = Implicit ownership removal
        # Must be '1' and '1' for full enforcement
        if ($dsh.Length -lt 29) {
            $issues += 'KB5008383 / CVE-2021-42291 enforcement not configured (dSHeuristics too short — chars 28-29 absent)'
        } else {
            $c28 = $dsh[27]; $c29 = $dsh[28]
            if ($c28 -ne '1' -or $c29 -ne '1') {
                $issues += "KB5008383 / CVE-2021-42291 not in Enforce mode (chars 28-29 = $c28$c29, should be 11)"
            }
        }

        if ($issues.Count -gt 0) {
            $findings += @{
                ObjectDN = 'CN=Directory Service,CN=Windows NT,CN=Services'
                Domain   = (Get-ADForest -ErrorAction SilentlyContinue).RootDomain
                Details  = @{
                    DsHeuristics = $dsh
                    Issues       = ($issues -join '; ')
                }
            }
        }
        return $findings
    }
}
