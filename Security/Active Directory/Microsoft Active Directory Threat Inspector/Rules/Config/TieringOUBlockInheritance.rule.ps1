# Rules\Config\TieringOUBlockInheritance.rule.ps1
# Flags Tier 0 OUs where GPO Block Inheritance is not enabled.

@{
    Id          = 'MATI-CONFIG-020'
    Title       = 'Tier 0 OU without GPO Block Inheritance'
    Severity    = 'Medium'
    Description = "A top-level tiering OU (Tier 0 or equivalent) does not have GPO Block Inheritance enabled. Without Block Inheritance, domain-level GPOs flow into Tier 0 OUs, potentially weakening hardening policies or introducing unintended settings. In a tiered AD environment, Tier 0 OUs should block inheritance and have all required GPOs explicitly linked."
    Remediation = "Enable Block Inheritance on the Tier 0 OU: Set-GPInheritance -Target 'OU=Tier 0,DC=domain,DC=local' -IsBlocked Yes. Then ensure all required GPOs (hardening baseline, audit policy, LAPS, etc.) are explicitly linked to the Tier 0 OU since inherited GPOs will no longer apply."
    Collectors  = @('GPOInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn789195(v=ws.11)'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Configurable: OU name patterns that indicate Tier 0 (case-insensitive)
        $tier0Patterns = $Config.Thresholds.TieringOUPatterns ?? @(
            '^Tier\s*0$', '^T0$', '^Tier0$', '^Admin\s*Tier\s*0$', '^Control\s*Plane$'
        )

        foreach ($ou in $Data.GPOInfo.OUInheritance) {
            $isTier0 = $false
            foreach ($pattern in $tier0Patterns) {
                if ($ou.Name -match $pattern) {
                    $isTier0 = $true
                    break
                }
            }

            if ($isTier0 -and -not $ou.BlockInheritance) {
                $findings += @{
                    ObjectDN = $ou.DistinguishedName
                    Domain   = $ou.Domain
                    Details  = @{
                        OUName           = $ou.Name
                        BlockInheritance = 'Not enabled'
                        Risk             = 'Domain-level GPOs flow into Tier 0, potentially weakening hardening'
                    }
                }
            }
        }
        return $findings
    }
}
