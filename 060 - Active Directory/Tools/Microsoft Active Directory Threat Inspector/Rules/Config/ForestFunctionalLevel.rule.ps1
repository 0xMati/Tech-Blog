# Rules\Config\ForestFunctionalLevel.rule.ps1
# Checks if the forest functional level is below the configured minimum.

@{
    Id          = 'MATI-CONFIG-002'
    Title       = 'Outdated forest functional level'
    Severity    = 'Medium'
    Description = "The forest functional level is below the recommended minimum. This limits forest-wide security features."
    Remediation = "Raise the forest functional level to at least Windows Server 2016 after raising all domains."
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $forest = $Data.DomainInfo.Forest
        $minLevel = $Config.Thresholds.MinForestFunctionalLevel
        if ([int]$forest.ForestModeNumeric -lt $minLevel) {
            return @(@{
                ObjectDN = "Forest: $($forest.Name)"
                Domain   = $forest.RootDomain
                Details  = @{
                    CurrentLevel = "$($forest.ForestMode)"
                    MinRequired  = "$minLevel"
                }
            })
        }
        return @()
    }
}
