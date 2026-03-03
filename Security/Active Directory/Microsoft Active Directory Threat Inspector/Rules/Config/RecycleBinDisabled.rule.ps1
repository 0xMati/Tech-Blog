# Rules\Config\RecycleBinDisabled.rule.ps1
# Checks if the AD Recycle Bin optional feature is enabled.

@{
    Id          = 'MATI-CONFIG-003'
    Title       = 'Active Directory Recycle Bin not enabled'
    Severity    = 'Medium'
    Description = "The AD Recycle Bin optional feature is not enabled. Without it, restoring accidentally deleted objects is complex and risks data loss."
    Remediation = "Enable the Recycle Bin feature via: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name"
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $forest = $Data.DomainInfo.Forest
        if (-not $forest.RecycleBinEnabled) {
            return @(@{
                ObjectDN = "Forest: $($forest.Name)"
                Domain   = $forest.RootDomain
                Details  = @{ RecycleBinEnabled = 'False' }
            })
        }
        return @()
    }
}
