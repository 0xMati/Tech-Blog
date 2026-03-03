# Rules\Config\TombstoneLifetime.rule.ps1
# Checks if the tombstone lifetime is too short or undefined.

@{
    Id          = 'MATI-CONFIG-004'
    Title       = 'Tombstone lifetime too short or undefined'
    Severity    = 'Medium'
    Description = "The tombstone lifetime (tombstoneLifetime) is either undefined or below the recommended minimum. A value that is too low reduces the restoration window and can cause replication issues."
    Remediation = "Set tombstoneLifetime to at least 180 days via ADSI Edit on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration."
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $forest  = $Data.DomainInfo.Forest
        $minDays = $Config.Thresholds.MinTombstoneLifetime
        $tsLife  = $forest.TombstoneLifetime

        if (-not $tsLife -or $tsLife -lt $minDays) {
            return @(@{
                ObjectDN = "Forest: $($forest.Name)"
                Domain   = $forest.RootDomain
                Details  = @{
                    TombstoneLifetime = if ($tsLife) { "$tsLife days" } else { 'Not defined' }
                    MinRequired       = "$minDays days"
                }
            })
        }
        return @()
    }
}
