# Collectors\Get-MATIPasswordPolicy.ps1
# MATIv2 - Collects default domain password policy and Fine-Grained Password Policies.

function Get-MATIPasswordPolicy {
    <#
    .SYNOPSIS
        Collects the default domain password policy and all FGPPs across the forest.
    .OUTPUTS
        [hashtable] with keys: DefaultPolicies, FineGrainedPolicies
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $defaultPolicies = [System.Collections.Generic.List[PSCustomObject]]::new()
    $fgppList        = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domainDns in $forest.Domains) {
        try {
            $policy = Get-ADDefaultDomainPasswordPolicy -Server $domainDns -ErrorAction Stop
            $defaultPolicies.Add([PSCustomObject]@{
                Domain                = $domainDns
                MinPasswordLength     = $policy.MinPasswordLength
                PasswordHistoryCount  = $policy.PasswordHistoryCount
                MaxPasswordAge        = $policy.MaxPasswordAge
                MinPasswordAge        = $policy.MinPasswordAge
                ComplexityEnabled     = $policy.ComplexityEnabled
                ReversibleEncryption  = $policy.ReversibleEncryptionEnabled
                LockoutThreshold      = $policy.LockoutThreshold
                LockoutDuration       = $policy.LockoutDuration
                LockoutObservationWindow = $policy.LockoutObservationWindow
            })
        }
        catch {
            Write-Warning "    Cannot read password policy for $domainDns : $($_.Exception.Message)"
        }

        # Fine-Grained Password Policies (requires 2008+ functional level)
        try {
            $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($fgpp in $fgpps) {
                $fgppList.Add([PSCustomObject]@{
                    Name                  = $fgpp.Name
                    Domain                = $domainDns
                    Precedence            = $fgpp.Precedence
                    MinPasswordLength     = $fgpp.MinPasswordLength
                    PasswordHistoryCount  = $fgpp.PasswordHistoryCount
                    MaxPasswordAge        = $fgpp.MaxPasswordAge
                    MinPasswordAge        = $fgpp.MinPasswordAge
                    ComplexityEnabled     = $fgpp.ComplexityEnabled
                    ReversibleEncryption  = $fgpp.ReversibleEncryptionEnabled
                    LockoutThreshold      = $fgpp.LockoutThreshold
                    AppliesTo             = @($fgpp.AppliesTo)
                    DistinguishedName     = $fgpp.DistinguishedName
                })
            }
        }
        catch {
            # FGPP may not be available on older functional levels
            Write-Verbose "    No FGPP support or no policies found for $domainDns"
        }
    }

    return @{
        DefaultPolicies       = @($defaultPolicies)
        FineGrainedPolicies   = @($fgppList)
    }
}
