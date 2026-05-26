# Rules\Config\TrustInactive.rule.ps1
# Flags trust relationships that appear inactive.

@{
    Id          = 'MATI-CONFIG-014'
    Title       = 'Inactive trust relationship'
    Severity    = 'Medium'
    Description = "A trust relationship appears inactive or unhealthy when the corresponding trust account secret has not rotated for an extended period. Trust secrets should rotate automatically; an old secret often indicates a broken, unused, or neglected trust."
    Remediation = "Verify whether the trust is still needed. If not, remove it: Remove-ADTrust or netdom trust <domain> /domain:<target> /remove. If it is still in use, validate the trust from both sides and reset the trust secret with netdom trust /reset."
    Collectors  = @('TrustInfo', 'SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trust/')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $inactiveDays = $Config.Thresholds.TrustInactiveDays
        if (-not $inactiveDays) { $inactiveDays = 365 }

        $trustAccountsByDomain = @{}
        foreach ($trustAccount in @($Data.SecurityConfig.TrustAccounts)) {
            $trustAccountDomain = "$($trustAccount.Domain)"
            if ([string]::IsNullOrWhiteSpace($trustAccountDomain)) {
                continue
            }

            if (-not $trustAccountsByDomain.ContainsKey($trustAccountDomain)) {
                $trustAccountsByDomain[$trustAccountDomain] = @()
            }
            $trustAccountsByDomain[$trustAccountDomain] += $trustAccount
        }

        foreach ($trust in $Data.TrustInfo) {
            # Skip intra-forest trusts (always active)
            if ($trust.IntraForest) { continue }

            $sourceDomain = "$($trust.SourceDomain)"
            if ([string]::IsNullOrWhiteSpace($sourceDomain)) {
                $findings += @{
                    Severity = 'Informational'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $null
                    Details  = @{
                        TargetDomain     = $trust.TargetDomain
                        TrustType        = "$($trust.TrustType)"
                        Direction        = "$($trust.TrustDirection)"
                        EvaluationStatus = 'Trust source domain missing from collector output'
                    }
                }
                continue
            }

            $domainTrustAccounts = @($trustAccountsByDomain[$sourceDomain])
            $targetDomain = "$($trust.TargetDomain)"
            $targetFlat = if ($targetDomain -match '^([^\.]+)') { $Matches[1] } else { $targetDomain }

            $matchedAccounts = @($domainTrustAccounts | Where-Object {
                $samBase = ("$($_.SamAccountName)" -replace '\$$', '')
                $samBase -and (
                    $samBase.Equals($targetDomain, [System.StringComparison]::OrdinalIgnoreCase) -or
                    $samBase.Equals($targetFlat, [System.StringComparison]::OrdinalIgnoreCase) -or
                    $targetDomain.StartsWith("$samBase.", [System.StringComparison]::OrdinalIgnoreCase)
                )
            })

            if (@($matchedAccounts).Count -eq 0) {
                $findings += @{
                    Severity = 'Informational'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $sourceDomain
                    Details  = @{
                        TargetDomain      = $trust.TargetDomain
                        TrustType         = "$($trust.TrustType)"
                        Direction         = "$($trust.TrustDirection)"
                        EvaluationStatus  = 'Could not correlate trust to trust account secret'
                    }
                }
                continue
            }

            $matchedAccount = @($matchedAccounts | Sort-Object PasswordAgeDays -Descending)[0]
            if (-not $matchedAccount.PasswordLastSet) {
                $findings += @{
                    Severity = 'Informational'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $sourceDomain
                    Details  = @{
                        TargetDomain       = $trust.TargetDomain
                        TrustType          = "$($trust.TrustType)"
                        Direction          = "$($trust.TrustDirection)"
                        TrustAccount       = $matchedAccount.SamAccountName
                        EvaluationStatus   = 'Trust secret age unavailable'
                    }
                }
                continue
            }

            if ($matchedAccount.PasswordAgeDays -gt $inactiveDays) {
                $severity = if ($matchedAccount.PasswordAgeDays -gt ($inactiveDays * 2)) { 'High' } else { 'Medium' }
                $findings += @{
                    Severity = $severity
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $sourceDomain
                    Details  = @{
                        TargetDomain     = $trust.TargetDomain
                        TrustType        = "$($trust.TrustType)"
                        Direction        = "$($trust.TrustDirection)"
                        TrustAccount     = $matchedAccount.SamAccountName
                        PasswordLastSet  = "$($matchedAccount.PasswordLastSet)"
                        PasswordAgeDays  = "$($matchedAccount.PasswordAgeDays)"
                    }
                }
            }
        }
        return $findings
    }
}
