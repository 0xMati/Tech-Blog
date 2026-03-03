# Rules\PrivilegedAccounts\GMSAPermissions.rule.ps1
# Audits Group Managed Service Account (gMSA) password retrieval permissions.
# gMSAs with overly broad PrincipalsAllowedToRetrieveManagedPassword settings
# may allow low-privilege principals to read the gMSA password and abuse
# any services or SPNs tied to that account.

@{
    Id          = 'MATI-PRIV-010'
    Title       = 'gMSA Password Readable by Many Principals'
    Severity    = 'Medium'
    Description = 'One or more Group Managed Service Accounts (gMSAs) have a broad set of principals ' +
                  'authorized to retrieve the managed password. Each allowed principal can extract the ' +
                  'cleartext password and authenticate as the gMSA. Limit retrieval to only the specific ' +
                  'computer or group that hosts the service.'
    Remediation = 'Review PrincipalsAllowedToRetrieveManagedPassword on each gMSA. Remove unnecessary ' +
                  'principals using Set-ADServiceAccount -PrincipalsAllowedToRetrieveManagedPassword <list>. ' +
                  'Prefer a dedicated security group containing only the specific computer accounts that need access.'
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview'
        'https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword'
    )

    Condition = {
        param($Data, $Config)
        $secConfig = $Data['SecurityConfig']
        if (-not $secConfig -or -not $secConfig.GMSAAccounts) { return $null }

        $threshold = $Config.Thresholds.GMSAMaxPrincipals ?? 5
        $findings  = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($gmsa in $secConfig.GMSAAccounts) {
            if (-not $gmsa.Enabled) { continue }

            # Flag if too many principals or if no principals (orphaned gMSA)
            if ($gmsa.PrincipalsCount -gt $threshold) {
                $findings.Add(@{
                    Severity    = 'Medium'
                    Description = "gMSA '$($gmsa.SamAccountName)' allows $($gmsa.PrincipalsCount) principals " +
                                  "to retrieve its password (threshold: $threshold). Review and restrict access."
                    ObjectDN    = $gmsa.DistinguishedName
                    Domain      = $gmsa.Domain
                    Details     = @{
                        GMSAName          = $gmsa.SamAccountName
                        PrincipalsAllowed = $gmsa.PrincipalsCount
                        Principals        = ($gmsa.PrincipalsAllowed -join '; ')
                        PasswordInterval  = "$($gmsa.PasswordInterval) days"
                    }
                })
            }

            # Also flag gMSA with empty PrincipalsAllowed (potentially orphaned)
            if ($gmsa.PrincipalsCount -eq 0) {
                $findings.Add(@{
                    Severity    = 'Low'
                    Description = "gMSA '$($gmsa.SamAccountName)' has no principals allowed to retrieve its password. " +
                                  "This may indicate an orphaned/unused service account that should be removed."
                    ObjectDN    = $gmsa.DistinguishedName
                    Domain      = $gmsa.Domain
                    Details     = @{
                        GMSAName         = $gmsa.SamAccountName
                        PasswordInterval = "$($gmsa.PasswordInterval) days"
                        Created          = "$($gmsa.WhenCreated)"
                        Status           = 'Orphaned (0 principals)'
                    }
                })
            }
        }

        if ($findings.Count -gt 0) { return $findings }
        return $null
    }
}
