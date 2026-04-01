# Rules\Hardening\AuthSilosNotDeployed.rule.ps1
# Flags environments where Authentication Policies/Silos are not deployed for Tier 0 protection.

@{
    Id          = 'MATI-HARD-034'
    Category    = 'Governance'
    Title       = 'Authentication Policies and Silos not deployed'
    Severity    = 'Medium'
    Description = "No Authentication Policies or Silos are configured in the domain. Authentication Silos restrict where privileged accounts can authenticate, enforcing Tier 0 credential isolation at the Kerberos level. Without them, a compromised Tier 0 credential can be used from any machine. Requires Domain Functional Level 2012 R2 or higher."
    Remediation = "Create Authentication Policies with TGT lifetime restrictions and Authentication Silos to bind Tier 0 accounts to Tier 0 computers only. Deploy in audit mode first (monitor Event IDs 105/106 in the AuthenticationPolicyFailures-DomainController log), then switch to enforce mode."
    Collectors  = @('SecurityConfig', 'DomainInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Check if DFL supports Authentication Policies (2012 R2+ = numeric 6+)
        foreach ($domain in $Data.DomainInfo.Domains) {
            if ([int]$domain.DomainModeNumeric -lt 6) { continue }  # Skip domains below 2012 R2
        }

        $silos = $Data.SecurityConfig.AuthSilos
        $policies = $Data.SecurityConfig.AuthPolicies

        if ($silos.Count -eq 0 -and $policies.Count -eq 0) {
            $findings += @{
                ObjectDN = "Forest: $($Data.DomainInfo.Forest.Name)"
                Domain   = $Data.DomainInfo.Forest.RootDomain
                Details  = @{
                    AuthPolicies = '0 (none configured)'
                    AuthSilos    = '0 (none configured)'
                    Impact       = 'No Kerberos-level credential isolation for Tier 0 accounts'
                }
            }
        }
        elseif ($silos.Count -gt 0) {
            # Check for silos still in audit mode (not enforced)
            foreach ($silo in $silos) {
                if (-not $silo.Enforce) {
                    $findings += @{
                        ObjectDN = $silo.DistinguishedName
                        Domain   = $Data.DomainInfo.Forest.RootDomain
                        Details  = @{
                            SiloName    = $silo.Name
                            Enforce     = 'False (audit mode only)'
                            MemberCount = "$($silo.MemberCount)"
                        }
                    }
                }
            }
        }

        return $findings
    }
}
