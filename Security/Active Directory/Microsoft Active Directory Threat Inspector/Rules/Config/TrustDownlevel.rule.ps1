# Rules\Config\TrustDownlevel.rule.ps1
# Flags NT4 / downlevel trust relationships.

@{
    Id          = 'MATI-CONFIG-013'
    Title       = 'NT4 downlevel trust relationship'
    Severity    = 'High'
    Description = "A trust relationship is of type 'Downlevel' (NT4) or 'MIT' which uses legacy authentication protocols. NT4 trusts do not support Kerberos and rely on NTLM, which is vulnerable to relay and pass-the-hash attacks."
    Remediation = "Migrate the trust to a Forest or External trust. If the trusted domain still runs NT4, plan its decommissioning."
    Collectors  = @('TrustInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trust/')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # TrustType: Downlevel = 1 (Windows NT 4.0)
            if ($trust.TrustType -eq 'Downlevel' -or $trust.TrustType -eq 1) {
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain = $trust.TargetDomain
                        TrustType    = "$($trust.TrustType)"
                        Direction    = "$($trust.TrustDirection)"
                    }
                }
            }
        }
        return $findings
    }
}
