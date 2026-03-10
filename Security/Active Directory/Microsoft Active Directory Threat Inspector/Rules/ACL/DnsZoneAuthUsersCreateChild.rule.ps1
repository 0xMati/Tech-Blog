# Rules\ACL\DnsZoneAuthUsersCreateChild.rule.ps1
# Flags DNS zones where Authenticated Users can create records. [PingCastle: A-DnsZoneAUCreateChild]

@{
    Id          = 'MATI-ACL-016'
    Title       = 'Authenticated Users can create objects in DNS zone'
    Severity    = 'High'
    Description = "One or more AD-integrated DNS zones grant CreateChild or GenericAll rights to Authenticated Users or Everyone. This allows any domain user to create DNS records, enabling DNS spoofing attacks such as ADIDNS poisoning to capture authentication traffic (NTLM relay, Kerberos, etc.)."
    Remediation = "Remove the CreateChild permission for Authenticated Users/Everyone from the impacted DNS zones. Only DnsAdmins, Domain Admins, and the DNS server computer accounts should have write access to DNS zones."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://www.netspi.com/blog/technical-blog/network-penetration-testing/exploiting-adidns/'
        'https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-ref'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.ACLInfo.DnsZoneCreateChild) {
            $findings += @{
                ObjectDN = $entry.ZoneDN
                Domain   = $entry.Domain
                Details  = @{
                    ZoneName    = $entry.ZoneName
                    Principal   = $entry.IdentityRef
                    PrincipalSID = $entry.IdentitySID
                    Right       = $entry.Right
                    Issue       = "Any authenticated user can create DNS records in this zone"
                }
            }
        }
        return $findings
    }
}
