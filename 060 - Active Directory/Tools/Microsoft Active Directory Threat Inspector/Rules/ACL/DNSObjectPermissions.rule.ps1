# Rules\ACL\DNSObjectPermissions.rule.ps1
# ORADAD: vuln_permissions_msdns
# Flags dangerous ACEs on MicrosoftDNS container objects.

@{
    Id          = 'MATI-ACL-011'
    Title       = 'Dangerous permissions on MicrosoftDNS objects'
    Severity    = 'High'
    Description = "A principal other than the expected DNS administration principals has dangerous permissions on MicrosoftDNS container objects in the DomainDnsZones or ForestDnsZones application partition. An attacker with write access to DNS objects can create or modify DNS records to redirect traffic, enabling man-in-the-middle attacks, credential interception, or denial of service. This is particularly dangerous for WPAD, _msdcs, and SRV records used for DC location."
    Remediation = "Remove the dangerous ACE from MicrosoftDNS containers. Only DNS Admins, Domain Admins, and SYSTEM should have write access to DNS objects. Review DNS delegation and ensure the DnsAdmins group membership is tightly controlled (DnsAdmins is a known privilege escalation path via DLL injection)."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/networking/dns/troubleshoot/troubleshoot-dns-server'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # DnsAdmins domain-relative RID = -1101, DnsUpdateProxy = -1102
        # These groups are expected to have permissions on DNS objects
        $dnsAdminRIDs = @('-1101', '-1102')

        foreach ($ace in $Data.ACLInfo.DNSObjects) {
            # Skip DnsAdmins and DnsUpdateProxy (expected permissions)
            $sidStr = $ace.IdentitySID
            $isDnsGroup = $false
            foreach ($rid in $dnsAdminRIDs) {
                if ($sidStr -like "*$rid") { $isDnsGroup = $true; break }
            }
            if ($isDnsGroup) { continue }

            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    IdentityReference = $ace.IdentityRef
                    IdentitySID       = $ace.IdentitySID
                    Right             = $ace.Right
                    ADRights          = $ace.ADRights
                    IsInherited       = "$($ace.IsInherited)"
                }
            }
        }
        return $findings
    }
}
