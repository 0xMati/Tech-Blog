# Rules\RODC\OrphanKrbtgt.rule.ps1
# Flags orphan krbtgt_XXXXX accounts not linked to any RODC.

@{
    Id          = 'MATI-RODC-004'
    Title       = 'Orphan RODC krbtgt account detected'
    Severity    = 'Medium'
    Description = "A krbtgt_XXXXX account exists but is not linked to any active RODC via the msDS-KrbTgtLink attribute. This typically occurs when an RODC was decommissioned without proper cleanup. Orphan krbtgt accounts can be used for Golden Ticket-like attacks against former RODC services."
    Remediation = "Delete the orphan krbtgt account after confirming no RODC is using it. Use: Remove-ADUser -Identity <krbtgt_DN> -Confirm"
    Collectors  = @('RODCInfo')
    References  = @('ANSSI: vuln_rodc_orphan_krbtgt', 'PingCastle: P-RODCOrphan')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.RODCInfo.OrphanKrbtgt) {
            $findings += @{
                ObjectDN = $entry.DistinguishedName
                Domain   = $entry.Domain
                Details  = @{
                    SamAccountName = $entry.SamAccountName
                    Status         = 'Orphan (no linked RODC)'
                }
            }
        }
        return $findings
    }
}
