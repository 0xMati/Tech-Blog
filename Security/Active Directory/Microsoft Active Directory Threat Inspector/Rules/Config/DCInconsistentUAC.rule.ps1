# Rules\Config\DCInconsistentUAC.rule.ps1
# ORADAD: vuln_dc_inconsistent_uac
# Flags Domain Controllers with inconsistent UserAccountControl flags.

@{
    Id          = 'MATI-CONFIG-023'
    Title       = 'Domain Controller with inconsistent UserAccountControl'
    Severity    = 'High'
    Description = "A Domain Controller has a UserAccountControl value that does not include the SERVER_TRUST_ACCOUNT (0x2000) flag, or includes unexpected flags such as WORKSTATION_TRUST_ACCOUNT (0x1000), PASSWD_NOTREQD (0x20), or account disabled (0x2). A legitimate writable DC should have UAC 0x82000 (SERVER_TRUST_ACCOUNT + TRUSTED_FOR_DELEGATION) and an RODC should have 0x83000000 or similar. Inconsistent UAC may indicate a compromised or misconfigured DC."
    Remediation = "Investigate the affected DC object. Verify it was legitimately promoted. Ensure the UserAccountControl matches expected values for a domain controller. For writable DCs the expected flags include SERVER_TRUST_ACCOUNT (0x2000). For RODCs: PARTIAL_SECRETS_ACCOUNT (0x04000000)."
    Collectors  = @('DCInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        # Expected: SERVER_TRUST_ACCOUNT = 0x2000
        $SERVER_TRUST_ACCOUNT   = 0x2000
        $WORKSTATION_TRUST      = 0x1000
        $ACCOUNTDISABLE         = 0x2
        $PASSWD_NOTREQD         = 0x20

        foreach ($dc in $Data.DCInfo) {
            $uac = $dc.UserAccountControl
            if ($null -eq $uac) { continue }
            $issues = @()

            if (-not ($uac -band $SERVER_TRUST_ACCOUNT)) {
                $issues += 'Missing SERVER_TRUST_ACCOUNT (0x2000)'
            }
            if ($uac -band $WORKSTATION_TRUST) {
                $issues += 'Has WORKSTATION_TRUST_ACCOUNT (0x1000)'
            }
            if ($uac -band $ACCOUNTDISABLE) {
                $issues += 'Account is DISABLED (0x2)'
            }
            if ($uac -band $PASSWD_NOTREQD) {
                $issues += 'PASSWD_NOTREQD is set (0x20)'
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName             = $dc.Name
                        UserAccountControl = "0x$($uac.ToString('X'))"
                        Issues             = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}
