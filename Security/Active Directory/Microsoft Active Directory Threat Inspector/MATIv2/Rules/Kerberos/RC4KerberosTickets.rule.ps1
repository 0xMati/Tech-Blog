# Rules\Kerberos\RC4KerberosTickets.rule.ps1
# Fires when RC4-HMAC encrypted Kerberos tickets are observed in
# recent DC event logs (4768 TGT / 4769 TGS).

@{
    Id          = 'MATI-KERB-009'
    Title       = 'RC4-HMAC Kerberos Tickets Detected'
    Severity    = 'High'
    Description = 'Kerberos tickets encrypted with the legacy RC4-HMAC cipher were observed in the Security event logs ' +
                  'of the domain controllers. RC4 is cryptographically weak (equivalent to MD4/MD5 based keys) and ' +
                  'susceptible to offline brute-force and relay attacks. All accounts should be migrated to AES.'
    Remediation = 'Set msDS-SupportedEncryptionTypes = 24 (AES128+AES256) on every account, refresh secrets ' +
                  '(password change / machine password reset; gMSA rotates automatically), and configure ' +
                  'DefaultDomainSupportedEncTypes = 0x18 on all DCs once RC4 traffic reaches 0%. ' +
                  'Reference: KB5021131 / CVE-2022-37966.'
    Collectors  = @('LegacyProtocolAudit')
    References  = @(
        'https://support.microsoft.com/en-us/topic/kb5021131'
        'https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797'
    )

    Condition = {
        param($Data, $Config)
        $audit = $Data['LegacyProtocolAudit']
        if (-not $audit -or -not $audit.Kerberos) { return $null }

        $krb = $audit.Kerberos
        if ($krb.RC4Count -le 0) { return $null }

        $findings = [System.Collections.Generic.List[hashtable]]::new()

        # Global finding with summary
        $severity = if ($krb.RC4Percent -ge 30) { 'Critical' } elseif ($krb.RC4Percent -ge 10) { 'High' } else { 'Medium' }
        $findings.Add(@{
            Severity    = $severity
            Description = "Over the last $($audit.AuditHours) hours, $($krb.RC4Count) out of $($krb.TotalAll) Kerberos tickets " +
                          "used RC4-HMAC encryption ($($krb.RC4Percent)%). Target: 0%."
            Domain      = (Get-ADDomain).DNSRoot
            Details     = @{
                'AES tickets'         = $krb.AESCount
                'RC4 tickets'         = $krb.RC4Count
                'RC4 %'               = "$($krb.RC4Percent)%"
                'RC4 TGT count'       = $krb.Totals.TGT_RC4
                'RC4 TGS count'       = $krb.Totals.TGS_RC4
                'Audit window (hours)' = $audit.AuditHours
            }
        })

        # Per TGT RC4 account
        foreach ($acct in $krb.TopRC4TGTAccounts) {
            $findings.Add(@{
                Severity    = 'High'
                Description = "Account '$($acct.Name)' requested $($acct.Count) TGT(s) encrypted with RC4-HMAC. " +
                              "This typically means the account''s krbtgt key or the account itself only supports RC4."
                ObjectDN    = $acct.Name
                Domain      = (Get-ADDomain).DNSRoot
                Details     = @{ 'Account' = $acct.Name; 'RC4 TGT count' = $acct.Count; 'Type' = 'TGT (4768)' }
            })
        }

        # Per TGS RC4 service
        foreach ($svc in $krb.TopRC4TGSServices) {
            $findings.Add(@{
                Severity    = 'High'
                Description = "Service '$($svc.Name)' received $($svc.Count) service ticket(s) encrypted with RC4-HMAC. " +
                              "Set msDS-SupportedEncryptionTypes = 24 and rotate the service account password."
                ObjectDN    = $svc.Name
                Domain      = (Get-ADDomain).DNSRoot
                Details     = @{ 'Service' = $svc.Name; 'RC4 TGS count' = $svc.Count; 'Type' = 'TGS (4769)' }
            })
        }

        if ($findings.Count -gt 0) { return $findings }
        return $null
    }
}
