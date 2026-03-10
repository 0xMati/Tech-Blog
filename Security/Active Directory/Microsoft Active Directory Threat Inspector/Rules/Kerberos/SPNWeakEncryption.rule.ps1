# Rules\Kerberos\SPNWeakEncryption.rule.ps1
# ORADAD: vuln_kerberos_properties_encryption
# Flags service accounts (SPN) with weak or missing encryption types.

@{
    Id          = 'MATI-KERB-010'
    Title       = 'Service account with weak Kerberos encryption type'
    Severity    = 'Medium'
    Description = "A service account with SPN has msDS-SupportedEncryptionTypes set to only allow RC4-HMAC (0x4) or DES (0x1, 0x2, 0x3), or the attribute is not set at all (defaulting to RC4). These weak encryption types are vulnerable to offline brute-force attacks (Kerberoasting). Service accounts should explicitly support AES128 (0x8) and AES256 (0x10)."
    Remediation = "Set msDS-SupportedEncryptionTypes to at least 0x18 (AES128 + AES256) or 0x1C (RC4 + AES128 + AES256) on all service accounts. Test the service to ensure it supports AES before removing RC4. Use: Set-ADUser -Identity <account> -Replace @{'msDS-SupportedEncryptionTypes'=28}"
    Collectors  = @('KerberosConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-supported-encryption-types'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $domainBuckets = @{}

        foreach ($spnAccount in $Data.KerberosConfig.SPNAccounts) {
            if (-not $spnAccount.Enabled) { continue }
            # Skip krbtgt accounts — their encryption is handled by KERB-008
            if ($spnAccount.SamAccountName -like 'krbtgt*') { continue }

            $encTypes = $spnAccount.SupportedEncryptionTypes
            # AES128 = 0x8, AES256 = 0x10
            $hasAES = ($null -ne $encTypes) -and (($encTypes -band 0x18) -ne 0)

            if (-not $hasAES) {
                $encDisplay = if ($null -eq $encTypes) { 'Not set (RC4 default)' } else { "0x$($encTypes.ToString('X'))" }

                $key = $spnAccount.Domain
                if (-not $domainBuckets.ContainsKey($key)) {
                    $domainBuckets[$key] = @{
                        Domain   = $spnAccount.Domain
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $domainBuckets[$key].Count++
                if ($domainBuckets[$key].Examples.Count -lt 10) {
                    $domainBuckets[$key].Examples.Add("$($spnAccount.SamAccountName) ($encDisplay)")
                }
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $sev = if ($bucket.Count -gt 20) { 'High' }
                   elseif ($bucket.Count -gt 5) { 'Medium' }
                   else { 'Low' }
            $findings += @{
                Severity = $sev
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    WeakEncryptionSPNCount = "$($bucket.Count)"
                    Examples               = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}
