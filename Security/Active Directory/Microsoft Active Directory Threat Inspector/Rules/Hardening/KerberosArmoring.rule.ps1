# Rules\Hardening\KerberosArmoring.rule.ps1
# Flags DCs where Kerberos armoring (FAST) is not enabled via GPO.

@{
    Id          = 'MATI-HARD-015'
    Title       = 'Kerberos armoring (FAST) not configured on Domain Controller'
    Severity    = 'Medium'
    Description = "Kerberos Flexible Authentication Secure Tunneling (FAST/Armoring) is not enabled on this Domain Controller. Kerberos armoring protects AS-REQ exchanges, preventing offline password attacks and pre-authentication downgrade attacks. The GPO setting 'KDC support for claims, compound authentication and Kerberos armoring' should be set to 'Supported' or 'Always provide claims' on all DCs."
    Remediation = "Configure Kerberos armoring via GPO linked to the Domain Controllers OU: Computer Configuration > Policies > Administrative Templates > System > KDC > KDC support for claims, compound authentication and Kerberos armoring. Set to 'Supported' or 'Always provide claims'. Registry key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\EnableCbacAndArmor = 1 or 2."
    Collectors  = @('ProtocolConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.ProtocolConfig.DCs) {
            if (-not $dc.WinRMAccessible) { continue }
            # KdcArmoring: $null or 0 = not configured, 1 = Supported, 2 = Always
            if (-not $dc.KdcArmoring -or $dc.KdcArmoring -eq 0) {
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName              = $dc.Name
                        EnableCbacAndArmor  = "$(if ($null -eq $dc.KdcArmoring) { 'Not configured' } else { $dc.KdcArmoring })"
                    }
                }
            }
        }
        return $findings
    }
}
