# Rules\Config\CriticalObjectsMissing.rule.ps1
# ORADAD: vuln_critical_objects
# Flags missing critical AD containers or well-known groups.

@{
    Id          = 'MATI-CONFIG-027'
    Title       = 'Critical AD object is missing'
    Severity    = 'Critical'
    Description = "A critical well-known AD container or group is missing from the domain. These objects are essential for AD operations and their absence may indicate accidental deletion, a corruption event, or a targeted attack. Missing containers (Users, Computers, System, Builtin, Domain Controllers) can break domain functionality. Missing well-known groups (Domain Admins, Domain Users, etc.) can cause authentication and authorization failures."
    Remediation = "Investigate why the object is missing. If the AD Recycle Bin is enabled, attempt to restore the object. If not, restore from a System State backup. For containers: an authoritative restore may be needed. Contact Microsoft Support if critical domain objects cannot be recovered."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-authoritative-recovery'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($obj in $Data.SecurityConfig.CriticalObjectsStatus) {
            if ($obj.Status -eq 'Missing') {
                $findings += @{
                    ObjectDN = $obj.DistinguishedName
                    Domain   = $obj.Domain
                    Details  = @{
                        MissingObject = $obj.DistinguishedName
                        Status        = 'Missing'
                    }
                }
            }
        }
        return $findings
    }
}
