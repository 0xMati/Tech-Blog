# Rules\GPO\DangerousUserRights.rule.ps1
# Flags dangerous user-rights assignments granted to non-default principals on
# Domain Controllers via GPO (e.g. SeEnableDelegationPrivilege, SeDebugPrivilege).

@{
    Id          = 'MATI-GPO-016'
    Title       = 'Dangerous user-rights assignment granted to non-default principal on DC'
    Severity    = 'High'
    Description = "A high-impact user right (such as SeEnableDelegationPrivilege, SeTcbPrivilege, SeDebugPrivilege, SeBackupPrivilege or SeRestorePrivilege) is granted on Domain Controllers via GPO to a principal that is not one of the expected built-in administrative SIDs. These privileges allow bypassing access controls, reading LSASS memory, configuring delegation, or otherwise escalating to full domain compromise. They should only be held by Administrators and the relevant system accounts."
    Remediation = "Review the listed GPO user-rights assignment and remove the non-default principal from the privilege. Restrict these rights to BUILTIN\\Administrators and the required system accounts only. SeEnableDelegationPrivilege in particular should never be delegated, as it allows configuring Kerberos delegation that leads to credential theft."
    Collectors  = @('GPOSettings')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment',
        'https://www.cert.ssi.gouv.fr/uploads/guide-admin-securisee-si-v3.pdf'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $cfg = $Config.Thresholds.DangerousUserRights
        $dangerous = if ($cfg -and $cfg.Privileges) { @($cfg.Privileges) } else { @(
            'SeEnableDelegationPrivilege','SeTcbPrivilege','SeCreateTokenPrivilege',
            'SeDebugPrivilege','SeLoadDriverPrivilege','SeBackupPrivilege',
            'SeRestorePrivilege','SeTakeOwnershipPrivilege'
        ) }
        $allowed = if ($cfg -and $cfg.AllowedSIDs) { @($cfg.AllowedSIDs) } else { @(
            'S-1-5-18','S-1-5-19','S-1-5-20','S-1-5-9','S-1-5-32-544','S-1-5-32-549','S-1-5-32-551'
        ) }
        $allowedSet = @{}
        foreach ($s in $allowed) { $allowedSet[$s.ToUpperInvariant()] = $true }

        # Best-effort SID -> friendly name resolution for the report.
        $resolve = {
            param($sid)
            try { return ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value }
            catch { return $sid }
        }

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $userRights = $Data.GPOSettings.PerDomain[$domainDns].UserRights
            if (-not $userRights) { continue }

            foreach ($priv in $dangerous) {
                if (-not $userRights.Contains($priv)) { continue }
                $entry = $userRights[$priv]
                $rawValue = if ($entry -is [string]) { $entry } else { $entry.Value }
                $gpoLabel = if ($entry -is [string]) { '(unknown)' } else { $entry.GPO }
                if ([string]::IsNullOrWhiteSpace($rawValue)) { continue }

                foreach ($token in ($rawValue -split ',')) {
                    $t = $token.Trim()
                    if (-not $t) { continue }
                    # GptTmpl.inf prefixes SIDs with '*'.
                    $sid = $t.TrimStart('*')
                    $isSid = $sid -match '^S-1-'

                    if ($isSid -and $allowedSet.ContainsKey($sid.ToUpperInvariant())) { continue }

                    $principal = if ($isSid) { & $resolve $sid } else { $t }

                    $findings += @{
                        ObjectDN = $domainDns
                        Domain   = $domainDns
                        Details  = @{
                            Privilege = $priv
                            Principal = "$principal"
                            SID       = if ($isSid) { $sid } else { '(name)' }
                            GPO       = "$gpoLabel"
                        }
                    }
                }
            }
        }
        return $findings
    }
}
