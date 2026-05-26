# Rules\Config\GPOOrphan.rule.ps1
# Flags GPOs that exist but are not linked anywhere.

@{
    Id          = 'MATI-CONFIG-018'
    Title       = 'Orphan (unlinked) Group Policy Object'
    Severity    = 'Informational'
    Description = "A Group Policy Object exists but is not linked to any site, domain, or OU. Orphan GPOs increase management complexity and may contain outdated or insecure settings that could be accidentally linked in the future."
    Remediation = "Review unlinked GPOs and either delete them if no longer needed, or link them to the appropriate scope if they should be active."
    Collectors  = @('GPOInfo')
    References  = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/gpo-not-applied')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($gpo in $Data.GPOInfo.OrphanGPOs) {
            $findings += @{
                ObjectDN = $gpo.DistinguishedName
                Domain   = $gpo.Domain
                Details  = @{
                    GPOName     = $gpo.DisplayName
                    GUID        = $gpo.GUID
                    Created     = "$($gpo.WhenCreated)"
                    LastModified = "$($gpo.WhenChanged)"
                }
            }
        }
        return $findings
    }
}
