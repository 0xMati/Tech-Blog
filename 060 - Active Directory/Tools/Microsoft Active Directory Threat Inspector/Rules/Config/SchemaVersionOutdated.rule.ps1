# Rules\Config\SchemaVersionOutdated.rule.ps1
# ORADAD: vuln_adupdate_bad
# Flags AD schemas that are not at the latest version for the DC OS.

@{
    Id          = 'MATI-CONFIG-025'
    Title       = 'AD schema version is outdated'
    Severity    = 'Medium'
    Description = "The Active Directory schema version (objectVersion) does not match the latest known version. An outdated schema means adprep /forestprep was not run after upgrading Domain Controllers, preventing new features and security improvements from being available."
    Remediation = "Run 'adprep /forestprep' from the latest Windows Server installation media to update the AD schema. Ensure the account running adprep is a member of Schema Admins, Enterprise Admins, and Domain Admins of the forest root domain."
    Collectors  = @('DomainInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/adprep/adprep-running'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Known schema versions mapped to Windows Server releases
        # https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/adprep/adprep-domainprep
        $schemaVersionMap = [ordered]@{
            91  = 'Windows Server 2025'
            90  = 'Windows Server 2025 Preview'
            88  = 'Windows Server 2022 / 2019'
            87  = 'Windows Server 2016'
            69  = 'Windows Server 2012 R2'
            56  = 'Windows Server 2012'
            47  = 'Windows Server 2008 R2'
            44  = 'Windows Server 2008'
            31  = 'Windows Server 2003 R2'
            30  = 'Windows Server 2003'
        }
        $latestSchema = 91  # Windows Server 2025

        $schemaVersion = $Data.DomainInfo.Forest.SchemaVersion
        if ($null -eq $schemaVersion) { return $findings }

        if ($schemaVersion -lt $latestSchema) {
            $currentOS = $schemaVersionMap.Values | Select-Object -First 1
            foreach ($ver in $schemaVersionMap.Keys) {
                if ($schemaVersion -ge $ver) {
                    $currentOS = $schemaVersionMap[$ver]
                    break
                }
            }

            $sev = if ($schemaVersion -lt 56) { 'High' }         # < 2012
                   elseif ($schemaVersion -lt 87) { 'Medium' }    # < 2016
                   else { 'Low' }

            $findings += @{
                Severity = $sev
                ObjectDN = "Forest: $($Data.DomainInfo.Forest.Name)"
                Domain   = $Data.DomainInfo.Forest.RootDomain
                Details  = @{
                    CurrentSchemaVersion = "$schemaVersion"
                    LatestSchemaVersion  = "$latestSchema"
                    CurrentSchemaOS      = $currentOS
                    LatestSchemaOS       = 'Windows Server 2025'
                }
            }
        }
        return $findings
    }
}
