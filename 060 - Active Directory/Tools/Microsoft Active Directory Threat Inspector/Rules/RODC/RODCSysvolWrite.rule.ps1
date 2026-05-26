# Rules\RODC\RODCSysvolWrite.rule.ps1
# Flags RODCs with write access to SYSVOL replication objects. [PingCastle: P-RODCSYSVOLWrite]

@{
    Id          = 'MATI-RODC-005'
    Title       = 'RODC has write permissions on SYSVOL replication objects'
    Severity    = 'High'
    Description = "A Read-Only Domain Controller (RODC) has write permissions on DFSR/SYSVOL replication objects. RODCs by design should not be able to modify SYSVOL content. If an RODC is compromised (typically deployed in physically insecure locations), write access to SYSVOL allows the attacker to deploy malicious Group Policy logon scripts or other payloads that execute on all domain workstations."
    Remediation = "Review and tighten ACLs on the DFSR-LocalSettings, DFS Replication, and SYSVOL Subscription objects. Ensure RODC computer accounts have only read permissions on SYSVOL replication objects."
    Collectors  = @('ACLInfo', 'DCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/rodc/rodc-filtered-attribute-set')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Identify RODC hostnames
        $rodcDNs = @{}
        foreach ($dc in $Data.DCInfo) {
            if ($dc.IsReadOnly) {
                $rodcDNs[$dc.DistinguishedName.ToLower()] = $dc
                $rodcDNs[$dc.Name.ToLower()] = $dc
            }
        }
        if ($rodcDNs.Count -eq 0) { return $findings }

        # Check DFSR/SYSVOL ACEs for write by RODC accounts
        foreach ($ace in $Data.ACLInfo.DFSRSysvolObjects) {
            $identityName = $ace.IdentityRef.ToLower()
            $isRODC = $false
            $matchedDC = $null
            foreach ($key in $rodcDNs.Keys) {
                if ($identityName -match [regex]::Escape($key)) {
                    $isRODC = $true
                    $matchedDC = $rodcDNs[$key]
                    break
                }
            }
            if ($isRODC -and $ace.Right -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner|WriteAllProperties') {
                $findings += @{
                    ObjectDN = $ace.TargetDN
                    Domain   = $ace.Domain
                    Details  = @{
                        RODCName  = $matchedDC.Name
                        RODCHost  = $matchedDC.HostName
                        Right     = $ace.Right
                        TargetDN  = $ace.TargetDN
                        Issue     = 'RODC has write access to SYSVOL replication objects'
                    }
                }
            }
        }
        return $findings
    }
}
