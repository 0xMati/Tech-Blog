# Rules\Hardening\NTFRSSysvol.rule.ps1
# Flags domains still using NTFRS for SYSVOL replication.

@{
    Id          = 'MATI-HARD-008'
    Title       = 'SYSVOL replication uses NTFRS instead of DFSR'
    Severity    = 'Medium'
    Description = "SYSVOL is still replicated using NTFRS (File Replication Service) instead of DFSR (Distributed File System Replication). NTFRS is deprecated since Windows Server 2008 R2 and has known reliability issues. Migration to DFSR is required before upgrading to newer Windows Server versions."
    Remediation = "Migrate SYSVOL replication from NTFRS to DFSR using: dfsrmig /setglobalstate 3 (after proper preparation steps)."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: A-NTFRSOnSysvol', 'ANSSI: vuln_sysvol_ntfrs')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($item in $Data.SecurityConfig.SysvolReplication) {
            if ($item.Method -eq 'NTFRS') {
                $findings += @{
                    ObjectDN = $item.Domain
                    Domain   = $item.Domain
                    Details  = @{
                        ReplicationMethod = 'NTFRS'
                        Recommendation    = 'Migrate to DFSR'
                    }
                }
            }
        }
        return $findings
    }
}
