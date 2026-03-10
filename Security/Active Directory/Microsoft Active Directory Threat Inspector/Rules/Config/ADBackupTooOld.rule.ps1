# Rules\Config\ADBackupTooOld.rule.ps1
# Flags domains with old or missing AD backup. [PingCastle: A-BackupMetadata]

@{
    Id          = 'MATI-CONFIG-031'
    Title       = 'AD backup too old or never performed'
    Severity    = 'High'
    Description = "The Active Directory backup metadata indicates that no backup has been performed recently or the backup date is older than the tombstone lifetime. Without regular backups, disaster recovery may be impossible, especially for ransomware or catastrophic failure scenarios."
    Remediation = "Implement a regular AD backup schedule using Windows Server Backup or a supported third-party tool. Ensure backups are taken more frequently than the tombstone lifetime (default 180 days)."
    Collectors  = @('SecurityConfig', 'DomainInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-backing-up-a-full-server')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $tombstoneLifetime = $Data.DomainInfo.Forest.TombstoneLifetime
        if (-not $tombstoneLifetime) { $tombstoneLifetime = 180 }

        foreach ($backup in $Data.SecurityConfig.BackupMetadata) {
            if ($backup.BackupAgeDays -eq -1) {
                # No backup timestamp found
                $findings += @{
                    ObjectDN = $backup.Domain
                    Domain   = $backup.Domain
                    Details  = @{
                        LastBackup = 'Never or unknown'
                        Issue      = 'No AD backup metadata found (msDS-LastBackupRestoreTime is empty)'
                    }
                }
            }
            elseif ($backup.BackupAgeDays -gt $tombstoneLifetime) {
                $findings += @{
                    ObjectDN = $backup.Domain
                    Domain   = $backup.Domain
                    Details  = @{
                        LastBackupRestoreTime = "$($backup.LastBackupRestoreTime)"
                        BackupAgeDays         = $backup.BackupAgeDays
                        TombstoneLifetime     = $tombstoneLifetime
                        Issue                 = "Backup is older than tombstone lifetime ($tombstoneLifetime days)"
                    }
                }
            }
        }
        return $findings
    }
}
