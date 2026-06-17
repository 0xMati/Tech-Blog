# Rules\GPO\GPPCPassword.rule.ps1
# Flags Group Policy Preferences files in SYSVOL that contain a cpassword
# attribute (MS14-025). The AES key is public, so the password is recoverable
# by any authenticated user able to read SYSVOL.

@{
    Id          = 'MATI-GPO-015'
    Title       = 'Recoverable password in Group Policy Preferences (cpassword / MS14-025)'
    Severity    = 'Critical'
    Description = "One or more Group Policy Preferences files in SYSVOL contain a 'cpassword' attribute. Microsoft published the static AES-256 key used to encrypt these values (MS14-025), so any authenticated user who can read SYSVOL can decrypt them instantly. These credentials are frequently local administrator or service account passwords, providing a direct lateral-movement and privilege-escalation path."
    Remediation = "Remove the affected Group Policy Preferences items (Local Users/Groups, Services, Scheduled Tasks, Data Sources, Printers, Mapped Drives) that store a cpassword, and delete the cpassword attribute from the XML in SYSVOL. Rotate any password that was stored this way. Use LAPS for local administrator passwords and gMSA/managed service accounts instead of GPP-stored credentials. Install the MS14-025 update which prevents creating new cpassword preferences."
    Collectors  = @('GPPPasswords')
    References  = @(
        'https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025',
        'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($item in $Data.GPPPasswords.Findings) {
            $findings += @{
                ObjectDN = $item.FilePath
                Domain   = $item.Domain
                Details  = @{
                    GPOGuid     = "$($item.GPOGuid)"
                    FileType    = "$($item.FileType)"
                    Element     = "$($item.Element)"
                    AccountName = if ($item.AccountName) { "$($item.AccountName)" } else { '(unknown)' }
                    Recoverable = if ($item.Recoverable) { 'Yes (decrypted with public MS14-025 key)' } else { 'cpassword present' }
                }
            }
        }
        return $findings
    }
}
