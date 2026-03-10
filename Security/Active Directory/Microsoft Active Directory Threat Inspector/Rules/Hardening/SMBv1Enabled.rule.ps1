# Rules\Hardening\SMBv1Enabled.rule.ps1
# Flags Domain Controllers with SMBv1 protocol enabled. [PingCastle: S-SMB-v1]

@{
    Id          = 'MATI-HARD-045'
    Title       = 'SMBv1 protocol enabled on Domain Controller'
    Severity    = 'Critical'
    Description = "One or more Domain Controllers have the SMBv1 protocol enabled. SMBv1 is vulnerable to critical exploits such as EternalBlue (MS17-010, WannaCry, NotPetya) and lacks modern security features like encryption, signing negotiation, and pre-authentication integrity. Microsoft deprecated SMBv1 since Windows Server 2016."
    Remediation = "Disable SMBv1 on all Domain Controllers: Set-SmbServerConfiguration -EnableSMB1Protocol `$false. Also disable the SMB1 client and remove the feature: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol."
    Collectors  = @('DCInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3'
        'https://techcommunity.microsoft.com/t5/storage-at-microsoft/stop-using-smb1/ba-p/425858'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.DCInfo) {
            if ($dc.SMB1Enabled -eq $true) {
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName       = $dc.Name
                        HostName     = $dc.HostName
                        SMB1Enabled  = 'True'
                        Issue        = 'SMBv1 is enabled — vulnerable to EternalBlue and other critical exploits'
                    }
                }
            }
        }
        return $findings
    }
}
