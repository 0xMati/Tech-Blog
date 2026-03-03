# Rules\Hardening\LegacyDCEncryption.rule.ps1
# Flags DCs not supporting AES encryption.

@{
    Id          = 'MATI-HARD-016'
    Title       = 'Domain Controller does not support AES encryption'
    Severity    = 'High'
    Description = "A Domain Controller does not advertise AES encryption (AES128 or AES256) in its msDS-SupportedEncryptionTypes attribute. This forces the use of weaker RC4 or DES encryption for Kerberos, making tickets vulnerable to offline cracking attacks."
    Remediation = "Ensure DCs run at least Windows Server 2008 R2 (which supports AES natively). Set msDS-SupportedEncryptionTypes to include AES128 (0x8) and AES256 (0x10): Set-ADComputer <DC> -Replace @{'msDS-SupportedEncryptionTypes'=28}"
    Collectors  = @('DCInfo')
    References  = @('PingCastle: S-DC-NotUpdated', 'ANSSI: vuln_dc_encryption')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in $Data.DCInfo) {
            $encTypes = $dc.SupportedEncryptionTypes
            if ($null -eq $encTypes -or $encTypes -eq 0) {
                $findings += @{
                    ObjectDN = $dc.ComputerObjectDN
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName               = $dc.Name
                        OperatingSystem      = "$($dc.OperatingSystem)"
                        SupportedEncryption  = "$encTypes"
                        AESSupported         = 'False'
                    }
                }
            } else {
                # Check if AES128 (0x8) or AES256 (0x10) are present
                $hasAES = ($encTypes -band 0x8) -ne 0 -or ($encTypes -band 0x10) -ne 0
                if (-not $hasAES) {
                    $findings += @{
                        ObjectDN = $dc.ComputerObjectDN
                        Domain   = $dc.Domain
                        Details  = @{
                            DCName               = $dc.Name
                            OperatingSystem      = "$($dc.OperatingSystem)"
                            SupportedEncryption  = "$encTypes"
                            AESSupported         = 'False'
                        }
                    }
                }
            }
        }
        return $findings
    }
}
