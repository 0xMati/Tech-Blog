# Rules\GPO\LsassProtectionGPO.rule.ps1
# Flags domains where LSASS protection (RunAsPPL) is not enforced via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-002'
    Title       = 'LSASS protection (RunAsPPL) not enforced via GPO'
    Severity    = 'High'
    Description = "LSASS is not configured as a Protected Process Light (PPL) via Group Policy on Domain Controllers. Without RunAsPPL, credential-dumping tools like Mimikatz can read LSASS memory and extract plaintext passwords, NTLM hashes, and Kerberos tickets."
    Remediation = "Deploy a GPO to the Domain Controllers OU setting HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 (DWORD). Test with audit mode first on Windows Server 2022+."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $runAsPPL = $registryPolicies | Where-Object {
                $_.Key -like '*Control\Lsa' -and $_.ValueName -eq 'RunAsPPL' -and $_.Data -eq 1
            }

            if (-not $runAsPPL) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue       = "RunAsPPL not enforced via GPO"
                        ExpectedKey = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL'
                        ExpectedValue = '1'
                    }
                }
            }
        }
        return $findings
    }
}
