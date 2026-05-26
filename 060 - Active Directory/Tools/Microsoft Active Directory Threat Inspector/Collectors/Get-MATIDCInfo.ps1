# Collectors\Get-MATIDCInfo.ps1
# MATIv2 - Collects Domain Controller information.

function Get-MATIDCInfo {
    <#
    .SYNOPSIS
        Collects domain controller details across the forest.
    .OUTPUTS
        [array] of DC objects.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $directoryServer = $Config['_DirectoryServer'] ?? $forest.RootDomain
    $rootDSE = $Config['_RootDSECache'] ?? (Get-ADRootDSE -Server $directoryServer -ErrorAction Stop)

    # Pre-load all AD subnets for site coverage check
    $adSubnets = @{}
    try {
        $subnets = Get-ADObject -SearchBase "CN=Subnets,CN=Sites,$($rootDSE.configurationNamingContext)" `
            -Filter { objectClass -eq 'subnet' } -Server $directoryServer -Properties siteObject, cn -ErrorAction SilentlyContinue
        foreach ($s in $subnets) {
            $siteName = if ($s.siteObject) { ($s.siteObject -split ',')[0] -replace '^CN=' } else { 'Unlinked' }
            if (-not $adSubnets.ContainsKey($siteName)) { $adSubnets[$siteName] = @() }
            $adSubnets[$siteName] += $s.cn
        }
    } catch { }

    $dcs = foreach ($domainDns in $forest.Domains) {
        try {
            $domainDCs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $domainDCs) {
                # Get computer object for additional properties
                $dcComputer = Get-ADComputer $dc.Name -Server $domainDns -Properties `
                    OperatingSystem, OperatingSystemVersion, PasswordLastSet, `
                    'msDS-SupportedEncryptionTypes', UserAccountControl, WhenCreated -ErrorAction SilentlyContinue

                # Read SMBv1 and RefusePasswordChange registry settings
                $smb1Enabled = $null
                $refusePasswordChange = $null
                try {
                    $smbReg = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                        $smb1 = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
                        $refuse = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
                            -Name 'RefusePasswordChange' -ErrorAction SilentlyContinue).RefusePasswordChange
                        @{ SMB1 = $smb1; Refuse = $refuse }
                    } -ErrorAction SilentlyContinue
                    $smb1Enabled = $smbReg.SMB1
                    $refusePasswordChange = $smbReg.Refuse
                } catch { }

                [PSCustomObject]@{
                    Name                        = $dc.Name
                    HostName                    = $dc.HostName
                    Domain                      = $domainDns
                    Site                        = $dc.Site
                    IPv4Address                 = $dc.IPv4Address
                    OperatingSystem             = $dcComputer.OperatingSystem
                    OperatingSystemVersion      = $dcComputer.OperatingSystemVersion
                    IsGlobalCatalog             = $dc.IsGlobalCatalog
                    IsReadOnly                  = $dc.IsReadOnly
                    OperationMasterRoles        = $dc.OperationMasterRoles
                    PasswordLastSet             = $dcComputer.PasswordLastSet
                    PasswordAgeDays             = if ($dcComputer.PasswordLastSet) {
                        [math]::Round(((Get-Date) - $dcComputer.PasswordLastSet).TotalDays)
                    } else { 9999 }
                    SupportedEncryptionTypes    = $dcComputer.'msDS-SupportedEncryptionTypes'
                    DistinguishedName           = $dc.ComputerObjectDN
                    WhenCreated                 = $dcComputer.WhenCreated
                    UserAccountControl          = $dcComputer.UserAccountControl
                    SiteHasSubnets              = ($adSubnets.ContainsKey($dc.Site) -and $adSubnets[$dc.Site].Count -gt 0)
                    SiteSubnetCount             = if ($adSubnets.ContainsKey($dc.Site)) { $adSubnets[$dc.Site].Count } else { 0 }
                    SMB1Enabled                 = $smb1Enabled
                    RefusePasswordChange        = $refusePasswordChange
                }
            }
        }
        catch {
            Write-Warning "    Cannot query DCs for $domainDns : $($_.Exception.Message)"
        }
    }

    return @($dcs)
}
