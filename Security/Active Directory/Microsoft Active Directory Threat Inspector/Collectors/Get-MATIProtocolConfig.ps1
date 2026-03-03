# Collectors\Get-MATIProtocolConfig.ps1
# MATIv2 - Collects protocol hardening settings from DCs via WinRM/CIM.

function Get-MATIProtocolConfig {
    <#
    .SYNOPSIS
        Reads DC registry/policy settings for LDAP signing, channel binding,
        SMB signing, NTLMv1, LM hash storage, and audit policy.
        Requires WinRM access to domain controllers.
    .OUTPUTS
        [hashtable] with keys: DCProtocolSettings, Errors
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $dcSettings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errors = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domainDns in $forest.Domains) {
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $dcs) {
                $result = [PSCustomObject]@{
                    DCName                 = $dc.Name
                    HostName               = $dc.HostName
                    Domain                 = $domainDns
                    LDAPServerSigning      = $null   # 0=None, 1=Negotiated, 2=Required
                    LDAPChannelBinding     = $null   # 0=Never, 1=WhenSupported, 2=Always
                    SMBServerSigning       = $null   # RequireSecuritySignature: 0 or 1
                    NTLMLevel              = $null   # LmCompatibilityLevel: 0-5
                    NoLMHash               = $null   # NoLMHash: 0 or 1
                    AuditPolicySub         = $null   # Subcategory audit results
                    NetSessionHardened     = $null   # SrvsvcSessionInfo hardened (NetCease)
                    TLS                    = $null   # TLS/Schannel settings hashtable
                    WinRMAccessible        = $false
                }

                try {
                    $regData = Invoke-Command -ComputerName $dc.HostName -ErrorAction Stop -ScriptBlock {
                        $out = @{}

                        # LDAP Server Signing: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' `
                                -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue
                            $out['LDAPServerSigning'] = $v.LDAPServerIntegrity
                        } catch { $out['LDAPServerSigning'] = $null }

                        # LDAP Channel Binding: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' `
                                -Name 'LdapEnforceChannelBinding' -ErrorAction SilentlyContinue
                            $out['LDAPChannelBinding'] = $v.LdapEnforceChannelBinding
                        } catch { $out['LDAPChannelBinding'] = $null }

                        # SMB Server Signing: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' `
                                -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue
                            $out['SMBServerSigning'] = $v.RequireSecuritySignature
                        } catch { $out['SMBServerSigning'] = $null }

                        # NTLM Level: HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' `
                                -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
                            $out['NTLMLevel'] = $v.LmCompatibilityLevel
                        } catch { $out['NTLMLevel'] = $null }

                        # LM Hash storage: HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' `
                                -Name 'NoLMHash' -ErrorAction SilentlyContinue
                            $out['NoLMHash'] = $v.NoLMHash
                        } catch { $out['NoLMHash'] = $null }

                        # Advanced audit policy (quick check for key subcategories)
                        $auditResults = @{}
                        try {
                            $auditPol = & auditpol /get /category:* /r 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
                            foreach ($entry in $auditPol) {
                                $subcat = $entry.'Subcategory'
                                $setting = $entry.'Inclusion Setting'
                                $auditResults[$subcat] = $setting
                            }
                        } catch { }
                        $out['AuditPolicy'] = $auditResults

                        # ---- TLS / Schannel settings ----
                        $tls = @{}
                        $schBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
                        foreach ($ver in @('TLS 1.0','TLS 1.1','TLS 1.2')) {
                            $key = $ver -replace '[\s.]', ''
                            try {
                                $srv = Get-ItemProperty -Path "$schBase\$ver\Server" -ErrorAction SilentlyContinue
                                if ($srv) {
                                    $tls["${key}_Enabled"]           = $srv.Enabled
                                    $tls["${key}_DisabledByDefault"] = $srv.DisabledByDefault
                                }
                            } catch { }
                        }
                        # .NET Strong Crypto (v4)
                        try {
                            $net4 = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -ErrorAction SilentlyContinue
                            $tls['DotNetStrongCrypto']       = $net4.SchUseStrongCrypto
                            $tls['DotNetDefaultTlsVersions'] = $net4.SystemDefaultTlsVersions
                        } catch { }
                        $out['TLS'] = $tls

                        # ---- NetSession enumeration (SrvsvcSessionInfo) ----
                        $netSession = @{ Hardened = $null }
                        try {
                            $lmKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity'
                            $prop = Get-ItemProperty -Path $lmKey -Name 'SrvsvcSessionInfo' -ErrorAction SilentlyContinue
                            if ($prop -and $prop.SrvsvcSessionInfo) {
                                [byte[]]$raw = $prop.SrvsvcSessionInfo
                                # The NetCease hardened template is 176 bytes; check known hardened signature
                                # by verifying Authenticated Users SID (S-1-5-11 = 01 01 00 00 00 00 00 05 0B 00 00 00)
                                # is NOT present in the DACL portion
                                $authUsersSid = [byte[]](1,1,0,0,0,0,0,5,11,0,0,0)
                                $rawStr = [System.BitConverter]::ToString($raw)
                                $sidStr = [System.BitConverter]::ToString($authUsersSid)
                                $netSession['Hardened'] = -not ($rawStr.Contains($sidStr))
                            }
                        } catch { }
                        $out['NetSession'] = $netSession

                        return $out
                    }

                    $result.WinRMAccessible    = $true
                    $result.LDAPServerSigning  = $regData['LDAPServerSigning']
                    $result.LDAPChannelBinding = $regData['LDAPChannelBinding']
                    $result.SMBServerSigning   = $regData['SMBServerSigning']
                    $result.NTLMLevel          = $regData['NTLMLevel']
                    $result.NoLMHash           = $regData['NoLMHash']
                    $result.AuditPolicySub     = $regData['AuditPolicy']
                    $result.NetSessionHardened = $regData['NetSession']?.Hardened
                    $result.TLS                = $regData['TLS']
                }
                catch {
                    $errors.Add([PSCustomObject]@{
                        DCName   = $dc.Name
                        HostName = $dc.HostName
                        Domain   = $domainDns
                        Error    = $_.Exception.Message
                    })
                }

                $dcSettings.Add($result)
            }
        }
        catch {
            Write-Warning "    Cannot query DCs for protocol config in $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        DCProtocolSettings = @($dcSettings)
        Errors             = @($errors)
    }
}
