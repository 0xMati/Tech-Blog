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
                    AuditPolicyReadError   = $null   # Error returned while reading advanced audit policy
                    NetSessionHardened     = $null   # SrvsvcSessionInfo hardened (NetCease)
                    TLS                    = $null   # TLS/Schannel settings hashtable
                    WDigestEnabled         = $null   # UseLogonCredential: 0=disabled, 1=enabled
                    VbsEnabled             = $null   # EnableVirtualizationBasedSecurity: 0=disabled, 1=enabled
                    CredentialGuard        = $null   # LsaCfgFlags: 0=off, 1=with lock, 2=without lock
                    RunAsPPL               = $null   # RunAsPPL: 0=off, 1=enabled with UEFI lock, 2=enabled without UEFI lock
                    KdcArmoring            = $null   # EnableCbacAndArmor: 0=off, 1=supported, 2=always
                    StrongCertificateBindingEnforcement = $null   # KDC strong certificate binding: 0=disabled, 1=compatibility, 2=full
                    CertificateMappingMethods = $null   # Schannel certificate mapping methods bitmask
                    KdcDefaultEncTypes     = $null   # DefaultDomainSupportedEncTypes (Services\Kdc): KDC fallback when account attr unset; null=absent
                    Rc4DisablementPhase    = $null   # RC4DefaultDisablementPhase (KB5073381): 0=silent,1=audit,2=enforce; null=absent
                    DsrmAdminLogonBehavior = $null   # DSRM admin network logon: null/0=console only, 1=when ADWS stopped, 2=always (persistence risk)
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

                        # Advanced audit policy (GUID-based parsing for locale-safe subcategory identification)
                        $auditResults = @{}
                        $auditReadError = $null
                        try {
                            $auditCsv = @(& auditpol /get /subcategory:* /r 2>&1)
                            $auditLines = @($auditCsv | Where-Object { $_ -and $_.Trim() })
                            if ($LASTEXITCODE -ne 0) {
                                $auditReadError = ($auditLines -join ' | ')
                            }
                            elseif ($auditLines.Count -gt 1) {
                                $auditPayload = @($auditLines | Select-Object -Skip 1)
                                $auditPol = @()
                                $validEntries = @()

                                foreach ($delimiter in @(',', ';', "`t")) {
                                    $parsedRows = @($auditPayload |
                                        ConvertFrom-Csv -Delimiter $delimiter -Header 'MachineName','PolicyTarget','Subcategory','SubcategoryGuid','InclusionSetting','ExclusionSetting' -ErrorAction SilentlyContinue)
                                    $candidateEntries = @($parsedRows | Where-Object {
                                        ("$($_.SubcategoryGuid)" -replace '[{}]', '').Trim().ToUpperInvariant() -match '^[0-9A-F-]{36}$'
                                    })

                                    if ($candidateEntries.Count -gt 0) {
                                        $auditPol = $parsedRows
                                        $validEntries = $candidateEntries
                                        break
                                    }
                                }

                                if ($validEntries.Count -eq 0) {
                                    $auditReadError = 'Could not parse auditpol CSV output'
                                }

                                foreach ($entry in $validEntries) {
                                    $guid = ("$($entry.SubcategoryGuid)" -replace '[{}]', '').Trim().ToUpperInvariant()

                                    $auditResults["{$guid}"] = [PSCustomObject]@{
                                        Name             = "$($entry.Subcategory)".Trim()
                                        Guid             = "{$guid}"
                                        InclusionSetting = "$($entry.InclusionSetting)".Trim()
                                        ExclusionSetting = "$($entry.ExclusionSetting)".Trim()
                                    }
                                }
                            } elseif (-not $auditReadError) {
                                $auditReadError = 'auditpol returned no advanced audit policy rows'
                            }
                        } catch { }
                        $out['AuditPolicy'] = $auditResults
                        $out['AuditPolicyReadError'] = $auditReadError

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

                        # ---- WDigest (UseLogonCredential) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                                -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
                            $out['WDigest'] = $v.UseLogonCredential
                        } catch { $out['WDigest'] = $null }

                        # ---- Credential Guard (LsaCfgFlags) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
                                -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue
                            $out['VBSEnabled'] = $v.EnableVirtualizationBasedSecurity
                            $v2 = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                                -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue
                            $out['LsaCfgFlags'] = $v2.LsaCfgFlags
                        } catch { $out['VBSEnabled'] = $null; $out['LsaCfgFlags'] = $null }

                        # ---- LSASS RunAsPPL ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                                -Name 'RunAsPPL' -ErrorAction SilentlyContinue
                            $out['RunAsPPL'] = $v.RunAsPPL
                        } catch { $out['RunAsPPL'] = $null }

                        # ---- KDC Kerberos Armoring (FAST) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' `
                                -Name 'EnableCbacAndArmor' -ErrorAction SilentlyContinue
                            $out['KdcArmoring'] = $v.EnableCbacAndArmor
                        } catch { $out['KdcArmoring'] = $null }

                        # ---- Strong certificate binding / Schannel mapping ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                                -Name 'StrongCertificateBindingEnforcement' -ErrorAction SilentlyContinue
                            $out['StrongCertificateBindingEnforcement'] = $v.StrongCertificateBindingEnforcement
                        } catch { $out['StrongCertificateBindingEnforcement'] = $null }

                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' `
                                -Name 'CertificateMappingMethods' -ErrorAction SilentlyContinue
                            $out['CertificateMappingMethods'] = $v.CertificateMappingMethods
                        } catch { $out['CertificateMappingMethods'] = $null }

                        # ---- KDC default supported enc types (per-DC fallback when account attr unset) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                                -Name 'DefaultDomainSupportedEncTypes' -ErrorAction SilentlyContinue
                            $out['KdcDefaultEncTypes'] = $v.DefaultDomainSupportedEncTypes
                        } catch { $out['KdcDefaultEncTypes'] = $null }

                        # ---- RC4 disablement phase (KB5073381, Jan-Jul 2026) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
                                -Name 'RC4DefaultDisablementPhase' -ErrorAction SilentlyContinue
                            $out['Rc4DisablementPhase'] = $v.RC4DefaultDisablementPhase
                        } catch { $out['Rc4DisablementPhase'] = $null }

                        # ---- DSRM admin logon behavior (persistence: DsrmAdminLogonBehavior=2) ----
                        try {
                            $v = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                                -Name 'DsrmAdminLogonBehavior' -ErrorAction SilentlyContinue
                            $out['DsrmAdminLogonBehavior'] = $v.DsrmAdminLogonBehavior
                        } catch { $out['DsrmAdminLogonBehavior'] = $null }

                        return $out
                    }

                    $result.WinRMAccessible    = $true
                    $result.LDAPServerSigning  = $regData['LDAPServerSigning']
                    $result.LDAPChannelBinding = $regData['LDAPChannelBinding']
                    $result.SMBServerSigning   = $regData['SMBServerSigning']
                    $result.NTLMLevel          = $regData['NTLMLevel']
                    $result.NoLMHash           = $regData['NoLMHash']
                    $result.AuditPolicySub     = $regData['AuditPolicy']
                    $result.AuditPolicyReadError = $regData['AuditPolicyReadError']
                    $result.NetSessionHardened = $regData['NetSession']?.Hardened
                    $result.TLS                = $regData['TLS']
                    $result.WDigestEnabled     = $regData['WDigest']
                    $result.VbsEnabled         = $regData['VBSEnabled']
                    $result.CredentialGuard    = $regData['LsaCfgFlags']
                    $result.RunAsPPL           = $regData['RunAsPPL']
                    $result.KdcArmoring        = $regData['KdcArmoring']
                    $result.StrongCertificateBindingEnforcement = $regData['StrongCertificateBindingEnforcement']
                    $result.CertificateMappingMethods = $regData['CertificateMappingMethods']
                    $result.KdcDefaultEncTypes  = $regData['KdcDefaultEncTypes']
                    $result.Rc4DisablementPhase = $regData['Rc4DisablementPhase']
                    $result.DsrmAdminLogonBehavior = $regData['DsrmAdminLogonBehavior']
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
