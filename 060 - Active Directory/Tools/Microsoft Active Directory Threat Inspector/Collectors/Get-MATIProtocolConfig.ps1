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
                    OSBuildNumber          = $null
                    OSRevision             = $null
                }

                try {
                    $regData = Invoke-Command -ComputerName $dc.HostName -ErrorAction Stop -ScriptBlock {
                        $out = @{}
                        $out.ReadErrors = @()
                        $out.UnreadableValues = @()
                        function Read-MATIRegistryValue {
                            param([string]$Path, [string]$Name)
                            try {
                                $values = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
                                if (-not $Name) { return $values }
                                $property = $values.PSObject.Properties[$Name]
                                if ($property) { return $property.Value }
                            } catch {
                                if ($_.CategoryInfo.Category -ne 'ObjectNotFound') {
                                    $out.ReadErrors += "${Path}\${Name}: $($_.Exception.Message)"
                                    $out.UnreadableValues += $Name
                                }
                            }
                        }
                        $versionPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                        $out.OSBuildNumber = Read-MATIRegistryValue $versionPath 'CurrentBuildNumber'
                        $out.OSRevision = Read-MATIRegistryValue $versionPath 'UBR'

                        # LDAP Server Signing: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity
                        $out.LDAPServerSigning = Read-MATIRegistryValue 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'

                        # LDAP Channel Binding: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding
                        $out.LDAPChannelBinding = Read-MATIRegistryValue 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'

                        # SMB Server Signing: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature
                        $out.SMBServerSigning = Read-MATIRegistryValue 'HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'

                        # NTLM Level: HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
                        $out.NTLMLevel = Read-MATIRegistryValue 'HKLM:\System\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'

                        # LM Hash storage: HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash
                        $out.NoLMHash = Read-MATIRegistryValue 'HKLM:\System\CurrentControlSet\Control\Lsa' 'NoLMHash'

                        # Advanced audit policy (GUID-based parsing for locale-safe subcategory identification)
                        $auditResults = @{}
                        $auditReadError = $null
                        try {
                            $auditCsv = @(& auditpol /get /category:* /r 2>&1)
                            $auditExitCode = $LASTEXITCODE
                            $auditLines = @($auditCsv | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
                            $auditStderr = @($auditCsv | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
                            if ($auditExitCode -ne 0) {
                                $auditReadError = "auditpol exited with code ${auditExitCode}"
                                if ($auditLines.Count -gt 0) { $auditReadError += ': ' + ($auditLines -join ' | ') }
                            }
                            elseif ($auditStderr.Count -gt 0) {
                                $auditReadError = 'auditpol wrote to stderr: ' + (($auditStderr | ForEach-Object { [string]$_ }) -join ' | ')
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
                        } catch { $auditReadError = $_.Exception.Message }
                        $out['AuditPolicy'] = $auditResults
                        $out['AuditPolicyReadError'] = $auditReadError

                        # ---- TLS / Schannel settings ----
                        $tls = @{}
                        $schBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
                        foreach ($ver in @('TLS 1.0','TLS 1.1','TLS 1.2')) {
                            $key = $ver -replace '[\s.]', ''
                            $srv = Read-MATIRegistryValue "$schBase\$ver\Server"
                            if ($srv) {
                                $tls["${key}_Enabled"] = $srv.Enabled
                                $tls["${key}_DisabledByDefault"] = $srv.DisabledByDefault
                            }
                        }
                        # .NET Strong Crypto (v4)
                        $net4 = Read-MATIRegistryValue 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
                        $tls['DotNetStrongCrypto'] = $net4.SchUseStrongCrypto
                        $tls['DotNetDefaultTlsVersions'] = $net4.SystemDefaultTlsVersions
                        $out['TLS'] = $tls

                        # ---- NetSession enumeration (SrvsvcSessionInfo) ----
                        $netSession = @{ Hardened = $null }
                        try {
                            $lmKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity'
                            $sessionBytes = Read-MATIRegistryValue $lmKey 'SrvsvcSessionInfo'
                            if ($sessionBytes) {
                                [byte[]]$raw = $sessionBytes
                                # The NetCease hardened template is 176 bytes; check known hardened signature
                                # by verifying Authenticated Users SID (S-1-5-11 = 01 01 00 00 00 00 00 05 0B 00 00 00)
                                # is NOT present in the DACL portion
                                $authUsersSid = [byte[]](1,1,0,0,0,0,0,5,11,0,0,0)
                                $rawStr = [System.BitConverter]::ToString($raw)
                                $sidStr = [System.BitConverter]::ToString($authUsersSid)
                                $netSession['Hardened'] = -not ($rawStr.Contains($sidStr))
                            }
                        } catch { $out.ReadErrors += "NetSession: $($_.Exception.Message)" }
                        $out['NetSession'] = $netSession

                        # ---- WDigest (UseLogonCredential) ----
                        $out.WDigest = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'

                        # ---- Credential Guard (LsaCfgFlags) ----
                        $out.VBSEnabled = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity'
                        $out.LsaCfgFlags = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags'

                        # ---- LSASS RunAsPPL ----
                        $out.RunAsPPL = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'

                        # ---- KDC Kerberos Armoring (FAST) ----
                        $out.KdcArmoring = Read-MATIRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' 'EnableCbacAndArmor'

                        # ---- Strong certificate binding / Schannel mapping ----
                        $out.StrongCertificateBindingEnforcement = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement'

                        $out.CertificateMappingMethods = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' 'CertificateMappingMethods'

                        # ---- KDC default supported enc types (per-DC fallback when account attr unset) ----
                        $out.KdcDefaultEncTypes = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'DefaultDomainSupportedEncTypes'

                        # ---- RC4 disablement phase (KB5073381, Jan-Jul 2026) ----
                        $out.Rc4DisablementPhase = Read-MATIRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'RC4DefaultDisablementPhase'

                        # ---- DSRM admin logon behavior (persistence: DsrmAdminLogonBehavior=2) ----
                        $out.DsrmAdminLogonBehavior = Read-MATIRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DsrmAdminLogonBehavior'

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
                    $result.OSBuildNumber = $regData.OSBuildNumber
                    $result.OSRevision = $regData.OSRevision
                    $effective = Get-MATIEffectiveKdcSettings -Settings $result
                    if ('StrongCertificateBindingEnforcement' -in $regData.UnreadableValues) {
                        $effective.EffectiveStrongCertificateBinding = 'Unknown'
                    }
                    if ('DefaultDomainSupportedEncTypes' -in $regData.UnreadableValues -or
                        ($null -eq $result.KdcDefaultEncTypes -and 'RC4DefaultDisablementPhase' -in $regData.UnreadableValues)) {
                        $effective.EffectiveKdcEncTypes = $null
                    }
                    $result | Add-Member -NotePropertyMembers $effective
                    foreach ($message in @($regData.ReadErrors) + @($regData.AuditPolicyReadError, $effective.KdcSettingsError) | Where-Object { $_ }) {
                        $errors.Add([pscustomobject]@{ DCName = $dc.Name; HostName = $dc.HostName; Domain = $domainDns; Error = [string]$message })
                    }
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
            $errors.Add([pscustomobject]@{ Domain = $domainDns; Error = $_.Exception.Message })
        }
    }

    return @{
        DCProtocolSettings = @($dcSettings)
        Errors             = @($errors)
    }
}
