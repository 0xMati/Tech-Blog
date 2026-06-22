# Collectors\Get-MATIACLInfo.ps1
# MATIv2 - Collects ACLs on critical Active Directory objects.

function Get-MATIACLInfo {
    <#
    .SYNOPSIS
        Reads security descriptors on critical AD objects and identifies
        dangerous ACEs granted to non-default principals.
    .OUTPUTS
        [hashtable] with keys: AdminSDHolder, DomainRoots, SchemaObjects,
        DCObjects, GPOPriv, gMSAKeys, NamingContexts, DCSyncRights, Owners
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest  = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $rootDSE = $Config['_RootDSECache'] ?? (Get-ADRootDSE -Server ($Config['_DirectoryServer'] ?? $forest.RootDomain) -ErrorAction Stop)
    $domCache = $Config['_DomainCache'] ?? @{}

    # Helper: read ACL via a temporary AD PSDrive targeting the correct domain DC
    # This avoids LDAP referral errors when querying child domains.
    # When the ActiveDirectory PSProvider is unavailable (e.g. the module is
    # loaded through the Windows PowerShell compatibility layer from a
    # workstation), it transparently falls back to System.DirectoryServices so
    # ACL rules are not silently skipped.
    function Get-RemoteADACL {
        param([string]$DN, [string]$Server)

        # Preferred path: native AD: PSProvider (DC / RSAT host loaded in-process).
        if (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction SilentlyContinue) {
            $driveName = "MATITemp_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            try {
                New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "" -Server $Server -ErrorAction Stop | Out-Null
                if (-not (Test-Path -Path "${driveName}:\$DN")) {
                    throw "Active Directory path not found: $DN"
                }
                $acl = Get-ACL -Path "${driveName}:\$DN" -ErrorAction Stop
                return $acl
            }
            finally {
                Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue
            }
        }

        # Fallback path: read the security descriptor directly via LDAP/ADSI.
        # Returns a System.DirectoryServices.ActiveDirectorySecurity object,
        # the same type Get-DangerousACEs expects.
        $entry = $null
        try {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$DN")
            $null = $entry.RefreshCache(@('nTSecurityDescriptor'))
            $sd = $entry.ObjectSecurity
            if ($null -eq $sd) {
                throw "No security descriptor returned for $DN"
            }
            return $sd
        }
        finally {
            if ($entry) { $entry.Dispose() }
        }
    }

    # Well-known SIDs that are expected to have permissions (not flagged)
    $safeSIDs = @(
        'S-1-5-18',         # SYSTEM
        'S-1-5-32-544',     # Administrators
        'S-1-5-9',          # Enterprise Domain Controllers
        'S-1-3-0',          # Creator Owner
        'S-1-5-10'          # Self
    )

    # Dangerous AD rights that are checked:
    # - GenericAll, WriteDACL, WriteOwner, GenericWrite
    # - DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
    # - DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
    # - AllExtendedRights, WriteAllProperties

    # Helper: resolve SID to a readable name
    function Resolve-SIDName {
        param([string]$SIDString)
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($SIDString)
            $account = $sid.Translate([System.Security.Principal.NTAccount])
            return $account.Value
        }
        catch {
            return $SIDString
        }
    }

    # Helper: check if a SID is a well-known safe principal or domain admin group
    function Test-SafePrincipal {
        param([string]$SIDString, [string[]]$DomainAdminSIDs)
        if ($SIDString -in $safeSIDs) { return $true }
        # Domain/Enterprise Admins
        if ($SIDString -in $DomainAdminSIDs) { return $true }
        return $false
    }

    # Helper: extract dangerous ACEs from an ACL
    function Get-DangerousACEs {
        param(
            [System.DirectoryServices.ActiveDirectorySecurity]$ACL,
            [string[]]$PrivilegedSIDs,
            [string]$ObjectDN
        )
        $results = @()
        foreach ($ace in $ACL.Access) {
            $sid = $ace.IdentityReference
            try {
                $sidObj = $sid.Translate([System.Security.Principal.SecurityIdentifier])
                $sidStr = $sidObj.Value
            }
            catch {
                $sidStr = $sid.ToString()
            }

            if (Test-SafePrincipal -SIDString $sidStr -DomainAdminSIDs $PrivilegedSIDs) { continue }
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $isDangerous = $false
            $rightType = ''

            $rights = $ace.ActiveDirectoryRights.ToString()
            if ($rights -match 'GenericAll') {
                $isDangerous = $true; $rightType = 'GenericAll'
            }
            elseif ($rights -match 'WriteDacl') {
                $isDangerous = $true; $rightType = 'WriteDACL'
            }
            elseif ($rights -match 'WriteOwner') {
                $isDangerous = $true; $rightType = 'WriteOwner'
            }
            elseif ($rights -match 'GenericWrite') {
                $isDangerous = $true; $rightType = 'GenericWrite'
            }
            elseif ($rights -match 'ExtendedRight') {
                $objectType = $ace.ObjectType.ToString().ToLower()
                if ($objectType -eq '00000000-0000-0000-0000-000000000000') {
                    $isDangerous = $true; $rightType = 'AllExtendedRights'
                }
                elseif ($objectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') {
                    $isDangerous = $true; $rightType = 'DS-Replication-Get-Changes'
                }
                elseif ($objectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
                    $isDangerous = $true; $rightType = 'DS-Replication-Get-Changes-All'
                }
            }
            elseif ($rights -match 'WriteProperty') {
                $objectType = $ace.ObjectType.ToString().ToLower()
                if ($objectType -eq '00000000-0000-0000-0000-000000000000') {
                    $isDangerous = $true; $rightType = 'WriteAllProperties'
                }
            }

            if ($isDangerous) {
                $results += [PSCustomObject]@{
                    TargetDN        = $ObjectDN
                    IdentityRef     = $sid.ToString()
                    IdentitySID     = $sidStr
                    Right           = $rightType
                    ADRights        = $rights
                    InheritanceType = $ace.InheritanceType.ToString()
                    IsInherited     = $ace.IsInherited
                }
            }
        }
        return $results
    }

    # Collect domain SIDs for privileged groups
    $privilegedSIDs = [System.Collections.Generic.List[string]]::new()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = Get-MATIDomainSidString (($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
            if (-not $domSID) { continue }
            $privilegedSIDs.Add("$domSID-512")  # Domain Admins
            $privilegedSIDs.Add("$domSID-519")  # Enterprise Admins
            $privilegedSIDs.Add("$domSID-518")  # Schema Admins
            $privilegedSIDs.Add("$domSID-516")  # Domain Controllers
            $privilegedSIDs.Add("$domSID-498")  # Enterprise Read-Only DCs
        } catch { }
    }
    $privSIDArray = @($privilegedSIDs)

    # ---- AdminSDHolder ----
    $adminSDHolderACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
            $acl = Get-RemoteADACL -DN $adminSDHolderDN -Server $domainDns
            $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $adminSDHolderDN
            foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
            $adminSDHolderACEs += $aces
        } catch {
            Write-Warning "    Cannot read AdminSDHolder ACL for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Domain Root (DCSync rights) ----
    $dcSyncRights = @()
    $domainRootACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $acl = Get-RemoteADACL -DN $domainDN -Server $domainDns
            $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $domainDN
            foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
            $domainRootACEs += $aces

            # Specific DCSync check: both Get-Changes + Get-Changes-All to same principal
            $replACEs = @{}
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                if ($rights -notmatch 'ExtendedRight') { continue }
                $objectType = $ace.ObjectType.ToString().ToLower()
                $sidStr = try {
                    $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch { $ace.IdentityReference.ToString() }
                if (Test-SafePrincipal -SIDString $sidStr -DomainAdminSIDs $privSIDArray) { continue }

                if ($objectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or
                    $objectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
                    if (-not $replACEs.ContainsKey($sidStr)) { $replACEs[$sidStr] = @() }
                    $replACEs[$sidStr] += $objectType
                }
            }
            foreach ($sid in $replACEs.Keys) {
                $guids = $replACEs[$sid]
                if (($guids -contains '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -and
                    ($guids -contains '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) {
                    $dcSyncRights += [PSCustomObject]@{
                        IdentitySID = $sid
                        IdentityRef = Resolve-SIDName -SIDString $sid
                        Domain      = $domainDns
                        TargetDN    = $domainDN
                    }
                }
            }
        } catch {
            Write-Warning "    Cannot read domain root ACL for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Schema container ----
    $schemaACEs = @()
    try {
        $schemaDN = $rootDSE.schemaNamingContext
        $acl = Get-RemoteADACL -DN $schemaDN -Server $forest.RootDomain
        $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $schemaDN
        foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $forest.RootDomain -Force }
        $schemaACEs = $aces
    } catch {
        Write-Warning "    Cannot read Schema ACL: $($_.Exception.Message)"
    }

    # ---- Configuration container ----
    $configACEs = @()
    try {
        $configDN = $rootDSE.configurationNamingContext
        $acl = Get-RemoteADACL -DN $configDN -Server $forest.RootDomain
        $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $configDN
        foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $forest.RootDomain -Force }
        $configACEs = $aces
    } catch {
        Write-Warning "    Cannot read Configuration ACL: $($_.Exception.Message)"
    }

    # ---- Critical object owners ----
    $ownerIssues = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = Get-MATIDomainSidString (($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName

            # Check DC objects ownership
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $dcs) {
                try {
                    $acl = Get-RemoteADACL -DN $dc.ComputerObjectDN -Server $domainDns
                    $ownerSID = try {
                        $acl.Owner
                        $ownerObj = New-Object System.Security.Principal.NTAccount($acl.Owner)
                        $ownerObj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch { '' }

                    $isOK = ($ownerSID -eq "$domSID-512") -or    # Domain Admins
                            ($ownerSID -eq "$domSID-519") -or    # Enterprise Admins
                            ($ownerSID -eq 'S-1-5-32-544') -or   # Administrators
                            ($ownerSID -eq 'S-1-5-18')           # SYSTEM

                    if (-not $isOK) {
                        $ownerIssues += [PSCustomObject]@{
                            ObjectDN    = $dc.ComputerObjectDN
                            ObjectType  = 'DomainController'
                            Owner       = $acl.Owner
                            OwnerSID    = $ownerSID
                            Domain      = $domainDns
                        }
                    }
                } catch { }
            }

            # Check AdminSDHolder ownership
            try {
                $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
                $acl = Get-RemoteADACL -DN $adminSDHolderDN -Server $domainDns
                $ownerSID = try {
                    (New-Object System.Security.Principal.NTAccount($acl.Owner)).Translate(
                        [System.Security.Principal.SecurityIdentifier]).Value
                } catch { '' }
                $isOK = ($ownerSID -eq "$domSID-512") -or ($ownerSID -eq 'S-1-5-32-544') -or ($ownerSID -eq 'S-1-5-18')
                if (-not $isOK) {
                    $ownerIssues += [PSCustomObject]@{
                        ObjectDN    = $adminSDHolderDN
                        ObjectType  = 'AdminSDHolder'
                        Owner       = $acl.Owner
                        OwnerSID    = $ownerSID
                        Domain      = $domainDns
                    }
                }
            } catch { }
        } catch {
            Write-Warning "    Cannot check owners for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- DC Computer Object ACLs (vuln_permissions_dc) ----
    $dcObjectACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $dcs) {
                try {
                    $acl = Get-RemoteADACL -DN $dc.ComputerObjectDN -Server $domainDns
                    $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $dc.ComputerObjectDN
                    foreach ($a in $aces) {
                        $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force
                        $a | Add-Member -NotePropertyName 'DCName' -NotePropertyValue $dc.Name -Force
                    }
                    $dcObjectACEs += $aces
                } catch { }
            }
        } catch {
            Write-Warning "    Cannot read DC object ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- DFSR SYSVOL Object ACLs (vuln_permissions_dfsr_sysvol) ----
    $dfsrSysvolACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # DFSR Global Settings — Domain System Volume
            $dfsrDN = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN"
            try {
                $acl = Get-RemoteADACL -DN $dfsrDN -Server $domainDns
                $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $dfsrDN
                foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
                $dfsrSysvolACEs += $aces
            } catch { }
            # SYSVOL Subscription object
            $sysvolSubDN = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN"
            try {
                $sysvolSubscription = Get-ADObject -Identity $sysvolSubDN -Server $domainDns -ErrorAction SilentlyContinue
                if ($sysvolSubscription) {
                    $acl = Get-RemoteADACL -DN $sysvolSubDN -Server $domainDns
                    $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $sysvolSubDN
                    foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
                    $dfsrSysvolACEs += $aces
                }
            } catch { }
            # Per-DC DFSR-LocalSettings
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction SilentlyContinue
            foreach ($dc in $dcs) {
                $localDN = "CN=DFSR-LocalSettings,$($dc.ComputerObjectDN)"
                try {
                    $acl = Get-RemoteADACL -DN $localDN -Server $domainDns
                    $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $localDN
                    foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
                    $dfsrSysvolACEs += $aces
                } catch { }
            }
        } catch {
            Write-Warning "    Cannot read DFSR SYSVOL ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- DPAPI Backup Key ACLs (vuln_permissions_dpapi) ----
    $dpapiACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # DPAPI domain backup keys: CN=BCKUPKEY_* under CN=System
            $bckupKeys = Get-ADObject -SearchBase "CN=System,$domainDN" -Filter { Name -like 'BCKUPKEY_*' } `
                -Server $domainDns -ErrorAction SilentlyContinue
            foreach ($key in $bckupKeys) {
                try {
                    $acl = Get-RemoteADACL -DN $key.DistinguishedName -Server $domainDns
                    $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $key.DistinguishedName
                    foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
                    $dpapiACEs += $aces
                } catch { }
            }
        } catch {
            Write-Warning "    Cannot read DPAPI ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- MicrosoftDNS Container ACLs (vuln_permissions_msdns) ----
    $dnsACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # DomainDnsZones partition
            $dnsDN = "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
            try {
                $acl = Get-RemoteADACL -DN $dnsDN -Server $domainDns
                $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $dnsDN
                foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force }
                $dnsACEs += $aces
            } catch { }
        } catch {
            Write-Warning "    Cannot read DNS ACLs for $domainDns : $($_.Exception.Message)"
        }
    }
    # ForestDnsZones (checked once for forest root)
    try {
        $forestDN = ($domCache[$forest.RootDomain] ?? (Get-ADDomain -Server $forest.RootDomain -ErrorAction Stop)).DistinguishedName
        $forestDnsDN = "CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN"
        $acl = Get-RemoteADACL -DN $forestDnsDN -Server $forest.RootDomain
        $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $forestDnsDN
        foreach ($a in $aces) { $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $forest.RootDomain -Force }
        $dnsACEs += $aces
    } catch { }

    # ---- GPOs linked to Domain Controllers OU (vuln_permissions_gpo_container_priv) ----
    $gpoPrivACEs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $dcOU = "OU=Domain Controllers,$domainDN"
            $gpLink = (Get-ADObject -Identity $dcOU -Server $domainDns -Properties gPLink -ErrorAction Stop).gPLink
            if ($gpLink) {
                # Parse gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;status]
                $gpoDNs = [regex]::Matches($gpLink, '\[LDAP://([^;]+);\d+\]') | ForEach-Object { $_.Groups[1].Value }
                foreach ($gpoDN in $gpoDNs) {
                    try {
                        $gpoName = (Get-ADObject -Identity $gpoDN -Server $domainDns -Properties DisplayName -ErrorAction SilentlyContinue).DisplayName
                        $acl = Get-RemoteADACL -DN $gpoDN -Server $domainDns
                        $aces = Get-DangerousACEs -ACL $acl -PrivilegedSIDs $privSIDArray -ObjectDN $gpoDN
                        foreach ($a in $aces) {
                            $a | Add-Member -NotePropertyName 'Domain' -NotePropertyValue $domainDns -Force
                            $a | Add-Member -NotePropertyName 'LinkedTo' -NotePropertyValue $dcOU -Force
                            $a | Add-Member -NotePropertyName 'GPOName' -NotePropertyValue $gpoName -Force
                        }
                        $gpoPrivACEs += $aces
                    } catch { }
                }
            }
        } catch {
            Write-Warning "    Cannot read GPO ACLs for privileged OUs in $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Exchange-specific ACEs on AdminSDHolder and Domain Root ----
    # Tags any ACE where the identity matches a known Exchange group
    $exchangeACEs = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = Get-MATIDomainSidString (($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # Build a set of Exchange-related group names and SIDs
            $exchangeSIDs = @{}
            $exchangeGroupNames = @(
                'Exchange Windows Permissions', 'Exchange Trusted Subsystem',
                'Exchange Servers', 'Organization Management'
            )
            foreach ($gn in $exchangeGroupNames) {
                try {
                    $g = Get-ADGroup -Filter "Name -eq '$gn'" -Server $domainDns -Properties objectSid -ErrorAction SilentlyContinue
                    if ($g) { $exchangeSIDs[[string]$g.SID] = $gn }
                } catch { }
            }
            if ($exchangeSIDs.Count -eq 0) { continue }

            # Check Domain Root ACL for Exchange WriteDACL
            $domainRootACL = Get-RemoteADACL -DN $domainDN -Server $domainDns
            foreach ($ace in $domainRootACL.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sidStr = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                if (-not $exchangeSIDs.ContainsKey($sidStr)) { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                $isDangerous = $rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights'
                if ($isDangerous) {
                    $exchangeACEs.Add([PSCustomObject]@{
                        TargetDN    = $domainDN
                        TargetType  = 'DomainRoot'
                        IdentityRef = $exchangeSIDs[$sidStr]
                        IdentitySID = $sidStr
                        Right       = ($rights -split ',' | Where-Object { $_ -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights' }) -join ', '
                        Domain      = $domainDns
                    })
                }
            }

            # Check AdminSDHolder ACL for Exchange
            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
            try {
                $asdACL = Get-RemoteADACL -DN $adminSDHolderDN -Server $domainDns
                foreach ($ace in $asdACL.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $sidStr = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                    if (-not $exchangeSIDs.ContainsKey($sidStr)) { continue }
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $isDangerous = $rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights'
                    if ($isDangerous) {
                        $exchangeACEs.Add([PSCustomObject]@{
                            TargetDN    = $adminSDHolderDN
                            TargetType  = 'AdminSDHolder'
                            IdentityRef = $exchangeSIDs[$sidStr]
                            IdentitySID = $sidStr
                            Right       = ($rights -split ',' | Where-Object { $_ -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|AllExtendedRights' }) -join ', '
                            Domain      = $domainDns
                        })
                    }
                }
            } catch { }
        } catch {
            Write-Warning "    Cannot check Exchange ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Key Admins group dangerous permissions ----
    $keyAdminACEs = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = Get-MATIDomainSidString (($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
            if (-not $domSID) { continue }
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # Key Admins = domSID-526, Enterprise Key Admins = rootDomSID-527
            $keyAdminSIDs = @{}
            foreach ($rid in @('526', '527')) {
                $testSID = "$domSID-$rid"
                try {
                    $g = Get-ADGroup -Identity $testSID -Server $domainDns -ErrorAction SilentlyContinue
                    if ($g) { $keyAdminSIDs[$testSID] = $g.Name }
                } catch { }
            }
            if ($keyAdminSIDs.Count -eq 0) { continue }

            # Check domain root for Key Admin ACEs with msDS-KeyCredentialLink write
            $acl = Get-RemoteADACL -DN $domainDN -Server $domainDns
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $sidStr = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                if (-not $keyAdminSIDs.ContainsKey($sidStr)) { continue }
                $rights = $ace.ActiveDirectoryRights.ToString()
                # GenericAll or WriteProperty for msDS-KeyCredentialLink
                if ($rights -match 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner') {
                    $keyAdminACEs.Add([PSCustomObject]@{
                        TargetDN    = $domainDN
                        IdentityRef = $keyAdminSIDs[$sidStr]
                        IdentitySID = $sidStr
                        Right       = $rights
                        Domain      = $domainDns
                    })
                }
            }
        } catch {
            Write-Warning "    Cannot check Key Admin ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- DNS Zone CreateChild by Authenticated Users ----
    $dnsZoneCreateChild = [System.Collections.Generic.List[PSCustomObject]]::new()
    $authUsersSID = 'S-1-5-11'  # Authenticated Users
    $everyoneSID  = 'S-1-1-0'   # Everyone
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $dnsPartitions = @(
                "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
            )
            foreach ($dnsBaseDN in $dnsPartitions) {
                try {
                    $zones = Get-ADObject -SearchBase $dnsBaseDN -Filter { objectClass -eq 'dnsZone' } `
                        -Server $domainDns -ErrorAction SilentlyContinue
                    foreach ($zone in @($zones)) {
                        if ($null -eq $zone) { continue }
                        try {
                            $acl = Get-RemoteADACL -DN $zone.DistinguishedName -Server $domainDns
                            foreach ($ace in $acl.Access) {
                                if ($ace.AccessControlType -ne 'Allow') { continue }
                                $sidStr = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
                                if ($sidStr -ne $authUsersSID -and $sidStr -ne $everyoneSID) { continue }
                                $rights = $ace.ActiveDirectoryRights.ToString()
                                if ($rights -match 'CreateChild|GenericAll|GenericWrite') {
                                    $dnsZoneCreateChild.Add([PSCustomObject]@{
                                        ZoneDN      = $zone.DistinguishedName
                                        ZoneName    = $zone.Name
                                        IdentitySID = $sidStr
                                        IdentityRef = if ($sidStr -eq $authUsersSID) { 'Authenticated Users' } else { 'Everyone' }
                                        Right       = $rights
                                        Domain      = $domainDns
                                    })
                                }
                            }
                        } catch { }
                    }
                } catch { }
            }
        } catch {
            Write-Warning "    Cannot check DNS zone ACLs for $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        AdminSDHolder     = @($adminSDHolderACEs)
        DomainRoots       = @($domainRootACEs)
        SchemaObjects     = @($schemaACEs)
        ConfigObjects     = @($configACEs)
        DCSyncRights      = @($dcSyncRights)
        Owners            = @($ownerIssues)
        DCObjects         = @($dcObjectACEs)
        DFSRSysvolObjects = @($dfsrSysvolACEs)
        DPAPIObjects      = @($dpapiACEs)
        DNSObjects        = @($dnsACEs)
        GPOPrivilegedOUs  = @($gpoPrivACEs)
        ExchangeACEs      = @($exchangeACEs)
        KeyAdminACEs      = @($keyAdminACEs)
        DnsZoneCreateChild = @($dnsZoneCreateChild)
    }
}
