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
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    $domCache = $Config['_DomainCache'] ?? @{}

    # Helper: read ACL via a temporary AD PSDrive targeting the correct domain DC
    # This avoids LDAP referral errors when querying child domains.
    function Get-RemoteADACL {
        param([string]$DN, [string]$Server)
        $driveName = "MATITemp_$([guid]::NewGuid().ToString('N').Substring(0,8))"
        try {
            New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "" -Server $Server -ErrorAction Stop | Out-Null
            $acl = Get-ACL -Path "${driveName}:\$DN" -ErrorAction Stop
            return $acl
        }
        finally {
            Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue
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
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
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
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
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

    return @{
        AdminSDHolder     = @($adminSDHolderACEs)
        DomainRoots       = @($domainRootACEs)
        SchemaObjects     = @($schemaACEs)
        ConfigObjects     = @($configACEs)
        DCSyncRights      = @($dcSyncRights)
        Owners            = @($ownerIssues)
    }
}
