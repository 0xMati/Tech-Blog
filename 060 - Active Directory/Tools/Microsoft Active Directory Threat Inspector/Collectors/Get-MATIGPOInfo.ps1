# Collectors\Get-MATIGPOInfo.ps1
# MATIv2 - Collects GPO information and permissions.

function Get-MATIGPOInfo {
    <#
    .SYNOPSIS
        Collects Group Policy Objects, their links, and dangerous ACLs.
    .OUTPUTS
        [hashtable] with keys: GPOs, DangerousGPOPerms, OrphanGPOs
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)

    # Well-known privileged SIDs
    $privilegedSIDs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = Get-MATIDomainSidString (($Config['_DomainCache'][$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
            if (-not $domSID) { continue }
            $null = $privilegedSIDs.Add("$domSID-512")  # Domain Admins
            $null = $privilegedSIDs.Add("$domSID-519")  # Enterprise Admins
            $null = $privilegedSIDs.Add("$domSID-518")  # Schema Admins
        } catch { }
    }
    $null = $privilegedSIDs.Add('S-1-5-32-544')  # Administrators
    $null = $privilegedSIDs.Add('S-1-5-18')       # SYSTEM
    $null = $privilegedSIDs.Add('S-1-5-9')        # Enterprise Domain Controllers
    $null = $privilegedSIDs.Add('S-1-3-0')        # CREATOR OWNER (default ACE)
    $null = $privilegedSIDs.Add('S-1-5-10')       # SELF

    $gpoList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $dangerousPerms = [System.Collections.Generic.List[PSCustomObject]]::new()
    $orphanGPOs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domainDns in $forest.Domains) {
        try {
            # Check if GroupPolicy module is available (it depends on GPMC)
            if (-not (Get-Command Get-GPO -ErrorAction SilentlyContinue)) {
                # Fallback: use AD objects directly
                $domainDN = ($Config['_DomainCache'][$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
                $gpContainer = "CN=Policies,CN=System,$domainDN"
                $gpos = Get-ADObject -SearchBase $gpContainer -Filter { objectClass -eq 'groupPolicyContainer' } `
                    -Server $domainDns -Properties displayName, gPCFileSysPath, flags, whenCreated, whenChanged `
                    -ErrorAction Stop

                foreach ($gpo in $gpos) {
                    $gpoGuid = ($gpo.Name -replace '[{}]', '').ToLower()

                    # Check if GPO is linked anywhere (search for gPLink containing this GUID)
                    $linked = $false
                    try {
                        $linkSearch = Get-ADObject -Filter "gPLink -like '*$gpoGuid*'" -Server $domainDns `
                            -Properties gPLink -ErrorAction SilentlyContinue
                        if ($linkSearch) { $linked = $true }
                    } catch { }

                    $gpoObj = [PSCustomObject]@{
                        DisplayName       = $gpo.displayName
                        GUID              = $gpoGuid
                        DistinguishedName = $gpo.DistinguishedName
                        Domain            = $domainDns
                        IsLinked          = $linked
                        WhenCreated       = $gpo.whenCreated
                        WhenChanged       = $gpo.whenChanged
                    }
                    $gpoList.Add($gpoObj)

                    if (-not $linked) {
                        $orphanGPOs.Add($gpoObj)
                    }

                    # Check GPO ACL for dangerous permissions by low-priv principals
                    try {
                        $acl = Get-MATIObjectAcl -DistinguishedName $gpo.DistinguishedName -Server $domainDns
                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }
                            $sidStr = try {
                                $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            } catch { $ace.IdentityReference.ToString() }

                            if ($privilegedSIDs.Contains($sidStr)) { continue }

                            $rights = $ace.ActiveDirectoryRights.ToString()
                            $isDangerous = $false
                            $rightType = ''

                            if ($rights -match 'GenericAll') {
                                $isDangerous = $true; $rightType = 'GenericAll'
                            }
                            elseif ($rights -match 'GenericWrite|WriteProperty') {
                                $isDangerous = $true; $rightType = 'WriteProperty'
                            }
                            elseif ($rights -match 'WriteDacl') {
                                $isDangerous = $true; $rightType = 'WriteDACL'
                            }
                            elseif ($rights -match 'WriteOwner') {
                                $isDangerous = $true; $rightType = 'WriteOwner'
                            }

                            if ($isDangerous) {
                                $identityName = try {
                                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                                    $sid.Translate([System.Security.Principal.NTAccount]).Value
                                } catch { $sidStr }

                                $dangerousPerms.Add([PSCustomObject]@{
                                    GPOName           = $gpo.displayName
                                    GPOGUID           = $gpoGuid
                                    GPOLinked         = $linked
                                    Domain            = $domainDns
                                    IdentityRef       = $identityName
                                    IdentitySID       = $sidStr
                                    Right             = $rightType
                                    DistinguishedName = $gpo.DistinguishedName
                                })
                            }
                        }
                    } catch { }
                }
            }
            else {
                # Use GroupPolicy module if available
                $gpos = Get-GPO -All -Domain $domainDns -ErrorAction Stop
                $domainDN = ($Config['_DomainCache'][$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName

                foreach ($gpo in $gpos) {
                    $gpoGuid = $gpo.Id.ToString().ToLower()
                    $gpoDN = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"

                    # Check links
                    $linked = $false
                    try {
                        $linkSearch = Get-ADObject -Filter "gPLink -like '*$gpoGuid*'" -Server $domainDns `
                            -Properties gPLink -ErrorAction SilentlyContinue
                        if ($linkSearch) { $linked = $true }
                    } catch { }

                    $gpoObj = [PSCustomObject]@{
                        DisplayName       = $gpo.DisplayName
                        GUID              = $gpoGuid
                        DistinguishedName = $gpoDN
                        Domain            = $domainDns
                        IsLinked          = $linked
                        WhenCreated       = $gpo.CreationTime
                        WhenChanged       = $gpo.ModificationTime
                    }
                    $gpoList.Add($gpoObj)

                    if (-not $linked) {
                        $orphanGPOs.Add($gpoObj)
                    }

                    # Check GPO permissions
                    try {
                        $acl = Get-MATIObjectAcl -DistinguishedName $gpoDN -Server $domainDns
                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }
                            $sidStr = try {
                                $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            } catch { $ace.IdentityReference.ToString() }

                            if ($privilegedSIDs.Contains($sidStr)) { continue }

                            $rights = $ace.ActiveDirectoryRights.ToString()
                            $isDangerous = $false
                            $rightType = ''

                            if ($rights -match 'GenericAll') {
                                $isDangerous = $true; $rightType = 'GenericAll'
                            }
                            elseif ($rights -match 'GenericWrite|WriteProperty') {
                                $isDangerous = $true; $rightType = 'WriteProperty'
                            }
                            elseif ($rights -match 'WriteDacl') {
                                $isDangerous = $true; $rightType = 'WriteDACL'
                            }
                            elseif ($rights -match 'WriteOwner') {
                                $isDangerous = $true; $rightType = 'WriteOwner'
                            }

                            if ($isDangerous) {
                                $identityName = try {
                                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                                    $sid.Translate([System.Security.Principal.NTAccount]).Value
                                } catch { $sidStr }

                                $dangerousPerms.Add([PSCustomObject]@{
                                    GPOName           = $gpo.DisplayName
                                    GPOGUID           = $gpoGuid
                                    GPOLinked         = $linked
                                    Domain            = $domainDns
                                    IdentityRef       = $identityName
                                    IdentitySID       = $sidStr
                                    Right             = $rightType
                                    DistinguishedName = $gpoDN
                                })
                            }
                        }
                    } catch { }
                }
            }
        }
        catch {
            Write-Warning "    Cannot query GPOs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- OU GPO Inheritance (Block Inheritance detection) ----
    $ouInheritance = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($domainDns in $forest.Domains) {
        try {
            # gPOptions attribute: 0 or not set = inherit, 1 = Block Inheritance
            $ous = Get-ADOrganizationalUnit -Filter * -Server $domainDns `
                -Properties gPOptions, Name, DistinguishedName -ErrorAction Stop
            foreach ($ou in $ous) {
                $ouInheritance.Add([PSCustomObject]@{
                    Name              = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    Domain            = $domainDns
                    BlockInheritance  = ($ou.gPOptions -eq 1)
                })
            }
        } catch {
            Write-Verbose "    Cannot query OU inheritance for $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        GPOs             = @($gpoList)
        DangerousGPOPerms = @($dangerousPerms)
        OrphanGPOs       = @($orphanGPOs)
        OUInheritance    = @($ouInheritance)
    }
}
