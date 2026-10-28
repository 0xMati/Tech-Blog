# Collectors\Get-MATIPrivilegedAccounts.ps1
# MATIv2 - Collects privileged accounts and groups.

function Get-MATIPrivilegedAccounts {
    <#
    .SYNOPSIS
        Collects members of privileged groups and their properties.
    .OUTPUTS
        [hashtable] with keys: Groups, Accounts
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    function Get-MATIMemberSnapshot {
        param(
            $Member,
            [string]$FallbackDomain
        )

        $distinguishedName = $Member.DistinguishedName
        $memberDomain = $FallbackDomain
        if ($distinguishedName -match '(DC=[^,]+(?:,DC=[^,]+)*)$') {
            $memberDomain = (($Matches[1] -replace 'DC=', '') -replace ',', '.').ToLower()
        }

        $memberSid = $null
        if ($Member.PSObject.Properties['SID'] -and $Member.SID) {
            $memberSid = [string]$Member.SID
        }

        [PSCustomObject]@{
            Name                = $Member.Name
            SamAccountName      = $Member.SamAccountName
            DistinguishedName   = $distinguishedName
            ObjectClass         = $Member.objectClass
            SID                 = $memberSid
            Domain              = $memberDomain
            IsForeignSecurityPrincipal = ($Member.objectClass -eq 'foreignSecurityPrincipal')
            MembershipResolved = if ($Member.PSObject.Properties['MembershipResolved']) { $Member.MembershipResolved } else { $true }
            ExternalResolutionStatus = if ($Member.ExternalResolutionStatus) { $Member.ExternalResolutionStatus }
                elseif ($Member.objectClass -eq 'foreignSecurityPrincipal') { 'ReturnedByADWS' } else { 'NotApplicable' }
            ResolvedName = $Member.ResolvedName
            ResolvedDistinguishedName = $Member.ResolvedDistinguishedName
            ResolvedObjectClass = $Member.ResolvedObjectClass
            ResolutionError = $Member.ResolutionError
            ResolutionAttempts = @($Member.ResolutionAttempts)
            OutsideAssessmentScope = [bool]$Member.OutsideAssessmentScope
        }
    }

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $userProps = @(@($Config.Collectors.UserProperties) + 'msDS-ResultantPSO' | Select-Object -Unique)

    # Well-known privileged group SIDs (relative to domain)
    $privilegedGroupRIDs = @{
        'Domain Admins'       = '-512'
        'Enterprise Admins'   = '-519'
        'Schema Admins'       = '-518'
        'Administrators'      = 'S-1-5-32-544'
        'Account Operators'   = 'S-1-5-32-548'
        'Server Operators'    = 'S-1-5-32-549'
        'Backup Operators'    = 'S-1-5-32-551'
        'Print Operators'     = 'S-1-5-32-550'
    }

    $allGroups   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seenUsers   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($domainDns in $forest.Domains) {
        $domainSID = $null
        try {
            $domainSID = Get-MATIDomainSidString (Get-ADDomain -Server $domainDns -ErrorAction Stop).DomainSID
        }
        catch {
            Write-Warning "    Cannot contact domain $domainDns : $($_.Exception.Message)"
            continue
        }
        if (-not $domainSID) {
            Write-Warning "    Could not resolve domain SID for $domainDns - skipping privileged group enumeration."
            continue
        }

        foreach ($groupName in $privilegedGroupRIDs.Keys) {
            $rid = $privilegedGroupRIDs[$groupName]

            # Build the SID
            if ($rid.StartsWith('S-1-5-32-')) {
                $groupSID = $rid
            } else {
                $groupSID = "$domainSID$rid"
            }

            try {
                $group = Get-ADGroup -Identity $groupSID -Server $domainDns -Properties Members, Description -ErrorAction Stop
            }
            catch {
                # Group may not exist in child domains (e.g., Enterprise Admins only in root)
                continue
            }

            $recursiveResult = @{ Members = @(); Complete = $false; ReadMethod = 'Failed'; UnresolvedMembers = @($group.DistinguishedName) }
            try {
                $recursiveDatasets = @("Groups/Recursive/$groupName", 'Accounts')
                $recursiveResult = Resolve-MATIGroupMembership -Identity $group.DistinguishedName -Server $domainDns -Recursive `
                    -Config $Config -CollectionDatasets $recursiveDatasets -ResolutionDatasets $recursiveDatasets -ErrorAction Stop
            }
            catch {
                Write-Warning "    Cannot enumerate members of $($group.Name) in $domainDns : $($_.Exception.Message)"
            }
            $members = @($recursiveResult.Members)

            $directMembers = @($group.Members | Where-Object { $_ })
            $directMemberDetails = @()
            $directResult = @{ Members = @(); Complete = $false; UnresolvedMembers = @($group.DistinguishedName) }
            try {
                $directResult = Resolve-MATIGroupMembership -Identity $group.DistinguishedName -Server $domainDns `
                    -Config $Config -CollectionDatasets @('Groups/DirectDetails') -ErrorAction Stop
                if (-not $group.PSObject.Properties['Members']) {
                    $directMembers = @($directResult.Members | ForEach-Object { $_.DistinguishedName })
                }
                $directMemberDetails = @($directResult.Members | ForEach-Object { Get-MATIMemberSnapshot -Member $_ -FallbackDomain $domainDns })
            }
            catch {
                Write-Warning "    Cannot resolve direct members of $($group.Name) in $domainDns : $($_.Exception.Message)"
            }

            $memberDetails = @($members | ForEach-Object { Get-MATIMemberSnapshot -Member $_ -FallbackDomain $domainDns })
            $knownMemberCount = @($memberDetails | Where-Object { $_.MembershipResolved -and -not $_.OutsideAssessmentScope }).Count
            $externalMembers = @($memberDetails | Where-Object OutsideAssessmentScope -eq $true)
            $membershipComplete = $recursiveResult.Complete -and $directResult.Complete

            $allGroups.Add([PSCustomObject]@{
                GroupName         = $group.Name
                GroupKey          = $groupName
                Domain            = $domainDns
                DistinguishedName = $group.DistinguishedName
                SID               = [string]$group.SID
                MemberCount       = if ($membershipComplete -and -not $externalMembers.Count) { $members.Count } else { $null }
                KnownMemberCount  = $knownMemberCount
                DirectMemberCount = $directMembers.Count
                MembershipComplete = $membershipComplete
                MembershipScope = 'TargetForest'
                ExternalPrincipalCount = $externalMembers.Count
                ExternalMembers = $externalMembers
                DirectMembershipComplete = [bool]$group.PSObject.Properties['Members']
                LocalMemberObjectsComplete = $directResult.LocalObjectsComplete
                IdentityResolutionComplete = $directResult.Complete -and @($directMemberDetails | Where-Object {
                    $_.IsForeignSecurityPrincipal -and -not $_.ResolvedName -and $_.ExternalResolutionStatus -ne 'Resolved'
                }).Count -eq 0
                RecursiveMembershipComplete = $recursiveResult.Complete
                MembershipReadMethod = $recursiveResult.ReadMethod
                UnresolvedMembers = @(@($recursiveResult.UnresolvedMembers) + @($directResult.UnresolvedMembers) | Select-Object -Unique)
                Description       = $group.Description
                DirectMembers     = $directMembers
                DirectMemberDetails = $directMemberDetails
                MemberDetails     = $memberDetails
            })

            # Collect user accounts (deduplicated across groups)
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user' -and -not $member.OutsideAssessmentScope -and -not $seenUsers.Contains($member.DistinguishedName)) {
                    $null = $seenUsers.Add($member.DistinguishedName)
                    try {
                        # Derive the member's domain from its DN (handles cross-domain membership)
                        $memberDN = $member.DistinguishedName
                        $memberDomain = $domainDns
                        if ($memberDN -match '(DC=[^,]+(?:,DC=[^,]+)*)$') {
                            $dcPart = $Matches[1]
                            $derivedDomain = ($dcPart -replace 'DC=','' -replace ',','.').ToLower()
                            if ($derivedDomain -ne $domainDns.ToLower()) {
                                $memberDomain = $derivedDomain
                            }
                        }

                        if ($memberDomain -notin $forest.Domains) { continue }
                        $user = Get-ADUser -Identity $memberDN -Server $memberDomain `
                            -Properties $userProps -ErrorAction Stop

                        if ($null -eq $user) { throw "No account properties returned for '$memberDN'." }
                        $allAccounts.Add([PSCustomObject]@{
                            SamAccountName        = $user.SamAccountName
                            DistinguishedName     = $user.DistinguishedName
                            Domain                = $memberDomain
                            Enabled               = $user.Enabled
                            PasswordNeverExpires   = $user.PasswordNeverExpires
                            PasswordLastSet       = $user.PasswordLastSet
                            LastLogonTimestamp     = if ($user.LastLogonTimestamp) {
                                [DateTime]::FromFileTime($user.LastLogonTimestamp)
                            } else { $null }
                            AdminCount            = $user.AdminCount
                            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
                            SIDHistory            = @($user.SIDHistory)
                            ServicePrincipalName  = @($user.ServicePrincipalName)
                            MemberOf              = @($user.MemberOf)
                            ResultantPasswordPolicy = $user.'msDS-ResultantPSO'
                            Description           = $user.Description
                            WhenCreated           = $user.WhenCreated
                            SID                   = [string]$user.SID
                            TrustedForDelegation  = $user.TrustedForDelegation
                            UserAccountControl    = $user.UserAccountControl
                            mail                  = $user.mail
                            ScriptPath            = $user.scriptPath
                        })
                    }
                    catch {
                        Write-MATICollectionDiagnostic -Config $Config -Datasets @('Accounts') -HandledError $_ `
                            -Message "    Cannot read user $($member.DistinguishedName): $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    return @{
        Groups   = @($allGroups)
        Accounts = @($allAccounts)
    }
}
