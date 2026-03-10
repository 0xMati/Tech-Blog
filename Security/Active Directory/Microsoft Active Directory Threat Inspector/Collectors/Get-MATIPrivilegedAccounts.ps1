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

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $userProps = $Config.Collectors.UserProperties

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
            $domainSID = (Get-ADDomain -Server $domainDns -ErrorAction Stop).DomainSID.Value
        }
        catch {
            Write-Warning "    Cannot contact domain $domainDns : $($_.Exception.Message)"
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

            # Resolve members with resilient fallback chain
            $members = @()
            try {
                $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Server $domainDns -Recursive -ErrorAction Stop)
            }
            catch {
                Write-Verbose "    Recursive member resolution failed for $($group.Name) in $domainDns, falling back to non-recursive."
                try {
                    $members = @(Get-ADGroupMember -Identity $group.DistinguishedName -Server $domainDns -ErrorAction Stop)
                }
                catch {
                    Write-Warning "    Cannot enumerate members of $($group.Name) in $domainDns : $($_.Exception.Message)"
                    $members = @()
                }
            }

            # Collect direct members for group info (separate protected call)
            $directMembers = @()
            try {
                $directMembers = @(
                    (Get-ADGroupMember -Identity $group.DistinguishedName -Server $domainDns -ErrorAction Stop) |
                    ForEach-Object { $_.DistinguishedName }
                )
            }
            catch {
                $directMembers = @()
            }

            $allGroups.Add([PSCustomObject]@{
                GroupName         = $group.Name
                Domain            = $domainDns
                DistinguishedName = $group.DistinguishedName
                SID               = $group.SID.Value
                MemberCount       = $members.Count
                Description       = $group.Description
                DirectMembers     = $directMembers
            })

            # Collect user accounts (deduplicated across groups)
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user' -and -not $seenUsers.Contains($member.DistinguishedName)) {
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

                        $user = Get-ADUser -Identity $memberDN -Server $memberDomain `
                            -Properties $userProps -ErrorAction Stop

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
                            Description           = $user.Description
                            WhenCreated           = $user.WhenCreated
                            SID                   = $user.SID.Value
                            TrustedForDelegation  = $user.TrustedForDelegation
                            UserAccountControl    = $user.UserAccountControl
                            mail                  = $user.mail
                        })
                    }
                    catch {
                        Write-Warning "    Cannot read user $($member.DistinguishedName): $($_.Exception.Message)"
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
