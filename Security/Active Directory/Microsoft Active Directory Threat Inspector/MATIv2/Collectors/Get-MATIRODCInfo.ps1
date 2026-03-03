# Collectors\Get-MATIRODCInfo.ps1
# MATIv2 - Collects Read-Only Domain Controller configuration.

function Get-MATIRODCInfo {
    <#
    .SYNOPSIS
        Collects RODC configuration: revealed users, replication groups,
        never-reveal policy, orphan krbtgt accounts.
    .OUTPUTS
        [hashtable] with keys: RODCs, RevealedUsers, AllowedGroup, DeniedGroup, OrphanKrbtgt
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = Get-ADForest -ErrorAction Stop
    $rodcList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $revealedUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allowedGroupIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
    $deniedGroupIssues  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $orphanKrbtgt       = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domainDns in $forest.Domains) {
        try {
            $domObj = Get-ADDomain -Server $domainDns -ErrorAction Stop
            $domSID = $domObj.DomainSID.Value

            # Get RODCs
            $rodcs = Get-ADDomainController -Filter { IsReadOnly -eq $true } -Server $domainDns -ErrorAction SilentlyContinue
            if (-not $rodcs) { continue }

            foreach ($rodc in $rodcs) {
                $rodcList.Add([PSCustomObject]@{
                    Name       = $rodc.Name
                    HostName   = $rodc.HostName
                    Site       = $rodc.Site
                    Domain     = $domainDns
                    ComputerDN = $rodc.ComputerObjectDN
                })

                # msDS-RevealedUsers
                try {
                    $rodcObj = Get-ADComputer -Identity $rodc.ComputerObjectDN -Server $domainDns `
                        -Properties 'msDS-RevealedUsers' -ErrorAction Stop
                    $revealed = @($rodcObj.'msDS-RevealedUsers')
                    foreach ($r in $revealed) {
                        # Parse the DN from the revealed user entry
                        $dn = if ($r -match 'B:(\d+):([^:]*):(.+)') { $Matches[3] } else { $r }
                        try {
                            $user = Get-ADUser -Identity $dn -Server $domainDns `
                                -Properties AdminCount, SamAccountName -ErrorAction Stop
                            if ($user.AdminCount -eq 1) {
                                $revealedUsers.Add([PSCustomObject]@{
                                    RODCName          = $rodc.Name
                                    Domain            = $domainDns
                                    RevealedUser      = $user.SamAccountName
                                    RevealedDN        = $user.DistinguishedName
                                    IsPrivileged      = $true
                                })
                            }
                        } catch { }
                    }
                } catch { }
            }

            # Allowed RODC Password Replication Group
            try {
                $allowedMembers = @(Get-ADGroupMember -Identity 'Allowed RODC Password Replication Group' `
                    -Server $domainDns -ErrorAction Stop)
                foreach ($m in $allowedMembers) {
                    # Check if privileged
                    try {
                        $obj = Get-ADObject -Identity $m.DistinguishedName -Server $domainDns `
                            -Properties AdminCount -ErrorAction Stop
                        if ($obj.AdminCount -eq 1) {
                            $allowedGroupIssues.Add([PSCustomObject]@{
                                Domain          = $domainDns
                                MemberName      = $m.Name
                                MemberDN        = $m.DistinguishedName
                                IsPrivileged    = $true
                            })
                        }
                    } catch { }
                }
            } catch { }

            # Denied RODC Password Replication Group - check if it's been emptied/modified
            try {
                $deniedMembers = @(Get-ADGroupMember -Identity 'Denied RODC Password Replication Group' `
                    -Server $domainDns -ErrorAction Stop)
                # By default should contain: Domain Admins, Enterprise Admins, Schema Admins,
                # Administrators, Account Operators, Server Operators, Backup Operators, krbtgt
                $expectedSIDs = @(
                    "$domSID-512",   # Domain Admins
                    "$domSID-519",   # Enterprise Admins
                    "$domSID-518",   # Schema Admins
                    'S-1-5-32-544',  # Administrators
                    'S-1-5-32-548',  # Account Operators
                    'S-1-5-32-549',  # Server Operators
                    'S-1-5-32-551',  # Backup Operators
                    "$domSID-502"    # krbtgt
                )
                $memberSIDs = @($deniedMembers | ForEach-Object { $_.SID.Value })
                $missingSIDs = @($expectedSIDs | Where-Object { $_ -notin $memberSIDs })
                if ($missingSIDs.Count -gt 0) {
                    $deniedGroupIssues.Add([PSCustomObject]@{
                        Domain      = $domainDns
                        MissingSIDs = $missingSIDs
                        MissingCount = $missingSIDs.Count
                    })
                }
            } catch { }

            # Orphan RODC krbtgt accounts (krbtgt_XXXXX not associated with any RODC)
            try {
                $krbtgtAccounts = Get-ADUser -Filter { SamAccountName -like 'krbtgt_*' } `
                    -Server $domainDns -Properties SamAccountName -ErrorAction Stop
                foreach ($kacct in $krbtgtAccounts) {
                    # Each RODC should have a krbtgt_XXXXX mapped via msDS-KrbTgtLink
                    $isOrphan = $true
                    foreach ($rodc in $rodcs) {
                        try {
                            $rodcComp = Get-ADComputer -Identity $rodc.ComputerObjectDN -Server $domainDns `
                                -Properties 'msDS-KrbTgtLink' -ErrorAction Stop
                            if ($rodcComp.'msDS-KrbTgtLink' -eq $kacct.DistinguishedName) {
                                $isOrphan = $false
                                break
                            }
                        } catch { }
                    }
                    if ($isOrphan) {
                        $orphanKrbtgt.Add([PSCustomObject]@{
                            SamAccountName    = $kacct.SamAccountName
                            DistinguishedName = $kacct.DistinguishedName
                            Domain            = $domainDns
                        })
                    }
                }
            } catch { }

        } catch {
            Write-Warning "    Cannot query RODC info for $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        RODCs              = @($rodcList)
        RevealedPrivileged = @($revealedUsers)
        AllowedGroupIssues = @($allowedGroupIssues)
        DeniedGroupIssues  = @($deniedGroupIssues)
        OrphanKrbtgt       = @($orphanKrbtgt)
    }
}
