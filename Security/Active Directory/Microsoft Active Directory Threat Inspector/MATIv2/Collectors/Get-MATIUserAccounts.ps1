# Collectors\Get-MATIUserAccounts.ps1
# MATIv2 - Collects all user accounts (for stale object detection, etc.)

function Get-MATIUserAccounts {
    <#
    .SYNOPSIS
        Collects all user accounts across the forest with key properties.
    .OUTPUTS
        [array] of user objects.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest   = Get-ADForest -ErrorAction Stop
    $userProps = $Config.Collectors.UserProperties

    $users = foreach ($domainDns in $forest.Domains) {
        try {
            $domainUsers = Get-ADUser -Filter * -Server $domainDns -Properties $userProps -ErrorAction Stop
            foreach ($user in $domainUsers) {
                [PSCustomObject]@{
                    SamAccountName        = $user.SamAccountName
                    DistinguishedName     = $user.DistinguishedName
                    Domain                = $domainDns
                    Enabled               = $user.Enabled
                    LastLogonTimestamp     = if ($user.LastLogonTimestamp) {
                        [DateTime]::FromFileTime($user.LastLogonTimestamp)
                    } else { $null }
                    PasswordLastSet       = $user.PasswordLastSet
                    PasswordNeverExpires  = $user.PasswordNeverExpires
                    PasswordNotRequired   = $user.PasswordNotRequired
                    AdminCount            = $user.AdminCount
                    WhenCreated           = $user.WhenCreated
                    Description           = $user.Description
                    SID                   = $user.SID.Value
                }
            }
        }
        catch {
            Write-Warning "    Cannot query users for $domainDns : $($_.Exception.Message)"
        }
    }

    return @($users)
}
