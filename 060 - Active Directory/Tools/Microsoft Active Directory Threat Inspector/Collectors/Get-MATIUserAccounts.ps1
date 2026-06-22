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

    $forest   = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
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
                    LastLogonDate         = $user.LastLogonDate
                    PasswordLastSet       = $user.PasswordLastSet
                    PasswordNeverExpires  = $user.PasswordNeverExpires
                    PasswordNotRequired   = $user.PasswordNotRequired
                    CannotChangePassword  = $user.CannotChangePassword
                    SmartcardLogonRequired = $user.SmartcardLogonRequired
                    AdminCount            = $user.AdminCount
                    WhenCreated           = $user.WhenCreated
                    Description           = $user.Description
                    DisplayName           = $user.DisplayName
                    Name                  = $user.Name
                    UserPrincipalName     = $user.UserPrincipalName
                    SID                   = [string]$user.SID
                    PrimaryGroupID        = $user.PrimaryGroupID
                    SIDHistory            = $user.SIDHistory
                    UserAccountControl    = $user.UserAccountControl
                    # Service-account discovery signals (ADMIN-020)
                    ServicePrincipalName       = @($user.ServicePrincipalName)
                    SupportedEncryptionTypes   = $user.'msDS-SupportedEncryptionTypes'
                    TrustedForDelegation       = $user.TrustedForDelegation
                    TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
                    AllowedToDelegateTo        = @($user.'msDS-AllowedToDelegateTo')
                    # Shadow Credentials
                    KeyCredentialLink     = $user.'msDS-KeyCredentialLink'
                }
            }
        }
        catch {
            Write-Warning "    Cannot query users for $domainDns : $($_.Exception.Message)"
        }
    }

    return @($users)
}
