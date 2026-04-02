[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TargetGroup,

    [Parameter(Mandatory)]
    [ValidateRange(1, 1440)]
    [int]$Minutes,

    [string]$AdminAccount = $env:USERNAME
)

Import-Module ActiveDirectory

$ttl = New-TimeSpan -Minutes $Minutes

$params = @{
    Identity         = $TargetGroup
    Members          = $AdminAccount
    MemberTimeToLive = $ttl
}

Add-ADGroupMember @params

Get-ADGroup -Identity $TargetGroup -Properties member -ShowMemberTimeToLive |
    Select-Object -ExpandProperty member