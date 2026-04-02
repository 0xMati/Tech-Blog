[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RequestPath,

    [string]$PolicyPath = (Join-Path -Path $PSScriptRoot -ChildPath 'JitBrokerPolicy.psd1')
)

Import-Module ActiveDirectory

$request = Get-Content -Path $RequestPath -Raw | ConvertFrom-Json
$policy = Import-PowerShellDataFile -Path $PolicyPath

if ($request.ApprovalState -ne 'Approved') {
    throw 'Request is not approved'
}

if (-not $policy.AllowedGroups.ContainsKey($request.Requester)) {
    throw "Requester not authorized: $($request.Requester)"
}

$allowedGroups = $policy.AllowedGroups[$request.Requester]
if ($request.TargetGroup -notin $allowedGroups) {
    throw "Requester $($request.Requester) cannot request group $($request.TargetGroup)"
}

if (-not $policy.MaxTtlByGroup.ContainsKey($request.TargetGroup)) {
    throw "Target group not managed by the broker: $($request.TargetGroup)"
}

$approvedMinutes = [Math]::Min(
    [int]$request.RequestedMinutes,
    [int]$policy.MaxTtlByGroup[$request.TargetGroup]
)

$ttl = New-TimeSpan -Minutes $approvedMinutes

$params = @{
    Identity         = $request.TargetGroup
    Members          = $request.Requester
    MemberTimeToLive = $ttl
}

Add-ADGroupMember @params

$logDirectory = Split-Path -Path $policy.LogPath -Parent
if ($logDirectory -and -not (Test-Path -Path $logDirectory)) {
    New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
}

[pscustomobject]@{
    Requester       = $request.Requester
    TargetGroup     = $request.TargetGroup
    ApprovedMinutes = $approvedMinutes
    TicketId        = $request.TicketId
    ExecutedAt      = Get-Date
} | Export-Csv -Path $policy.LogPath -Append -NoTypeInformation

[pscustomobject]@{
    Requester       = $request.Requester
    TargetGroup     = $request.TargetGroup
    ApprovedMinutes = $approvedMinutes
    TicketId        = $request.TicketId
    LogPath         = $policy.LogPath
}