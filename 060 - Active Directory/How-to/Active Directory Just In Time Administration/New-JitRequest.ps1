[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Requester,

    [Parameter(Mandatory)]
    [string]$TargetGroup,

    [Parameter(Mandatory)]
    [ValidateRange(1, 1440)]
    [int]$RequestedMinutes,

    [Parameter(Mandatory)]
    [string]$TicketId,

    [string]$OutputDirectory = 'C:\JIT\Requests'
)

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$request = [pscustomobject]@{
    Requester        = $Requester
    TargetGroup      = $TargetGroup
    RequestedMinutes = $RequestedMinutes
    TicketId         = $TicketId
    ApprovalState    = 'Pending'
    RequestedAt      = Get-Date
}

$requestPath = Join-Path -Path $OutputDirectory -ChildPath ("{0}.json" -f $TicketId)

$request | ConvertTo-Json | Set-Content -Path $requestPath

Get-Item -Path $requestPath