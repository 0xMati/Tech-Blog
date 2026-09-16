#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$InventoryPath = (Join-Path $PSScriptRoot 'inventory.json'),
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'compliance.settings.json'),
    [ValidateSet('Audit', 'Remediate')][string]$Operation = 'Audit',
    [ValidateNotNullOrEmpty()][string[]]$ComputerName = @(),
    [ValidateNotNullOrEmpty()][string[]]$ControlId = @(),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'Reports'),
    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DCCompliance.psm1') -Force -ErrorAction Stop
$remoteScript = Join-Path $PSScriptRoot 'Invoke-DCResource.ps1'

function New-DCResultRow {
    param([string]$HostName, $Control)
    [pscustomobject][ordered]@{
        HostName = $HostName
        ControlId = $Control.Id
        ControlName = $Control.Name
        Owner = $Control.Owner
        Mode = $Control.Mode
        ResourceType = $Control.ResourceType
        Status = 'NotEvaluated'
        Action = 'None'
        EvaluatedAtUtc = $null
        DesiredState = $Control.Properties
        ActualState = $null
        DifferingProperties = @()
        Message = ''
    }
}

function New-DCRequest {
    param([string]$RemoteOperation, [string]$HostName, $Control)
    $request = [ordered]@{
        Operation = $RemoteOperation
        HostName = $HostName
        Domain = $inputs.Inventory.Domain
        Settings = $inputs.Settings
        ResourceTypes = @($controls.ResourceType | Sort-Object -Unique)
        Control = $Control
        ConfigurationJson = $(if ($null -ne $Control) { New-DCConfiguration -Control $Control } else { '' })
    }
    ConvertTo-Json -InputObject $request -Depth 20
}

function Set-DCRowState {
    param($Row, $State)
    $Row.ActualState = $State.ActualState
    $Row.DifferingProperties = @($State.DifferingProperties)
    $Row.Status = if ($State.InDesiredState) { 'Compliant' } else { 'NonCompliant' }
    $Row.EvaluatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
}

try {
    $inputs = Read-DCComplianceInput -InventoryPath $InventoryPath -SettingsPath $SettingsPath
    if (-not (Test-Path -LiteralPath $remoteScript -PathType Leaf)) { throw 'Invoke-DCResource.ps1 is missing.' }
    foreach ($name in @($ComputerName)) {
        if ($inputs.Inventory.DomainControllers.HostName -notcontains $name) {
            throw "DC '$name' is not in the inventory. Use its full HostName."
        }
    }
    foreach ($identifier in @($ControlId)) {
        if ($inputs.Settings.Controls.Id -notcontains $identifier) { throw "Unknown control ID: '$identifier'." }
    }
    $controls = @($inputs.Settings.Controls | Where-Object { -not $ControlId -or $ControlId -contains $_.Id })
    $targets = @(
        foreach ($target in $inputs.Inventory.DomainControllers) {
            $scope = 'Included'
            $reason = 'Writable DC selected for this run'
            if ($target.IsReadOnly) { $scope = 'Excluded'; $reason = 'Read-only DCs are outside this control set' }
            elseif ($inputs.Settings.ExcludedDCs -contains $target.HostName) { $scope = 'Excluded'; $reason = 'Listed in ExcludedDCs' }
            elseif ($ComputerName -and $ComputerName -notcontains $target.HostName) { $scope = 'NotSelected'; $reason = 'Outside the explicit ComputerName selection' }
            [pscustomobject]@{ HostName = $target.HostName; Scope = $scope; Reason = $reason }
        }
    )
    $includedTargets = @($targets | Where-Object Scope -eq 'Included')
    if ($includedTargets.Count -eq 0) { throw 'No writable DCs are selected. No assessment was performed.' }
    if ($Operation -eq 'Remediate') {
        if (-not $ComputerName -or -not $ControlId) { throw 'Remediate requires explicit ComputerName and ControlId parameters.' }
        foreach ($name in $ComputerName) {
            if ($includedTargets.HostName -notcontains $name) { throw "DC '$name' is excluded from remediation." }
        }
        foreach ($control in $controls) {
            if ($control.Mode -cne 'Enforce' -or $control.Owner -cne 'DSC') {
                throw "'$($control.Id)' must be DSC-owned and in Enforce mode before remediation."
            }
        }
    }
    $runId = [guid]::NewGuid().ToString('N')
    $runName = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $runId.Substring(0, 8)
    $rootOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $runDirectory = Join-Path $rootOutput $runName
    $null = New-Item -Path $runDirectory -ItemType Directory -WhatIf:$false -Confirm:$false -ErrorAction Stop
    $evidenceDirectory = Join-Path $runDirectory 'Evidence'
    $null = New-Item -Path $evidenceDirectory -ItemType Directory -WhatIf:$false -Confirm:$false -ErrorAction Stop
    [System.IO.File]::WriteAllText((Join-Path $runDirectory 'inventory.input.json'), $inputs.InventoryText, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $runDirectory 'compliance.input.json'), $inputs.SettingsText, [System.Text.UTF8Encoding]::new($false))
    $results = [System.Collections.Generic.List[object]]::new()
    $metadata = [System.Collections.Generic.List[object]]::new()
    $report = [pscustomobject][ordered]@{
        SchemaVersion = 1
        RunId = $runId
        Domain = $inputs.Inventory.Domain
        Operation = $Operation
        WhatIf = [bool]$WhatIfPreference
        BaselineVersion = $inputs.Settings.BaselineVersion
        StartedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        CompletedAtUtc = $null
        SourceComputer = $env:COMPUTERNAME
        InventoryDiscoveredAtUtc = $inputs.Inventory.DiscoveredAtUtc
        InventorySha256 = $inputs.InventorySha256
        SettingsSha256 = $inputs.SettingsSha256
        Targets = $targets
        TargetMetadata = @()
        Results = @()
    }
    foreach ($target in $includedTargets) {
        $session = $null
        $connectionEstablished = $false
        Write-Information -MessageData "Assessing $($target.HostName) ($Operation)" -InformationAction Continue
        try {
            $sessionParameters = @{
                ComputerName = $target.HostName
                ConfigurationName = 'Microsoft.PowerShell'
                Authentication = 'Kerberos'
                SessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 240000
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) { $sessionParameters.Credential = $Credential }
            $session = New-PSSession @sessionParameters
            $connectionEstablished = $true
            $preflightRequest = New-DCRequest -RemoteOperation 'Preflight' -HostName $target.HostName
            $preflight = @(Invoke-Command -Session $session -FilePath $remoteScript -ArgumentList $preflightRequest -ErrorAction Stop)
            if ($preflight.Count -ne 1 -or $preflight[0].HostName -ine $target.HostName) { throw 'Invalid preflight response.' }
            $metadata.Add($preflight[0])
        }
        catch {
            $failure = $_
            $status = 'Error'
            if (-not $connectionEstablished -and $failure.Exception -isnot [UnauthorizedAccessException] -and
                $failure.CategoryInfo.Category -notin @('PermissionDenied', 'AuthenticationError', 'SecurityError')) {
                $status = 'Unreachable'
            }
            foreach ($control in $controls) {
                $row = New-DCResultRow -HostName $target.HostName -Control $control
                $row.Status = $status
                $row.Action = 'PreflightFailed'
                $row.Message = $failure.Exception.Message
                $results.Add($row)
            }
            if ($null -ne $session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
            continue
        }
        try {
            foreach ($control in $controls) {
                $row = New-DCResultRow -HostName $target.HostName -Control $control
                $evidence = [ordered]@{ HostName = $target.HostName; ControlId = $control.Id; Configuration = New-DCConfiguration $control; Before = $null; Set = $null; After = $null; Error = $null }
                try {
                    $testRequest = New-DCRequest -RemoteOperation 'Test' -HostName $target.HostName -Control $control
                    $beforeResponses = @(Invoke-Command -Session $session -FilePath $remoteScript -ArgumentList $testRequest -ErrorAction Stop)
                    if ($beforeResponses.Count -ne 1) { throw 'Expected one DSC process response.' }
                    $evidence.Before = $beforeResponses[0]
                    $before = Get-DCTestState -Response $evidence.Before -Control $control
                    Set-DCRowState -Row $row -State $before
                    $row.Action = 'Test'
                    if ($Operation -eq 'Remediate') {
                        if ($before.InDesiredState) { $row.Action = 'AlreadyCompliant' }
                        elseif ($PSCmdlet.ShouldProcess($target.HostName, "DSC Set $($control.Id)")) {
                            $row.Action = 'Set'
                            $setError = $null
                            try {
                                $setRequest = New-DCRequest -RemoteOperation 'Set' -HostName $target.HostName -Control $control
                                $setResponses = @(Invoke-Command -Session $session -FilePath $remoteScript -ArgumentList $setRequest -ErrorAction Stop)
                                if ($setResponses.Count -ne 1) { throw 'Expected one DSC Set response.' }
                                $evidence.Set = $setResponses[0]
                                $setOutput = $evidence.Set.StdOut | ConvertFrom-Json -ErrorAction Stop
                                if ($evidence.Set.ExitCode -ne 0 -or $setOutput.hadErrors -isnot [bool] -or $setOutput.hadErrors) {
                                    throw "DSC Set failed. $($evidence.Set.StdErr)"
                                }
                            }
                            catch { $setError = $_.Exception.Message }
                            $afterResponses = @(Invoke-Command -Session $session -FilePath $remoteScript -ArgumentList $testRequest -ErrorAction Stop)
                            if ($afterResponses.Count -ne 1) { throw 'Expected one post-remediation test response.' }
                            $evidence.After = $afterResponses[0]
                            $after = Get-DCTestState -Response $evidence.After -Control $control
                            Set-DCRowState -Row $row -State $after
                            if ($null -ne $setError) { throw $setError }
                        }
                        else {
                            $row.Action = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
                            $row.Message = 'No Set was executed; the observed state is from the read-only test.'
                        }
                    }
                }
                catch {
                    $row.Status = 'Error'
                    $row.Message = $_.Exception.Message
                    $evidence.Error = $row.Message
                }
                if ($control.ResourceType -eq 'PSDscResources/Registry') {
                    $row.Message = ($row.Message + ' Explicit policy value check only; no inference about implicit LDAP defaults or effective enforcement.').Trim()
                }
                $evidencePath = Join-Path $evidenceDirectory ('{0}--{1}.json' -f $target.HostName, $control.Id)
                [System.IO.File]::WriteAllText($evidencePath, (ConvertTo-Json -InputObject $evidence -Depth 35), [System.Text.UTF8Encoding]::new($false))
                $results.Add($row)
            }
        }
        finally { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
    $report.Results = @($results.ToArray())
    $report.TargetMetadata = @($metadata.ToArray())
    $report.CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    $summary = Write-DCComplianceReport -Report $report -RunDirectory $runDirectory
    $summary
    if ($summary.Errors -gt 0 -or $summary.NotEvaluated -gt 0) { exit 2 }
    if ($summary.NonCompliant -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 2
}