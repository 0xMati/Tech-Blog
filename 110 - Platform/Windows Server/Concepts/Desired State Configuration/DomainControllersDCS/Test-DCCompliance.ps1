#Requires -Version 5.1

[CmdletBinding()]
param([string]$PreviewDirectory)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('DCCompliance-Test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -Path $temporaryRoot -ItemType Directory
$inventoryPath = Join-Path $temporaryRoot 'inventory.json'
$settingsPath = Join-Path $temporaryRoot 'compliance.settings.json'
$baseSettingsText = Get-Content -LiteralPath (Join-Path $root 'compliance.settings.json') -Raw -Encoding UTF8
$passed = [System.Collections.Generic.List[string]]::new()
$calls = [System.Collections.Generic.List[object]]::new()
$fixtureState = @{ Scenario = 'Compliant'; Changed = $false }

function Assert-Test {
    param([bool]$Condition, [string]$Name)
    if (-not $Condition) { throw "FAILED: $Name" }
    $passed.Add($Name)
    Write-Output "PASS: $Name"
}

function Write-Fixture {
    param([string]$Path, $Value)
    [System.IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Value -Depth 25), [System.Text.UTF8Encoding]::new($false))
}

function Reset-Fixtures {
    $fixtureState.Scenario = 'Compliant'
    $fixtureState.Changed = $false
    $calls.Clear()
    $inventory = [pscustomobject]@{
        Domain = 'inventory.test'
        DiscoveredAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        SourceComputer = 'TEST-ADMIN'
        DomainControllers = @(
            foreach ($hostName in @('dc-a.inventory.test', 'dc-b.inventory.test', 'rodc.inventory.test')) {
                [pscustomobject]@{
                    HostName = $hostName
                    Domain = 'inventory.test'
                    Site = 'Test-Site'
                    OperatingSystem = 'Windows Server 2025'
                    IsReadOnly = $hostName -like 'rodc.*'
                }
            }
        )
    }
    Write-Fixture -Path $inventoryPath -Value $inventory
    [System.IO.File]::WriteAllText($settingsPath, $baseSettingsText, [System.Text.UTF8Encoding]::new($false))
}

function New-PSSessionOption {
    param($OpenTimeout, $OperationTimeout)
    @{}
}

function New-PSSession {
    [CmdletBinding()]
    param($ComputerName, $ConfigurationName, $Authentication, $SessionOption, $Credential)
    if ($ConfigurationName -ne 'Microsoft.PowerShell' -or $Authentication -ne 'Kerberos') { throw 'Unexpected remoting configuration.' }
    if ($fixtureState.Scenario -eq 'Unreachable' -and $ComputerName -eq 'dc-b.inventory.test') {
        throw 'Simulated network failure.'
    }
    [pscustomobject]@{ ComputerName = $ComputerName }
}

function Remove-PSSession {
    [CmdletBinding()]
    param($Session)
}

function Invoke-Command {
    [CmdletBinding()]
    param($Session, $FilePath, $ArgumentList)
    $request = $ArgumentList | ConvertFrom-Json
    $calls.Add([pscustomobject]@{ HostName = $Session.ComputerName; Operation = $request.Operation; ControlId = $(if ($request.Control) { $request.Control.Id } else { '' }) })
    if ($request.Operation -eq 'Preflight') {
        return [pscustomobject]@{ HostName = $Session.ComputerName; DscVersion = '3.2.3'; Account = 'inventory\TestOperator'; OperatingSystem = 'Windows Server 2025' }
    }
    $document = $request.ConfigurationJson | ConvertFrom-Json
    if ($document.resources.Count -ne 1 -or $document.resources[0].name -ne $request.Control.Id) { throw 'Invalid requested DSC document.' }
    if ($request.Operation -eq 'Set') {
        if ($fixtureState.Scenario -eq 'SetFailure') {
            return [pscustomobject]@{ ExitCode = 1; StdOut = '{"hadErrors":true}'; StdErr = 'Simulated Set failure'; TimedOut = $false }
        }
        $fixtureState.Changed = $true
        return [pscustomobject]@{ ExitCode = 0; StdOut = '{"hadErrors":false,"results":[]}'; StdErr = ''; TimedOut = $false }
    }
    if ($fixtureState.Scenario -eq 'ResourceError' -and $request.Control.Id -eq 'DSC-03-Logon') {
        return [pscustomobject]@{ ExitCode = 1; StdOut = '{"hadErrors":true}'; StdErr = 'Simulated resource failure'; TimedOut = $false }
    }
    $noncompliant = $request.Control.Id -eq 'DSC-01-Spooler' -and $fixtureState.Scenario -in @('Drift', 'SetFailure') -and -not $fixtureState.Changed
    $actual = $request.Control.Properties | ConvertTo-Json -Depth 10 | ConvertFrom-Json
    if ($noncompliant) { $actual.State = 'Running'; $actual.StartupType = 'Automatic' }
    $state = [ordered]@{
        inDesiredState = -not $noncompliant
        actualState = $actual
        desiredState = $request.Control.Properties
        differingProperties = @()
    }
    if ($noncompliant) { $state.differingProperties = @('State', 'StartupType') }
    if ($fixtureState.Scenario -eq 'Malformed' -and $request.Control.Id -eq 'DSC-03-Logon') { $state.inDesiredState = 'true' }
    $output = @{ hadErrors = $false; results = @(@{ name = $request.Control.Id; type = $request.Control.ResourceType; result = $state }) }
    [pscustomobject]@{ ExitCode = 0; StdOut = (ConvertTo-Json -InputObject $output -Depth 15); StdErr = ''; TimedOut = $false }
}

function Invoke-FixtureRun {
    param([hashtable]$Parameters = @{})
    $summary = & (Join-Path $root 'Invoke-DCCompliance.ps1') -InventoryPath $inventoryPath -SettingsPath $settingsPath -OutputDirectory (Join-Path $temporaryRoot 'Reports') @Parameters
    $exitCode = $LASTEXITCODE
    [pscustomobject]@{ Summary = $summary; ExitCode = $exitCode }
}

function Enable-SpoolerEnforcement {
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    ($settings.Controls | Where-Object Id -eq 'DSC-01-Spooler').Mode = 'Enforce'
    Write-Fixture -Path $settingsPath -Value $settings
}

function Invoke-PreparationFixture {
    param([hashtable]$Parameters = @{})
    $effects = [System.Collections.Generic.List[string]]::new()
    $packageDirectory = Join-Path $temporaryRoot 'PreparationPackages'
    function Invoke-WebRequest {
        [CmdletBinding()]param($Uri, $OutFile, [switch]$UseBasicParsing)
        $effects.Add('DownloadZIP')
    }
    function Save-Module {
        [CmdletBinding()]param($Name, $RequiredVersion, $Repository, $Path, [switch]$Force)
        $effects.Add("SaveModule:$Name")
    }
    function Get-FileHash {
        [CmdletBinding()]param($LiteralPath, $Algorithm)
        if ($LiteralPath -like '*.zip') {
            [pscustomobject]@{ Hash = 'E1E48218014C166BBBE0EE6364D1E9C2AB20AB5515CEDA4EABD529A4BFD49881' }
        }
        else { Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm }
    }
    function Test-ModuleManifest {
        [CmdletBinding()]param($Path)
        [pscustomobject]@{ Version = [version](Split-Path (Split-Path $Path -Parent) -Leaf) }
    }
    function New-PSSession {
        [CmdletBinding()]param($ComputerName, $ConfigurationName, $Authentication, $Credential)
        if ($ConfigurationName -ne 'Microsoft.PowerShell' -or $Authentication -ne 'Kerberos') { throw 'Unexpected preparation endpoint.' }
        $effects.Add("Connect:$ComputerName")
        [pscustomobject]@{ ComputerName = $ComputerName }
    }
    function Copy-Item {
        [CmdletBinding()]param($LiteralPath, $Destination, [switch]$Recurse, $ToSession)
        $effects.Add("Copy:$($ToSession.ComputerName)")
    }
    function Invoke-Command {
        [CmdletBinding()]param($Session, $ArgumentList, [scriptblock]$ScriptBlock)
        $parameterNames = @($ScriptBlock.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        if ($parameterNames[0] -eq 'ExpectedDomain') {
            return 'C:\ProgramData\DCCompliance-TestStage'
        }
        if ($parameterNames.Count -eq 3) {
            $effects.Add("Install:$($Session.ComputerName)")
            return [pscustomobject]@{ ComputerName = $Session.ComputerName; Result = 'Prepared' }
        }
        $effects.Add("Cleanup:$($Session.ComputerName)")
    }
    function Remove-PSSession {
        [CmdletBinding()]param($Session)
        $effects.Add("Disconnect:$($Session.ComputerName)")
    }
    $rows = @()
    $failure = $null
    try {
        $rows = @(
            & (Join-Path $root 'Initialize-DCCompliance.ps1') -InventoryPath $inventoryPath `
                -SettingsPath $settingsPath -PackageDirectory $packageDirectory -Confirm:$false @Parameters
        )
    }
    catch { $failure = $_.Exception.Message }
    [pscustomobject]@{ Rows = $rows; Effects = @($effects.ToArray()); Error = $failure; PackageDirectory = $packageDirectory }
}

try {
    foreach ($file in (Get-ChildItem -LiteralPath $root -File | Where-Object Extension -in @('.ps1', '.psm1'))) {
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        Assert-Test ($parseErrors.Count -eq 0) "Syntax: $($file.Name)"
    }
    Reset-Fixtures
    $run = Invoke-FixtureRun
    if ($run.ExitCode -ne 0 -or $run.Summary.Compliant -ne 22) {
        $run.Summary | Format-List
        if ($run.Summary.JsonPath) {
            (Get-Content -LiteralPath $run.Summary.JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json).Results |
                Select-Object ControlId, Status, Message | Format-Table -AutoSize -Wrap
        }
    }
    Assert-Test ($run.ExitCode -eq 0 -and $run.Summary.Compliant -eq 22) 'Default audit covers eleven controls on two writable DCs'
    Assert-Test (@($calls | Where-Object Operation -eq 'Set').Count -eq 0) 'Audit never invokes Set'
    $report = Get-Content -LiteralPath $run.Summary.JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Test (@($report.Targets | Where-Object Scope -eq 'Excluded').Count -eq 1) 'RODC remains visible as excluded'
    Assert-Test (@(Get-ChildItem -LiteralPath (Join-Path $run.Summary.RunDirectory 'Evidence') -File).Count -eq 22) 'Each checked control has raw evidence'

    Reset-Fixtures
    $fixtureState.Scenario = 'Drift'
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 1 -and $run.Summary.NonCompliant -eq 2) 'Real drift produces exit code 1'
    if ($PreviewDirectory) {
        $preview = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PreviewDirectory)
        $null = New-Item -Path $preview -ItemType Directory -Force
        Copy-Item -LiteralPath $run.Summary.HtmlPath -Destination (Join-Path $preview 'report.html') -Force
    }

    Reset-Fixtures
    $fixtureState.Scenario = 'Unreachable'
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 2 -and $run.Summary.Errors -eq 11 -and $run.Summary.Compliant -eq 11) 'Unreachable DC produces eleven failures without hiding the reachable DC'

    Reset-Fixtures
    $fixtureState.Scenario = 'ResourceError'
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 2 -and $run.Summary.Errors -eq 2 -and $run.Summary.Compliant -eq 20) 'A resource failure does not suppress other controls'

    Reset-Fixtures
    $fixtureState.Scenario = 'Malformed'
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 2 -and $run.Summary.Errors -eq 2) 'Invalid DSC Boolean values are errors, not compliance'

    Reset-Fixtures
    $run = Invoke-FixtureRun @{ ComputerName = @('dc-a.inventory.test'); ControlId = @('DSC-01-Spooler') }
    Assert-Test ($run.ExitCode -eq 0 -and $run.Summary.Compliant -eq 1) 'Pilot selection uses one DC and one control'

    Reset-Fixtures
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.ExcludedDCs = @('dc-b.inventory.test')
    Write-Fixture $settingsPath $settings
    $run = Invoke-FixtureRun
    Assert-Test ($run.Summary.Compliant -eq 11 -and @($calls | Where-Object HostName -eq 'dc-b.inventory.test').Count -eq 0) 'Explicit exclusions prevent remote execution'

    Reset-Fixtures
    Enable-SpoolerEnforcement
    $fixtureState.Scenario = 'Drift'
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 1 -and @($calls | Where-Object Operation -eq 'Set').Count -eq 0) 'Enforce mode alone does not turn Audit into Set'

    Reset-Fixtures
    Enable-SpoolerEnforcement
    $fixtureState.Scenario = 'Drift'
    $run = Invoke-FixtureRun @{ Operation = 'Remediate'; ComputerName = @('dc-a.inventory.test'); ControlId = @('DSC-01-Spooler'); Confirm = $false }
    Assert-Test ($run.ExitCode -eq 0 -and ($calls.Operation -join ',') -eq 'Preflight,Test,Set,Test') 'Explicit remediation executes Test, Set, and a fresh Test'

    Reset-Fixtures
    Enable-SpoolerEnforcement
    $fixtureState.Scenario = 'Drift'
    $run = Invoke-FixtureRun @{ Operation = 'Remediate'; ComputerName = @('dc-a.inventory.test'); ControlId = @('DSC-01-Spooler'); WhatIf = $true }
    Assert-Test ($run.ExitCode -eq 1 -and @($calls | Where-Object Operation -eq 'Set').Count -eq 0) 'Runner WhatIf tests state but never invokes Set'

    Reset-Fixtures
    Enable-SpoolerEnforcement
    $fixtureState.Scenario = 'SetFailure'
    $run = Invoke-FixtureRun @{ Operation = 'Remediate'; ComputerName = @('dc-a.inventory.test'); ControlId = @('DSC-01-Spooler'); Confirm = $false }
    Assert-Test ($run.ExitCode -eq 2 -and ($calls.Operation -join ',') -eq 'Preflight,Test,Set,Test') 'Set failures remain errors and still trigger a post-test'

    Reset-Fixtures
    $run = Invoke-FixtureRun @{ Operation = 'Remediate' }
    Assert-Test ($run.ExitCode -eq 2 -and $calls.Count -eq 0) 'Unbounded remediation is rejected before connecting'

    Reset-Fixtures
    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.Controls[1].Mode = 'Enforce'
    Write-Fixture $settingsPath $settings
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 2 -and $calls.Count -eq 0) 'GPO Enforce is rejected before connecting'

    Reset-Fixtures
    $inventory = Get-Content -LiteralPath $inventoryPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $inventory.DiscoveredAtUtc = (Get-Date).AddDays(-2).ToUniversalTime().ToString('o')
    Write-Fixture $inventoryPath $inventory
    $run = Invoke-FixtureRun
    Assert-Test ($run.ExitCode -eq 2 -and $calls.Count -eq 0) 'Stale inventory is rejected before connecting'

    Reset-Fixtures
    $run = Invoke-FixtureRun @{ ComputerName = @('unknown.inventory.test') }
    Assert-Test ($run.ExitCode -eq 2 -and $calls.Count -eq 0) 'Unknown targets are rejected before connecting'

    Reset-Fixtures
    $preparation = Invoke-PreparationFixture @{ WhatIf = $true }
    Assert-Test ($null -eq $preparation.Error -and $preparation.Rows.Count -eq 0 -and $preparation.Effects.Count -eq 0 -and
        -not (Test-Path -LiteralPath $preparation.PackageDirectory)) 'Inventory-based preparation WhatIf performs no download, staging, or connection'

    $preparation = Invoke-PreparationFixture
    Assert-Test ($null -eq $preparation.Error -and ($preparation.Rows.ComputerName -join ',') -eq 'dc-a.inventory.test,dc-b.inventory.test' -and
        @($preparation.Effects | Where-Object { $_ -like 'Install:*' }).Count -eq 2) 'Preparation defaults to all writable inventory DCs, not RODCs'

    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.ExcludedDCs = @('dc-b.inventory.test')
    Write-Fixture $settingsPath $settings
    $preparation = Invoke-PreparationFixture
    Assert-Test ($null -eq $preparation.Error -and $preparation.Rows.Count -eq 1 -and $preparation.Rows[0].ComputerName -eq 'dc-a.inventory.test') 'Preparation respects ExcludedDCs'

    foreach ($name in @('dc-b.inventory.test', 'rodc.inventory.test', 'unknown.inventory.test')) {
        $preparation = Invoke-PreparationFixture @{ ComputerName = @($name) }
        Assert-Test ($preparation.Error -like '*must be an included writable DC*' -and $preparation.Effects.Count -eq 0) "Preparation rejects invalid explicit target: $name"
    }

    Reset-Fixtures
    $preparation = Invoke-PreparationFixture @{ ComputerName = @('dc-b.inventory.test') }
    Assert-Test ($null -eq $preparation.Error -and $preparation.Rows.Count -eq 1 -and $preparation.Rows[0].ComputerName -eq 'dc-b.inventory.test') 'ComputerName still restricts preparation to one DC'
    $preparation = Invoke-PreparationFixture @{ ComputerName = @() }
    Assert-Test ($null -ne $preparation.Error -and $preparation.Effects.Count -eq 0) 'An explicitly empty target list cannot fall back to preparing every DC'

    $settings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $settings.ExcludedDCs = @('dc-a.inventory.test', 'dc-b.inventory.test')
    Write-Fixture $settingsPath $settings
    $preparation = Invoke-PreparationFixture
    Assert-Test ($preparation.Error -like 'No writable DCs are included for preparation*' -and $preparation.Effects.Count -eq 0) 'Preparation rejects an inventory with no eligible DCs'

    Write-Output "VALIDATION OK: $($passed.Count) assertions under PowerShell $($PSVersionTable.PSVersion). All AD/WinRM/DSC operations mocked; temporary report files removed."
}
finally {
    Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction Stop
}