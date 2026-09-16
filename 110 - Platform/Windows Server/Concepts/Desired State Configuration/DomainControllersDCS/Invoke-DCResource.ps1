#Requires -Version 5.1

[CmdletBinding()]
param([Parameter(Mandatory)][string]$RequestJson)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-DCNativeProcess {
    param([string]$Executable, [string]$Arguments, [int]$TimeoutSeconds = 180)
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'Could not start DSC.' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit($TimeoutSeconds * 1000)
        $cleanupError = ''
        if ($timedOut) {
            $stopProcess = $null
            try {
                $stopInfo = [System.Diagnostics.ProcessStartInfo]::new()
                $stopInfo.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
                $stopInfo.Arguments = '/PID {0} /T /F' -f $process.Id
                $stopInfo.UseShellExecute = $false
                $stopInfo.CreateNoWindow = $true
                $stopInfo.RedirectStandardOutput = $true
                $stopInfo.RedirectStandardError = $true
                $stopProcess = [System.Diagnostics.Process]::Start($stopInfo)
                if (-not $stopProcess.WaitForExit(10000)) {
                    $stopProcess.Kill()
                    $cleanupError = 'Process-tree cleanup timed out.'
                }
                elseif ($stopProcess.ExitCode -ne 0) {
                    $cleanupError = $stopProcess.StandardError.ReadToEnd()
                }
            }
            catch { $cleanupError = $_.Exception.Message }
            finally { if ($null -ne $stopProcess) { $stopProcess.Dispose() } }
            try {
                if (-not $process.WaitForExit(5000)) {
                    $process.Kill()
                    $null = $process.WaitForExit(5000)
                    $cleanupError += ' Only the parent process was stopped; child processes may still exist.'
                }
            }
            catch { $cleanupError += ' ' + $_.Exception.Message }
        }
        $stdout = if ($stdoutTask.Wait(5000)) { $stdoutTask.Result } else { '' }
        $stderr = if ($stderrTask.Wait(5000)) { $stderrTask.Result } else { 'DSC diagnostic stream did not close.' }
        if ($timedOut) {
            $stderr += "`nDSC exceeded $TimeoutSeconds seconds. A process-tree stop was requested; target state must be checked again."
            if ($cleanupError) { $stderr += "`nCleanup diagnostic: $cleanupError" }
        }
        [pscustomobject]@{
            ExitCode = $(if ($timedOut) { -1 } else { $process.ExitCode })
            StdOut = $stdout
            StdErr = $stderr
            TimedOut = $timedOut
            CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        }
    }
    finally { $process.Dispose() }
}

function ConvertTo-DCVersion {
    param([string]$Value)
    $version = [version]$Value
    [version]::new($version.Major, $version.Minor, [Math]::Max(0, $version.Build), [Math]::Max(0, $version.Revision))
}

$request = $RequestJson | ConvertFrom-Json -ErrorAction Stop
if ($request.Operation -cnotin @('Preflight', 'Test', 'Set')) { throw 'Unsupported remote operation.' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'Use the Microsoft.PowerShell endpoint (Windows PowerShell 5.1).'
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The WindowsPowerShell DSC adapter requires an elevated target process.'
}
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$actualHostName = '{0}.{1}' -f $computer.DNSHostName, $computer.Domain
if ($computer.DomainRole -notin @(4, 5) -or $computer.Domain -ine $request.Domain -or $actualHostName -ine $request.HostName) {
    throw "Target identity or DC role mismatch: reached '$actualHostName'."
}
if ([int]$operatingSystem.BuildNumber -notin @(17763, 20348, 26100)) {
    throw 'This control set targets Windows Server 2019, 2022, and 2025 DCs.'
}
$settings = $request.Settings
if (-not (Test-Path -LiteralPath $settings.DscExecutable -PathType Leaf)) {
    throw "DSC executable is missing: $($settings.DscExecutable)"
}
$env:PATH = '{0};{1}' -f (Split-Path $settings.DscExecutable -Parent), $env:PATH
$machineModuleRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
$systemModuleRoot = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$machineModuleRoot;$systemModuleRoot"

if ($request.Operation -eq 'Preflight') {
    $versionResult = Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments '--version'
    if ($versionResult.ExitCode -ne 0 -or $versionResult.StdOut.Trim() -notmatch '^dsc\s+(\S+)$') {
        throw "Could not read the DSC version. $($versionResult.StdErr)"
    }
    $dscVersion = $Matches[1]
    if ($dscVersion -cne $settings.DscVersion) {
        throw "DSC version mismatch: expected $($settings.DscVersion), found $dscVersion."
    }
    $resourceVersions = @(
        foreach ($resourceType in $request.ResourceTypes) {
            $moduleName, $resourceName = $resourceType -split '/', 2
            $expectedVersion = $settings.ModuleVersions.$moduleName
            $resourceInfo = @(Get-DscResource -Name $resourceName -Module $moduleName -ErrorAction Stop)
            if ($resourceInfo.Count -ne 1 -or
                (ConvertTo-DCVersion ([string]$resourceInfo[0].Version)) -ne (ConvertTo-DCVersion $expectedVersion)) {
                throw "Resource '$resourceType' must resolve to version $expectedVersion in machine scope."
            }
            $listing = Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments ('resource list --adapter Microsoft.Adapter/WindowsPowerShell {0} --output-format json' -f $resourceType)
            if ($listing.ExitCode -ne 0) { throw "DSC discovery failed for '$resourceType'. $($listing.StdErr)" }
            $discoveredResources = @(
                foreach ($line in ($listing.StdOut -split '\r?\n')) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) { $line | ConvertFrom-Json -ErrorAction Stop }
                }
            )
            $match = @($discoveredResources | Where-Object type -eq $resourceType)
            if ($match.Count -ne 1 -or $match[0].requireAdapter -cne 'Microsoft.Adapter/WindowsPowerShell' -or
                (ConvertTo-DCVersion ([string]$match[0].version)) -ne (ConvertTo-DCVersion $expectedVersion)) {
                throw "DSC did not discover '$resourceType' with the pinned version and adapter."
            }
            [pscustomobject]@{ Type = $resourceType; Version = [string]$match[0].version; DiscoveryDiagnostics = $listing.StdErr }
        }
    )
    [pscustomobject]@{
        HostName = $actualHostName
        OperatingSystem = $operatingSystem.Caption
        BuildNumber = $operatingSystem.BuildNumber
        Account = $identity.Name
        DscVersion = $dscVersion
        ResourceVersions = $resourceVersions
        CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

if ($request.Operation -eq 'Set') {
    $control = $request.Control
    if ($control.Mode -cne 'Enforce' -or $control.Owner -cne 'DSC' -or
        $control.ResourceType -cnotin @('PSDscResources/Service', 'ComputerManagementDsc/WindowsEventLog')) {
        throw 'This control is not eligible for DSC remediation.'
    }
}
$configuration = $request.ConfigurationJson | ConvertFrom-Json -ErrorAction Stop
if ($configuration.resources.Count -ne 1 -or
    $configuration.resources[0].name -cne $request.Control.Id -or
    $configuration.resources[0].type -cne $request.Control.ResourceType) {
    throw 'Unexpected DSC document for this control.'
}
$temporaryPath = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N') + '.dsc.config.json')
try {
    [System.IO.File]::WriteAllText($temporaryPath, $request.ConfigurationJson, [System.Text.UTF8Encoding]::new($false))
    $arguments = 'config {0} --file "{1}" --output-format json' -f $request.Operation.ToLowerInvariant(), $temporaryPath
    Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments $arguments
}
finally {
    if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
}