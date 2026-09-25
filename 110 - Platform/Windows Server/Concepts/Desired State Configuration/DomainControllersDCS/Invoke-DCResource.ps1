#Requires -Version 5.1

[CmdletBinding()]
param([Parameter(Mandatory)][string]$RequestJson)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-DCNativeProcess {
    param([string]$Executable, [string]$Arguments, [int]$TimeoutSeconds = 180, [hashtable]$Environment = @{})
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    foreach ($name in $Environment.Keys) { $startInfo.EnvironmentVariables[$name] = [string]$Environment[$name] }
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

$request = $RequestJson | ConvertFrom-Json -ErrorAction Stop
if ($request.Operation -cnotin @('Preflight', 'Test', 'Set')) { throw 'Unsupported remote operation.' }
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
    throw 'Use an x64 Microsoft.PowerShell endpoint (Windows PowerShell 5.1).'
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The native DC resource checks require an elevated target process.'
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
$powerShellRoot = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0'
$nativeEnvironment = @{
    DSC_RESOURCE_PATH = $settings.ResourceDirectory + ';' + $powerShellRoot
    PATH = $powerShellRoot + ';' + $env:PATH
}

if ($request.Operation -eq 'Preflight') {
    if (-not (Test-Path -LiteralPath $settings.ResourceDirectory -PathType Container)) { throw 'The native resource package is missing. Run preparation first.' }
    if ($request.ResourceFiles -isnot [array] -or $request.ResourceFiles.Count -ne 8) { throw 'Expected eight native resource-file hashes.' }
    foreach ($file in $request.ResourceFiles) {
        if ($file.Name -cnotmatch '^[A-Za-z][A-Za-z0-9.]+$' -or $file.Sha256 -cnotmatch '^[A-F0-9]{64}$') { throw 'Invalid native resource-file identity.' }
        if ((Get-FileHash -LiteralPath (Join-Path $settings.ResourceDirectory $file.Name) -Algorithm SHA256 -ErrorAction Stop).Hash -cne $file.Sha256) {
            throw "Installed native resource file differs from the orchestration package: $($file.Name). Deploy the matching resource version."
        }
    }
    if (@(Get-ChildItem -LiteralPath $settings.ResourceDirectory -File -Recurse -Force).Count -ne $request.ResourceFiles.Count) { throw 'Unexpected files in the installed native resource directory.' }
    $versionResult = Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments '--version' -Environment $nativeEnvironment
    if ($versionResult.ExitCode -ne 0 -or $versionResult.StdOut.Trim() -notmatch '^dsc\s+(\S+)$') {
        throw "Could not read the DSC version. $($versionResult.StdErr)"
    }
    $dscVersion = $Matches[1]
    if ($dscVersion -cne $settings.DscVersion) {
        throw "DSC version mismatch: expected $($settings.DscVersion), found $dscVersion."
    }
    $listing = Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments 'resource list Blog.DC/* --output-format json' -Environment $nativeEnvironment
    if ($listing.ExitCode -ne 0) { throw "Native resource discovery failed. $($listing.StdErr)" }
    $discoveredResources = @(
        foreach ($line in ($listing.StdOut -split '\r?\n')) {
            if (-not [string]::IsNullOrWhiteSpace($line)) { $line | ConvertFrom-Json -ErrorAction Stop }
        }
    )
    $resourceVersions = @(
        foreach ($resourceType in $request.ResourceTypes) {
            $match = @($discoveredResources | Where-Object type -eq $resourceType)
            if ($match.Count -ne 1 -or $match[0].kind -cne 'resource' -or
                ($match[0].PSObject.Properties['requireAdapter'] -and $match[0].requireAdapter) -or
                $match[0].version -cne $settings.ResourceVersion) {
                throw "DSC did not discover native '$resourceType' version $($settings.ResourceVersion)."
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
        ResourceDirectory = $settings.ResourceDirectory
        ResourceFileHashes = $request.ResourceFiles
        CompletedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    return
}

if ($request.Operation -eq 'Set') {
    $control = $request.Control
    if ($control.Mode -cne 'Enforce' -or $control.Owner -cne 'DSC' -or
        $control.ResourceType -cnotin @('Blog.DC/Spooler', 'Blog.DC/EventLog')) {
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
    Invoke-DCNativeProcess -Executable $settings.DscExecutable -Arguments $arguments -Environment $nativeEnvironment
}
finally {
    if ([System.IO.File]::Exists($temporaryPath)) { [System.IO.File]::Delete($temporaryPath) }
}