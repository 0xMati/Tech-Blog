#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$InventoryPath = (Join-Path $PSScriptRoot 'inventory.json'),
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'compliance.settings.json'),
    [ValidateNotNullOrEmpty()][string[]]$ComputerName = @(),
    [string]$PackageDirectory = (Join-Path $PSScriptRoot 'Packages'),
    [pscredential]$Credential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'DCCompliance.psm1') -Force
$inputs = Read-DCComplianceInput -InventoryPath $InventoryPath -SettingsPath $SettingsPath
if ($inputs.Settings.DscVersion -cne '3.2.3' -or $inputs.Settings.DscExecutable -ine 'C:\Tools\DSC\dsc.exe') {
    throw 'This preparation script stages DSC 3.2.3 at C:\Tools\DSC. Use manual preparation for another path/version.'
}
$targetNames = @($ComputerName)
if (-not $PSBoundParameters.ContainsKey('ComputerName')) {
    $targetNames = @(
        $inputs.Inventory.DomainControllers |
            Where-Object { -not $_.IsReadOnly -and $inputs.Settings.ExcludedDCs -notcontains $_.HostName } |
            Select-Object -ExpandProperty HostName
    )
}
if ($targetNames.Count -eq 0) {
    throw 'No writable DCs are included for preparation. Check the inventory and ExcludedDCs.'
}
foreach ($name in $targetNames) {
    $target = @($inputs.Inventory.DomainControllers | Where-Object HostName -eq $name)
    if ($target.Count -ne 1 -or $target[0].IsReadOnly -or $inputs.Settings.ExcludedDCs -contains $name) {
        throw "'$name' must be an included writable DC from the inventory."
    }
}
$selectedTargets = @(
    foreach ($name in ($targetNames | Sort-Object -Unique)) {
        if ($PSCmdlet.ShouldProcess($name, 'Install DSC 3.2.3 and the three pinned resource modules')) { $name }
    }
)
if ($selectedTargets.Count -eq 0) { return }
$packageRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PackageDirectory)
$null = New-Item -Path $packageRoot -ItemType Directory -Force -Confirm:$false
$zipPath = Join-Path $packageRoot 'DSC-3.2.3-x86_64-pc-windows-msvc.zip'
$expectedHash = 'E1E48218014C166BBBE0EE6364D1E9C2AB20AB5515CEDA4EABD529A4BFD49881'
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    Invoke-WebRequest -Uri 'https://github.com/PowerShell/DSC/releases/download/v3.2.3/DSC-3.2.3-x86_64-pc-windows-msvc.zip' -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
}
if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -cne $expectedHash) {
    throw 'DSC ZIP hash does not match the pinned release. Remove the invalid cached download before retrying.'
}
$moduleRoot = Join-Path $packageRoot 'Modules'
$null = New-Item -Path $moduleRoot -ItemType Directory -Force -Confirm:$false
foreach ($module in $inputs.Settings.ModuleVersions.PSObject.Properties) {
    $manifest = Join-Path $moduleRoot ('{0}\{1}\{0}.psd1' -f $module.Name, $module.Value)
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        Save-Module -Name $module.Name -RequiredVersion $module.Value -Repository PSGallery -Path $moduleRoot -Force -ErrorAction Stop
    }
    $moduleInfo = Test-ModuleManifest -Path $manifest -ErrorAction Stop
    if ([version]$moduleInfo.Version -ne [version]$module.Value) { throw "Wrong cached module version: $($module.Name)." }
}
$transportPath = Join-Path ([System.IO.Path]::GetTempPath()) ('DCCompliance-Package-' + [guid]::NewGuid().ToString('N') + '.zip')
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::CreateFromDirectory($moduleRoot, $transportPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
    $archive = [System.IO.Compression.ZipFile]::Open($transportPath, [System.IO.Compression.ZipArchiveMode]::Update)
    try {
        $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $zipPath, 'dsc.zip', [System.IO.Compression.CompressionLevel]::NoCompression)
    }
    finally { $archive.Dispose() }
    [System.IO.File]::SetAttributes($transportPath, [System.IO.FileAttributes]::Normal)
    $transportHash = (Get-FileHash -LiteralPath $transportPath -Algorithm SHA256).Hash
    foreach ($name in $selectedTargets) {
        $session = $null
        $stagePath = $null
        try {
            $sessionArguments = @{
                ComputerName = $name
                ConfigurationName = 'Microsoft.PowerShell'
                Authentication = 'Kerberos'
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) { $sessionArguments.Credential = $Credential }
            $session = New-PSSession @sessionArguments
            $stagePath = Invoke-Command -Session $session -ArgumentList $inputs.Inventory.Domain, $name -ErrorAction Stop -ScriptBlock {
                param($ExpectedDomain, $ExpectedHostName)
                $ErrorActionPreference = 'Stop'
                $computer = Get-CimInstance Win32_ComputerSystem
                $actualHost = '{0}.{1}' -f $computer.DNSHostName, $computer.Domain
                if ($computer.DomainRole -notin @(4, 5) -or $computer.Domain -ine $ExpectedDomain -or $actualHost -ine $ExpectedHostName) {
                    throw 'Unexpected target identity or role.'
                }
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
                if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Target preparation requires elevation.' }
                $stage = Join-Path $env:ProgramData ('DCCompliance-Stage-' + [guid]::NewGuid().ToString('N'))
                $null = New-Item -Path $stage -ItemType Directory
                $stage
            }
            Copy-Item -LiteralPath $transportPath -Destination (Join-Path $stagePath 'package.zip') -ToSession $session -ErrorAction Stop
            $versionsJson = $inputs.Settings.ModuleVersions | ConvertTo-Json -Compress
            Invoke-Command -Session $session -ArgumentList $stagePath, $expectedHash, $transportHash, $versionsJson -ErrorAction Stop -ScriptBlock {
                param($StagePath, $ZipHash, $PackageHash, $VersionsJson)
                $ErrorActionPreference = 'Stop'
                $package = Join-Path $StagePath 'package.zip'
                if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -cne $PackageHash) { throw 'The transferred preparation package failed hash verification.' }
                Expand-Archive -LiteralPath $package -DestinationPath $StagePath -ErrorAction Stop
                $zip = Join-Path $StagePath 'dsc.zip'
                if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -cne $ZipHash) { throw 'The transferred DSC ZIP failed hash verification.' }
                $dscPath = 'C:\Tools\DSC\dsc.exe'
                if (Test-Path -LiteralPath $dscPath -PathType Leaf) {
                    $versionOutput = & $dscPath --version
                    if ($LASTEXITCODE -ne 0 -or ($versionOutput -join '').Trim() -cne 'dsc 3.2.3') {
                        throw 'Another DSC version already occupies C:\Tools\DSC. It was not overwritten.'
                    }
                }
                else {
                    if ((Test-Path -LiteralPath 'C:\Tools\DSC') -and @(Get-ChildItem -LiteralPath 'C:\Tools\DSC' -Force).Count -gt 0) {
                        throw 'C:\Tools\DSC is not empty and contains no dsc.exe. It was not overwritten.'
                    }
                    Expand-Archive -LiteralPath $zip -DestinationPath 'C:\Tools\DSC' -ErrorAction Stop
                }
                $versions = $VersionsJson | ConvertFrom-Json
                $destinationRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
                foreach ($module in $versions.PSObject.Properties) {
                    $moduleDirectory = Join-Path $destinationRoot $module.Name
                    $destination = Join-Path $moduleDirectory $module.Value
                    if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
                        $null = New-Item -Path $moduleDirectory -ItemType Directory -Force
                        $source = Join-Path $StagePath ('Modules\{0}\{1}' -f $module.Name, $module.Value)
                        Copy-Item -LiteralPath $source -Destination $moduleDirectory -Recurse -ErrorAction Stop
                    }
                    $manifest = Join-Path $destination ($module.Name + '.psd1')
                    $installed = Test-ModuleManifest -Path $manifest -ErrorAction Stop
                    if ([version]$installed.Version -ne [version]$module.Value) { throw "Unexpected installed version of $($module.Name)." }
                }
                [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; DscPath = $dscPath; ModulesPath = $destinationRoot; Result = 'Prepared' }
            }
        }
        finally {
            if ($null -ne $session) {
                if ($stagePath) {
                    Invoke-Command -Session $session -ArgumentList $stagePath -ErrorAction Continue -ScriptBlock {
                        param($StagePath)
                        Remove-Item -LiteralPath $StagePath -Recurse -Force -ErrorAction Continue
                    }
                }
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $transportPath) {
        Remove-Item -LiteralPath $transportPath -Force -Confirm:$false -ErrorAction Continue
    }
}