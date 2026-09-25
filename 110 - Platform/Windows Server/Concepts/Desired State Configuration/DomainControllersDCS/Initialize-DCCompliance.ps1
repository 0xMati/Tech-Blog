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
        if ($PSCmdlet.ShouldProcess($name, 'Install DSC 3.2.3 and the versioned native DC resource package')) { $name }
    }
)
if ($selectedTargets.Count -eq 0) { return }
$resourcePackage = Get-DCResourcePackage -ResourceVersion $inputs.Settings.ResourceVersion
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
$transportPath = Join-Path ([System.IO.Path]::GetTempPath()) ('DCCompliance-Package-' + [guid]::NewGuid().ToString('N') + '.zip')
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::CreateFromDirectory($resourcePackage.Directory, $transportPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)
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
                SessionOption = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 240000
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) { $sessionArguments.Credential = $Credential }
            $session = New-PSSession @sessionArguments
            $stagePath = Invoke-Command -Session $session -ArgumentList $inputs.Inventory.Domain, $name -ErrorAction Stop -ScriptBlock {
                param($ExpectedDomain, $ExpectedHostName)
                $ErrorActionPreference = 'Stop'
                if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
                    throw 'Preparation requires an x64 Windows PowerShell 5.1 target endpoint.'
                }
                $computer = Get-CimInstance Win32_ComputerSystem
                $operatingSystem = Get-CimInstance Win32_OperatingSystem
                $actualHost = '{0}.{1}' -f $computer.DNSHostName, $computer.Domain
                if ($computer.DomainRole -notin @(4, 5) -or $computer.Domain -ine $ExpectedDomain -or $actualHost -ine $ExpectedHostName -or
                    [int]$operatingSystem.BuildNumber -notin @(17763, 20348, 26100)) {
                    throw 'Unexpected target identity, DC role, or supported Windows Server build.'
                }
                $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
                if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Target preparation requires elevation.' }
                $stage = Join-Path $env:ProgramData ('DCCompliance-Stage-' + [guid]::NewGuid().ToString('N'))
                $null = New-Item -Path $stage -ItemType Directory
                $stage
            }
            Copy-Item -LiteralPath $transportPath -Destination (Join-Path $stagePath 'package.zip') -ToSession $session -ErrorAction Stop
            $resourceJson = @{ Version = $resourcePackage.Version; Destination = $inputs.Settings.ResourceDirectory; Files = $resourcePackage.Files } | ConvertTo-Json -Depth 8 -Compress
            Invoke-Command -Session $session -ArgumentList $stagePath, $expectedHash, $transportHash, $resourceJson -ErrorAction Stop -ScriptBlock {
                param($StagePath, $ZipHash, $PackageHash, $ResourceJson)
                $ErrorActionPreference = 'Stop'
                Set-StrictMode -Version Latest
                $package = Join-Path $StagePath 'package.zip'
                if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash -cne $PackageHash) { throw 'The transferred preparation package failed hash verification.' }
                Expand-Archive -LiteralPath $package -DestinationPath $StagePath -ErrorAction Stop
                $zip = Join-Path $StagePath 'dsc.zip'
                if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -cne $ZipHash) { throw 'The transferred DSC ZIP failed hash verification.' }
                $resources = $ResourceJson | ConvertFrom-Json
                $source = Join-Path $StagePath 'Resources'
                foreach ($file in $resources.Files) {
                    if ((Get-FileHash -LiteralPath (Join-Path $source $file.Name) -Algorithm SHA256).Hash -cne $file.Sha256) {
                        throw "Transferred native resource file failed hash verification: $($file.Name)."
                    }
                }
                $destination = $resources.Destination
                if (Test-Path -LiteralPath $destination) {
                    foreach ($file in $resources.Files) {
                        $installedPath = Join-Path $destination $file.Name
                        if (-not (Test-Path -LiteralPath $installedPath -PathType Leaf) -or
                            (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256).Hash -cne $file.Sha256) {
                            throw "Resource version $($resources.Version) already exists with different content. Publish a new resource version; it was not overwritten."
                        }
                    }
                    if (@(Get-ChildItem -LiteralPath $destination -File -Recurse -Force).Count -ne $resources.Files.Count) {
                        throw 'Existing resource directory contains unexpected files; it was not overwritten.'
                    }
                }
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
                if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
                    $null = New-Item -Path $destination -ItemType Directory -Force
                    Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $destination -Recurse -Force -ErrorAction Stop
                }
                foreach ($file in $resources.Files) {
                    if ((Get-FileHash -LiteralPath (Join-Path $destination $file.Name) -Algorithm SHA256).Hash -cne $file.Sha256) {
                        throw "Installed native resource file failed hash verification: $($file.Name)."
                    }
                }
                [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; DscPath = $dscPath; ResourcePath = $destination; ResourceVersion = $resources.Version; Result = 'Prepared' }
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