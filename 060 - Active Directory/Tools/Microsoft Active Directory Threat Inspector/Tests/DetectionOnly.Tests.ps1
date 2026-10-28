$toolRoot = Split-Path -Parent $PSScriptRoot

Describe 'MATI detection-only entry point' {
    It 'offers detection without a tiering deployment entry point' {
        $source = Get-Content -LiteralPath (Join-Path $toolRoot 'Invoke-MATI.ps1') -Raw
        $source.Contains('function Invoke-MATIThreatDetection') | Should Be $true
        $source.Contains('Read-MATITargetForest -CurrentTargetForest $selectedTargetForest') | Should Be $true
        $source.Contains('Invoke-MATITiering') | Should Be $false
        $source.Contains('Implement Tiering Model') | Should Be $false
        $source.Contains('MATIMode') | Should Be $false
        Test-Path -LiteralPath (Join-Path $toolRoot 'Config\Tiering.config.psd1') | Should Be $false
        @(Get-ChildItem -LiteralPath (Join-Path $toolRoot 'Tiering') -Filter '*.ps1' -ErrorAction SilentlyContinue).Count | Should Be 0
    }

    It 'has valid syntax for each changed engine component' {
        foreach ($relativePath in 'Invoke-MATI.ps1', 'Engine\Initialize-MATIEngine.ps1', 'Engine\Get-MATISummarySnapshot.ps1') {
            $tokens = $null
            $parseErrors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $toolRoot $relativePath), [ref]$tokens, [ref]$parseErrors)
            @($parseErrors).Count | Should Be 0
        }
    }
}

Describe 'MATI detection output isolation' {
    function Test-MATIWinPSCompat { return $false }
    function Get-ADForest {
        [CmdletBinding()]
        param($Identity)
        throw 'AD access is forbidden in this test.'
    }
    function Get-ADDomain {
        [CmdletBinding()]
        param($Identity, $Server)
        throw 'AD access is forbidden in this test.'
    }
    function Get-ADRootDSE {
        [CmdletBinding()]
        param($Server)
        throw 'AD access is forbidden in this test.'
    }

    It 'keeps ThreatDetection output paths regardless of a legacy global mode' {
        . (Join-Path $toolRoot 'Engine\Initialize-MATIEngine.ps1')
        $isolatedRoot = Join-Path $TestDrive 'MATI'
        foreach ($directory in 'Config', 'Models', 'Collectors', 'Rules') {
            New-Item -ItemType Directory -Path (Join-Path $isolatedRoot $directory) -Force | Out-Null
        }
        Copy-Item -LiteralPath (Join-Path $toolRoot 'Config\MATI.config.psd1') -Destination (Join-Path $isolatedRoot 'Config')
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADForest { [pscustomobject]@{ Name = 'lab.test'; RootDomain = 'lab.test'; Domains = @('lab.test') } }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'lab.test' } }
        Mock Get-ADRootDSE { [pscustomobject]@{ DefaultNamingContext = 'DC=lab,DC=test' } }
        Mock Write-Host {}
        $previousMode = Get-Variable -Name MATIMode -Scope Global -ErrorAction SilentlyContinue
        try {
            $global:MATIMode = 'TieringModel'
            $context = Initialize-MATIEngine -RootPath $isolatedRoot -TargetForest 'lab.test'
            $context.OutputRoot.StartsWith((Join-Path $isolatedRoot 'Outputs\ThreatDetection\Output_')) | Should Be $true
            foreach ($path in $context.CsvDir, $context.HtmlDir, $context.JsonDir) {
                Test-Path -LiteralPath $path -PathType Container | Should Be $true
            }
            $context.Config['_TargetForest'] | Should Be 'lab.test'
        }
        finally {
            if ($previousMode) {
                $global:MATIMode = $previousMode.Value
            } else {
                Remove-Variable -Name MATIMode -Scope Global
            }
        }
    }
}
