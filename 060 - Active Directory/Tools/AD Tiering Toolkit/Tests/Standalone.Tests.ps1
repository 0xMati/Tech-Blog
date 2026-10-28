$toolRoot = Split-Path -Parent $PSScriptRoot

Describe 'ADTT standalone package' {
    BeforeEach {
        $isolatedRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $isolatedRoot | Out-Null
        foreach ($item in 'Config', 'Engine', 'Tiering', 'Invoke-ADTT.ps1') {
            Copy-Item -LiteralPath (Join-Path $toolRoot $item) -Destination $isolatedRoot -Recurse
        }
        . (Join-Path $isolatedRoot 'Tiering\Invoke-ADTTMenu.ps1')
        Mock Write-Host {}
    }

    It 'parses every PowerShell source and configuration file' {
        $failures = @(
            Get-ChildItem -LiteralPath $toolRoot -Recurse -File |
                Where-Object Extension -in '.ps1', '.psd1' |
                ForEach-Object {
                    $tokens = $null
                    $parseErrors = $null
                    $null = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
                    $parseErrors
                }
        )
        $failures.Count | Should Be 0
    }

    It 'loads all modules and quits without MATI or an AD connection' {
        Mock Read-Host { 'Q' }
        { Invoke-ADTTMenu -RootPath $isolatedRoot } | Should Not Throw
        Assert-MockCalled Read-Host -Times 1 -Exactly -Scope It
    }

    It 'fails explicitly when the configuration is missing' {
        { Invoke-ADTTMenu -RootPath $isolatedRoot -ConfigPath (Join-Path $isolatedRoot 'missing.psd1') } |
            Should Throw 'Tiering configuration not found'
    }

    It 'fails explicitly when a required standalone helper is missing' {
        Remove-Item -LiteralPath (Join-Path $isolatedRoot 'Engine\Get-ADTTSummarySnapshot.ps1')
        { Invoke-ADTTMenu -RootPath $isolatedRoot } | Should Throw 'Tiering module not found'
    }

    It 'routes every phase with the standalone root and selected configuration' {
        $customConfig = Join-Path $isolatedRoot 'custom.psd1'
        Set-Content -LiteralPath $customConfig -Value "@{ Marker = 'custom-config' }"
        foreach ($phase in 0..9) {
            $name = if ($phase -eq 0) { 'Invoke-ADTTDiscovery' } else { "Invoke-ADTTPhase$phase" }
            $stub = @'
function __NAME__ {
    param($RootPath, $TieringConfig, $OutputDir)
    [pscustomobject]@{
        Phase = __PHASE__
        RootPath = $RootPath
        OutputDir = $OutputDir
        Marker = $TieringConfig.Marker
    }
}
'@
            $stub = $stub.Replace('__NAME__', $name).Replace('__PHASE__', [string]$phase)
            Set-Content -LiteralPath (Join-Path $isolatedRoot "Tiering\$name.ps1") -Value $stub
        }
        $script:phaseChoices = [System.Collections.Generic.Queue[string]]::new()
        foreach ($choice in @('invalid', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'Q')) {
            $script:phaseChoices.Enqueue($choice)
        }
        Mock Read-Host { $script:phaseChoices.Dequeue() }

        $results = @(Invoke-ADTTMenu -RootPath $isolatedRoot -ConfigPath $customConfig)

        ($results.Phase -join ',') | Should Be '0,1,2,3,4,5,6,7,8,9'
        foreach ($result in $results) {
            $result.RootPath | Should Be $isolatedRoot
            $result.Marker | Should Be 'custom-config'
            $result.OutputDir.StartsWith((Join-Path $isolatedRoot 'Outputs\Tiering\')) | Should Be $true
        }
    }

    It 'preserves the legacy phase 1 state filename in all consumers' {
        foreach ($phase in 1, 3, 4, 5, 6, 7) {
            $source = Get-Content -LiteralPath (Join-Path $isolatedRoot "Tiering\Invoke-ADTTPhase$phase.ps1") -Raw
            $source.Contains('Outputs\Tiering\MATI-Tiering-Phase1-Latest.json') | Should Be $true
        }
    }
}

Describe 'ADTT discovery summary' {
    BeforeEach {
        . (Join-Path $toolRoot 'Engine\Get-ADTTSummarySnapshot.ps1')
        $discovery = @{
            Forest = @{ DomainCount = 1; SiteCount = 1 }
            Domains = @('lab.test')
            DirectoryCounts = @{ Users = 10; Groups = 5 }
            ComputersByTier = @{ Tier0 = @('dc1'); Tier1 = @('server1'); Tier2 = @(); Unclassified = @() }
            PrivilegedAccounts = @{
                'LAB\Domain Admins' = @(
                    @{ SamAccountName = 'admin1' }
                    @{ SamAccountName = 'admin1' }
                    @{ SamAccountName = 'admin2' }
                )
                'LAB\Enterprise Admins' = @(@{ SamAccountName = 'admin1' })
            }
            ServiceAccountsInDA = @()
            ManagedServiceAccounts = @{ GMSA = @('gmsa1'); MSA = @() }
            AdminCountOrphans = @()
            Trusts = @()
            DomainControllers = @('dc1')
            OUStructure = @('OU=Tier 0,DC=lab,DC=test')
            GPOs = @()
        }
    }

    It 'preserves counts, deduplication and threshold colors' {
        $summary = Get-ADTTSummarySnapshot -Discovery $discovery
        $summary.Environment.Computers | Should Be 2
        $summary.Environment.Users | Should Be 10
        $summary.Environment.Groups | Should Be 5
        $summary.IdentityAccess.DomainAdmins.Count | Should Be 2
        $summary.IdentityAccess.DomainAdmins.Dot | Should Be 'green'
        $summary.IdentityAccess.EnterpriseAdmins.Count | Should Be 1
        $summary.IdentityAccess.GMSA.Dot | Should Be 'green'
        $summary.Infrastructure.DomainControllers | Should Be 1
    }

    It 'preserves the unsafe-trust and service-account warnings' {
        $discovery.ServiceAccountsInDA = @('svc1')
        $discovery.Trusts = @([pscustomobject]@{ SIDFilteringQuarantined = $false; IntraForest = $false })
        $summary = Get-ADTTSummarySnapshot -Discovery $discovery
        $summary.IdentityAccess.ServiceAccountsInDA.Dot | Should Be 'red'
        $summary.Trusts.UnsafeTrusts.Count | Should Be 1
        $summary.Trusts.TrustRelationships.Dot | Should Be 'red'
    }

    It 'renders an ADTT discovery report without the MATI engine' {
        . (Join-Path $toolRoot 'Tiering\Export-TieringDiscoveryHtml.ps1')
        $discovery.Timestamp = '2026-10-26 12:00:00'
        $discovery.Forest.Name = 'lab.test'
        $discovery.Domains = @()
        $discovery.ComputersByTier = @{ Tier0 = @(); Tier1 = @(); Tier2 = @(); Unclassified = @() }
        $discovery.DomainControllers = @()
        $discovery.DCConnectivity = @()
        $discovery.OUStructure = @()
        $discovery.GPOs = @()
        $discovery.GPOLinks = @()
        $discovery.ReviewQueue = @()
        $discovery.PriorityActions = @()
        $discovery.ClassificationSummary = @{}
        $discovery.AuthenticationControls = @{ Policies = @(); Silos = @(); Summary = @{} }
        $discovery.ExistingTiering = @{}
        $discovery.Readiness = @{}
        $discovery.Observations = @{}
        $outputPath = Join-Path $TestDrive 'ADTT-Discovery.html'

        Export-TieringDiscoveryHtml -Discovery $discovery -OutputPath $outputPath

        $html = Get-Content -LiteralPath $outputPath -Raw
        $html.Contains('<title>ADTT') | Should Be $true
        $html.Contains('Generated by ADTT') | Should Be $true
        $html.Contains('Generated by MATI') | Should Be $false
        $html.Contains('lab.test') | Should Be $true
    }
}

Describe 'ADTT standalone launcher' {
    function Get-ADDomain {
        [CmdletBinding()]
        param()
        throw 'AD access is forbidden in this test.'
    }

    BeforeEach {
        $isolatedRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $isolatedRoot | Out-Null
        foreach ($item in 'Config', 'Engine', 'Tiering', 'Invoke-ADTT.ps1') {
            Copy-Item -LiteralPath (Join-Path $toolRoot $item) -Destination $isolatedRoot -Recurse
        }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADDomain { [pscustomobject]@{ DNSRoot = 'lab.test' } }
        Mock Start-Transcript {}
        Mock Stop-Transcript {}
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Read-Host { 'Q' }
    }

    It 'opens and exits with mocked AD preflight and no deployment' {
        { & (Join-Path $isolatedRoot 'Invoke-ADTT.ps1') } | Should Not Throw
        Assert-MockCalled Get-ADDomain -Times 1 -Exactly -Scope It
        Assert-MockCalled Start-Transcript -Times 1 -Exactly -Scope It
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }

    It 'stops before querying AD when its module cannot load' {
        Mock Import-Module { throw 'synthetic missing module' } -ParameterFilter { $Name -eq 'ActiveDirectory' }
        { & (Join-Path $isolatedRoot 'Invoke-ADTT.ps1') } | Should Throw 'Cannot load the ActiveDirectory module'
        Assert-MockCalled Get-ADDomain -Times 0 -Exactly -Scope It
    }

    It 'closes the transcript when a selected phase fails' {
        Set-Content -LiteralPath (Join-Path $isolatedRoot 'Tiering\Invoke-ADTTPhase1.ps1') -Value @'
function Invoke-ADTTPhase1 {
    param($RootPath, $TieringConfig, $OutputDir)
    throw 'synthetic phase failure'
}
'@
        Mock Read-Host { '1' }
        { & (Join-Path $isolatedRoot 'Invoke-ADTT.ps1') } | Should Throw 'synthetic phase failure'
        Assert-MockCalled Stop-Transcript -Times 1 -Exactly -Scope It
    }
}
