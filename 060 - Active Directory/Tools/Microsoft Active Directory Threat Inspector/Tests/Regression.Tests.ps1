$toolRoot = Split-Path -Parent $PSScriptRoot
foreach ($file in @(
    'Models\Finding.ps1', 'Engine\MATI.Common.ps1', 'Engine\Invoke-MATICollectors.ps1',
    'Engine\Invoke-MATIRules.ps1', 'Engine\Get-MATISummarySnapshot.ps1',
    'Scoring\Get-MATIScore.ps1', 'Reporters\Export-MATIHtml.ps1', 'Reporters\Export-MATIJson.ps1', 'Reporters\Export-MATICsv.ps1',
    'Collectors\Get-MATIKerberosConfig.ps1', 'Collectors\Get-MATICertificateServices.ps1',
    'Collectors\Get-MATIProtocolConfig.ps1', 'Collectors\Get-MATIGPOSettings.ps1',
    'Collectors\Get-MATILegacyProtocolAudit.ps1', 'Collectors\Get-MATIPrivilegedAccounts.ps1',
    'Collectors\Get-MATISecurityConfig.ps1', 'Collectors\Get-MATIDNSConfig.ps1', 'Collectors\Get-MATITrustInfo.ps1'
)) { . (Join-Path $toolRoot $file) }

function New-MATIRegressionRule {
    param([scriptblock]$Condition = { param($Data, $Config) @() }, [string[]]$Collectors = @())
    @{ Id = 'TEST-001'; Title = 'Test rule'; Severity = 'High'; _Category = 'Kerberos'; _FileName = 'test.rule.ps1'; Collectors = $Collectors; Condition = $Condition }
}

function New-MATIRegressionContext {
    $directory = Join-Path $TestDrive 'reports'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $config = Import-PowerShellDataFile (Join-Path $toolRoot 'Config\MATI.config.psd1')
    $config['_TargetForest'] = 'lab.test'
    $config['_ForestCache'] = @{ Name = 'lab.test'; RootDomain = 'lab.test'; Domains = @('lab.test') }
    $config['_DirectoryServer'] = 'lab.test'
    $config['_DomainCache'] = @{ 'lab.test' = @{ DistinguishedName = 'DC=lab,DC=test'; DomainSID = 'S-1-5-21-1-2-3' } }
    $config['_RootDSECache'] = @{ configurationNamingContext = 'CN=Configuration,DC=lab,DC=test' }
    @{
        RootPath = $toolRoot; Config = $config; Rules = @((New-MATIRegressionRule))
        Collectors = @{}; DataCache = @{}; AssessmentScope = @{}
        Findings = [System.Collections.Generic.List[object]]::new()
        NotAssessedRules = [System.Collections.Generic.List[object]]::new()
        RuleResults = [System.Collections.Generic.List[object]]::new()
        CollectionIssues = [System.Collections.Generic.List[object]]::new()
        FailedCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        PartialCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        DCConnectivity = [System.Collections.Generic.List[object]]::new()
        WinPSCompat = $false; Timestamp = 'test'; HtmlDir = $directory; JsonDir = $directory; CsvDir = $directory
    }
}

function Get-ADUser { [CmdletBinding()]param($Filter, $LDAPFilter, $Identity, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-ADComputer { [CmdletBinding()]param($Filter, $Identity, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-ADObject { [CmdletBinding()]param($Filter, $Identity, $Server, $Properties, $SearchBase) throw 'Live AD access forbidden.' }
function Get-ADDomainController { [CmdletBinding()]param($Filter, $Server, $DomainName, [switch]$Discover) throw 'Live AD access forbidden.' }
function Get-ADGroup { [CmdletBinding()]param($Filter, $Identity, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-ADGroupMember { [CmdletBinding()]param($Identity, $Server, [switch]$Recursive) throw 'Live AD access forbidden.' }
function Get-ADServiceAccount { [CmdletBinding()]param($Filter, $Identity, $Properties, $SearchBase, $Server) throw 'Live AD access forbidden.' }
function Get-ADDomain { [CmdletBinding()]param($Server, $Identity) throw 'Live AD access forbidden.' }
function Get-ADForest { [CmdletBinding()]param($Server, $Identity) throw 'Live AD access forbidden.' }
function Get-ADRootDSE { [CmdletBinding()]param($Server) throw 'Live AD access forbidden.' }
function Get-ADOrganizationalUnit { [CmdletBinding()]param($Filter, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-ADAuthenticationPolicy { [CmdletBinding()]param($Filter, $Server) throw 'Live AD access forbidden.' }
function Get-ADAuthenticationPolicySilo { [CmdletBinding()]param($Filter, $Identity, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-ADTrust { [CmdletBinding()]param($Filter, $Server, $Properties) throw 'Live AD access forbidden.' }
function Get-DnsServerZone { [CmdletBinding()]param($ComputerName) throw 'Live DNS access forbidden.' }
function Get-DnsServerZoneAging { [CmdletBinding()]param($Name, $ComputerName) throw 'Live DNS access forbidden.' }
# Pester 3 cannot mock the native Get-Module PSEdition parameter on PowerShell 7.
function Get-Module {
    [CmdletBinding()]param($Name, [switch]$ListAvailable, [switch]$All)
    Microsoft.PowerShell.Core\Get-Module @PSBoundParameters
}
function auditpol { throw 'Live audit policy access forbidden.' }

Describe 'Honest assessment coverage and score' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'preserves a complete clean assessment as 100/A' {
        Set-MATIAssessmentScope -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $score = Get-MATIScore -EngineContext $ctx
        $score.Score | Should Be 100
        $score.Grade | Should Be 'A'
        $score.GradeIsProvisional | Should Be $false
        $score.AssessmentStatus | Should Be 'Complete'
        $score.FullyAssessedRuleCount | Should Be 1
    }

    It 'records rule exceptions instead of issuing a clean grade' {
        $ctx.Rules = @((New-MATIRegressionRule -Condition { throw 'synthetic failure' }))
        Invoke-MATIRules -EngineContext $ctx
        $score = Get-MATIScore -EngineContext $ctx
        $ctx.NotAssessedRules.Count | Should Be 1
        $ctx.RuleResults[0].Status | Should Be 'Error'
        $score.PartialAssessment | Should Be $true
        $score.Grade | Should Be 'N/A'
        $score.GradeIsProvisional | Should Be $false
        $score.EvaluatedRuleCount | Should Be 0
    }

    It 'treats a non-terminating rule error as an evaluation failure' {
        $ctx.Rules = @((New-MATIRegressionRule -Condition { Write-Error 'synthetic non-terminating error' }))
        Invoke-MATIRules -EngineContext $ctx
        $ctx.RuleResults[0].Status | Should Be 'Error'
    }

    It 'records invalid conditions as not assessed' {
        $ctx.Rules[0].Condition = 'not executable'
        Invoke-MATIRules -EngineContext $ctx
        $ctx.NotAssessedRules.Count | Should Be 1
        (Get-MATIScore -EngineContext $ctx).Grade | Should Be 'N/A'
    }

    It 'records missing collectors and skips dependent rules' {
        $ctx.Rules = @((New-MATIRegressionRule -Collectors Missing))
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.FailedCollectors.Contains('Missing') | Should Be $true
        $ctx.RuleResults[0].Status | Should Be 'NotAssessed'
        (Get-MATIScore -EngineContext $ctx).Grade | Should Be 'N/A'
    }

    It 'detects a collector swallowing a domain access failure' {
        $ctx.Rules = @((New-MATIRegressionRule -Collectors UserAccounts))
        $ctx.Collectors.UserAccounts = @{ Function = 'Get-MATIUserAccounts'; FilePath = Join-Path $toolRoot 'Collectors\Get-MATIUserAccounts.ps1' }
        Mock Get-ADUser { throw 'synthetic access denied' }
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.PartialCollectors.Contains('UserAccounts') | Should Be $true
        ($ctx.CollectionIssues.Count -gt 0) | Should Be $true
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be $score.CalculatedGrade
        $score.GradeIsProvisional | Should Be $true
    }

    It 'retains known findings and labels the calculated grade as provisional for partial data' {
        $ctx.DataCache.Partial = @(@{ Name = 'known risk' })
        $null = $ctx.PartialCollectors.Add('Partial')
        $ctx.Rules = @((New-MATIRegressionRule -Collectors Partial -Condition { @{ ObjectDN = 'CN=risk' } }))
        Invoke-MATIRules -EngineContext $ctx
        $ctx.Findings.Count | Should Be 1
        $ctx.RuleResults[0].Status | Should Be 'Partial'
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be $score.CalculatedGrade
        $score.GradeIsProvisional | Should Be $true
        $score.AssessmentStatus | Should Be 'Partial'
    }

    It 'keeps a calculated grade provisional when another rule fails' {
        $failed = New-MATIRegressionRule -Condition { throw 'synthetic failure' }
        $failed.Id = 'TEST-002'
        $ctx.Rules += $failed
        Invoke-MATIRules -EngineContext $ctx
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be 'A'
        $score.GradeIsProvisional | Should Be $true
        $score.EvaluatedRuleCount | Should Be 1
        $score.FullyAssessedRuleCount | Should Be 1
        $ctx.RuleResults[1].Status | Should Be 'Error'
    }

    It 'rejects empty selections and scoring before evaluation' {
        { Get-MATIScore -EngineContext $ctx } | Should Throw 'Rule execution results are incomplete'
        $ctx.Rules = @()
        { Set-MATIAssessmentScope -EngineContext $ctx } | Should Throw 'No active rules match'
        { Invoke-MATICollectors -EngineContext $ctx } | Should Throw 'empty rule selection'
        { Invoke-MATIRules -EngineContext $ctx } | Should Throw 'empty rule selection'
        { Get-MATIScore -EngineContext $ctx } | Should Throw 'empty rule selection'
    }

    It 'rejects unknown and disjoint filters' {
        { Set-MATIAssessmentScope -EngineContext $ctx -RulesOnly TYPO } | Should Throw 'Unknown or disabled rule'
        { Set-MATIAssessmentScope -EngineContext $ctx -CategoriesOnly TYPO } | Should Throw 'Unknown or disabled category'
        $other = New-MATIRegressionRule
        $other.Id = 'TEST-002'; $other._Category = 'ADCS'
        $ctx.Rules += $other
        { Set-MATIAssessmentScope -EngineContext $ctx -CategoriesOnly ADCS -RulesOnly TEST-001 } | Should Throw 'No active rules match'
    }

    It 'labels a deliberately filtered clean scan without a global grade' {
        Set-MATIAssessmentScope -EngineContext $ctx -RulesOnly TEST-001
        Invoke-MATIRules -EngineContext $ctx
        $score = Get-MATIScore -EngineContext $ctx
        $score.PartialAssessment | Should Be $false
        $score.AssessmentStatus | Should Be 'Filtered'
        $score.Grade | Should Be 'N/A'
        $score.GradeIsProvisional | Should Be $false
    }

    It 'keeps compatibility mode and excluded objects visible in coverage' {
        $ctx.WinPSCompat = $true
        $ctx.Config.Exclusions.ExcludedDNs = @('CN=excluded')
        Invoke-MATIRules -EngineContext $ctx
        $score = Get-MATIScore -EngineContext $ctx
        $score.PartialAssessment | Should Be $true
        $score.FilteredAssessment | Should Be $true
    }
}

Describe 'Stable exports and scoped history' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    foreach ($count in 0, 1, 2) {
        It "always exports a JSON array for $count findings" {
            Invoke-MATIRules -EngineContext $ctx
            for ($i = 0; $i -lt $count; $i++) {
                $ctx.Findings.Add((New-MATIFinding -Id "TEST-$i" -Category Kerberos -Severity High -Title 'Test'))
            }
            $null = Get-MATIScore -EngineContext $ctx
            Export-MATIJson -EngineContext $ctx
            $raw = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Findings_test.json') -Raw
            $raw.TrimStart().StartsWith('[') | Should Be $true
            @(ConvertFrom-Json -InputObject $raw).Count | Should Be $count
        }
    }

    It 'exports failed-rule details and visibly removes the HTML grade' {
        $ctx.Rules = @((New-MATIRegressionRule -Condition { throw '<b>synthetic error</b>' }))
        $ctx.Config.Scoring.BaseScore = 50
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATIHtml -EngineContext $ctx
        Export-MATIJson -EngineContext $ctx
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $html.Contains('Assessment coverage: Partial') | Should Be $true
        $html.Contains('Grade N/A') | Should Be $true
        $html.Contains('No rules evaluated - grade unavailable.') | Should Be $true
        $html.Contains('score-hero grade-a') | Should Be $false
        $html.Contains('&lt;b&gt;synthetic error&lt;/b&gt;') | Should Be $true
        $html.Contains('out of 50') | Should Be $true
        $html.Contains('Missing data must not be interpreted as zero') | Should Be $true
        $html.Contains('{{') | Should Be $false
        $json = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Report_test.json') -Raw | ConvertFrom-Json
        $json.coverage.notAssessedRules[0].Reason | Should Be '<b>synthetic error</b>'
        $json.coverage.evaluatedRules | Should Be 0
    }

    It 'exports the provisional grade consistently with a short small HTML note' {
        $ctx.WinPSCompat = $true
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATIHtml -EngineContext $ctx
        Export-MATIJson -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $json = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Report_test.json') -Raw | ConvertFrom-Json
        $csv = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_Assessment_test.csv')
        $html.Contains('Grade A') | Should Be $true
        $html.Contains('<p class="coverage-note coverage-grade-note">Provisional grade - partial assessment.</p>') | Should Be $true
        $html.Contains('.coverage-grade-note { font-size: 0.75rem; }') | Should Be $true
        $html.Contains('No global grade is assigned.') | Should Be $false
        $json.score.Grade | Should Be 'A'
        $json.score.GradeIsProvisional | Should Be $true
        $json.coverage.status | Should Be 'Partial'
        $csv.Grade | Should Be 'A'
        $csv.GradeIsProvisional | Should Be 'True'
    }

    It 'keeps deliberately filtered reports ungraded with a concise scope note' {
        Set-MATIAssessmentScope -EngineContext $ctx -RulesOnly TEST-001
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATIHtml -EngineContext $ctx
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $html.Contains('Grade N/A') | Should Be $true
        $html.Contains('Selected scope only - no global grade.') | Should Be $true
        $html.Contains('Provisional grade - partial assessment.') | Should Be $false
    }

    It 'fails explicitly when the HTML template is unavailable' {
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        $ctx.RootPath = $TestDrive
        { Export-MATIHtml -EngineContext $ctx } | Should Throw 'template'
    }

    It 'exports partial coverage and rule errors to CSV even with no findings' {
        $ctx.Rules = @((New-MATIRegressionRule -Condition { throw 'synthetic CSV failure' }))
        $ctx.CollectionIssues.Add([pscustomobject]@{ Collector = 'Test'; Scope = 'lab.test'; Message = 'read denied' })
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        $assessment = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_Assessment_test.csv')
        $assessment.AssessmentStatus | Should Be 'Partial'
        $assessment.Grade | Should Be 'N/A'
        $assessment.CollectionIssueCount | Should Be '1'
        $assessment.FullyAssessedRules | Should Be '0'
        $assessment.ToolVersion | Should Be $ctx.Config.General.Version
        $outcomes = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_RuleResults_test.csv')
        $outcomes.Status | Should Be 'Error'
        $outcomes.Reason | Should Be 'synthetic CSV failure'
        (Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_CollectionIssues_test.csv')).Message | Should Be 'read denied'
    }

    It 'preserves old history and records forest, scope, version and coverage' {
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        $ctx.RootPath = Join-Path $TestDrive 'history-test'
        $history = Join-Path $ctx.RootPath 'History'
        New-Item -ItemType Directory -Path $history -Force | Out-Null
        $legacy = Join-Path $history 'MATI_ScoreHistory.csv'
        'legacy-data' | Set-Content -LiteralPath $legacy
        Save-MATIScoreHistory -EngineContext $ctx
        $ctx.Config['_TargetForest'] = 'second.test'
        Save-MATIScoreHistory -EngineContext $ctx
        (Get-Content -LiteralPath $legacy) | Should Be 'legacy-data'
        $rows = @(Import-Csv -LiteralPath (Join-Path $history 'MATI_ScoreHistory_v2.csv'))
        $rows.Count | Should Be 2
        $rows[0].TargetForest | Should Be 'lab.test'
        $rows[1].TargetForest | Should Be 'second.test'
        $rows[0].ToolVersion | Should Be $ctx.Config.General.Version
        $rows[0].AssessmentStatus | Should Be 'Complete'
        ($rows[0].Scope | ConvertFrom-Json).Exclusions.DisabledRules.Count | Should Be 0
    }
}

Describe 'Collector output and trust contracts' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        $ctx.Config['_RootDSECache'].schemaNamingContext = 'CN=Schema,CN=Configuration,DC=lab,DC=test'
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-ADObject { @() }
        Mock Get-ADUser { @() }
        Mock Get-ADComputer { @() }
        Mock Get-ADDomainController { @() }
        Mock Get-ADServiceAccount { @() }
        Mock Get-ADOrganizationalUnit { @() }
        Mock Get-ADAuthenticationPolicy { @() }
        Mock Get-ADAuthenticationPolicySilo { @() }
        Mock Get-ADGroupMember { @() }
        Mock Get-ADGroup {
            if ($Filter) {
                [pscustomobject]@{ DistinguishedName = 'CN=One,DC=lab,DC=test'; MemberOf = @() }
                [pscustomobject]@{ DistinguishedName = 'CN=Two,DC=lab,DC=test'; MemberOf = @() }
            }
        }
        $script:trustAttributes = 8
        Mock Get-ADTrust {
            [pscustomobject]@{
                Target = 'other.test'; Direction = 'Bidirectional'; TrustType = 'Forest'
                TrustAttributes = $script:trustAttributes; IntraForest = $false
            }
        }
    }

    It 'returns exactly one SecurityConfig hashtable without null pipeline records' {
        $output = @(Get-MATISecurityConfig -Config $ctx.Config)
        $output.Count | Should Be 1
        ($output[0] -is [hashtable]) | Should Be $true
        $output[0].GroupCounts[0].Count | Should Be 2
    }

    It 'exports SecurityConfig datasets instead of Hashtable implementation properties' {
        $ctx.DataCache.SecurityConfig = Get-MATISecurityConfig -Config $ctx.Config
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        $path = Join-Path $ctx.CsvDir 'MATI_SecurityConfig_GroupCounts.csv'
        (Test-Path -LiteralPath $path) | Should Be $true
        (Import-Csv -LiteralPath $path)[0].Count | Should Be '2'
        (Test-Path -LiteralPath (Join-Path $ctx.CsvDir 'MATI_SecurityConfig.csv')) | Should Be $false
    }

    It 'preserves group cycle findings while suppressing DFS pipeline output' {
        Mock Get-ADGroup {
            if ($Filter) {
                [pscustomobject]@{ DistinguishedName = 'CN=One,DC=lab,DC=test'; MemberOf = @('CN=Two,DC=lab,DC=test') }
                [pscustomobject]@{ DistinguishedName = 'CN=Two,DC=lab,DC=test'; MemberOf = @('CN=One,DC=lab,DC=test') }
            }
        }
        $output = @(Get-MATISecurityConfig -Config $ctx.Config)
        $output.Count | Should Be 1
        @($output[0].GroupLoops).Count | Should Be 1
        $output[0].GroupLoops[0].CycleLength | Should Be 2
        ($output[0].GroupLoops[0].Groups -contains 'CN=One,DC=lab,DC=test') | Should Be $true
        ($output[0].GroupLoops[0].Groups -contains 'CN=Two,DC=lab,DC=test') | Should Be $true
    }

    It 'interprets NON_TRANSITIVE as disabling transitivity rather than enabling it' {
        foreach ($attributes in 0, 8, 32) {
            $script:trustAttributes = $attributes
            (Get-MATITrustInfo -Config $ctx.Config)[0].IsTransitive | Should Be $true
        }
        foreach ($attributes in 1, 9, 33) {
            $script:trustAttributes = $attributes
            (Get-MATITrustInfo -Config $ctx.Config)[0].IsTransitive | Should Be $false
        }
    }
}

Describe 'Native DNS zone policy collection' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Get-ADObject { @() }
        Mock Resolve-MATIGroupMembership { @{ Members = @(); Complete = $true } }
        Mock Get-Module { [pscustomobject]@{ Name = 'DnsServer' } } -ParameterFilter { $Name -eq 'DnsServer' }
        Mock Get-ADDomainController { [pscustomobject]@{ HostName = @('dc.lab.test') } }
        Mock Get-DnsServerZoneAging {
            [pscustomobject]@{
                AgingEnabled = $false; NoRefreshInterval = [timespan]::FromDays(7)
                RefreshInterval = [timespan]::FromDays(7); ScavengingServers = @()
            }
        }
        $script:dnsZone = [pscustomobject]@{
            ZoneName = 'lab.test'; ZoneType = 'Primary'; IsAutoCreated = $false
            IsDsIntegrated = $false; DynamicUpdate = 'None'
            SecureSecondaries = 'TransferAnyServer'; SecondaryServers = @()
        }
        Mock Get-DnsServerZone { $script:dnsZone }
        Mock Write-Warning {}
    }

    It 'reads AD integration from IsDsIntegrated rather than IsAutoCreated' {
        $readErrors = @()
        $result = Get-MATIDNSConfig -Config $ctx.Config -ErrorVariable readErrors
        if ($readErrors.Count) { throw ($readErrors | Out-String) }
        $result.Zones[0].IsADIntegrated | Should Be $false
        $script:dnsZone.IsDsIntegrated = $true
        (Get-MATIDNSConfig -Config $ctx.Config).Zones[0].IsADIntegrated | Should Be $true
    }

    It 'preserves each native transfer policy independently of the secondary server list' {
        foreach ($policy in 'NoTransfer', 'TransferAnyServer', 'TransferToZoneNameServer', 'TransferToSecureServers') {
            $script:dnsZone.SecureSecondaries = $policy
            foreach ($servers in @(@(), @('192.0.2.10'))) {
                $script:dnsZone.SecondaryServers = $servers
                (Get-MATIDNSConfig -Config $ctx.Config).Zones[0].ZoneTransferPolicy | Should Be $policy
            }
        }
    }

    It 'keeps missing and unrecognized policies explicitly unknown and emits a warning' {
        foreach ($policy in @($null, 'UnexpectedPolicy')) {
            $script:dnsZone.SecureSecondaries = $policy
            (Get-MATIDNSConfig -Config $ctx.Config).Zones[0].ZoneTransferPolicy | Should Be 'Unknown'
        }
        Assert-MockCalled Write-Warning -Times 2 -Exactly -Scope It
    }

    It 'does not invent AD integration when the native property is unavailable' {
        $script:dnsZone.PSObject.Properties.Remove('IsDsIntegrated')
        $script:dnsZone.SecureSecondaries = 'NoTransfer'
        $result = Get-MATIDNSConfig -Config $ctx.Config
        ($null -eq $result.Zones[0].IsADIntegrated) | Should Be $true
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It
    }
}

Describe 'Readable HTML assessment coverage' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Write-Host {}
        Mock Write-Warning {}
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
    }

    It 'groups exact duplicate messages per collector and scope while retaining occurrence counts' {
        foreach ($issue in @(
            @{ Collector = 'Accounts'; Scope = 'scope-one'; Message = 'read denied' },
            @{ Collector = 'Accounts'; Scope = 'scope-one'; Message = 'read denied' },
            @{ Collector = 'Accounts'; Scope = 'scope-two'; Message = 'read denied' },
            @{ Collector = 'Config'; Scope = 'scope-one'; Message = 'read denied' }
        )) { $ctx.CollectionIssues.Add([pscustomobject]$issue) }
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        $html.Contains('2 collectors with reported issues; 4 raw records, 3 distinct scoped messages') | Should Be $true
        ([regex]::Matches($html, 'class="coverage-details coverage-collector"')).Count | Should Be 2
        ([regex]::Matches($html, 'class="coverage-issue"')).Count | Should Be 3
        $html.Contains('2 occurrences') | Should Be $true
        $html.Contains('Scope: scope-one') | Should Be $true
        $html.Contains('Scope: scope-two') | Should Be $true
        ([regex]::IsMatch($html, '<details[^>]*\sopen(?:\s|=|>)')) | Should Be $false
    }

    It 'summarizes fifty partial rules without mixing them with errors or missing assessments' {
        $ctx.RuleResults.Clear()
        foreach ($i in 1..50) {
            $ctx.RuleResults.Add([pscustomobject]@{ Id = "PARTIAL-$i"; Status = 'Partial'; Reason = 'Incomplete collectors: Config' })
        }
        $ctx.RuleResults.Add([pscustomobject]@{ Id = 'ERROR-1'; Status = 'Error'; Reason = 'execution failed' })
        $ctx.RuleResults.Add([pscustomobject]@{ Id = 'MISSING-1'; Status = 'NotAssessed'; Reason = 'missing collector' })
        $ctx.Score.SelectedRuleCount = 52
        $ctx.Score.EvaluatedRuleCount = 51
        $ctx.Score.FullyAssessedRuleCount = 0
        $ctx.Score.PartialAssessment = $true
        $ctx.Score.AssessmentStatus = 'Partial'
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        ([regex]::Matches($html, 'class="coverage-details coverage-rule-group"')).Count | Should Be 3
        $html.Contains('50 rules') | Should Be $true
        $html.Contains('<strong>1</strong><span>Execution errors</span>') | Should Be $true
        $html.Contains('<strong>1</strong><span>Not assessed</span>') | Should Be $true
        $html.Contains('Partial rules may still report known findings; they are not execution errors.') | Should Be $true
        foreach ($id in 'PARTIAL-1', 'PARTIAL-50', 'ERROR-1', 'MISSING-1') {
            $html.Contains("<code>$id</code>") | Should Be $true
        }
    }

    It 'uses a readable full-scope summary instead of displaying empty JSON configuration' {
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        $html.Contains('Scope: all enabled rules. No configured exclusions.') | Should Be $true
        $html.Contains('No collection issues recorded.') | Should Be $true
        $html.Contains('<strong>1</strong><span>Fully assessed</span>') | Should Be $true
        $html.Contains('Selection and exclusions: {') | Should Be $false
        $html.Contains('No global grade is assigned.') | Should Be $false
    }

    It 'does not promote legacy foreign-principal diagnostics to a report-front warning' {
        $advice = Get-MATIADWSForeignPrincipalAdvice
        foreach ($collector in 'PrivilegedAccounts', 'SecurityConfig') {
            foreach ($i in 1..2) {
                $ctx.CollectionIssues.Add([pscustomobject]@{
                    Collector = $collector; Scope = 'Collector'; Message = "$($advice.Message) See $($advice.Reference)"
                })
            }
        }
        $before = ConvertTo-Json -InputObject @($ctx.CollectionIssues) -Depth 5 -Compress
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        ([regex]::Matches($html, 'class="coverage-warning coverage-adws-fsp-note"')).Count | Should Be 0
        $html.Contains('Why foreign-principal membership can remain incomplete') | Should Be $false
        $html.Contains('one-way trusts') | Should Be $true
        $html.Contains('Enterprise Admin rights in the local forest do not guarantee access') | Should Be $true
        $html.Contains('do not prove that a SID is orphaned or that a trust is broken') | Should Be $true
        $html.Contains('4 raw records, 2 distinct scoped messages') | Should Be $true
        (ConvertTo-Json -InputObject @($ctx.CollectionIssues) -Depth 5 -Compress) | Should Be $before
    }

    It 'supports foreign-principal warnings from earlier reports without inventing extra issue records' {
        $ctx.CollectionIssues.Add([pscustomobject]@{
            Collector = 'PrivilegedAccounts'; Scope = 'Collector'
            Message = "Foreign principal 'CN=S-1-5-21-4-5-6-500,CN=ForeignSecurityPrincipals,DC=lab,DC=test' retained in 'Administrators'; its external identity and any nested membership were not resolved."
        })
        (Get-MATIAssessmentCoverageHtml -EngineContext $ctx).Contains('coverage-adws-fsp-note') | Should Be $false
        $ctx.CollectionIssues.Count | Should Be 1
    }

    It 'does not show foreign-principal advice for clean or unrelated ADWS failures' {
        (Get-MATIAssessmentCoverageHtml -EngineContext $ctx).Contains('coverage-adws-fsp-note') | Should Be $false
        $ctx.CollectionIssues.Add([pscustomobject]@{
            Collector = 'SecurityConfig'; Scope = 'Collector'
            Message = 'Group membership enumeration failed for a local-only group: access denied.'
        })
        (Get-MATIAssessmentCoverageHtml -EngineContext $ctx).Contains('coverage-adws-fsp-note') | Should Be $false
    }

    It 'retains diagnostic guidance and its reference in JSON and CSV without changing coverage or findings' {
        $advice = Get-MATIADWSForeignPrincipalAdvice
        $message = "$($advice.Message) See $($advice.Reference)"
        $ctx.CollectionIssues.Add([pscustomobject]@{ Collector = 'Test'; Scope = 'Collector'; Message = $message })
        $null = $ctx.PartialCollectors.Add('Test')
        $ctx.Rules = @((New-MATIRegressionRule -Collectors Test))
        $ctx.DataCache.Test = @()
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        Export-MATIJson -EngineContext $ctx
        $csv = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_CollectionIssues_test.csv')
        $json = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Report_test.json') -Raw | ConvertFrom-Json
        $csv.Message | Should Be $message
        $json.coverage.collectionIssues[0].Message | Should Be $message
        $json.coverage.ruleResults[0].Status | Should Be 'Partial'
        $json.score.Grade | Should Be $json.score.CalculatedGrade
        $json.score.GradeIsProvisional | Should Be $true
        $json.summary.totalFindings | Should Be 0
    }

    It 'keeps one HTML report without adding a prominent external-membership inventory panel' {
        $ctx.DataCache.PrivilegedAccounts = @{ Groups = @([pscustomobject]@{
            GroupName = 'Administrators'; Domain = 'lab.test'; MembershipReadMethod = 'MemberLinks'
            DirectMembershipComplete = $true; DirectMemberCount = 8; KnownMemberCount = 6
            RecursiveMembershipComplete = $false
            DirectMemberDetails = @(
                [pscustomobject]@{ IsForeignSecurityPrincipal = $true; ExternalResolutionStatus = 'Resolved' },
                [pscustomobject]@{ IsForeignSecurityPrincipal = $true; ExternalResolutionStatus = 'Unresolved' },
                [pscustomobject]@{ IsForeignSecurityPrincipal = $true; ExternalResolutionStatus = 'TimedOut' },
                [pscustomobject]@{ IsForeignSecurityPrincipal = $true; ExternalResolutionStatus = 'Unresolved' }
            )
        }) }
        Export-MATIHtml -EngineContext $ctx
        Export-MATIHtml -EngineContext $ctx
        @(Get-ChildItem -LiteralPath $ctx.HtmlDir -Filter '*.html').Count | Should Be 1
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $html.Contains('Recovered privileged-group inventory') | Should Be $false
        ([regex]::Matches($html, 'class="coverage-details coverage-membership"')).Count | Should Be 0
    }

    It 'retains explicit selected scope and exclusions in collapsed human-readable details' {
        $ctx.AssessmentScope = @{ CategoriesOnly = @('ADCS'); DisabledRules = @('RULE-1') }
        $ctx.Config.Exclusions.DisabledRules = @('RULE-1')
        $ctx.Config.Exclusions.ExcludedSamAccountNames = @('svc<script>$')
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        $html.Contains('<summary>Selection and exclusions</summary>') | Should Be $true
        $html.Contains('Selected categories:</strong> ADCS') | Should Be $true
        ([regex]::Matches($html, 'RULE-1')).Count | Should Be 1
        $html.Contains('svc&lt;script&gt;$') | Should Be $true
        $html.Contains('No configured exclusions.') | Should Be $false
    }

    It 'escapes all displayed technical fields without mutating the source records' {
        $ctx.CollectionIssues.Add([pscustomobject]@{ Collector = '<collector>'; Scope = '<scope>'; Message = '<script>message</script>' })
        $ctx.RuleResults.Add([pscustomobject]@{ Id = '<rule>'; Status = 'Error'; Reason = '<b>reason</b>' })
        $before = ConvertTo-Json -InputObject @($ctx.CollectionIssues) -Depth 5 -Compress
        $html = Get-MATIAssessmentCoverageHtml -EngineContext $ctx
        foreach ($text in '&lt;collector&gt;', '&lt;scope&gt;', '&lt;script&gt;message&lt;/script&gt;', '&lt;rule&gt;', '&lt;b&gt;reason&lt;/b&gt;') {
            $html.Contains($text) | Should Be $true
        }
        (ConvertTo-Json -InputObject @($ctx.CollectionIssues) -Depth 5 -Compress) | Should Be $before
    }

    It 'keeps every raw CSV and JSON collection record while grouping only the HTML display' {
        foreach ($i in 1..2) {
            $ctx.CollectionIssues.Add([pscustomobject]@{ Collector = 'Test'; Scope = 'lab.test'; Message = 'read denied' })
        }
        $null = $ctx.PartialCollectors.Add('Test')
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATIHtml -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        Export-MATIJson -EngineContext $ctx
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $json = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Report_test.json') -Raw | ConvertFrom-Json
        ([regex]::Matches($html, 'class="coverage-issue"')).Count | Should Be 1
        $html.Contains('2 occurrences') | Should Be $true
        @(Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_CollectionIssues_test.csv')).Count | Should Be 2
        $json.coverage.collectionIssues.Count | Should Be 2
        $ctx.CollectionIssues.Count | Should Be 2
    }
}

Describe 'Localized identities and actual password policy coverage' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'detects renamed forest admin groups using the SID and configured thresholds' {
        $group = @{ GroupName = 'Renamed group'; SID = 'S-1-5-21-1-2-3-519'; MemberCount = 4; DirectMembers = @(); Domain = 'lab.test' }
        $data = @{ PrivilegedAccounts = @{ Groups = @($group) } }
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\PermanentEASAMembers.rule.ps1')
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 1
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\ExcessiveGroupMembers.rule.ps1')
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 1
        $ctx.Config.Thresholds.PrivilegedGroupMaxMembers['Enterprise Admins'] = 0
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 1
    }

    It 'uses SIDs in the shared environment snapshot' {
        $ctx.DataCache.PrivilegedAccounts = @{
            Groups = @(@{ GroupName = 'Renamed group'; SID = 'S-1-5-21-1-2-3-512'; MemberDetails = @(@{ SamAccountName = 'admin' }) })
            Accounts = @()
        }
        (Get-MATISummarySnapshot -EngineContext $ctx).Environment.DomainAdmins.Count | Should Be 1
    }

    It 'detects renamed domain and builtin groups without requiring a canonical name' {
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\PermanentPrivilegedMembers.rule.ps1')
        foreach ($sid in 'S-1-5-21-1-2-3-512', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551') {
            $group = @{ SID = $sid; GroupName = 'Renamed privileged group'; MemberCount = 1; DirectMembers = @(); Domain = 'lab.test' }
            $findings = @(& $rule.Condition @{ PrivilegedAccounts = @{ Groups = @($group) } } @{})
            $findings.Count | Should Be 1
            $findings[0].Details.GroupName | Should Be 'Renamed privileged group'
            ($findings[0].Details.GroupKey -ne $group.GroupName) | Should Be $true
        }
    }

    It 'requests and exposes the server-calculated resultant PSO on privileged users' {
        Mock Get-ADDomain { [pscustomobject]@{ DomainSID = 'S-1-5-21-1-2-3' } }
        Mock Get-ADGroup { [pscustomobject]@{ Name = 'Renamed'; SID = $Identity; DistinguishedName = 'CN=group,DC=lab,DC=test'; Members = @('CN=admin,DC=lab,DC=test') } }
        Mock Get-ADObject { [pscustomobject]@{ Name = 'admin'; sAMAccountName = 'admin'; objectClass = 'user'; DistinguishedName = 'CN=admin,DC=lab,DC=test'; objectSid = 'S-1-5-21-1-2-3-1000' } }
        Mock Get-ADGroupMember { [pscustomobject]@{ Name = 'admin'; SamAccountName = 'admin'; objectClass = 'user'; DistinguishedName = 'CN=admin,DC=lab,DC=test' } }
        Mock Get-ADUser { [pscustomobject]@{ SamAccountName = 'admin'; DistinguishedName = 'CN=admin,DC=lab,DC=test'; Enabled = $true; 'msDS-ResultantPSO' = 'CN=AdminPolicy,DC=lab,DC=test' } }
        $data = Get-MATIPrivilegedAccounts -Config $ctx.Config
        $data.Accounts[0].ResultantPasswordPolicy | Should Be 'CN=AdminPolicy,DC=lab,DC=test'
        Assert-MockCalled Get-ADUser -Times 1 -ParameterFilter { $Properties -contains 'msDS-ResultantPSO' }
    }

    It 'does not confuse a standard-user FGPP with privileged-account coverage' {
        $rule = & (Join-Path $toolRoot 'Rules\PasswordPolicy\NoFGPPPrivileged.rule.ps1')
        $account = @{ Domain = 'lab.test'; Enabled = $true; SamAccountName = 'admin'; ResultantPasswordPolicy = $null }
        $data = @{
            PasswordPolicy = @{ DefaultPolicies = @(@{ Domain = 'lab.test'; MinPasswordLength = 8 }); FineGrainedPolicies = @(@{ Name = 'Standard only' }) }
            PrivilegedAccounts = @{ Accounts = @($account) }
        }
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 1
        $account.ResultantPasswordPolicy = 'CN=AdminPolicy'
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 0
    }

    It 'does not recommend authentication silos below the supported DFL' {
        $rule = & (Join-Path $toolRoot 'Rules\Hardening\AuthSilosNotDeployed.rule.ps1')
        $domain = @{ DomainModeNumeric = 4 }
        $data = @{ DomainInfo = @{ Domains = @($domain); Forest = @{ Name = 'lab.test'; RootDomain = 'lab.test' } }; SecurityConfig = @{ AuthSilos = @(); AuthPolicies = @() } }
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 0
        $domain.DomainModeNumeric = 6
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 1
    }

    It 'collects Kerberos-only constrained delegation for users and computers' {
        Mock Get-ADUser {
            if ($Identity -eq 'krbtgt') { return [pscustomobject]@{ SamAccountName = 'krbtgt'; PasswordLastSet = Get-Date } }
            if ($Filter -like '*msDS-AllowedToDelegateTo*') { return [pscustomobject]@{ SamAccountName = 'svc'; DistinguishedName = 'CN=svc'; Enabled = $true; 'msDS-AllowedToDelegateTo' = @('ldap/dc1.lab.test') } }
        }
        Mock Get-ADComputer {
            if ($Filter -like '*msDS-AllowedToDelegateTo*') { return [pscustomobject]@{ SamAccountName = 'comp$'; DistinguishedName = 'CN=comp'; Enabled = $true; 'msDS-AllowedToDelegateTo' = @('ldap/dc1.lab.test') } }
        }
        Mock Get-ADObject {}
        $kerberos = Get-MATIKerberosConfig -Config $ctx.Config
        $kerberos.DelegationAccounts.Count | Should Be 2
        $rule = & (Join-Path $toolRoot 'Rules\Delegation\ConstrainedDelegationToDC.rule.ps1')
        @(& $rule.Condition @{ KerberosConfig = $kerberos; DCInfo = @(@{ Name = 'dc1'; HostName = 'dc1.lab.test' }) } $ctx.Config).Count | Should Be 2
    }
}

Describe 'Resilient group membership collection' {
    function Get-MATIMembershipRegressionBlock {
        param([string]$FileName, [type]$StatementType, [string]$Marker)
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $toolRoot "Collectors\$FileName"), [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors.Count) { throw $parseErrors[0].Message }
        $statement = $ast.FindAll({
            param($node)
            $node -is $StatementType -and $node.Extent.Text.Contains($Marker)
        }, $true) | Sort-Object { $_.Extent.Text.Length } | Select-Object -First 1
        if (-not $statement) { throw "Collector statement not found: $Marker" }
        return [scriptblock]::Create($statement.Extent.Text)
    }

    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        $script:membershipRootDN = 'CN=Administrators,CN=Builtin,DC=lab,DC=test'
        $script:membershipUserDN = 'CN=admin,DC=lab,DC=test'
        $script:membershipNestedDN = 'CN=Nested,DC=child,DC=lab,DC=test'
        $script:membershipChildUserDN = 'CN=childadmin,DC=child,DC=lab,DC=test'
        $script:membershipForeignDN = 'CN=S-1-5-21-4-5-6-500,CN=ForeignSecurityPrincipals,DC=lab,DC=test'
        $script:membershipManagedDN = 'CN=svc$,CN=Managed Service Accounts,DC=lab,DC=test'
        $ctx.Config['_ForestCache'].Domains = @('lab.test','child.lab.test')
        $ctx.Config['_DomainCache']['child.lab.test'] = @{ DomainSID = 'S-1-5-21-7-8-9'; DistinguishedName = 'DC=child,DC=lab,DC=test' }
        $script:membershipGroups = @{
            $membershipRootDN = @($membershipUserDN, $membershipNestedDN, $membershipForeignDN, $membershipManagedDN)
            $membershipNestedDN = @($membershipUserDN, $membershipChildUserDN, $membershipRootDN)
        }
        $script:membershipObjects = @{}
        foreach ($entry in @(
            @($membershipUserDN, 'admin', 'user', 'S-1-5-21-1-2-3-1000'),
            @($membershipChildUserDN, 'childadmin', 'user', 'S-1-5-21-7-8-9-1000'),
            @($membershipNestedDN, 'Nested', 'group', 'S-1-5-21-7-8-9-1001'),
            @($membershipForeignDN, 'S-1-5-21-4-5-6-500', 'foreignSecurityPrincipal', 'S-1-5-21-4-5-6-500'),
            @($membershipManagedDN, 'svc$', 'msDS-GroupManagedServiceAccount', 'S-1-5-21-1-2-3-1002')
        )) {
            $membershipObjects[$entry[0]] = [pscustomobject]@{
                DistinguishedName = $entry[0]; Name = $entry[1]; sAMAccountName = $entry[1]
                objectClass = $entry[2]; objectSid = $entry[3]; SID = $entry[3]
            }
        }
        $script:membershipNative = $false
        $script:membershipObjectFailures = @()
        $script:membershipGroupFailures = @()
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status = 'NotAttempted'; ResolvedName = $null; DistinguishedName = $null
                ObjectClass = $null; Domain = $null; Error = 'Synthetic external identity unavailable'; Attempts = @()
                OutsideAssessmentScope = $true
            }
        }
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-ADGroupMember {
            if ($script:membershipNative) { return $script:membershipObjects[$script:membershipUserDN] }
            throw 'synthetic ADWS internal error'
        }
        Mock Get-ADGroup {
            if ($Server -eq 'child.lab.test' -and $Identity -like 'S-1-*') {
                return [pscustomobject]@{ Name='ChildEmpty'; SID=$Identity; DistinguishedName="CN=$Identity,DC=child,DC=lab,DC=test"; Members=@() }
            }
            $dn = if ($Identity -in @('S-1-5-32-544', 'Denied RODC Password Replication Group')) { $script:membershipRootDN } else { $Identity }
            if ($dn -in $script:membershipGroupFailures) { throw 'synthetic group read failure' }
            if ($script:membershipGroups.ContainsKey($dn)) {
                return [pscustomobject]@{
                    Name = 'group'; SID = 'S-1-5-32-544'; DistinguishedName = $dn
                    Members = $script:membershipGroups[$dn]
                }
            }
            if ($Identity -like 'S-1-*') {
                return [pscustomobject]@{
                    Name = $Identity; SID = $Identity
                    DistinguishedName = "CN=$Identity,DC=lab,DC=test"; Members = @()
                }
            }
            if ($Identity -like 'CN=S-1-*,DC=lab,DC=test') {
                return [pscustomobject]@{
                    Name = $Identity; SID = $null; DistinguishedName = $Identity; Members = @()
                }
            }
            throw "synthetic unknown group: $Identity"
        }
        Mock Get-ADObject {
            if ($Identity -in $script:membershipObjectFailures) { throw 'synthetic member read failure' }
            if ($script:membershipObjects.ContainsKey($Identity)) { return $script:membershipObjects[$Identity] }
            throw "synthetic unknown member: $Identity"
        }
        Mock Get-ADDomain { [pscustomobject]@{ DomainSID = 'S-1-5-21-1-2-3' } }
        Mock Get-ADUser {
            [pscustomobject]@{
                SamAccountName = 'admin'; DistinguishedName = if ($Identity) { $Identity } else { 'CN=orphan,DC=lab,DC=test' }
                Enabled = $true; SID = 'S-1-5-21-1-2-3-1000'
            }
        }
    }

    It 'preserves the successful ADWS path without extra directory reads' {
        $script:membershipNative = $true
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive
        $result.ReadMethod | Should Be 'ADWS'
        $result.Complete | Should Be $true
        $result.Members.Count | Should Be 1
        $result.Members[0].Name | Should Be 'admin'
        Assert-MockCalled Get-ADGroup -Times 0 -Scope It
        Assert-MockCalled Get-ADObject -Times 0 -Scope It
    }

    It 'retains direct users groups managed accounts and foreign SID identities after ADWS failure' {
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $result.ReadMethod | Should Be 'MemberLinks'
        $result.Members.Count | Should Be 4
        @($result.Members | Where-Object objectClass -eq 'group').Count | Should Be 1
        @($result.Members | Where-Object objectClass -eq 'msDS-GroupManagedServiceAccount').Count | Should Be 1
        ($result.Members | Where-Object objectClass -eq 'foreignSecurityPrincipal').SID | Should Be 'S-1-5-21-4-5-6-500'
        $result.Complete | Should Be $false
        ($result.UnresolvedMembers -contains $membershipForeignDN) | Should Be $true
        Assert-MockCalled Write-Warning -Scope It -ParameterFilter { $Message -like '*does not establish that the SID is orphaned*' }
    }

    It 'emits the foreign-principal diagnostic once per fallback lookup including unreadable FSP objects' {
        $script:membershipObjectFailures = @($membershipForeignDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive
        $result.Complete | Should Be $false
        $result.ReadMethod | Should Be 'MemberLinks'
        Assert-MockCalled Write-Warning -Times 1 -Exactly -Scope It -ParameterFilter {
            $Message -like 'ADWS foreign-principal resolution:*' -and
            $Message -like '*one-way trusts*' -and
            $Message -like '*get-adgroupmember-error-remote-forest-members*'
        }
    }

    It 'does not emit foreign-principal advice for a local-only fallback' {
        $script:membershipGroups[$membershipRootDN] = @($membershipUserDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $result.Complete | Should Be $true
        Assert-MockCalled Write-Warning -Times 0 -Scope It -ParameterFilter {
            $Message -like 'ADWS foreign-principal resolution:*'
        }
    }

    It 'does not emit foreign-principal advice when ADWS successfully returns a foreign principal' {
        Mock Get-ADGroupMember { $script:membershipObjects[$script:membershipForeignDN] }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $result.Complete | Should Be $true
        $result.ReadMethod | Should Be 'ADWS'
        Assert-MockCalled Write-Warning -Times 0 -Scope It
        Assert-MockCalled Get-ADGroup -Times 0 -Scope It
    }

    It 'distinguishes a successfully read empty group from unreadable membership' {
        $script:membershipGroups[$membershipRootDN] = @()
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $result.Members.Count | Should Be 0
        $result.UnresolvedMembers.Count | Should Be 0
        $result.Complete | Should Be $true
        $result.ReadMethod | Should Be 'MemberLinks'
    }

    It 'expands cross-domain groups while deduplicating users and stopping cycles' {
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive
        $result.Members.Count | Should Be 4
        @($result.Members | Where-Object objectClass -eq 'group').Count | Should Be 0
        @($result.Members | Where-Object DistinguishedName -eq $membershipUserDN).Count | Should Be 1
        @($result.Members | Where-Object DistinguishedName -eq $membershipChildUserDN).Count | Should Be 1
        Assert-MockCalled Get-ADGroup -Scope It -Times 1 -ParameterFilter {
            $Identity -eq $script:membershipNestedDN -and $Server -eq 'child.lab.test'
        }
    }

    It 'does not expand nested groups for a direct membership request' {
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        @($result.Members | Where-Object objectClass -eq 'group').Count | Should Be 1
        Assert-MockCalled Get-ADGroup -Times 0 -Scope It -ParameterFilter { $Identity -eq $script:membershipNestedDN }
    }

    It 'keeps unresolved member links instead of turning read errors into absent members' {
        $script:membershipObjectFailures = @($membershipUserDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $result.Members.Count | Should Be 4
        $unknown = $result.Members | Where-Object DistinguishedName -eq $membershipUserDN
        $unknown.objectClass | Should Be 'unknown'
        $unknown.MembershipResolved | Should Be $false
        ($result.UnresolvedMembers -contains $membershipUserDN) | Should Be $true
        $result.Complete | Should Be $false
    }

    It 'retains the SID from a foreign member link even when its local object cannot be read' {
        $script:membershipObjectFailures = @($membershipForeignDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        $foreign = $result.Members | Where-Object DistinguishedName -eq $membershipForeignDN
        $foreign.SID | Should Be 'S-1-5-21-4-5-6-500'
        $foreign.objectClass | Should Be 'foreignSecurityPrincipal'
        $foreign.MembershipResolved | Should Be $false
        $result.Complete | Should Be $false
    }

    It 'normalizes deserialized SID values returned through Windows PowerShell compatibility' {
        $script:membershipObjects[$membershipForeignDN].objectSid = [pscustomobject]@{
            Value = 'S-1-5-21-4-5-6-500'
        }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test'
        ($result.Members | Where-Object DistinguishedName -eq $membershipForeignDN).SID | Should Be 'S-1-5-21-4-5-6-500'
    }

    It 'exposes a failed nested-group expansion without discarding other members' {
        $script:membershipGroupFailures = @($membershipNestedDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive
        $result.Members.Count | Should Be 4
        ($result.UnresolvedMembers -contains $membershipNestedDN) | Should Be $true
        ($result.Members | Where-Object DistinguishedName -eq $membershipNestedDN).MembershipResolved | Should Be $false
        $result.Complete | Should Be $false
    }

    It 'surfaces failure of both enumeration and the root member-link read' {
        $script:membershipGroupFailures = @($membershipRootDN)
        { Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' } | Should Throw 'synthetic group read failure'
        Assert-MockCalled Write-Warning -Times 0 -Scope It
    }

    It 'keeps an explicitly targeted DC for local members and selects the owning domain for other members' {
        $null = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'dc1.lab.test' -Recursive
        Assert-MockCalled Get-ADObject -Scope It -Times 1 -ParameterFilter {
            $Identity -eq $script:membershipUserDN -and $Server -eq 'dc1.lab.test'
        }
        Assert-MockCalled Get-ADObject -Scope It -Times 1 -ParameterFilter {
            $Identity -eq $script:membershipChildUserDN -and $Server -eq 'child.lab.test'
        }
    }

    It 'preserves all eight raw direct links and restores foreign-principal and managed-account findings' {
        $emptyGroupDN = 'CN=EmptyAdmins,DC=lab,DC=test'
        $script:membershipGroups[$emptyGroupDN] = @()
        $script:membershipGroups[$membershipRootDN] += $emptyGroupDN
        $script:membershipObjects[$emptyGroupDN] = [pscustomobject]@{
            Name = 'EmptyAdmins'; sAMAccountName = 'EmptyAdmins'; DistinguishedName = $emptyGroupDN
            objectClass = 'group'; objectSid = 'S-1-5-21-1-2-3-519'
        }
        foreach ($rid in 1001..1003) {
            $sid = "S-1-5-21-4-5-6-$rid"
            $dn = "CN=$sid,CN=ForeignSecurityPrincipals,DC=lab,DC=test"
            $script:membershipGroups[$membershipRootDN] += $dn
            $script:membershipObjects[$dn] = [pscustomobject]@{
                Name = $sid; sAMAccountName = $null; DistinguishedName = $dn
                objectClass = 'foreignSecurityPrincipal'; objectSid = $sid
            }
        }
        $data = Get-MATIPrivilegedAccounts -Config $ctx.Config
        $group = $data.Groups | Where-Object DistinguishedName -eq $membershipRootDN
        $group.DirectMemberCount | Should Be 8
        $group.DirectMembers.Count | Should Be 8
        $group.DirectMemberDetails.Count | Should Be 8
        ($null -eq $group.MemberCount) | Should Be $true
        $group.KnownMemberCount | Should Be 3
        $group.MembershipComplete | Should Be $true
        $group.UnresolvedMembers.Count | Should Be 0
        $group.ExternalPrincipalCount | Should Be 4
        $group.MembershipReadMethod | Should Be 'ScopedMemberLinks'
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\ForeignPrincipalInPrivilegedGroup.rule.ps1')
        @(& $rule.Condition @{ PrivilegedAccounts = $data } $ctx.Config).Count | Should Be 4
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\ManagedServiceInPrivilegedGroup.rule.ps1')
        @(& $rule.Condition @{ PrivilegedAccounts = $data } $ctx.Config).Count | Should Be 1
    }

    It 'retains external findings without making target-forest collection partial' {
        $ctx.Rules = @((New-MATIRegressionRule -Collectors PrivilegedAccounts -Condition {
            param($Data, $Config)
            $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\ForeignPrincipalInPrivilegedGroup.rule.ps1')
            & $rule.Condition $Data $Config
        }))
        $ctx.Collectors.PrivilegedAccounts = @{
            Function = 'Get-MATIPrivilegedAccounts'
            FilePath = Join-Path $toolRoot 'Collectors\Get-MATIPrivilegedAccounts.ps1'
        }
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.PartialCollectors.Contains('PrivilegedAccounts') | Should Be $false
        $ctx.RuleResults[0].Status | Should Be 'Evaluated'
        $ctx.Findings.Count | Should Be 1
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be $score.CalculatedGrade
        $score.GradeIsProvisional | Should Be $false
    }

    It 'recovers a local-only group without making recovered ADWS errors global coverage failures' {
        $script:membershipGroups[$membershipRootDN] = @($membershipUserDN)
        $ctx.Rules = @((New-MATIRegressionRule -Collectors PrivilegedAccounts -Condition {
            param($Data, $Config)
            @($Data.PrivilegedAccounts.Accounts | Where-Object Enabled -eq $false)
        }))
        $ctx.Collectors.PrivilegedAccounts = @{
            Function = 'Get-MATIPrivilegedAccounts'
            FilePath = Join-Path $toolRoot 'Collectors\Get-MATIPrivilegedAccounts.ps1'
        }
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.PartialCollectors.Count | Should Be 0
        @($ctx.CollectionIssues | Where-Object AffectsCoverage -ne $false).Count | Should Be 0
        $ctx.CollectionIssues.Count | Should Be 0
        Assert-MockCalled Get-ADGroupMember -Times 0 -Exactly -Scope It
        $ctx.RuleResults[0].Status | Should Be 'Evaluated'
        (Get-MATIScore -EngineContext $ctx).Grade | Should Be 'A'
    }

    It 'keeps local account checks complete and records external scope in the FSP finding' {
        $ctx.Rules = @(
            (& (Join-Path $toolRoot 'Rules\PrivilegedAccounts\ForeignPrincipalInPrivilegedGroup.rule.ps1')),
            (New-MATIRegressionRule -Collectors PrivilegedAccounts -Condition {
                param($Data, $Config)
                @($Data.PrivilegedAccounts.Accounts | Where-Object Enabled -eq $false)
            })
        )
        $ctx.Rules[0]['_Category'] = 'PrivilegedAccounts'
        $ctx.Rules[0]['_FileName'] = 'ForeignPrincipalInPrivilegedGroup.rule.ps1'
        $ctx.Collectors.PrivilegedAccounts = @{
            Function = 'Get-MATIPrivilegedAccounts'
            FilePath = Join-Path $toolRoot 'Collectors\Get-MATIPrivilegedAccounts.ps1'
        }
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.RuleResults[0].Status | Should Be 'Evaluated'
        $ctx.RuleResults[1].Status | Should Be 'Evaluated'
        $ctx.Findings[0].Title | Should Be 'External principal in privileged group'
        $ctx.Findings[0].Details.SID | Should Be 'S-1-5-21-4-5-6-500'
        $ctx.Findings[0].Details.OrphanStatus | Should Be 'NotDetermined'
        $ctx.Findings[0].Details.ResolutionError | Should Be 'Synthetic external identity unavailable'
        $ctx.Findings[0].Details.OutsideAssessmentScope | Should Be $true
        $ctx.Findings[0].Details.Note | Should Match 'one-way trusts'
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be $score.CalculatedGrade
        $score.GradeIsProvisional | Should Be $false
        $ctx.PartialCollectors.Count | Should Be 0
        Export-MATIHtml -EngineContext $ctx
        Export-MATIJson -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        $html = Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw
        $html.Contains('Provisional grade - partial assessment.') | Should Be $false
        $html.Contains('Why foreign-principal membership can remain incomplete') | Should Be $false
        $html.Contains('MATI-ADMIN-018') | Should Be $true
        $html.Contains('one-way trusts') | Should Be $true
        $kbLink = 'href="https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/get-adgroupmember-error-remote-forest-members"'
        ($html.IndexOf($kbLink) -gt $html.IndexOf('<th>References</th>')) | Should Be $true
        $json = Get-Content -LiteralPath (Join-Path $ctx.JsonDir 'MATI_Report_test.json') -Raw | ConvertFrom-Json
        $json.metadata.principalAuditScope | Should Be 'TargetForest'
        $csv = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_Assessment_test.csv')
        $csv.PrincipalAuditScope | Should Be 'TargetForest'
    }

    It 'keeps a genuine in-forest object read failure visible as partial collection' {
        $script:membershipObjectFailures = @($membershipUserDN)
        $ctx.Rules = @((New-MATIRegressionRule -Collectors PrivilegedAccounts -Condition {
            param($Data, $Config)
            @($Data.PrivilegedAccounts.Accounts | Where-Object Enabled -eq $false)
        }))
        $ctx.Collectors.PrivilegedAccounts = @{
            Function = 'Get-MATIPrivilegedAccounts'
            FilePath = Join-Path $toolRoot 'Collectors\Get-MATIPrivilegedAccounts.ps1'
        }
        Invoke-MATICollectors -EngineContext $ctx
        Invoke-MATIRules -EngineContext $ctx
        $ctx.PartialCollectors.Contains('PrivilegedAccounts') | Should Be $true
        $ctx.RuleResults[0].Status | Should Be 'Partial'
        @($ctx.CollectionIssues | Where-Object AffectsCoverage -ne $false).Count | Should BeGreaterThan 0
    }

    It 'does not treat a missing local Members property as an empty complete group' {
        Mock Get-ADGroup { [pscustomobject]@{ DistinguishedName = $membershipRootDN } }
        { Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Config $ctx.Config } |
            Should Throw 'Members property was not returned'
    }

    It 'keeps optional external lookup state <LookupStatus> out of local coverage' -TestCases @(
        @{ LookupStatus='Unresolved' }, @{ LookupStatus='TimedOut' }
    ) {
        param($LookupStatus)
        $script:scopeLookupStatus = $LookupStatus
        $script:membershipGroups[$membershipRootDN] = @($membershipForeignDN)
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status=$script:scopeLookupStatus; ResolvedName=$null; OutsideAssessmentScope=$true
                Error='Optional SID name lookup unavailable; deletion is not established.'
            }
        }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $result.Complete | Should Be $true
        $result.UnresolvedMembers.Count | Should Be 0
        $result.Members[0].ExternalResolutionStatus | Should Be $LookupStatus
        $ctx.CollectionIssues.Count | Should Be 0
    }

    It 'detects permanent EA or SA membership even when its only direct principal is outside the forest' {
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\PermanentEASAMembers.rule.ps1')
        $data = @{ PrivilegedAccounts=@{ Groups=@([pscustomobject]@{
            GroupKey='Enterprise Admins'; GroupName='Enterprise Admins'; Domain='lab.test'
            DistinguishedName='CN=Enterprise Admins,DC=lab,DC=test'; DirectMemberCount=1
            DirectMembers=@($membershipForeignDN); MemberCount=$null; KnownMemberCount=0
            MembershipComplete=$true; ExternalPrincipalCount=1
        }) } }
        $findings = @(& $rule.Condition $data $ctx.Config)
        $findings.Count | Should Be 1
        $findings[0].Details.MemberCount | Should Be '1'
        $rule.CollectorDatasets.PrivilegedAccounts[0] | Should Be 'Groups/DirectLinks'
    }

    It 'retains a directly linked remote DN without reading that remote object' {
        $remoteDN = 'CN=RemoteAdmin,DC=red,DC=test'
        $script:membershipGroups[$membershipRootDN] = @($remoteDN)
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $result.Complete | Should Be $true
        $result.Members[0].DistinguishedName | Should Be $remoteDN
        $result.Members[0].OutsideAssessmentScope | Should Be $true
        Assert-MockCalled Get-ADObject -Times 0 -Exactly -Scope It -ParameterFilter { $Server -eq 'red.test' }
    }

    It 'retains external users as scoped inventory without requesting their directory attributes' {
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status = 'Resolved'; SID = 'S-1-5-21-4-5-6-500'; ResolvedName = 'RED\externaladmin'
                DistinguishedName = 'CN=externaladmin,DC=red,DC=test'; ObjectClass = 'user'; Domain = 'red.test'
                Name = 'externaladmin'; SamAccountName = 'externaladmin'; Error = $null; Attempts = @()
            }
        }
        $script:membershipGroups[$membershipRootDN] = @($membershipForeignDN)
        $recursive = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $recursive.Complete | Should Be $true
        $recursive.Members[0].objectClass | Should Be 'foreignSecurityPrincipal'
        $recursive.Members[0].DistinguishedName | Should Be $membershipForeignDN
        $recursive.Members[0].OutsideAssessmentScope | Should Be $true
        $direct = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Config $ctx.Config
        $direct.Members[0].objectClass | Should Be 'foreignSecurityPrincipal'
        $direct.Members[0].DistinguishedName | Should Be $membershipForeignDN
        $direct.Members[0].ResolvedName | Should Be 'RED\externaladmin'
        $direct.MemberLinksComplete | Should Be $true
        Assert-MockCalled Get-ADUser -Times 0 -Exactly -Scope It -ParameterFilter { $Server -eq 'red.test' }
        Assert-MockCalled Get-ADObject -Times 0 -Exactly -Scope It -ParameterFilter { $Server -eq 'red.test' }
    }

    It 'expands a verified in-forest FSP group and deduplicates its principals by SID' {
        $script:membershipGroups[$membershipRootDN] = @($membershipForeignDN, $membershipChildUserDN)
        $script:membershipGroups['CN=ChildGroup,DC=child,DC=lab,DC=test'] = @($membershipChildUserDN)
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status = 'Resolved'; ResolvedName = 'CHILD\ChildGroup'
                DistinguishedName = 'CN=ChildGroup,DC=child,DC=lab,DC=test'; ObjectClass = 'group'; Domain = 'child.lab.test'
                Name = 'ExternalGroup'; SamAccountName = 'ExternalGroup'; Error = $null; Attempts = @()
            }
        }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $result.Complete | Should Be $true
        $result.Members.Count | Should Be 1
        $result.Members[0].DistinguishedName | Should Be $membershipChildUserDN
        Assert-MockCalled Get-ADGroup -Times 1 -Scope It -ParameterFilter {
            $Identity -eq 'CN=ChildGroup,DC=child,DC=lab,DC=test' -and $Server -eq 'child.lab.test'
        }
    }

    It 'keeps an unreadable in-forest FSP group partial instead of excluding a real local read failure' {
        $script:membershipGroups[$membershipRootDN] = @($membershipForeignDN)
        $script:membershipGroupFailures = @('CN=ChildGroup,DC=child,DC=lab,DC=test')
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status = 'Resolved'; ResolvedName = 'CHILD\ChildGroup'
                DistinguishedName = 'CN=ChildGroup,DC=child,DC=lab,DC=test'; ObjectClass = 'group'; Domain = 'child.lab.test'
                Error = $null; Attempts = @()
            }
        }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $result.Complete | Should Be $false
        $result.MemberLinksComplete | Should Be $false
        $result.Members[0].ResolvedName | Should Be 'CHILD\ChildGroup'
        $result.Members[0].MembershipResolved | Should Be $false
    }

    It 'does not expand a group in a trusted forest or make that excluded expansion a local collection failure' {
        $script:membershipGroups[$membershipRootDN] = @($membershipForeignDN)
        Mock Resolve-MATIForeignPrincipal {
            [pscustomobject]@{
                Status='Resolved'; ResolvedName='RED\AdminGroup'; Domain='red.test'
                DistinguishedName='CN=AdminGroup,DC=red,DC=test'; ObjectClass='group'
            }
        }
        $result = Resolve-MATIGroupMembership -Identity $membershipRootDN -Server 'lab.test' -Recursive -Config $ctx.Config
        $result.Complete | Should Be $true
        $result.MembershipScope | Should Be 'TargetForest'
        $result.Members[0].OutsideAssessmentScope | Should Be $true
        $result.Members[0].ResolvedName | Should Be 'RED\AdminGroup'
        Assert-MockCalled Get-ADGroup -Times 0 -Exactly -Scope It -ParameterFilter { $Server -eq 'red.test' }
    }

    It 'does not label AdminCount users orphaned when privileged membership is incomplete' {
        $script:membershipObjectFailures = @($membershipUserDN)
        $block = Get-MATIMembershipRegressionBlock -FileName 'Get-MATISecurityConfig.ps1' `
            -StatementType ([System.Management.Automation.Language.ForEachStatementAst]) -Marker '$adminCountUsers ='
        $forest = @{ Domains = @('lab.test') }
        $domCache = $ctx.Config['_DomainCache']
        $adminCountOrphans = @()
        . $block
        $adminCountOrphans.Count | Should Be 0
        Assert-MockCalled Get-ADUser -Times 0 -Scope It
        Assert-MockCalled Write-Warning -Scope It -ParameterFilter { $Message -like '*Cannot determine AdminCount orphan status*' }
    }

    It 'preserves AdminCount orphan detection when privileged membership is complete' {
        $script:membershipNative = $true
        $block = Get-MATIMembershipRegressionBlock -FileName 'Get-MATISecurityConfig.ps1' `
            -StatementType ([System.Management.Automation.Language.ForEachStatementAst]) -Marker '$adminCountUsers ='
        $forest = @{ Domains = @('lab.test') }
        $domCache = $ctx.Config['_DomainCache']
        $adminCountOrphans = @()
        . $block
        $adminCountOrphans.Count | Should Be 1
        $adminCountOrphans[0].DistinguishedName | Should Be 'CN=orphan,DC=lab,DC=test'
    }

    It 'does not declare expected RODC deny members missing from an incomplete read' {
        $script:membershipObjectFailures = @($membershipUserDN)
        $block = Get-MATIMembershipRegressionBlock -FileName 'Get-MATIRODCInfo.ps1' `
            -StatementType ([System.Management.Automation.Language.TryStatementAst]) -Marker '$deniedMembership ='
        $domainDns = 'lab.test'
        $domSID = 'S-1-5-21-1-2-3'
        $deniedGroupIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
        . $block
        $deniedMembership.Complete | Should Be $false
        $missingSIDs.Count | Should Be 8
        $deniedGroupIssues.Count | Should Be 0
    }

    It 'can establish missing RODC deny SIDs from complete local links despite unresolved foreign identities' {
        $Config = $ctx.Config
        $block = Get-MATIMembershipRegressionBlock -FileName 'Get-MATIRODCInfo.ps1' `
            -StatementType ([System.Management.Automation.Language.TryStatementAst]) -Marker '$deniedMembership ='
        $domainDns = 'lab.test'
        $domSID = 'S-1-5-21-1-2-3'
        $deniedGroupIssues = [System.Collections.Generic.List[PSCustomObject]]::new()
        . $block
        $deniedMembership.Complete | Should Be $true
        $deniedMembership.MemberLinksComplete | Should Be $true
        $deniedGroupIssues.Count | Should Be 1
        $deniedGroupIssues[0].MissingCount | Should Be 8
    }

    It 'uses only confirmed lower bounds for partial group-count findings' {
        $group = @{
            GroupName = 'Admins'; SID = 'S-1-5-21-1-2-3-519'; MemberCount = $null
            KnownMemberCount = 1; DirectMembers = @(); Domain = 'lab.test'
        }
        $ctx.Config.Thresholds.PrivilegedGroupMaxMembers['Enterprise Admins'] = 0
        $data = @{ PrivilegedAccounts = @{ Groups = @($group) } }
        foreach ($file in 'ExcessiveGroupMembers', 'PermanentEASAMembers') {
            $rule = & (Join-Path $toolRoot "Rules\PrivilegedAccounts\$file.rule.ps1")
            $findings = @(& $rule.Condition $data $ctx.Config)
            $findings.Count | Should Be 1
            $findings[0].Details.MemberCount | Should Be 'At least 1 (partial membership)'
        }
        $group.SID = 'S-1-5-32-544'
        $rule = & (Join-Path $toolRoot 'Rules\PrivilegedAccounts\PermanentPrivilegedMembers.rule.ps1')
        $findings = @(& $rule.Condition $data $ctx.Config)
        $findings.Count | Should Be 1
        $findings[0].Severity | Should Be 'Medium'
        $findings[0].Details.MemberCount | Should Be 'At least 1 (partial membership)'
        $group.KnownMemberCount = 0
        @(& $rule.Condition $data $ctx.Config).Count | Should Be 0
    }
}

Describe 'Build-aware KDC hardening' {
    BeforeEach { Mock Write-Host {}; Mock Write-Warning {} }
    foreach ($row in @(
        @{ Build = 14393; Initial = 8783; April = 9060; July = 9339; September = 8422 },
        @{ Build = 17763; Initial = 8276; April = 8644; July = 9020; September = 7792 },
        @{ Build = 20348; Initial = 4648; April = 5020; July = 5386; September = 4171 },
        @{ Build = 26100; Initial = 32230; April = 32690; July = 33158; September = 6584 }
    )) {
        It "ignores residual weak certificate binding after enforcement on $($row.Build)" {
            $settings = @{ OSBuildNumber = $row.Build; OSRevision = $row.September; StrongCertificateBindingEnforcement = 1 }
            (Get-MATIEffectiveKdcSettings $settings).EffectiveStrongCertificateBinding | Should Be 'FullEnforcement'
            $settings.OSRevision--
            (Get-MATIEffectiveKdcSettings $settings).EffectiveStrongCertificateBinding | Should Be 'Compatibility'
        }
        It "handles initial, rollback and final RC4 phases on $($row.Build)" {
            $settings = @{ OSBuildNumber = $row.Build; OSRevision = $row.Initial }
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x27
            $settings.Rc4DisablementPhase = 2
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x18
            $settings.OSRevision = $row.April; $settings.Rc4DisablementPhase = $null
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x18
            $settings.Rc4DisablementPhase = 1
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x27
            $settings.OSRevision = $row.July
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x18
            $settings.KdcDefaultEncTypes = 0x27
            (Get-MATIEffectiveKdcSettings $settings).EffectiveKdcEncTypes | Should Be 0x27
        }
    }
    It 'recognizes the distinct September hotpatch revisions' {
        foreach ($row in @(@{ Build = 20348; Revision = 4106 }, @{ Build = 26100; Revision = 6508 })) {
            (Get-MATIEffectiveKdcSettings @{ OSBuildNumber = $row.Build; OSRevision = $row.Revision; StrongCertificateBindingEnforcement = 1 }).EffectiveStrongCertificateBinding | Should Be 'FullEnforcement'
        }
    }
    It 'does not guess defaults for unsupported or missing revisions' {
        $result = Get-MATIEffectiveKdcSettings @{ OSBuildNumber = 9600; OSRevision = 20000 }
        $result.EffectiveStrongCertificateBinding | Should Be 'Unknown'
        $result.EffectiveKdcEncTypes | Should Be $null
        [string]::IsNullOrWhiteSpace($result.KdcSettingsError) | Should Be $false
    }
    It 'does not flag an absent registry value when the effective default is AES-only' {
        $rule = & (Join-Path $toolRoot 'Rules\Hardening\KdcRc4ByOmission.rule.ps1')
        $dc = @{ HostName = 'dc'; WinRMAccessible = $true; EffectiveKdcEncTypes = 0x18 }
        @(& $rule.Condition @{ ProtocolConfig = @{ DCProtocolSettings = @($dc) } } @{}).Count | Should Be 0
        $dc.EffectiveKdcEncTypes = 0x27
        @(& $rule.Condition @{ ProtocolConfig = @{ DCProtocolSettings = @($dc) } } @{}).Count | Should Be 1
        $dc.EffectiveKdcEncTypes = $null
        { & $rule.Condition @{ ProtocolConfig = @{ DCProtocolSettings = @($dc) } } @{} } | Should Throw 'Effective'
    }
    It 'uses effective rather than residual certificate-binding values in ESC9' {
        $rule = & (Join-Path $toolRoot 'Rules\ADCS\ESC9_NoSecurityExtension.rule.ps1')
        $data = @{
            CertificateServices = @{ IsADCSDeployed = $true; Templates = @(@{ NoSecurityExtension = $true; IsAuthTemplate = $true; LowPrivEnrollment = $true; IsPublished = $true }); CASecurityInfo = @() }
            ProtocolConfig = @{ DCProtocolSettings = @(@{ WinRMAccessible = $true; StrongCertificateBindingEnforcement = 1; EffectiveStrongCertificateBinding = 'FullEnforcement' }) }
        }
        $finding = @(& $rule.Condition $data @{})[0]
        $finding.Details.StrongBindingSummary | Should Be 'FullEnforcementObserved'
        $finding.Details.ExploitabilityContext | Should Be 'Additional prerequisites required'
    }
}

Describe 'Protocol registry reads and effective settings integration' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        $script:denyKdcRegistry = $false
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-ADDomainController { [pscustomobject]@{ Name = 'dc1'; HostName = 'dc1.lab.test' } }
        Mock Invoke-Command { & $ScriptBlock @ArgumentList }
        Mock Get-ItemProperty {
            if ($script:denyKdcRegistry -and $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc') {
                throw [UnauthorizedAccessException]::new('synthetic KDC read denied')
            }
            if ($LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') {
                return [pscustomobject]@{ CurrentBuildNumber = '26100'; UBR = 33158 }
            }
            [pscustomobject]@{}
        }
        Mock auditpol {
            $global:LASTEXITCODE = 0
            'MachineName,PolicyTarget,Subcategory,SubcategoryGuid,InclusionSetting,ExclusionSetting'
            'DC,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success,None'
        }
    }
    It 'uses the returned OS revision when optional registry values are absent' {
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].WinRMAccessible | Should Be $true
        $result.DCProtocolSettings[0].EffectiveStrongCertificateBinding | Should Be 'FullEnforcement'
        $result.DCProtocolSettings[0].EffectiveKdcEncTypes | Should Be 0x18
        $result.Errors.Count | Should Be 0
    }
    It 'does not treat unreadable KDC registry values as absent defaults' {
        $script:denyKdcRegistry = $true
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].EffectiveStrongCertificateBinding | Should Be 'Unknown'
        $result.DCProtocolSettings[0].EffectiveKdcEncTypes | Should Be $null
        ($result.Errors.Count -ge 2) | Should Be $true
    }
    It 'does not mark expected absent registry keys as collection failures' {
        Mock Get-ItemProperty {
            if ($LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') {
                return [pscustomobject]@{ CurrentBuildNumber = '26100'; UBR = 33158 }
            }
            Get-Item -LiteralPath (Join-Path $TestDrive 'absent-registry-fixture') -ErrorAction Stop
        }
        $ctx.Rules = @((New-MATIRegressionRule -Collectors ProtocolConfig))
        $ctx.Collectors.ProtocolConfig = @{ Function = 'Get-MATIProtocolConfig'; FilePath = Join-Path $toolRoot 'Collectors\Get-MATIProtocolConfig.ps1' }
        Invoke-MATICollectors -EngineContext $ctx
        $ctx.CollectionIssues.Count | Should Be 0
        Invoke-MATIRules -EngineContext $ctx
        (Get-MATIScore -EngineContext $ctx).AssessmentStatus | Should Be 'Complete'
    }
    It 'surfaces audit policy and remote connection failures' {
        Mock auditpol { throw 'synthetic audit policy denied' }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.Errors[0].Error | Should Be 'synthetic audit policy denied'
        Mock Invoke-Command { throw 'synthetic WinRM denied' }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].WinRMAccessible | Should Be $false
        $result.Errors[0].Error | Should Be 'synthetic WinRM denied'
    }
    It 'includes domain enumeration errors in its data contract' {
        Mock Get-ADDomainController { throw 'synthetic domain unavailable' }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.Errors[0].Domain | Should Be 'lab.test'
        $result.Errors[0].Error | Should Be 'synthetic domain unavailable'
    }
    It 'requests all audit categories with the documented wildcard syntax' {
        Mock auditpol {
            $script:auditpolArguments = @($args)
            $global:LASTEXITCODE = 0
            'MachineName,PolicyTarget,Subcategory,SubcategoryGuid,InclusionSetting,ExclusionSetting'
            'DC,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success,None'
        }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        ($script:auditpolArguments -join ' ') | Should Be '/get /category:* /r'
        $result.Errors.Count | Should Be 0
        $result.DCProtocolSettings[0].AuditPolicySub.Count | Should Be 1
    }
    It 'preserves native auditpol stderr instead of failing to trim an ErrorRecord' {
        Mock auditpol {
            $global:LASTEXITCODE = 5
            [System.Management.Automation.ErrorRecord]::new(
                [UnauthorizedAccessException]::new('synthetic native access denied'),
                'NativeCommandError', [System.Management.Automation.ErrorCategory]::PermissionDenied, $null
            )
        }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].AuditPolicyReadError | Should Match 'synthetic native access denied'
        $result.DCProtocolSettings[0].AuditPolicyReadError | Should Match 'code 5'
        $result.DCProtocolSettings[0].AuditPolicySub.Count | Should Be 0
        $result.Errors.Count | Should Be 1
    }
    It 'reports a nonzero auditpol exit even when the command emits nothing' {
        Mock auditpol { $global:LASTEXITCODE = 5 }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].AuditPolicyReadError | Should Match 'code 5'
        $result.Errors.Count | Should Be 1
    }
    It 'does not silently parse native stderr as audit policy CSV on exit zero' {
        Mock auditpol {
            $global:LASTEXITCODE = 0
            'MachineName,PolicyTarget,Subcategory,SubcategoryGuid,InclusionSetting,ExclusionSetting'
            'DC,System,Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success,None'
            [System.Management.Automation.ErrorRecord]::new(
                [Exception]::new('synthetic native warning'),
                'NativeCommandError', [System.Management.Automation.ErrorCategory]::NotSpecified, $null
            )
        }
        $result = Get-MATIProtocolConfig -Config $ctx.Config
        $result.DCProtocolSettings[0].AuditPolicyReadError | Should Match 'synthetic native warning'
        $result.DCProtocolSettings[0].AuditPolicySub.Count | Should Be 0
        $result.Errors.Count | Should Be 1
    }
}

Describe 'CA policy module and CA service permissions' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        $script:caDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:(A;;0x1;;;AU)')
        $script:caPolicyFlags = 0x40000
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Get-ADObject {
            if ($SearchBase -like 'CN=Enrollment Services,*') { return [pscustomobject]@{ Name = 'TestCA'; dNSHostName = 'ca.lab.test'; DistinguishedName = 'CN=TestCA' } }
            if ($SearchBase -like 'CN=Certificate Templates,*') { return @() }
            [pscustomobject]@{ Name = 'Public Key Services' }
        }
        Mock Invoke-Command { & $ScriptBlock @ArgumentList }
        Mock Get-ItemProperty {
            if ($LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TestCA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy' -and $Name -eq 'EditFlags') {
                return [pscustomobject]@{ EditFlags = $script:caPolicyFlags }
            }
            if ($LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\TestCA' -and $Name -eq 'Security') {
                $bytes = [byte[]]::new($script:caDescriptor.BinaryLength)
                $script:caDescriptor.GetBinaryForm($bytes, 0)
                return [pscustomobject]@{ Security = $bytes }
            }
            throw 'Unexpected registry path or value'
        }
        Mock Get-MATIObjectAcl { throw 'AD object ACL is not the CA service security descriptor.' }
    }
    It 'reads ESC6 from the exact CA policy module and ESC7 from service security' {
        $result = Get-MATICertificateServices -Config $ctx.Config
        $result.CASecurityInfo[0].EditfSANEnabled | Should Be $true
        $result.CASecurityInfo[0].LowPrivManageCA | Should Be $true
        $result.CASecurityInfo[0].ManagementACEs[0].ManageCA | Should Be $true
        $result.Errors.Count | Should Be 0
        Assert-MockCalled Get-MATIObjectAcl -Times 0
    }
    It 'detects Issue and Manage Certificates independently of Manage CA' {
        $script:caDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:(A;;0x2;;;AU)')
        $result = Get-MATICertificateServices -Config $ctx.Config
        $result.CASecurityInfo[0].ManagementACEs[0].ManageCertificates | Should Be $true
        $result.CASecurityInfo[0].ManagementACEs[0].ManageCA | Should Be $false
    }
    It 'does not interpret CA enrollment or same-SID denied management as Manage CA' {
        foreach ($sddl in 'O:SYG:SYD:(A;;0x100;;;AU)', 'O:SYG:SYD:(D;;0x1;;;AU)(A;;0x1;;;AU)') {
            $script:caDescriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($sddl)
            (Get-MATICertificateServices -Config $ctx.Config).CASecurityInfo[0].LowPrivManageCA | Should Be $false
        }
    }
    It 'keeps unreadable CA settings unknown and reports the collection error' {
        Mock Get-ItemProperty { throw 'synthetic registry access denied' }
        $result = Get-MATICertificateServices -Config $ctx.Config
        $result.CASecurityInfo[0].EditfSANEnabled | Should Be $null
        $result.CASecurityInfo[0].LowPrivManageCA | Should Be $null
        $result.Errors.Count | Should Be 2
    }
    It 'evaluates CA service ACEs in the default Windows PowerShell 5.1 remoting runtime' {
        $path = Join-Path $toolRoot 'Collectors\Get-MATICertificateServices.ps1'
        $ast = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $command = $ast.Find({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'Invoke-Command'
        }, $true)
        $remoteBlock = $command.Find({
            param($node)
            $node -is [Management.Automation.Language.ScriptBlockExpressionAst]
        }, $true).Extent.Text
        $fixture = @'
$ProgressPreference = 'SilentlyContinue'
function Get-ItemProperty {
    [CmdletBinding()]param($LiteralPath, $Name)
    if ($Name -eq 'EditFlags') { [pscustomobject]@{ EditFlags = 0x40000 } }
    else { [pscustomobject]@{ Security = $script:securityBytes } }
}
'@
        $cases = @'
$results = foreach ($sddl in @(
    'O:SYG:SYD:(A;;0x1;;;AU)',
    'O:SYG:SYD:(A;;0x2;;;AU)',
    'O:SYG:SYD:(A;CIIO;0x1;;;AU)',
    'O:SYG:SYD:(D;;0x1;;;AU)(A;;0x1;;;AU)'
)) {
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($sddl)
    $script:securityBytes = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($script:securityBytes, 0)
    & $remote 'TestCA'
}
$results | ConvertTo-Json -Depth 6
'@
        $payload = $fixture + "`n`$remote = $remoteBlock`n" + $cases
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $output = & $windowsPowerShell -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand $encoded
        $LASTEXITCODE | Should Be 0
        $results = ($output -join "`n") | ConvertFrom-Json
        $results.Count | Should Be 4
        foreach ($result in $results) {
            $result.SecurityRead | Should Be $true
            $result.Errors.Count | Should Be 0
        }
        $results[0].ManagementACEs[0].ManageCA | Should Be $true
        $results[1].ManagementACEs[0].ManageCertificates | Should Be $true
        $results[2].ManagementACEs.Count | Should Be 0
        $results[3].ManagementACEs.Count | Should Be 0
    }
}

Describe 'Event evidence and NTLM unknowns' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        Mock Write-Host {}
        Mock Write-Warning {}
        $script:events = @()
        Mock Get-ADDomainController { [pscustomobject]@{ Name = 'dc1'; HostName = 'dc1.lab.test' } }
        Mock Invoke-Command {
            $payload = & $ScriptBlock @ArgumentList
            $payload.PSComputerName = 'dc1.lab.test'
            $payload
        }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ActiveDirectory' }
        Mock Get-ADUser {}
        Mock Get-ADComputer {}
        Mock Get-ADServiceAccount {}
        Mock Get-WinEvent {
            if ($FilterXml -and $FilterXml.OuterXml -like '*NtLmSsp*') { return $script:events }
            @()
        }
    }
    It 'keeps missing NTLM version evidence out of the NTLMv2 bucket' {
        foreach ($version in @('', 'NTLM V1', 'NTLM V2')) {
            $event = [pscustomobject]@{ Package = $version }
            $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value {
                "<Event><EventData><Data Name=`"TargetUserName`">test</Data><Data Name=`"LmPackageName`">$($this.Package)</Data></EventData></Event>"
            }
            $script:events += $event
        }
        $result = Get-MATILegacyProtocolAudit -Config $ctx.Config
        $result.NTLM.NTLMv1Count | Should Be 1
        $result.NTLM.NTLMv2Count | Should Be 1
        $result.NTLM.UnknownCount | Should Be 1
        $result.NTLM.TotalEvents | Should Be 3
        $result.Errors.Count | Should Be 0
        $result.NTLM.UnknownPercent | Should Be 33.3
        $ctx.DataCache.LegacyProtocolAudit = $result
        Invoke-MATIRules -EngineContext $ctx
        $null = Get-MATIScore -EngineContext $ctx
        Export-MATICsv -EngineContext $ctx
        $summary = Import-Csv -LiteralPath (Join-Path $ctx.CsvDir 'MATI_ProtocolAudit_NTLM_Summary.csv')
        $summary.NTLM_Unknown | Should Be '1'
        $summary.Unknown_Percent | Should Be '33.3'
        Export-MATIHtml -EngineContext $ctx
        (Get-Content -LiteralPath (Join-Path $ctx.HtmlDir 'MATI_Report_test.html') -Raw).Contains('Unknown version: 1 (33.3%)') | Should Be $true
    }
    It 'surfaces event log access errors instead of reporting no events' {
        Mock Get-WinEvent { throw 'synthetic event log access denied' }
        $result = Get-MATILegacyProtocolAudit -Config $ctx.Config
        ($result.Errors.Count -gt 0) | Should Be $true
    }
    It 'keeps low-volume RC4 service observations outside the report TopN limit' {
        $ctx.Config.Thresholds.EventLogAudit.TopN = 1
        $script:kerberosEvents = @()
        foreach ($service in 'popular', 'popular', 'rare') {
            $event = [pscustomobject]@{ Id = 4769; Service = $service }
            $event | Add-Member ScriptMethod ToXml {
                "<Event><EventData><Data Name=`"TicketEncryptionType`">0x17</Data><Data Name=`"Status`">0x0</Data><Data Name=`"ServiceName`">$($this.Service)</Data></EventData></Event>"
            }
            $script:kerberosEvents += $event
        }
        Mock Get-WinEvent { $script:kerberosEvents } -ParameterFilter { $FilterHashtable.Id -contains 4769 }
        $result = Get-MATILegacyProtocolAudit -Config $ctx.Config
        $result.Kerberos.TopRC4TGSServices.Count | Should Be 1
        @($result.Kerberos.RC4ServiceObservations | Where-Object Name -eq 'rare').Count | Should Be 1
        $result.Kerberos.RC4Count | Should Be 3
        $result.Kerberos.RC4ServiceObservationsComplete | Should Be $true
    }
    It 'does not count failed Kerberos requests as successfully issued RC4 tickets' {
        $event = [pscustomobject]@{ Id = 4769 }
        $event | Add-Member ScriptMethod ToXml {
            '<Event><EventData><Data Name="TicketEncryptionType">0x17</Data><Data Name="Status">0x12</Data><Data Name="ServiceName">svc</Data></EventData></Event>'
        }
        $script:failedKerberosEvent = $event
        Mock Get-WinEvent { $script:failedKerberosEvent } -ParameterFilter { $FilterHashtable.Id -contains 4769 }
        $result = Get-MATILegacyProtocolAudit -Config $ctx.Config
        $result.Kerberos.RC4Count | Should Be 0
        $result.Kerberos.FailedCount | Should Be 1
        $result.Kerberos.RC4ServiceObservations.Count | Should Be 0
    }
    It 'keeps coverage unknown and the NTLM contract stable when no DC is returned' {
        Mock Get-ADDomainController {}
        $result = Get-MATILegacyProtocolAudit -Config $ctx.Config
        $result.Kerberos.RC4ServiceObservationsComplete | Should Be $false
        $result.NTLM.UnknownCount | Should Be 0
        ($result.Errors.Count -gt 0) | Should Be $true
        Assert-MockCalled Invoke-Command -Times 0 -Scope It
    }
    It 'correlates RC4 with the service account SID or domain/account, not the SPN' {
        $rule = & (Join-Path $toolRoot 'Rules\Kerberos\SPNWeakEncryption.rule.ps1')
        $data = @{
            LegacyProtocolAudit = @{ Kerberos = @{ RC4ServiceObservationsComplete = $true; TopRC4TGSServices = @(@{ Name = 'different-top-service' }); RC4ServiceObservations = @(@{ SID = 'S-1-5-21-1-2-3-1000'; Name = 'svcSql'; Domain = 'lab.test' }) } }
            KerberosConfig = @{ SPNAccounts = @(@{ SamAccountName = 'svcSql'; SID = 'S-1-5-21-1-2-3-1000'; Enabled = $true; Domain = 'lab.test'; SupportedEncryptionTypes = $null; ServicePrincipalName = @('MSSQLSvc/sql.lab.test:1433') }) }
        }
        $finding = @(& $rule.Condition $data @{})[0]
        $finding.Details.Classification | Should Be 'UnsetObservedRC4'
        $finding.Severity | Should Be 'Medium'
        $data.KerberosConfig.SPNAccounts[0].SID = 'S-1-5-21-9-8-7-1000'
        $data.KerberosConfig.SPNAccounts[0].Domain = 'other.test'
        @(& $rule.Condition $data @{})[0].Details.Classification | Should Be 'UnsetNoObservedRC4'
    }
}

Describe 'Linked GPO precedence with local SYSVOL fixtures' {
    BeforeEach {
        $script:ctx = New-MATIRegressionContext
        $script:gpoRoot = Join-Path $TestDrive 'policies'
        $script:domainGuid = '{00000000-0000-0000-0000-000000000001}'
        $script:ouGuid = '{00000000-0000-0000-0000-000000000002}'
        foreach ($fixture in @(@{ Guid = $domainGuid; Minimum = 14 }, @{ Guid = $ouGuid; Minimum = 6 })) {
            $directory = Join-Path $gpoRoot "$($fixture.Guid)\Machine\Microsoft\Windows NT\SecEdit"
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
            "[System Access]`r`nMinimumPasswordLength = $($fixture.Minimum)" | Set-Content -LiteralPath (Join-Path $directory 'GptTmpl.inf') -Encoding Unicode
            $bytes = [System.Collections.Generic.List[byte]]::new()
            $bytes.AddRange([byte[]](80,82,101,103,1,0,0,0))
            $bytes.AddRange([Text.Encoding]::Unicode.GetBytes("[Software\Policies\Microsoft\Windows\Installer`0;AlwaysInstallElevated`0;"))
            $bytes.AddRange([BitConverter]::GetBytes([uint32]4))
            $bytes.AddRange([Text.Encoding]::Unicode.GetBytes(';'))
            $bytes.AddRange([BitConverter]::GetBytes([uint32]4))
            $bytes.AddRange([Text.Encoding]::Unicode.GetBytes(';'))
            $bytes.AddRange([BitConverter]::GetBytes([uint32]$(if ($fixture.Minimum -eq 14) { 1 } else { 0 })))
            $bytes.AddRange([Text.Encoding]::Unicode.GetBytes(']'))
            [IO.File]::WriteAllBytes((Join-Path $gpoRoot "$($fixture.Guid)\Machine\Registry.pol"), $bytes.ToArray())
        }
        $script:domainOptions = 2; $script:blockInheritance = 0; $script:disabledDomain = $false
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Join-Path {
            Microsoft.PowerShell.Management\Join-Path -Path $script:gpoRoot -ChildPath $ChildPath
        } -ParameterFilter { $Path -eq '\\lab.test\SYSVOL\lab.test\Policies' }
        Mock Get-ADObject {
            if ($Identity -eq 'DC=lab,DC=test') {
                return [pscustomobject]@{ gpLink = "[LDAP://CN=$domainGuid,CN=Policies,CN=System,DC=lab,DC=test;$domainOptions]" }
            }
            if ($Identity -eq 'OU=Domain Controllers,DC=lab,DC=test') {
                return [pscustomobject]@{ gpLink = "[LDAP://CN=$ouGuid,CN=Policies,CN=System,DC=lab,DC=test;0]"; gpOptions = $blockInheritance }
            }
            [pscustomobject]@{ displayName = $Identity; flags = $(if ($disabledDomain -and $Identity -like "*$domainGuid*") { 2 } else { 0 }) }
        }
    }
    It 'lets enforced domain settings win over DC OU settings' {
        $result = Get-MATIGPOSettings -Config $ctx.Config
        $result.PerDomain['lab.test'].SystemAccess.MinimumPasswordLength | Should Be '14'
        $result.PerDomain['lab.test'].AssessmentBasis.Contains('not RSoP') | Should Be $true
    }
    It 'preserves normal OU precedence without enforcement' {
        $script:domainOptions = 0
        (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].SystemAccess.MinimumPasswordLength | Should Be '6'
    }
    It 'keeps only the winning registry value with enforcement and normal OU precedence' {
        $policies = (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].RegistryPolicies
        $policies.Count | Should Be 1
        $policies[0].Data | Should Be 1
        $script:domainOptions = 0
        $policies = (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].RegistryPolicies
        $policies.Count | Should Be 1
        $policies[0].Data | Should Be 0
    }
    It 'honors enforced links through blocked inheritance' {
        $script:blockInheritance = 1
        (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].SystemAccess.MinimumPasswordLength | Should Be '14'
    }
    It 'does not apply disabled computer-side GPOs' {
        $script:disabledDomain = $true
        (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].SystemAccess.MinimumPasswordLength | Should Be '6'
    }
    It 'processes the highest-priority link last at the same scope' {
        Mock Get-ADObject {
            if ($Identity -eq 'DC=lab,DC=test') { return [pscustomobject]@{ gpLink = "[LDAP://CN=$domainGuid,CN=Policies,CN=System,DC=lab,DC=test;0][LDAP://CN=$ouGuid,CN=Policies,CN=System,DC=lab,DC=test;0]" } }
            if ($Identity -eq 'OU=Domain Controllers,DC=lab,DC=test') { return [pscustomobject]@{ gpLink = ''; gpOptions = 0 } }
            [pscustomobject]@{ displayName = $Identity; flags = 0 }
        }
        (Get-MATIGPOSettings -Config $ctx.Config).PerDomain['lab.test'].SystemAccess.MinimumPasswordLength | Should Be '14'
    }
}
