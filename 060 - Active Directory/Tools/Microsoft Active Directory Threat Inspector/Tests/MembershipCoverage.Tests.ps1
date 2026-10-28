$toolRoot = Split-Path -Parent $PSScriptRoot
foreach ($file in @(
    'Models\Finding.ps1', 'Engine\MATI.Common.ps1', 'Engine\Invoke-MATIRules.ps1', 'Scoring\Get-MATIScore.ps1'
)) { . (Join-Path $toolRoot $file) }

function Get-ADTrust {
    [CmdletBinding()]param($Filter, $Server, $Properties)
    throw 'Live AD access forbidden.'
}

function New-MATICoverageContext {
    $config = Import-PowerShellDataFile (Join-Path $toolRoot 'Config\MATI.config.psd1')
    $config['_ForestCache'] = @{ Domains = @('lab.test') }
    $config['_DomainCache'] = @{ 'lab.test' = @{ DomainSID = 'S-1-5-21-1-2-3' } }
    @{
        Config = $config; Rules = @(); DataCache = @{}; AssessmentScope = @{}
        Findings = [System.Collections.Generic.List[object]]::new()
        NotAssessedRules = [System.Collections.Generic.List[object]]::new()
        RuleResults = [System.Collections.Generic.List[object]]::new()
        CollectionIssues = [System.Collections.Generic.List[object]]::new()
        FailedCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        PartialCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        WinPSCompat = $false
    }
}

function New-MATICoverageRule {
    param([string]$Id, [scriptblock]$Condition, [string[]]$Collectors = @('SecurityConfig'))
    @{
        Id = $Id; Title = $Id; Severity = 'High'; _Category = 'Hardening'; _FileName = 'coverage.rule.ps1'
        Collectors = $Collectors; Condition = $Condition
    }
}

Describe 'Dataset-scoped membership coverage' {
    BeforeEach {
        $script:ctx = New-MATICoverageContext
        Mock Write-Host {}
        Mock Write-Warning {}
        $ctx.DataCache.SecurityConfig = @{ AdminCountOrphans = @(); MachineAccountQuotas = @() }
        $null = $ctx.PartialCollectors.Add('SecurityConfig')
        $ctx.CollectionIssues.Add([pscustomobject]@{
            Collector = 'SecurityConfig'; Scope = 'AdminCountOrphans'
            Message = 'External membership unknown'; Datasets = @('AdminCountOrphans'); AffectsCoverage = $true
        })
        $ctx.Rules = @(
            (New-MATICoverageRule -Id 'ORPHAN' -Condition { param($Data, $Config) $Data.SecurityConfig.AdminCountOrphans }),
            (New-MATICoverageRule -Id 'QUOTA' -Condition { param($Data, $Config) $Data.SecurityConfig.MachineAccountQuotas })
        )
    }

    It 'limits an incomplete privileged membership index to the AdminCount orphan rule' {
        Invoke-MATIRules -EngineContext $ctx
        $ctx.RuleResults[0].Status | Should Be 'Partial'
        $ctx.RuleResults[1].Status | Should Be 'Evaluated'
        (Get-MATIScore -EngineContext $ctx).FullyAssessedRuleCount | Should Be 1
        $score = Get-MATIScore -EngineContext $ctx
        $score.Grade | Should Be 'A'
        $score.GradeIsProvisional | Should Be $true
        $score.AssessmentStatus | Should Be 'Partial'
    }

    It 'retains conservative collector-wide coverage for an unclassified read failure' {
        $ctx.CollectionIssues.Add([pscustomobject]@{ Collector = 'SecurityConfig'; Scope = 'Collector'; Message = 'Access denied' })
        Invoke-MATIRules -EngineContext $ctx
        @($ctx.RuleResults | Where-Object Status -eq 'Partial').Count | Should Be 2
    }

    It 'does not infer completeness for aliased indexed or invoked collector access' {
        foreach ($condition in @(
            { param($Data, $Config) $alias = $Data.SecurityConfig; $alias.AdminCountOrphans },
            { param($Data, $Config) $Data.SecurityConfig[$Config.Dataset] },
            { param($Data, $Config) $Data['SecurityConfig'].AdminCountOrphans },
            { param($Data, $Config) $Data.SecurityConfig.GetEnumerator() },
            { param($Data, $Config) $Data.SecurityConfig.MachineAccountQuotas; Invoke-UnknownHelper $Data },
            { param($Data, $Config) $Data.SecurityConfig.MachineAccountQuotas; $alias = $Data; $alias.SecurityConfig.AdminCountOrphans },
            { param($Data, $Config) $Data.SecurityConfig.MachineAccountQuotas; & { param($Data) $Data.SecurityConfig.AdminCountOrphans } @{} }
        )) {
            $rule = New-MATICoverageRule -Id 'DYNAMIC' -Condition $condition
            @(Get-MATIRuleCollectorDatasets -Rule $rule -Collector SecurityConfig -Config $ctx.Config)[0] | Should Be '*'
        }
    }

    It 'infers multiple direct datasets and honors a differently named data parameter' {
        $rule = New-MATICoverageRule -Id 'MULTI' -Condition {
            param($Inventory, $Config)
            $Inventory.SecurityConfig.AuthSilos
            $Inventory.SecurityConfig.AuthPolicies
        }
        $datasets = @(Get-MATIRuleCollectorDatasets -Rule $rule -Collector SecurityConfig -Config $ctx.Config)
        $datasets.Count | Should Be 2
        ($datasets -contains 'AuthSilos') | Should Be $true
        ($datasets -contains 'AuthPolicies') | Should Be $true
    }

    It 'does not treat explanatory diagnostics as missing data or a reason to withhold a grade' {
        $ctx.PartialCollectors.Clear()
        $ctx.CollectionIssues.Clear()
        $ctx.CollectionIssues.Add([pscustomobject]@{
            Collector = 'SecurityConfig'; Scope = 'Diagnostic'; Message = 'ADWS fallback recovered all members'
            AffectsCoverage = $false; Datasets = @()
        })
        Invoke-MATIRules -EngineContext $ctx
        (Get-MATIScore -EngineContext $ctx).Grade | Should Be 'A'
    }

    It 'keeps direct group inventory and unaffected count rules complete while recursive inspection stays partial' {
        $ctx.PartialCollectors.Clear()
        $ctx.CollectionIssues.Clear()
        $null = $ctx.PartialCollectors.Add('PrivilegedAccounts')
        $ctx.CollectionIssues.Add([pscustomobject]@{
            Collector = 'PrivilegedAccounts'; Scope = 'Administrators'; Message = 'External membership unknown'
            Datasets = @('Accounts', 'Groups/Recursive/Administrators'); AffectsCoverage = $true
        })
        $ctx.DataCache.PrivilegedAccounts = @{ Groups = @(@{
            GroupName = 'Administrators'; GroupKey = 'Administrators'; SID = 'S-1-5-32-544'
            DistinguishedName = 'CN=Administrators,CN=Builtin,DC=lab,DC=test'; Domain = 'lab.test'
            DirectMemberCount = 8; MemberCount = $null; KnownMemberCount = 6; MembershipComplete = $false
            DirectMembers = @('CN=A', 'CN=B', 'CN=C', 'CN=D', 'CN=E', 'CN=F', 'CN=G', 'CN=H')
            MemberDetails = @()
        }); Accounts = @() }
        $ctx.Rules = @(
            foreach ($name in 'ExcessiveGroupMembers', 'PermanentEASAMembers', 'PermanentPrivilegedMembers', 'ComputerInPrivilegedGroup') {
                $rule = & (Join-Path $toolRoot "Rules\PrivilegedAccounts\$name.rule.ps1")
                $rule['_Category'] = 'PrivilegedAccounts'; $rule['_FileName'] = "$name.rule.ps1"
                $rule
            }
        )
        Invoke-MATIRules -EngineContext $ctx
        foreach ($index in 0..2) { $ctx.RuleResults[$index].Status | Should Be 'Evaluated' }
        $ctx.RuleResults[3].Status | Should Be 'Partial'
        $finding = $ctx.Findings | Where-Object Id -eq 'MATI-ADMIN-014'
        $finding.Details.MemberCount | Should Be '8'
        $finding.Severity | Should Be 'High'
        $ctx.Config.Thresholds.PrivilegedGroupMaxMembers['Administrators'] = 5
        $ctx.Findings.Clear()
        Invoke-MATIRules -EngineContext $ctx
        $ctx.RuleResults[0].Status | Should Be 'Partial'
    }

    It 'can infer concrete SecurityConfig datasets for all current built-in rules without ambiguous access' {
        $checked = 0
        foreach ($file in Get-ChildItem -LiteralPath (Join-Path $toolRoot 'Rules') -Recurse -Filter '*.rule.ps1') {
            $rule = & $file.FullName
            if ('SecurityConfig' -notin $rule.Collectors) { continue }
            $datasets = @(Get-MATIRuleCollectorDatasets -Rule $rule -Collector SecurityConfig -Config $ctx.Config)
            $datasets.Count | Should BeGreaterThan 0
            ($datasets -contains '*') | Should Be $false
            $checked++
        }
        $checked | Should Be 34
    }
}

Describe 'Bounded and cached external identity lookup' {
    BeforeEach {
        $script:ctx = New-MATICoverageContext
        Mock Write-Warning {}
        Mock Get-ADTrust { [pscustomobject]@{ Target = 'red.test' } }
        Mock Invoke-MATIForeignPrincipalLookup {
            [pscustomobject]@{
                Status = if ($Targets.Count) { 'Resolved' } else { 'NameOnly' }
                SID = $SID; ResolvedName = 'RED\externaladmin'
                DistinguishedName = if ($Targets.Count) { 'CN=admin,DC=lab,DC=test' } else { $null }
                ObjectClass = if ($Targets.Count) { 'user' } else { $null }
                Domain = if ($Targets.Count) { 'lab.test' } else { $null }
                Error = $null; Attempts = @()
            }
        }
    }

    It 'caches external name resolution without discovering or querying trusted forests' {
        $sid = 'S-1-5-21-4-5-6-500'
        $first = Resolve-MATIForeignPrincipal -SID $sid -Config $ctx.Config
        $second = Resolve-MATIForeignPrincipal -SID $sid -Config $ctx.Config
        $first.Status | Should Be 'NameOnly'
        $second.ResolvedName | Should Be 'RED\externaladmin'
        $first.OutsideAssessmentScope | Should Be $true
        Assert-MockCalled Invoke-MATIForeignPrincipalLookup -Times 1 -Exactly -Scope It -ParameterFilter {
            $SID -eq 'S-1-5-21-4-5-6-500' -and $Targets.Count -eq 0
        }
        Assert-MockCalled Get-ADTrust -Times 0 -Exactly -Scope It
    }

    It 'preserves unresolved status and evidence without declaring a principal deleted' {
        Mock Invoke-MATIForeignPrincipalLookup {
            [pscustomobject]@{
                Status = 'Unresolved'; SID = $SID; ResolvedName = $null
                Error = 'No identity verified; deletion is not established.'; Attempts = @('red.test: unavailable')
            }
        }
        $result = Resolve-MATIForeignPrincipal -SID 'S-1-5-21-4-5-6-500' -Config $ctx.Config
        $result.Status | Should Be 'Unresolved'
        $result.Attempts[0] | Should Be 'red.test: unavailable'
        $result.Error | Should Match 'not established'
        $result.OutsideAssessmentScope | Should Be $true
    }

    It 'restricts an in-forest FSP lookup to its owning forest domain' {
        $result = Resolve-MATIForeignPrincipal -SID 'S-1-5-21-1-2-3-1000' -Config $ctx.Config
        $result.OutsideAssessmentScope | Should Be $false
        $result.Status | Should Be 'Resolved'
        Assert-MockCalled Invoke-MATIForeignPrincipalLookup -Times 1 -Exactly -Scope It -ParameterFilter {
            $Targets.Count -eq 1 -and $Targets[0] -eq 'lab.test'
        }
    }

    It 'does not silently exclude principals when the target forest SID scope is unavailable' {
        $ctx.Config['_DomainCache']['lab.test'].DomainSID = 'invalid'
        { Resolve-MATIForeignPrincipal -SID 'S-1-5-21-4-5-6-500' -Config $ctx.Config } |
            Should Throw 'Cannot establish the assessed forest SID scope'
    }
}

Describe 'Name-only lookup outside directory scope' {
    It 'resolves a local built-in SID without any LDAP search target or AD access' {
        $result = Invoke-MATIForeignPrincipalLookup -SID 'S-1-5-32-544' -Targets @() -TimeoutSeconds 10
        $result.Status | Should Be 'NameOnly'
        [string]::IsNullOrWhiteSpace($result.ResolvedName) | Should Be $false
        $result.Error | Should Be $null
    }
}

Describe 'External lookup timeout and cleanup' {
    BeforeEach {
        $script:nativeStartJob = Get-Command Start-Job -CommandType Cmdlet
        $script:lookupTestJob = $null
        Mock Start-Job {
            $script:lookupTestJob = & $script:nativeStartJob -ScriptBlock { Start-Sleep -Seconds 30 }
            $script:lookupTestJob
        }
    }

    It 'enforces a real timeout and removes only its own job without contacting AD' {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $result = Invoke-MATIForeignPrincipalLookup -SID 'S-1-5-21-4-5-6-500' -Targets @() -TimeoutSeconds 2
        $timer.Stop()
        $result.Status | Should Be 'TimedOut'
        ($timer.Elapsed.TotalSeconds -lt 12) | Should Be $true
        $result.Error | Should Match '2 seconds'
        @(Get-Job -Id $script:lookupTestJob.Id -ErrorAction SilentlyContinue).Count | Should Be 0
    }
}
