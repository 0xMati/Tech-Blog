# Engine\Invoke-MATIRules.ps1
# MATIv2 - Rule execution engine
# Iterates over discovered rules, runs their Condition scriptblock
# against the DataCache, and produces MATIFinding objects.

function Get-MATIRuleCollectorDatasets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Rule,
        [Parameter(Mandatory)][string]$Collector,
        [hashtable]$Config
    )

    if ($Rule.CollectorDatasets -and $Rule.CollectorDatasets.ContainsKey($Collector)) {
        $requirement = $Rule.CollectorDatasets[$Collector]
        if ($requirement -is [scriptblock]) { return @(& $requirement $Config) }
        return @($requirement)
    }
    $parameter = $Rule.Condition.Ast.ParamBlock.Parameters | Select-Object -First 1
    if (-not $parameter) { return @('*') }
    $dataName = $parameter.Name.VariablePath.UserPath
    $shadowed = @($Rule.Condition.Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.ScriptBlockAst] -and
        -not [object]::ReferenceEquals($node, $Rule.Condition.Ast) -and
        $dataName -in @($node.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    }, $true))
    if ($shadowed.Count) { return @('*') }
    $dataReferences = @($Rule.Condition.Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.VariablePath.UserPath -eq $dataName
    }, $true))
    foreach ($reference in $dataReferences) {
        if ($reference.Parent -is [System.Management.Automation.Language.ParameterAst]) { continue }
        if ($reference.Parent -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
            $reference.Parent.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            return @('*')
        }
    }
    $roots = @($Rule.Condition.Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $node.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Expression.VariablePath.UserPath -eq $dataName -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Member.Value -eq $Collector
    }, $true))
    if (-not $roots.Count) { return @('*') }
    $datasets = foreach ($root in $roots) {
        $parent = $root.Parent
        if ($parent -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
            $parent -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
            $parent.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
            return @('*')
        }
        $parent.Member.Value
    }
    return @($datasets | Select-Object -Unique)
}

function Invoke-MATIRules {
    <#
    .SYNOPSIS
        Executes all active rules against the collected data and populates
        the Findings list in the engine context.
    .PARAMETER EngineContext
        The engine context hashtable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    Write-Host "=== Phase 2: Rule Evaluation ===" -ForegroundColor Cyan
    if ($EngineContext.Rules.Count -eq 0) { throw 'Cannot evaluate an empty rule selection.' }
    $ErrorActionPreference = 'Stop'
    $EngineContext.RuleResults = [System.Collections.Generic.List[object]]::new()
    $EngineContext.NotAssessedRules.Clear()

    $config     = $EngineContext.Config
    $dataCache  = $EngineContext.DataCache
    $findings   = $EngineContext.Findings
    $exclusions = $config.Exclusions

    $excludedDNs  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in @($exclusions.ExcludedDNs | Where-Object { $_ })) {
        $null = $excludedDNs.Add($dn)
    }
    $excludedSAMs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sam in @($exclusions.ExcludedSamAccountNames | Where-Object { $_ })) {
        $null = $excludedSAMs.Add($sam)
    }

    $ruleCount    = 0
    $findingCount = 0

    foreach ($rule in $EngineContext.Rules) {
        $ruleCount++
        $ruleId   = $rule.Id
        $category = $rule['_Category']
        $fileName = $rule['_FileName']
        $evaluation = [pscustomobject]@{ Id = $ruleId; Title = $rule.Title; Category = $category; Status = 'NotAssessed'; Reason = ''; FailedCollectors = @() }
        $EngineContext.RuleResults.Add($evaluation)

        Write-Host "  [$ruleCount/$($EngineContext.Rules.Count)] $ruleId - $($rule.Title) ..." -ForegroundColor DarkGray -NoNewline

        # Validate that the rule has a Condition scriptblock
        if (-not $rule.Condition -or $rule.Condition -isnot [scriptblock]) {
            Write-Host " SKIP (no Condition)" -ForegroundColor Yellow
            $evaluation.Reason = 'Missing executable Condition'
            $EngineContext.NotAssessedRules.Add($evaluation)
            Write-Warning "Rule $ruleId has no executable Condition."
            continue
        }

        # If any required collector failed, the rule cannot be trusted (a missing
        # data set would otherwise look like "no finding" and inflate the score).
        # Mark it as NOT ASSESSED so the result stays honest.
        $failedDeps = @()
        $failedDeps = @($rule.Collectors | Where-Object { $EngineContext.FailedCollectors.Contains($_) -or -not $dataCache.ContainsKey($_) })
        if ($failedDeps.Count -gt 0) {
            Write-Host " NOT ASSESSED (collector failed: $($failedDeps -join ', '))" -ForegroundColor Yellow
            $evaluation.FailedCollectors = $failedDeps
            $evaluation.Reason = "Missing or failed collectors: $($failedDeps -join ', ')"
            $EngineContext.NotAssessedRules.Add($evaluation)
            continue
        }
        $partialDeps = @(
            foreach ($dependency in $rule.Collectors) {
                if (-not $EngineContext.PartialCollectors -or -not $EngineContext.PartialCollectors.Contains($dependency)) { continue }
                $issues = @($EngineContext.CollectionIssues | Where-Object {
                    $_.Collector -eq $dependency -and $_.AffectsCoverage -ne $false
                })
                if (-not $issues.Count -or @($issues | Where-Object { -not $_.Datasets }).Count) {
                    $dependency
                    continue
                }
                $requiredDatasets = @(Get-MATIRuleCollectorDatasets -Rule $rule -Collector $dependency -Config $config)
                foreach ($issue in $issues) {
                    if (@($requiredDatasets | Where-Object {
                        $required = $_
                        $required -eq '*' -or @($issue.Datasets | Where-Object {
                            $_ -eq $required -or $_.StartsWith("$required/", [StringComparison]::OrdinalIgnoreCase)
                        }).Count -gt 0
                    }).Count) { $dependency; break }
                }
            }
        )

        try {
            # Invoke the rule's condition, passing DataCache and Config
            $results = & $rule.Condition $dataCache $config
            $evaluation.Status = if ($partialDeps.Count -gt 0) { 'Partial' } else { 'Evaluated' }
            if ($partialDeps.Count -gt 0) { $evaluation.Reason = "Incomplete collectors: $($partialDeps -join ', ')" }

            if (-not $results) {
                Write-Host " NO FINDING" -ForegroundColor Green
                continue
            }

            # Ensure results is always an array
            $results = @($results)

            $ruleFindings = 0
            foreach ($result in $results) {
                # Apply exclusions
                if ($result.ObjectDN -and $excludedDNs.Contains($result.ObjectDN)) { continue }
                if ($result.SamAccountName -and $excludedSAMs.Contains($result.SamAccountName)) { continue }

                # Determine severity (rule-level default or per-result override)
                $severity = if ($result.Severity) { $result.Severity } else { $rule.Severity }

                # Determine weight
                $weight = if (($result -is [hashtable]) -and $result.ContainsKey('Weight') -and $result.Weight -ge 0) {
                    $result.Weight
                } elseif ($rule.ContainsKey('Weight') -and $rule.Weight -ge 0) {
                    $rule.Weight
                } else {
                    -1  # Let New-MATIFinding derive from severity
                }

                $finding = New-MATIFinding `
                    -Id          $ruleId `
                    -Category    $category `
                    -Severity    $severity `
                    -Title       ($result.Title ?? $rule.Title) `
                    -Description ($result.Description ?? $rule.Description ?? '') `
                    -Remediation ($result.Remediation ?? $rule.Remediation ?? '') `
                    -ObjectDN    ($result.ObjectDN ?? '') `
                    -Domain      ($result.Domain ?? '') `
                    -RuleFile    $fileName `
                    -Details     ($result.Details ?? @{}) `
                    -References  @($rule.References | Where-Object { $_ }) `
                    -Weight      $weight

                $findings.Add($finding)
                $ruleFindings++
            }

            $findingCount += $ruleFindings
            if ($ruleFindings -gt 0) {
                Write-Host " FINDINGS: $ruleFindings" -ForegroundColor DarkYellow
            } else {
                Write-Host " NO FINDING (excluded)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host " ERROR" -ForegroundColor Red
            Write-Warning "    Rule $ruleId failed: $($_.Exception.Message)"
            $evaluation.Status = 'Error'
            $evaluation.Reason = $_.Exception.Message
            $EngineContext.NotAssessedRules.Add($evaluation)
        }
    }

    Write-Host "`n  Rule evaluation complete: $findingCount findings from $ruleCount rules.`n" -ForegroundColor Cyan
}
