# Engine\Invoke-MATIRules.ps1
# MATIv2 - Rule execution engine
# Iterates over discovered rules, runs their Condition scriptblock
# against the DataCache, and produces MATIFinding objects.

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

        Write-Host "  [$ruleCount/$($EngineContext.Rules.Count)] $ruleId - $($rule.Title) ..." -ForegroundColor DarkGray -NoNewline

        # Validate that the rule has a Condition scriptblock
        if (-not $rule.Condition -or $rule.Condition -isnot [scriptblock]) {
            Write-Host " SKIP (no Condition)" -ForegroundColor Yellow
            continue
        }

        # If any required collector failed, the rule cannot be trusted (a missing
        # data set would otherwise look like "no finding" and inflate the score).
        # Mark it as NOT ASSESSED so the result stays honest.
        $failedDeps = @()
        if ($EngineContext.ContainsKey('FailedCollectors') -and $EngineContext.FailedCollectors.Count -gt 0) {
            $failedDeps = @($rule.Collectors | Where-Object { $EngineContext.FailedCollectors.Contains($_) })
        }
        if ($failedDeps.Count -gt 0) {
            Write-Host " NOT ASSESSED (collector failed: $($failedDeps -join ', '))" -ForegroundColor Yellow
            if ($EngineContext.ContainsKey('NotAssessedRules')) {
                $EngineContext.NotAssessedRules.Add([PSCustomObject]@{
                    Id              = $ruleId
                    Title           = $rule.Title
                    Category        = $category
                    FailedCollectors = ($failedDeps -join ', ')
                })
            }
            continue
        }

        try {
            # Invoke the rule's condition, passing DataCache and Config
            $results = & $rule.Condition $dataCache $config

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
                    -Title       $rule.Title `
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
        }
    }

    Write-Host "`n  Rule evaluation complete: $findingCount findings from $ruleCount rules.`n" -ForegroundColor Cyan
}
