# Scoring\Get-MATIScore.ps1
# MATIv2 - Multiplicative-Decay scoring engine.
#
# Each category owns a budget (slice of 100 points).
# Every distinct rule that fires consumes a %age of the remaining
# budget in its category (SeverityImpact).  Multiplicative decay
# provides natural diminishing returns — the first Critical rule in
# a category hurts far more than the sixth High rule.
#
# Score = BaseScore - SUM(all category deductions)

function Get-MATIScore {
    <#
    .SYNOPSIS
        Calculates the overall security score using multiplicative-decay
        per-category budgets.
    .OUTPUTS
        [hashtable] with keys: Score, Grade, TotalDeduction, …
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    Write-Host "=== Phase 3: Scoring ===" -ForegroundColor Cyan

    $config   = $EngineContext.Config
    $findings = @($EngineContext.Findings)
    $scoring  = $config.Scoring
    if ($EngineContext.Rules.Count -eq 0) { throw 'Cannot score an empty rule selection.' }
    if (@($EngineContext.RuleResults).Count -ne $EngineContext.Rules.Count) {
        throw 'Rule execution results are incomplete. Run rule evaluation before scoring.'
    }
    $fullyAssessed = @($EngineContext.RuleResults | Where-Object Status -eq 'Evaluated').Count
    $evaluated = @($EngineContext.RuleResults | Where-Object Status -in @('Evaluated', 'Partial')).Count
    $partialAssessment = $fullyAssessed -ne $EngineContext.Rules.Count -or
        @($EngineContext.CollectionIssues | Where-Object AffectsCoverage -ne $false).Count -gt 0 -or
        $EngineContext.FailedCollectors.Count -gt 0 -or $EngineContext.WinPSCompat
    $scope = $EngineContext.AssessmentScope
    $filteredAssessment = [bool]$scope.CategoriesOnly -or [bool]$scope.RulesOnly -or
        @($config.Exclusions.DisabledRules).Count -gt 0 -or @($config.Exclusions.DisabledCategories).Count -gt 0 -or
        @($config.Exclusions.ExcludedDNs).Count -gt 0 -or @($config.Exclusions.ExcludedSamAccountNames).Count -gt 0

    $baseScore       = $scoring.BaseScore
    $severityImpact  = $scoring.SeverityImpact
    $categoryWeights = $scoring.CategoryWeights
    $defaultWeight   = if ($scoring.DefaultCategoryWeight) { $scoring.DefaultCategoryWeight } else { 8 }

    # Severity ranking for sort order
    $severityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Informational = 0 }

    # ------------------------------------------------------------------
    # 1. One entry per rule — take the highest severity across findings
    # ------------------------------------------------------------------
    $ruleGroups = $findings | Group-Object -Property Id
    $ruleSummaries = @{}

    foreach ($rg in @($ruleGroups)) {
        $highestSeverity = 'Informational'
        $highestRank     = 0
        foreach ($f in $rg.Group) {
            $rank = $severityRank[$f.Severity]
            if ($rank -gt $highestRank) {
                $highestRank     = $rank
                $highestSeverity = $f.Severity
            }
        }
        $ruleSummaries[$rg.Name] = @{
            Severity     = $highestSeverity
            SeverityRank = $highestRank
            FindingCount = $rg.Count
            Category     = $rg.Group[0].Category
            Title        = $rg.Group[0].Title
        }
    }

    # ------------------------------------------------------------------
    # 2. Multiplicative decay per category
    # ------------------------------------------------------------------
    $categoryDeductions = @{}
    $ruleDeductions     = @{}

    # Group the rule summaries by category
    $catGroups = $ruleSummaries.GetEnumerator() | Group-Object { $_.Value.Category }

    foreach ($cg in @($catGroups)) {
        $catName = $cg.Name
        $budget  = if ($categoryWeights.ContainsKey($catName)) {
            [double]$categoryWeights[$catName]
        } else {
            [double]$defaultWeight
        }

        # Sort worst-first so Critical rules consume budget first
        $orderedRules = $cg.Group | Sort-Object { $_.Value.SeverityRank } -Descending

        $remaining = $budget
        foreach ($re in $orderedRules) {
            $ruleId   = $re.Key
            $severity = $re.Value.Severity
            $impact   = if ($severityImpact.ContainsKey($severity)) { $severityImpact[$severity] } else { 0 }

            $consumed  = $remaining * ($impact / 100.0)
            $remaining -= $consumed

            $ruleDeductions[$ruleId] = @{
                Deduction    = [math]::Round($consumed, 2)
                FindingCount = $re.Value.FindingCount
                Category     = $catName
                Severity     = $severity
                Title        = $re.Value.Title
            }
        }

        $categoryDeductions[$catName] = [math]::Round($budget - $remaining, 1)
    }

    # ------------------------------------------------------------------
    # 3. Final score & grade
    # ------------------------------------------------------------------
    $totalDeduction = 0.0
    foreach ($v in @($categoryDeductions.Values)) { $totalDeduction += $v }
    $totalDeduction = [math]::Round($totalDeduction, 1)

    $finalScore = [math]::Max(0, [math]::Round($baseScore - $totalDeduction))

    $grade = 'E'
    $gradeEntries = @($scoring.Grades.GetEnumerator()) | Sort-Object Value -Descending
    foreach ($g in $gradeEntries) {
        if ($finalScore -ge $g.Value) {
            $grade = $g.Key
            break
        }
    }
    $calculatedGrade = $grade
    if ($filteredAssessment -or $evaluated -eq 0) { $grade = 'N/A' }

    # ------------------------------------------------------------------
    # 4. Build result object (backward-compatible keys)
    # ------------------------------------------------------------------
    $scoreResult = @{
        Score              = $finalScore
        Grade              = $grade
        CalculatedGrade    = $calculatedGrade
        GradeIsProvisional = [bool]($partialAssessment -and $grade -ne 'N/A')
        AssessmentStatus   = if ($partialAssessment) { 'Partial' } elseif ($filteredAssessment) { 'Filtered' } else { 'Complete' }
        SelectedRuleCount  = $EngineContext.Rules.Count
        EvaluatedRuleCount = $evaluated
        FullyAssessedRuleCount = $fullyAssessed
        FilteredAssessment = $filteredAssessment
        BaseScore          = $baseScore
        TotalDeduction     = $totalDeduction
        TotalFindings      = $findings.Count
        RulesTriggered     = $ruleSummaries.Count
        RuleDeductions     = $ruleDeductions
        CategoryDeductions = $categoryDeductions
        BySeverity         = @{
            Critical      = @($findings | Where-Object Severity -eq 'Critical').Count
            High          = @($findings | Where-Object Severity -eq 'High').Count
            Medium        = @($findings | Where-Object Severity -eq 'Medium').Count
            Low           = @($findings | Where-Object Severity -eq 'Low').Count
            Informational = @($findings | Where-Object Severity -eq 'Informational').Count
        }
        NotAssessedCount   = if ($EngineContext.ContainsKey('NotAssessedRules')) { $EngineContext.NotAssessedRules.Count } else { 0 }
        FailedCollectors   = if ($EngineContext.ContainsKey('FailedCollectors')) { @($EngineContext.FailedCollectors) } else { @() }
        PartialAssessment  = [bool]$partialAssessment
    }

    $EngineContext.Score = $scoreResult

    # ------------------------------------------------------------------
    # 5. Console output
    # ------------------------------------------------------------------
    $gradeColor = switch ($grade) {
        'A' { 'Green' }
        'B' { 'Green' }
        'C' { 'Yellow' }
        'D' { 'Red' }
        default { 'Red' }
    }

    Write-Host ""
    Write-Host "  ┌────────────────────────────────┐" -ForegroundColor $gradeColor
    Write-Host "  │  Score: $finalScore / $baseScore  (Grade: $grade)    │" -ForegroundColor $gradeColor
    Write-Host "  └────────────────────────────────┘" -ForegroundColor $gradeColor
    Write-Host ""
    Write-Host "  Total findings : $($findings.Count) (from $($ruleSummaries.Count) rules)" -ForegroundColor DarkGray
    Write-Host "  Critical: $($scoreResult.BySeverity.Critical) | High: $($scoreResult.BySeverity.High) | Medium: $($scoreResult.BySeverity.Medium) | Low: $($scoreResult.BySeverity.Low)" -ForegroundColor DarkGray
    Write-Host "  Total deduction: $totalDeduction points`n" -ForegroundColor DarkGray

    if ($scoreResult.PartialAssessment) {
        $gradeNotice = if ($scoreResult.GradeIsProvisional) { 'Provisional grade - partial assessment.' }
            elseif ($evaluated -eq 0) { 'Grade unavailable - no rules evaluated.' }
            else { 'Partial assessment - selected scope only.' }
        Write-Host "  [!] $gradeNotice" -ForegroundColor Yellow
        if ($scoreResult.NotAssessedCount -gt 0) {
            Write-Host "      $($scoreResult.NotAssessedCount) rule(s) were NOT ASSESSED or failed during evaluation." -ForegroundColor Yellow
        }
        if ($scoreResult.FailedCollectors.Count -gt 0) {
            Write-Host "      Failed collectors: $($scoreResult.FailedCollectors -join ', ')" -ForegroundColor Yellow
        }
        if ($EngineContext.ContainsKey('WinPSCompat') -and $EngineContext.WinPSCompat) {
            Write-Host "      AD module ran in compatibility mode (deserialized objects) - run on a DC for full coverage." -ForegroundColor Yellow
        }
        Write-Host ""
    }

    if ($filteredAssessment) {
        Write-Warning 'Selected scope only - no global grade.'
    }

    # Category breakdown
    foreach ($cat in @($categoryDeductions.GetEnumerator()) | Sort-Object Value -Descending) {
        $budget = if ($categoryWeights.ContainsKey($cat.Key)) { $categoryWeights[$cat.Key] } else { $defaultWeight }
        $pct = [math]::Round(100 * $cat.Value / $budget)
        Write-Host "    $($cat.Key): -$($cat.Value) / $budget pts ($pct%)" -ForegroundColor DarkGray
    }
    Write-Host ""

    return $scoreResult
}

function Save-MATIScoreHistory {
    <#
    .SYNOPSIS
        Appends the current score to the history CSV for trend tracking.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    $historyDir  = Join-Path $EngineContext.RootPath 'History'
    if (-not (Test-Path $historyDir)) {
        New-Item -ItemType Directory -Path $historyDir -Force | Out-Null
    }
    $historyPath = Join-Path $historyDir 'MATI_ScoreHistory_v2.csv'
    $score = $EngineContext.Score

    $entry = [PSCustomObject]@{
        DateTimeUtc   = (Get-Date).ToUniversalTime().ToString('o')
        TargetForest  = $EngineContext.Config['_TargetForest']
        ToolVersion   = $EngineContext.Config.General.Version
        AssessmentStatus = $score.AssessmentStatus
        Scope         = ConvertTo-Json -InputObject @{
            Selection = $EngineContext.AssessmentScope
            Exclusions = $EngineContext.Config.Exclusions
        } -Depth 5 -Compress
        SelectedRules = $score.SelectedRuleCount
        FullyAssessedRules = $score.FullyAssessedRuleCount
        PartialAssessment = $score.PartialAssessment
        Score         = $score.Score
        Grade         = $score.Grade
        TotalFindings = $score.TotalFindings
        Critical      = $score.BySeverity.Critical
        High          = $score.BySeverity.High
        Medium        = $score.BySeverity.Medium
        Low           = $score.BySeverity.Low
        Informational = $score.BySeverity.Informational
        Deduction     = $score.TotalDeduction
    }

    if (Test-Path $historyPath) {
        $entry | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8 -Append
    } else {
        $entry | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8
    }
}
