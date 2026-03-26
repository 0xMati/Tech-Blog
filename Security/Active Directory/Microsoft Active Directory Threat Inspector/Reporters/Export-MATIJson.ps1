# Reporters\Export-MATIJson.ps1
# MATIv2 - JSON reporter (for SIEM integration, automation, etc.)

function Export-MATIJson {
    <#
    .SYNOPSIS
        Exports findings and score to a structured JSON file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    $jsonDir   = $EngineContext.JsonDir
    $timestamp = $EngineContext.Timestamp
    $config    = $EngineContext.Config
    $filePrefix = if ($config['_ReportFilePrefix']) { $config['_ReportFilePrefix'] } else { 'MATI_' }

    $jsonReport = @{
        metadata = @{
            tool             = $config.General.ToolName
            version          = $config.General.Version
            timestamp        = $timestamp
            generatedAt      = (Get-Date -Format 'o')
            targetForest     = $config['_TargetForest']
            executionContext = $EngineContext.ExecutionContext
        }
        score    = $EngineContext.Score
        summary  = @{
            totalFindings = $EngineContext.Findings.Count
            bySeverity    = @{
                Critical      = ($EngineContext.Findings | Where-Object Severity -eq 'Critical').Count
                High          = ($EngineContext.Findings | Where-Object Severity -eq 'High').Count
                Medium        = ($EngineContext.Findings | Where-Object Severity -eq 'Medium').Count
                Low           = ($EngineContext.Findings | Where-Object Severity -eq 'Low').Count
                Informational = ($EngineContext.Findings | Where-Object Severity -eq 'Informational').Count
            }
            byCategory    = @{}
        }
        findings = @()
    }

    # Group by category
    $grouped = $EngineContext.Findings | Group-Object Category
    foreach ($group in $grouped) {
        $jsonReport.summary.byCategory[$group.Name] = $group.Count
    }

    # Serialize findings
    $jsonReport.findings = @($EngineContext.Findings | ForEach-Object {
        @{
            id          = $_.Id
            category    = $_.Category
            severity    = $_.Severity
            title       = $_.Title
            description = $_.Description
            remediation = $_.Remediation
            objectDN    = $_.ObjectDN
            domain      = $_.Domain
            ruleFile    = $_.RuleFile
            weight      = $_.Weight
            details     = $_.Details
            timestamp   = $_.Timestamp.ToString('o')
        }
    })

    $jsonPath = Join-Path $jsonDir "${filePrefix}Report_$timestamp.json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

    # Also export a lightweight findings-only JSON
    $findingsOnlyPath = Join-Path $jsonDir "${filePrefix}Findings_$timestamp.json"
    $jsonReport.findings | ConvertTo-Json -Depth 10 | Out-File -FilePath $findingsOnlyPath -Encoding UTF8
}
