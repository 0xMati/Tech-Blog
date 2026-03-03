# Engine\ConvertTo-MATIReport.ps1
# MATIv2 - Report orchestrator
# Calls the appropriate reporters based on configuration.

function ConvertTo-MATIReport {
    <#
    .SYNOPSIS
        Orchestrates report generation (CSV, HTML, JSON) based on config.
    .PARAMETER EngineContext
        The engine context hashtable containing findings, score, paths, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    Write-Host "=== Phase 4: Report Generation ===" -ForegroundColor Cyan

    $enabledFormats = @($EngineContext.Config.Report.EnabledFormats)

    # Load reporter functions
    $reportersDir = Join-Path $EngineContext.RootPath 'Reporters'
    foreach ($reporterFile in (Get-ChildItem -Path $reportersDir -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        if ($reporterFile.Name -notlike '*.tpl*') {
            . $reporterFile.FullName
        }
    }

    if ('CSV' -in $enabledFormats) {
        Write-Host "  [>] Generating CSV report..." -ForegroundColor DarkGray
        Export-MATICsv -EngineContext $EngineContext
        Write-Host "  [+] CSV exported to $($EngineContext.CsvDir)" -ForegroundColor Green
    }

    if ('HTML' -in $enabledFormats) {
        Write-Host "  [>] Generating HTML report..." -ForegroundColor DarkGray
        Export-MATIHtml -EngineContext $EngineContext
        Write-Host "  [+] HTML exported to $($EngineContext.HtmlDir)" -ForegroundColor Green
    }

    if ('JSON' -in $enabledFormats) {
        Write-Host "  [>] Generating JSON report..." -ForegroundColor DarkGray
        Export-MATIJson -EngineContext $EngineContext
        Write-Host "  [+] JSON exported to $($EngineContext.JsonDir)" -ForegroundColor Green
    }

    Write-Host "  Report generation complete.`n" -ForegroundColor Green
}
