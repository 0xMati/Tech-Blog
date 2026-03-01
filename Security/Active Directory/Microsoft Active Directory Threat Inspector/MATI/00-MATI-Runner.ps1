# 00-MATI-Runner.ps1
#requires -Version 5.1

<#
    MATI - Microsoft Active Directory Threat Inspector
    Runner script

    - Creates a relative output folder under .\Outputs
    - Checks prerequisites (PowerShell, AD module, basic AD read rights)
    - Loads the common finding model
    - Calls MATI modules (config, privileged accounts, Kerberos, ACLs, ADCS...)
    - Produces:
        * Global CSV of all findings
        * HTML summary report
        * Overall score on 100
        * Score history (CSV) to track evolution over time
#>

cls

Write-Host "=== MATI - Microsoft Active Directory Threat Inspector (Runner) ===" -ForegroundColor Cyan

# --------------------------------------------------------------------
# 1. Timestamp & centralized output paths (.\Outputs\Output_*)
# --------------------------------------------------------------------
$OutputsBase = Join-Path $PSScriptRoot "Outputs"
New-Item -ItemType Directory -Path $OutputsBase -Force | Out-Null

$Date       = Get-Date -Format "yyyyMMdd-HHmmss"
$OutputRoot = Join-Path $OutputsBase "Output_$Date"
$CsvDir     = Join-Path $OutputRoot "CSV"
$HtmlDir    = Join-Path $OutputRoot "HTML"

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $CsvDir     -Force | Out-Null
New-Item -ItemType Directory -Path $HtmlDir    -Force | Out-Null

$TranscriptPath = Join-Path $OutputRoot "Transcript_MATI_AD_Security_Assessment_$Date.txt"
Start-Transcript -Path $TranscriptPath | Out-Null

Write-Host "Output root : $OutputRoot" -ForegroundColor DarkGray

# --------------------------------------------------------------------
# 2. Prerequisites checks
# --------------------------------------------------------------------

# PowerShell version (MATI targets Windows PowerShell 5.1)
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "MATI requires Windows PowerShell 5.1."
    Stop-Transcript | Out-Null
    return
}

# ActiveDirectory module (RSAT)
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory module not found. Install RSAT (AD DS and LDS tools) on this machine."
    Stop-Transcript | Out-Null
    return
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    Stop-Transcript | Out-Null
    return
}

# Basic AD read permissions
try {
    Get-ADDomain -ErrorAction Stop | Out-Null
}
catch {
    Write-Error "Insufficient permissions to read Active Directory. Run MATI with a user that has AD read access."
    Stop-Transcript | Out-Null
    return
}

Write-Host "Prerequisites check passed." -ForegroundColor Green

# --------------------------------------------------------------------
# 3. Load common functions & initialize global findings
# --------------------------------------------------------------------
$commonPath = Join-Path $PSScriptRoot "Common\Finding.ps1"
if (-not (Test-Path $commonPath)) {
    Write-Error "Common file not found: $commonPath"
    Stop-Transcript | Out-Null
    return
}

. $commonPath

# Legacy global findings (used by older modules)
$Global:Findings = @()

# Aggregated findings from all modules (new pattern)
$allFindings = @()

# --------------------------------------------------------------------
# 4. Run MATI modules
# --------------------------------------------------------------------
$modulesRoot = Join-Path $PSScriptRoot "Modules"

# Modules order
$moduleList = @(
    "10-MATI-Config.ps1",
    "20-MATI-PrivilegedAccounts.ps1",
    "30-MATI-KerberosAndDelegation.ps1",
    "40-MATI-StaleObjectsAndOS.ps1",
    "50-MATI-ACLs.ps1",          # Nouveau module ACLs (AdminSDHolder + objets protégés)
    "60-MATI-GPO-ACLs.ps1",      # Futur module GPO ACLs (sera ignoré tant que le fichier n'existe pas)
    "60-MATI-ADCS-LightCheck.ps1"
)

foreach ($m in $moduleList) {
    $modulePath = Join-Path $modulesRoot $m

    if (-not (Test-Path $modulePath)) {
        Write-Warning "Module not found (skipped): $modulePath"
        continue
    }

    Write-Host "`n[*] Running module: $m" -ForegroundColor Yellow

    try {
        # Each module must accept -OutputRoot and may:
        #  - append to $Global:Findings (legacy style)
        #  - return a list of Finding objects (new style)
        $moduleResult = & $modulePath -OutputRoot $OutputRoot

        if ($null -ne $moduleResult) {
            $moduleFindings = $moduleResult | Where-Object {
                $_ -is [psobject] -and
                $_.PSObject.Properties['Id'] -and
                $_.PSObject.Properties['Category'] -and
                $_.PSObject.Properties['Severity']
            }

            if ($moduleFindings) {
                $allFindings += $moduleFindings
            }
        }
    }
    catch {
        Write-Error "Module $m failed: $($_.Exception.Message)"
        # Continue with other modules; you can change this behavior later if needed
    }
}

# --------------------------------------------------------------------
# 4bis. Merge legacy $Global:Findings into $allFindings
# --------------------------------------------------------------------
if ($Global:Findings -and $Global:Findings.Count -gt 0) {
    $legacyFindings = $Global:Findings | Where-Object {
        $_ -is [psobject] -and
        $_.PSObject.Properties['Id'] -and
        $_.PSObject.Properties['Category'] -and
        $_.PSObject.Properties['Severity']
    }

    if ($legacyFindings) {
        $allFindings += $legacyFindings
    }
}

# Deduplicate findings (in case some modules later do both: global + return)
if ($allFindings.Count -gt 0) {
    $allFindings = $allFindings |
        Sort-Object Id, ObjectDN, Source -Unique
}

# --------------------------------------------------------------------
# 5. Global findings export (CSV + HTML) + scoring
# --------------------------------------------------------------------
$criticalCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount     = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount   = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount      = ($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count
$totalFindings = $allFindings.Count

# Scoring weights (can be adjusted later)
$baseScore = 100
$risk      = ($criticalCount * 10) + `
             ($highCount     * 5)  + `
             ($mediumCount   * 2)  + `
             ($lowCount      * 1)

$score = $baseScore - $risk
if ($score -lt 0) { $score = 0 }

if ($totalFindings -eq 0) {
    Write-Host "`nNo findings were generated by MATI modules." -ForegroundColor Cyan
}

Write-Host "`nMATI score: $score / 100" -ForegroundColor Cyan
Write-Host "Critical: $criticalCount; High: $highCount; Medium: $mediumCount; Low: $lowCount (Total: $totalFindings)" -ForegroundColor DarkGray

# 5.1 Global CSV (even if empty, for consistency)
$globalCsvPath = Join-Path $CsvDir "MATI_AD_Findings_Global_$Date.csv"
$allFindings |
    Sort-Object Severity, Category, Id |
    Export-Csv -Path $globalCsvPath -NoTypeInformation -Encoding UTF8

Write-Host "`nGlobal findings CSV: $globalCsvPath" -ForegroundColor Green

# --------------------------------------------------------------------
# 5.2 HTML report
# --------------------------------------------------------------------
$htmlBody = @()

$htmlBody += "<h1>MATI - Microsoft Active Directory Threat Inspector</h1>"
$htmlBody += "<p>Date: $(Get-Date)</p>"

# Overall score
$htmlBody += "<h2>Overall score</h2>"
$htmlBody += "<p><strong>MATI score:</strong> $score / 100</p>"
$htmlBody += "<p>Critical: $criticalCount; High: $highCount; Medium: $mediumCount; Low: $lowCount; Total findings: $totalFindings</p>"

# Summary by severity
$htmlBody += "<h2>Summary by severity</h2>"
$htmlBody += "<table>"
$htmlBody += "<tr><th>Severity</th><th>Count</th></tr>"

$summary = $allFindings |
    Group-Object Severity |
    Select-Object Name, Count

foreach ($s in $summary) {
    $htmlBody += "<tr><td>$($s.Name)</td><td>$($s.Count)</td></tr>"
}
$htmlBody += "</table>"

# --------------------------------------------------------------------
# Details by category, in module order
# --------------------------------------------------------------------
# IMPORTANT: these names must match the Category field used in New-Finding
$categoryOrder = @(
    'Config',              # 10-MATI-Config
    'PrivilegedAccounts',  # 20-MATI-PrivilegedAccounts
    'Kerberos',            # 30-MATI-KerberosAndDelegation
    'StaleObjectsAndOS',   # 40-MATI-StaleObjectsAndOS
    'ACLs',                # 50-MATI-ACLs.ps1
    'GPO-ACLs',            # 60-MATI-GPO-ACLs.ps1 (futur module)
    'ADCS'                 # 60-MATI-ADCS-LightCheck.ps1
)

# 1) Categories dans l'ordre des modules
foreach ($catName in $categoryOrder) {

    $catFindings = $allFindings | Where-Object { $_.Category -eq $catName }

    if (-not $catFindings) {
        continue
    }

    $htmlBody += "<h2>Module: $catName</h2>"
    $htmlBody += "<table>"
    $htmlBody += "<tr><th>Id</th><th>Severity</th><th>Title</th><th>Description</th><th>Object</th><th>Remediation</th><th>Details</th></tr>"

    foreach ($f in $catFindings) {
        $htmlBody += "<tr>"
        $htmlBody += "<td>$($f.Id)</td>"
        $htmlBody += "<td>$($f.Severity)</td>"
        $htmlBody += "<td>$($f.Title)</td>"
        $htmlBody += "<td>$($f.Description)</td>"
        $htmlBody += "<td><code>$($f.ObjectDN)</code></td>"
        $htmlBody += "<td>$($f.Remediation)</td>"
        $htmlBody += "<td>$($f.Details)</td>"
        $htmlBody += "</tr>"
    }

    $htmlBody += "</table>"
}

# 2) Éventuelles catégories “hors ordre” (modules futurs)
$known = $categoryOrder
$otherCategories = $allFindings |
    Group-Object Category |
    Where-Object { $known -notcontains $_.Name }

foreach ($cat in $otherCategories) {
    $htmlBody += "<h2>Category: $($cat.Name)</h2>"
    $htmlBody += "<table>"
    $htmlBody += "<tr><th>Id</th><th>Severity</th><th>Title</th><th>Description</th><th>Object</th><th>Remediation</th><th>Details</th></tr>"

    foreach ($f in $cat.Group) {
        $htmlBody += "<tr>"
        $htmlBody += "<td>$($f.Id)</td>"
        $htmlBody += "<td>$($f.Severity)</td>"
        $htmlBody += "<td>$($f.Title)</td>"
        $htmlBody += "<td>$($f.Description)</td>"
        $htmlBody += "<td><code>$($f.ObjectDN)</code></td>"
        $htmlBody += "<td>$($f.Remediation)</td>"
        $htmlBody += "<td>$($f.Details)</td>"
        $htmlBody += "</tr>"
    }

    $htmlBody += "</table>"
}

$htmlPath = Join-Path $HtmlDir "MATI_AD_Security_Assessment_$Date.html"

$fullHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8' />
<title>MATI - AD Security Assessment - $Date</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; font-size: 12px; }
h1, h2 { color: #2F5597; }
table { border-collapse: collapse; margin-bottom: 20px; width: 100%; }
th { background-color: #D9E1F2; text-align: left; }
td, th { border: 1px solid #B4C7E7; padding: 4px; vertical-align: top; }
code { font-size: 11px; }
</style>
</head>
<body>
$($htmlBody -join "`n")
</body>
</html>
"@

$fullHtml | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "HTML report: $htmlPath" -ForegroundColor Green

# --------------------------------------------------------------------
# 6. Score history (relative to runner)
# --------------------------------------------------------------------
$historyDir  = Join-Path $PSScriptRoot "History"
$historyPath = Join-Path $historyDir "MATI_ScoreHistory.csv"

New-Item -ItemType Directory -Path $historyDir -Force | Out-Null

$nowUtc = (Get-Date).ToUniversalTime().ToString("o")  # ISO 8601

$historyLine = [PSCustomObject]@{
    DateTimeUtc    = $nowUtc
    Score          = $score
    CriticalCount  = $criticalCount
    HighCount      = $highCount
    MediumCount    = $mediumCount
    LowCount       = $lowCount
    TotalFindings  = $totalFindings
}

if (-not (Test-Path $historyPath)) {
    $historyLine | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8
}
else {
    $historyLine | Export-Csv -Path $historyPath -NoTypeInformation -Encoding UTF8 -Append
}

Write-Host "Score history updated: $historyPath" -ForegroundColor DarkGray

# --------------------------------------------------------------------
# 7. End
# --------------------------------------------------------------------
Stop-Transcript | Out-Null
Write-Host "`nMATI run completed." -ForegroundColor Cyan
