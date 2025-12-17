<# 
.SYNOPSIS
  Conditional Access troubleshooting from Entra ID sign-in logs (Microsoft Graph)
  - Table 1 (all policies): normal console table
  - Table 2 (recap): yellow table block

.PREREQUISITES
  - PowerShell 5.1 compatible
  - Microsoft Graph PowerShell SDK installed
  - Permissions: AuditLog.Read.All
#>

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Reports -ErrorAction Stop   # Get-MgAuditLogSignIn



# --------------------------------------------------------------------------------------------------------------------
# MAIN SETTINGS
# --------------------------------------------------------------------------------------------------------------------
$DaysBack   = 1
$ShowTop    = 5
$FilterUser = "barack.obama@mathiasmotron.com"   # e.g. "barack.obama@mathiasmotron.com" or $null
# --------------------------------------------------------------------------------------------------------------------
# 
# --------------------------------------------------------------------------------------------------------------------





try {
    $ctx = Get-MgContext
    if (-not $ctx -or -not $ctx.Account) {
        Connect-MgGraph -Scopes "AuditLog.Read.All" | Out-Null
    }
}
catch {
    Connect-MgGraph -Scopes "AuditLog.Read.All" | Out-Null
}

function Write-Separator {
    param([string]$Title = "")
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor DarkCyan
    if ($Title -and $Title.Trim().Length -gt 0) {
        Write-Host $Title -ForegroundColor Cyan
        Write-Host ("-" * 70) -ForegroundColor DarkCyan
    }
}

function Get-SignInLocationText {
    param([Parameter(Mandatory=$true)]$SignIn)

    $country = $null; $state = $null; $city = $null

    if ($SignIn.LocationDetails) {
        $country = $SignIn.LocationDetails.CountryOrRegion
        $state   = $SignIn.LocationDetails.State
        $city    = $SignIn.LocationDetails.City
    }
    elseif ($SignIn.Location) {
        $country = $SignIn.Location.CountryOrRegion
        $state   = $SignIn.Location.State
        $city    = $SignIn.Location.City
    }

    ("{0} / {1} / {2}" -f $country, $state, $city)
}

function Get-CAPolicyEvaluationRows {
    param([Parameter(Mandatory=$true)]$SignIn)

    if (-not $SignIn.AppliedConditionalAccessPolicies -or $SignIn.AppliedConditionalAccessPolicies.Count -eq 0) {
        return @()
    }

    $rows = foreach ($cap in $SignIn.AppliedConditionalAccessPolicies) {
        $result = $cap.Result

        $category = switch ($result) {
            "failure"               { "BLOCKED" }
            "success"               { "PASSED" }
            "notApplied"            { "NOT_APPLIED" }
            "reportOnlyFailure"     { "REPORT_ONLY_WOULD_FAIL" }
            "reportOnlyInterrupted" { "REPORT_ONLY_INTERRUPTED" }
            "reportOnlySuccess"     { "REPORT_ONLY_WOULD_PASS" }
            "reportOnlyNotApplied"  { "REPORT_ONLY_NOT_APPLIED" }
            default                 { "UNKNOWN" }
        }

        $severity = switch ($result) {
            "failure"               { 1 }
            "reportOnlyFailure"     { 2 }
            "reportOnlyInterrupted" { 3 }
            "success"               { 4 }
            "reportOnlySuccess"     { 5 }
            "notApplied"            { 6 }
            "reportOnlyNotApplied"  { 7 }
            default                 { 99 }
        }

        [PSCustomObject]@{
            Severity   = $severity
            Category   = $category
            Result     = $result
            PolicyName = $cap.DisplayName
            PolicyId   = $cap.Id
            Grant      = if ($cap.EnforcedGrantControls)   { ($cap.EnforcedGrantControls -join ", ") }   else { "" }
            Session    = if ($cap.EnforcedSessionControls) { ($cap.EnforcedSessionControls -join ", ") } else { "" }
        }
    }

    $rows | Sort-Object Severity, PolicyName
}

function Show-SignInHeader {
    param([Parameter(Mandatory=$true)]$SignIn)

    $locText = Get-SignInLocationText -SignIn $SignIn
    $errCode = $null
    if ($SignIn.Status) { $errCode = $SignIn.Status.ErrorCode }

    Write-Host ("Time   : {0}" -f $SignIn.CreatedDateTime)
    Write-Host ("User   : {0}" -f $SignIn.UserPrincipalName)
    Write-Host ("App    : {0}" -f $SignIn.AppDisplayName)
    Write-Host ("IP     : {0}" -f $SignIn.IPAddress)
    Write-Host ("Loc    : {0}" -f $locText)
    Write-Host ("CAStat : {0}" -f $SignIn.ConditionalAccessStatus)
    Write-Host ("ErrCode: {0}" -f $errCode)
    if ($SignIn.Status -and $SignIn.Status.FailureReason) {
        Write-Host ("Reason : {0}" -f $SignIn.Status.FailureReason)
    }
}

function Write-YellowTable {
    param(
        [Parameter(Mandatory=$true)]$Objects,
        [Parameter(Mandatory=$true)][string[]]$Columns
    )
    $txt = $Objects | Select-Object $Columns | Format-Table -AutoSize | Out-String
    Write-Host $txt -ForegroundColor Yellow
}

$since = (Get-Date).ToUniversalTime().AddDays(-1 * $DaysBack).ToString("o")
Write-Host ("Querying sign-ins since: {0} (UTC)" -f $since) -ForegroundColor Cyan

$signins = Get-MgAuditLogSignIn -Filter "createdDateTime ge $since" -All

$failures = $signins | Where-Object {
    $_.ConditionalAccessStatus -eq "failure" -and
    $_.Status -and $_.Status.ErrorCode -ne 0
}

if ($FilterUser -and $FilterUser.Trim().Length -gt 0) {
    $failures = $failures | Where-Object { $_.UserPrincipalName -eq $FilterUser }
}

$failures = $failures | Sort-Object CreatedDateTime -Descending | Select-Object -First $ShowTop

if (-not $failures -or $failures.Count -eq 0) {
    Write-Host "No Conditional Access failures found in the selected time window." -ForegroundColor Yellow
    return
}

foreach ($s in $failures) {

    Write-Separator -Title "SIGN-IN SUMMARY"
    Show-SignInHeader -SignIn $s

    $rows = Get-CAPolicyEvaluationRows -SignIn $s
    if (-not $rows -or $rows.Count -eq 0) {
        Write-Host ""
        Write-Host "No AppliedConditionalAccessPolicies returned for this event." -ForegroundColor Yellow
        continue
    }

    Write-Separator -Title "ALL CONDITIONAL ACCESS POLICIES (this sign-in)"
    $rows |
        Select-Object Category, PolicyName, Result, Grant, Session, PolicyId |
        Format-Table -AutoSize

    # RECAP: uniquement les policies qui BLOQUENT (sans report-only)
    $recap = $rows | Where-Object { $_.Category -eq "BLOCKED" }

    Write-Separator -Title "RECAP (ONLY BLOCKED - excluding REPORT-ONLY)"
    if (-not $recap -or $recap.Count -eq 0) {
        Write-Host "No blocking Conditional Access policy found in this event." -ForegroundColor Green
    }
    else {
        Write-YellowTable -Objects $recap -Columns @("Category","PolicyName","Result","Grant","Session","PolicyId")
    }

    Write-Host ""
}
