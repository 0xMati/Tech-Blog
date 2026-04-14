<#
.SYNOPSIS
    Audits and optionally remediates GPO permissions to ensure the built-in
    "Administrators" group has Full Control (Edit settings, delete, modify security)
    on all Group Policy Objects in the domain.

.DESCRIPTION
    This script:
    - Enumerates all GPOs in the target domain
    - Checks if the built-in Administrators group has GpoEditDeleteModifySecurity
    - Produces a CSV report of all GPOs with their current status
    - In -Remediate mode, adds the missing permission

.PARAMETER DomainName
    The FQDN of the target domain. Defaults to the current domain.

.PARAMETER Remediate
    Switch to apply the missing permissions. Without this, the script runs in audit-only mode.

.PARAMETER ReportPath
    Path for the CSV report. Defaults to .\GPO_Administrators_Audit_<domain>_<date>.csv

.EXAMPLE
    # Audit only
    .\Set-GPOAdministratorsFullControl.ps1

.EXAMPLE
    # Audit + Remediate
    .\Set-GPOAdministratorsFullControl.ps1 -Remediate

.EXAMPLE
    # Target a specific domain
    .\Set-GPOAdministratorsFullControl.ps1 -DomainName child.contoso.com -Remediate

.NOTES
    Requirements:
    - GroupPolicy PowerShell module (RSAT)
    - Domain Admin or equivalent permissions on the target domain
    - Run from a machine joined to the target domain or a trusted domain
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [string]$DomainName = (Get-ADDomain).DNSRoot,

    [Parameter()]
    [switch]$Remediate,

    [Parameter()]
    [string]$ReportPath
)

#Requires -Modules GroupPolicy, ActiveDirectory

# ── Setup ──────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'Stop'

if (-not $ReportPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeDomain = $DomainName -replace '\.', '_'
    $ReportPath = ".\GPO_Administrators_Audit_${safeDomain}_${timestamp}.csv"
}

$targetGroup = "BUILTIN\Administrators"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " GPO Administrators Full Control - Audit & Remediation"       -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain      : $DomainName"
Write-Host "Mode        : $(if ($Remediate) { 'REMEDIATE' } else { 'AUDIT ONLY' })"
Write-Host "Report      : $ReportPath"
Write-Host ""

# ── Enumerate GPOs ─────────────────────────────────────────────────────────────
Write-Host "Retrieving all GPOs from $DomainName ..." -ForegroundColor Yellow
$allGPOs = Get-GPO -All -Domain $DomainName
Write-Host "Found $($allGPOs.Count) GPO(s)." -ForegroundColor Green
Write-Host ""

# ── Audit & Remediate ──────────────────────────────────────────────────────────
$report = [System.Collections.Generic.List[PSCustomObject]]::new()
$missingCount = 0
$fixedCount   = 0
$errorCount   = 0

foreach ($gpo in $allGPOs) {

    $status       = "OK"
    $currentPerm  = $null
    $action       = "None"

    # Check current permission for Administrators
    try {
        $perm = Get-GPPermission -Guid $gpo.Id -TargetName "Administrators" `
                    -TargetType Group -DomainName $DomainName -ErrorAction Stop

        $currentPerm = $perm.Permission

        if ($perm.Permission -ne 'GpoEditDeleteModifySecurity') {
            $status = "Incomplete"
            $missingCount++
        }
    }
    catch {
        # The group has no explicit permission on this GPO
        $currentPerm = "None"
        $status = "Missing"
        $missingCount++
    }

    # Remediate if requested
    if ($Remediate -and $status -ne "OK") {
        if ($PSCmdlet.ShouldProcess($gpo.DisplayName, "Add Administrators Full Control")) {
            try {
                Set-GPPermission -Guid $gpo.Id `
                    -PermissionLevel GpoEditDeleteModifySecurity `
                    -TargetName "Administrators" `
                    -TargetType Group `
                    -DomainName $DomainName `
                    -Replace

                $action = "Fixed"
                $fixedCount++
                Write-Host "  [FIXED]   $($gpo.DisplayName)" -ForegroundColor Green
            }
            catch {
                $action = "Error: $($_.Exception.Message)"
                $errorCount++
                Write-Warning "  [ERROR]   $($gpo.DisplayName) - $($_.Exception.Message)"
            }
        }
    }
    elseif ($status -ne "OK") {
        Write-Host "  [MISSING] $($gpo.DisplayName) (Current: $currentPerm)" -ForegroundColor Yellow
    }

    $report.Add([PSCustomObject]@{
        GPOName           = $gpo.DisplayName
        GPOId             = $gpo.Id
        GPOStatus         = $gpo.GpoStatus
        CreationTime      = $gpo.CreationTime
        ModificationTime  = $gpo.ModificationTime
        Owner             = $gpo.Owner
        AdminPermission   = $currentPerm
        Status            = $status
        ActionTaken       = $action
    })
}

# ── Export report ──────────────────────────────────────────────────────────────
$report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Summary"                                                      -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Total GPOs     : $($allGPOs.Count)"
Write-Host "Already OK     : $($allGPOs.Count - $missingCount)" -ForegroundColor Green
Write-Host "Missing / Incomplete : $missingCount"                -ForegroundColor $(if ($missingCount -gt 0) { 'Yellow' } else { 'Green' })

if ($Remediate) {
    Write-Host "Fixed          : $fixedCount"  -ForegroundColor Green
    Write-Host "Errors         : $errorCount"  -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'Green' })
}

Write-Host ""
Write-Host "Report exported to: $ReportPath" -ForegroundColor Cyan
