<#
.SYNOPSIS
    Modifies the default security descriptor (defaultSecurityDescriptor) of the
    groupPolicyContainer schema class to include Built-in Administrators (BA)
    with Full Control, so that all newly created GPOs inherit this permission.

.DESCRIPTION
    By default, the groupPolicyContainer class in the AD schema does NOT include
    the Built-in Administrators (BA) group in its default SDDL. This means that
    when a new GPO is created, the Administrators group does not automatically
    get Full Control.

    This script:
    1. Connects to the Schema naming context
    2. Reads the current defaultSecurityDescriptor of groupPolicyContainer
    3. Checks if the BA ACE is already present
    4. If missing, appends the BA Full Control ACE to the SDDL
    5. In -Apply mode, writes the updated SDDL back to the schema

    The ACE added is:
        (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;BA)

    This grants: Read/Write Property, Create/Delete Child, List Children,
    List Object, Read Control, Write Owner, Write DACL, Standard Delete,
    Delete Tree, Self Write — with Container Inherit.

.PARAMETER Apply
    Switch to actually apply the schema change. Without this, the script
    runs in read-only mode and only shows what would change.

.PARAMETER Revert
    Switch to remove the Built-in Administrators (BA) ACE from the
    defaultSecurityDescriptor, reverting to the original default state.
    Must be combined with -Apply to actually write the change.

.EXAMPLE
    # Read-only: show the current and proposed SDDL
    .\Set-GPODefaultSchemaPermission.ps1

.EXAMPLE
    # Apply the change
    .\Set-GPODefaultSchemaPermission.ps1 -Apply

.EXAMPLE
    # Show what reverting would look like (dry run)
    .\Set-GPODefaultSchemaPermission.ps1 -Revert

.EXAMPLE
    # Revert to default (remove BA ACE)
    .\Set-GPODefaultSchemaPermission.ps1 -Revert -Apply

.NOTES
    Requirements:
    - Must be run as a member of the Schema Admins group
    - Must be run on or able to reach the Schema Master FSMO
    - This is a FOREST-WIDE schema change — it affects ALL domains
    - The change is irreversible through normal means (backup the current SDDL)
    - Replication of the schema change may take time depending on the topology
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [switch]$Revert
)

#Requires -Modules ActiveDirectory

$ErrorActionPreference = 'Stop'

# ── Identify the Schema Master ────────────────────────────────────────────────
$forest = Get-ADForest
$schemaMaster = $forest.SchemaMaster
Write-Host "Schema Master FSMO : $schemaMaster" -ForegroundColor Cyan

# ── Get the groupPolicyContainer class from the schema ─────────────────────────
$schemaNC = (Get-ADRootDSE).schemaNamingContext

$gpcClass = Get-ADObject -SearchBase $schemaNC `
    -Filter { lDAPDisplayName -eq "groupPolicyContainer" } `
    -Properties defaultSecurityDescriptor, lDAPDisplayName `
    -Server $schemaMaster

if (-not $gpcClass) {
    Write-Error "Could not find the groupPolicyContainer class in the schema."
    return
}

$currentSDDL = $gpcClass.defaultSecurityDescriptor

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " groupPolicyContainer - Default Security Descriptor"          -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Current SDDL:" -ForegroundColor Yellow
Write-Host $currentSDDL
Write-Host ""

# ── The ACE to add for Built-in Administrators (BA) ───────────────────────────
# Full Control with Container Inherit, matching the rights given to DA/EA/SY
$baACE = "(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;BA)"

# ── Revert mode: remove the BA ACE ───────────────────────────────────────────
if ($Revert) {
    if ($currentSDDL -notmatch ';;;BA\)') {
        Write-Host "The Built-in Administrators (BA) group is NOT present in the SDDL." -ForegroundColor Green
        Write-Host "Already in default state - no modification needed." -ForegroundColor Green
        return
    }

    # Remove all BA ACEs from the SDDL
    $newSDDL = $currentSDDL -replace '\([^)]*;;;BA\)', ''

    Write-Host "REVERT MODE: Removing Built-in Administrators (BA) ACE." -ForegroundColor Magenta
    Write-Host ""

    if ($currentSDDL -match '(\([^)]*;;;BA\))') {
        Write-Host "BA ACE being removed: $($Matches[1])" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Proposed reverted SDDL:" -ForegroundColor Yellow
    Write-Host $newSDDL
    Write-Host ""
}
else {
    # ── Check if BA is already present ────────────────────────────────────────
    if ($currentSDDL -match ';;;BA\)') {
        Write-Host "The Built-in Administrators (BA) group is ALREADY present in the SDDL." -ForegroundColor Green
        Write-Host "No modification needed." -ForegroundColor Green
        Write-Host ""

        # Parse and display the existing BA ACE
        if ($currentSDDL -match '(\([^)]*;;;BA\))') {
            Write-Host "Existing BA ACE: $($Matches[1])" -ForegroundColor Cyan
        }
        return
    }

    # ── Build the new SDDL ────────────────────────────────────────────────────
    $newSDDL = $currentSDDL + $baACE

    Write-Host "Built-in Administrators (BA) is NOT present in the default SDDL." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Proposed new SDDL:" -ForegroundColor Yellow
    Write-Host $newSDDL
    Write-Host ""
}

# ── Validate the SDDL ────────────────────────────────────────────────────────
try {
    $testSD = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $newSDDL
    $aceCount = $testSD.DiscretionaryAcl.Count
    Write-Host "SDDL validation : OK `($aceCount ACEs`)" -ForegroundColor Green
}
catch {
    Write-Error "The proposed SDDL is invalid: $($_.Exception.Message)"
    return
}

# ── Apply or display ─────────────────────────────────────────────────────────
if ($Apply) {
    $action = if ($Revert) { "Revert defaultSecurityDescriptor (remove BA)" } else { "Update defaultSecurityDescriptor (add BA)" }
    if ($PSCmdlet.ShouldProcess("groupPolicyContainer schema class", $action)) {

        # Backup the current SDDL
        $backupFile = ".\GPO_Schema_SDDL_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $currentSDDL | Out-File -FilePath $backupFile -Encoding UTF8
        Write-Host "Backup of current SDDL saved to: $backupFile" -ForegroundColor Cyan

        # Apply the change
        Set-ADObject -Identity $gpcClass.DistinguishedName `
            -Replace @{ defaultSecurityDescriptor = $newSDDL } `
            -Server $schemaMaster

        Write-Host ""
        if ($Revert) {
            Write-Host "Schema modification REVERTED successfully." -ForegroundColor Green
            Write-Host "The Built-in Administrators (BA) ACE has been removed." -ForegroundColor Green
        }
        else {
            Write-Host "Schema modification APPLIED successfully." -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "IMPORTANT:" -ForegroundColor Red
        Write-Host "  - This change applies to ALL domains in the forest." -ForegroundColor Red
        Write-Host "  - Only NEW GPOs will inherit this permission change." -ForegroundColor Red
        Write-Host "  - Existing GPOs are NOT affected." -ForegroundColor Red
        Write-Host "  - Allow time for schema replication across all DCs." -ForegroundColor Red
    }
}
else {
    $hint = if ($Revert) { " Re-run with -Revert -Apply to revert the schema" } else { " Re-run with -Apply to modify the schema" }
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " DRY RUN - No changes applied"                                -ForegroundColor Yellow
    Write-Host $hint                                                           -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
}
