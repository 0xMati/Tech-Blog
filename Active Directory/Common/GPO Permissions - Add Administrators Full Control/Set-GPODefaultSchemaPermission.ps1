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

.EXAMPLE
    # Read-only: show the current and proposed SDDL
    .\Set-GPODefaultSchemaPermission.ps1

.EXAMPLE
    # Apply the change
    .\Set-GPODefaultSchemaPermission.ps1 -Apply

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
    [switch]$Apply
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

# ── Check if BA is already present ────────────────────────────────────────────
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

# ── Build the new SDDL ───────────────────────────────────────────────────────
$newSDDL = $currentSDDL + $baACE

Write-Host "Built-in Administrators (BA) is NOT present in the default SDDL." -ForegroundColor Yellow
Write-Host ""
Write-Host "Proposed new SDDL:" -ForegroundColor Yellow
Write-Host $newSDDL
Write-Host ""

# ── Validate the SDDL ────────────────────────────────────────────────────────
try {
    $testSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($newSDDL)
    Write-Host "SDDL validation : OK ($($testSD.DiscretionaryAcl.Count) ACEs)" -ForegroundColor Green
}
catch {
    Write-Error "The proposed SDDL is invalid: $($_.Exception.Message)"
    return
}

# ── Apply or display ─────────────────────────────────────────────────────────
if ($Apply) {
    if ($PSCmdlet.ShouldProcess("groupPolicyContainer schema class", "Update defaultSecurityDescriptor")) {

        # Backup the current SDDL
        $backupFile = ".\GPO_Schema_SDDL_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        $currentSDDL | Out-File -FilePath $backupFile -Encoding UTF8
        Write-Host "Backup of current SDDL saved to: $backupFile" -ForegroundColor Cyan

        # Apply the change
        Set-ADObject -Identity $gpcClass.DistinguishedName `
            -Replace @{ defaultSecurityDescriptor = $newSDDL } `
            -Server $schemaMaster

        Write-Host ""
        Write-Host "Schema modification APPLIED successfully." -ForegroundColor Green
        Write-Host ""
        Write-Host "IMPORTANT:" -ForegroundColor Red
        Write-Host "  - This change applies to ALL domains in the forest." -ForegroundColor Red
        Write-Host "  - Only NEW GPOs will inherit this permission." -ForegroundColor Red
        Write-Host "  - Existing GPOs are NOT affected (use the remediation script)." -ForegroundColor Red
        Write-Host "  - Allow time for schema replication across all DCs." -ForegroundColor Red
    }
}
else {
    Write-Host "============================================================" -ForegroundColor Yellow
    Write-Host " DRY RUN - No changes applied"                                -ForegroundColor Yellow
    Write-Host " Re-run with -Apply to modify the schema"                     -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Yellow
}
