function Invoke-EIDMPhase_02-IdentityPreparation {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $steps = @(
        @{
            Id       = "02-01-BuildUsersOnPremProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-01-BuildUsersOnPremProvisioningPlan"
            Requires = @()
        }
    )

    Invoke-EIDMPhase -Ctx $Ctx -PhaseName "02-IdentityPreparation" -Steps $steps
}

function Step-02-01-BuildUsersOnPremProvisioningPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Users_OnPrem_ProvisioningPlan"

    # --------------------------------------------------
    # Context shortcuts (do NOT use global $config)
    # --------------------------------------------------
    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    # Ensure OnPremIdentity section exists in config (safety)
    if (-not $config.ContainsKey("OnPremIdentity")) {
        $config.OnPremIdentity = @{}
    }
    if (-not $config.OnPremIdentity.ContainsKey("LastUsedTargetOU")) {
        $config.OnPremIdentity.LastUsedTargetOU = ""
    }

    # --------------------------------------------------
    # Load Discovery Users
    # --------------------------------------------------
    $usersPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraUsers_SOURCE.csv"
    if (-not (Test-Path $usersPath)) {
        throw "EntraUsers_SOURCE.csv not found. Run Discovery first."
    }

    $users = Import-Csv $usersPath

    # Filter Synced users only
    $synced = $users | Where-Object { $_.OnPremisesSyncEnabled -eq "True" }

    if (-not $synced -or $synced.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No synced users detected." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Synced users detected: {0}" -f $synced.Count) -Color Cyan
    Write-Host ""

    # --------------------------------------------------
    # Ask Target OU (interactive)
    # --------------------------------------------------
    $defaultOU = [string]$config.OnPremIdentity.LastUsedTargetOU
    if (-not $defaultOU) { $defaultOU = "" }

    $prompt = "Enter Target OU for synced users"
    if ($defaultOU) {
        $inputOU = Read-Host ("{0} [{1}]" -f $prompt, $defaultOU)
        if ([string]::IsNullOrWhiteSpace($inputOU)) { $inputOU = $defaultOU }
    }
    else {
        $inputOU = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($inputOU)) {
            throw "Target OU cannot be empty."
        }
    }

    # Persist last used OU in config.psd1
    $config.OnPremIdentity.LastUsedTargetOU = $inputOU
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    # --------------------------------------------------
    # Extract distinct UPN suffixes from synced users (source)
    # Use OnPremisesUserPrincipalName if present, else UserPrincipalName
    # --------------------------------------------------
    $suffixes = $synced | ForEach-Object {
        $upn = if ($_.OnPremisesUserPrincipalName) { $_.OnPremisesUserPrincipalName } else { $_.UserPrincipalName }
        if ($upn -and $upn.Contains("@")) { $upn.Split("@")[1] } else { "" }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

    $suffixDecisions = @{}  # key = SourceSuffix, value = @{ Target=""; Status="Ready|Blocked" }

    foreach ($suffix in $suffixes) {

        Write-Host ""
        Write-EIDMTag -Tag "SUFFIX" -Text $suffix -Color Yellow

        do {
        $use = Read-Host "Use this suffix in target AD? (Y/N)"
            if ([string]::IsNullOrWhiteSpace($use)) { $use = "N" }  # default behavior
            $use = $use.Trim().ToUpper()
        } while ($use -notin @("Y","N"))

        if ($use.ToUpper() -eq "Y") {
            $targetSuffix = $suffix
        }
        else {
            $targetSuffix = Read-Host "Enter target suffix to use instead (e.g. newcorp.com)"
            if ([string]::IsNullOrWhiteSpace($targetSuffix)) {
                $suffixDecisions[$suffix] = @{ Target = ""; Status = "Blocked" }
                continue
            }
            $targetSuffix = $targetSuffix.Trim()
        }

        # Check if suffix exists in AD
        $forest = Get-ADForest
        $exists = $false

        # forest.UPNSuffixes is the authoritative list; RootDomain can also be used as a suffix sometimes
        if ($forest.UPNSuffixes -contains $targetSuffix -or $forest.RootDomain -eq $targetSuffix) {
            $exists = $true
        }

        if (-not $exists) {
            $create = Read-Host ("Target AD does not contain UPN suffix '{0}'. Create it now? (Y/N)" -f $targetSuffix)
            $create = ($create | ForEach-Object { $_.Trim() })

            if ($create.ToUpper() -eq "Y") {
                Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Add = $targetSuffix }
                # Re-check (fail-fast if not added)
                $forest2 = Get-ADForest
                if ($forest2.UPNSuffixes -contains $targetSuffix -or $forest2.RootDomain -eq $targetSuffix) {
                    $exists = $true
                }
            }
        }

        if (-not $exists) {
            $suffixDecisions[$suffix] = @{ Target = $targetSuffix; Status = "Blocked" }
        }
        else {
            $suffixDecisions[$suffix] = @{ Target = $targetSuffix; Status = "Ready" }
        }
    }

    # --------------------------------------------------
    # Build Provisioning Plan (single output file)
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($u in $synced) {

        $sourceUPN = if ($u.OnPremisesUserPrincipalName) { $u.OnPremisesUserPrincipalName } else { $u.UserPrincipalName }
        $sourceSuffix = if ($sourceUPN -and $sourceUPN.Contains("@")) { $sourceUPN.Split("@")[1] } else { "" }

        $localPart = [string]$u.OnPremisesSamAccountName

        # If samAccountName is missing, we block (do not invent)
        if ([string]::IsNullOrWhiteSpace($localPart)) {
            $plan.Add([PSCustomObject]@{
                SourceObjectId                 = $u.Id
                SourceUPN                      = $u.UserPrincipalName
                SourceDisplayName              = $u.DisplayName
                SourceOnPremisesSamAccountName = $u.OnPremisesSamAccountName
                SourceUPNSuffix                = $sourceSuffix
                TargetUPNSuffix_Selected        = ""
                ProvisioningAction              = "Blocked"
                TargetOU_Proposed               = $inputOU
                TargetSamAccountName_Proposed   = ""
                TargetUPN_Proposed              = ""
                OnPremCreationStatus            = "Pending"
                OnPremCreationMessage           = "Blocked: Missing OnPremisesSamAccountName"
            })
            continue
        }

        $decision = $suffixDecisions[$sourceSuffix]
        if (-not $decision) {
            $decision = @{ Target = ""; Status = "Blocked" }
        }

        $status = $decision.Status
        $targetSuffix = [string]$decision.Target

        $targetUPN = ""
        if ($status -eq "Ready" -and -not [string]::IsNullOrWhiteSpace($targetSuffix)) {
            $targetUPN = ("{0}@{1}" -f $localPart, $targetSuffix)
        }

        $plan.Add([PSCustomObject]@{
            SourceObjectId                 = $u.Id
            SourceUPN                      = $u.UserPrincipalName
            SourceDisplayName              = $u.DisplayName
            SourceOnPremisesSamAccountName = $u.OnPremisesSamAccountName
            SourceUPNSuffix                = $sourceSuffix
            TargetUPNSuffix_Selected        = $targetSuffix
            ProvisioningAction              = if ($status -eq "Ready") { "CreateInOnPrem" } else { "Blocked" }
            TargetOU_Proposed               = $inputOU
            TargetSamAccountName_Proposed   = $localPart
            TargetUPN_Proposed              = $targetUPN
            OnPremCreationStatus            = "Pending"
            OnPremCreationMessage           = if ($status -eq "Ready") { "" } else { "Blocked: UPN suffix not ready in target AD" }
        })
    }

    # Ensure phase folder exists
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "Users_OnPrem_ProvisioningPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Provisioning plan generated: {0}" -f $outputPath) -Color Green

    # Gate: operator must review the plan
    return $script:EIDMStatus_WaitingUser
}
function Get-EIDMIdentityPreparationSteps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id       = "02-01-BuildUsersOnPremProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-01-BuildUsersOnPremProvisioningPlan"
            Requires = @()
        }
    )
}

