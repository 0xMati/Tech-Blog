# Engine\Initialize-MATIEngine.ps1
# MATIv2 - Bootstrap engine
# Loads configuration, discovers collectors and rules, validates prerequisites.

function Initialize-MATIEngine {
    <#
    .SYNOPSIS
        Initializes the MATI engine: loads config, discovers rules & collectors,
        checks prerequisites.
    .OUTPUTS
        [hashtable] Engine context object used by all subsequent phases.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [string]$ConfigPath,

        [string]$TargetForest
    )

    Write-Host "`n=== MATI v2 - Microsoft Active Directory Threat Inspector ===" -ForegroundColor Cyan
    Write-Host "Initializing engine...`n" -ForegroundColor DarkGray

    # ------------------------------------------------------------------
    # 1. Load configuration
    # ------------------------------------------------------------------
    if (-not $ConfigPath) {
        $ConfigPath = Join-Path $RootPath 'Config\MATI.config.psd1'
    }
    $configPath = $ConfigPath
    if (-not (Test-Path $configPath)) {
        throw "Configuration file not found: $configPath"
    }
    $Config = Import-PowerShellDataFile -Path $configPath
    Write-Host "  [+] Configuration loaded from $configPath" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 2. Load models (Finding class + factory)
    # ------------------------------------------------------------------
    $modelsDir = Join-Path $RootPath 'Models'
    foreach ($modelFile in (Get-ChildItem -Path $modelsDir -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        . $modelFile.FullName
    }
    Write-Host "  [+] Models loaded" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 3. Discover collectors
    # ------------------------------------------------------------------
    $collectorsDir = Join-Path $RootPath 'Collectors'
    $collectors = @{}
    foreach ($collectorFile in (Get-ChildItem -Path $collectorsDir -Filter '*.ps1' -ErrorAction SilentlyContinue)) {
        # Derive collector name from filename: Get-MATIDomainInfo.ps1 → DomainInfo
        $collectorName = $collectorFile.BaseName -replace '^Get-MATI', ''
        $collectors[$collectorName] = @{
            Name     = $collectorName
            FilePath = $collectorFile.FullName
            Function = $collectorFile.BaseName   # e.g. Get-MATIDomainInfo
        }
        . $collectorFile.FullName
    }
    Write-Host "  [+] Discovered $($collectors.Count) collectors" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 4. Discover rules
    # ------------------------------------------------------------------
    $rulesDir = Join-Path $RootPath 'Rules'
    $rules = [System.Collections.Generic.List[hashtable]]::new()
    $disabledRules      = @($Config.Exclusions.DisabledRules)
    $disabledCategories = @($Config.Exclusions.DisabledCategories)

    foreach ($categoryDir in (Get-ChildItem -Path $rulesDir -Directory -ErrorAction SilentlyContinue)) {
        $category = $categoryDir.Name

        if ($category -in $disabledCategories) {
            Write-Host "  [~] Category '$category' is disabled - skipping" -ForegroundColor Yellow
            continue
        }

        foreach ($ruleFile in (Get-ChildItem -Path $categoryDir.FullName -Filter '*.rule.ps1')) {
            $ruleDef = & $ruleFile.FullName  # Execute to get the hashtable definition

            if ($ruleDef -isnot [hashtable] -or -not $ruleDef.Id) {
                throw "Invalid rule definition: $($ruleFile.FullName)"
            }

            # Schema validation — warn on missing required keys
            $requiredKeys = @('Id', 'Title', 'Severity', 'Condition', 'Collectors')
            $missingKeys  = $requiredKeys | Where-Object { -not $ruleDef.ContainsKey($_) -or $null -eq $ruleDef[$_] }
            if ($missingKeys) {
                throw "Rule $($ruleDef.Id) ($($ruleFile.Name)) missing keys: $($missingKeys -join ', ')"
            }
            if ($ruleDef.Condition -isnot [scriptblock]) { throw "Rule $($ruleDef.Id) has no executable Condition." }
            if ($ruleDef.Id -in $rules.Id) { throw "Duplicate rule ID: $($ruleDef.Id)" }
            foreach ($dependency in $ruleDef.Collectors) {
                if (-not $collectors.ContainsKey($dependency)) { throw "Rule $($ruleDef.Id) requires missing collector '$dependency'." }
            }
            if ($ruleDef.ContainsKey('CollectorDatasets')) {
                if ($ruleDef.CollectorDatasets -isnot [hashtable]) { throw "Rule $($ruleDef.Id) has invalid CollectorDatasets." }
                foreach ($dependency in $ruleDef.CollectorDatasets.Keys) {
                    if ($dependency -notin $ruleDef.Collectors) { throw "Rule $($ruleDef.Id) declares datasets for an unused collector '$dependency'." }
                    $requirement = $ruleDef.CollectorDatasets[$dependency]
                    if ($requirement -isnot [scriptblock] -and
                        (@($requirement).Count -eq 0 -or @($requirement | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count)) {
                        throw "Rule $($ruleDef.Id) has invalid dataset requirements for '$dependency'."
                    }
                }
            }

            if ($ruleDef.Id -in $disabledRules) {
                Write-Host "  [~] Rule $($ruleDef.Id) is disabled - skipping" -ForegroundColor Yellow
                continue
            }

            $effectiveCategory = if ($ruleDef.ContainsKey('Category') -and -not [string]::IsNullOrWhiteSpace($ruleDef.Category)) {
                "$($ruleDef.Category)".Trim()
            } else {
                $category
            }

            if ($effectiveCategory -in $disabledCategories) {
                Write-Host "  [~] Rule $($ruleDef.Id) category '$effectiveCategory' is disabled - skipping" -ForegroundColor Yellow
                continue
            }

            # Inject metadata
            $ruleDef['_Category'] = $effectiveCategory
            $ruleDef['_FilePath'] = $ruleFile.FullName
            $ruleDef['_FileName'] = $ruleFile.Name

            # Default Collectors to empty array if not specified
            if (-not $ruleDef.ContainsKey('Collectors')) {
                $ruleDef['Collectors'] = @()
            }

            $rules.Add($ruleDef)
        }
    }
    Write-Host "  [+] Discovered $($rules.Count) active rules" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 5. Prerequisites
    # ------------------------------------------------------------------
    Write-Host "`n  Checking prerequisites..." -ForegroundColor DarkGray

    # ActiveDirectory module
    # Try importing directly — on older OS (e.g. Server 2012) the module may only
    # be visible through the WinPSCompatibility layer and not via Get-Module -ListAvailable.
    try {
        Import-Module ActiveDirectory -SkipEditionCheck -ErrorAction Stop
    }
    catch {
        throw "ActiveDirectory module not found. Install RSAT (AD DS and LDS tools)."
    }
    Write-Host "  [+] ActiveDirectory module loaded" -ForegroundColor Green

    # Detect Windows PowerShell compatibility mode (module served via implicit
    # remoting). In this mode AD objects are deserialized and the AD: PSProvider
    # is unavailable locally, which degrades several collectors. Surface it loudly
    # so the assessment is not silently run from a non-ideal host.
    $winPSCompat = Test-MATIWinPSCompat
    $Config['_WinPSCompat'] = $winPSCompat
    if ($winPSCompat) {
        Write-Host "" 
        Write-Host "  [!] NOTE: ActiveDirectory module loaded via Windows PowerShell compatibility (WinPSCompatSession)." -ForegroundColor Yellow
        Write-Host "      This installation returns deserialized AD objects. MATI hardens critical paths, but some" -ForegroundColor Yellow
        Write-Host "      checks may be degraded or incomplete depending on the environment." -ForegroundColor Yellow
        Write-Host "      Run MATI on a domain controller or domain-joined admin host with RSAT for the best results." -ForegroundColor Yellow
        Write-Host ""
    }

    # Basic AD read access + build forest/domain cache
    try {
        $resolvedTargetForest = if ([string]::IsNullOrWhiteSpace($TargetForest)) {
            $null
        } else {
            $TargetForest.Trim()
        }

        if ($resolvedTargetForest) {
            $forestObj = Get-ADForest -Identity $resolvedTargetForest -ErrorAction Stop
        } else {
            $forestObj = Get-ADForest -ErrorAction Stop
        }

        $directoryServer = if ([string]::IsNullOrWhiteSpace($forestObj.RootDomain)) {
            $forestObj.Name
        } else {
            $forestObj.RootDomain
        }
        $rootDseObj = Get-ADRootDSE -Server $directoryServer -ErrorAction Stop
        $domainCacheMap = @{}
        foreach ($domDns in $forestObj.Domains) {
            try {
                $domainCacheMap[$domDns] = Get-ADDomain -Identity $domDns -Server $domDns -ErrorAction Stop
            } catch {
                Write-Warning "  [!] Could not query domain '${domDns}': $($_.Exception.Message)"
            }
        }
        # Inject caches into Config so all collectors can reuse them
        $forestFileLabel = ($forestObj.Name -replace '[<>:"/\\|?*]', '_').Trim()
        if ([string]::IsNullOrWhiteSpace($forestFileLabel)) {
            $forestFileLabel = 'UnknownForest'
        }

        $Config['_ForestCache'] = $forestObj
        $Config['_DomainCache'] = $domainCacheMap
        $Config['_RootDSECache'] = $rootDseObj
        $Config['_DirectoryServer'] = $directoryServer
        $Config['_TargetForest'] = $forestObj.Name
        $Config['_ReportFilePrefix'] = "MATI_${forestFileLabel}_"
    }
    catch {
        $targetLabel = if ([string]::IsNullOrWhiteSpace($TargetForest)) { 'current forest' } else { $TargetForest }
        throw "Cannot read Active Directory for '$targetLabel'. Ensure the target forest is reachable and the current user has read access. Error: $($_.Exception.Message)"
    }
    Write-Host "  [+] AD read access confirmed for forest '$($forestObj.Name)' ($($domainCacheMap.Count) domain(s) cached)" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 6. Prepare output paths
    # ------------------------------------------------------------------
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outputBase = Join-Path $RootPath 'Outputs'
    $outputRoot = Join-Path $outputBase "ThreatDetection\Output_$timestamp"
    $csvDir     = Join-Path $outputRoot 'CSV'
    $htmlDir    = Join-Path $outputRoot 'HTML'
    $jsonDir    = Join-Path $outputRoot 'JSON'

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $csvDir     -Force | Out-Null
    New-Item -ItemType Directory -Path $htmlDir    -Force | Out-Null
    New-Item -ItemType Directory -Path $jsonDir    -Force | Out-Null

    Write-Host "  [+] Output directory: $outputRoot`n" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 7. Build and return engine context
    # ------------------------------------------------------------------
    $engineContext = @{
        RootPath         = $RootPath
        Config           = $Config
        Collectors       = $collectors
        Rules            = $rules
        Timestamp        = $timestamp
        OutputRoot       = $outputRoot
        CsvDir           = $csvDir
        HtmlDir          = $htmlDir
        JsonDir          = $jsonDir
        DataCache        = @{}          # Populated by Invoke-MATICollectors
        FailedCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)  # Collectors that threw
        PartialCollectors = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        CollectionIssues = [System.Collections.Generic.List[object]]::new()
        RuleResults      = [System.Collections.Generic.List[object]]::new()
        AssessmentScope  = @{}
        NotAssessedRules = [System.Collections.Generic.List[object]]::new()   # Rules skipped due to failed collectors
        WinPSCompat      = $winPSCompat
        Findings         = [System.Collections.Generic.List[object]]::new()
        DCConnectivity   = [System.Collections.Generic.List[object]]::new()   # Populated by Invoke-MATICollectors
    }

    return $engineContext
}
