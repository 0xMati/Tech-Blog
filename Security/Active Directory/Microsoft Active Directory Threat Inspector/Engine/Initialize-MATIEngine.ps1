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

        [string]$ConfigPath
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

            if (-not $ruleDef -or -not $ruleDef.Id) {
                Write-Warning "  [!] Invalid rule file (no Id): $($ruleFile.Name)"
                continue
            }

            # Schema validation — warn on missing required keys
            $requiredKeys = @('Id', 'Title', 'Severity', 'Condition', 'Collectors')
            $missingKeys  = $requiredKeys | Where-Object { -not $ruleDef.ContainsKey($_) -or $null -eq $ruleDef[$_] }
            if ($missingKeys) {
                Write-Warning "  [!] Rule $($ruleDef.Id) ($($ruleFile.Name)) missing keys: $($missingKeys -join ', ')"
            }

            if ($ruleDef.Id -in $disabledRules) {
                Write-Host "  [~] Rule $($ruleDef.Id) is disabled - skipping" -ForegroundColor Yellow
                continue
            }

            # Inject metadata
            $ruleDef['_Category'] = $category
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

    # Basic AD read access + build forest/domain cache
    try {
        $forestObj = Get-ADForest -ErrorAction Stop
        $domainCacheMap = @{}
        foreach ($domDns in $forestObj.Domains) {
            try {
                $domainCacheMap[$domDns] = Get-ADDomain -Server $domDns -ErrorAction Stop
            } catch {
                Write-Warning "  [!] Could not query domain '$domDns': $($_.Exception.Message)"
            }
        }
        # Inject caches into Config so all collectors can reuse them
        $Config['_ForestCache'] = $forestObj
        $Config['_DomainCache'] = $domainCacheMap
    }
    catch {
        throw "Cannot read Active Directory. Ensure the current user has read access. Error: $($_.Exception.Message)"
    }
    Write-Host "  [+] AD read access confirmed (forest + $($domainCacheMap.Count) domain(s) cached)" -ForegroundColor Green

    # ------------------------------------------------------------------
    # 6. Prepare output paths
    # ------------------------------------------------------------------
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outputBase = Join-Path $RootPath 'Outputs'
    $modeFolder = if ($global:MATIMode -eq 'TieringModel') { 'TieringModel' } else { 'ThreatDetection' }
    $outputRoot = Join-Path $outputBase "$modeFolder\Output_$timestamp"
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
        Findings         = [System.Collections.Generic.List[object]]::new()
        DCConnectivity   = [System.Collections.Generic.List[object]]::new()   # Populated by Invoke-MATICollectors
    }

    return $engineContext
}
