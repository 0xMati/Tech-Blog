#Requires -Version 5.1
<#
.SYNOPSIS
    Assesses AD FS Relying Party Trusts for migration readiness to Microsoft Entra ID.

.DESCRIPTION
    Modern reimplementation of the archived Microsoft module ADFSAADMigrationUtils.psm1
    (https://github.com/AzureAD/Deployment-Plans/tree/master/ADFS%20to%20AzureAD%20App%20Migration).

    Reproduces locally the validation tests performed by the Entra portal's
    "AD FS application migration" dashboard (Usage & insights), so that customers
    without Entra Connect Health for AD FS or P1/P2 licenses can run the same analysis.

    Produces a self-contained HTML report (drill-down + persistent migration checklist
    via localStorage) plus JSON and CSV outputs.

.PARAMETER OutputPath
    Destination folder for the report. Created if missing.
    Default: an 'output' subfolder next to the script ($PSScriptRoot\output).

.PARAMETER RelyingPartyName
    Optional list of RP names to filter on. Wildcards supported.

.PARAMETER IncludeUsageStats
    Parse the AD FS Security event log to compute per-RP sign-in counts and last seen.

.PARAMETER UsageDays
    Lookback window for usage stats. Default: 30.

.PARAMETER FarmServers
    Optional list of ADFS farm member FQDNs. When -IncludeUsageStats is set, the
    Security event log of each server is queried and results are aggregated.
    If omitted, the script auto-discovers farm members via Get-AdfsFarmInformation
    and falls back to the local server only if discovery fails.
    Requires WinRM / PSRemoting (or SMB+RPC for Get-WinEvent) to remote servers.

.PARAMETER IncludeMicrosoftRPs
    Include Microsoft-internal RPs (Office 365, WHfB, etc.) which are normally excluded.

.PARAMETER NoHtml / -NoCsv / -NoJson
    Skip the corresponding output format.

.EXAMPLE
    .\Invoke-AdfsRpMigrationAssessment.ps1 -OutputPath C:\Temp\AdfsReport -IncludeUsageStats

.NOTES
    Run as Administrator on a server where the ADFS role is installed.
    Tests reflect Entra ID capabilities as of 2026-06.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'output'),

    [string[]]$RelyingPartyName,

    [switch]$IncludeUsageStats,

    [int]$UsageDays = 30,

    [string[]]$FarmServers,

    [switch]$IncludeMicrosoftRPs,

    [switch]$NoHtml,

    [switch]$NoCsv,

    [switch]$NoJson
)

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

#region Helpers ---------------------------------------------------------------

function Write-Section { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Info    { param([string]$Text) Write-Host "[ ] $Text" -ForegroundColor Gray }
function Write-Ok      { param([string]$Text) Write-Host "[+] $Text" -ForegroundColor Green }
function Write-Warn2   { param([string]$Text) Write-Host "[!] $Text" -ForegroundColor Yellow }

function Test-IsMicrosoftRP {
    param($Rp)
    $patterns = @(
        '^urn:federation:MicrosoftOnline$',
        'microsoftonline\.com',
        'microsoft:winhello',
        'urn:federation:microsoft',
        'Office 365 Identity Platform',
        'Device Registration Service',
        'CRL Distribution Point'
    )
    foreach ($p in $patterns) {
        foreach ($id in @($Rp.Identifier)) {
            if ($id -match $p) { return $true }
        }
        if ($Rp.Name -match $p) { return $true }
    }
    return $false
}

function ConvertTo-SafeFileName {
    param([string]$Name)
    $invalid = [IO.Path]::GetInvalidFileNameChars() + ':', '*', '?', '"', '<', '>', '|', '/', '\'
    $clean = $Name
    foreach ($c in $invalid) { $clean = $clean.Replace([string]$c, '_') }
    if ($clean.Length -gt 120) { $clean = $clean.Substring(0, 120) }
    return $clean
}

#endregion

#region Claim rule parser ----------------------------------------------------

# AD FS claim rule language reference:
# https://learn.microsoft.com/windows-server/identity/ad-fs/technical-reference/the-role-of-the-claim-rule-language

$script:KnownPatterns = @(
    @{ Name = 'PassThrough'              ; Regex = '(?ims)^\s*c:\s*\[\s*Type\s*==\s*"[^"]+"\s*\]\s*=>\s*issue\s*\(\s*claim\s*=\s*c\s*\)' }
    @{ Name = 'PassThroughWithFilter'    ; Regex = '(?ims)c:\[Type\s*==\s*"[^"]+"\s*,\s*Value\s*[=~]+\s*"[^"]+"\]\s*=>\s*issue\(\s*claim\s*=\s*c\s*\)' }
    @{ Name = 'IssueAttributeFromAD'     ; Regex = '(?ims)c:\[Type\s*==\s*"[^"]+windowsaccountname[^"]*"[^\]]*\]\s*=>\s*issue\(\s*store\s*=\s*"Active Directory"\s*,\s*types\s*=\s*\(' }
    @{ Name = 'TransformWindowsAccount'  ; Regex = '(?ims)c:\[Type\s*==\s*"[^"]+windowsaccountname[^"]*"[^\]]*\]\s*=>\s*issue\(' }
    @{ Name = 'StaticIssue'              ; Regex = '(?ims)=>\s*issue\(\s*Type\s*=\s*"[^"]+"\s*,\s*Value\s*=\s*"[^"]+"\s*\)' }
    @{ Name = 'PermitAll'                ; Regex = '(?ims)=>\s*issue\(\s*Type\s*=\s*"http://schemas\.microsoft\.com/authorization/claims/permit"\s*,\s*Value\s*=\s*"true"\s*\)' }
)

$script:NonMigratableSignals = @(
    @{ Code = 'UNSUPPORTED_CONDITION_PARAMETER'    ; Regex = '(?i)Value\s*=~\s*"' ;                    Message = 'Regex condition (Value =~)' }
    @{ Code = 'UNSUPPORTED_ISSUANCE_TRANSFORMATION'; Regex = '(?i)RegExReplace\s*\(' ;                 Message = 'RegExReplace transform' }
    @{ Code = 'UNSUPPORTED_CONDITION_CLASS'        ; Regex = '(?ims)\][\s\r\n]*&&[\s\r\n]*c\d*:?\[' ;  Message = 'Multi-condition rule (&& with multiple selectors)' }
    @{ Code = 'EXTERNAL_ATTRIBUTE_STORE'           ; Regex = '(?i)store\s*=\s*"(?!Active Directory|_OpaqueIdStore|_ProxyCredentialStore)([^"]+)"' ; Message = 'External attribute store (SQL/LDAP/custom)' }
    @{ Code = 'UNSUPPORTED_ISSUANCE_CLASS'         ; Regex = '(?i)=>\s*add\s*\(' ;                     Message = 'ADD issuance (vs ISSUE)' }
    @{ Code = 'UNSUPPORTED_RULE_TYPE'              ; Regex = '(?i)NOT\s+EXISTS\s*\[' ;                 Message = 'NOT EXISTS rule' }
    @{ Code = 'UNSUPPORTED_ISSUER'                 ; Regex = '(?i)Issuer\s*==\s*"(?!AD AUTHORITY)' ;   Message = 'Issuer != AD AUTHORITY' }
)

# Claim type URIs that Entra ID restricts (subset of the well-known list)
$script:RestrictedClaimTypes = @(
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/role',
    'http://schemas.microsoft.com/ws/2008/06/identity/claims/userprincipalname',
    'http://schemas.microsoft.com/identity/claims/objectidentifier',
    'http://schemas.microsoft.com/identity/claims/tenantid'
)

# AD attributes synced to Entra ID by Entra Connect by default
$script:DefaultSyncedAdAttributes = @(
    'cn','displayName','givenName','sn','mail','mailNickname','userPrincipalName',
    'sAMAccountName','objectGUID','objectSID','employeeID','department','title',
    'telephoneNumber','mobile','physicalDeliveryOfficeName','streetAddress',
    'postalCode','st','l','c','co','company','manager','description',
    'msDS-cloudExtensionAttribute1','msDS-cloudExtensionAttribute2',
    'extensionAttribute1','extensionAttribute2','extensionAttribute3',
    'extensionAttribute4','extensionAttribute5','extensionAttribute6',
    'extensionAttribute7','extensionAttribute8','extensionAttribute9',
    'extensionAttribute10','extensionAttribute11','extensionAttribute12',
    'extensionAttribute13','extensionAttribute14','extensionAttribute15',
    'proxyAddresses','accountExpires','msExchHideFromAddressLists'
)

function ConvertFrom-AdfsRuleSet {
    <#
    Splits a multi-rule AD FS string into individual rules and runs heuristics on each.
    Returns array of PSCustomObject.
    #>
    param([string]$RuleSet, [string]$Kind)

    if ([string]::IsNullOrWhiteSpace($RuleSet)) { return @() }

    # Split rules on @RuleTemplate / @RuleName boundaries while preserving content
    $parts = [System.Text.RegularExpressions.Regex]::Split(
        $RuleSet,
        '(?ims)(?=@RuleTemplate|@RuleName)'
    ) | Where-Object { $_.Trim() }

    if (-not $parts) { $parts = @($RuleSet) }

    $results = foreach ($rule in $parts) {
        $ruleText = $rule.Trim()
        $name = if ($ruleText -match '@RuleName\s*=\s*"([^"]+)"') { $Matches[1] } else { $null }

        # Extract claim types referenced
        $claimTypes = [regex]::Matches($ruleText, '(?i)Type\s*==?\s*"([^"]+)"') |
            ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique

        # Extract issued types
        $issuedTypes = [regex]::Matches($ruleText, '(?i)issue\s*\([^)]*Type\s*=\s*"([^"]+)"') |
            ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique

        # Extract attribute stores
        $stores = [regex]::Matches($ruleText, '(?i)store\s*=\s*"([^"]+)"') |
            ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique

        # Extract AD attributes referenced (from types=(...) and ldap-style mappings)
        $adAttributes = @()
        $typesMatch = [regex]::Matches($ruleText, '(?ims)types\s*=\s*\(([^)]+)\)\s*,\s*query\s*=\s*";([^;"]+);')
        foreach ($m in $typesMatch) {
            $queryPart = $m.Groups[2].Value
            $adAttributes += $queryPart -split ',' | ForEach-Object { $_.Trim() }
        }
        $adAttributes = $adAttributes | Where-Object { $_ } | Select-Object -Unique

        # Pattern matching (known migratable)
        $matchedPattern = $null
        foreach ($p in $script:KnownPatterns) {
            if ($ruleText -match $p.Regex) { $matchedPattern = $p.Name; break }
        }

        # Non-migratable signals
        $issues = foreach ($sig in $script:NonMigratableSignals) {
            if ($ruleText -match $sig.Regex) {
                [PSCustomObject]@{ Code = $sig.Code; Message = $sig.Message }
            }
        }

        $isMigratable = ($null -ne $matchedPattern) -and ($issues.Count -eq 0)

        [PSCustomObject]@{
            Kind             = $Kind
            Name             = $name
            Text             = $ruleText
            ClaimTypes       = @($claimTypes)
            IssuedTypes      = @($issuedTypes)
            AttributeStores  = @($stores)
            AdAttributes     = @($adAttributes)
            KnownPattern     = $matchedPattern
            IsMigratable     = $isMigratable
            Issues           = @($issues)
        }
    }

    return @($results)
}

#endregion

#region Test functions -------------------------------------------------------

function New-TestResult {
    param(
        [string]$Name,
        [ValidateSet('Pass','Warning','Fail','Skipped')] [string]$Status,
        [string]$Message,
        $Detail = $null
    )
    [PSCustomObject]@{
        Name    = $Name
        Status  = $Status
        Message = $Message
        Detail  = $Detail
    }
}

function Test-RpAdditionalAuthenticationRules {
    param($Rp)
    if ([string]::IsNullOrWhiteSpace($Rp.AdditionalAuthenticationRules)) {
        return New-TestResult 'AdditionalAuthenticationRules' 'Pass' 'No on-prem MFA rules.'
    }
    New-TestResult 'AdditionalAuthenticationRules' 'Warning' `
        'On-prem MFA rules detected. Convert to Conditional Access + Entra MFA.' `
        $Rp.AdditionalAuthenticationRules
}

function Test-RpAdditionalWSFedEndpoint {
    param($Rp)
    if ($Rp.AdditionalWSFedEndpoint) {
        return New-TestResult 'AdditionalWSFedEndpoint' 'Fail' `
            'Multiple WS-Fed assertion endpoints — Entra ID supports only one.'
    }
    New-TestResult 'AdditionalWSFedEndpoint' 'Pass' 'Single WS-Fed endpoint.'
}

function Test-RpAllowedAuthenticationClassReferences {
    param($Rp)
    if ($Rp.AllowedAuthenticationClassReferences -and $Rp.AllowedAuthenticationClassReferences.Count -gt 0) {
        return New-TestResult 'AllowedAuthenticationClassReferences' 'Fail' `
            'Restricted auth class references — use Conditional Access in Entra.' `
            ($Rp.AllowedAuthenticationClassReferences -join ', ')
    }
    New-TestResult 'AllowedAuthenticationClassReferences' 'Pass' 'No auth class restriction.'
}

function Test-RpAlwaysRequireAuthentication {
    param($Rp)
    if ($Rp.AlwaysRequireAuthentication) {
        return New-TestResult 'AlwaysRequireAuthentication' 'Fail' `
            'Force re-auth — use Conditional Access Sign-in frequency in Entra.'
    }
    New-TestResult 'AlwaysRequireAuthentication' 'Pass' 'SSO cookies honored.'
}

function Test-RpAutoUpdateEnabled {
    param($Rp)
    if ($Rp.AutoUpdateEnabled) {
        return New-TestResult 'AutoUpdateEnabled' 'Warning' `
            'Federation metadata auto-update enabled. Entra ID does not auto-update from RP metadata.'
    }
    New-TestResult 'AutoUpdateEnabled' 'Pass' 'Auto-update disabled.'
}

function Test-RpClaimsProviderName {
    param($Rp)
    $providers = @($Rp.ClaimsProviderName)
    $nonAd = $providers | Where-Object { $_ -and $_ -ne 'Active Directory' }
    if ($nonAd) {
        return New-TestResult 'ClaimsProviderName' 'Fail' `
            'Non-AD Claims Provider detected. Use Entra B2B for external IdPs.' `
            ($providers -join ', ')
    }
    New-TestResult 'ClaimsProviderName' 'Pass' 'AD only.'
}

function Test-RpDelegationAuthorizationRules {
    param($Rp)
    if (-not [string]::IsNullOrWhiteSpace($Rp.DelegationAuthorizationRules)) {
        return New-TestResult 'DelegationAuthorizationRules' 'Fail' `
            'Custom delegation rules — WS-Trust concept; use OAuth on-behalf-of in Entra.' `
            $Rp.DelegationAuthorizationRules
    }
    New-TestResult 'DelegationAuthorizationRules' 'Pass' 'No delegation rules.'
}

function Test-RpEncryptClaims {
    # 2026 update: Entra ID supports SAML token encryption (was Fail in 2022 module)
    param($Rp)
    if ($Rp.EncryptClaims) {
        return New-TestResult 'EncryptClaims' 'Pass' `
            'Encrypted claims — supported by Entra (configure SAML token encryption).'
    }
    New-TestResult 'EncryptClaims' 'Pass' 'No claim encryption.'
}

function Test-RpEncryptedNameIdRequired {
    param($Rp)
    if ($Rp.EncryptedNameIdRequired) {
        return New-TestResult 'EncryptedNameIdRequired' 'Fail' `
            'Encrypted nameID required — Entra supports full-token encryption only, not per-claim encryption.'
    }
    New-TestResult 'EncryptedNameIdRequired' 'Pass' 'No encrypted nameID requirement.'
}

function Test-RpImpersonationAuthorizationRules {
    param($Rp)
    if (-not [string]::IsNullOrWhiteSpace($Rp.ImpersonationAuthorizationRules)) {
        return New-TestResult 'ImpersonationAuthorizationRules' 'Warning' `
            'Custom impersonation rules — WS-Trust concept; review for OAuth equivalents.' `
            $Rp.ImpersonationAuthorizationRules
    }
    New-TestResult 'ImpersonationAuthorizationRules' 'Pass' 'No impersonation rules.'
}

function Test-RpIssuanceAuthorizationRules {
    param($Rp)
    if ([string]::IsNullOrWhiteSpace($Rp.IssuanceAuthorizationRules)) {
        return New-TestResult 'IssuanceAuthorizationRules' 'Pass' 'No issuance authorization rules.'
    }
    # Detect "permit all" only (which is fine)
    $rules = $Rp.IssuanceAuthorizationRules
    $isPermitAll = $rules -match '(?ims)=>\s*issue\(\s*Type\s*=\s*"http://schemas\.microsoft\.com/authorization/claims/permit"\s*,\s*Value\s*=\s*"true"\s*\)'
    $hasOtherRules = $rules -match '(?ims)c\d*:\['
    if ($isPermitAll -and -not $hasOtherRules) {
        return New-TestResult 'IssuanceAuthorizationRules' 'Pass' 'Permit-all only.'
    }
    New-TestResult 'IssuanceAuthorizationRules' 'Warning' `
        'Custom authorization rules — recreate via Conditional Access or user/group assignment in Entra.' `
        $rules
}

function Test-RpIssuanceTransformRules {
    param($Rp, $ParsedRules)
    if (-not $ParsedRules -or $ParsedRules.Count -eq 0) {
        return New-TestResult 'IssuanceTransformRules' 'Pass' 'No transform rules.'
    }
    $nonMigratable = @($ParsedRules | Where-Object { -not $_.IsMigratable })
    if ($nonMigratable.Count -eq 0) {
        return New-TestResult 'IssuanceTransformRules' 'Pass' "$($ParsedRules.Count) rule(s), all match known migratable patterns."
    }
    New-TestResult 'IssuanceTransformRules' 'Warning' `
        "$($nonMigratable.Count) of $($ParsedRules.Count) rule(s) need manual review." `
        ($nonMigratable | Select-Object Name, Issues, KnownPattern, Text)
}

function Test-RpMonitoringEnabled {
    param($Rp)
    if ($Rp.MonitoringEnabled) {
        return New-TestResult 'MonitoringEnabled' 'Warning' `
            'Federation metadata monitoring enabled — not supported by Entra (informational).'
    }
    New-TestResult 'MonitoringEnabled' 'Pass' 'Monitoring disabled.'
}

function Test-RpNotBeforeSkew {
    param($Rp)
    if ($Rp.NotBeforeSkew -and $Rp.NotBeforeSkew -ne 0) {
        return New-TestResult 'NotBeforeSkew' 'Warning' `
            "NotBeforeSkew=$($Rp.NotBeforeSkew) min — Entra handles skew automatically (informational)."
    }
    New-TestResult 'NotBeforeSkew' 'Pass' 'No custom skew.'
}

function Test-RpRequestMFAFromClaimsProviders {
    param($Rp)
    if ($Rp.RequestMFAFromClaimsProviders) {
        return New-TestResult 'RequestMFAFromClaimsProviders' 'Warning' `
            'MFA requested from external IdP. Use Entra B2B + Conditional Access on guests.'
    }
    New-TestResult 'RequestMFAFromClaimsProviders' 'Pass' 'No MFA-from-CP requirement.'
}

function Test-RpSignedSamlRequestsRequired {
    # 2026 update: Entra accepts signed SAML requests (does not verify), so Warning not Fail
    param($Rp)
    if ($Rp.SignedSamlRequestsRequired) {
        return New-TestResult 'SignedSamlRequestsRequired' 'Warning' `
            'Signed SAML requests required. Entra accepts signed requests but does not verify the signature; reply URL allowlist provides equivalent protection.'
    }
    New-TestResult 'SignedSamlRequestsRequired' 'Pass' 'Signature not required.'
}

function Test-RpTokenLifetime {
    param($Rp)
    if ($Rp.TokenLifetime -and $Rp.TokenLifetime -ne 0) {
        return New-TestResult 'TokenLifetime' 'Warning' `
            "Custom token lifetime ($($Rp.TokenLifetime) min) — map via Conditional Access Sign-in frequency."
    }
    New-TestResult 'TokenLifetime' 'Pass' 'Default token lifetime.'
}

function Get-RpVerdict {
    param($Tests)
    $statuses = $Tests.Status
    if ($statuses -contains 'Fail')    { return 'AdditionalSteps' }
    if ($statuses -contains 'Warning') { return 'NeedsReview' }
    return 'Ready'
}

#endregion

#region Usage stats ---------------------------------------------------------

function Get-AdfsFarmServer {
    # Returns FQDN list of all ADFS servers in the farm. Falls back to local host on failure.
    try {
        $info = Get-AdfsFarmInformation -ErrorAction Stop
        $list = @()
        foreach ($n in $info.FarmNodes) {
            if ($n.FQDN)            { $list += $n.FQDN }
            elseif ($n.NodeName)    { $list += $n.NodeName }
        }
        if ($list.Count -gt 0) { return ,($list | Sort-Object -Unique) }
    } catch {
        Write-Warn2 "Get-AdfsFarmInformation failed: $_"
    }
    # Fallback: also try ADFS service account / config for SQL-based farm members via WMI? Keep it simple.
    return ,@($env:COMPUTERNAME)
}

function Get-AdfsRpUsage {
    param(
        [int]$Days = 30,
        [string[]]$Servers = @($env:COMPUTERNAME)
    )

    $startTime = (Get-Date).AddDays(-$Days)
    $perServer = @{}   # server -> @{ Reached=$bool; EventCount=int; Error=string }
    $usage = @{}

    foreach ($srv in $Servers) {
        $isLocal = ($srv -eq $env:COMPUTERNAME) -or ($srv -ieq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") -or ($srv -ieq 'localhost')
        Write-Info ("Reading event 1200 from {0} (since {1:yyyy-MM-dd HH:mm}) ..." -f $srv, $startTime)

        $filter = @{
            LogName   = 'Security'
            Id        = 1200
            StartTime = $startTime
        }

        try {
            if ($isLocal) {
                $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
            } else {
                $events = Get-WinEvent -ComputerName $srv -FilterHashtable $filter -ErrorAction Stop
            }
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'No events were found') {
                $perServer[$srv] = @{ Reached = $true; EventCount = 0; Error = $null }
                Write-Warn2 ("  {0}: no event 1200 found (audit policy not enabled?)." -f $srv)
                continue
            }
            $perServer[$srv] = @{ Reached = $false; EventCount = 0; Error = $msg }
            Write-Warn2 ("  {0}: unreachable - {1}" -f $srv, $msg)
            continue
        }

        $count = 0
        foreach ($e in $events) {
            try {
                $xml = [xml]$e.ToXml()
                $data = $xml.Event.EventData.Data
                $rp   = ($data | Where-Object Name -eq 'RelyingParty').'#text'
                $user = ($data | Where-Object Name -in 'UserName','TargetUser','SubjectName').'#text'
                if (-not $rp) { continue }

                if (-not $usage.ContainsKey($rp)) {
                    $usage[$rp] = [PSCustomObject]@{
                        SignInCount  = 0
                        UniqueUsers  = New-Object System.Collections.Generic.HashSet[string]
                        LastSeen     = $e.TimeCreated
                        FirstSeen    = $e.TimeCreated
                        Servers      = New-Object System.Collections.Generic.HashSet[string]
                    }
                }
                $usage[$rp].SignInCount++
                $count++
                if ($user) { [void]$usage[$rp].UniqueUsers.Add($user) }
                [void]$usage[$rp].Servers.Add($srv)
                if ($e.TimeCreated -gt $usage[$rp].LastSeen)  { $usage[$rp].LastSeen  = $e.TimeCreated }
                if ($e.TimeCreated -lt $usage[$rp].FirstSeen) { $usage[$rp].FirstSeen = $e.TimeCreated }
            } catch { continue }
        }
        $perServer[$srv] = @{ Reached = $true; EventCount = $count; Error = $null }
        Write-Ok ("  {0}: {1} event(s)." -f $srv, $count)
    }

    # Materialize unique users count
    $final = @{}
    foreach ($k in $usage.Keys) {
        $final[$k] = [PSCustomObject]@{
            SignInCount      = $usage[$k].SignInCount
            UniqueUserCount  = $usage[$k].UniqueUsers.Count
            LastSeen         = $usage[$k].LastSeen
            FirstSeen        = $usage[$k].FirstSeen
            ServersHit       = @($usage[$k].Servers) -join ', '
        }
    }
    Write-Ok ("Aggregated usage for {0} RP(s) across {1} server(s) over {2} day(s)." -f $final.Count, $Servers.Count, $Days)

    # Stash per-server diagnostics for the report
    $script:UsageServerStatus = $perServer
    return $final
}

#endregion

#region HTML report ----------------------------------------------------------

function New-HtmlReport {
    param(
        $Results,
        [string]$Generated,
        [string]$Server,
        [int]$DaysWindow,
        [bool]$UsageIncluded
    )

    # Compact JSON to embed
    $json = $Results | ConvertTo-Json -Depth 10 -Compress

    $totalCount         = $Results.Count
    $readyCount         = @($Results | Where-Object Verdict -eq 'Ready').Count
    $needsReviewCount   = @($Results | Where-Object Verdict -eq 'NeedsReview').Count
    $additionalCount    = @($Results | Where-Object Verdict -eq 'AdditionalSteps').Count

    $usageBlock = if ($UsageIncluded) { "Sign-in window: last $DaysWindow days." } else { 'Usage stats not collected.' }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD FS RP Migration Assessment</title>
<style>
:root {
  --bg:#0f172a; --panel:#1e293b; --panel2:#334155; --text:#f1f5f9; --muted:#94a3b8;
  --pass:#16a34a; --warn:#f59e0b; --fail:#dc2626; --info:#3b82f6;
  --ready-bg:#dcfce7; --ready-fg:#166534;
  --rev-bg:#fef3c7;   --rev-fg:#92400e;
  --add-bg:#fee2e2;   --add-fg:#991b1b;
}
* { box-sizing:border-box; }
body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; background:#f8fafc; color:#0f172a; }
header { background:linear-gradient(135deg,#1e3a8a,#3b82f6); color:#fff; padding:24px 32px; }
header h1 { margin:0 0 4px; font-size:24px; font-weight:600; }
header .meta { font-size:12px; opacity:0.85; }
.container { padding:24px 32px; max-width:1600px; margin:0 auto; }
.kpis { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:24px; }
.kpi { background:#fff; padding:20px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.1); border-left:4px solid var(--info); }
.kpi.ready    { border-left-color:var(--pass); }
.kpi.review   { border-left-color:var(--warn); }
.kpi.steps    { border-left-color:var(--fail); }
.kpi .num { font-size:32px; font-weight:600; }
.kpi .lbl { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }
.kpi .pct { font-size:12px; color:var(--muted); margin-top:2px; }
.controls { display:flex; gap:12px; align-items:center; margin-bottom:16px; flex-wrap:wrap; background:#fff; padding:12px; border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.05); }
.controls input, .controls select { padding:6px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; }
.controls input[type=search] { flex:1; min-width:240px; }
.count-info { font-size:12px; color:var(--muted); margin-left:auto; }
table { width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.1); }
th { background:#1e293b; color:#fff; font-weight:500; text-align:left; padding:10px 12px; font-size:12px; text-transform:uppercase; cursor:pointer; user-select:none; }
th:hover { background:#334155; }
th .sort-ind { font-size:10px; opacity:0.6; margin-left:4px; }
td { padding:10px 12px; border-top:1px solid #e2e8f0; vertical-align:top; }
tr.row { cursor:pointer; transition:background 0.15s; }
tr.row:hover { background:#f1f5f9; }
tr.row.disabled td { opacity:0.5; }
.badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:600; text-transform:uppercase; }
.badge.ready  { background:var(--ready-bg); color:var(--ready-fg); }
.badge.review { background:var(--rev-bg);   color:var(--rev-fg); }
.badge.steps  { background:var(--add-bg);   color:var(--add-fg); }
.badge.pass    { background:var(--ready-bg); color:var(--ready-fg); }
.badge.warning { background:var(--rev-bg);   color:var(--rev-fg); }
.badge.fail    { background:var(--add-bg);   color:var(--add-fg); }
.badge.skipped { background:#e5e7eb; color:#374151; }
.modal-bg { position:fixed; inset:0; background:rgba(15,23,42,0.6); display:none; align-items:flex-start; justify-content:center; padding:48px 24px; overflow-y:auto; z-index:50; }
.modal-bg.open { display:flex; }
.modal { background:#fff; max-width:1100px; width:100%; border-radius:10px; box-shadow:0 20px 50px rgba(0,0,0,0.3); }
.modal header { background:#0f172a; padding:16px 24px; border-radius:10px 10px 0 0; display:flex; justify-content:space-between; align-items:flex-start; gap:16px; }
.modal header h2 { margin:0 0 4px; font-size:18px; }
.modal header .id { font-size:12px; opacity:0.75; word-break:break-all; }
.modal .close { background:transparent; color:#fff; border:none; font-size:24px; cursor:pointer; line-height:1; }
.modal .body { padding:24px; }
.section-title { font-size:13px; font-weight:600; text-transform:uppercase; letter-spacing:0.5px; color:var(--muted); margin:20px 0 8px; }
.section-title:first-child { margin-top:0; }
.config-grid { display:grid; grid-template-columns:200px 1fr; gap:6px 16px; font-size:13px; }
.config-grid dt { color:var(--muted); }
.config-grid dd { margin:0; word-break:break-word; }
.tests { display:grid; gap:8px; }
.test { display:grid; grid-template-columns:120px 1fr auto; gap:12px; align-items:start; padding:10px; border:1px solid #e2e8f0; border-radius:6px; }
.test.pass    { border-left:3px solid var(--pass); }
.test.warning { border-left:3px solid var(--warn); }
.test.fail    { border-left:3px solid var(--fail); }
.test .name { font-weight:600; font-size:13px; }
.test .msg  { font-size:13px; color:#334155; }
.test details { margin-top:6px; }
.test summary { cursor:pointer; font-size:12px; color:var(--info); }
.test pre { background:#f1f5f9; padding:8px; border-radius:4px; font-size:11px; overflow-x:auto; max-height:200px; }
.rule { background:#f8fafc; padding:10px; margin:8px 0; border-radius:6px; border:1px solid #e2e8f0; }
.rule.bad  { border-left:3px solid var(--warn); }
.rule.good { border-left:3px solid var(--pass); }
.rule .header2 { display:flex; justify-content:space-between; gap:8px; align-items:center; margin-bottom:6px; }
.rule .name { font-size:12px; font-weight:600; }
.rule pre { background:#fff; padding:8px; border-radius:4px; font-size:11px; overflow-x:auto; margin:6px 0 0; }
.rule .issues { font-size:12px; color:var(--add-fg); margin-top:6px; }
.checklist { display:grid; gap:8px; }
.checklist label { display:flex; gap:8px; align-items:flex-start; padding:8px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; font-size:13px; cursor:pointer; }
.checklist label:hover { background:#f1f5f9; }
.checklist input { margin-top:3px; }
.checklist label.done { opacity:0.6; }
.checklist label.done .text { text-decoration:line-through; }
footer { padding:24px; text-align:center; font-size:11px; color:var(--muted); }
@media print {
  .controls, .modal .close, header { display:none; }
  .modal-bg { position:static; background:#fff; padding:0; }
  .modal { box-shadow:none; max-width:100%; }
}
</style>
</head>
<body>
<header>
  <h1>AD FS → Microsoft Entra ID — Migration Assessment</h1>
  <div class="meta">
    Generated <strong>$Generated</strong> from <strong>$Server</strong> &middot; $usageBlock
  </div>
</header>
<div class="container">
  <section class="kpis">
    <div class="kpi"><div class="num">$totalCount</div><div class="lbl">Total RPs analysed</div></div>
    <div class="kpi ready"><div class="num">$readyCount</div><div class="lbl">Ready to migrate</div></div>
    <div class="kpi review"><div class="num">$needsReviewCount</div><div class="lbl">Needs review</div></div>
    <div class="kpi steps"><div class="num">$additionalCount</div><div class="lbl">Additional steps required</div></div>
  </section>
  <div class="controls">
    <input type="search" id="search" placeholder="Filter by name or identifier...">
    <select id="verdictFilter">
      <option value="">All verdicts</option>
      <option value="Ready">Ready</option>
      <option value="NeedsReview">Needs review</option>
      <option value="AdditionalSteps">Additional steps</option>
    </select>
    <label style="font-size:12px;display:flex;gap:6px;align-items:center;">
      <input type="checkbox" id="hideDisabled"> Hide disabled RPs
    </label>
    <span class="count-info" id="counter"></span>
  </div>
  <table id="rpTable">
    <thead>
      <tr>
        <th data-sort="Name">Name<span class="sort-ind"></span></th>
        <th data-sort="Identifier">Identifier<span class="sort-ind"></span></th>
        <th data-sort="Verdict">Verdict<span class="sort-ind"></span></th>
        <th data-sort="FailCount">Fails<span class="sort-ind"></span></th>
        <th data-sort="WarningCount">Warnings<span class="sort-ind"></span></th>
        <th data-sort="SignInCount">Sign-ins ($DaysWindow d)<span class="sort-ind"></span></th>
        <th data-sort="LastSeen">Last seen<span class="sort-ind"></span></th>
        <th data-sort="Enabled">Enabled<span class="sort-ind"></span></th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
</div>

<div class="modal-bg" id="modalBg" onclick="if(event.target===this)closeModal()">
  <div class="modal" id="modal">
    <header>
      <div>
        <h2 id="mName"></h2>
        <div class="id" id="mId"></div>
      </div>
      <button class="close" onclick="closeModal()">&times;</button>
    </header>
    <div class="body" id="mBody"></div>
  </div>
</div>

<footer>
  Generated by Invoke-AdfsRpMigrationAssessment.ps1 &middot; checklist state stored in browser localStorage per RP identifier.
</footer>

<script id="data" type="application/json">$json</script>
"@ + @'
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
let SORT_KEY = 'Verdict', SORT_ASC = true;

const VERDICT_LABELS = { Ready:'Ready', NeedsReview:'Needs review', AdditionalSteps:'Additional steps' };
const VERDICT_CLASSES = { Ready:'ready', NeedsReview:'review', AdditionalSteps:'steps' };
const STATUS_RANK = { Pass:0, Warning:1, Fail:2, Skipped:-1 };
const VERDICT_RANK = { Ready:0, NeedsReview:1, AdditionalSteps:2 };

function getMetrics(rp){
  const tests = rp.Tests || [];
  return {
    FailCount: tests.filter(t=>t.Status==='Fail').length,
    WarningCount: tests.filter(t=>t.Status==='Warning').length,
    SignInCount: rp.Usage?rp.Usage.SignInCount:0,
    LastSeen: rp.Usage?rp.Usage.LastSeen:null
  };
}

function render() {
  const search = document.getElementById('search').value.toLowerCase();
  const vf = document.getElementById('verdictFilter').value;
  const hideDisabled = document.getElementById('hideDisabled').checked;

  let rows = DATA.map((rp,i)=>({...rp,_idx:i,...getMetrics(rp)}));
  rows = rows.filter(r=>{
    if (search && !((r.Name||'').toLowerCase().includes(search) || (r.Identifier||'').toLowerCase().includes(search))) return false;
    if (vf && r.Verdict!==vf) return false;
    if (hideDisabled && r.Enabled===false) return false;
    return true;
  });

  rows.sort((a,b)=>{
    let av=a[SORT_KEY], bv=b[SORT_KEY];
    if (SORT_KEY==='Verdict') { av=VERDICT_RANK[av]; bv=VERDICT_RANK[bv]; }
    if (SORT_KEY==='LastSeen') { av=av?new Date(av).getTime():0; bv=bv?new Date(bv).getTime():0; }
    if (SORT_KEY==='Enabled') { av=av?1:0; bv=bv?1:0; }
    if (av==null) av=''; if (bv==null) bv='';
    if (typeof av==='string') return SORT_ASC?av.localeCompare(bv):bv.localeCompare(av);
    return SORT_ASC?(av-bv):(bv-av);
  });

  const tbody = document.getElementById('tbody');
  tbody.innerHTML = rows.map(r=>{
    const verdictCls = VERDICT_CLASSES[r.Verdict]||'';
    const verdictLbl = VERDICT_LABELS[r.Verdict]||r.Verdict;
    const last = r.LastSeen ? new Date(r.LastSeen).toLocaleString() : '—';
    return `<tr class="row ${r.Enabled===false?'disabled':''}" data-idx="${r._idx}">
      <td><strong>${esc(r.Name||'')}</strong></td>
      <td style="font-size:11px;color:#64748b">${esc(r.Identifier||'')}</td>
      <td><span class="badge ${verdictCls}">${verdictLbl}</span></td>
      <td>${r.FailCount?'<span style=color:#dc2626;font-weight:600>'+r.FailCount+'</span>':'0'}</td>
      <td>${r.WarningCount?'<span style=color:#f59e0b;font-weight:600>'+r.WarningCount+'</span>':'0'}</td>
      <td>${r.SignInCount||'—'}</td>
      <td style="font-size:11px">${last}</td>
      <td>${r.Enabled===false?'No':'Yes'}</td>
    </tr>`;
  }).join('');

  document.getElementById('counter').textContent = `${rows.length} of ${DATA.length} RPs`;

  document.querySelectorAll('#tbody .row').forEach(tr=>{
    tr.onclick = ()=>openModal(parseInt(tr.dataset.idx));
  });
  document.querySelectorAll('th[data-sort]').forEach(th=>{
    const ind = th.querySelector('.sort-ind');
    if (th.dataset.sort===SORT_KEY) ind.textContent = SORT_ASC?'▲':'▼'; else ind.textContent='';
  });
}

function esc(s) { return String(s||'').replace(/[&<>"]/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;' }[c])); }

function openModal(idx) {
  const rp = DATA[idx];
  document.getElementById('mName').textContent = rp.Name || '';
  document.getElementById('mId').textContent = rp.Identifier || '';

  const tests = (rp.Tests||[]).slice().sort((a,b)=>STATUS_RANK[b.Status]-STATUS_RANK[a.Status]);
  const rules = rp.IssuanceRules || [];

  let html = '';
  html += '<div class="section-title">Configuration</div>';
  html += '<dl class="config-grid">';
  html += `<dt>Enabled</dt><dd>${rp.Enabled===false?'No':'Yes'}</dd>`;
  html += `<dt>Protocol</dt><dd>${esc(rp.ProtocolProfile||'')}</dd>`;
  html += `<dt>Token lifetime (min)</dt><dd>${rp.TokenLifetime||'default'}</dd>`;
  html += `<dt>WS-Fed endpoint</dt><dd>${esc(rp.WSFedEndpoint||'—')}</dd>`;
  html += `<dt>Encrypt claims</dt><dd>${rp.EncryptClaims?'Yes':'No'}</dd>`;
  html += `<dt>Signing algorithm</dt><dd>${esc(rp.SignatureAlgorithm||'—')}</dd>`;
  if (rp.Usage) {
    html += `<dt>Sign-ins (window)</dt><dd>${rp.Usage.SignInCount}</dd>`;
    html += `<dt>Unique users</dt><dd>${rp.Usage.UniqueUserCount}</dd>`;
    html += `<dt>Last seen</dt><dd>${rp.Usage.LastSeen?new Date(rp.Usage.LastSeen).toLocaleString():'—'}</dd>`;
  }
  html += '</dl>';

  html += '<div class="section-title">Validation tests</div>';
  html += '<div class="tests">';
  for (const t of tests) {
    const cls = (t.Status||'').toLowerCase();
    html += `<div class="test ${cls}">
      <div><span class="badge ${cls}">${t.Status}</span></div>
      <div>
        <div class="name">${esc(t.Name)}</div>
        <div class="msg">${esc(t.Message)}</div>
        ${t.Detail ? `<details><summary>Show detail</summary><pre>${esc(typeof t.Detail==='string'?t.Detail:JSON.stringify(t.Detail,null,2))}</pre></details>`:''}
      </div>
    </div>`;
  }
  html += '</div>';

  if (rules.length) {
    html += '<div class="section-title">Parsed claim rules ('+rules.length+')</div>';
    for (const r of rules) {
      const cls = r.IsMigratable?'good':'bad';
      const issues = r.Issues && r.Issues.length ? r.Issues.map(i=>`<div class="issues">⚠ ${esc(i.Code)} — ${esc(i.Message)}</div>`).join(''):'';
      html += `<div class="rule ${cls}">
        <div class="header2">
          <span class="name">${esc(r.Name||'(unnamed)')}</span>
          <span class="badge ${r.IsMigratable?'pass':'warning'}">${r.IsMigratable?'Migratable ('+esc(r.KnownPattern||'')+')':'Needs review'}</span>
        </div>
        ${issues}
        ${r.AdAttributes && r.AdAttributes.length ? '<div style="font-size:12px;margin-top:4px"><strong>AD attributes:</strong> '+r.AdAttributes.map(esc).join(', ')+'</div>' : ''}
        ${r.AttributeStores && r.AttributeStores.length ? '<div style="font-size:12px"><strong>Stores:</strong> '+r.AttributeStores.map(esc).join(', ')+'</div>' : ''}
        <details><summary>Show rule</summary><pre>${esc(r.Text)}</pre></details>
      </div>`;
    }
  }

  // Build migration playbook checklist
  const items = buildPlaybook(rp);
  if (items.length) {
    html += '<div class="section-title">Migration checklist</div>';
    html += '<div class="checklist" id="checklist">';
    items.forEach((it,i)=>{
      html += `<label data-i="${i}"><input type="checkbox"><span class="text">${esc(it)}</span></label>`;
    });
    html += '</div>';
  }

  document.getElementById('mBody').innerHTML = html;

  // Restore checklist state
  const key = 'adfsmig:'+(rp.Identifier||rp.Name);
  const state = JSON.parse(localStorage.getItem(key)||'{}');
  document.querySelectorAll('#checklist label').forEach(lbl=>{
    const i = lbl.dataset.i;
    if (state[i]) { lbl.classList.add('done'); lbl.querySelector('input').checked = true; }
    lbl.querySelector('input').onchange = (e)=>{
      lbl.classList.toggle('done', e.target.checked);
      const cur = JSON.parse(localStorage.getItem(key)||'{}');
      cur[i] = e.target.checked;
      localStorage.setItem(key, JSON.stringify(cur));
    };
  });

  document.getElementById('modalBg').classList.add('open');
}

function closeModal() { document.getElementById('modalBg').classList.remove('open'); }
document.addEventListener('keydown', e=>{ if (e.key==='Escape') closeModal(); });

function buildPlaybook(rp) {
  const items = [];
  items.push('Create Enterprise Application in Entra ID (gallery template if available)');
  items.push('Set Identifier (Entity ID) = ' + (rp.Identifier||''));
  if (rp.WSFedEndpoint) items.push('Set Reply URL = ' + rp.WSFedEndpoint);
  items.push('Configure SAML signing certificate in Entra (tenant cert by default)');
  const tests = rp.Tests||[];
  for (const t of tests) {
    if (t.Status === 'Pass') continue;
    if (t.Name === 'AdditionalAuthenticationRules')   items.push('Recreate on-prem MFA rules as Conditional Access policies with Entra MFA');
    if (t.Name === 'AllowedAuthenticationClassReferences') items.push('Translate auth class restriction to Conditional Access (auth strength)');
    if (t.Name === 'AlwaysRequireAuthentication')     items.push('Configure Conditional Access Sign-in frequency to force re-auth');
    if (t.Name === 'AdditionalWSFedEndpoint')         items.push('⚠ Reduce to a single WS-Fed reply URL (or split into multiple Entra apps)');
    if (t.Name === 'ClaimsProviderName')              items.push('Configure Entra B2B for users coming from external claims providers');
    if (t.Name === 'DelegationAuthorizationRules')    items.push('Replace WS-Trust delegation by OAuth On-Behalf-Of flow');
    if (t.Name === 'EncryptedNameIdRequired')         items.push('⚠ Per-claim encryption not supported — switch to full-token encryption or remove the requirement');
    if (t.Name === 'ImpersonationAuthorizationRules') items.push('Replace WS-Trust impersonation by OAuth On-Behalf-Of flow');
    if (t.Name === 'IssuanceAuthorizationRules')      items.push('Move authorization to user/group assignment + Conditional Access');
    if (t.Name === 'IssuanceTransformRules')          items.push('Recreate claim transformations (Extract / Trim / ToLower / IfEmpty) in Entra SAML claims pane');
    if (t.Name === 'MonitoringEnabled')               items.push('Disable RP federation metadata monitoring (informational)');
    if (t.Name === 'NotBeforeSkew')                   items.push('Remove custom NotBeforeSkew (Entra handles skew automatically)');
    if (t.Name === 'RequestMFAFromClaimsProviders')   items.push('Apply Conditional Access for guests via Entra B2B');
    if (t.Name === 'SignedSamlRequestsRequired')      items.push('Document that Entra accepts but does not verify request signatures (reply URL allowlist applies)');
    if (t.Name === 'TokenLifetime')                   items.push('Map custom token lifetime to Conditional Access Sign-in frequency');
    if (t.Name === 'EncryptClaims')                   items.push('Configure SAML token encryption in Entra app');
  }
  items.push('Test SSO with a pilot user against a non-prod RP / app instance');
  items.push('Switch the production app to the Entra endpoint');
  items.push('Disable / remove the AD FS RP after grace period');
  items.push('Remove from this checklist when migration is complete');
  return items;
}

document.getElementById('search').oninput = render;
document.getElementById('verdictFilter').onchange = render;
document.getElementById('hideDisabled').onchange = render;
document.querySelectorAll('th[data-sort]').forEach(th=>{
  th.onclick = ()=>{
    if (SORT_KEY===th.dataset.sort) SORT_ASC=!SORT_ASC; else { SORT_KEY=th.dataset.sort; SORT_ASC=true; }
    render();
  };
});

render();
</script>
'@ + @"
</script>
</body>
</html>
"@

    return $html
}

#endregion

#region Main -----------------------------------------------------------------

Write-Section 'AD FS RP Migration Assessment'

# Load ADFS module
try {
    Import-Module ADFS -ErrorAction Stop
} catch {
    throw "ADFS module not available. Run this script on a server with the AD FS role installed."
}

# Resolve output paths
$null = New-Item -ItemType Directory -Path $OutputPath -Force
$OutputPath = (Resolve-Path $OutputPath).Path
$rawDir = Join-Path $OutputPath 'Raw'
$null = New-Item -ItemType Directory -Path $rawDir -Force

Write-Info "Output: $OutputPath"

# Get RP trusts
Write-Info 'Reading relying party trusts...'
$rps = Get-AdfsRelyingPartyTrust

if ($RelyingPartyName) {
    $rps = $rps | Where-Object {
        $name = $_.Name
        ($RelyingPartyName | ForEach-Object { $name -like $_ }) -contains $true
    }
}

if (-not $IncludeMicrosoftRPs) {
    $beforeCount = $rps.Count
    $rps = $rps | Where-Object { -not (Test-IsMicrosoftRP $_) }
    $excluded = $beforeCount - $rps.Count
    if ($excluded -gt 0) { Write-Info "Excluded $excluded Microsoft-internal RP(s) (use -IncludeMicrosoftRPs to keep them)." }
}

Write-Ok "Analysing $($rps.Count) RP(s)..."

# Resolve farm members
$farm = if ($FarmServers) { $FarmServers } else { Get-AdfsFarmServer }
if ($farm.Count -gt 1) {
    Write-Ok ("Farm members detected ({0}): {1}" -f $farm.Count, ($farm -join ', '))
} else {
    Write-Info ("Single-server scope: {0}" -f $farm[0])
}

# Usage stats (optional)
$usage = @{}
$script:UsageServerStatus = @{}
if ($IncludeUsageStats) { $usage = Get-AdfsRpUsage -Days $UsageDays -Servers $farm }

# Run tests
$results = foreach ($rp in $rps) {
    Write-Info "  $($rp.Name)"

    # Save raw export
    $safeName = ConvertTo-SafeFileName $rp.Name
    $rp | Export-Clixml -Path (Join-Path $rawDir "$safeName.xml") -Depth 6

    # Parse rules
    $issuanceRules    = ConvertFrom-AdfsRuleSet -RuleSet $rp.IssuanceTransformRules     -Kind 'Issuance'
    # We parse the others too but the main test logic mostly uses issuance
    $authzRules       = ConvertFrom-AdfsRuleSet -RuleSet $rp.IssuanceAuthorizationRules -Kind 'IssuanceAuthorization'

    $tests = @(
        Test-RpAdditionalAuthenticationRules         $rp
        Test-RpAdditionalWSFedEndpoint               $rp
        Test-RpAllowedAuthenticationClassReferences  $rp
        Test-RpAlwaysRequireAuthentication           $rp
        Test-RpAutoUpdateEnabled                     $rp
        Test-RpClaimsProviderName                    $rp
        Test-RpDelegationAuthorizationRules          $rp
        Test-RpEncryptClaims                         $rp
        Test-RpEncryptedNameIdRequired               $rp
        Test-RpImpersonationAuthorizationRules       $rp
        Test-RpIssuanceAuthorizationRules            $rp
        Test-RpIssuanceTransformRules                $rp $issuanceRules
        Test-RpMonitoringEnabled                     $rp
        Test-RpNotBeforeSkew                         $rp
        Test-RpRequestMFAFromClaimsProviders         $rp
        Test-RpSignedSamlRequestsRequired            $rp
        Test-RpTokenLifetime                         $rp
    )

    $verdict = Get-RpVerdict $tests

    $rpUsage = if ($usage.ContainsKey($rp.Identifier[0])) { $usage[$rp.Identifier[0]] }
               else {
                   $found = $null
                   foreach ($id in $rp.Identifier) { if ($usage.ContainsKey($id)) { $found = $usage[$id]; break } }
                   $found
               }

    [PSCustomObject]@{
        Name               = $rp.Name
        Identifier         = ($rp.Identifier -join '; ')
        Enabled            = $rp.Enabled
        ProtocolProfile    = "$($rp.ProtocolProfile)"
        WSFedEndpoint      = "$($rp.WSFedEndpoint)"
        TokenLifetime      = $rp.TokenLifetime
        EncryptClaims      = $rp.EncryptClaims
        SignatureAlgorithm = $rp.SignatureAlgorithm
        Verdict            = $verdict
        Tests              = $tests
        IssuanceRules      = $issuanceRules
        AuthorizationRules = $authzRules
        Usage              = $rpUsage
    }
}

# Verdict summary
$verdictCounts = $results | Group-Object Verdict | ForEach-Object { "$($_.Name): $($_.Count)" }
Write-Ok ("Done. " + ($verdictCounts -join ' | '))

# Outputs
$generated = (Get-Date).ToString('u')
if ($IncludeUsageStats -and $farm.Count -gt 1) {
    $reached  = @($script:UsageServerStatus.GetEnumerator() | Where-Object { $_.Value.Reached }).Count
    $server   = "{0} (farm: {1}/{2} server(s) reached for usage)" -f $env:COMPUTERNAME, $reached, $farm.Count
} elseif ($farm.Count -gt 1) {
    $server   = "{0} (config) — farm: {1}" -f $env:COMPUTERNAME, ($farm -join ', ')
} else {
    $server   = $env:COMPUTERNAME
}

if (-not $NoJson) {
    $jsonPath = Join-Path $OutputPath 'AdfsAssessment-Data.json'
    $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -Encoding UTF8
    Write-Ok "JSON: $jsonPath"
}

if (-not $NoCsv) {
    $csvPath = Join-Path $OutputPath 'AdfsAssessment-Data.csv'
    $results | Select-Object Name, Identifier, Enabled, Verdict, ProtocolProfile, TokenLifetime, EncryptClaims,
        @{N='FailCount';   E={ @($_.Tests | Where-Object Status -eq 'Fail').Count }},
        @{N='WarningCount';E={ @($_.Tests | Where-Object Status -eq 'Warning').Count }},
        @{N='SignInCount'; E={ if ($_.Usage) { $_.Usage.SignInCount } else { 0 } }},
        @{N='LastSeen';    E={ if ($_.Usage) { $_.Usage.LastSeen   } else { $null } }} |
        Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
    Write-Ok "CSV : $csvPath"
}

if (-not $NoHtml) {
    $htmlPath = Join-Path $OutputPath 'AdfsAssessment-Report.html'
    $html = New-HtmlReport -Results $results -Generated $generated -Server $server `
                           -DaysWindow $UsageDays -UsageIncluded ([bool]$IncludeUsageStats)
    $html | Out-File $htmlPath -Encoding UTF8
    Write-Ok "HTML: $htmlPath"
}

$elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
Write-Ok ("Elapsed: {0:N1}s" -f $elapsed)
Write-Section 'Done'

#endregion
