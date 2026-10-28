# Engine\MATI.Common.ps1
# MATIv2 - Shared helper functions used across collectors, engine and scoring.
#
# These helpers exist primarily to make MATI resilient when the ActiveDirectory
# module is loaded through the Windows PowerShell compatibility layer
# (WinPSCompatSession) - e.g. when MATI runs from a workstation under PowerShell 7
# instead of directly on a domain controller. In that mode AD objects come back
# DESERIALIZED, which breaks naive casts like [int]$dom.DomainMode and
# property access like $dom.DomainSID.Value.

function Get-MATIFunctionalLevelNumeric {
    <#
    .SYNOPSIS
        Converts a domain/forest functional level (enum, int or deserialized
        string such as 'Windows2016Domain') to a comparable numeric level.
    .OUTPUTS
        [int] numeric level, or -1 when it cannot be determined.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        $Mode
    )

    if ($null -eq $Mode) { return -1 }

    # Native enum / integer
    if ($Mode -is [int]) { return [int]$Mode }

    $s = [string]$Mode
    if ([string]::IsNullOrWhiteSpace($s)) { return -1 }

    # Plain integer string
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }

    # Enum / deserialized string forms (e.g. 'Windows2016Domain', 'Windows2016Forest').
    # Order matters: more specific variants (Interim / R2) are tested first because
    # 'return' exits the function on the first match.
    switch -Regex ($s) {
        'Windows2000'        { return 0 }
        'Windows2003Interim' { return 1 }
        'Windows2003'        { return 2 }
        'Windows2008R2'      { return 4 }
        'Windows2008'        { return 3 }
        'Windows2012R2'      { return 6 }
        'Windows2012'        { return 5 }
        'Windows2016'        { return 7 }
        'Windows2019'        { return 7 }   # no distinct DFL beyond 2016
        'Windows2022'        { return 7 }
        'Windows2025'        { return 10 }
        default              { return -1 }
    }
}

    function Set-MATIAssessmentScope {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][hashtable]$EngineContext,
            [string[]]$CategoriesOnly,
            [string[]]$RulesOnly
        )

        $rules = @($EngineContext.Rules)
        foreach ($category in $CategoriesOnly) {
            if ($category -notin @($rules | ForEach-Object { $_['_Category'] })) {
                throw "Unknown or disabled category: $category"
            }
        }
        foreach ($id in $RulesOnly) {
            if ($id -notin @($rules | ForEach-Object { $_.Id })) {
                throw "Unknown or disabled rule: $id"
            }
        }
        if ($CategoriesOnly) { $rules = @($rules | Where-Object { $_['_Category'] -in $CategoriesOnly }) }
        if ($RulesOnly) { $rules = @($rules | Where-Object { $_.Id -in $RulesOnly }) }
        if ($rules.Count -eq 0) { throw 'No active rules match the assessment scope. No assessment or score can be produced.' }

        $EngineContext.Rules = $rules
        $EngineContext.AssessmentScope = @{
            CategoriesOnly = @($CategoriesOnly | Where-Object { $_ })
            RulesOnly = @($RulesOnly | Where-Object { $_ })
            DisabledRules = @($EngineContext.Config.Exclusions.DisabledRules)
            DisabledCategories = @($EngineContext.Config.Exclusions.DisabledCategories)
        }
    }

    function Get-MATIPrivilegedGroupKey {
        [CmdletBinding()]
        param([Parameter(Mandatory)]$Group)

        switch -Regex ([string]$Group.SID) {
            '^S-1-5-21-.+-512$' { return 'Domain Admins' }
            '^S-1-5-21-.+-519$' { return 'Enterprise Admins' }
            '^S-1-5-21-.+-518$' { return 'Schema Admins' }
            '^S-1-5-32-544$' { return 'Administrators' }
            '^S-1-5-32-548$' { return 'Account Operators' }
            '^S-1-5-32-549$' { return 'Server Operators' }
            '^S-1-5-32-550$' { return 'Print Operators' }
            '^S-1-5-32-551$' { return 'Backup Operators' }
        }
        if ($Group.GroupKey) { return $Group.GroupKey }
        return $Group.GroupName
    }

        function Get-MATIEffectiveKdcSettings {
            [CmdletBinding()]
            param([Parameter(Mandatory)]$Settings)

            # Microsoft Server release history: May 2022, Feb/Sep 2025, Jan/Apr/Jul 2026.
            # https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info
            $baselines = @{
                '14393' = @(5125, 7785, 8422, 8783, 9060, 9339)
                '17763' = @(2928, 6893, 7792, 8276, 8644, 9020)
                '20348' = @(707, 3207, 4171, 4648, 5020, 5386)
                '26100' = @(0, 3194, 6584, 32230, 32690, 33158)
            }
            $result = @{
                EffectiveStrongCertificateBinding = 'Unknown'
                EffectiveKdcEncTypes = $null
                KdcSettingsEvidence = "Windows build $($Settings.OSBuildNumber).$($Settings.OSRevision)"
                KdcSettingsError = $null
            }
            $build = [string]$Settings.OSBuildNumber
            if ($null -eq $Settings.OSRevision -or -not $baselines.ContainsKey($build)) {
                $result.KdcSettingsError = 'Missing or unsupported Windows build/revision; effective KDC defaults require manual verification.'
                return $result
            }
            $revision = [int]$Settings.OSRevision
            $limits = $baselines[$build]
            $certDefault = $revision -ge $limits[1] -or
                ($build -eq '20348' -and $revision -eq 3148) -or ($build -eq '26100' -and $revision -eq 3107)
            $certEnforced = $revision -ge $limits[2] -or
                ($build -eq '20348' -and $revision -eq 4106) -or ($build -eq '26100' -and $revision -eq 6508)
            $binding = $Settings.StrongCertificateBindingEnforcement
            if ($certEnforced) {
                $result.EffectiveStrongCertificateBinding = 'FullEnforcement'
            }
            elseif ($revision -ge $limits[0]) {
                if ($binding -eq 2 -or ($null -eq $binding -and $certDefault)) {
                    $result.EffectiveStrongCertificateBinding = 'FullEnforcement'
                }
                elseif ($binding -eq 1 -or ($null -eq $binding -and -not $certDefault)) {
                    $result.EffectiveStrongCertificateBinding = 'Compatibility'
                }
                else { $result.KdcSettingsError = 'Deprecated or invalid strong-binding registry setting; effective behavior requires verification.' }
            }
            else { $result.KdcSettingsError = 'Windows build predates the strong-binding implementation baseline.' }

            if ($null -ne $Settings.KdcDefaultEncTypes) {
                $result.EffectiveKdcEncTypes = [int]$Settings.KdcDefaultEncTypes
            }
            elseif ($revision -ge $limits[5]) {
                $result.EffectiveKdcEncTypes = 0x18
            }
            elseif ($revision -ge $limits[3]) {
                $phase = $Settings.Rc4DisablementPhase
                if ($null -ne $phase -and $phase -notin @(0, 1, 2)) {
                    $result.KdcSettingsError = 'Invalid RC4DefaultDisablementPhase; effective behavior requires verification.'
                }
                elseif ($phase -eq 2 -or ($null -eq $phase -and $revision -ge $limits[4])) {
                    $result.EffectiveKdcEncTypes = 0x18
                }
                else { $result.EffectiveKdcEncTypes = 0x27 }
            }
            else { $result.EffectiveKdcEncTypes = 0x27 }
            return $result
        }

function Get-MATIADWSForeignPrincipalAdvice {
    return @{
        Message = 'ADWS foreign-principal resolution: Possible causes of an enumeration failure involving foreign principals include deleted accounts in their source forest, or identities that are inaccessible because of forest availability, DNS, connectivity or trust authentication conditions. Microsoft KB 3171600 also documents this error with one-way trusts. Enterprise Admin rights in the local forest do not guarantee access to external identities. These possibilities do not prove that a SID is orphaned or that a trust is broken.'
        Reference = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/get-adgroupmember-error-remote-forest-members'
    }
}

function Write-MATICollectionDiagnostic {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [Parameter(Mandatory)][string]$Message,
        [string[]]$Datasets = @(),
        [bool]$AffectsCoverage = $true,
        [System.Management.Automation.ErrorRecord]$HandledError
    )

    if ($Config -and $Config.ContainsKey('_CollectionDiagnostics')) {
        $Config['_CollectionDiagnostics'].Add([pscustomobject]@{
            Message = $Message
            Datasets = @($Datasets)
            AffectsCoverage = $AffectsCoverage
        })
        if ($HandledError) { $Config['_HandledCollectionErrors'].Add($HandledError) }
    }
    Write-Warning $Message
}

function Invoke-MATIForeignPrincipalLookup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^S-\d+(?:-\d+)+$')][string]$SID,
        [string[]]$Targets,
        [ValidateRange(1, 60)][int]$TimeoutSeconds = 15
    )

    $job = Start-Job -ArgumentList $SID, $Targets -ScriptBlock {
        param($SID, $Targets)
        $ErrorActionPreference = 'Stop'
        $name = $null
        $attempts = [System.Collections.Generic.List[string]]::new()
        try {
            $name = [Security.Principal.SecurityIdentifier]::new($SID).Translate([Security.Principal.NTAccount]).Value
            [pscustomobject]@{ Stage = 'Name'; ResolvedName = $name }
        } catch { $attempts.Add("SID translation: $($_.Exception.Message)") }

        $candidates = @($Targets | Where-Object { $_ } | Select-Object -Unique)
        try {
            if ($candidates.Count) { Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop }
            foreach ($target in $candidates) {
                $context = $null; $principal = $null
                try {
                    $context = [DirectoryServices.AccountManagement.PrincipalContext]::new(
                        [DirectoryServices.AccountManagement.ContextType]::Domain, $target)
                    $principal = [DirectoryServices.AccountManagement.Principal]::FindByIdentity(
                        $context, [DirectoryServices.AccountManagement.IdentityType]::Sid, $SID)
                    if ($null -eq $principal) { $attempts.Add("$target : SID not found in this search context."); continue }
                    if ($principal.Sid.Value -ne $SID) { throw 'Directory result SID did not match the requested SID.' }
                    $entry = $principal.GetUnderlyingObject()
                    try {
                        $dn = $principal.DistinguishedName
                        $class = $entry.SchemaClassName
                    } finally { $entry.Dispose() }
                    if ($dn -notmatch '(?i)(DC=[^,]+(?:,DC=[^,]+)*)$') { throw 'Resolved principal has no domain distinguished name.' }
                    $domain = (($Matches[1] -replace '(?i)DC=', '') -replace ',', '.').ToLowerInvariant()
                    [pscustomobject]@{
                        Stage = 'Result'; Status = 'Resolved'; SID = $SID
                        ResolvedName = if ($name) { $name } else { "$domain\$($principal.SamAccountName)" }
                        Name = $principal.Name; SamAccountName = $principal.SamAccountName
                        DistinguishedName = $dn; ObjectClass = $class; Domain = $domain
                        Error = $null; Attempts = $attempts.ToArray()
                    }
                    return
                } catch { $attempts.Add("$target : $($_.Exception.Message)") }
                finally {
                    if ($principal) { $principal.Dispose() }
                    if ($context) { $context.Dispose() }
                }
            }
        } catch { $attempts.Add($_.Exception.Message) }
        [pscustomobject]@{
            Stage = 'Result'; Status = if ($name) { 'NameOnly' } else { 'Unresolved' }; SID = $SID; ResolvedName = $name
            DistinguishedName = $null; ObjectClass = $null; Domain = $null
            Error = if ($candidates.Count) { 'The principal could not be verified in the assessed forest. This is not proof of deletion.' }
                elseif (-not $name) { 'Windows could not translate the SID. Remote directory attributes are outside the assessment scope; deletion is not established.' }
                else { $null }
            Attempts = $attempts.ToArray()
        }
    }
    try {
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $completed) { Stop-Job -Job $job }
        $output = @(Receive-Job -Job $job -ErrorAction Stop)
        $result = $output | Where-Object Stage -eq 'Result' | Select-Object -Last 1
        if ($completed -and $job.State -eq 'Completed' -and $result) { return $result }
        if ($completed) { throw "Foreign principal lookup job failed or returned no result for '$SID'." }
        return [pscustomobject]@{
            Status = 'TimedOut'; SID = $SID
            ResolvedName = ($output | Where-Object Stage -eq 'Name' | Select-Object -Last 1).ResolvedName
            DistinguishedName = $null; ObjectClass = $null; Domain = $null
            Error = "External lookup exceeded $TimeoutSeconds seconds; no deletion or orphan status can be inferred."
            Attempts = @()
        }
    } finally { Remove-Job -Job $job -Force }
}

function Resolve-MATIForeignPrincipal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^S-\d+(?:-\d+)+$')][string]$SID,
        [Parameter(Mandatory)][hashtable]$Config,
        [string[]]$Datasets
    )

    if (-not $Config.ContainsKey('_ForeignPrincipalCache')) { $Config['_ForeignPrincipalCache'] = @{} }
    if ($Config['_ForeignPrincipalCache'].ContainsKey($SID)) { return $Config['_ForeignPrincipalCache'][$SID] }
    if (-not $Config.ContainsKey('_ForeignPrincipalTargets')) {
        $targets = @{}
        if (-not @($Config['_ForestCache'].Domains | Where-Object { $_ }).Count) {
            throw 'Cannot establish the assessed forest SID scope: no target forest domains are available.'
        }
        if (-not $Config.ContainsKey('_DomainCache')) { $Config['_DomainCache'] = @{} }
        foreach ($domain in $Config['_ForestCache'].Domains) {
            $domainInfo = $Config['_DomainCache'][$domain]
            if (-not $domainInfo) { $domainInfo = Get-ADDomain -Server $domain -ErrorAction Stop }
            $domainSID = Get-MATIDomainSidString $domainInfo.DomainSID
            if (-not $domainSID) { throw "Cannot establish the assessed forest SID scope for '$domain'." }
            $targets[$domainSID] = $domain
        }
        $Config['_ForeignPrincipalTargets'] = $targets
    }
    $targetDomains = @(
        foreach ($domainSID in $Config['_ForeignPrincipalTargets'].Keys) {
            if ($SID.StartsWith("$domainSID-", [StringComparison]::OrdinalIgnoreCase)) {
                $Config['_ForeignPrincipalTargets'][$domainSID]
            }
        }
    )
    $result = Invoke-MATIForeignPrincipalLookup -SID $SID -Targets $targetDomains
    $result | Add-Member -NotePropertyName OutsideAssessmentScope -NotePropertyValue ($targetDomains.Count -eq 0) -Force
    $Config['_ForeignPrincipalCache'][$SID] = $result
    return $result
}

function Resolve-MATIGroupMembership {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$Server,
        [switch]$Recursive,
        [hashtable]$Config,
        [string[]]$CollectionDatasets = @(),
        [string[]]$ResolutionDatasets = @()
    )

    if ($Config) {
        if (-not @($Config['_ForestCache'].Domains | Where-Object { $_ }).Count) {
            throw 'Cannot collect scoped group membership without target forest domains.'
        }
        $rootGroup = Get-ADGroup -Identity $Identity -Server $Server -Properties Members -ErrorAction Stop
        if ($null -eq $rootGroup) { throw "No directory group returned for '$Identity' on '$Server'." }
    } else {
        try {
            $members = @(Get-ADGroupMember -Identity $Identity -Server $Server -Recursive:$Recursive -ErrorAction Stop)
            return @{
                Members = $members
                Complete = $true
                ReadMethod = 'ADWS'
                UnresolvedMembers = @()
                MemberLinksComplete = $true
                LocalObjectsComplete = $true
            }
        }
        catch {
            $enumerationError = $_
            $rootGroup = Get-ADGroup -Identity $Identity -Server $Server -Properties Members -ErrorAction Stop
            if ($null -eq $rootGroup) { throw "No directory group returned for '$Identity' on '$Server'." }
            Write-MATICollectionDiagnostic -Config $Config -AffectsCoverage $false -HandledError $enumerationError `
                -Message "Group membership enumeration failed for '$Identity' on '$Server': $($enumerationError.Exception.Message). Member links recovered; identity resolution and recursive coverage are tracked separately."
        }
    }

    if (-not $rootGroup.PSObject.Properties['Members']) {
        throw "The Members property was not returned for '$Identity' on '$Server'."
    }

    $rootDomain = $null
    if ($rootGroup.DistinguishedName -match '(?i)(DC=[^,]+(?:,DC=[^,]+)*)$') {
        $rootDomain = (($Matches[1] -replace '(?i)DC=', '') -replace ',', '.').ToLowerInvariant()
    }

    $members = [System.Collections.Generic.List[object]]::new()
    $unresolved = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $seenGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.Queue[object]]::new()
    $null = $seenGroups.Add($rootGroup.DistinguishedName)
    $pending.Enqueue($rootGroup)
    $memberLinksComplete = $true
    $localObjectsComplete = $true
    $foreignEncountered = $false

    while ($pending.Count -gt 0) {
        $group = $pending.Dequeue()
        foreach ($memberDN in $group.Members) {
            if ($Recursive -and $seenGroups.Contains($memberDN)) { continue }
            if (-not $seenMembers.Add($memberDN)) { continue }

            $memberServer = $Server
            if ($memberDN -match '(?i)(DC=[^,]+(?:,DC=[^,]+)*)$') {
                $memberDomain = (($Matches[1] -replace '(?i)DC=', '') -replace ',', '.').ToLowerInvariant()
                if ($Config -and $memberDomain -notin $Config['_ForestCache'].Domains) {
                    $members.Add([pscustomobject]@{
                        Name = $memberDN; DistinguishedName = $memberDN; SID = $null
                        objectClass = 'foreignSecurityPrincipal'; MembershipResolved = $true
                        OutsideAssessmentScope = $true; ExternalResolutionStatus = 'OutsideTargetForest'
                        ResolutionError = 'Remote object attributes and membership expansion are outside the assessed forest.'
                    })
                    continue
                }
                if ($memberDomain -ne $rootDomain) { $memberServer = $memberDomain }
            }

            $member = $null
            try {
                $member = Get-ADObject -Identity $memberDN -Server $memberServer `
                    -Properties objectSid, sAMAccountName -ErrorAction Stop
                if ($null -eq $member) { throw "No directory object returned for '$memberDN'." }
            }
            catch {
                $null = $unresolved.Add($memberDN)
                $localObjectsComplete = $false
                Write-MATICollectionDiagnostic -Config $Config -Datasets $CollectionDatasets -HandledError $_ `
                    -Message "Cannot resolve member '$memberDN' of '$Identity' on '$memberServer': $($_.Exception.Message)"
                $sid = $null
                $objectClass = 'unknown'
                if ($memberDN -match '(?i)^CN=(S-\d+(?:-\d+)+),CN=ForeignSecurityPrincipals,') {
                    $sid = $Matches[1]
                    $objectClass = 'foreignSecurityPrincipal'
                }
                $members.Add([pscustomobject]@{
                    Name = $memberDN
                    SamAccountName = $null
                    DistinguishedName = $memberDN
                    objectClass = $objectClass
                    SID = $sid
                    MembershipResolved = $false
                    ExternalResolutionStatus = if ($objectClass -eq 'foreignSecurityPrincipal') { 'LocalObjectUnreadable' } else { 'NotApplicable' }
                    ResolutionError = $_.Exception.Message
                    ResolutionAttempts = @()
                })
                continue
            }

            $resolvedMember = [pscustomobject]@{
                Name = $member.Name
                SamAccountName = $member.sAMAccountName
                DistinguishedName = $member.DistinguishedName
                objectClass = $member.objectClass
                SID = if ($member.objectSid -and $member.objectSid.PSObject.Properties['Value']) {
                    [string]$member.objectSid.Value
                } else { [string]$member.objectSid }
                MembershipResolved = $true
            }

            if ($Recursive -and $member.objectClass -eq 'group') {
                if (-not $seenGroups.Add($memberDN)) { continue }
                try {
                    $nestedGroup = Get-ADGroup -Identity $memberDN -Server $memberServer -Properties Members -ErrorAction Stop
                    if ($null -eq $nestedGroup -or -not $nestedGroup.PSObject.Properties['Members']) {
                        throw "No readable group member links returned for '$memberDN'."
                    }
                    $pending.Enqueue($nestedGroup)
                }
                catch {
                    $null = $unresolved.Add($memberDN)
                    $memberLinksComplete = $false
                    Write-MATICollectionDiagnostic -Config $Config -Datasets $CollectionDatasets -HandledError $_ `
                        -Message "Cannot expand nested group '$memberDN' of '$Identity' on '$memberServer': $($_.Exception.Message)"
                    $resolvedMember.MembershipResolved = $false
                    $members.Add($resolvedMember)
                }
                continue
            }

            if ($member.objectClass -eq 'foreignSecurityPrincipal') {
                $foreignEncountered = $true
                $resolution = [pscustomobject]@{
                    Status = 'NotAttempted'; ResolvedName = $null; DistinguishedName = $null
                    ObjectClass = $null; Domain = $null
                    Error = 'External identity lookup requires the collector context.'; Attempts = @()
                }
                if ($Config -and $resolvedMember.SID -match '^S-\d+(?:-\d+)+$') {
                    $resolution = Resolve-MATIForeignPrincipal -SID $resolvedMember.SID -Config $Config -Datasets $ResolutionDatasets
                } elseif ($Config) {
                    $resolution.Status = 'InvalidSID'
                    $resolution.Error = 'The local foreign-principal object did not provide a valid SID for external lookup.'
                }
                if ($Config -and $resolution.Domain -and $resolution.Domain -notin $Config['_ForestCache'].Domains) {
                    $resolution | Add-Member -NotePropertyName OutsideAssessmentScope -NotePropertyValue $true -Force
                }
                $resolvedMember | Add-Member -NotePropertyMembers @{
                    ExternalResolutionStatus = $resolution.Status
                    ResolvedName = $resolution.ResolvedName
                    ResolvedDistinguishedName = $resolution.DistinguishedName
                    ResolvedObjectClass = $resolution.ObjectClass
                    ResolutionError = $resolution.Error
                    ResolutionAttempts = @($resolution.Attempts)
                    OutsideAssessmentScope = [bool]$resolution.OutsideAssessmentScope
                }
                if ($resolution.OutsideAssessmentScope) {
                    $members.Add($resolvedMember)
                    continue
                }
                if ($resolution.Status -eq 'Resolved') {
                    if (-not $Recursive) { $members.Add($resolvedMember); continue }
                    if ($resolution.ObjectClass -eq 'group') {
                        if (-not $seenGroups.Add($resolution.DistinguishedName)) { continue }
                        try {
                            $resolvedGroup = Get-ADGroup -Identity $resolution.DistinguishedName -Server $resolution.Domain `
                                -Properties Members -ErrorAction Stop
                            if ($null -eq $resolvedGroup -or -not $resolvedGroup.PSObject.Properties['Members']) {
                                throw "No readable group member links returned for '$($resolution.DistinguishedName)'."
                            }
                            $pending.Enqueue($resolvedGroup)
                            continue
                        } catch {
                            $memberLinksComplete = $false
                            Write-MATICollectionDiagnostic -Config $Config -Datasets $ResolutionDatasets -HandledError $_ `
                                -Message "Cannot expand resolved in-forest group '$($resolution.DistinguishedName)' of '$Identity': $($_.Exception.Message)"
                        }
                    } else {
                        $members.Add([pscustomobject]@{
                            Name = $resolution.Name; SamAccountName = $resolution.SamAccountName
                            DistinguishedName = $resolution.DistinguishedName; objectClass = $resolution.ObjectClass
                            SID = $resolvedMember.SID; MembershipResolved = $true
                            SourceForeignPrincipalDN = $memberDN; ExternalResolutionStatus = 'Resolved'
                            ResolvedName = $resolution.ResolvedName
                        })
                        continue
                    }
                }
                $null = $unresolved.Add($memberDN)
                $resolvedMember.MembershipResolved = $false
                Write-MATICollectionDiagnostic -Config $Config -Datasets $ResolutionDatasets `
                    -AffectsCoverage ($ResolutionDatasets.Count -gt 0 -or -not $Config) `
                    -Message "Foreign principal '$memberDN' (SID '$($resolvedMember.SID)') retained in '$Identity'; its external identity and any nested membership were not resolved. Resolution status: $($resolution.Status). This does not establish that the SID is orphaned."
            }
            $members.Add($resolvedMember)
        }
    }

    if (-not $Config -and ($foreignEncountered -or ($members | Where-Object {
        $_.objectClass -eq 'foreignSecurityPrincipal' -or
        $_.DistinguishedName -like '*,CN=ForeignSecurityPrincipals,*'
    } | Select-Object -First 1))) {
        $advice = Get-MATIADWSForeignPrincipalAdvice
        Write-MATICollectionDiagnostic -Config $Config -AffectsCoverage $false `
            -Message "$($advice.Message) See $($advice.Reference)"
    }

    if ($Recursive) {
        $uniqueMembers = [System.Collections.Generic.List[object]]::new()
        $identities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $members) {
            $key = if ($entry.SID) { [string]$entry.SID } else { [string]$entry.DistinguishedName }
            if ($identities.Add($key)) { $uniqueMembers.Add($entry) }
        }
        $members = $uniqueMembers
    }
    return @{
        Members = $members.ToArray()
        Complete = ($unresolved.Count -eq 0)
        ReadMethod = if ($Config) { 'ScopedMemberLinks' } else { 'MemberLinks' }
        MembershipScope = if ($Config) { 'TargetForest' } else { 'Unrestricted' }
        UnresolvedMembers = @($unresolved)
        MemberLinksComplete = $memberLinksComplete
        LocalObjectsComplete = $localObjectsComplete
    }
}

function Get-MATIDomainSidString {
    <#
    .SYNOPSIS
        Robustly extracts a domain SID string (S-1-5-21-...) from an AD object's
        DomainSID property, whether native (SecurityIdentifier) or deserialized
        (string / PSObject) under WinPSCompat.
    .OUTPUTS
        [string] the domain SID, or $null when it is not a valid domain SID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        $DomainSID
    )

    if ($null -eq $DomainSID) { return $null }

    if ($DomainSID -is [System.Security.Principal.SecurityIdentifier]) {
        return $DomainSID.Value
    }

    # Deserialized objects may surface .Value as a NoteProperty; otherwise the
    # object itself stringifies to the SID (its preserved ToString()).
    $val = $null
    try { $val = $DomainSID.Value } catch { $val = $null }
    $sid = if ($val) { [string]$val } else { [string]$DomainSID }

    if ($sid -match '^S-1-5-21-\d') { return $sid }
    return $null
}

function Test-MATIWinPSCompat {
    <#
    .SYNOPSIS
        Returns $true when the ActiveDirectory module is being served through the
        Windows PowerShell compatibility layer (implicit remoting), which returns
        deserialized objects and disables the AD: PSProvider locally.
    #>
    [CmdletBinding()]
    param()

    # The compatibility layer creates an implicit remoting session named
    # 'WinPSCompatSession'. Its presence is the most reliable signal.
    if (Get-PSSession -Name 'WinPSCompatSession' -ErrorAction SilentlyContinue) {
        return $true
    }

    # Secondary signal: the AD provider is registered natively only when the
    # module is loaded in-process (native), not via compatibility remoting.
    if (-not (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction SilentlyContinue)) {
        return $true
    }

    return $false
}

function Get-MATIObjectAcl {
    <#
    .SYNOPSIS
        Reads the security descriptor of an AD object in a way that works both
        on a domain controller (native AD: PSProvider) and from a workstation
        where the ActiveDirectory module is served via the compatibility layer
        (provider unavailable -> System.DirectoryServices fallback).
    .PARAMETER DistinguishedName
        The DN of the object to read.
    .PARAMETER Server
        Optional DC / domain to target (avoids LDAP referrals on child domains).
    .OUTPUTS
        [System.DirectoryServices.ActiveDirectorySecurity] (has .Access / .Owner).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [string]$Server
    )

    # Preferred path: native AD: PSProvider (DC / in-process RSAT).
    if (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction SilentlyContinue) {
        if ($Server) {
            $driveName = "MATIAcl_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            try {
                New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "" -Server $Server -ErrorAction Stop | Out-Null
                return Get-Acl -Path "${driveName}:\$DistinguishedName" -ErrorAction Stop
            }
            finally {
                Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue
            }
        }
        return Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    }

    # Fallback path: read the security descriptor directly via LDAP/ADSI.
    $entry = $null
    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $null = $entry.RefreshCache(@('nTSecurityDescriptor'))
        $sd = $entry.ObjectSecurity
        if ($null -eq $sd) {
            throw "No security descriptor returned for $DistinguishedName"
        }
        return $sd
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
}
