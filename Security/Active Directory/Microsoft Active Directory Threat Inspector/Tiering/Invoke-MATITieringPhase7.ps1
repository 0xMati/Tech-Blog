# Tiering\Invoke-MATITieringPhase7.ps1
# Phase 7 — Implement Tier 0 Object Protection
# Audits ACLs on critical Tier 0 AD objects, Tier 0-linked GPO ownership and
# permissions, krbtgt password age, and service account exposure.

function Invoke-MATITieringPhase7 {
    <#
    .SYNOPSIS
        Phase 7 — Audit Tier 0 AD object protection.
    .DESCRIPTION
        Guided, step-by-step assessment:
        1. Consume the exact OU state exported by Phase 1
        2. Audit ACLs on critical Tier 0 AD objects
        3. Audit ownership and edit permissions on GPOs linked to Tier 0
        4. Review krbtgt password age and optionally perform the first reset
        5. Audit SPN-bearing accounts, sMSAs, and gMSAs for privileged exposure
        6. Generate an HTML audit report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RootPath,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputDir
    )

    $ErrorActionPreference = 'Continue'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

    $domain = Get-ADDomain
    $rootDse = Get-ADRootDSE
    $domainDN = $domain.DistinguishedName
    $ouCfg = $TieringConfig.OUStructure

    $phase1StatePath = Join-Path $RootPath 'Outputs\Tiering\MATI-Tiering-Phase1-Latest.json'
    if (-not (Test-Path $phase1StatePath)) {
        Write-Host "`n  [ERROR] Phase 1 state file not found. Run Phase 1 first." -ForegroundColor Red
        Write-Host "    Expected: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    try {
        $phase1State = Get-Content -Path $phase1StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "`n  [ERROR] Failed to read Phase 1 state file." -ForegroundColor Red
        Write-Host "    $phase1StatePath" -ForegroundColor DarkGray
        Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $baseDN = [string]$phase1State.BaseDN
    $containerOU = if ($null -ne $phase1State.ContainerOU -and [string]$phase1State.ContainerOU -ne '') { [string]$phase1State.ContainerOU } else { $null }
    $tier0OUDN = [string]$phase1State.Tier0OUDN

    if ([string]::IsNullOrWhiteSpace($baseDN) -or [string]::IsNullOrWhiteSpace($tier0OUDN)) {
        Write-Host "`n  [ERROR] Phase 1 state is incomplete. Run Phase 1 again." -ForegroundColor Red
        Write-Host "    State file: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $results = @{
        BaseDN              = $baseDN
        ContainerOU         = $containerOU
        Phase1StatePath     = $phase1StatePath
        Tier0OUDN           = $tier0OUDN
        AuditedObjects      = [System.Collections.Generic.List[object]]::new()
        AuditedGPOs         = [System.Collections.Generic.List[object]]::new()
        ACLFindings         = [System.Collections.Generic.List[object]]::new()
        GPOFindings         = [System.Collections.Generic.List[object]]::new()
        KrbtgtStatus        = $null
        KrbtgtRotated       = $false
        ServiceAccountAudit = [System.Collections.Generic.List[object]]::new()
        Warnings            = [System.Collections.Generic.List[string]]::new()
        Errors              = [System.Collections.Generic.List[string]]::new()
    }

    function Test-AdObjectExists {
        param([string]$DistinguishedName)

        if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }
        try {
            return [adsi]::Exists("LDAP://$DistinguishedName")
        } catch {
            return $false
        }
    }

    function Add-AuditedObject {
        param(
            [string]$Name,
            [string]$Path,
            [string]$Category,
            [string]$Notes
        )

        $results.AuditedObjects.Add([PSCustomObject]@{
            Name     = $Name
            Path     = $Path
            Category = $Category
            Notes    = $Notes
        })
    }

    function New-StrongPassword {
        param([int]$Length = 48)

        $allowedCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}'
        $bytes = New-Object byte[] $Length
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

        try {
            $rng.GetBytes($bytes)
        } finally {
            $rng.Dispose()
        }

        $passwordCharacters = foreach ($byte in $bytes) {
            $allowedCharacters[$byte % $allowedCharacters.Length]
        }

        return (-join $passwordCharacters)
    }

    function Add-PrivilegeMembers {
        param(
            [string]$GroupIdentity,
            [string]$Label,
            [hashtable]$PrivilegeMap
        )

        try {
            $group = Get-ADGroup -Identity $GroupIdentity -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
            foreach ($member in $members) {
                if ([string]::IsNullOrWhiteSpace([string]$member.DistinguishedName)) {
                    continue
                }
                if (-not $PrivilegeMap.ContainsKey($member.DistinguishedName)) {
                    $PrivilegeMap[$member.DistinguishedName] = [System.Collections.Generic.List[string]]::new()
                }
                if (-not $PrivilegeMap[$member.DistinguishedName].Contains($Label)) {
                    $PrivilegeMap[$member.DistinguishedName].Add($Label)
                }
            }
        } catch {
            $results.Warnings.Add("Unable to resolve privileged group '$GroupIdentity' during service account audit: $($_.Exception.Message)")
        }
    }

    function Resolve-IdentityReferenceValue {
        param([string]$IdentityValue)

        if ([string]::IsNullOrWhiteSpace($IdentityValue)) {
            return $IdentityValue
        }

        if ($IdentityValue -match '^S-\d-') {
            try {
                $sid = [System.Security.Principal.SecurityIdentifier]::new($IdentityValue)
                return $sid.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                return $IdentityValue
            }
        }

        return $IdentityValue
    }

    function Add-AclFinding {
        param(
            [Parameter(Mandatory)] [hashtable]$Index,
            [Parameter(Mandatory)] [string]$Object,
            [Parameter(Mandatory)] [string]$Category,
            [Parameter(Mandatory)] [string]$Path,
            [Parameter(Mandatory)] [string]$Identity,
            [Parameter(Mandatory)] [string]$Rights,
            [Parameter(Mandatory)] [bool]$Inherited,
            [Parameter(Mandatory)] [string]$Severity
        )

        $key = "$Object|$Category|$Path|$Identity|$Rights|$Inherited|$Severity"
        if ($Index.ContainsKey($key)) {
            $Index[$key].Occurrences++
            return
        }

        $finding = [PSCustomObject]@{
            Object      = $Object
            Category    = $Category
            Path        = $Path
            Identity    = $Identity
            Rights      = $Rights
            Inherited   = $Inherited
            Severity    = $Severity
            Occurrences = 1
        }

        $Index[$key] = $finding
        $results.ACLFindings.Add($finding)
    }

    function Get-DirectGpoLinksFromOu {
        param(
            [Parameter(Mandatory)] [string]$OrganizationalUnitDn
        )

        $ouObject = Get-ADObject -Identity $OrganizationalUnitDn -Properties gPLink -ErrorAction Stop
        $gpoLinks = [System.Collections.Generic.List[object]]::new()
        $rawGpLink = [string]$ouObject.gPLink

        if ([string]::IsNullOrWhiteSpace($rawGpLink)) {
            return $gpoLinks
        }

        $matches = [regex]::Matches($rawGpLink, '\[(?<path>LDAP://[^;\]]+);(?<flags>\d+)\]')
        $order = 1
        foreach ($match in $matches) {
            $pathValue = [string]$match.Groups['path'].Value
            $flags = [int]$match.Groups['flags'].Value
            $guidMatch = [regex]::Match($pathValue, '\{(?<guid>[0-9A-Fa-f-]+)\}')
            if (-not $guidMatch.Success) {
                continue
            }

            $guidValue = [guid]$guidMatch.Groups['guid'].Value
            $gpoLinks.Add([PSCustomObject]@{
                GpoId    = $guidValue
                Enabled  = [bool](($flags -band 1) -eq 0)
                Enforced = [bool](($flags -band 2) -ne 0)
                Order    = $order
            })
            $order++
        }

        return $gpoLinks
    }

    function Get-ServiceAccountRisk {
        param(
            [string]$AccountType,
            [bool]$Enabled,
            [int]$PasswordAgeDays,
            [bool]$PasswordNeverExpires,
            [bool]$IsPrivileged,
            [bool]$AdminCount,
            [bool]$IsTier0Scoped
        )

        if ($IsPrivileged) { return 'Critical' }
        if (-not $Enabled) { return 'Low' }
        if ($AccountType -in @('gMSA', 'sMSA')) {
            if ($IsTier0Scoped) { return 'Medium' }
            return 'Low'
        }
        if ($PasswordNeverExpires) { return 'High' }
        if ($AdminCount) { return 'High' }
        if ($PasswordAgeDays -gt 365) { return 'High' }
        if ($PasswordAgeDays -gt 180) { return 'Medium' }
        if ($IsTier0Scoped) { return 'Medium' }
        return 'Low'
    }

    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 7 — Implement Tier 0 Object Protection" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Audits critical Tier 0 objects, Tier 0-linked GPOs, krbtgt, and service account exposure." -ForegroundColor DarkGray
    Write-Host "   Consumes the exact OU state exported by Phase 1 instead of reconstructing the hierarchy." -ForegroundColor DarkGray
    Write-Host ""

    $criticalObjects = [System.Collections.Generic.List[object]]::new()
    $criticalObjects.Add([PSCustomObject]@{ Name = 'Domain Root'; Path = $domainDN; Category = 'Directory'; Notes = 'Default naming context root.' })
    $criticalObjects.Add([PSCustomObject]@{ Name = 'AdminSDHolder'; Path = "CN=AdminSDHolder,CN=System,$domainDN"; Category = 'Privileged Protection'; Notes = 'Protected ACL template for privileged objects.' })
    $criticalObjects.Add([PSCustomObject]@{ Name = 'Configuration'; Path = [string]$rootDse.configurationNamingContext; Category = 'Directory'; Notes = 'Configuration partition.' })
    $criticalObjects.Add([PSCustomObject]@{ Name = 'Schema'; Path = [string]$rootDse.schemaNamingContext; Category = 'Directory'; Notes = 'Schema partition.' })
    $criticalObjects.Add([PSCustomObject]@{ Name = 'System'; Path = "CN=System,$domainDN"; Category = 'Directory'; Notes = 'System container hosting privileged metadata.' })
    $criticalObjects.Add([PSCustomObject]@{ Name = 'Tier 0 Root OU'; Path = $tier0OUDN; Category = 'Tier 0 OU'; Notes = 'Exact Tier 0 OU from Phase 1 state.' })

    foreach ($subOuName in $ouCfg.SubOUs.Tier0) {
        $subOuDn = "OU=$subOuName,$tier0OUDN"
        if (Test-AdObjectExists -DistinguishedName $subOuDn) {
            $criticalObjects.Add([PSCustomObject]@{
                Name = "Tier 0 $subOuName OU"
                Path = $subOuDn
                Category = 'Tier 0 OU'
                Notes = 'Tier 0 child OU created by the tiering model.'
            })
        }
    }

    $trustedAclPatterns = 'S-1-5-18|NT AUTHORITY\\SYSTEM|^SYSTEM$|BUILTIN\\Administrators|Domain Admins|Enterprise Admins|Schema Admins|Enterprise Domain Controllers|Key Admins|Enterprise Key Admins'
    $dangerousRightsPattern = 'GenericAll|WriteDacl|WriteOwner|GenericWrite|CreateChild|DeleteChild'
    $aclFindingIndex = @{}

    Write-Host "  Step 1/4 — ACL Audit on Critical Tier 0 Objects" -ForegroundColor Yellow
    Write-Host ""

    foreach ($obj in $criticalObjects) {
        Add-AuditedObject -Name $obj.Name -Path $obj.Path -Category $obj.Category -Notes $obj.Notes

        Write-Host "    Auditing: $($obj.Name)" -ForegroundColor White
        try {
            $acl = Get-Acl "AD:\$($obj.Path)" -ErrorAction Stop
            $dangerousAces = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference.Value -notmatch $trustedAclPatterns -and
                $_.ActiveDirectoryRights.ToString() -match $dangerousRightsPattern
            }

            foreach ($ace in $dangerousAces) {
                $rights = $ace.ActiveDirectoryRights.ToString()
                $severity = if ($rights -match 'GenericAll|WriteDacl|WriteOwner') { 'Critical' } else { 'High' }
                $resolvedIdentity = Resolve-IdentityReferenceValue -IdentityValue $ace.IdentityReference.Value
                Write-Host "      [!] ${severity}: $resolvedIdentity has $rights on $($obj.Name)" -ForegroundColor $(if ($severity -eq 'Critical') { 'Red' } else { 'Yellow' })
                Add-AclFinding -Index $aclFindingIndex -Object $obj.Name -Category $obj.Category -Path $obj.Path -Identity $resolvedIdentity -Rights $rights -Inherited ([bool]$ace.IsInherited) -Severity $severity
            }

            if (-not $dangerousAces) {
                Write-Host "      [OK] No dangerous non-standard ACEs found" -ForegroundColor Green
            }
        } catch {
            Write-Host "      [!] Cannot read ACL: $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("ACL audit failed on $($obj.Name): $($_.Exception.Message)")
        }
    }

    Write-Host ""
    Write-Host "  Step 2/4 — Tier 0-Linked GPO Audit" -ForegroundColor Yellow
    Write-Host ""

    try {
        $tier0GpoLinks = @(Get-DirectGpoLinksFromOu -OrganizationalUnitDn $tier0OUDN)

        if (-not $tier0GpoLinks -or $tier0GpoLinks.Count -eq 0) {
            Write-Host "    [!] No GPOs are directly linked to the Tier 0 OU." -ForegroundColor Yellow
            $results.Warnings.Add('No GPOs are directly linked to the Tier 0 OU exported by Phase 1. Phase 7 only audits GPOs linked to that exact OU.')
        }

        $trustedGpoPermissionPatterns = 'Domain Admins|Enterprise Admins|NT AUTHORITY\\SYSTEM|^SYSTEM$'

        foreach ($link in $tier0GpoLinks) {
            try {
                $gpo = Get-GPO -Guid $link.GpoId -ErrorAction Stop
            } catch {
                $results.Warnings.Add("A Tier 0-linked GPO with GUID '$($link.GpoId)' could not be resolved. The link entry was skipped.")
                continue
            }

            $results.AuditedGPOs.Add([PSCustomObject]@{
                GPOName   = $gpo.DisplayName
                GPOId     = $gpo.Id.ToString()
                TargetOU  = $tier0OUDN
                Enabled   = [bool]$link.Enabled
                Enforced  = [bool]$link.Enforced
                LinkOrder = [int]$link.Order
            })

            $ownerStatus = if ($gpo.Owner -match 'Domain Admins|Enterprise Admins') { 'OK' } else { 'Warning' }
            if ($ownerStatus -ne 'OK') {
                Write-Host "      [!] GPO '$($gpo.DisplayName)' has non-standard owner: $($gpo.Owner)" -ForegroundColor Yellow
            }

            $results.GPOFindings.Add([PSCustomObject]@{
                GPOName     = $gpo.DisplayName
                GPOId       = $gpo.Id.ToString()
                FindingType = 'Owner'
                Principal   = $gpo.Owner
                Permission  = 'Owner'
                Status      = $ownerStatus
                Details     = if ($ownerStatus -eq 'OK') { 'Owner is a standard Tier 0 admin principal.' } else { 'Owner should normally be Domain Admins or Enterprise Admins.' }
            })

            try {
                $permissions = Get-GPPermission -Name $gpo.DisplayName -All -ErrorAction Stop
                foreach ($permissionEntry in $permissions) {
                    $principal = if ($permissionEntry.Trustee) { [string]$permissionEntry.Trustee.Name } else { [string]$permissionEntry.Trustee }
                    $permissionName = [string]$permissionEntry.Permission
                    if ([string]::IsNullOrWhiteSpace($principal)) { continue }

                    if ($permissionName -match 'GpoEditDeleteModifySecurity|GpoEdit|GpoCustom' -and $principal -notmatch $trustedGpoPermissionPatterns) {
                        Write-Host "      [!] Critical: $principal has $permissionName on '$($gpo.DisplayName)'" -ForegroundColor Red
                        $results.GPOFindings.Add([PSCustomObject]@{
                            GPOName     = $gpo.DisplayName
                            GPOId       = $gpo.Id.ToString()
                            FindingType = 'Permission'
                            Principal   = $principal
                            Permission  = $permissionName
                            Status      = 'Critical'
                            Details     = 'Non-standard principal can edit or modify security on a Tier 0-linked GPO.'
                        })
                    }
                }
            } catch {
                Write-Host "      [!] Cannot read GPO permissions for '$($gpo.DisplayName)': $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO permission audit failed for '$($gpo.DisplayName)': $($_.Exception.Message)")
            }
        }

        $gpoIssueCount = ($results.GPOFindings | Where-Object Status -ne 'OK').Count
        Write-Host "    Tier 0-linked GPOs audited: $($results.AuditedGPOs.Count) | Issues: $gpoIssueCount" -ForegroundColor $(if ($gpoIssueCount -gt 0) { 'Yellow' } else { 'Green' })
    } catch {
        Write-Host "      [!] Cannot audit Tier 0-linked GPOs: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("GPO audit failed: $($_.Exception.Message)")
    }

    Write-Host ""
    Write-Host "  Step 3/4 — krbtgt Account Status" -ForegroundColor Yellow
    Write-Host ""

    try {
        $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet, Enabled -ErrorAction Stop
        $pwdAge = if ($krbtgt.PasswordLastSet) { (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days } else { 9999 }
        $severity = if ($pwdAge -le 180) { 'OK' } elseif ($pwdAge -le 365) { 'Warning' } else { 'Critical' }

        $results.KrbtgtStatus = [PSCustomObject]@{
            PasswordLastSet     = $krbtgt.PasswordLastSet
            AgeDays             = $pwdAge
            Severity            = $severity
            Enabled             = [bool]$krbtgt.Enabled
            RotationRecommended = [bool]($pwdAge -gt 180)
            Guidance            = if ($pwdAge -gt 180) { 'Perform a double rotation with replication time between resets. This phase only offers the first reset.' } else { 'Password age is within the current threshold.' }
        }

        $color = switch ($severity) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Critical' { 'Red' } }
        Write-Host "    krbtgt password last set: $($krbtgt.PasswordLastSet) ($pwdAge days ago)" -ForegroundColor $color

        if ($pwdAge -gt 180) {
            $results.Warnings.Add("krbtgt password age is $pwdAge days. Microsoft guidance requires a controlled double rotation, not a single reset.")
            Write-Host "    [!] krbtgt password is older than 180 days. Controlled double rotation is recommended." -ForegroundColor Yellow
            $rotateChoice = Read-Host "    Type ROTATE to perform only the first krbtgt reset now, or press Enter to skip"
            if ($rotateChoice.Trim().ToUpper() -eq 'ROTATE') {
                try {
                    $newPwd = New-StrongPassword -Length 64
                    Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword (
                        ConvertTo-SecureString -String $newPwd -AsPlainText -Force
                    ) -ErrorAction Stop
                    Write-Host "    [+] First krbtgt reset complete. Wait for replication and perform the second reset later." -ForegroundColor Green
                    $results.KrbtgtRotated = $true
                    $results.Warnings.Add('First krbtgt reset completed. A second reset is still required after replication convergence.')
                } catch {
                    Write-Host "    [!] krbtgt reset failed: $($_.Exception.Message)" -ForegroundColor Red
                    $results.Errors.Add("krbtgt reset failed: $($_.Exception.Message)")
                }
            }
        }
    } catch {
        Write-Host "    [!] Cannot read krbtgt: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("krbtgt audit failed: $($_.Exception.Message)")
    }

    Write-Host ""
    Write-Host "  Step 4/4 — Service Account Exposure Audit" -ForegroundColor Yellow
    Write-Host ""

    try {
        $tier0ServiceAccountsDn = "OU=Service Accounts,$tier0OUDN"
        $privilegeMap = @{}
        $groupPrefix = $TieringConfig.Naming.GroupPrefix
        $tier0AdminsGroup = "${groupPrefix}0-Admins"
        $privilegedGroups = @(
            @{ Name = 'Domain Admins'; Label = 'Domain Admins' }
            @{ Name = 'Enterprise Admins'; Label = 'Enterprise Admins' }
            @{ Name = 'Schema Admins'; Label = 'Schema Admins' }
            @{ Name = 'Administrators'; Label = 'Administrators' }
            @{ Name = 'Account Operators'; Label = 'Account Operators' }
            @{ Name = 'Server Operators'; Label = 'Server Operators' }
            @{ Name = 'Backup Operators'; Label = 'Backup Operators' }
            @{ Name = 'Print Operators'; Label = 'Print Operators' }
            @{ Name = 'DnsAdmins'; Label = 'DnsAdmins' }
            @{ Name = $tier0AdminsGroup; Label = $tier0AdminsGroup }
        )

        foreach ($groupInfo in $privilegedGroups) {
            Add-PrivilegeMembers -GroupIdentity $groupInfo.Name -Label $groupInfo.Label -PrivilegeMap $privilegeMap
        }

        $serviceUsers = @(Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, Enabled, DistinguishedName, SamAccountName, AdminCount -ErrorAction Stop | Where-Object { $_.SamAccountName -ne 'krbtgt' })
        $managedServiceAccounts = @()
        try {
            $managedServiceAccounts = @(Get-ADServiceAccount -Filter * -Properties ServicePrincipalName, Enabled, DistinguishedName, SamAccountName, ObjectClass -ErrorAction Stop)
        } catch {
            $results.Warnings.Add("Managed service account enumeration failed: $($_.Exception.Message)")
        }

        foreach ($svc in $serviceUsers) {
            $passwordAge = if ($svc.PasswordLastSet) { (New-TimeSpan -Start $svc.PasswordLastSet -End (Get-Date)).Days } else { 9999 }
            $passwordState = if ($svc.PasswordNeverExpires) { 'Never expires' } elseif ($svc.PasswordLastSet) { "$passwordAge days" } else { 'Unknown' }
            $isTier0Scoped = $svc.DistinguishedName -like "*$tier0OUDN"
            $privilegedLabels = if ($privilegeMap.ContainsKey($svc.DistinguishedName)) { @($privilegeMap[$svc.DistinguishedName]) } else { @() }
            $risk = Get-ServiceAccountRisk -AccountType 'User-SPN' -Enabled ([bool]$svc.Enabled) -PasswordAgeDays $passwordAge -PasswordNeverExpires ([bool]$svc.PasswordNeverExpires) -IsPrivileged ($privilegedLabels.Count -gt 0) -AdminCount ([bool]($svc.AdminCount -eq 1)) -IsTier0Scoped $isTier0Scoped

            $results.ServiceAccountAudit.Add([PSCustomObject]@{
                Name              = $svc.SamAccountName
                AccountType       = 'User-SPN'
                Enabled           = [bool]$svc.Enabled
                PasswordState     = $passwordState
                PrivilegedGroups  = if ($privilegedLabels.Count -gt 0) { $privilegedLabels -join ', ' } else { '' }
                Tier0Scoped       = $isTier0Scoped
                SPNs              = ($svc.ServicePrincipalName -join '; ')
                DistinguishedName = $svc.DistinguishedName
                Risk              = $risk
            })

            if ($risk -in @('Critical', 'High')) {
                Write-Host "      [$risk] $($svc.SamAccountName) — $passwordState$(if ($privilegedLabels.Count -gt 0) { " — Privileged: $($privilegedLabels -join ', ')" })" -ForegroundColor $(if ($risk -eq 'Critical') { 'Red' } else { 'Yellow' })
            }
        }

        foreach ($svc in $managedServiceAccounts) {
            $accountType = if ([string]$svc.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
            $isTier0Scoped = $svc.DistinguishedName -like "*$tier0ServiceAccountsDn" -or $svc.DistinguishedName -like "*$tier0OUDN"
            $privilegedLabels = if ($privilegeMap.ContainsKey($svc.DistinguishedName)) { @($privilegeMap[$svc.DistinguishedName]) } else { @() }
            $risk = Get-ServiceAccountRisk -AccountType $accountType -Enabled ([bool]$svc.Enabled) -PasswordAgeDays 0 -PasswordNeverExpires $false -IsPrivileged ($privilegedLabels.Count -gt 0) -AdminCount $false -IsTier0Scoped $isTier0Scoped

            $results.ServiceAccountAudit.Add([PSCustomObject]@{
                Name              = $svc.SamAccountName
                AccountType       = $accountType
                Enabled           = [bool]$svc.Enabled
                PasswordState     = 'Managed by AD'
                PrivilegedGroups  = if ($privilegedLabels.Count -gt 0) { $privilegedLabels -join ', ' } else { '' }
                Tier0Scoped       = $isTier0Scoped
                SPNs              = if ($svc.ServicePrincipalName) { $svc.ServicePrincipalName -join '; ' } else { '' }
                DistinguishedName = $svc.DistinguishedName
                Risk              = $risk
            })

            if ($risk -eq 'Critical') {
                Write-Host "      [Critical] $($svc.SamAccountName) — Privileged managed service account" -ForegroundColor Red
            }
        }

        $criticalSvc = ($results.ServiceAccountAudit | Where-Object Risk -eq 'Critical').Count
        $highSvc = ($results.ServiceAccountAudit | Where-Object Risk -eq 'High').Count
        Write-Host "    Accounts audited: $($results.ServiceAccountAudit.Count) | Critical: $criticalSvc | High: $highSvc" -ForegroundColor $(if ($criticalSvc -gt 0) { 'Red' } elseif ($highSvc -gt 0) { 'Yellow' } else { 'Green' })
    } catch {
        Write-Host "    [!] Service account audit failed: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("Service account audit failed: $($_.Exception.Message)")
    }

    Write-Host ""
    Write-Host "  Generating Phase 7 report..." -ForegroundColor Yellow
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase7-$timestamp.html"
    Export-TieringPhase7Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase7-$timestamp.json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 7 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   Objects audited  : $($results.AuditedObjects.Count)" -ForegroundColor White
    Write-Host "   ACL findings     : $($results.ACLFindings.Count)" -ForegroundColor White
    Write-Host "   Tier 0 GPO issues: $(($results.GPOFindings | Where-Object Status -ne 'OK').Count)" -ForegroundColor White
    Write-Host "   krbtgt age       : $(if ($results.KrbtgtStatus) { "$($results.KrbtgtStatus.AgeDays) days ($($results.KrbtgtStatus.Severity))" } else { 'N/A' })" -ForegroundColor White
    Write-Host "   Svc acct risks   : $(($results.ServiceAccountAudit | Where-Object { $_.Risk -in 'Critical', 'High' }).Count)" -ForegroundColor White
    if ($results.Warnings.Count -gt 0) { Write-Host "   Warnings         : $($results.Warnings.Count)" -ForegroundColor Yellow }
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors           : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report           : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}
