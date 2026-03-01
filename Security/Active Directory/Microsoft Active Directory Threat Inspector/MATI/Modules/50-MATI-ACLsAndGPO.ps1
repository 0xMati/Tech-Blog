#requires -Version 5.1
<#
50-MATI-ACLsAndGPO.ps1  (MATI – Microsoft Active Directory Threat Inspector)
Module 50 – ACLs & GPOs

Findings (agrégés) :
  - MATI-ACL-001 – AdminSDHolder dangerous ACLs
  - MATI-ACL-002 – Protected groups with dangerous ACLs
  - MATI-ACL-003 – Protected users with dangerous ACLs
  - MATI-ACL-004 – GPOs with dangerous permissions

Outputs :
  - CSV\MATI_AD_ACL_AdminSDHolder.csv
  - CSV\MATI_AD_ACL_ProtectedObjects.csv
  - CSV\MATI_AD_ACL_GPOs.csv
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$moduleTag = '[50-MATI-ACLsAndGPO]'
Write-Host "$moduleTag Output root : $OutputRoot" -ForegroundColor Cyan

# --------------------------------------------------------------------
# 1. CSV folders
# --------------------------------------------------------------------
$csvRoot = Join-Path -Path $OutputRoot -ChildPath 'CSV'
if (-not (Test-Path -Path $csvRoot)) {
    New-Item -Path $csvRoot -ItemType Directory | Out-Null
}

# --------------------------------------------------------------------
# 2. Load common finding helper (New-Finding)
# --------------------------------------------------------------------
$findingLibPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Common\Finding.ps1'
if (Test-Path -Path $findingLibPath) {
    . $findingLibPath
} else {
    Write-Warning ("{0} Common finding library not found at {1}" -f $moduleTag, $findingLibPath)
    return
}

# --------------------------------------------------------------------
# 3. Import required modules (AD + GroupPolicy)
# --------------------------------------------------------------------
try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
} catch {
    Write-Error ("{0} Failed to load ActiveDirectory module: {1}" -f $moduleTag, $_.Exception.Message)
    return
}

$gpAvailable = $true
try {
    if (-not (Get-Module -Name GroupPolicy -ErrorAction SilentlyContinue)) {
        Import-Module GroupPolicy -ErrorAction Stop
    }
} catch {
    Write-Warning ("{0} Failed to load GroupPolicy module: {1}. GPO ACL checks will be skipped." -f $moduleTag, $_.Exception.Message)
    $gpAvailable = $false
}

# --------------------------------------------------------------------
# 4. Helpers
# --------------------------------------------------------------------
function Convert-MatiToSafeString {
    param([object]$Value)

    if ($null -eq $Value) { return '' }
    try {
        return [string]$Value
    } catch {
        return ''
    }
}

function New-MatiSafeSidSet {
    # Safe list très conservatrice : systèmes + groupes bien connus
    $set = New-Object 'System.Collections.Generic.HashSet[string]'

    $safe = @(
        'S-1-5-18',        # LOCAL SYSTEM
        'S-1-5-19',        # LOCAL SERVICE
        'S-1-5-20',        # NETWORK SERVICE
        'S-1-5-32-544',    # BUILTIN\Administrators
        'S-1-5-32-551',    # BUILTIN\Backup Operators (optionnel, on le considère safe ici)
        'S-1-5-32-549',    # BUILTIN\Server Operators (optionnel)
        'S-1-5-32-548',    # BUILTIN\Account Operators (optionnel)
        'S-1-5-32-550',    # BUILTIN\Print Operators (optionnel)
        'S-1-5-11'         # Authenticated Users (safe pour certains scénarios de lecture)
    )

    foreach ($sid in $safe) {
        [void]$set.Add($sid)
    }

    return $set
}

function Test-MatiIsSafePrincipal {
    param(
        [string]$SidValue,
        [System.Collections.Generic.HashSet[string]]$SafeSidSet
    )

    if ([string]::IsNullOrEmpty($SidValue)) { return $false }

    # 1) Exact match : safe well-known SIDs (BUILTIN\Admins, SYSTEM, etc.)
    if ($SafeSidSet.Contains($SidValue)) {
        return $true
    }

    # 2) Domain-specific SIDs : Domain Admins, Enterprise Admins, etc.
    # On se base sur le RID terminal :
    #  512 = Domain Admins
    #  516 = Domain Controllers
    #  518 = Schema Admins
    #  519 = Enterprise Admins
    #  520 = Group Policy Creator Owners
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidValue)
    } catch {
        return $false
    }

    $sidStr = $sidObj.Value
    $parts  = $sidStr.Split('-')
    if ($parts.Length -lt 2) { return $false }

    $rid = $parts[$parts.Length - 1]
    if ($rid -in @('512','516','518','519','520')) {
        return $true
    }

    return $false
}

function Test-MatiIsDangerousAdRight {
    param(
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    # On considère comme "dangereux" les droits permettant contrôle/écriture
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -ne 0 ) { return $true }
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -ne 0 ) { return $true }
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -ne 0 ) { return $true }
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)  -ne 0 ) { return $true }
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0 ) { return $true }
    if ( ($Rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0 ) { return $true }

    return $false
}

function Get-MatiDirectorySecurity {
    param([string]$DistinguishedName)

    # On passe par ADSI / LDAP pour éviter les soucis de provider AD:\ et de referrals
    try {
        $ldapPath = "LDAP://$DistinguishedName"
        $entry    = [ADSI]$ldapPath
        return $entry.psbase.ObjectSecurity
    } catch {
        return $null
    }
}

function Resolve-MatiSidToName {
    param([string]$SidValue)

    if ([string]::IsNullOrEmpty($SidValue)) { return '' }

    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidValue)
        $nt     = $sidObj.Translate([System.Security.Principal.NTAccount])
        return [string]$nt.Value
    } catch {
        return ''
    }
}

# --------------------------------------------------------------------
# 5. Init collections
# --------------------------------------------------------------------
$findings        = @()
$adminSdRows     = @()
$protectedRows   = @()
$gpoAclRows      = @()

$safeSidSet = New-MatiSafeSidSet

# --------------------------------------------------------------------
# 6. Forest & domains
# --------------------------------------------------------------------
try {
    $forest  = Get-ADForest -ErrorAction Stop
} catch {
    Write-Error ("{0} Failed to query forest: {1}" -f $moduleTag, $_.Exception.Message)
    return
}

$domains = @()
foreach ($domName in $forest.Domains) {
    try {
        $domains += Get-ADDomain -Identity $domName -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query domain {1}: {2}" -f $moduleTag, $domName, $_.Exception.Message)
    }
}

foreach ($domain in $domains) {

    $domainDns     = $domain.DNSRoot
    $domainDn      = $domain.DistinguishedName
    $domainNetbios = $domain.NetBIOSName

    Write-Host "$moduleTag Processing domain $domainDns..." -ForegroundColor Cyan

    # Pour l'agrégation des findings
    $dangerousAdminSdPrincipals = New-Object 'System.Collections.Generic.HashSet[string]'
    $dangerousGroupAcls         = @()
    $dangerousUserAcls          = @()
    $dangerousGpoAcls           = @()

    # ================================================================
    # 6.1 AdminSDHolder
    # ================================================================
    $adminSdDn = "CN=AdminSDHolder,CN=System,$domainDn"

    $adminSdSec = Get-MatiDirectorySecurity -DistinguishedName $adminSdDn
    if ($null -eq $adminSdSec) {
        Write-Warning ("{0} Failed to read AdminSDHolder ACL for {1}" -f $moduleTag, $domainDns)
    } else {
        $rules = $adminSdSec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($ace in $rules) {

            # On ne garde que les ACE non héritées
            if ($ace.IsInherited) { continue }

            $sidValue   = Convert-MatiToSafeString $ace.IdentityReference.Value
            $shortName  = Resolve-MatiSidToName $sidValue
            $rightsStr  = Convert-MatiToSafeString $ace.ActiveDirectoryRights
            $dangerous  = Test-MatiIsDangerousAdRight -Rights $ace.ActiveDirectoryRights
            $isSafe     = $false

            if (-not [string]::IsNullOrEmpty($sidValue)) {
                $isSafe = Test-MatiIsSafePrincipal -SidValue $sidValue -SafeSidSet $safeSidSet
            }

            $adminSdRows += [pscustomobject][ordered]@{
                DomainDNS        = $domainDns
                ObjectDN         = $adminSdDn
                Trustee          = $sidValue
                TrusteeShortName = $shortName
                Rights           = $rightsStr
                IsDangerous      = [bool]$dangerous
                IsSafePrincipal  = [bool]$isSafe
            }

            if ($dangerous -and (-not $isSafe)) {
                [void]$dangerousAdminSdPrincipals.Add(($shortName, $sidValue -join ' | '))
            }
        }
    }

    if ($dangerousAdminSdPrincipals.Count -gt 0) {
        $detailsText = "Principals=" + ([string]::Join(', ', $dangerousAdminSdPrincipals))

        $findings += New-Finding `
            -Id 'MATI-ACL-001' `
            -Category 'ACLs' `
            -Severity 'High' `
            -Title 'AdminSDHolder ACL grants dangerous rights to non-safe principals' `
            -Description ("AdminSDHolder in domain {0} grants dangerous Active Directory rights (e.g., GenericAll/WriteDacl/WriteOwner) to one or more principals that are not in the safe list. Any compromise or misuse of these principals can impact all protected accounts inheriting from AdminSDHolder (Domain Admins, Enterprise Admins, etc.)." -f $domainDns) `
            -Remediation "Review and harden the ACL on AdminSDHolder. Restrict dangerous rights (GenericAll, GenericWrite, WriteOwner, WriteDacl, ExtendedRight) to a minimal set of highly trusted administrative groups. Align with Microsoft tiering / admin isolation guidelines." `
            -ObjectDN $adminSdDn `
            -Domain $domainDns `
            -Source '50-MATI-ACLsAndGPO' `
            -Details $detailsText
    }

    # ================================================================
    # 6.2 Protected objects (groups & users, adminCount=1)
    # ================================================================
    $protectedGroups = @()
    $protectedUsers  = @()

    try {
        $protectedGroups = Get-ADGroup -LDAPFilter '(adminCount=1)' `
            -SearchBase $domainDn -SearchScope Subtree -Server $domainDns `
            -Properties adminCount,DistinguishedName -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query protected groups in {1}: {2}" -f $moduleTag, $domainDns, $_.Exception.Message)
    }

    try {
        $protectedUsers = Get-ADUser -LDAPFilter '(adminCount=1)' `
            -SearchBase $domainDn -SearchScope Subtree -Server $domainDns `
            -Properties adminCount,DistinguishedName -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query protected users in {1}: {2}" -f $moduleTag, $domainDns, $_.Exception.Message)
    }

    # --- Groups
    foreach ($g in $protectedGroups) {

        $objDn  = $g.DistinguishedName
        $objSec = Get-MatiDirectorySecurity -DistinguishedName $objDn
        if ($null -eq $objSec) {
            Write-Warning ("{0} Failed to read ACL for protected group {1} in {2}" -f $moduleTag, $objDn, $domainDns)
            continue
        }

        $rules = $objSec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($ace in $rules) {
            if ($ace.IsInherited) { continue }

            $sidValue   = Convert-MatiToSafeString $ace.IdentityReference.Value
            $shortName  = Resolve-MatiSidToName $sidValue
            $rightsStr  = Convert-MatiToSafeString $ace.ActiveDirectoryRights
            $dangerous  = Test-MatiIsDangerousAdRight -Rights $ace.ActiveDirectoryRights
            $isSafe     = $false

            if (-not [string]::IsNullOrEmpty($sidValue)) {
                $isSafe = Test-MatiIsSafePrincipal -SidValue $sidValue -SafeSidSet $safeSidSet
            }

            $protectedRows += [pscustomobject][ordered]@{
                DomainDNS        = $domainDns
                ObjectDN         = $objDn
                ObjectClass      = 'group'
                ProtectedType    = 'Group'
                Trustee          = $sidValue
                TrusteeShortName = $shortName
                Rights           = $rightsStr
                IsDangerous      = [bool]$dangerous
                IsSafePrincipal  = [bool]$isSafe
            }

            if ($dangerous -and (-not $isSafe)) {
                $dangerousGroupAcls += [pscustomobject]@{
                    ObjectDN  = $objDn
                    Principal = $shortName
                    Sid       = $sidValue
                    Rights    = $rightsStr
                }
            }
        }
    }

    if ($dangerousGroupAcls.Count -gt 0) {
        $sample = $dangerousGroupAcls |
            Select-Object -First 5 |
            ForEach-Object { "{0} <- {1}" -f $_.ObjectDN, $_.Principal }

        $detailsText = "Examples=" + ([string]::Join('; ', $sample))

        $findings += New-Finding `
            -Id 'MATI-ACL-002' `
            -Category 'ACLs' `
            -Severity 'High' `
            -Title 'Protected groups have dangerous ACLs granted to non-safe principals' `
            -Description ("One or more protected groups (adminCount=1) in domain {0} have dangerous Active Directory rights (GenericAll/WriteDacl/WriteOwner/ExtendedRight) granted to principals that are not in the safe list. This can allow privilege escalation against highly privileged groups." -f $domainDns) `
            -Remediation "Review and harden ACLs on all protected groups (adminCount=1). Ensure that only dedicated, well-controlled administrative groups hold powerful rights such as GenericAll, GenericWrite, WriteOwner, WriteDacl or ExtendedRight." `
            -ObjectDN $domainDn `
            -Domain $domainDns `
            -Source '50-MATI-ACLsAndGPO' `
            -Details $detailsText
    }

    # --- Users
    foreach ($u in $protectedUsers) {

        $objDn  = $u.DistinguishedName
        $objSec = Get-MatiDirectorySecurity -DistinguishedName $objDn
        if ($null -eq $objSec) {
            Write-Warning ("{0} Failed to read ACL for protected user {1} in {2}" -f $moduleTag, $objDn, $domainDns)
            continue
        }

        $rules = $objSec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($ace in $rules) {
            if ($ace.IsInherited) { continue }

            $sidValue   = Convert-MatiToSafeString $ace.IdentityReference.Value
            $shortName  = Resolve-MatiSidToName $sidValue
            $rightsStr  = Convert-MatiToSafeString $ace.ActiveDirectoryRights
            $dangerous  = Test-MatiIsDangerousAdRight -Rights $ace.ActiveDirectoryRights
            $isSafe     = $false

            if (-not [string]::IsNullOrEmpty($sidValue)) {
                $isSafe = Test-MatiIsSafePrincipal -SidValue $sidValue -SafeSidSet $safeSidSet
            }

            $protectedRows += [pscustomobject][ordered]@{
                DomainDNS        = $domainDns
                ObjectDN         = $objDn
                ObjectClass      = 'user'
                ProtectedType    = 'User'
                Trustee          = $sidValue
                TrusteeShortName = $shortName
                Rights           = $rightsStr
                IsDangerous      = [bool]$dangerous
                IsSafePrincipal  = [bool]$isSafe
            }

            if ($dangerous -and (-not $isSafe)) {
                $dangerousUserAcls += [pscustomobject]@{
                    ObjectDN  = $objDn
                    Principal = $shortName
                    Sid       = $sidValue
                    Rights    = $rightsStr
                }
            }
        }
    }

    if ($dangerousUserAcls.Count -gt 0) {
        $sample = $dangerousUserAcls |
            Select-Object -First 5 |
            ForEach-Object { "{0} <- {1}" -f $_.ObjectDN, $_.Principal }

        $detailsText = "Examples=" + ([string]::Join('; ', $sample))

        $findings += New-Finding `
            -Id 'MATI-ACL-003' `
            -Category 'ACLs' `
            -Severity 'High' `
            -Title 'Protected users have dangerous ACLs granted to non-safe principals' `
            -Description ("One or more protected users (adminCount=1) in domain {0} have dangerous Active Directory rights granted to principals that are not in the safe list. This can enable direct compromise of highly privileged user accounts." -f $domainDns) `
            -Remediation "Review and harden ACLs on all protected user objects (adminCount=1). Restrict powerful rights to dedicated administrative groups and follow tiering/segregation best practices." `
            -ObjectDN $domainDn `
            -Domain $domainDns `
            -Source '50-MATI-ACLsAndGPO' `
            -Details $detailsText
    }

    # ================================================================
    # 6.3 GPO ACLs (si GroupPolicy dispo)
    # ================================================================
    if ($gpAvailable) {

        $gpos = @()
        try {
            $gpos = Get-GPO -All -Domain $domainDns -ErrorAction Stop
        } catch {
            Write-Warning ("{0} Failed to enumerate GPOs for {1}: {2}" -f $moduleTag, $domainDns, $_.Exception.Message)
            $gpos = @()
        }

        foreach ($gpo in $gpos) {

            $gpoDisplayName = $gpo.DisplayName
            $gpoId          = $gpo.Id

            $perms    = $null
            $gotPerms = $false

            # 1) Essai avec FQDN (child.mathiasmotron.com / mathiasmotron.com)
            try {
                $perms = Get-GPPermissions -Guid $gpoId -All -Domain $domainDns -ErrorAction Stop
                $gotPerms = $true
            } catch {
                Write-Warning ("{0} Get-GPPermissions -Domain {1} failed for {2} ({3}): {4}" -f `
                    $moduleTag, $domainDns, $gpoDisplayName, $gpoId, $_.Exception.Message)
            }

            # 2) Fallback avec NetBIOS
            if (-not $gotPerms -and -not [string]::IsNullOrEmpty($domainNetbios)) {
                try {
                    $perms = Get-GPPermissions -Guid $gpoId -All -Domain $domainNetbios -ErrorAction Stop
                    $gotPerms = $true
                } catch {
                    Write-Warning ("{0} Get-GPPermissions -Domain {1} failed for {2} ({3}): {4}" -f `
                        $moduleTag, $domainNetbios, $gpoDisplayName, $gpoId, $_.Exception.Message)
                }
            }

            # 3) Dernier recours : sans -Domain (contexte courant)
            if (-not $gotPerms) {
                try {
                    $perms = Get-GPPermissions -Guid $gpoId -All -ErrorAction Stop
                    $gotPerms = $true
                    Write-Warning ("{0} Falling back to Get-GPPermissions without -Domain for {1} ({2}) in {3}" -f `
                        $moduleTag, $gpoDisplayName, $gpoId, $domainDns)
                } catch {
                    Write-Warning ("{0} Failed to query GPO permissions for {1} ({2}) in {3}: {4}" -f `
                        $moduleTag, $gpoDisplayName, $gpoId, $domainDns, $_.Exception.Message)
                    continue
                }
            }

            foreach ($p in $perms) {

                $sidValue    = ''
                $shortName   = ''
                $permStr     = ''
                $inherited   = ''
                $isSafe      = $false
                $isDangerous = $false

                try {
                    if ($p.Trustee -and $p.Trustee.Sid) {
                        $sidValue = Convert-MatiToSafeString $p.Trustee.Sid.Value
                        if ([string]::IsNullOrEmpty($sidValue)) {
                            $sidValue = Convert-MatiToSafeString $p.Trustee.Sid
                        }
                    }
                } catch { }

                try { $shortName = Convert-MatiToSafeString $p.Trustee.Name } catch { }
                try { $permStr   = Convert-MatiToSafeString $p.Permission } catch { }
                try { $inherited = Convert-MatiToSafeString $p.InheritedFrom } catch { }

                if (-not [string]::IsNullOrEmpty($sidValue)) {
                    $isSafe = Test-MatiIsSafePrincipal -SidValue $sidValue -SafeSidSet $safeSidSet
                }

                # On considère dangereux tout ce qui permet de modifier le GPO :
                #  - GpoEdit
                #  - GpoEditDeleteModifySecurity
                if ($permStr -match 'GpoEdit') {
                    $isDangerous = $true
                }

                $gpoAclRows += [pscustomobject][ordered]@{
                    DomainDNS        = $domainDns
                    GpoDisplayName   = Convert-MatiToSafeString $gpoDisplayName
                    GpoId            = [string]$gpoId
                    Trustee          = $sidValue
                    TrusteeShortName = $shortName
                    Permission       = $permStr
                    IsDangerous      = [bool]$isDangerous
                    IsSafePrincipal  = [bool]$isSafe
                    InheritedFrom    = $inherited
                }

                if ($isDangerous -and (-not $isSafe)) {
                    $dangerousGpoAcls += [pscustomobject]@{
                        GpoDisplayName = $gpoDisplayName
                        GpoId          = [string]$gpoId
                        Principal      = $shortName
                        Sid            = $sidValue
                        Permission     = $permStr
                    }
                }
            }
        }

        if ($dangerousGpoAcls.Count -gt 0) {
            $sample = $dangerousGpoAcls |
                Select-Object -First 5 |
                ForEach-Object { "{0} ({1}) <- {2}" -f $_.GpoDisplayName, $_.GpoId, $_.Principal }

            $detailsText = "Examples=" + ([string]::Join('; ', $sample))

            $findings += New-Finding `
                -Id 'MATI-ACL-004' `
                -Category 'ACLs' `
                -Severity 'High' `
                -Title 'GPOs grant dangerous edit rights to non-safe principals' `
                -Description ("One or more Group Policy Objects in domain {0} grant dangerous edit rights (GpoEdit/GpoEditDeleteModifySecurity) to principals that are not in the safe list. A compromise of these principals can be leveraged to push malicious settings across the environment." -f $domainDns) `
                -Remediation "Review ACLs on all critical GPOs (especially Default Domain Policy, Default Domain Controllers Policy and security hardening GPOs). Ensure only dedicated, well-controlled administrative groups have rights to edit or modify security on these GPOs." `
                -ObjectDN $domainDn `
                -Domain $domainDns `
                -Source '50-MATI-ACLsAndGPO' `
                -Details $detailsText
        }
    } # if ($gpAvailable)
} # foreach domain

# --------------------------------------------------------------------
# 7. Export CSVs
# --------------------------------------------------------------------
try {
    $adminSdCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_ACL_AdminSDHolder.csv'
    $adminSdRows |
        Sort-Object DomainDNS, ObjectDN, Trustee |
        Export-Csv -Path $adminSdCsvPath -NoTypeInformation -Encoding UTF8

    $protectedCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_ACL_ProtectedObjects.csv'
    $protectedRows |
        Sort-Object DomainDNS, ObjectDN, Trustee |
        Export-Csv -Path $protectedCsvPath -NoTypeInformation -Encoding UTF8

    $gpoCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_ACL_GPOs.csv'
    $gpoAclRows |
        Sort-Object DomainDNS, GpoDisplayName, Trustee |
        Export-Csv -Path $gpoCsvPath -NoTypeInformation -Encoding UTF8

    Write-Host ("{0} AdminSDHolder ACL CSV: {1}" -f $moduleTag, $adminSdCsvPath) -ForegroundColor Green
    Write-Host ("{0} Protected objects ACL CSV: {1}" -f $moduleTag, $protectedCsvPath) -ForegroundColor Green
    Write-Host ("{0} GPO ACL CSV: {1}" -f $moduleTag, $gpoCsvPath) -ForegroundColor Green
} catch {
    Write-Warning ("{0} Failed to export ACL CSV files: {1}" -f $moduleTag, $_.Exception.Message)
}

Write-Host "$moduleTag Module completed." -ForegroundColor Cyan

# --------------------------------------------------------------------
# 8. Retour des findings au runner
# --------------------------------------------------------------------
return ,$findings
