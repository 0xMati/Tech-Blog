#requires -Version 5.1
<#
50-MATI-ACLs.ps1
MATI – Microsoft Active Directory Threat Inspector
Module 50 – ACLs on AdminSDHolder and protected objects

Outputs:
  - CSV\MATI_AD_ACL_AdminSDHolder.csv
  - CSV\MATI_AD_ACL_ProtectedObjects.csv

Findings (exemples):
  - MATI-ACL-001 – AdminSDHolder grants dangerous rights to non-safe principal
  - MATI-ACL-002 – Protected object grants dangerous rights to non-safe principal
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$moduleTag = '[50-MATI-ACLs]'
Write-Host "$moduleTag Output root : $OutputRoot" -ForegroundColor Cyan

# --------------------------------------------------------------------
# 1. Préparation dossiers / CSV
# --------------------------------------------------------------------
$csvRoot = Join-Path -Path $OutputRoot -ChildPath 'CSV'
if (-not (Test-Path -Path $csvRoot)) {
    New-Item -Path $csvRoot -ItemType Directory | Out-Null
}

$adminSdCsvPath   = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_ACL_AdminSDHolder.csv'
$protectedCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_ACL_ProtectedObjects.csv'

# --------------------------------------------------------------------
# 2. Chargement Finding.ps1 + module AD
# --------------------------------------------------------------------
$findingLibPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Common\Finding.ps1'
if (-not (Test-Path -Path $findingLibPath)) {
    Write-Error "$moduleTag Common Finding.ps1 not found at $findingLibPath"
    return
}
. $findingLibPath

try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
}
catch {
    Write-Error ("{0} Failed to load ActiveDirectory module: {1}" -f $moduleTag, $_.Exception.Message)
    return
}

# --------------------------------------------------------------------
# 3. Helpers
# --------------------------------------------------------------------

# Liste de droits considérés "dangereux" pour objets protégés
function Test-MatiDangerousRights {
    param(
        [System.DirectoryServices.ActiveDirectoryRights]$Rights
    )

    $dangerous = @(
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::Delete,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
    )

    foreach ($d in $dangerous) {
        if (($Rights -band $d) -ne 0) {
            return $true
        }
    }
    return $false
}

# Safe-list de principals pour ACL AdminSDHolder / objets protégés
function Test-MatiSafePrincipalAcl {
    param(
        [string]$DomainDns,
        [string]$DomainNetbios,
        [string]$TrusteeShortName  # Ex: "MATHIAS\Domain Admins" ou "NT AUTHORITY\SELF"
    )

    if ([string]::IsNullOrWhiteSpace($TrusteeShortName)) {
        return $false
    }

    $name = $TrusteeShortName.Trim()

    # Tout NT AUTHORITY sauf ANONYMOUS LOGON = safe (inclut SELF)
    if ($name -like 'NT AUTHORITY\*' -and $name -ne 'NT AUTHORITY\ANONYMOUS LOGON') {
        return $true
    }

    # Everyone / Authenticated Users / Users du domaine : safe pour lecture simple
    if ($name -eq 'Everyone') { return $true }
    if ($name -eq 'NT AUTHORITY\Authenticated Users') { return $true }

    # Builtin admins & opérateurs
    $builtinSafe = @(
        'BUILTIN\Administrators',
        'BUILTIN\Account Operators',
        'BUILTIN\Backup Operators',
        'BUILTIN\Print Operators',
        'BUILTIN\Server Operators'
    )
    if ($builtinSafe -contains $name) {
        return $true
    }

    # Groupes admins du domaine (NetBIOS\Domain Admins, etc.)
    $domainPrefix = "$DomainNetbios\"
    if ($name.StartsWith($domainPrefix)) {
        $short = $name.Substring($domainPrefix.Length)

        $domainSafe = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Domain Controllers',
            'Cert Publishers'
        )

        if ($domainSafe -contains $short) {
            return $true
        }
    }

    # Par défaut : non-safe
    return $false
}

# Récupération des ACE d'un DN donné
function Get-MatiAclEntriesForDn {
    param(
        [string]$DomainDns,
        [string]$DomainNetbios,
        [string]$ObjectDn,
        [string]$ObjectType,
        [string]$SamAccountName,
        [bool]  $IsProtectedByAdminSDHolder
    )

    $results = @()

    try {
        $entry = [ADSI]("LDAP://$ObjectDn")
        $acl   = $entry.ObjectSecurity

        $rules = $acl.GetAccessRules(
            $true,   # includeExplicit
            $true,   # includeInherited
            [System.Security.Principal.SecurityIdentifier]
        )

        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference

            $trusteeName = $null
            try {
                $nt = $sid.Translate([System.Security.Principal.NTAccount])
                $trusteeName = $nt.Value
            }
            catch {
                # Si on ne peut pas traduire, on garde le SID
                $trusteeName = $sid.Value
            }

            $isSafe = Test-MatiSafePrincipalAcl `
                -DomainDns $DomainDns `
                -DomainNetbios $DomainNetbios `
                -TrusteeShortName $trusteeName

            $isDangerous = $false
            if (-not $isSafe -and (Test-MatiDangerousRights -Rights $rule.ActiveDirectoryRights)) {
                $isDangerous = $true
            }

            $results += [pscustomobject]@{
                DomainDNS                     = $DomainDns
                ObjectDN                      = $ObjectDn
                ObjectType                    = $ObjectType
                SamAccountName                = $SamAccountName
                IsProtectedByAdminSDHolder    = $IsProtectedByAdminSDHolder
                Trustee                       = $trusteeName
                TrusteeShortName              = $trusteeName
                AccessControlType             = $rule.AccessControlType.ToString()
                ActiveDirectoryRights         = $rule.ActiveDirectoryRights.ToString()
                IsInherited                   = $rule.IsInherited
                IsSafePrincipal               = $isSafe
                IsDangerousForProtectedObjects = $isDangerous
            }
        }
    }
    catch {
        Write-Warning ("{0} Failed to read ACL for {1} in {2}: {3}" -f $moduleTag, $ObjectDn, $DomainDns, $_.Exception.Message)
    }

    return ,$results
}

$allAdminSdAcl   = @()
$allProtectedAcl = @()
$findings        = @()

# --------------------------------------------------------------------
# 4. Récupération forêt / domaines
# --------------------------------------------------------------------
try {
    $forest = Get-ADForest -ErrorAction Stop
}
catch {
    Write-Error ("{0} Failed to query forest: {1}" -f $moduleTag, $_.Exception.Message)
    return
}

$domains = @()
foreach ($domName in $forest.Domains) {
    try {
        $domains += Get-ADDomain -Identity $domName -ErrorAction Stop
    }
    catch {
        Write-Warning ("{0} Failed to query domain {1}: {2}" -f $moduleTag, $domName, $_.Exception.Message)
    }
}

# --------------------------------------------------------------------
# 5. Boucle domaines : AdminSDHolder + objets protégés
# --------------------------------------------------------------------
foreach ($domain in $domains) {

    $domainDns     = $domain.DNSRoot
    $domainNetbios = $domain.NetBIOSName

    Write-Host "$moduleTag Processing domain $domainDns..." -ForegroundColor Cyan

    # ------------------------------------------------------------
    # 5.1 AdminSDHolder ACL
    # ------------------------------------------------------------
    $adminSdDn = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"

    $adminSdEntries = Get-MatiAclEntriesForDn `
        -DomainDns $domainDns `
        -DomainNetbios $domainNetbios `
        -ObjectDn $adminSdDn `
        -ObjectType 'AdminSDHolder' `
        -SamAccountName 'AdminSDHolder' `
        -IsProtectedByAdminSDHolder $true

    $allAdminSdAcl += $adminSdEntries

    # Findings sur AdminSDHolder : ACE dangereux vers non-safe principal
    foreach ($ace in $adminSdEntries | Where-Object { $_.IsDangerousForProtectedObjects -eq $true }) {
        $findings += New-Finding `
            -Id 'MATI-ACL-001' `
            -Category 'ACLs' `
            -Severity 'High' `
            -Title 'AdminSDHolder grants dangerous rights to a non-safe principal' `
            -Description ("AdminSDHolder in domain {0} grants dangerous Active Directory rights to non-safe principal {1}. This can compromise the security of all protected accounts inheriting from AdminSDHolder." -f $domainDns, $ace.TrusteeShortName) `
            -Remediation "Review the ACL on AdminSDHolder and restrict dangerous rights (GenericAll/GenericWrite/WriteDacl/WriteOwner/Delete/ExtendedRight) to a minimal set of trusted admin groups." `
            -ObjectDN $adminSdDn `
            -Domain $domainDns `
            -Source '50-MATI-ACLs' `
            -Details ("Trustee={0}; Rights={1}; AccessControlType={2}; IsInherited={3}" -f $ace.TrusteeShortName, $ace.ActiveDirectoryRights, $ace.AccessControlType, $ace.IsInherited)
    }

    # ------------------------------------------------------------
    # 5.2 Objets protégés (adminCount=1) : groupes + users
    # ------------------------------------------------------------
    $protectedGroups = @()
    $protectedUsers  = @()

    try {
        $protectedGroups = Get-ADGroup -LDAPFilter '(adminCount=1)' `
            -SearchBase $domain.DistinguishedName `
            -SearchScope Subtree `
            -Server $domainDns `
            -Properties adminCount,SamAccountName,DistinguishedName `
            -ErrorAction Stop
    }
    catch {
        Write-Warning ("{0} Failed to query protected groups in {1}: {2}" -f $moduleTag, $domainDns, $_.Exception.Message)
    }

    try {
        $protectedUsers = Get-ADUser -LDAPFilter '(adminCount=1)' `
            -SearchBase $domain.DistinguishedName `
            -SearchScope Subtree `
            -Server $domainDns `
            -Properties adminCount,SamAccountName,DistinguishedName `
            -ErrorAction Stop
    }
    catch {
        Write-Warning ("{0} Failed to query protected users in {1}: {2}" -f $moduleTag, $domainDns, $_.Exception.Message)
    }

    $allProtected = @()
    foreach ($g in $protectedGroups) {
        $allProtected += [pscustomobject]@{
            ObjectDN           = $g.DistinguishedName
            ObjectType         = 'Group'
            SamAccountName     = $g.SamAccountName
            IsProtectedByAdminSDHolder = $true
        }
    }
    foreach ($u in $protectedUsers) {
        $allProtected += [pscustomobject]@{
            ObjectDN           = $u.DistinguishedName
            ObjectType         = 'User'
            SamAccountName     = $u.SamAccountName
            IsProtectedByAdminSDHolder = $true
        }
    }

    foreach ($obj in $allProtected) {
        $entries = Get-MatiAclEntriesForDn `
            -DomainDns $domainDns `
            -DomainNetbios $domainNetbios `
            -ObjectDn $obj.ObjectDN `
            -ObjectType $obj.ObjectType `
            -SamAccountName $obj.SamAccountName `
            -IsProtectedByAdminSDHolder $obj.IsProtectedByAdminSDHolder

        $allProtectedAcl += $entries

        foreach ($ace in $entries | Where-Object { $_.IsDangerousForProtectedObjects -eq $true }) {
            $severity = 'High'
            $findings += New-Finding `
                -Id 'MATI-ACL-002' `
                -Category 'ACLs' `
                -Severity $severity `
                -Title 'Protected object grants dangerous rights to a non-safe principal' `
                -Description ("Protected object {0} ({1}) in domain {2} grants dangerous Active Directory rights to non-safe principal {3}. This may allow attackers to modify or take control of privileged accounts or groups." -f $obj.SamAccountName, $obj.ObjectType, $domainDns, $ace.TrusteeShortName) `
                -Remediation "Review the ACL of this protected object and restrict dangerous rights to a minimal set of trusted admin groups. Ensure that delegated admins are managed through controlled groups and not directly on protected objects." `
                -ObjectDN $obj.ObjectDN `
                -Domain $domainDns `
                -Source '50-MATI-ACLs' `
                -Details ("Trustee={0}; Rights={1}; AccessControlType={2}; IsInherited={3}" -f $ace.TrusteeShortName, $ace.ActiveDirectoryRights, $ace.AccessControlType, $ace.IsInherited)
        }
    }
}

# --------------------------------------------------------------------
# 6. Export CSV
# --------------------------------------------------------------------
try {
    $allAdminSdAcl |
        Sort-Object DomainDNS, TrusteeShortName, ActiveDirectoryRights |
        Export-Csv -Path $adminSdCsvPath -NoTypeInformation -Encoding UTF8

    $allProtectedAcl |
        Sort-Object DomainDNS, ObjectType, SamAccountName, TrusteeShortName |
        Export-Csv -Path $protectedCsvPath -NoTypeInformation -Encoding UTF8

    Write-Host "$moduleTag AdminSDHolder ACL CSV: $adminSdCsvPath" -ForegroundColor Green
    Write-Host "$moduleTag Protected objects ACL CSV: $protectedCsvPath" -ForegroundColor Green
}
catch {
    Write-Warning ("{0} Failed to export ACL CSV files: {1}" -f $moduleTag, $_.Exception.Message)
}

Write-Host "$moduleTag Module completed." -ForegroundColor Cyan

# Renvoie les findings au runner
return ,$findings
