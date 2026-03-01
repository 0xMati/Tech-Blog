# Modules\20-MATI-PrivilegedAccounts.ps1
#requires -Version 5.1

<#
    MATI - Microsoft Active Directory Threat Inspector
    Module 20 - Privileged Accounts

    - Can run standalone or from 00-MATI-Runner.ps1
    - Collects:
        * Privileged groups (EA, SA, DA, etc.) per domain
        * Members (direct + nested) of those groups
        * Account properties (users/computers/service accounts)
    - Exports:
        * Outputs\Output_*\CSV\MATI_AD_PrivilegedAccounts.csv
        * Outputs\Output_*\CSV\MATI_AD_PrivilegedGroups.csv
    - Adds findings to $Global:Findings:
        * MATI-ADMIN-001 : Privileged account with non-expiring password
        * MATI-ADMIN-002 : Privileged account inactive for more than 90 days
        * MATI-ADMIN-003 : Disabled account still member of privileged groups
        * MATI-ADMIN-004 : Excessive number of members in Domain Admins / Enterprise Admins
        * MATI-ADMIN-005 : Privileged account not protected by AdminSDHolder
        * MATI-ADMIN-007 : Privileged account password not changed for more than 180 days
        * MATI-ADMIN-008 : Privileged user account not in Protected Users
        * MATI-ADMIN-009 : Built-in Administrator (RID 500) account enabled
        * MATI-ADMIN-010 : Privileged group with broad membership (Domain Users / Authenticated Users / Everyone)
        * MATI-ADMIN-011 : Privileged account with SIDHistory
        * MATI-ADMIN-013 : Privileged group containing Foreign Security Principals
#>

param(
    [string]$OutputRoot
)

# --------------------------------------------------------------------
# 1. Standalone vs runner mode & centralized output folders
# --------------------------------------------------------------------

if (-not $Global:Findings) {
    $Global:Findings = @()
    $Standalone = $true
} else {
    $Standalone = $false
}

# Resolve MATI root directory (parent of Modules)
$MatiRoot    = Split-Path $PSScriptRoot -Parent
$OutputsBase = Join-Path $MatiRoot "Outputs"

New-Item -ItemType Directory -Path $OutputsBase -Force | Out-Null

# If no OutputRoot was provided (standalone), create one under .\Outputs
if (-not $OutputRoot) {
    $Date       = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputRoot = Join-Path $OutputsBase "Output_$Date"
}

$CsvDir = Join-Path $OutputRoot "CSV"

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
New-Item -ItemType Directory -Path $CsvDir     -Force | Out-Null

Write-Host "[20-MATI-PrivilegedAccounts] Output root : $OutputRoot" -ForegroundColor DarkGray

# --------------------------------------------------------------------
# 2. Load common finding model & AD module
# --------------------------------------------------------------------
$commonPath = Join-Path $MatiRoot "Common\Finding.ps1"
if (-not (Test-Path $commonPath)) {
    Write-Error "[20-MATI-PrivilegedAccounts] Common file not found: $commonPath"
    return
}

. $commonPath

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "[20-MATI-PrivilegedAccounts] ActiveDirectory module not found. Install RSAT (AD DS and LDS tools)."
    return
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error ("[20-MATI-PrivilegedAccounts] Failed to import ActiveDirectory module: {0}" -f $_.Exception.Message)
    return
}

# --------------------------------------------------------------------
# 3. Forest & domains discovery
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Collecting forest and domains..." -ForegroundColor Yellow

try {
    $forest = Get-ADForest -ErrorAction Stop
}
catch {
    Write-Error ("[20-MATI-PrivilegedAccounts] Failed to query forest: {0}" -f $_.Exception.Message)
    return
}

$domains = @()
foreach ($domainName in $forest.Domains) {
    try {
        $d = Get-ADDomain -Identity $domainName -ErrorAction Stop
        $domains += $d
    }
    catch {
        Write-Error ("[20-MATI-PrivilegedAccounts] Failed to query domain {0}: {1}" -f $domainName, $_.Exception.Message)
    }
}

if ($domains.Count -eq 0) {
    Write-Error "[20-MATI-PrivilegedAccounts] No domains found in forest."
    return
}

# --------------------------------------------------------------------
# 4. Privileged groups definitions
# --------------------------------------------------------------------
# All groups identified by sAMAccountName (works across localized ADs)

# Domain-level privileged groups
$domainPrivGroupsSam = @(
    @{ Sam = "Domain Admins";              Role = "DomainAdmins" },
    @{ Sam = "Administrators";             Role = "Administrators" },
    @{ Sam = "Account Operators";          Role = "AccountOperators" },
    @{ Sam = "Backup Operators";           Role = "BackupOperators" },
    @{ Sam = "Server Operators";           Role = "ServerOperators" },
    @{ Sam = "Print Operators";            Role = "PrintOperators" }, # Findings Low
    @{ Sam = "DnsAdmins";                  Role = "DnsAdmins" },
    @{ Sam = "Group Policy Creator Owners"; Role = "GPCreatorOwners" }
)

# Forest-level privileged groups (root domain only)
$forestPrivGroupsSam = @(
    @{ Sam = "Enterprise Admins"; Role = "EnterpriseAdmins" },
    @{ Sam = "Schema Admins";     Role = "SchemaAdmins" }
)

# Protected Users group (per domain, same sAMAccountName)
$protectedUsersSam = "Protected Users"

# Broad membership group names (potentially dangerous in privileged groups)
$broadGroupSamList = @(
    "Domain Users",
    "Authenticated Users",
    "Everyone"
)

# --------------------------------------------------------------------
# 5. Collect privileged groups and Protected Users per domain
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Resolving privileged groups..." -ForegroundColor Yellow

$privGroups            = @()  # list of all privileged groups (all domains)
$protectedUsersMembers = @{}  # hashtable of DN -> $true for Protected Users membership (all domains)

foreach ($d in $domains) {

    $domainDns = $d.DNSRoot

    # Domain-level privileged groups
    foreach ($gDef in $domainPrivGroupsSam) {
        $sam  = $gDef.Sam
        $role = $gDef.Role

        try {
            $g = Get-ADGroup -Filter ("sAMAccountName -eq '{0}'" -f $sam) -Server $domainDns -ErrorAction Stop
            $privGroups += [PSCustomObject]@{
                SamAccountName    = $g.SamAccountName
                Name              = $g.Name
                DistinguishedName = $g.DistinguishedName
                DomainDNS         = $domainDns
                Role              = $role
                Scope             = "Domain"
            }
        }
        catch {
            # Not all groups must exist in all domains
            Write-Host ("[20-MATI-PrivilegedAccounts] Group {0} not found in domain {1}" -f $sam, $domainDns) -ForegroundColor DarkGray
        }
    }

    # Protected Users group for this domain (for later check)
    try {
        $puGroup   = Get-ADGroup -Filter ("sAMAccountName -eq '{0}'" -f $protectedUsersSam) -Server $domainDns -ErrorAction Stop
        $puMembers = @(Get-ADGroupMember -Identity $puGroup.DistinguishedName -Recursive -Server $domainDns -ErrorAction SilentlyContinue)

        foreach ($m in $puMembers) {
            if ($m.DistinguishedName -and -not $protectedUsersMembers.ContainsKey($m.DistinguishedName)) {
                $protectedUsersMembers[$m.DistinguishedName] = $true
            }
        }
    }
    catch {
        Write-Host ("[20-MATI-PrivilegedAccounts] Protected Users group not found in domain {0}" -f $domainDns) -ForegroundColor DarkGray
    }
}

# Forest-level groups (root domain only)
$rootDomainDns = $forest.RootDomain
foreach ($gDef in $forestPrivGroupsSam) {
    $sam  = $gDef.Sam
    $role = $gDef.Role

    try {
        $g = Get-ADGroup -Filter ("sAMAccountName -eq '{0}'" -f $sam) -Server $rootDomainDns -ErrorAction Stop
        $privGroups += [PSCustomObject]@{
            SamAccountName    = $g.SamAccountName
            Name              = $g.Name
            DistinguishedName = $g.DistinguishedName
            DomainDNS         = $rootDomainDns
            Role              = $role
            Scope             = "Forest"
        }
    }
    catch {
        Write-Host ("[20-MATI-PrivilegedAccounts] Forest-level group {0} not found in root domain {1}" -f $sam, $rootDomainDns) -ForegroundColor DarkGray
    }
}

if ($privGroups.Count -eq 0) {
    Write-Warning "[20-MATI-PrivilegedAccounts] No privileged groups found. Nothing to do."
    return
}

# --------------------------------------------------------------------
# 6. Collect privileged accounts from groups (members direct + recursive)
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Enumerating privileged group memberships..." -ForegroundColor Yellow

# Map: DN -> account info skeleton
$accountMap = @{}   # key: DistinguishedName, value: PSCustomObject with base fields

# List: group info for CSV
$groupInfoList = @()

foreach ($g in $privGroups) {

    $domainDns = $g.DomainDNS
    $groupDn   = $g.DistinguishedName

    # Direct members (force array)
    $directMembers = @()
    try {
        $directMembers = @(Get-ADGroupMember -Identity $groupDn -Server $domainDns -ErrorAction Stop)
    }
    catch {
        Write-Warning ("[20-MATI-PrivilegedAccounts] Failed to query direct members of group {0}: {1}" -f $g.SamAccountName, $_.Exception.Message)
    }

    # Recursive members (force array)
    $allMembers = @()
    try {
        $allMembers = @(Get-ADGroupMember -Identity $groupDn -Recursive -Server $domainDns -ErrorAction Stop)
    }
    catch {
        Write-Warning ("[20-MATI-PrivilegedAccounts] Failed to query recursive members of group {0}: {1}" -f $g.SamAccountName, $_.Exception.Message)
    }

    # Analyse broad membership & foreign security principals
    $broadMembersSam = @()
    $hasFsp          = $false
    $fspCount        = 0

    foreach ($m in $allMembers) {
        if (-not $m) { continue }

        if ($m.ObjectClass -eq "group") {
            if ($m.SamAccountName -and $broadGroupSamList -contains $m.SamAccountName) {
                if ($broadMembersSam -notcontains $m.SamAccountName) {
                    $broadMembersSam += $m.SamAccountName
                }
            }
        }
        elseif ($m.ObjectClass -eq "foreignSecurityPrincipal") {
            $hasFsp = $true
            $fspCount++
        }
    }

    $groupInfoList += [PSCustomObject]@{
        GroupName                    = $g.Name
        SamAccountName               = $g.SamAccountName
        DistinguishedName            = $g.DistinguishedName
        DomainDNS                    = $g.DomainDNS
        Role                         = $g.Role
        Scope                        = $g.Scope
        MemberCountDirect            = $directMembers.Count
        MemberCountRecursive         = $allMembers.Count
        HasBroadMembership           = ($broadMembersSam.Count -gt 0)
        BroadMembersSam              = $broadMembersSam -join ";"
        HasForeignSecurityPrincipals = $hasFsp
        ForeignSecurityPrincipalsCount = $fspCount
    }

    foreach ($m in $allMembers) {
        if (-not $m -or -not $m.DistinguishedName) { continue }

        if (-not $accountMap.ContainsKey($m.DistinguishedName)) {
            # Extract domain DNS from DN (DC=... parts at the end)
            $dn       = $m.DistinguishedName
            $rdnParts = $dn -split ","
            $dcParts  = @()
            foreach ($p in $rdnParts) {
                if ($p -like "DC=*") {
                    $dcParts += ($p.Substring(3))
                }
            }
            $acctDomainDns = $dcParts -join "."

            $accountMap[$m.DistinguishedName] = [PSCustomObject]@{
                DistinguishedName        = $m.DistinguishedName
                DomainDNS                = $acctDomainDns
                ObjectClass              = $m.ObjectClass
                SamAccountName           = $null
                UserPrincipalName        = $null
                Enabled                  = $null
                PasswordNeverExpires     = $null
                AdminCount               = $null
                IsProtected              = $false
                IsRid500                 = $false
                PasswordLastSet          = $null
                PasswordLastSetDays      = $null
                LastLogonDate            = $null
                LastLogonDays            = $null
                MemberOfPrivilegedGroups = @()
                IsMemberOfDA             = $false
                IsMemberOfEA             = $false
                IsInProtectedUsers       = $false
                HasSIDHistory            = $false
                SIDHistoryCount          = $null
                AccountType              = $null
            }
        }

        $entry = $accountMap[$m.DistinguishedName]

        # Track membership of each privileged group (by SamAccountName)
        if ($entry.MemberOfPrivilegedGroups -notcontains $g.SamAccountName) {
            $entry.MemberOfPrivilegedGroups += $g.SamAccountName
        }

        # Flags for DA/EA membership (recursive)
        if ($g.Role -eq "DomainAdmins") {
            $entry.IsMemberOfDA = $true
        }
        if ($g.Role -eq "EnterpriseAdmins") {
            $entry.IsMemberOfEA = $true
        }
    }
}

if ($accountMap.Count -eq 0) {
    Write-Host "[20-MATI-PrivilegedAccounts] No privileged accounts found." -ForegroundColor Cyan
}

# --------------------------------------------------------------------
# 7. Enrich accounts with AD properties
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Enriching privileged accounts with AD attributes..." -ForegroundColor Yellow

$now                      = Get-Date
$inactiveThresholdDays    = 90   # for MATI-ADMIN-002
$oldPasswordThresholdDays = 180  # for MATI-ADMIN-007

$privAccounts = @()

foreach ($key in $accountMap.Keys) {
    $entry = $accountMap[$key]

    $dn   = $entry.DistinguishedName
    $ocl  = $entry.ObjectClass
    $acct = $null

    try {
        if ($ocl -eq "user") {
            $acct = Get-ADUser -Identity $dn -Server $entry.DomainDNS -Properties SamAccountName,UserPrincipalName,Enabled,PasswordNeverExpires,AdminCount,PasswordLastSet,LastLogonDate,objectSid,SIDHistory -ErrorAction Stop
            $entry.AccountType = "User"
        }
        elseif ($ocl -eq "computer") {
            $acct = Get-ADComputer -Identity $dn -Server $entry.DomainDNS -Properties SamAccountName,UserPrincipalName,Enabled,PasswordNeverExpires,AdminCount,PasswordLastSet,LastLogonDate,objectSid,SIDHistory -ErrorAction Stop
            $entry.AccountType = "Computer"
        }
        elseif ($ocl -like "*ServiceAccount*") {
            try {
                $acct = Get-ADServiceAccount -Identity $dn -Server $entry.DomainDNS -Properties SamAccountName,UserPrincipalName,Enabled,PasswordNeverExpires,AdminCount,PasswordLastSet,LastLogonDate,objectSid,SIDHistory -ErrorAction Stop
                $entry.AccountType = "ServiceAccount"
            }
            catch {
                # Fallback: generic ADObject
                $acct = Get-ADObject -Identity $dn -Server $entry.DomainDNS -Properties SamAccountName,UserPrincipalName,AdminCount,objectSid,SIDHistory -ErrorAction Stop
                $entry.AccountType = "Other"
            }
        }
        else {
            # Generic object (group, contact, foreign security principal, ...)
            $acct = Get-ADObject -Identity $dn -Server $entry.DomainDNS -Properties SamAccountName,UserPrincipalName,AdminCount,objectSid,SIDHistory -ErrorAction Stop
            $entry.AccountType = "Other"
        }
    }
    catch {
        Write-Warning ("[20-MATI-PrivilegedAccounts] Failed to read account {0}: {1}" -f $dn, $_.Exception.Message)
        continue
    }

    if ($acct -eq $null) { continue }

    $entry.SamAccountName    = $acct.SamAccountName
    $entry.UserPrincipalName = $acct.UserPrincipalName

    if ($acct.PSObject.Properties.Match("Enabled").Count -gt 0) {
        $entry.Enabled = $acct.Enabled
    }

    if ($acct.PSObject.Properties.Match("PasswordNeverExpires").Count -gt 0) {
        $entry.PasswordNeverExpires = [bool]$acct.PasswordNeverExpires
    }

    if ($acct.PSObject.Properties.Match("AdminCount").Count -gt 0) {
        $entry.AdminCount = $acct.AdminCount
        if ($entry.AdminCount -gt 0) {
            $entry.IsProtected = $true
        }
    }

    # SID / RID 500 detection (built-in Administrator)
    if ($acct.PSObject.Properties.Match("objectSid").Count -gt 0 -and $acct.objectSid) {
        # objectSid is already a SecurityIdentifier; use its Value
        $sidStr = $acct.objectSid.Value
        if ($sidStr -match "-500$") {
            $entry.IsRid500 = $true
        }
    }

    # SIDHistory presence
    if ($acct.PSObject.Properties.Match("SIDHistory").Count -gt 0 -and $acct.SIDHistory) {
        # SIDHistory can be a single SID or a collection
        $sidHistValues = @($acct.SIDHistory)
        $entry.HasSIDHistory   = ($sidHistValues.Count -gt 0)
        $entry.SIDHistoryCount = $sidHistValues.Count
    }

    # PasswordLastSet / PasswordLastSetDays
    if ($acct.PSObject.Properties.Match("PasswordLastSet").Count -gt 0 -and $acct.PasswordLastSet) {
        $pls = $acct.PasswordLastSet
        $entry.PasswordLastSet      = $pls
        $entry.PasswordLastSetDays  = [int]([Math]::Round(($now - $pls).TotalDays, 0))
    }

    # LastLogonDate / LastLogonDays
    if ($acct.PSObject.Properties.Match("LastLogonDate").Count -gt 0 -and $acct.LastLogonDate) {
        $lld = $acct.LastLogonDate
        $entry.LastLogonDate = $lld
        $entry.LastLogonDays = [int]([Math]::Round(($now - $lld).TotalDays, 0))
    }

    # Protected Users membership (user only)
    if ($entry.ObjectClass -eq "user") {
        if ($protectedUsersMembers.ContainsKey($entry.DistinguishedName)) {
            $entry.IsInProtectedUsers = $true
        }
    }

    $privAccounts += $entry
}

# --------------------------------------------------------------------
# 8. Export CSVs (accounts + groups)
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Exporting CSV files..." -ForegroundColor Yellow

# Accounts CSV
$accountsCsvPath = Join-Path $CsvDir "MATI_AD_PrivilegedAccounts.csv"
$privAccounts |
    Sort-Object DomainDNS, SamAccountName |
    Select-Object `
        SamAccountName,
        UserPrincipalName,
        DistinguishedName,
        ObjectClass,
        AccountType,
        DomainDNS,
        Enabled,
        PasswordNeverExpires,
        AdminCount,
        IsProtected,
        IsRid500,
        HasSIDHistory,
        SIDHistoryCount,
        PasswordLastSet,
        PasswordLastSetDays,
        LastLogonDate,
        LastLogonDays,
        IsMemberOfDA,
        IsMemberOfEA,
        IsInProtectedUsers,
        @{ Name = "MemberOfPrivilegedGroups"; Expression = { $_.MemberOfPrivilegedGroups -join ";" } } |
    Export-Csv -Path $accountsCsvPath -NoTypeInformation -Encoding UTF8

Write-Host "[20-MATI-PrivilegedAccounts] Privileged accounts CSV: $accountsCsvPath" -ForegroundColor Green

# Groups CSV
$groupsCsvPath = Join-Path $CsvDir "MATI_AD_PrivilegedGroups.csv"
$groupInfoList |
    Sort-Object DomainDNS, Role, SamAccountName |
    Export-Csv -Path $groupsCsvPath -NoTypeInformation -Encoding UTF8

Write-Host "[20-MATI-PrivilegedAccounts] Privileged groups CSV: $groupsCsvPath" -ForegroundColor Green

# --------------------------------------------------------------------
# 9. Generate findings (MATI-ADMIN-xxx)
# --------------------------------------------------------------------
Write-Host "[20-MATI-PrivilegedAccounts] Generating findings..." -ForegroundColor Yellow

# 9.1 Non-expiring passwords on privileged accounts (enabled OR disabled)
foreach ($acc in $privAccounts) {
    if ($acc.PasswordNeverExpires) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-001" `
            -Category "PrivilegedAccounts" `
            -Severity "High" `
            -Title "Privileged account with non-expiring password" `
            -Description ("Privileged account {0} in domain {1} has a non-expiring password." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Avoid non-expiring passwords on privileged accounts. Enforce password rotation or migrate to managed service accounts or JIT/PAM mechanisms where appropriate." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; Enabled={2}; PasswordNeverExpires=True; MemberOf={3}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.Enabled, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.2 Privileged accounts inactive for more than 90 days (enabled only)
foreach ($acc in $privAccounts) {
    if ($acc.Enabled -eq $true -and $acc.LastLogonDays -ne $null -and $acc.LastLogonDays -gt $inactiveThresholdDays) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-002" `
            -Category "PrivilegedAccounts" `
            -Severity "Medium" `
            -Title "Privileged account inactive for more than 90 days" `
            -Description ("Privileged account {0} in domain {1} has not logged on for {2} days." -f $acc.SamAccountName, $acc.DomainDNS, $acc.LastLogonDays) `
            -Remediation "Review this account with its owner or the security team. Disable or remove unused privileged accounts, or convert them to non-privileged accounts if they are still needed." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; Enabled={2}; LastLogonDays={3}; MemberOf={4}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.Enabled, $acc.LastLogonDays, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.3 Disabled accounts still member of privileged groups
foreach ($acc in $privAccounts) {
    if ($acc.Enabled -eq $false) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-003" `
            -Category "PrivilegedAccounts" `
            -Severity "Low" `
            -Title "Disabled account still member of privileged groups" `
            -Description ("Disabled account {0} in domain {1} is still a member of privileged groups." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Review whether this account should be removed from privileged groups or deleted if it is no longer needed." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; MemberOf={2}" -f $acc.SamAccountName, $acc.DomainDNS, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.4 Excessive members in Domain Admins / Enterprise Admins
foreach ($g in $groupInfoList) {

    $severity  = $null
    $threshold = $null
    $title     = $null

    if ($g.Role -eq "DomainAdmins") {
        $threshold = 5
        if ($g.MemberCountRecursive -gt $threshold) {
            $severity = "High"
            $title    = "Excessive number of members in Domain Admins"
        }
    }
    elseif ($g.Role -eq "EnterpriseAdmins") {
        $threshold = 3
        if ($g.MemberCountRecursive -gt $threshold) {
            $severity = "High"
            $title    = "Excessive number of members in Enterprise Admins"
        }
    }

    if ($severity -and $title) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-004" `
            -Category "PrivilegedAccounts" `
            -Severity $severity `
            -Title $title `
            -Description ("Group {0} in domain {1} has {2} recursive members, which is higher than commonly recommended ({3})." -f $g.SamAccountName, $g.DomainDNS, $g.MemberCountRecursive, $threshold) `
            -Remediation "Reduce the number of highly privileged accounts. Introduce tiering, JIT elevation, and strict governance for Domain Admins and Enterprise Admins membership." `
            -ObjectDN $g.DistinguishedName `
            -Domain $g.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("Group={0}; DomainDNS={1}; MemberCountRecursive={2}; Threshold={3}" -f $g.SamAccountName, $g.DomainDNS, $g.MemberCountRecursive, $threshold)
    }
}

# 9.5 Privileged account not protected by AdminSDHolder (AdminCount = 0)
foreach ($acc in $privAccounts) {
    if ($acc.AdminCount -eq 0 -and ($acc.IsMemberOfDA -or $acc.IsMemberOfEA)) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-005" `
            -Category "PrivilegedAccounts" `
            -Severity "Medium" `
            -Title "Privileged account not protected by AdminSDHolder" `
            -Description ("Privileged account {0} in domain {1} is a member of high-privilege groups but is not marked as protected by AdminSDHolder (AdminCount=0)." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Review your use of AdminSDHolder and ensure that highly privileged accounts are either protected by AdminSDHolder or managed through clearly defined and audited delegation models." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; AdminCount={2}; IsMemberOfDA={3}; IsMemberOfEA={4}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.AdminCount, $acc.IsMemberOfDA, $acc.IsMemberOfEA)
    }
}

# 9.6 Privileged account password not changed for more than 180 days
foreach ($acc in $privAccounts) {
    if ($acc.PasswordLastSetDays -ne $null -and $acc.PasswordLastSetDays -gt $oldPasswordThresholdDays) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-007" `
            -Category "PrivilegedAccounts" `
            -Severity "Medium" `
            -Title "Privileged account password not changed for more than 180 days" `
            -Description ("Privileged account {0} in domain {1} has not changed its password for {2} days." -f $acc.SamAccountName, $acc.DomainDNS, $acc.PasswordLastSetDays) `
            -Remediation "Review the password rotation policy for this account and enforce more frequent password changes for privileged identities." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; PasswordLastSetDays={2}; MemberOf={3}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.PasswordLastSetDays, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.7 Privileged user account not in Protected Users (Low)
foreach ($acc in $privAccounts) {
    if ($acc.ObjectClass -eq "user" -and $acc.Enabled -eq $true -and -not $acc.IsInProtectedUsers) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-008" `
            -Category "PrivilegedAccounts" `
            -Severity "Low" `
            -Title "Privileged user account not in Protected Users" `
            -Description ("Privileged user account {0} in domain {1} is not a member of the Protected Users group." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Evaluate whether this privileged user account can be added to the Protected Users group to benefit from stronger protections (no NTLM, no DES/RC4, no delegation, etc.)." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; Enabled={2}; IsInProtectedUsers={3}; MemberOf={4}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.Enabled, $acc.IsInProtectedUsers, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.8 Built-in Administrator (RID 500) account enabled
foreach ($acc in $privAccounts) {
    if ($acc.IsRid500 -and $acc.Enabled -eq $true) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-009" `
            -Category "PrivilegedAccounts" `
            -Severity "High" `
            -Title "Built-in Administrator (RID 500) account enabled" `
            -Description ("The built-in Administrator account (RID 500) {0} in domain {1} is enabled and has privileged group memberships." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Consider disabling or strictly restricting the use of the built-in Administrator account, and replace it with named administrative accounts governed by strong authentication and audit policies." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; IsRid500=True; Enabled={2}; MemberOf={3}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.Enabled, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.9 Privileged group with broad membership (Domain Users / Authenticated Users / Everyone)
foreach ($g in $groupInfoList) {
    if ($g.HasBroadMembership) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-010" `
            -Category "PrivilegedAccounts" `
            -Severity "High" `
            -Title "Privileged group with broad membership" `
            -Description ("Privileged group {0} in domain {1} includes broad membership groups ({2}), which can dramatically increase the blast radius of a compromise." -f $g.SamAccountName, $g.DomainDNS, $g.BroadMembersSam) `
            -Remediation "Remove broad groups such as Domain Users, Authenticated Users, or similar from highly privileged groups. Restrict membership to a small, named set of administrative identities, ideally managed through JIT/PAM." `
            -ObjectDN $g.DistinguishedName `
            -Domain $g.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("Group={0}; DomainDNS={1}; BroadMembers={2}" -f $g.SamAccountName, $g.DomainDNS, $g.BroadMembersSam)
    }
}

# 9.10 Privileged account with SIDHistory
foreach ($acc in $privAccounts) {
    if ($acc.HasSIDHistory -and ($acc.IsMemberOfDA -or $acc.IsMemberOfEA -or ($acc.MemberOfPrivilegedGroups -and $acc.MemberOfPrivilegedGroups.Count -gt 0))) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-011" `
            -Category "PrivilegedAccounts" `
            -Severity "High" `
            -Title "Privileged account with SIDHistory" `
            -Description ("Privileged account {0} in domain {1} has one or more SIDHistory values, which can be abused for stealthy privilege escalation across legacy domains or trusts." -f $acc.SamAccountName, $acc.DomainDNS) `
            -Remediation "Review the origin of SIDHistory on this account, remove stale values and ensure that SIDHistory is only used under strict governance and for clearly documented migration scenarios." `
            -ObjectDN $acc.DistinguishedName `
            -Domain $acc.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("SamAccountName={0}; DomainDNS={1}; SIDHistoryCount={2}; MemberOf={3}" -f $acc.SamAccountName, $acc.DomainDNS, $acc.SIDHistoryCount, ($acc.MemberOfPrivilegedGroups -join ","))
    }
}

# 9.11 Privileged group containing Foreign Security Principals
foreach ($g in $groupInfoList) {
    if ($g.HasForeignSecurityPrincipals) {
        $Global:Findings += New-Finding `
            -Id "MATI-ADMIN-013" `
            -Category "PrivilegedAccounts" `
            -Severity "High" `
            -Title "Privileged group containing Foreign Security Principals" `
            -Description ("Privileged group {0} in domain {1} contains one or more foreignSecurityPrincipal objects, indicating that external or cross-forest identities may hold privileged access." -f $g.SamAccountName, $g.DomainDNS) `
            -Remediation "Review the foreign security principals in this group, validate the necessity of cross-forest or external privileged access, and remove or restrict them where possible." `
            -ObjectDN $g.DistinguishedName `
            -Domain $g.DomainDNS `
            -Source "20-MATI-PrivilegedAccounts" `
            -Details ("Group={0}; DomainDNS={1}; ForeignSecurityPrincipalsCount={2}" -f $g.SamAccountName, $g.DomainDNS, $g.ForeignSecurityPrincipalsCount)
    }
}

Write-Host "[20-MATI-PrivilegedAccounts] Module completed." -ForegroundColor Cyan
