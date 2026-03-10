# Collectors\Get-MATISecurityConfig.ps1
# MATIv2 - Collects AD security hardening configuration.

function Get-MATISecurityConfig {
    <#
    .SYNOPSIS
        Collects various AD security settings: dsHeuristics, Pre-Windows 2000
        group, MachineAccountQuota, Guest, Protected Users, SYSVOL replication,
        Kerberos armoring, DES accounts, operator groups, etc.
    .OUTPUTS
        [hashtable] with multiple keys for each config area.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest  = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    $domCache = $Config['_DomainCache'] ?? @{}

    # ---- dsHeuristics ----
    $dsHeuristics = $null
    try {
        $dsService = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)" `
            -Properties dSHeuristics -ErrorAction Stop
        $dsHeuristics = $dsService.dSHeuristics
    } catch {
        Write-Warning "    Cannot read dsHeuristics: $($_.Exception.Message)"
    }

    # ---- DenyUnauthenticatedBind (msDS-Other-Settings on Directory Service object) ----
    $denyUnauthBind = $null
    try {
        $dsOtherSettings = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDSE.configurationNamingContext)" `
            -Properties 'msDS-Other-Settings' -ErrorAction Stop
        $otherSettings = @($dsOtherSettings.'msDS-Other-Settings')
        $entry = $otherSettings | Where-Object { $_ -like 'DenyUnauthenticatedBind=*' } | Select-Object -First 1
        if ($entry) {
            $parts = $entry -split '=', 2
            $denyUnauthBind = if ($parts.Length -ge 2) { $parts[1] } else { $null }
        }
    } catch {
        Write-Warning "    Cannot read msDS-Other-Settings: $($_.Exception.Message)"
    }

    # ---- MachineAccountQuota per domain ----
    $machineAccountQuotas = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $domObj = Get-ADObject $domainDN -Server $domainDns -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
            $machineAccountQuotas += [PSCustomObject]@{
                Domain = $domainDns
                MachineAccountQuota = $domObj.'ms-DS-MachineAccountQuota'
            }
        } catch {
            Write-Warning "    Cannot read MachineAccountQuota for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Pre-Windows 2000 Compatible Access group ----
    $preWin2000Members = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $members = Get-ADGroupMember -Identity 'S-1-5-32-554' -Server $domainDns -ErrorAction Stop
            foreach ($m in $members) {
                $preWin2000Members += [PSCustomObject]@{
                    Domain          = $domainDns
                    MemberName      = $m.Name
                    MemberSID       = $m.SID.Value
                    ObjectClass     = $m.objectClass
                    DistinguishedName = $m.DistinguishedName
                    # S-1-1-0 = Everyone, S-1-5-7 = Anonymous Logon, S-1-5-11 = Authenticated Users
                    IsDangerous     = ($m.SID.Value -in @('S-1-1-0', 'S-1-5-7', 'S-1-5-11'))
                }
            }
        } catch {
            # Group may not exist or may be empty
            Write-Verbose "    Pre-Win2000 group not found or empty for $domainDns"
        }
    }

    # ---- Guest account per domain ----
    $guestAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
            $guest = Get-ADUser -Identity "$domSID-501" -Server $domainDns -Properties Enabled, PasswordLastSet, LastLogonTimestamp -ErrorAction Stop
            $guestAccounts += [PSCustomObject]@{
                Domain           = $domainDns
                SamAccountName   = $guest.SamAccountName
                Enabled          = $guest.Enabled
                PasswordLastSet  = $guest.PasswordLastSet
                SID              = $guest.SID.Value
            }
        } catch { }
    }

    # ---- Protected Users group membership ----
    $protectedUsersInfo = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
            $members = @()
            try {
                $members = @(Get-ADGroupMember -Identity "$domSID-525" -Server $domainDns -ErrorAction Stop)
            } catch { }

            $protectedUsersInfo += [PSCustomObject]@{
                Domain      = $domainDns
                MemberCount = $members.Count
                Members     = @($members | ForEach-Object { $_.DistinguishedName })
            }
        } catch { }
    }

    # ---- Operator groups (should be empty) ----
    $operatorGroups = @()
    $operatorRIDs = @{
        'Account Operators' = 'S-1-5-32-548'
        'Server Operators'  = 'S-1-5-32-549'
        'Print Operators'   = 'S-1-5-32-550'
        'Backup Operators'  = 'S-1-5-32-551'
    }
    foreach ($domainDns in $forest.Domains) {
        foreach ($groupName in $operatorRIDs.Keys) {
            try {
                $members = @(Get-ADGroupMember -Identity $operatorRIDs[$groupName] -Server $domainDns -ErrorAction Stop)
                $operatorGroups += [PSCustomObject]@{
                    GroupName   = $groupName
                    GroupSID    = $operatorRIDs[$groupName]
                    Domain      = $domainDns
                    MemberCount = $members.Count
                    Members     = @($members | ForEach-Object { $_.SamAccountName })
                }
            } catch { }
        }
    }

    # ---- SYSVOL replication method (NTFRS vs DFSR) ----
    $sysvolReplication = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            # Check for DFSR migration state
            $dfsrDN = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,$domainDN"
            $dfsrObj = Get-ADObject -Identity $dfsrDN -Server $domainDns -Properties 'msDFSR-Flags' -ErrorAction SilentlyContinue
            if ($dfsrObj) {
                $sysvolReplication += [PSCustomObject]@{
                    Domain     = $domainDns
                    Method     = 'DFSR'
                    DFSRFlags  = $dfsrObj.'msDFSR-Flags'
                }
            } else {
                $sysvolReplication += [PSCustomObject]@{
                    Domain     = $domainDns
                    Method     = 'NTFRS'
                    DFSRFlags  = $null
                }
            }
        } catch {
            $sysvolReplication += [PSCustomObject]@{
                Domain     = $domainDns
                Method     = 'Unknown'
                DFSRFlags  = $null
            }
        }
    }

    # ---- Accounts with DES encryption enabled ----
    $desAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            # UAC flag USE_DES_KEY_ONLY = 0x200000
            $desUsers = Get-ADUser -Filter { UserAccountControl -band 0x200000 } `
                -Server $domainDns -Properties SamAccountName, Enabled, UserAccountControl -ErrorAction Stop
            foreach ($u in $desUsers) {
                $desAccounts += [PSCustomObject]@{
                    SamAccountName = $u.SamAccountName
                    Domain         = $domainDns
                    Enabled        = $u.Enabled
                    ObjectClass    = 'user'
                    DistinguishedName = $u.DistinguishedName
                }
            }
        } catch { }
    }

    # ---- Accounts with PASSWORD_NOT_REQUIRED ----
    $pwdNotReqAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $users = Get-ADUser -Filter { PasswordNotRequired -eq $true } `
                -Server $domainDns -Properties SamAccountName, Enabled, PasswordNotRequired, UserAccountControl -ErrorAction Stop
            foreach ($u in $users) {
                if (-not $u.Enabled) { continue }
                # Skip interdomain trust accounts (UAC flag 0x800) — PASSWD_NOTREQD is expected on them
                if ($u.UserAccountControl -band 0x800) { continue }
                $pwdNotReqAccounts += [PSCustomObject]@{
                    SamAccountName    = $u.SamAccountName
                    Domain            = $domainDns
                    Enabled           = $u.Enabled
                    DistinguishedName = $u.DistinguishedName
                }
            }
        } catch { }
    }

    # ---- Kerberos Armoring ----
    $kerberosArmoring = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $domFuncLevel = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainMode
            $kerberosArmoring += [PSCustomObject]@{
                Domain              = $domainDns
                DomainFunctionalLevel = [int]$domFuncLevel
                # Kerberos Armoring requires functional level >= 2012 (6)
                ArmoringPossible    = ([int]$domFuncLevel -ge 6)
            }
        } catch { }
    }

    # ---- Print Spooler / WebClient on DCs (best effort, may fail without remote access) ----
    $dcServices = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $dcs = Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop
            foreach ($dc in $dcs) {
                $spoolerStatus = 'Unknown'
                $webClientStatus = 'Unknown'
                try {
                    $svc = Get-Service -Name 'Spooler' -ComputerName $dc.HostName -ErrorAction Stop
                    $spoolerStatus = $svc.Status.ToString()
                } catch { }
                try {
                    $svc = Get-Service -Name 'WebClient' -ComputerName $dc.HostName -ErrorAction Stop
                    $webClientStatus = $svc.Status.ToString()
                } catch { }

                $dcServices += [PSCustomObject]@{
                    DCName         = $dc.Name
                    HostName       = $dc.HostName
                    Domain         = $domainDns
                    SpoolerStatus  = $spoolerStatus
                    WebClientStatus = $webClientStatus
                }
            }
        } catch { }
    }

    # ---- Unprotected OUs (not protected from accidental deletion) ----
    $unprotectedOUs = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $ous = Get-ADOrganizationalUnit -Filter * -Server $domainDns -Properties ProtectedFromAccidentalDeletion -ErrorAction Stop
            foreach ($ou in $ous) {
                if (-not $ou.ProtectedFromAccidentalDeletion) {
                    $unprotectedOUs += [PSCustomObject]@{
                        Name              = $ou.Name
                        DistinguishedName = $ou.DistinguishedName
                        Domain            = $domainDns
                    }
                }
            }
        } catch { }
    }

    # ---- Admin accounts that can be delegated ----
    $delegatableAdmins = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
            # Get Domain Admins + Enterprise Admins
            foreach ($groupSID in @("$domSID-512", "$domSID-519")) {
                try {
                    $members = @(Get-ADGroupMember -Identity $groupSID -Server $domainDns -Recursive -ErrorAction Stop)
                    foreach ($m in $members) {
                        if ($m.objectClass -ne 'user') { continue }
                        try {
                            $user = Get-ADUser -Identity $m.DistinguishedName -Server $domainDns `
                                -Properties AccountNotDelegated, Enabled -ErrorAction Stop
                            if ($user.Enabled -and -not $user.AccountNotDelegated) {
                                $delegatableAdmins += [PSCustomObject]@{
                                    SamAccountName      = $user.SamAccountName
                                    Domain              = $domainDns
                                    DistinguishedName   = $user.DistinguishedName
                                    AccountNotDelegated = $false
                                }
                            }
                        } catch { }
                    }
                } catch { }
            }
        } catch { }
    }

    # ---- LAPS deployment (legacy ms-Mcs-AdmPwd and Windows LAPS ms-LAPS-Password) ----
    $lapsInfo = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName

            # Check if LAPS schema attributes exist
            $hasLegacyLaps = $false
            $hasWindowsLaps = $false
            try {
                $null = Get-ADObject "CN=ms-Mcs-AdmPwd,$($rootDSE.schemaNamingContext)" -ErrorAction Stop
                $hasLegacyLaps = $true
            } catch { }
            try {
                $null = Get-ADObject "CN=ms-LAPS-Password,$($rootDSE.schemaNamingContext)" -ErrorAction Stop
                $hasWindowsLaps = $true
            } catch { }

            # Count computers with and without LAPS
            $totalComputers = 0
            $lapsLegacyCount = 0
            $lapsWindowsCount = 0
            $noLapsComputers = [System.Collections.Generic.List[PSCustomObject]]::new()

            $computers = Get-ADComputer -Filter { Enabled -eq $true } -Server $domainDns `
                -Properties 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'msLAPS-Password', 'msLAPS-PasswordExpirationTime', OperatingSystem `
                -ErrorAction Stop

            foreach ($comp in $computers) {
                # Skip DCs
                if ($comp.DistinguishedName -match 'OU=Domain Controllers') { continue }
                # Skip servers without workstation OS (optional)
                $totalComputers++

                $hasLegacy = $null -ne $comp.'ms-Mcs-AdmPwdExpirationTime' -and $comp.'ms-Mcs-AdmPwdExpirationTime' -ne 0
                $hasWindows = $null -ne $comp.'msLAPS-PasswordExpirationTime'

                if ($hasLegacy) { $lapsLegacyCount++ }
                elseif ($hasWindows) { $lapsWindowsCount++ }
                else {
                    $noLapsComputers.Add([PSCustomObject]@{
                        SamAccountName    = $comp.SamAccountName
                        DistinguishedName = $comp.DistinguishedName
                        OperatingSystem   = $comp.OperatingSystem
                    })
                }
            }

            $lapsInfo += [PSCustomObject]@{
                Domain              = $domainDns
                HasLegacyLapsSchema = $hasLegacyLaps
                HasWindowsLapsSchema= $hasWindowsLaps
                TotalComputers      = $totalComputers
                LapsLegacyCount     = $lapsLegacyCount
                LapsWindowsCount    = $lapsWindowsCount
                NoLapsCount         = $noLapsComputers.Count
                NoLapsComputers     = @($noLapsComputers)
                CoveragePercent     = if ($totalComputers -gt 0) {
                    [math]::Round(($lapsLegacyCount + $lapsWindowsCount) / $totalComputers * 100, 1)
                } else { 100 }
            }
        } catch {
            Write-Warning "    Cannot check LAPS for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- AdminCount orphans (AdminCount=1 but not in any privileged group) ----
    $adminCountOrphans = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domSID = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID.Value
            # Get actual privileged members (recursive)
            $actualPrivDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($rid in @('512', '519', '518', '544', '548', '549', '550', '551')) {
                $grpSID = if ($rid -match '^\d{3}$' -and [int]$rid -lt 600) { "S-1-5-32-$rid" } else { "$domSID-$rid" }
                # Domain Admins=512, Enterprise Admins=519, Schema Admins=518
                if ($rid -in @('512', '519', '518')) { $grpSID = "$domSID-$rid" }
                # Builtin groups
                if ($rid -in @('544', '548', '549', '550', '551')) { $grpSID = "S-1-5-32-$rid" }
                try {
                    $members = @(Get-ADGroupMember -Identity $grpSID -Server $domainDns -Recursive -ErrorAction SilentlyContinue)
                    foreach ($m in $members) { $null = $actualPrivDNs.Add($m.DistinguishedName) }
                } catch { }
            }

            # Find users with AdminCount=1 who are NOT in any privileged group
            $adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } `
                -Server $domainDns -Properties AdminCount, SamAccountName -ErrorAction Stop
            foreach ($u in $adminCountUsers) {
                if ($u.SamAccountName -eq 'krbtgt') { continue }
                if (-not $actualPrivDNs.Contains($u.DistinguishedName)) {
                    $adminCountOrphans += [PSCustomObject]@{
                        SamAccountName    = $u.SamAccountName
                        DistinguishedName = $u.DistinguishedName
                        Domain            = $domainDns
                    }
                }
            }
        } catch {
            Write-Warning "    Cannot check AdminCount orphans for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- PwdNeverExpires on non-privileged accounts ----
    $pwdNeverExpiresAll = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $users = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
                -Server $domainDns -Properties SamAccountName, AdminCount, PasswordLastSet -ErrorAction Stop
            foreach ($u in $users) {
                $pwdNeverExpiresAll += [PSCustomObject]@{
                    SamAccountName    = $u.SamAccountName
                    DistinguishedName = $u.DistinguishedName
                    Domain            = $domainDns
                    AdminCount        = $u.AdminCount
                    PasswordLastSet   = $u.PasswordLastSet
                }
            }
        } catch { }
    }

    # ---- SCRIL (Smart Card Required for Interactive Logon) password rotation ----
    $scrilRotation = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainObj = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop))
            $domainDN  = $domainObj.DistinguishedName
            # Read msDS-ExpirePasswordsOnSmartCardOnlyAccounts from domain object
            $domAD = Get-ADObject $domainDN -Server $domainDns `
                -Properties 'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' -ErrorAction Stop
            $expireSC = $domAD.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'

            # Count SCRIL accounts (SmartcardLogonRequired = 0x40000 in UAC)
            $scrilCount = 0
            try {
                $scrilCount = @(Get-ADUser -Filter { SmartcardLogonRequired -eq $true -and Enabled -eq $true } `
                    -Server $domainDns -ErrorAction Stop).Count
            } catch { }

            $scrilRotation += [PSCustomObject]@{
                Domain                  = $domainDns
                DomainDN                = $domainDN
                ExpirePasswordsOnSCOnly = $expireSC
                SCRILAccountCount       = $scrilCount
            }
        } catch {
            Write-Warning "    Cannot check SCRIL rotation for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Group Managed Service Accounts (gMSA) ----
    $gmsaAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $gmsas = Get-ADServiceAccount -Filter * -Server $domainDns `
                -Properties PrincipalsAllowedToRetrieveManagedPassword, msDS-ManagedPasswordInterval, `
                            Enabled, SamAccountName, DistinguishedName, WhenCreated, Description `
                -ErrorAction Stop
            foreach ($gmsa in $gmsas) {
                $principals = @($gmsa.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ })
                $gmsaAccounts += [PSCustomObject]@{
                    SamAccountName        = $gmsa.SamAccountName
                    DistinguishedName     = $gmsa.DistinguishedName
                    Domain                = $domainDns
                    Enabled               = $gmsa.Enabled
                    PrincipalsAllowed     = @($principals)
                    PrincipalsCount       = $principals.Count
                    PasswordInterval      = $gmsa.'msDS-ManagedPasswordInterval'
                    WhenCreated           = $gmsa.WhenCreated
                    Description           = $gmsa.Description
                }
            }
        } catch {
            Write-Verbose "    Cannot enumerate gMSAs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Authentication Policies and Silos ----
    $authPolicies = @()
    $authSilos = @()
    try {
        # Authentication Policies and Silos are forest-wide (stored in Configuration partition)
        $rootDomain = $forest.RootDomain
        $policies = Get-ADAuthenticationPolicy -Filter * -Server $rootDomain -ErrorAction SilentlyContinue
        foreach ($policy in $policies) {
            $authPolicies += [PSCustomObject]@{
                Name              = $policy.Name
                DistinguishedName = $policy.DistinguishedName
                Enforce           = $policy.Enforce
                UserTGTLifetime   = $policy.UserAllowedToAuthenticateFrom
                Description       = $policy.Description
            }
        }
        $silos = Get-ADAuthenticationPolicySilo -Filter * -Server $rootDomain -ErrorAction SilentlyContinue
        foreach ($silo in $silos) {
            $members = @()
            try {
                $members = @(Get-ADAuthenticationPolicySilo -Identity $silo.Name -Server $rootDomain `
                    -Properties Members -ErrorAction SilentlyContinue).Members
            } catch { }
            $authSilos += [PSCustomObject]@{
                Name              = $silo.Name
                DistinguishedName = $silo.DistinguishedName
                Enforce           = $silo.Enforce
                MemberCount       = $members.Count
                Members           = @($members)
                UserPolicy        = $silo.UserAuthenticationPolicy
                ComputerPolicy    = $silo.ComputerAuthenticationPolicy
                ServicePolicy     = $silo.ServiceAuthenticationPolicy
                Description       = $silo.Description
            }
        }
    } catch {
        Write-Verbose "    Cannot enumerate Authentication Policies/Silos: $($_.Exception.Message)"
    }

    # ---- Standalone Managed Service Accounts (sMSA, not gMSA) ----
    $msaAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName
            $msas = Get-ADObject -Filter { objectClass -eq 'msDS-ManagedServiceAccount' } `
                -SearchBase "CN=Managed Service Accounts,$domainDN" -Server $domainDns `
                -Properties SamAccountName, Enabled, PasswordLastSet, WhenCreated, Description `
                -ErrorAction SilentlyContinue
            foreach ($msa in $msas) {
                $pwdAge = if ($msa.PasswordLastSet) { ((Get-Date) - $msa.PasswordLastSet).Days } else { 9999 }
                $msaAccounts += [PSCustomObject]@{
                    SamAccountName    = $msa.SamAccountName
                    DistinguishedName = $msa.DistinguishedName
                    Domain            = $domainDns
                    Enabled           = $msa.Enabled
                    PasswordLastSet   = $msa.PasswordLastSet
                    PasswordAgeDays   = $pwdAge
                    WhenCreated       = $msa.WhenCreated
                    Description       = $msa.Description
                    IsGMSA            = $false
                }
            }
        } catch {
            Write-Verbose "    Cannot enumerate sMSAs for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Cluster Virtual Computer Objects (VCOs) — password age check ----
    $clusterAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            # Cluster computer accounts often have ServicePrincipalName containing MSClusterVirtualServer
            $clusterComps = Get-ADComputer -Filter { ServicePrincipalName -like '*MSClusterVirtualServer*' } `
                -Server $domainDns -Properties SamAccountName, PasswordLastSet, Enabled, ServicePrincipalName, Description `
                -ErrorAction SilentlyContinue
            foreach ($c in $clusterComps) {
                $pwdAge = if ($c.PasswordLastSet) { ((Get-Date) - $c.PasswordLastSet).Days } else { 9999 }
                $clusterAccounts += [PSCustomObject]@{
                    SamAccountName    = $c.SamAccountName
                    DistinguishedName = $c.DistinguishedName
                    Domain            = $domainDns
                    Enabled           = $c.Enabled
                    PasswordLastSet   = $c.PasswordLastSet
                    PasswordAgeDays   = $pwdAge
                    Description       = $c.Description
                }
            }
        } catch {
            Write-Verbose "    Cannot enumerate cluster accounts for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Trust account password age (trust user objects: CN=<domain>$) ----
    $trustAccounts = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            # Trust accounts have UAC flag INTERDOMAIN_TRUST_ACCOUNT (0x800)
            $trustUsers = Get-ADUser -Filter { UserAccountControl -band 2048 } `
                -Server $domainDns -Properties SamAccountName, PasswordLastSet, Enabled, UserAccountControl `
                -ErrorAction SilentlyContinue
            foreach ($t in $trustUsers) {
                $pwdAge = if ($t.PasswordLastSet) { ((Get-Date) - $t.PasswordLastSet).Days } else { 9999 }
                $trustAccounts += [PSCustomObject]@{
                    SamAccountName    = $t.SamAccountName
                    DistinguishedName = $t.DistinguishedName
                    Domain            = $domainDns
                    Enabled           = $t.Enabled
                    PasswordLastSet   = $t.PasswordLastSet
                    PasswordAgeDays   = $pwdAge
                }
            }
        } catch {
            Write-Verbose "    Cannot enumerate trust accounts for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Group nesting loops (cycle detection) ----
    $groupLoops = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $allGroups = Get-ADGroup -Filter * -Server $domainDns -Properties MemberOf -ErrorAction Stop
            # Build adjacency: group DN -> set of parent group DNs
            $memberOfMap = @{}
            foreach ($g in $allGroups) {
                $memberOfMap[$g.DistinguishedName] = @($g.MemberOf)
            }
            # DFS cycle detection
            $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $inStack = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $reportedCycles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

            function Find-GroupCycle {
                param([string]$Node, [System.Collections.Generic.List[string]]$Path)
                if ($inStack.Contains($Node)) {
                    # Found a cycle — extract the loop portion
                    $loopStart = $Path.IndexOf($Node)
                    if ($loopStart -ge 0) {
                        $cycle = @($Path[$loopStart..($Path.Count - 1)])
                        $cycleKey = ($cycle | Sort-Object) -join '|'
                        if (-not $reportedCycles.Contains($cycleKey)) {
                            $null = $reportedCycles.Add($cycleKey)
                            return $cycle
                        }
                    }
                    return $null
                }
                if ($visited.Contains($Node)) { return $null }
                $null = $visited.Add($Node)
                $null = $inStack.Add($Node)
                $Path.Add($Node)
                if ($memberOfMap.ContainsKey($Node)) {
                    foreach ($parent in $memberOfMap[$Node]) {
                        if ($memberOfMap.ContainsKey($parent)) {
                            $result = Find-GroupCycle -Node $parent -Path $Path
                            if ($result) {
                                # Remove last item and continue looking for more cycles
                                $script:foundCycles += ,@($result)
                            }
                        }
                    }
                }
                $Path.RemoveAt($Path.Count - 1)
                $null = $inStack.Remove($Node)
                return $null
            }

            $script:foundCycles = @()
            foreach ($gDN in $memberOfMap.Keys) {
                if (-not $visited.Contains($gDN)) {
                    $path = [System.Collections.Generic.List[string]]::new()
                    Find-GroupCycle -Node $gDN -Path $path
                }
            }

            foreach ($cycle in $script:foundCycles) {
                $groupLoops += [PSCustomObject]@{
                    Domain     = $domainDns
                    CycleLength = $cycle.Count
                    Groups     = @($cycle)
                    GroupNames = @($cycle | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' })
                }
            }
        } catch {
            Write-Warning "    Cannot check group loops for $domainDns : $($_.Exception.Message)"
        }
    }

    # ---- Display Specifiers with scriptPath (potential backdoor) ----
    $dangerousDisplaySpecifiers = @()
    try {
        $configDN = $rootDSE.configurationNamingContext
        # Display Specifiers live under CN=DisplaySpecifiers,CN=Configuration,...
        $displaySpecDN = "CN=DisplaySpecifiers,$configDN"
        $specEntries = Get-ADObject -SearchBase $displaySpecDN -Filter * `
            -Properties adminContextMenu, contextMenu, shellContextMenu, adminPropertyPages, `
                        shellPropertyPages, treatAsLeaf, extraColumns `
            -ErrorAction SilentlyContinue
        foreach ($spec in $specEntries) {
            # Check for any attribute containing a script/executable path
            foreach ($attr in @('adminContextMenu', 'contextMenu', 'shellContextMenu')) {
                $values = @($spec.$attr | Where-Object { $_ })
                foreach ($val in $values) {
                    if ($val -match '\\\\|\.exe|\.vbs|\.ps1|\.bat|\.cmd|\.js|\.wsh|\.wsf|http') {
                        $dangerousDisplaySpecifiers += [PSCustomObject]@{
                            DistinguishedName = $spec.DistinguishedName
                            Attribute         = $attr
                            Value             = $val
                        }
                    }
                }
            }
        }
    } catch {
        Write-Warning "    Cannot check Display Specifiers: $($_.Exception.Message)"
    }

    # ---- Critical AD objects existence check ----
    $criticalObjectsStatus = @()
    foreach ($domainDns in $forest.Domains) {
        try {
            $domObj = $domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)
            $domainDN = $domObj.DistinguishedName
            $domSID   = $domObj.DomainSID.Value

            # List of critical well-known containers/objects that must exist
            $criticalObjDNs = @(
                "CN=Users,$domainDN"
                "CN=Computers,$domainDN"
                "CN=System,$domainDN"
                "CN=Builtin,$domainDN"
                "OU=Domain Controllers,$domainDN"
                "CN=Infrastructure,$domainDN"
                "CN=Managed Service Accounts,$domainDN"
                "CN=NTDS Quotas,$domainDN"
            )
            foreach ($dn in $criticalObjDNs) {
                try {
                    $null = Get-ADObject -Identity $dn -Server $domainDns -ErrorAction Stop
                } catch {
                    $criticalObjectsStatus += [PSCustomObject]@{
                        Domain            = $domainDns
                        DistinguishedName = $dn
                        Status            = 'Missing'
                    }
                }
            }

            # Critical well-known groups (by RID)
            $criticalGroups = @{
                'Domain Admins'      = "$domSID-512"
                'Domain Users'       = "$domSID-513"
                'Domain Computers'   = "$domSID-515"
                'Domain Controllers' = "$domSID-516"
                'Cert Publishers'    = "$domSID-517"
                'Schema Admins'      = "$domSID-518"
                'Enterprise Admins'  = "$domSID-519"
                'Group Policy CO'    = "$domSID-520"
            }
            foreach ($name in $criticalGroups.Keys) {
                try {
                    $null = Get-ADGroup -Identity $criticalGroups[$name] -Server $domainDns -ErrorAction Stop
                } catch {
                    $criticalObjectsStatus += [PSCustomObject]@{
                        Domain            = $domainDns
                        DistinguishedName = "$name ($($criticalGroups[$name]))"
                        Status            = 'Missing'
                    }
                }
            }
        } catch {
            Write-Warning "    Cannot check critical objects for $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        DsHeuristics             = $dsHeuristics
        DenyUnauthenticatedBind  = $denyUnauthBind
        MachineAccountQuotas     = @($machineAccountQuotas)
        PreWin2000Members    = @($preWin2000Members)
        GuestAccounts        = @($guestAccounts)
        ProtectedUsers       = @($protectedUsersInfo)
        OperatorGroups       = @($operatorGroups)
        SysvolReplication    = @($sysvolReplication)
        DESAccounts          = @($desAccounts)
        PwdNotRequired       = @($pwdNotReqAccounts)
        KerberosArmoring     = @($kerberosArmoring)
        DCServices           = @($dcServices)
        UnprotectedOUs       = @($unprotectedOUs)
        DelegatableAdmins    = @($delegatableAdmins)
        LAPSInfo             = @($lapsInfo)
        AdminCountOrphans    = @($adminCountOrphans)
        PwdNeverExpiresAll   = @($pwdNeverExpiresAll)
        SCRILRotation        = @($scrilRotation)
        GMSAAccounts         = @($gmsaAccounts)
        MSAAccounts          = @($msaAccounts)
        ClusterAccounts      = @($clusterAccounts)
        TrustAccounts        = @($trustAccounts)
        GroupLoops           = @($groupLoops)
        DangerousDisplaySpecifiers = @($dangerousDisplaySpecifiers)
        CriticalObjectsStatus = @($criticalObjectsStatus)
        AuthPolicies         = @($authPolicies)
        AuthSilos            = @($authSilos)
    }
}
