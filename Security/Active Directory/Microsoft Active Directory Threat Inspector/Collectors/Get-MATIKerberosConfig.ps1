# Collectors\Get-MATIKerberosConfig.ps1
# MATIv2 - Collects Kerberos configuration and SPN accounts.

function Get-MATIKerberosConfig {
    <#
    .SYNOPSIS
        Collects Kerberos-related configuration: KRBTGT accounts,
        accounts with SPNs, delegation settings, pre-auth settings.
    .OUTPUTS
        [hashtable] with keys: KrbtgtAccounts, SPNAccounts, DelegationAccounts
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest   = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $userProps = $Config.Collectors.UserProperties

    $krbtgtAccounts     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $spnAccounts        = [System.Collections.Generic.List[PSCustomObject]]::new()
    $delegationAccounts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allSPNs            = @{}

    foreach ($domainDns in $forest.Domains) {
        try {
            # KRBTGT account
            $krbtgt = Get-ADUser -Identity 'krbtgt' -Server $domainDns `
                -Properties PasswordLastSet, 'msDS-SupportedEncryptionTypes', WhenCreated -ErrorAction Stop

            $krbtgtAccounts.Add([PSCustomObject]@{
                SamAccountName           = $krbtgt.SamAccountName
                Domain                   = $domainDns
                DistinguishedName        = $krbtgt.DistinguishedName
                PasswordLastSet          = $krbtgt.PasswordLastSet
                SupportedEncryptionTypes = $krbtgt.'msDS-SupportedEncryptionTypes'
                PasswordAgeDays          = if ($krbtgt.PasswordLastSet) {
                    [math]::Round(((Get-Date) - $krbtgt.PasswordLastSet).TotalDays)
                } else { 9999 }
            })

            # Accounts with SPNs (Kerberoastable) - exclude computer accounts and krbtgt
            $spnUsers = Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Server $domainDns `
                -Properties $userProps -ErrorAction Stop

            foreach ($user in $spnUsers) {
                if ($user.SamAccountName -eq 'krbtgt') { continue }

                $spnAccounts.Add([PSCustomObject]@{
                    SamAccountName           = $user.SamAccountName
                    DistinguishedName        = $user.DistinguishedName
                    Domain                   = $domainDns
                    Enabled                  = $user.Enabled
                    AdminCount               = $user.AdminCount
                    ServicePrincipalName     = @($user.ServicePrincipalName)
                    PasswordLastSet          = $user.PasswordLastSet
                    PasswordNeverExpires     = $user.PasswordNeverExpires
                    SupportedEncryptionTypes = $user.'msDS-SupportedEncryptionTypes'
                    DoesNotRequirePreAuth    = $user.DoesNotRequirePreAuth
                    Description              = $user.Description
                    SID                      = $user.SID.Value
                })
            }

            # Accounts with AS-REP Roasting risk (DONT_REQUIRE_PREAUTH)
            # Avoid duplicates: track which users we already added from SPN query
            $seenSPNUsers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($s in $spnAccounts) { $null = $seenSPNUsers.Add($s.DistinguishedName) }

            $asrepUsers = Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Server $domainDns `
                -Properties $userProps -ErrorAction Stop

            foreach ($user in $asrepUsers) {
                # If already collected via SPN query, just flag it as ASREP roastable
                $existing = $spnAccounts | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
                if ($existing) {
                    # Can't modify PSCustomObject property directly, add a note
                    $existing | ForEach-Object { $_ | Add-Member -NotePropertyName '_ASREPRoastable' -NotePropertyValue $true -Force }
                    continue
                }

                $spnAccounts.Add([PSCustomObject]@{
                    SamAccountName           = $user.SamAccountName
                    DistinguishedName        = $user.DistinguishedName
                    Domain                   = $domainDns
                    Enabled                  = $user.Enabled
                    AdminCount               = $user.AdminCount
                    ServicePrincipalName     = @($user.ServicePrincipalName)
                    PasswordLastSet          = $user.PasswordLastSet
                    PasswordNeverExpires     = $user.PasswordNeverExpires
                    SupportedEncryptionTypes = $user.'msDS-SupportedEncryptionTypes'
                    DoesNotRequirePreAuth    = $user.DoesNotRequirePreAuth
                    Description              = $user.Description
                    SID                      = $user.SID.Value
                    _ASREPRoastable          = $true
                })
            }

            # Accounts with unconstrained / constrained delegation
            $compProps = $Config.Collectors.ComputerProperties

            $delegUsers = Get-ADUser -Filter 'TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true' `
                -Server $domainDns -Properties $userProps -ErrorAction Stop

            $delegComputers = Get-ADComputer -Filter 'TrustedForDelegation -eq $true -or TrustedToAuthForDelegation -eq $true' `
                -Server $domainDns -Properties $compProps -ErrorAction Stop

            $allDeleg = @($delegUsers) + @($delegComputers)
            foreach ($obj in $allDeleg) {
                $delegationAccounts.Add([PSCustomObject]@{
                    SamAccountName           = $obj.SamAccountName
                    DistinguishedName        = $obj.DistinguishedName
                    Domain                   = $domainDns
                    ObjectClass              = $obj.ObjectClass
                    Enabled                  = $obj.Enabled
                    TrustedForDelegation     = $obj.TrustedForDelegation              # Unconstrained
                    TrustedToAuthForDelegation = $obj.TrustedToAuthForDelegation      # Constrained (protocol transition)
                    AllowedToDelegateTo      = @($obj.'msDS-AllowedToDelegateTo')
                    OperatingSystem          = $obj.OperatingSystem
                    Description              = $obj.Description
                    SID                      = $obj.SID.Value
                })
            }

            # Collect all SPNs for duplicate detection
            $allObjects = Get-ADObject -Filter 'ServicePrincipalName -like "*"' -Server $domainDns `
                -Properties ServicePrincipalName, SamAccountName -ErrorAction SilentlyContinue
            foreach ($obj in $allObjects) {
                foreach ($spn in $obj.ServicePrincipalName) {
                    $spnNorm = $spn.ToLower()
                    if (-not $allSPNs.ContainsKey($spnNorm)) { $allSPNs[$spnNorm] = @() }
                    $allSPNs[$spnNorm] += [PSCustomObject]@{
                        SPN               = $spn
                        SamAccountName    = $obj.SamAccountName
                        DistinguishedName = $obj.DistinguishedName
                        Domain            = $domainDns
                    }
                }
            }
        }
        catch {
            Write-Warning "    Cannot query Kerberos config for $domainDns : $($_.Exception.Message)"
        }
    }

    # Build duplicate SPN list
    $duplicateSPNs = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($entry in $allSPNs.GetEnumerator()) {
        if ($entry.Value.Count -gt 1) {
            $duplicateSPNs.Add([PSCustomObject]@{
                SPN      = $entry.Key
                Count    = $entry.Value.Count
                Accounts = @($entry.Value)
            })
        }
    }

    return @{
        KrbtgtAccounts     = @($krbtgtAccounts)
        SPNAccounts        = @($spnAccounts)
        DelegationAccounts = @($delegationAccounts)
        DuplicateSPNs      = @($duplicateSPNs)
    }
}

