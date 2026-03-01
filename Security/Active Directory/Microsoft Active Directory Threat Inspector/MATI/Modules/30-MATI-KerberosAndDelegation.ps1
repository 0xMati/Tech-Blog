#requires -Version 5.1
<#
30-MATI-KerberosAndDelegation.ps1  (MATI – Microsoft Active Directory Threat Inspector)
Module 30 – Kerberos & Delegation

Findings implemented:
  - MATI-KERB-010 – Domain controllers allow RC4 Kerberos encryption   (High)
  - MATI-KERB-012 – Domain default Kerberos encryption may allow RC4   (Medium, OS-aware)
  - MATI-KERB-001 – KRBTGT account not AES-only                        (High, if KDC RC4 allowed)
  - MATI-KERB-002 – Domain Controller account not AES-only             (High, if KDC RC4 allowed)
  - MATI-KERB-003 – Service account with SPN allowing legacy encryption (RC4/DES) (Medium/High)
  - MATI-KERB-004 – Service account with SPN and no AES support        (Medium)
  - MATI-KERB-005 – Account configured with DONT_REQUIRE_PREAUTH       (High / Medium)
  - MATI-KERB-006 – Unconstrained delegation enabled                   (High / Medium, non-DC only)

Outputs:
  - CSV\MATI_AD_Kerberos_Accounts.csv
  - CSV\MATI_AD_Kerberos_KdcConfig.csv
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot
)

$moduleTag = '[30-MATI-Kerberos]'
Write-Host "$moduleTag Output root : $OutputRoot" -ForegroundColor Cyan

# Ensure CSV folder exists
$csvRoot = Join-Path -Path $OutputRoot -ChildPath 'CSV'
if (-not (Test-Path -Path $csvRoot)) {
    New-Item -Path $csvRoot -ItemType Directory | Out-Null
}

# Load findings helper (common)
$findingLibPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Common\Finding.ps1'
if (Test-Path -Path $findingLibPath) {
    . $findingLibPath
} else {
    Write-Warning "$moduleTag Finding library not found at $findingLibPath"
    return
}

# Try to import ActiveDirectory
try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
} catch {
    Write-Error "$moduleTag Failed to load ActiveDirectory module: $($_.Exception.Message)"
    return
}

# Helpers for enc types
function Test-MatiRC4Allowed {
    param([nullable[uint32]]$EncTypes)
    if ($null -eq $EncTypes) { return $false }
    return (($EncTypes -band 0x04) -ne 0)
}
function Test-MatiDESAllowed {
    param([nullable[uint32]]$EncTypes)
    if ($null -eq $EncTypes) { return $false }
    return (($EncTypes -band 0x03) -ne 0)
}
function Test-MatiAES128Allowed {
    param([nullable[uint32]]$EncTypes)
    if ($null -eq $EncTypes) { return $false }
    return (($EncTypes -band 0x08) -ne 0)
}
function Test-MatiAES256Allowed {
    param([nullable[uint32]]$EncTypes)
    if ($null -eq $EncTypes) { return $false }
    return (($EncTypes -band 0x10) -ne 0)
}

# OS helper
function Test-MatiOsIsAtLeast2022 {
    param([string]$OperatingSystem)
    if ([string]::IsNullOrEmpty($OperatingSystem)) { return $false }
    if ($OperatingSystem -like '*2022*') { return $true }
    if ($OperatingSystem -like '*2025*') { return $true } # future-proof
    return $false
}

# Remote registry helper
function Get-MatiRemoteRegDword {
    param(
        [string]$ComputerName,
        [string]$Path,
        [string]$Name
    )
    try {
        $script = {
            param($innerPath, $innerName)
            if (Test-Path -Path $innerPath) {
                $item = Get-ItemProperty -Path $innerPath -Name $innerName -ErrorAction SilentlyContinue
                if ($null -ne $item) {
                    return [nullable[uint32]]($item.$innerName)
                }
            }
            return $null
        }
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $script -ArgumentList $Path, $Name -ErrorAction Stop
        if ($result.Count -gt 0) {
            return [nullable[uint32]]$result[0]
        } else {
            return [nullable[uint32]]$null
        }
    } catch {
        Write-Warning ("{0} Failed to read registry on {1} ({2}\{3}): {4}" -f $moduleTag, $ComputerName, $Path, $Name, $_.Exception.Message)
        return $null
    }
}

$findings     = @()
$kerbAccounts = @()
$kdcConfig    = @()

# Forest & domains
try {
    $forest  = Get-ADForest -ErrorAction Stop
    $domains = @()
    foreach ($domName in $forest.Domains) {
        try {
            $domains += Get-ADDomain -Identity $domName -ErrorAction Stop
        } catch {
            Write-Warning ("{0} Failed to query domain {1}: {2}" -f $moduleTag, $domName, $_.Exception.Message)
        }
    }
} catch {
    Write-Error "$moduleTag Failed to query forest: $($_.Exception.Message)"
    return
}

foreach ($domain in $domains) {
    $domainName = $domain.DNSRoot
    Write-Host "$moduleTag Processing domain $domainName..." -ForegroundColor Cyan

    # ------------------------
    # Domain controllers (full list)
    # ------------------------
    $dcs = @()
    try {
        $dcs = Get-ADDomainController -Filter * -Server $domainName -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query domain controllers for {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    # If no DCs found, we still continue for users, etc.
    $domainKdcRC4Allowed          = $false
    $anyDefaultDomainKeyPresent   = $false
    $anyDefaultDomainKeyRC4       = $false
    $anyDCBelow2022               = $false

    $dcsWithRC4Supported          = @()
    $dcsWithDefaultDomainEncRC4   = @()
    $dcsBelow2022                 = @()

    # PDC for IsPDC flag in CSV
    $pdcFqdn = $domain.PDCEmulator

    # -----------------------
    # KDC configuration per DC
    # -----------------------
    foreach ($dc in $dcs) {
        $dcComputer = $null
        $osIsAtLeast2022 = $false
        $supportedEnc    = $null
        $defaultDomainEnc = $null
        $kdcRc4ThisDc    = $false

        try {
            $dcComputer = Get-ADComputer -Identity $dc.ComputerObjectDN -Server $domainName `
                -Properties OperatingSystem,OperatingSystemVersion -ErrorAction Stop
        } catch {
            Write-Warning ("{0} Failed to query DC computer object {1} in {2}: {3}" -f $moduleTag, $dc.HostName, $domainName, $_.Exception.Message)
        }

        if ($dcComputer -ne $null) {
            $osIsAtLeast2022 = Test-MatiOsIsAtLeast2022 -OperatingSystem $dcComputer.OperatingSystem
            if (-not $osIsAtLeast2022) {
                $anyDCBelow2022 = $true
                $dcsBelow2022 += $dc.HostName
            }
        }

        # Use FQDN for WinRM / registry
        $remoteName = $dc.HostName

        # SupportedEncryptionTypes (GPO)
        $supportedEnc = Get-MatiRemoteRegDword -ComputerName $remoteName `
            -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' `
            -Name 'SupportedEncryptionTypes'

        if ($supportedEnc -ne $null) {
            $kdcRc4ThisDc = Test-MatiRC4Allowed -EncTypes $supportedEnc
            if ($kdcRc4ThisDc) {
                $domainKdcRC4Allowed = $true
                $dcsWithRC4Supported += $dc.HostName
            }
        }

        # DefaultDomainSupportedEncTypes (override)
        $defaultDomainEnc = Get-MatiRemoteRegDword -ComputerName $remoteName `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\KDC' `
            -Name 'DefaultDomainSupportedEncTypes'

        if ($defaultDomainEnc -ne $null) {
            $anyDefaultDomainKeyPresent = $true
            if (Test-MatiRC4Allowed -EncTypes $defaultDomainEnc) {
                $anyDefaultDomainKeyRC4 = $true
                $dcsWithDefaultDomainEncRC4 += ("{0}(0x{1:X})" -f $dc.HostName, $defaultDomainEnc)
            }
        }

        # Snapshot KDC config per DC
        $kdcConfig += [pscustomobject]@{
            DomainDNS                      = $domainName
            DCName                         = $dc.HostName
            IsPDC                          = ($dc.HostName -eq $pdcFqdn)
            OperatingSystem                = if ($dcComputer -ne $null) { $dcComputer.OperatingSystem } else { $null }
            SupportedEncryptionTypes       = if ($supportedEnc -ne $null) { ('0x{0:X}' -f $supportedEnc) } else { $null }
            DefaultDomainSupportedEncTypes = if ($defaultDomainEnc -ne $null) { ('0x{0:X}' -f $defaultDomainEnc) } else { $null }
            KdcRC4Allowed                  = $kdcRc4ThisDc
            OsIsAtLeast2022                = $osIsAtLeast2022
        }
    }

    # -----------------------
    # Domain-level findings (010 / 012)
    # -----------------------

    # MATI-KERB-010 – if at least one DC allows RC4
    if ($domainKdcRC4Allowed) {
        $details010 = "DCsWithRC4=" + ($dcsWithRC4Supported -join ',') + "; TotalDCs=" + $dcs.Count
        $findings += New-Finding `
            -Id 'MATI-KERB-010' `
            -Category 'Kerberos' `
            -Severity 'High' `
            -Title 'Domain controllers allow RC4 Kerberos encryption' `
            -Description ("One or more domain controllers for {0} are configured to allow RC4-HMAC Kerberos encryption via SupportedEncryptionTypes on the KDC. This enables the use of weak Kerberos encryption and increases exposure to Kerberoasting and downgrade attacks." -f $domainName) `
            -Remediation "Review Kerberos encryption requirements and progressively restrict SupportedEncryptionTypes on all domain controllers to AES-only (AES128/AES256). Validate service compatibility before disabling RC4." `
            -ObjectDN $domain.DistinguishedName `
            -Domain $domainName `
            -Source '30-MATI-KerberosAndDelegation' `
            -Details $details010
    }

    # MATI-KERB-012 – DefaultDomainSupportedEncTypes / default behavior
    if ($anyDefaultDomainKeyPresent) {
        if ($anyDefaultDomainKeyRC4) {
            $details012 = "DCsWithDefaultDomainSupportedEncTypesRC4=" + ($dcsWithDefaultDomainEncRC4 -join ',')
            $findings += New-Finding `
                -Id 'MATI-KERB-012' `
                -Category 'Kerberos' `
                -Severity 'Medium' `
                -Title 'Domain default Kerberos encryption may allow RC4' `
                -Description ("The KDC default domain encryption configuration for {0} explicitly allows RC4 via DefaultDomainSupportedEncTypes on one or more domain controllers. Depending on OS version and patches, this may enable weak Kerberos encryption for accounts inheriting the default." -f $domainName) `
                -Remediation "Review the need for RC4 at the domain level. If possible, update DefaultDomainSupportedEncTypes on all domain controllers to an AES-only configuration (e.g. AES128/AES256) and validate compatibility. Consider explicitly defining this key to override legacy defaults." `
                -ObjectDN $domain.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details $details012
        }
    } else {
        if ($anyDCBelow2022) {
            $details012 = "DCsBelow2022=" + ($dcsBelow2022 -join ',') + "; DefaultDomainSupportedEncTypes=<not set on any DC>"
            $findings += New-Finding `
                -Id 'MATI-KERB-012' `
                -Category 'Kerberos' `
                -Severity 'Medium' `
                -Title 'Domain default Kerberos encryption may allow RC4' `
                -Description ("No explicit DefaultDomainSupportedEncTypes is configured on domain {0} and one or more domain controllers run an OS version earlier than Windows Server 2022. The legacy KDC default behavior may still allow RC4, depending on the patch level." -f $domainName) `
                -Remediation "Review the Kerberos encryption configuration on domain controllers and plan to explicitly configure AES-only defaults. You can use DefaultDomainSupportedEncTypes to override legacy defaults and align with an RC4-free posture." `
                -ObjectDN $domain.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details $details012
        }
    }

    # Domain-level view: RC4 allowed if at least one DC allows it
    $kdcRC4AllowedForDomain = $domainKdcRC4Allowed

    # ------------------------
    # Accounts: KRBTGT / DCs
    # ------------------------

    # 1) KRBTGT
    $krbTgts = @()
    try {
        $krbTgts = Get-ADUser -Filter "SamAccountName -like 'krbtgt*'" -Server $domainName `
            -Properties msDS-SupportedEncryptionTypes,userAccountControl,DistinguishedName -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query krbtgt accounts in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($kr in $krbTgts) {
        $enc = $null
        if ($kr.'msDS-SupportedEncryptionTypes' -ne $null) {
            $enc = [uint32]$kr.'msDS-SupportedEncryptionTypes'
        }

        $allowRC4    = Test-MatiRC4Allowed    -EncTypes $enc
        $allowDES    = Test-MatiDESAllowed    -EncTypes $enc
        $allowAES128 = Test-MatiAES128Allowed -EncTypes $enc
        $allowAES256 = Test-MatiAES256Allowed -EncTypes $enc

        $encSource = if ($kr.'msDS-SupportedEncryptionTypes' -ne $null) { 'Explicit' } else { 'InheritedFromKdcDefault' }

        $kerbAccounts += [pscustomobject]@{
            DomainDNS               = $domainName
            SamAccountName          = $kr.SamAccountName
            ObjectDN                = $kr.DistinguishedName
            ObjectType              = 'KRBTGT'
            EncTypesSource          = $encSource
            EncTypesRaw             = if ($enc -ne $null) { ('0x{0:X}' -f $enc) } else { $null }
            AllowDES                = $allowDES
            AllowRC4                = $allowRC4
            AllowAES128             = $allowAES128
            AllowAES256             = $allowAES256
            KdcRC4Allowed           = $kdcRC4AllowedForDomain
            DontRequirePreauth      = $false
            UnconstrainedDelegation = $false
            HasSPN                  = $false
            IsPrivileged            = $true
        }

        if ($kdcRC4AllowedForDomain -and ($allowRC4 -or $allowDES)) {
            $findings += New-Finding `
                -Id 'MATI-KERB-001' `
                -Category 'Kerberos' `
                -Severity 'High' `
                -Title 'KRBTGT account not AES-only' `
                -Description ("The KRBTGT account {0} in domain {1} supports legacy Kerberos encryption types (RC4 and/or DES) while domain controllers still accept RC4. This weakens the overall Kerberos security posture and increases the impact of Kerberos ticket forgery attacks." -f $kr.SamAccountName, $domainName) `
                -Remediation "Restrict the KRBTGT account to AES-only encryption (AES128/AES256) and plan a staged KRBTGT password reset process. Validate service compatibility before enforcing AES-only settings." `
                -ObjectDN $kr.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details ("msDS-SupportedEncryptionTypes={0}; AllowRC4={1}; AllowDES={2}; KdcRC4Allowed={3}" -f $enc, $allowRC4, $allowDES, $kdcRC4AllowedForDomain)
        }
    }

    # 2) Domain Controllers (machine account in AD, not registry)
    foreach ($dc in $dcs) {
        $dcComputer = $null
        try {
            $dcComputer = Get-ADComputer -Identity $dc.ComputerObjectDN -Server $domainName `
                -Properties msDS-SupportedEncryptionTypes,userAccountControl,DistinguishedName -ErrorAction Stop
        } catch {
            Write-Warning ("{0} Failed to query DC computer object {1} in {2}: {3}" -f $moduleTag, $dc.HostName, $domainName, $_.Exception.Message)
            continue
        }

        $enc = $null
        if ($dcComputer.'msDS-SupportedEncryptionTypes' -ne $null) {
            $enc = [uint32]$dcComputer.'msDS-SupportedEncryptionTypes'
        }

        $allowRC4    = Test-MatiRC4Allowed    -EncTypes $enc
        $allowDES    = Test-MatiDESAllowed    -EncTypes $enc
        $allowAES128 = Test-MatiAES128Allowed -EncTypes $enc
        $allowAES256 = Test-MatiAES256Allowed -EncTypes $enc

        $encSource = if ($dcComputer.'msDS-SupportedEncryptionTypes' -ne $null) { 'Explicit' } else { 'InheritedFromKdcDefault' }

        $kerbAccounts += [pscustomobject]@{
            DomainDNS               = $domainName
            SamAccountName          = $dcComputer.SamAccountName
            ObjectDN                = $dcComputer.DistinguishedName
            ObjectType              = 'DomainController'
            EncTypesSource          = $encSource
            EncTypesRaw             = if ($enc -ne $null) { ('0x{0:X}' -f $enc) } else { $null }
            AllowDES                = $allowDES
            AllowRC4                = $allowRC4
            AllowAES128             = $allowAES128
            AllowAES256             = $allowAES256
            KdcRC4Allowed           = $kdcRC4AllowedForDomain
            DontRequirePreauth      = $false
            UnconstrainedDelegation = $false
            HasSPN                  = $false
            IsPrivileged            = $true
        }

        if ($kdcRC4AllowedForDomain -and ($allowRC4 -or $allowDES)) {
            $findings += New-Finding `
                -Id 'MATI-KERB-002' `
                -Category 'Kerberos' `
                -Severity 'High' `
                -Title 'Domain Controller account not AES-only' `
                -Description ("The domain controller account {0} in domain {1} supports legacy Kerberos encryption types (RC4 and/or DES) while the KDC still accepts RC4. This weakens Kerberos security and should be remediated before enforcing an AES-only posture." -f $dcComputer.SamAccountName, $domainName) `
                -Remediation "Restrict Kerberos encryption types for domain controller accounts to AES-only (AES128/AES256) and validate compatibility before disabling RC4 at the KDC level." `
                -ObjectDN $dcComputer.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details ("msDS-SupportedEncryptionTypes={0}; AllowRC4={1}; AllowDES={2}; KdcRC4Allowed={3}" -f $enc, $allowRC4, $allowDES, $kdcRC4AllowedForDomain)
        }
    }

    # ------------------------
    # SPN accounts (003 / 004)
    # ------------------------
    $spnAccounts = @()
    try {
        $spnAccounts = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -SearchBase $domain.DistinguishedName `
            -SearchScope Subtree -Server $domainName `
            -Properties servicePrincipalName,msDS-SupportedEncryptionTypes,userAccountControl,adminCount,distinguishedName,sAMAccountName,objectClass -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query SPN accounts in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($obj in $spnAccounts) {
        $objClass = ($obj.objectClass | Select-Object -Last 1)
        if ($objClass -notin @('user', 'computer')) { continue }

        # Skip krbtgt (already handled)
        if ($objClass -eq 'user' -and $obj.sAMAccountName -like 'krbtgt*') {
            continue
        }

        # Skip DCs here (already handled as DomainController)
        $isDC = $false
        if ($objClass -eq 'computer' -and $dcs) {
            if ($dcs.ComputerObjectDN -contains $obj.DistinguishedName) {
                $isDC = $true
            }
        }
        if ($isDC) { continue }

        $enc = $null
        if ($obj.'msDS-SupportedEncryptionTypes' -ne $null) {
            $enc = [uint32]$obj.'msDS-SupportedEncryptionTypes'
        }

        $allowRC4    = Test-MatiRC4Allowed    -EncTypes $enc
        $allowDES    = Test-MatiDESAllowed    -EncTypes $enc
        $allowAES128 = Test-MatiAES128Allowed -EncTypes $enc
        $allowAES256 = Test-MatiAES256Allowed -EncTypes $enc

        $encSource = if ($obj.'msDS-SupportedEncryptionTypes' -ne $null) { 'Explicit' } else { 'InheritedFromKdcDefault' }

        $isPrivileged = $false
        if ($objClass -eq 'user' -and $obj.adminCount -eq 1) {
            $isPrivileged = $true
        }

        $kerbAccounts += [pscustomobject]@{
            DomainDNS               = $domainName
            SamAccountName          = $obj.sAMAccountName
            ObjectDN                = $obj.DistinguishedName
            ObjectType              = if ($objClass -eq 'user') { 'UserWithSPN' } else { 'ComputerWithSPN' }
            EncTypesSource          = $encSource
            EncTypesRaw             = if ($enc -ne $null) { ('0x{0:X}' -f $enc) } else { $null }
            AllowDES                = $allowDES
            AllowRC4                = $allowRC4
            AllowAES128             = $allowAES128
            AllowAES256             = $allowAES256
            KdcRC4Allowed           = $kdcRC4AllowedForDomain
            DontRequirePreauth      = $false
            UnconstrainedDelegation = $false
            HasSPN                  = $true
            IsPrivileged            = $isPrivileged
        }

        # 003 – SPN + RC4/DES (if at least one DC allows RC4)
        if ($kdcRC4AllowedForDomain -and ($allowRC4 -or $allowDES)) {
            $severity = if ($isPrivileged) { 'High' } else { 'Medium' }
            $findings += New-Finding `
                -Id 'MATI-KERB-003' `
                -Category 'Kerberos' `
                -Severity $severity `
                -Title 'Service account with SPN allows legacy Kerberos encryption' `
                -Description ("The service account {0} in domain {1} has one or more Service Principal Names and supports legacy Kerberos encryption types (RC4 and/or DES) while at least one domain controller still accepts RC4. This exposes the account to Kerberoasting attacks using weak encryption." -f $obj.sAMAccountName, $domainName) `
                -Remediation "Restrict Kerberos encryption types for this service account to AES-only (AES128/AES256) and validate application compatibility. Consider rotating the password after configuration changes." `
                -ObjectDN $obj.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details ("msDS-SupportedEncryptionTypes={0}; AllowRC4={1}; AllowDES={2}; KdcRC4Allowed={3}; Privileged={4}" -f $enc, $allowRC4, $allowDES, $kdcRC4AllowedForDomain, $isPrivileged)
        }

        # 004 – SPN + explicit no AES
        if ($obj.'msDS-SupportedEncryptionTypes' -ne $null -and -not $allowAES128 -and -not $allowAES256) {
            $findings += New-Finding `
                -Id 'MATI-KERB-004' `
                -Category 'Kerberos' `
                -Severity 'Medium' `
                -Title 'Service account with SPN does not support AES Kerberos encryption' `
                -Description ("The service account {0} in domain {1} has one or more Service Principal Names and an explicit Kerberos encryption configuration that does not include AES128 or AES256. This prevents the domain from moving to an AES-only Kerberos posture and may require RC4 to remain enabled for compatibility." -f $obj.sAMAccountName, $domainName) `
                -Remediation "Update the msDS-SupportedEncryptionTypes attribute for this account to include AES128 and/or AES256, and validate service compatibility before disabling RC4 at the KDC level." `
                -ObjectDN $obj.DistinguishedName `
                -Domain $domainName `
                -Source '30-MATI-KerberosAndDelegation' `
                -Details ("msDS-SupportedEncryptionTypes={0}; AllowAES128={1}; AllowAES256={2}" -f $enc, $allowAES128, $allowAES256)
        }
    }

    # ------------------------
    # 005 – DONT_REQUIRE_PREAUTH
    # ------------------------
    $userWithNoPreauth = @()
    try {
        $userWithNoPreauth = Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' `
            -SearchBase $domain.DistinguishedName -SearchScope Subtree -Server $domainName `
            -Properties userAccountControl,DistinguishedName,sAMAccountName,Enabled -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query DONT_REQUIRE_PREAUTH users in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($u in $userWithNoPreauth) {
        $enabled = $true
        try { $enabled = [bool]$u.Enabled } catch { }

        $kerbAccounts += [pscustomobject]@{
            DomainDNS               = $domainName
            SamAccountName          = $u.sAMAccountName
            ObjectDN                = $u.DistinguishedName
            ObjectType              = 'User'
            EncTypesSource          = $null
            EncTypesRaw             = $null
            AllowDES                = $false
            AllowRC4                = $false
            AllowAES128             = $false
            AllowAES256             = $false
            KdcRC4Allowed           = $kdcRC4AllowedForDomain
            DontRequirePreauth      = $true
            UnconstrainedDelegation = $false
            HasSPN                  = $false
            IsPrivileged            = $false
        }

        $severity = if ($enabled) { 'High' } else { 'Medium' }

        $findings += New-Finding `
            -Id 'MATI-KERB-005' `
            -Category 'Kerberos' `
            -Severity $severity `
            -Title 'Kerberos pre-authentication disabled (AS-REP Roasting)' `
            -Description ("The account {0} in domain {1} has Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). This allows attackers to request AS-REP responses without prior authentication and perform offline password cracking attacks." -f $u.sAMAccountName, $domainName) `
            -Remediation "Enable Kerberos pre-authentication for this account unless there is a strict and documented requirement. After remediation, reset the account password." `
            -ObjectDN $u.DistinguishedName `
            -Domain $domainName `
            -Source '30-MATI-KerberosAndDelegation' `
            -Details ("Enabled={0}; userAccountControl=0x{1:X}" -f $enabled, $u.userAccountControl)
    }

    # ------------------------
    # 006 – Unconstrained delegation (non-DC only)
    # ------------------------
    $delegObjs = @()
    try {
        $delegObjs = Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
            -SearchBase $domain.DistinguishedName -SearchScope Subtree -Server $domainName `
            -Properties userAccountControl,distinguishedName,sAMAccountName,objectClass,Enabled -ErrorAction Stop
    } catch {
        Write-Warning ("{0} Failed to query unconstrained delegation objects in {1}: {2}" -f $moduleTag, $domainName, $_.Exception.Message)
    }

    foreach ($o in $delegObjs) {
        $objClass = ($o.objectClass | Select-Object -Last 1)
        if ($objClass -notin @('user', 'computer')) { continue }

        # 👉 Option A: exclude Domain Controllers from this finding
        if ($objClass -eq 'computer' -and $dcs) {
            if ($dcs.ComputerObjectDN -contains $o.DistinguishedName) {
                # This is a DC machine account (SERVER_TRUST_ACCOUNT + TRUSTED_FOR_DELEGATION by design)
                # We skip it for MATI-KERB-006.
                continue
            }
        }

        $enabled = $true
        try { $enabled = [bool]$o.Enabled } catch { }

        $kerbAccounts += [pscustomobject]@{
            DomainDNS               = $domainName
            SamAccountName          = $o.sAMAccountName
            ObjectDN                = $o.DistinguishedName
            ObjectType              = if ($objClass -eq 'user') { 'User' } else { 'Computer' }
            EncTypesSource          = $null
            EncTypesRaw             = $null
            AllowDES                = $false
            AllowRC4                = $false
            AllowAES128             = $false
            AllowAES256             = $false
            KdcRC4Allowed           = $kdcRC4AllowedForDomain
            DontRequirePreauth      = $false
            UnconstrainedDelegation = $true
            HasSPN                  = $false
            IsPrivileged            = $false
        }

        $severity = if ($enabled) { 'High' } else { 'Medium' }

        $findings += New-Finding `
            -Id 'MATI-KERB-006' `
            -Category 'Kerberos' `
            -Severity $severity `
            -Title 'Unconstrained Kerberos delegation enabled' `
            -Description ("The {0} account {1} in domain {2} is configured for unconstrained Kerberos delegation. If this account is compromised, attackers can obtain Kerberos tickets for users authenticating to the service, potentially leading to domain-wide compromise." -f $objClass, $o.sAMAccountName, $domainName) `
            -Remediation "Disable unconstrained delegation for this account. If delegation is required, replace it with constrained delegation or resource-based constrained delegation and validate application behavior." `
            -ObjectDN $o.DistinguishedName `
            -Domain $domainName `
            -Source '30-MATI-KerberosAndDelegation' `
            -Details ("Enabled={0}; userAccountControl=0x{1:X}" -f $enabled, $o.userAccountControl)
    }
}

# Export CSVs
try {
    $kerbCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_Kerberos_Accounts.csv'
    $kerbAccounts | Sort-Object DomainDNS, ObjectType, SamAccountName |
        Export-Csv -Path $kerbCsvPath -NoTypeInformation -Encoding UTF8

    $kdcCsvPath = Join-Path -Path $csvRoot -ChildPath 'MATI_AD_Kerberos_KdcConfig.csv'
    $kdcConfig | Sort-Object DomainDNS, DCName |
        Export-Csv -Path $kdcCsvPath -NoTypeInformation -Encoding UTF8

    Write-Host "$moduleTag Kerberos accounts CSV: $kerbCsvPath" -ForegroundColor Green
    Write-Host "$moduleTag KDC configuration CSV: $kdcCsvPath" -ForegroundColor Green
} catch {
    Write-Warning "$moduleTag Failed to export Kerberos CSV files: $($_.Exception.Message)"
}

Write-Host "$moduleTag Module completed." -ForegroundColor Cyan

return ,$findings
