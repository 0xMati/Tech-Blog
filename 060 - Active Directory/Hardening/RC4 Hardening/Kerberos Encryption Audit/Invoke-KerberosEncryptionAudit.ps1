#Requires -Version 7.2
#Version 1.1.3
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string[]]$DomainControllers,
    [int]$MaxEventsPerDc = 5000,
    [switch]$ExportCsv,
    [switch]$OpenReport,
    [switch]$IncludeTrusts,
    [string]$OwnerMappingPath,
    [string]$OutputDir = $(Join-Path -Path $PSScriptRoot -ChildPath ("Outputs\KerberosEncryptionAudit_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

# PowerShell 7+ is required for ForEach-Object -Parallel (per-DC concurrent collection).
# The #Requires statement above already aborts on older hosts, but we double-check for clarity.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "This script requires PowerShell 7.2 or later. Current host: $($PSVersionTable.PSVersion). Install pwsh from https://aka.ms/pwsh and re-run from a pwsh session."
}

# Hardcoded concurrency cap for per-DC collection. Tuned for 95% of production environments
# (small to mid forests, mixed WAN topology). Bump only if you know your DCs and bandwidth.
$script:DcParallelThrottle = 4

$ErrorActionPreference = 'Continue'

function Write-Banner {
    param(
        [string]$Title,
        [string]$Subtitle
    )

    $line = ('=' * 78)
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ('  {0}' -f $Title) -ForegroundColor Cyan
    if (-not [string]::IsNullOrWhiteSpace($Subtitle)) {
        Write-Host ('  {0}' -f $Subtitle) -ForegroundColor DarkGray
    }
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Section {
    param(
        [string]$Title,
        [ConsoleColor]$Color = 'Cyan'
    )

    Write-Host ""
    Write-Host $Title -ForegroundColor $Color
}

function Write-Step {
    param(
        [int]$Number,
        [string]$Title,
        [string]$Hint
    )

    Write-Host ''
    Write-Host ('[{0}/5] {1}' -f $Number, $Title) -ForegroundColor Yellow
    if (-not [string]::IsNullOrWhiteSpace($Hint)) {
        Write-Host ('      {0}' -f $Hint) -ForegroundColor DarkGray
    }
}

function Write-StatusLine {
    param(
        [string]$Label,
        [string]$Value,
        [ConsoleColor]$Color = 'Gray'
    )

    Write-Host ('  - {0}: ' -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

function Write-TaskMessage {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'Gray'
    )

    Write-Host ('    > {0}' -f $Message) -ForegroundColor $Color
}

function Get-ExecutionContext {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $identity.Name
    $computerName = $env:COMPUTERNAME
    $fqdn = $computerName
    $osCaption = [System.Environment]::OSVersion.VersionString

    try {
        $ipProps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if (-not [string]::IsNullOrWhiteSpace($ipProps.DomainName)) {
            $fqdn = '{0}.{1}' -f $computerName, $ipProps.DomainName
        }
    } catch {
    }

    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($osInfo.Caption) {
            $osCaption = $osInfo.Caption
        }
    } catch {
    }

    return [PSCustomObject]@{
        User = $userName
        ComputerName = $computerName
        FQDN = $fqdn
        OS = $osCaption
        PowerShell = $PSVersionTable.PSVersion.ToString()
        StartedAt = Get-Date
    }
}

function Get-DirectorySnapshot {
    param(
        [string]$DomainDn
    )

    $snapshot = [ordered]@{
        Users = 'n/a'
        Computers = 'n/a'
        Groups = 'n/a'
    }

    try {
        $snapshot.Users = [string]((Get-ADUser -Filter * -SearchBase $DomainDn -ResultSetSize $null -ErrorAction Stop | Measure-Object).Count)
    } catch {
    }

    try {
        $snapshot.Computers = [string]((Get-ADComputer -Filter * -SearchBase $DomainDn -ResultSetSize $null -ErrorAction Stop | Measure-Object).Count)
    } catch {
    }

    try {
        $snapshot.Groups = [string]((Get-ADGroup -Filter * -SearchBase $DomainDn -ResultSetSize $null -ErrorAction Stop | Measure-Object).Count)
    } catch {
    }

    return [PSCustomObject]$snapshot
}

function Write-ContextBlock {
    param(
        [string]$Title,
        [hashtable]$Items
    )

    Write-Host ''
    Write-Host ('  {0}' -f $Title) -ForegroundColor Yellow
    foreach ($key in $Items.Keys) {
        Write-StatusLine -Label $key -Value ([string]$Items[$key]) -Color White
    }
}

function Write-MetricDashboard {
    param(
        [object[]]$Items,
        [int]$Columns = 3,
        [int]$Width = 24
    )

    if (-not $Items -or $Items.Count -eq 0) {
        return
    }

    for ($index = 0; $index -lt $Items.Count; $index += $Columns) {
        $chunk = @($Items[$index..([Math]::Min($index + $Columns - 1, $Items.Count - 1))])

        foreach ($item in $chunk) {
            Write-Host ('+{0}+' -f ('-' * $Width)) -NoNewline -ForegroundColor DarkCyan
            Write-Host '  ' -NoNewline
        }
        Write-Host ''

        foreach ($item in $chunk) {
            $label = [string]$item.Label
            if ($label.Length -gt $Width) { $label = $label.Substring(0, $Width) }
            Write-Host ('|{0}|' -f $label.PadRight($Width)) -NoNewline -ForegroundColor DarkGray
            Write-Host '  ' -NoNewline
        }
        Write-Host ''

        foreach ($item in $chunk) {
            $value = [string]$item.Value
            if ($value.Length -gt $Width) { $value = $value.Substring(0, $Width) }
            Write-Host '|' -NoNewline -ForegroundColor DarkCyan
            Write-Host ($value.PadRight($Width)) -NoNewline -ForegroundColor $item.Color
            Write-Host '|' -NoNewline -ForegroundColor DarkCyan
            Write-Host '  ' -NoNewline
        }
        Write-Host ''

        foreach ($item in $chunk) {
            Write-Host ('+{0}+' -f ('-' * $Width)) -NoNewline -ForegroundColor DarkCyan
            Write-Host '  ' -NoNewline
        }
        Write-Host ''
        Write-Host ''
    }
}

function HtmlEncode {
    param([string]$Text)

    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-EncTypeLabel {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return 'UNKNOWN' }

    $normalized = if ($Value -match '^0x[0-9A-Fa-f]+$') {
        $Value.ToLowerInvariant()
    } elseif ($Value -match '^\d+$') {
        ('0x{0:X}' -f [int]$Value).ToLowerInvariant()
    } else {
        $null
    }

    switch ($normalized) {
        '0x12' { return 'AES256-CTS-HMAC-SHA1-96' }
        '0x11' { return 'AES128-CTS-HMAC-SHA1-96' }
        '0x17' { return 'RC4-HMAC' }
        '0xffffffff' { return 'UNKNOWN (no ticket/failed ticket)' }
        default { return 'UNKNOWN' }
    }
}

function Convert-EncryptionFlagsToText {
    param([Nullable[int]]$Value)

    if ($null -eq $Value -or $Value -eq 0) {
        return '(absent/0)'
    }

    $flags = @()
    if (($Value -band 0x01) -ne 0) { $flags += 'DES-CBC-CRC' }
    if (($Value -band 0x02) -ne 0) { $flags += 'DES-CBC-MD5' }
    if (($Value -band 0x04) -ne 0) { $flags += 'RC4-HMAC' }
    if (($Value -band 0x08) -ne 0) { $flags += 'AES128' }
    if (($Value -band 0x10) -ne 0) { $flags += 'AES256' }

    if ($flags.Count -eq 0) {
        return ('0x{0:X}' -f $Value)
    }

    return ('0x{0:X} [{1}]' -f $Value, ($flags -join ', '))
}

function Get-EncStatus {
    param(
        [Nullable[int]]$Value,
        [string]$Category = 'User/Service',
        [bool]$HasSPN = $false,
        [bool]$KdcDefaultsExplicitAesOnly = $false
    )

    $hasAes128 = ($null -ne $Value) -and (($Value -band 0x08) -ne 0)
    $hasAes256 = ($null -ne $Value) -and (($Value -band 0x10) -ne 0)
    $hasAes = $hasAes128 -or $hasAes256
    $hasRc4 = ($null -ne $Value) -and (($Value -band 0x04) -ne 0)
    $hasDes = ($null -ne $Value) -and ((($Value -band 0x01) -ne 0) -or (($Value -band 0x02) -ne 0))

    if ($null -eq $Value -or $Value -eq 0) {
        $serviceLike = $HasSPN -or $Category -in @('gMSA', 'sMSA')
        if ($serviceLike) {
            if ($KdcDefaultsExplicitAesOnly) {
                return 'Review (Unset/0, service relies on explicit KDC AES-only default)'
            }
            return 'Warning (Unset/0, service relies on KDC default)'
        }

        if ($KdcDefaultsExplicitAesOnly) {
            return 'Info (Unset/0, non-service account inherits AES-only KDC default)'
        }

        return 'Info (Unset/0, non-service account inherits KDC default)'
    }
    if ($hasAes) {
        if ($hasRc4) { return 'Warning (AES present + RC4 allowed)' }
        return 'Compliant (AES present)'
    }
    if ($hasRc4) {
        return 'Failed (RC4-only/No AES)'
    }
    if ($hasDes) {
        return 'Failed (DES-only/No AES)'
    }
    return 'Failed (No AES)'
}

function Get-KdcDefaultStatus {
    param([Nullable[int]]$Value)

    if ($null -eq $Value) {
        return 'Warning (AES default, not enforced)'
    }

    $hasAes = (($Value -band 0x18) -eq 0x18)
    $hasRc4 = (($Value -band 0x04) -ne 0)
    $hasDes = (($Value -band 0x03) -ne 0)

    if ($hasAes -and -not $hasRc4 -and -not $hasDes) {
        return 'Compliant (AES-only default)'
    }

    return 'Warning (Mixed or RC4 allowed)'
}

function Get-Rc4DisablementPhaseStatus {
    param([object]$Value)

    if ($null -eq $Value) {
        return [PSCustomObject]@{
            Phase  = $null
            Label  = '(absent)'
            Status = 'Info (registry absent)'
        }
    }

    $intValue = [int]$Value
    switch ($intValue) {
        0 { return [PSCustomObject]@{ Phase = 0; Label = 'Phase 0 - silent (audit disabled)';  Status = 'Warning (silent)' } }
        1 { return [PSCustomObject]@{ Phase = 1; Label = 'Phase 1 - audit (warnings)';         Status = 'Compliant (Phase 1 audit)' } }
        2 { return [PSCustomObject]@{ Phase = 2; Label = 'Phase 2 - enforce (errors)';         Status = 'Compliant (Phase 2 enforce)' } }
        default { return [PSCustomObject]@{ Phase = $intValue; Label = ("Phase {0} (unknown)" -f $intValue); Status = 'Info (unknown phase value)' } }
    }
}

function Get-StatusBadgeClass {
    param([string]$Status)

    if ($Status -like 'Compliant*' -or $Status -eq 'OK') { return 'pass' }
    if ($Status -like 'Review*') { return 'warn' }
    if ($Status -like 'Warning*') { return 'warn' }
    if ($Status -like 'Failed*' -or $Status -eq 'Critical') { return 'fail' }
    return 'info'
}

function Get-KpiDescription {
    param([psobject]$Kpi)

    switch ($Kpi.Name) {
        'DCs with AES-only KDC default' {
            return 'Reads DefaultDomainSupportedEncTypes on every DC. A value like 0/3 means no DC is explicitly set to 0x18, so AES-only is not enforced through the KDC baseline even if patched DCs usually prefer AES.'
        }
        'SPN accounts failed (RC4 or no AES)' {
            return 'Counts SPN-bearing identities whose msDS-SupportedEncryptionTypes does not expose usable AES capability. These are direct blockers for clean AES-only service ticket issuance.'
        }
        'SPN accounts unset' {
            return 'Counts SPN-bearing identities where msDS-SupportedEncryptionTypes is absent or 0. That does not always mean broken, but it leaves the KDC to fall back to the domain controller default instead of an explicit per-account declaration.'
        }
        'RC4 events' {
            return 'Observed 4768/4769 events that actually used RC4 in the selected time window. This is protocol evidence, not just directory configuration.'
        }
        'Avoidable RC4 TGS' {
            return 'RC4 TGS events where the event fields suggest client, service, and DC all advertised AES. Those are the highest-signal RC4 cases because the protocol path looks capable of doing better already.'
        }
        default {
            return ''
        }
    }
}

function Get-KdcDefaultExplanation {
    param([psobject]$Row)

    if ($Row.Status -eq 'Failed') {
        return 'The registry value could not be read from this domain controller, so its fallback Kerberos baseline could not be evaluated.'
    }

    if ($Row.RawValue -eq '(absent)') {
        return 'The registry value is not explicitly set. After KB5021131 the DC usually prefers AES, but AES-only is not pinned here, so unset accounts still rely on implicit behavior.'
    }

    if ($Row.Status -like 'Compliant*') {
        return 'This DC is explicitly pinned to 0x18, meaning AES128 and AES256 only when an account does not define msDS-SupportedEncryptionTypes.'
    }

    return 'This DC has an explicit KDC baseline, but the value still allows mixed behavior such as RC4 when the account attribute is unset.'
}

function Get-ObjectEnabledState {
    param([int]$UserAccountControl)

    if ($UserAccountControl -eq 0) { return $false }
    return (($UserAccountControl -band 0x0002) -eq 0)
}

function Get-ObjectCategory {
    param([string]$ObjectClass)

    switch ($ObjectClass) {
        'computer' { return 'Computer' }
        'msDS-GroupManagedServiceAccount' { return 'gMSA' }
        'msDS-ManagedServiceAccount' { return 'sMSA' }
        default { return 'User/Service' }
    }
}

function Get-KdcDefaultAudit {
    param([string[]]$Dcs)

    $remoteScript = {
        $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
        $name = 'DefaultDomainSupportedEncTypes'
        $raw = $null

        if (Test-Path -Path $path) {
            try {
                $raw = (Get-ItemProperty -Path $path -ErrorAction Stop).$name
            } catch {
                $raw = $null
            }
        }

        [PSCustomObject]@{
            Computer = $env:COMPUTERNAME
            RawValue = $raw
        }
    }

    # Parallel per-DC: each iteration produces a [PSCustomObject] with the raw value or an error marker.
    # Local helpers (Get-KdcDefaultStatus, Convert-EncryptionFlagsToText) live in the parent runspace,
    # so we post-process AFTER the parallel block in the main thread.
    # Note: PS 7 -Parallel forbids passing scriptblocks via $using:. We pass the textual representation
    # and rebuild the scriptblock inside each runspace via [scriptblock]::Create().
    $remoteScriptText = $remoteScript.ToString()
    $parallelResults = $Dcs | ForEach-Object -ThrottleLimit $script:DcParallelThrottle -Parallel {
        $dc = $_
        $rs = [scriptblock]::Create($using:remoteScriptText)
        Write-Host ("    [..] Querying KDC default on {0}" -f $dc) -ForegroundColor DarkGray
        try {
            $rawResult = Invoke-Command -ComputerName $dc -ScriptBlock $rs -ErrorAction Stop
            [PSCustomObject]@{ Dc = $dc; Computer = $rawResult.Computer; RawValue = $rawResult.RawValue; Failed = $false }
        } catch {
            Write-Host ("    [XX] {0} -> failed to query registry: {1}" -f $dc, $_.Exception.Message) -ForegroundColor Red
            [PSCustomObject]@{ Dc = $dc; Computer = $dc; RawValue = $null; Failed = $true }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $parallelResults) {
        if ($r.Failed) {
            $rows.Add([PSCustomObject]@{
                Computer = $r.Computer
                RawValue = '(n/a)'
                Decoded  = '(error)'
                Status   = 'Failed'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
            }) | Out-Null
            continue
        }

        $status = Get-KdcDefaultStatus -Value $r.RawValue
        Write-TaskMessage -Message ("{0} -> {1}" -f $r.Computer, $status) -Color $(if ($status -like 'Compliant*') { 'Green' } else { 'Yellow' })
        $rows.Add([PSCustomObject]@{
            Computer = $r.Computer
            RawValue = if ($null -ne $r.RawValue) { '0x{0:X}' -f [int]$r.RawValue } else { '(absent)' }
            Decoded  = Convert-EncryptionFlagsToText -Value $r.RawValue
            Status   = $status
            RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
        }) | Out-Null
    }

    return $rows
}

function Get-Rc4DisablementPhaseAudit {
    param([string[]]$Dcs)

    $remoteScript = {
        $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
        $name = 'RC4DefaultDisablementPhase'
        $raw  = $null

        if (Test-Path -Path $path) {
            try {
                $raw = (Get-ItemProperty -Path $path -ErrorAction Stop).$name
            } catch {
                $raw = $null
            }
        }

        [PSCustomObject]@{
            Computer = $env:COMPUTERNAME
            RawValue = $raw
        }
    }

    $remoteScriptText = $remoteScript.ToString()
    $parallelResults = $Dcs | ForEach-Object -ThrottleLimit $script:DcParallelThrottle -Parallel {
        $dc = $_
        $rs = [scriptblock]::Create($using:remoteScriptText)
        Write-Host ("    [..] Querying RC4DefaultDisablementPhase on {0}" -f $dc) -ForegroundColor DarkGray
        try {
            $rawResult = Invoke-Command -ComputerName $dc -ScriptBlock $rs -ErrorAction Stop
            [PSCustomObject]@{ Dc = $dc; Computer = $rawResult.Computer; RawValue = $rawResult.RawValue; Failed = $false }
        } catch {
            Write-Host ("    [XX] {0} -> failed to query registry: {1}" -f $dc, $_.Exception.Message) -ForegroundColor Red
            [PSCustomObject]@{ Dc = $dc; Computer = $dc; RawValue = $null; Failed = $true }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in $parallelResults) {
        if ($r.Failed) {
            $rows.Add([PSCustomObject]@{
                Computer     = $r.Computer
                RawValue     = '(n/a)'
                Phase        = $null
                PhaseLabel   = '(error)'
                Status       = 'Failed'
                RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\RC4DefaultDisablementPhase'
            }) | Out-Null
            continue
        }

        $statusObj = Get-Rc4DisablementPhaseStatus -Value $r.RawValue
        $color = if ($statusObj.Status -like 'Compliant*') { 'Green' }
                 elseif ($statusObj.Status -like 'Warning*') { 'Yellow' }
                 else { 'Gray' }
        Write-TaskMessage -Message ("{0} -> {1}" -f $r.Computer, $statusObj.Label) -Color $color
        $rows.Add([PSCustomObject]@{
            Computer     = $r.Computer
            RawValue     = if ($null -ne $r.RawValue) { [string]$r.RawValue } else { '(absent)' }
            Phase        = $statusObj.Phase
            PhaseLabel   = $statusObj.Label
            Status       = $statusObj.Status
            RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\RC4DefaultDisablementPhase'
        }) | Out-Null
    }

    return $rows
}

function Get-AccountKerberosAudit {
    param([bool]$KdcDefaultsExplicitAesOnly = $false)

    $rows = New-Object System.Collections.Generic.List[object]

    $userProps = @('msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'userAccountControl', 'pwdLastSet', 'lastLogonDate', 'distinguishedName')

    Write-TaskMessage -Message 'Enumerating AD users...' -Color DarkGray
    $users = @(Get-ADUser -Filter * -Properties $userProps -ErrorAction Stop)
    Write-TaskMessage -Message ("Users loaded: {0}" -f $users.Count) -Color Green
    foreach ($user in $users) {
        $encValue = if ($null -ne $user.'msDS-SupportedEncryptionTypes') { [int]$user.'msDS-SupportedEncryptionTypes' } else { $null }
        $rows.Add([PSCustomObject]@{
            Name = $user.SamAccountName
            Category = 'User/Service'
            Enabled = [bool](Get-ObjectEnabledState -UserAccountControl ([int]$user.userAccountControl))
            HasSPN = [bool]$user.servicePrincipalName
            EncValue = $encValue
            EncHex = if ($null -ne $encValue) { '0x{0:X}' -f $encValue } else { '(absent/0)' }
            Flags = Convert-EncryptionFlagsToText -Value $encValue
            Status = Get-EncStatus -Value $encValue -Category 'User/Service' -HasSPN ([bool]$user.servicePrincipalName) -KdcDefaultsExplicitAesOnly $KdcDefaultsExplicitAesOnly
            DistinguishedName = $user.DistinguishedName
            PasswordLastSet = if ($user.pwdLastSet) { [datetime]::FromFileTime([int64]$user.pwdLastSet) } else { $null }
            LastLogonDate = $user.LastLogonDate
            SPNs = if ($user.servicePrincipalName) { $user.servicePrincipalName -join '; ' } else { '' }
        }) | Out-Null
    }

    $computerProps = @('msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'userAccountControl', 'pwdLastSet', 'lastLogonDate', 'distinguishedName', 'dNSHostName')
    Write-TaskMessage -Message 'Enumerating AD computers...' -Color DarkGray
    $computers = @(Get-ADComputer -Filter * -Properties $computerProps -ErrorAction Stop)
    Write-TaskMessage -Message ("Computers loaded: {0}" -f $computers.Count) -Color Green
    foreach ($computer in $computers) {
        $encValue = if ($null -ne $computer.'msDS-SupportedEncryptionTypes') { [int]$computer.'msDS-SupportedEncryptionTypes' } else { $null }
        $rows.Add([PSCustomObject]@{
            Name = $computer.SamAccountName
            Category = 'Computer'
            Enabled = [bool](Get-ObjectEnabledState -UserAccountControl ([int]$computer.userAccountControl))
            HasSPN = [bool]$computer.servicePrincipalName
            EncValue = $encValue
            EncHex = if ($null -ne $encValue) { '0x{0:X}' -f $encValue } else { '(absent/0)' }
            Flags = Convert-EncryptionFlagsToText -Value $encValue
            Status = Get-EncStatus -Value $encValue -Category 'Computer' -HasSPN ([bool]$computer.servicePrincipalName) -KdcDefaultsExplicitAesOnly $KdcDefaultsExplicitAesOnly
            DistinguishedName = $computer.DistinguishedName
            PasswordLastSet = if ($computer.pwdLastSet) { [datetime]::FromFileTime([int64]$computer.pwdLastSet) } else { $null }
            LastLogonDate = $computer.LastLogonDate
            SPNs = if ($computer.servicePrincipalName) { $computer.servicePrincipalName -join '; ' } else { '' }
        }) | Out-Null
    }

    try {
        Write-TaskMessage -Message 'Enumerating managed service accounts...' -Color DarkGray
        $serviceAccounts = @(Get-ADServiceAccount -Filter * -Properties 'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'distinguishedName', 'SamAccountName', 'ObjectClass' -ErrorAction Stop)
        Write-TaskMessage -Message ("Managed service accounts loaded: {0}" -f $serviceAccounts.Count) -Color Green
        foreach ($serviceAccount in $serviceAccounts) {
            $encValue = if ($null -ne $serviceAccount.'msDS-SupportedEncryptionTypes') { [int]$serviceAccount.'msDS-SupportedEncryptionTypes' } else { $null }
            $rows.Add([PSCustomObject]@{
                Name = $serviceAccount.SamAccountName
                Category = Get-ObjectCategory -ObjectClass ([string]$serviceAccount.ObjectClass)
                Enabled = $true
                HasSPN = [bool]$serviceAccount.servicePrincipalName
                EncValue = $encValue
                EncHex = if ($null -ne $encValue) { '0x{0:X}' -f $encValue } else { '(absent/0)' }
                Flags = Convert-EncryptionFlagsToText -Value $encValue
                Status = Get-EncStatus -Value $encValue -Category (Get-ObjectCategory -ObjectClass ([string]$serviceAccount.ObjectClass)) -HasSPN ([bool]$serviceAccount.servicePrincipalName) -KdcDefaultsExplicitAesOnly $KdcDefaultsExplicitAesOnly
                DistinguishedName = $serviceAccount.DistinguishedName
                PasswordLastSet = $null
                LastLogonDate = $null
                SPNs = if ($serviceAccount.servicePrincipalName) { $serviceAccount.servicePrincipalName -join '; ' } else { '' }
            }) | Out-Null
        }
    } catch {
        Write-TaskMessage -Message ("Managed service account enumeration failed: {0}" -f $_.Exception.Message) -Color Yellow
    }

    return $rows
}

function Get-KerberosEventAudit {
    param(
        [string[]]$Dcs,
        [int]$LookbackHours,
        [int]$MaxEvents
    )

    $rawEvents = @()
    $errors = @()

    $remoteScript = {
        param([int]$HoursBack, [int]$MaxEventsPerDc)

        $since = (Get-Date).AddHours(-1 * $HoursBack)
        $filter = @{
            LogName = 'Security'
            Id = 4768, 4769
            StartTime = $since
            ProviderName = 'Microsoft-Windows-Security-Auditing'
        }

        function Get-EventFieldValue {
            param(
                [xml]$Xml,
                [string]$Name
            )

            return ($Xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
        }

        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerDc -ErrorAction Stop)
        $output = foreach ($eventRecord in $events) {
            $xml = [xml]$eventRecord.ToXml()
            $encRaw = Get-EventFieldValue -Xml $xml -Name 'TicketEncryptionType'
            $account = Get-EventFieldValue -Xml $xml -Name 'TargetUserName'
            if ([string]::IsNullOrWhiteSpace($account)) {
                $account = Get-EventFieldValue -Xml $xml -Name 'Account Name'
            }
            $clientIp = Get-EventFieldValue -Xml $xml -Name 'ClientAddress'
            if ([string]::IsNullOrWhiteSpace($clientIp)) {
                $clientIp = Get-EventFieldValue -Xml $xml -Name 'IpAddress'
            }
            if ($clientIp) {
                $clientIp = $clientIp.Replace('::ffff:', '')
            }

            [PSCustomObject]@{
                DC = $env:COMPUTERNAME
                Time = $eventRecord.TimeCreated
                EventId = $eventRecord.Id
                TicketType = if ($eventRecord.Id -eq 4768) { 'TGT' } elseif ($eventRecord.Id -eq 4769) { 'TGS' } else { 'UNKNOWN' }
                Account = if ($account) { $account } else { '(n/a)' }
                Service = if ($eventRecord.Id -eq 4769) { (Get-EventFieldValue -Xml $xml -Name 'ServiceName') } else { '(n/a)' }
                ServiceSid = if ($eventRecord.Id -eq 4769) { (Get-EventFieldValue -Xml $xml -Name 'ServiceSid') } else { $null }
                ClientIP = if ($clientIp) { $clientIp } else { '(n/a)' }
                EncHex = if ($encRaw) { $encRaw } else { '(unknown)' }
                ServiceAvailableKeys = Get-EventFieldValue -Xml $xml -Name 'ServiceAvailableKeys'
                ClientAdvertizedEncryption = Get-EventFieldValue -Xml $xml -Name 'ClientAdvertizedEncryptionTypes'
                DCSupportedEncryptionTypes = Get-EventFieldValue -Xml $xml -Name 'DCSupportedEncryptionTypes'
                # Post-January-2025 fields (KB5051987 + KB5052006). Multiple candidate names because
                # Microsoft has used slightly different spellings across cumulative updates.
                PreAuthEncryptionType = $(
                    $v = Get-EventFieldValue -Xml $xml -Name 'PreAuthEncryptionType'
                    if (-not $v) { $v = Get-EventFieldValue -Xml $xml -Name 'PreAuthType' }
                    if (-not $v) { $v = Get-EventFieldValue -Xml $xml -Name 'PreAuthenticationEncryptionType' }
                    $v
                )
                SessionKeyEncryptionType = $(
                    $v = Get-EventFieldValue -Xml $xml -Name 'SessionKeyEncryptionType'
                    if (-not $v) { $v = Get-EventFieldValue -Xml $xml -Name 'SessionEncryptionType' }
                    if (-not $v) { $v = Get-EventFieldValue -Xml $xml -Name 'SessionKeyEncType' }
                    $v
                )
            }
        }

        return $output
    }

    # Parallel per-DC collection. Each iteration emits a single [PSCustomObject] containing the
    # event batch and any error string. Aggregation happens in the main thread after the pipeline.
    # Scriptblock is converted to text and rebuilt inside each runspace (PS 7 -Parallel limitation).
    $remoteScriptText = $remoteScript.ToString()
    $parallelResults = $Dcs | ForEach-Object -ThrottleLimit $script:DcParallelThrottle -Parallel {
        $dc  = $_
        $rs  = [scriptblock]::Create($using:remoteScriptText)
        $hrs = $using:LookbackHours
        $max = $using:MaxEvents
        Write-Host ("    [..] Collecting 4768/4769 from {0}" -f $dc) -ForegroundColor DarkGray
        try {
            $dcEvents = @(Invoke-Command -ComputerName $dc -ScriptBlock $rs -ArgumentList $hrs, $max -ErrorAction Stop)
            Write-Host ("    [OK] {0} -> {1} event(s) collected" -f $dc, $dcEvents.Count) -ForegroundColor Green
            [PSCustomObject]@{ Events = $dcEvents; Error = $null }
        } catch {
            Write-Host ("    [!!] {0} -> collection failed" -f $dc) -ForegroundColor Yellow
            [PSCustomObject]@{ Events = @(); Error = ("Failed to collect 4768/4769 from {0}: {1}" -f $dc, $_.Exception.Message) }
        }
    }

    foreach ($r in $parallelResults) {
        if ($r.Events -and $r.Events.Count -gt 0) { $rawEvents += $r.Events }
        if ($r.Error) { $errors += $r.Error }
    }

    foreach ($item in @($rawEvents)) {
        Add-Member -InputObject $item -MemberType NoteProperty -Name EncType -Value (Get-EncTypeLabel -Value $item.EncHex) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name ClientSupportsAES -Value ([bool]($item.ClientAdvertizedEncryption -match 'AES')) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name ServiceHasAESKeys -Value ([bool]($item.ServiceAvailableKeys -match 'AES')) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name DCSupportsAES -Value ([bool]($item.DCSupportedEncryptionTypes -match 'AES')) -Force
        $avoidable = ($item.TicketType -eq 'TGS' -and $item.EncType -eq 'RC4-HMAC' -and $item.ClientSupportsAES -and $item.ServiceHasAESKeys -and $item.DCSupportsAES)
        Add-Member -InputObject $item -MemberType NoteProperty -Name RC4ChosenWhileAESAvailable -Value $avoidable -Force
        # Post-Jan-2025 enriched signals (label + decoupled session key etype)
        $preAuthLabel = if ($item.PreAuthEncryptionType) { Get-EncTypeLabel -Value $item.PreAuthEncryptionType } else { '' }
        $sessionKeyLabel = if ($item.SessionKeyEncryptionType) { Get-EncTypeLabel -Value $item.SessionKeyEncryptionType } else { '' }
        Add-Member -InputObject $item -MemberType NoteProperty -Name PreAuthEncType -Value $preAuthLabel -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name SessionKeyEncType -Value $sessionKeyLabel -Force
        # Misconfigured-client signal: pre-auth was done with AES but the issued ticket etype is RC4 —
        # this means the client *can* do AES (proven by pre-auth) but something forced RC4 down the line.
        $misconfiguredClient = ($preAuthLabel -like 'AES*' -and $item.EncType -eq 'RC4-HMAC')
        Add-Member -InputObject $item -MemberType NoteProperty -Name MisconfiguredClientSignal -Value $misconfiguredClient -Force
    }

    return [PSCustomObject]@{
        RawEvents = @($rawEvents)
        Errors = @($errors)
    }
}

function Get-KdcsvcEventAudit {
    param(
        [string[]]$Dcs,
        [int]$LookbackHours,
        [int]$MaxEvents
    )

    $rawEvents = @()
    $errors    = @()

    $remoteScript = {
        param([int]$HoursBack, [int]$MaxEventsPerDc)

        $since  = (Get-Date).AddHours(-1 * $HoursBack)
        $filter = @{
            LogName      = 'System'
            Id           = 201, 202, 203, 204, 205, 206, 207, 208, 209
            StartTime    = $since
            ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
        }

        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEventsPerDc -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -like '*No events were found*') {
                return @()
            }
            throw
        }

        $output = foreach ($eventRecord in $events) {
            $xml    = [xml]$eventRecord.ToXml()
            $fields = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) {
                    $fields[$d.Name] = $d.'#text'
                }
            }

            $accountName = $fields['AccountName']
            if (-not $accountName) { $accountName = $fields['UserName'] }
            if (-not $accountName) { $accountName = $fields['TargetAccount'] }
            if (-not $accountName) { $accountName = '(unparsed)' }

            $serviceName = $fields['ServiceName']
            if (-not $serviceName) { $serviceName = $fields['ServiceSid'] }
            if (-not $serviceName) { $serviceName = '' }

            $clientAddress = $fields['ClientAddress']
            if (-not $clientAddress) { $clientAddress = $fields['IpAddress'] }
            if (-not $clientAddress) { $clientAddress = '' }

            [PSCustomObject]@{
                DC          = $env:COMPUTERNAME
                Time        = $eventRecord.TimeCreated
                EventId     = [int]$eventRecord.Id
                Level       = $eventRecord.LevelDisplayName
                Account     = $accountName
                Service     = $serviceName
                ClientAddr  = $clientAddress
                Message     = $eventRecord.Message
            }
        }

        return $output
    }

    $remoteScriptText = $remoteScript.ToString()
    $parallelResults = $Dcs | ForEach-Object -ThrottleLimit $script:DcParallelThrottle -Parallel {
        $dc  = $_
        $rs  = [scriptblock]::Create($using:remoteScriptText)
        $hrs = $using:LookbackHours
        $max = $using:MaxEvents
        Write-Host ("    [..] Collecting Kdcsvc 201-209 from {0}" -f $dc) -ForegroundColor DarkGray
        try {
            $dcEvents = @(Invoke-Command -ComputerName $dc -ScriptBlock $rs -ArgumentList $hrs, $max -ErrorAction Stop)
            $color = if ($dcEvents.Count -eq 0) { 'Green' } else { 'Yellow' }
            Write-Host ("    [OK] {0} -> {1} Kdcsvc event(s) collected" -f $dc, $dcEvents.Count) -ForegroundColor $color
            [PSCustomObject]@{ Events = $dcEvents; Error = $null }
        } catch {
            Write-Host ("    [!!] {0} -> Kdcsvc collection failed" -f $dc) -ForegroundColor Yellow
            [PSCustomObject]@{ Events = @(); Error = ("Failed to collect Kdcsvc 201-209 from {0}: {1}" -f $dc, $_.Exception.Message) }
        }
    }

    foreach ($r in $parallelResults) {
        if ($r.Events -and $r.Events.Count -gt 0) { $rawEvents += $r.Events }
        if ($r.Error) { $errors += $r.Error }
    }

    # Pattern map (see Article 1 §6 grid)
    $patternMap = @{
        201 = @{ Pattern = 'B';       Cause = 'client RC4-only';                                          Policy = 'implicit'; Severity = 'Audit'   }
        202 = @{ Pattern = 'D';       Cause = 'service has no AES key (stale-key trap)';                  Policy = 'implicit'; Severity = 'Audit'   }
        203 = @{ Pattern = 'B';       Cause = 'client RC4-only';                                          Policy = 'implicit'; Severity = 'Enforce' }
        204 = @{ Pattern = 'D';       Cause = 'service has no AES key (stale-key trap)';                  Policy = 'implicit'; Severity = 'Enforce' }
        205 = @{ Pattern = 'Hygiene'; Cause = 'DC has explicit insecure DefaultDomainSupportedEncTypes';  Policy = 'n/a';      Severity = 'Hygiene' }
        206 = @{ Pattern = 'B';       Cause = 'client RC4-only';                                          Policy = 'explicit'; Severity = 'Audit'   }
        207 = @{ Pattern = 'D';       Cause = 'service has no AES key (stale-key trap)';                  Policy = 'explicit'; Severity = 'Audit'   }
        208 = @{ Pattern = 'B';       Cause = 'client RC4-only';                                          Policy = 'explicit'; Severity = 'Enforce' }
        209 = @{ Pattern = 'D';       Cause = 'service has no AES key (stale-key trap)';                  Policy = 'explicit'; Severity = 'Enforce' }
    }

    foreach ($item in @($rawEvents)) {
        $info = $patternMap[[int]$item.EventId]
        if ($info) {
            Add-Member -InputObject $item -MemberType NoteProperty -Name Pattern  -Value $info.Pattern  -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Cause    -Value $info.Cause    -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Policy   -Value $info.Policy   -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Severity -Value $info.Severity -Force
        } else {
            Add-Member -InputObject $item -MemberType NoteProperty -Name Pattern  -Value '(unknown)' -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Cause    -Value '(unknown)' -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Policy   -Value 'n/a'       -Force
            Add-Member -InputObject $item -MemberType NoteProperty -Name Severity -Value 'Info'      -Force
        }
    }

    return [PSCustomObject]@{
        RawEvents = @($rawEvents)
        Errors    = @($errors)
    }
}

function Resolve-AdPrincipalSummary {
    param([string]$Identity)

    if ([string]::IsNullOrWhiteSpace($Identity) -or $Identity -eq '(n/a)' -or $Identity -eq '(unreachable)') {
        return $null
    }

    $principal = $null
    $category = $null
    $normalizedIdentity = $Identity
    $localPart = if ($Identity -like '*@*') { ($Identity -split '@', 2)[0] } else { $Identity }

    if ($Identity -like '*@*') {
        try {
            $principal = Get-ADUser -Filter "userPrincipalName -eq '$Identity'" -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop
            $category = 'User/Service'
        } catch {
            $principal = $null
        }
    }

    if (-not $principal) {
        try {
            $principal = Get-ADUser -Identity $normalizedIdentity -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop
            $category = 'User/Service'
        } catch {
            try {
                $principal = Get-ADComputer -Identity $normalizedIdentity -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop
                $category = 'Computer'
            } catch {
                try {
                    $principal = Get-ADServiceAccount -Identity $normalizedIdentity -Properties 'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'distinguishedName', 'SamAccountName', 'ObjectClass' -ErrorAction Stop
                    $category = Get-ObjectCategory -ObjectClass ([string]$principal.ObjectClass)
                } catch {
                    $principal = $null
                }
            }
        }
    }

    if (-not $principal -and -not [string]::IsNullOrWhiteSpace($localPart) -and $localPart -ne $Identity) {
        foreach ($resolver in @(
            { Get-ADUser -Identity $localPart -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADComputer -Identity $localPart -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADServiceAccount -Identity $localPart -Properties 'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'distinguishedName', 'SamAccountName', 'ObjectClass' -ErrorAction Stop }
        )) {
            try {
                $principal = & $resolver
                if ($principal) {
                    break
                }
            } catch {
            }
        }

        if ($principal) {
            if ($principal.ObjectClass -eq 'computer') {
                $category = 'Computer'
            } elseif ($principal.ObjectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
                $category = Get-ObjectCategory -ObjectClass ([string]$principal.ObjectClass)
            } else {
                $category = 'User/Service'
            }
        }
    }

    if (-not $principal) {
        return $null
    }

    $encValue = if ($null -ne $principal.'msDS-SupportedEncryptionTypes') { [int]$principal.'msDS-SupportedEncryptionTypes' } else { $null }
    return [PSCustomObject]@{
        Identity = $Identity
        Category = $category
        SamAccountName = $principal.SamAccountName
        DistinguishedName = $principal.DistinguishedName
        EncHex = if ($null -ne $encValue) { '0x{0:X}' -f $encValue } else { '(absent/0)' }
        Status = Get-EncStatus -Value $encValue -Category $category -HasSPN ([bool]$principal.servicePrincipalName)
        PasswordLastSet = if ($principal.pwdLastSet) { [datetime]::FromFileTime([int64]$principal.pwdLastSet) } else { $null }
        LastLogonDate = $principal.LastLogonDate
        SPNs = if ($principal.servicePrincipalName) { $principal.servicePrincipalName -join '; ' } else { '' }
    }
}

function Resolve-AdServiceTargetSummary {
    param(
        [string]$ServiceSid,
        [string]$ServiceSpn
    )

    $principal = $null
    $category = $null

    if (-not [string]::IsNullOrWhiteSpace($ServiceSid)) {
        foreach ($resolver in @(
            { Get-ADUser -Filter "objectSid -eq '$ServiceSid'" -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADComputer -Filter "objectSid -eq '$ServiceSid'" -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADServiceAccount -Filter "objectSid -eq '$ServiceSid'" -Properties 'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'distinguishedName', 'SamAccountName', 'ObjectClass' -ErrorAction Stop }
        )) {
            try {
                $principal = & $resolver
                if ($principal) { break }
            } catch {
            }
        }
    }

    if (-not $principal -and -not [string]::IsNullOrWhiteSpace($ServiceSpn)) {
        try {
            $principal = Get-ADObject -LDAPFilter ("(servicePrincipalName={0})" -f $ServiceSpn) -Properties 'objectClass', 'SamAccountName', 'DistinguishedName', 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop
        } catch {
            $principal = $null
        }
    }

    if (-not $principal -and -not [string]::IsNullOrWhiteSpace($ServiceSpn)) {
        foreach ($resolver in @(
            { Get-ADUser -Filter "samAccountName -eq '$ServiceSpn'" -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADComputer -Filter "samAccountName -eq '$ServiceSpn'" -Properties 'pwdLastSet', 'msDS-SupportedEncryptionTypes', 'lastLogonDate', 'userAccountControl', 'servicePrincipalName' -ErrorAction Stop },
            { Get-ADServiceAccount -Filter "samAccountName -eq '$ServiceSpn'" -Properties 'msDS-SupportedEncryptionTypes', 'servicePrincipalName', 'distinguishedName', 'SamAccountName', 'ObjectClass' -ErrorAction Stop }
        )) {
            try {
                $principal = & $resolver
                if ($principal) { break }
            } catch {
            }
        }
    }

    if (-not $principal) {
        return $null
    }

    $principalClass = if ($principal.PSObject.Properties['ObjectClass']) { [string]$principal.ObjectClass } else { [string]$principal.objectClass }
    if ($principalClass -eq 'computer') { $category = 'Computer' }
    elseif ($principalClass -eq 'user') { $category = 'User/Service' }
    else { $category = Get-ObjectCategory -ObjectClass $principalClass }

    $encValue = if ($null -ne $principal.'msDS-SupportedEncryptionTypes') { [int]$principal.'msDS-SupportedEncryptionTypes' } else { $null }
    return [PSCustomObject]@{
        ServiceSid = $ServiceSid
        ServiceSpn = $ServiceSpn
        Category = $category
        SamAccountName = $principal.SamAccountName
        DistinguishedName = $principal.DistinguishedName
        EncHex = if ($null -ne $encValue) { '0x{0:X}' -f $encValue } else { '(absent/0)' }
        Status = Get-EncStatus -Value $encValue -Category $category -HasSPN ([bool]$principal.servicePrincipalName)
        PasswordLastSet = if ($principal.PSObject.Properties['pwdLastSet'] -and $principal.pwdLastSet) { [datetime]::FromFileTime([int64]$principal.pwdLastSet) } else { $null }
        LastLogonDate = if ($principal.PSObject.Properties['lastLogonDate']) { $principal.lastLogonDate } else { $null }
        SPNs = if ($principal.PSObject.Properties['servicePrincipalName'] -and $principal.servicePrincipalName) { $principal.servicePrincipalName -join '; ' } else { '' }
    }
}

function Invoke-TrustEncryptionAudit {
    <#
        Wrapper around the sister script Get-TrustEncryptionAudit.ps1.
        Runs it with -ExportJson into a temp file, captures the rows, and
        returns @{ Rows = ...; Errors = ... } so the parent script can fold
        them into $results.Trusts. Read-only by construction.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$SisterScriptPath
    )

    $rows   = New-Object System.Collections.Generic.List[object]
    $errors = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -Path $SisterScriptPath)) {
        $errors.Add("Trust audit sister script not found at: $SisterScriptPath") | Out-Null
        return @{ Rows = $rows; Errors = $errors }
    }

    $tempJson = Join-Path -Path $env:TEMP -ChildPath ("trust-audit-{0}.json" -f ([guid]::NewGuid().ToString('N')))
    try {
        Write-TaskMessage -Message ("Invoking sister script: {0}" -f $SisterScriptPath) -Color DarkGray
        & $SisterScriptPath -ExportJson $tempJson | Out-Null

        if (Test-Path -Path $tempJson) {
            $raw = Get-Content -Path $tempJson -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
                # ConvertFrom-Json may return a single object instead of an array if the dataset has one row
                if ($parsed -isnot [System.Collections.IEnumerable] -or $parsed -is [string]) {
                    $parsed = @($parsed)
                }
                foreach ($row in $parsed) { $rows.Add($row) | Out-Null }
            }
        } else {
            $errors.Add("Trust audit produced no JSON output (no trusts in this domain or sister script returned early).") | Out-Null
        }
    } catch {
        $errors.Add("Trust audit failed: $($_.Exception.Message)") | Out-Null
    } finally {
        if (Test-Path -Path $tempJson) {
            Remove-Item -Path $tempJson -Force -ErrorAction SilentlyContinue
        }
    }

    return @{ Rows = $rows; Errors = $errors }
}

function Build-Rc4Backlog {
    <#
        Produces the §0 deliverable: one row per RC4 dependency with deterministic
        Blast-radius / Exposure / Fix-cost scoring (1-9). Inputs come from $Results
        already populated by earlier steps:
            - $Results.Rc4TargetServices  -> rows for services receiving RC4 TGS
            - $Results.Trusts             -> rows for TDOs not in AES-only state
            - $Results.Rc4RequestorAccounts -> rows for clients still requesting RC4
        $OwnerMapping is a hashtable Pattern -> Owner where Pattern supports * wildcards.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Results,

        [hashtable]$OwnerMapping = @{}
    )

    $backlog = New-Object System.Collections.Generic.List[object]

    # Helper: resolve owner from mapping using wildcard match (-like). First match wins.
    function Resolve-BacklogOwner {
        param([string]$Dependency, [hashtable]$Mapping)
        if (-not $Mapping -or $Mapping.Count -eq 0) { return 'TBD' }
        foreach ($pattern in $Mapping.Keys) {
            if ($Dependency -like $pattern) { return $Mapping[$pattern] }
        }
        return 'TBD'
    }

    # Helper: map verbal labels to numeric weights per §4 of Article 2
    $blastWeight    = @{ 'Critical' = 3; 'Important' = 2; 'Standard' = 1 }
    $exposureWeight = @{ 'Frequent' = 3; 'Occasional' = 2; 'Rare' = 1 }
    $fixCostWeight  = @{ 'Low' = 3; 'Medium' = 2; 'High' = 1 }

    # ---------------------------------------------------------------
    # Source 1: services receiving RC4 TGS (Rc4TargetServices)
    # ---------------------------------------------------------------
    foreach ($svc in @($Results.Rc4TargetServices)) {
        $events = [int]$svc.Events
        $sam    = [string]$svc.SamAccountName
        $service = [string]$svc.Service
        $encHex  = [string]$svc.EncHex

        # Type: krbtgt/<REALM> means cross-realm referral, handled in trust block too;
        # account ending in $ = computer; otherwise service account
        $type = if ($service -like 'krbtgt/*') { 'TDO referral' }
                elseif ($sam -like '*$')       { 'Computer account' }
                else                            { 'Service account' }

        # Blast radius: krbtgt referrals and very high volumes -> Critical, otherwise Important
        $blast = if ($type -eq 'TDO referral' -or $events -ge 5000) { 'Critical' }
                 elseif ($events -ge 100)                            { 'Important' }
                 else                                                { 'Standard' }

        # Exposure: based on RC4 ticket count over the observation window
        $exposure = if ($events -ge 500) { 'Frequent' }
                    elseif ($events -ge 50) { 'Occasional' }
                    else { 'Rare' }

        # Fix cost: depends on the account's declared capability (EncHex)
        # - Account is RC4-only declared (0x4) -> High (vendor / app coordination needed)
        # - Account already advertises AES (0x1C, 0x18) -> Medium (likely password rotation + retest)
        # - Anything else (unset, partial) -> Medium
        $fixCost = if ($encHex -match '0x4$' -or $encHex -eq '0x4') { 'High' }
                   elseif ($encHex -match '0x1[8C]') { 'Medium' }
                   else { 'Medium' }

        # Action: tied to fix cost decision tree
        $action = if ($fixCost -eq 'High') {
                      'Migrate consumer to AES (vendor / app track) or document temporary exception'
                  } elseif ($encHex -match '0x18') {
                      'AES already declared - investigate why RC4 still issued (client negotiation, stale key, downstream consumer)'
                  } else {
                      'Set msDS-SupportedEncryptionTypes to 0x18 (AES-only), rotate password to derive AES keys, validate, then drop RC4'
                  }

        $depKey = if ($sam) { $sam } else { $service }

        $score = $blastWeight[$blast] + $exposureWeight[$exposure] + $fixCostWeight[$fixCost]

        $backlog.Add([PSCustomObject]@{
            Dependency   = $depKey
            Type         = $type
            RC4Evidence  = "$events RC4 TGS over $($Results.Hours)h ($encHex declared)"
            BlastRadius  = $blast
            Exposure     = $exposure
            FixCost      = $fixCost
            Score        = $score
            Owner        = Resolve-BacklogOwner -Dependency $depKey -Mapping $OwnerMapping
            Action       = $action
        }) | Out-Null
    }

    # ---------------------------------------------------------------
    # Source 2: trusts not in AES-only state
    # ---------------------------------------------------------------
    foreach ($trust in @($Results.Trusts)) {
        $cls = [string]$trust.Classification
        if ($cls -notin @('RC4-only','Mixed','Unset','Legacy-DES')) { continue }

        $trustName = if ($trust.PSObject.Properties['Trust']) { [string]$trust.Trust }
                     elseif ($trust.PSObject.Properties['Partner']) { [string]$trust.Partner }
                     else { '(unknown trust)' }
        $depKey = "Trust: $trustName"

        # Trusts always score high - cross-realm impact is by definition Critical, and any
        # active trust generates frequent referrals
        $blast    = 'Critical'
        $exposure = 'Frequent'
        $fixCost  = if ($cls -eq 'Legacy-DES') { 'High' } else { 'Medium' }

        $action = "Set msDS-SupportedEncryptionTypes to 0x18 on the TDO and rotate the trust password (BOTH sides). Current state: $cls ($($trust.EncBitsHex))."

        $score = $blastWeight[$blast] + $exposureWeight[$exposure] + $fixCostWeight[$fixCost]

        $backlog.Add([PSCustomObject]@{
            Dependency   = $depKey
            Type         = 'TDO'
            RC4Evidence  = "TDO classification = $cls ($($trust.EncBitsHex)); LastChange $($trust.LastChange)"
            BlastRadius  = $blast
            Exposure     = $exposure
            FixCost      = $fixCost
            Score        = $score
            Owner        = Resolve-BacklogOwner -Dependency $depKey -Mapping $OwnerMapping
            Action       = $action
        }) | Out-Null
    }

    # ---------------------------------------------------------------
    # Source 3: client accounts still requesting RC4 (Pattern B candidates)
    # Only keep the top requestors - low-volume noise belongs in the raw event log,
    # not in the backlog.
    # ---------------------------------------------------------------
    foreach ($req in @($Results.Rc4RequestorAccounts | Where-Object { [int]$_.Events -ge 50 })) {
        $events = [int]$req.Events
        $depKey = [string]$req.Account

        # If the same account already appears as a service target, skip - it would be a duplicate row.
        if ($backlog | Where-Object { $_.Dependency -eq $depKey }) { continue }

        $blast    = if ($events -ge 1000) { 'Important' } else { 'Standard' }
        $exposure = if ($events -ge 500) { 'Frequent' }
                    elseif ($events -ge 100) { 'Occasional' }
                    else { 'Rare' }
        $fixCost  = 'High'   # client-side legacy almost always needs vendor / OS work

        $action = 'Identify the device(s) authenticating with this account (4768 by Client Address) and remediate the legacy stack (OS, krb5.conf, keytab)'

        $score = $blastWeight[$blast] + $exposureWeight[$exposure] + $fixCostWeight[$fixCost]

        $backlog.Add([PSCustomObject]@{
            Dependency   = $depKey
            Type         = 'Client account (Pattern B)'
            RC4Evidence  = "$events RC4 AS/TGS as requestor over $($Results.Hours)h"
            BlastRadius  = $blast
            Exposure     = $exposure
            FixCost      = $fixCost
            Score        = $score
            Owner        = Resolve-BacklogOwner -Dependency $depKey -Mapping $OwnerMapping
            Action       = $action
        }) | Out-Null
    }

    # Sort: highest score first, then alphabetical for stable output
    return @($backlog | Sort-Object @{ Expression = 'Score'; Descending = $true }, Dependency)
}

function Build-HtmlReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $errorCount = $Results.Errors.Count
    $warningCount = $Results.Warnings.Count
    $kdcWarningCount = @($Results.KdcDefaults | Where-Object { $_.Status -like 'Warning*' -or $_.Status -like 'Failed*' }).Count
    $topRc4Targets = @($Results.Rc4TargetServices | Sort-Object Events -Descending | Select-Object -First 3)
    $topPriority = @($Results.PriorityAccounts | Where-Object { $_.Status -like 'Failed*' -or $_.Status -like 'Warning*' } | Select-Object -First 3)
    $rc4Explanation = if ($Results.TotalRc4Events -gt 0) {
        "This section answers two different questions: who was involved in RC4 ticket activity, and which service identities still received RC4 service tickets. The left table is about requestors observed in RC4 events. The right table is about target services for RC4 TGS issuance, which is usually the more actionable remediation view."
    } else {
        "No RC4 events were observed in the selected window, so these tables are empty by design. If that is unexpected, widen the lookback window or check Security log retention on the domain controllers."
    }

    $findingItems = @()
    if ($kdcWarningCount -gt 0) {
        $findingItems += "<div class='finding danger'><strong>KDC baseline:</strong> $kdcWarningCount domain controller(s) still rely on implicit or mixed encryption defaults.</div>"
    }
    if ($Results.AvoidableRc4Tgs -gt 0) {
        $serviceList = if ($topRc4Targets.Count -gt 0) { ($topRc4Targets | ForEach-Object { HtmlEncode $_.Service }) -join ', ' } else { 'see RC4 hotspots' }
        $findingItems += "<div class='finding danger'><strong>Avoidable RC4:</strong> $($Results.AvoidableRc4Tgs) RC4 TGS event(s) look avoidable. Top target(s): $serviceList.</div>"
    }
    if ($topPriority.Count -gt 0) {
        $priorityList = ($topPriority | ForEach-Object { HtmlEncode $_.Name }) -join ', '
        $findingItems += "<div class='finding warn'><strong>Priority accounts:</strong> Highest-interest identities right now: $priorityList.</div>"
    }
    if ($findingItems.Count -eq 0) {
        $findingItems += "<div class='finding good'><strong>Signal:</strong> No immediate high-signal findings were derived from the current dataset.</div>"
    }

    $summaryRows = ''
    foreach ($kpi in $Results.Kpis) {
        $badgeClass = Get-StatusBadgeClass -Status $kpi.Status
        $kpiDescription = if ($kpi.PSObject.Properties['Description']) { [string]$kpi.Description } else { Get-KpiDescription -Kpi $kpi }
        $summaryRows += "<tr><td>$(HtmlEncode $kpi.Name)</td><td style='font-weight:700;'>$(HtmlEncode ([string]$kpi.Value))</td><td>$(HtmlEncode $kpiDescription)</td><td>$(HtmlEncode ([string]$kpi.Target))</td><td><span class='badge $badgeClass'>$(HtmlEncode $kpi.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($summaryRows)) {
        $summaryRows = "<tr><td colspan='5' class='empty'>No KPI data available.</td></tr>"
    }

    $kdcRows = ''
    foreach ($row in $Results.KdcDefaults) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $kdcRows += "<tr><td>$(HtmlEncode $row.Computer)</td><td>$(HtmlEncode $row.RawValue)</td><td>$(HtmlEncode $row.Decoded)</td><td>$(HtmlEncode (Get-KdcDefaultExplanation -Row $row))</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($kdcRows)) {
        $kdcRows = "<tr><td colspan='5' class='empty'>No KDC data collected.</td></tr>"
    }

    $phaseRows = ''
    foreach ($row in $Results.Rc4DisablementPhase) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $phaseRows += "<tr><td>$(HtmlEncode $row.Computer)</td><td>$(HtmlEncode ([string]$row.RawValue))</td><td>$(HtmlEncode $row.PhaseLabel)</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($phaseRows)) {
        $phaseRows = "<tr><td colspan='4' class='empty'>No RC4DefaultDisablementPhase data collected.</td></tr>"
    }

    $kdcsvcSummaryRowsHtml = ''
    foreach ($row in $Results.KdcsvcSummary) {
        $sevBadge = if ($row.Severity -eq 'Enforce') { 'fail' } elseif ($row.Severity -eq 'Audit') { 'warn' } elseif ($row.Severity -eq 'Hygiene') { 'info' } else { 'info' }
        $kdcsvcSummaryRowsHtml += "<tr><td>$(HtmlEncode $row.DC)</td><td>$($row.EventId)</td><td><span class='badge $sevBadge'>$(HtmlEncode $row.Pattern)</span></td><td>$(HtmlEncode $row.Cause)</td><td><span class='badge $sevBadge'>$(HtmlEncode $row.Severity)</span></td><td style='font-weight:700;'>$($row.Count)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($kdcsvcSummaryRowsHtml)) {
        $kdcsvcSummaryRowsHtml = "<tr><td colspan='6' class='empty'>No Kdcsvc 201-209 events collected. Either no DC is at Phase >= 1, or no RC4 negotiations were observed during the window.</td></tr>"
    }

    $kdcsvcTopDisplayLimit = 100
    $kdcsvcTopRowsRaw = @($Results.KdcsvcEvents | Sort-Object Time -Descending | Select-Object -First $kdcsvcTopDisplayLimit)
    $kdcsvcTopEventsRowsHtml = ''
    foreach ($row in $kdcsvcTopRowsRaw) {
        $sevBadge = if ($row.Severity -eq 'Enforce') { 'fail' } elseif ($row.Severity -eq 'Audit') { 'warn' } elseif ($row.Severity -eq 'Hygiene') { 'info' } else { 'info' }
        $timeText = if ($row.Time) { $row.Time.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $kdcsvcTopEventsRowsHtml += "<tr><td>$(HtmlEncode $timeText)</td><td>$(HtmlEncode $row.DC)</td><td>$($row.EventId)</td><td><span class='badge $sevBadge'>$(HtmlEncode $row.Pattern)</span></td><td>$(HtmlEncode ([string]$row.Account))</td><td>$(HtmlEncode ([string]$row.Service))</td><td>$(HtmlEncode ([string]$row.ClientAddr))</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($kdcsvcTopEventsRowsHtml)) {
        $kdcsvcTopEventsRowsHtml = "<tr><td colspan='7' class='empty'>No Kdcsvc 201-209 events to show.</td></tr>"
    }
    $kdcsvcTopRowsNote = if ($Results.KdcsvcEvents.Count -gt $kdcsvcTopDisplayLimit) {
        "Showing the most recent $kdcsvcTopDisplayLimit events out of $($Results.KdcsvcEvents.Count). Use the JSON or CSV artifact for the full dataset."
    } else {
        "Showing all $($Results.KdcsvcEvents.Count) Kdcsvc events collected in this run."
    }

    $trustsRowsHtml = ''
    foreach ($row in $Results.Trusts) {
        $cls = [string]$row.Classification
        $sevBadge = switch ($cls) {
            'AES-only'   { 'pass'; break }
            'Mixed'      { 'warn'; break }
            'RC4-only'   { 'fail'; break }
            'Legacy-DES' { 'fail'; break }
            'Unset'      { 'warn'; break }
            default      { 'info' }
        }
        $trustName = if ($row.PSObject.Properties['Trust']) { [string]$row.Trust } else { '(unnamed)' }
        $encBits   = if ($row.PSObject.Properties['EncBitsHex']) { [string]$row.EncBitsHex } else { '' }
        $encFlags  = if ($row.PSObject.Properties['EncFlags']) { [string]$row.EncFlags } else { '' }
        $lastChg   = if ($row.PSObject.Properties['LastChange'] -and $row.LastChange) { [string]$row.LastChange } else { '' }
        $trustsRowsHtml += "<tr><td>$(HtmlEncode $trustName)</td><td><span class='badge $sevBadge'>$(HtmlEncode $cls)</span></td><td>$(HtmlEncode $encBits)</td><td>$(HtmlEncode $encFlags)</td><td>$(HtmlEncode $lastChg)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($trustsRowsHtml)) {
        $trustsRowsHtml = "<tr><td colspan='5' class='empty'>No trust inventory data. Run with <span class='mono'>-IncludeTrusts</span> to invoke <span class='mono'>Get-TrustEncryptionAudit.ps1</span>.</td></tr>"
    }

    $backlogDisplayLimit = 200
    $backlogDisplayRows = @($Results.Backlog | Select-Object -First $backlogDisplayLimit)
    $backlogRowsHtml = ''
    foreach ($row in $backlogDisplayRows) {
        $scoreBadge = if ($row.Score -ge 8) { 'fail' } elseif ($row.Score -ge 6) { 'warn' } else { 'info' }
        $brBadge = switch ($row.BlastRadius) {
            'Critical'  { 'fail' }
            'Important' { 'warn' }
            default     { 'info' }
        }
        $backlogRowsHtml += "<tr><td>$(HtmlEncode $row.Dependency)</td><td>$(HtmlEncode $row.Type)</td><td>$(HtmlEncode $row.RC4Evidence)</td><td><span class='badge $brBadge'>$(HtmlEncode $row.BlastRadius)</span></td><td>$(HtmlEncode $row.Exposure)</td><td>$(HtmlEncode $row.FixCost)</td><td><span class='badge $scoreBadge'>$($row.Score)</span></td><td>$(HtmlEncode $row.Owner)</td><td>$(HtmlEncode $row.Action)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($backlogRowsHtml)) {
        $backlogRowsHtml = "<tr><td colspan='9' class='empty'>No backlog rows scored. Either no remediation items were found, or capability is already AES-only across the estate.</td></tr>"
    }
    $backlogRowsNote = if ($Results.Backlog.Count -gt $backlogDisplayLimit) {
        "Showing the first $backlogDisplayLimit backlog rows out of $($Results.Backlog.Count). Use <span class='mono'>Backlog.csv</span> for the full dataset."
    } else {
        "Showing all $($Results.Backlog.Count) backlog rows scored in this run."
    }

    $priorityDisplayLimit = 200
    $priorityDisplayRows = @($Results.PriorityAccounts | Select-Object -First $priorityDisplayLimit)
    $priorityRows = ''
    foreach ($row in $priorityDisplayRows) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $priorityRows += "<tr><td>$(HtmlEncode $row.Name)</td><td>$(HtmlEncode $row.Category)</td><td>$($row.Enabled)</td><td>$($row.HasSPN)</td><td>$(HtmlEncode $row.EncHex)</td><td>$(HtmlEncode $row.Flags)</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($priorityRows)) {
        $priorityRows = "<tr><td colspan='7' class='empty'>No priority accounts identified.</td></tr>"
    }
    $priorityRowsNote = if ($Results.PriorityAccounts.Count -gt $priorityDisplayLimit) {
        "Showing the first $priorityDisplayLimit priority accounts out of $($Results.PriorityAccounts.Count). Use the JSON or CSV artifact for the full dataset."
    } else {
        "Showing all $($Results.PriorityAccounts.Count) priority accounts identified in this run."
    }

    $accountStatusRows = ''
    foreach ($row in $Results.AccountStatusSummary) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $accountStatusRows += "<tr><td>$(HtmlEncode $row.Category)</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td><td style='font-weight:700;'>$($row.Count)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($accountStatusRows)) {
        $accountStatusRows = "<tr><td colspan='3' class='empty'>No account summary available.</td></tr>"
    }

    $breakdownRows = ''
    foreach ($row in $Results.TicketBreakdownByType) {
        $breakdownRows += "<tr><td>$(HtmlEncode $row.TicketType)</td><td>$(HtmlEncode $row.EncType)</td><td style='font-weight:700;'>$($row.Events)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($breakdownRows)) {
        $breakdownRows = "<tr><td colspan='3' class='empty'>No Kerberos ticket events were collected for the selected window.</td></tr>"
    }

    $globalRows = ''
    foreach ($row in $Results.TicketBreakdownGlobal) {
        $badgeClass = if ($row.EncType -eq 'RC4-HMAC') { 'fail' } elseif ($row.EncType -like 'AES*') { 'pass' } else { 'info' }
        $globalRows += "<tr><td>$(HtmlEncode $row.EncType)</td><td style='font-weight:700;'>$($row.Events)</td><td>$($row.Percent)%</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.EncType)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($globalRows)) {
        $globalRows = "<tr><td colspan='4' class='empty'>No global ticket distribution available.</td></tr>"
    }

    $rc4AccountRows = ''
    foreach ($row in $Results.Rc4RequestorAccounts) {
        $rc4AccountRows += "<tr><td>$(HtmlEncode $row.Account)</td><td style='font-weight:700;'>$($row.Events)</td><td>$(HtmlEncode $row.EncHex)</td><td>$(HtmlEncode $row.Status)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($rc4AccountRows)) {
        $rc4AccountRows = "<tr><td colspan='4' class='empty'>No RC4 requestor accounts identified.</td></tr>"
    }

    $rc4ServiceRows = ''
    foreach ($row in $Results.Rc4TargetServices) {
        $avoidable = if ($row.AvoidableRc4Events -gt 0) { "<span class='badge fail'>$($row.AvoidableRc4Events)</span>" } else { "<span class='badge pass'>0</span>" }
        $rc4ServiceRows += "<tr><td>$(HtmlEncode $row.Service)</td><td>$(HtmlEncode $row.SamAccountName)</td><td style='font-weight:700;'>$($row.Events)</td><td>$avoidable</td><td>$(HtmlEncode $row.EncHex)</td><td>$(HtmlEncode $row.Status)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($rc4ServiceRows)) {
        $rc4ServiceRows = "<tr><td colspan='6' class='empty'>No RC4 target services identified.</td></tr>"
    }

    $warningRows = ''
    foreach ($warning in $Results.Warnings) {
        $warningRows += "<tr><td>$(HtmlEncode $warning)</td></tr>`n"
    }

    $errorRows = ''
    foreach ($errorText in $Results.Errors) {
        $errorRows += "<tr><td>$(HtmlEncode $errorText)</td></tr>`n"
    }

    $artifactRows = ''
    foreach ($artifact in $Results.Artifacts) {
        $artifactRows += "<tr><td>$(HtmlEncode $artifact.Type)</td><td class='mono'>$(HtmlEncode $artifact.Path)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($artifactRows)) {
        $artifactRows = "<tr><td colspan='2' class='empty'>No report artifacts recorded.</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Kerberos Encryption Audit Report</title>
<style>
:root{--bg:#09111f;--bg-soft:#0f1b2d;--card:#111c30;--card-2:#16233a;--border:#28405f;--text:#dce7f7;--muted:#93a7c4;--accent:#68c3ff;--accent-2:#8ef0c9;--green:#49d17d;--red:#ff6b6b;--yellow:#f0c45c;--cyan:#52d6ff}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:radial-gradient(circle at top,#173055 0%,var(--bg) 45%,#08101c 100%);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1440px;margin:0 auto}
h1{color:#f4fbff;font-size:2.2rem;margin-bottom:.5rem;letter-spacing:-.02em}h2{color:var(--accent);font-size:1.35rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:var(--muted);font-size:.92rem;margin-bottom:0}
.hero{background:linear-gradient(135deg,rgba(104,195,255,.2),rgba(142,240,201,.1));border:1px solid rgba(104,195,255,.28);border-radius:18px;padding:1.6rem 1.8rem;margin-bottom:1.5rem;box-shadow:0 18px 50px rgba(0,0,0,.25)}.hero p{color:var(--muted);max-width:900px}.hero strong{color:var(--accent-2)}
.findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.5rem}.finding{border-radius:14px;padding:1rem 1.1rem;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text)}.finding strong{display:block;margin-bottom:.35rem}.finding.danger{border-color:rgba(255,107,107,.35);background:rgba(255,107,107,.08)}.finding.warn{border-color:rgba(240,196,92,.35);background:rgba(240,196,92,.08)}.finding.good{border-color:rgba(73,209,125,.35);background:rgba(73,209,125,.08)}
.card{background:linear-gradient(180deg,var(--card),var(--card-2));border:1px solid var(--border);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 12px 30px rgba(0,0,0,.18)}.advisory{background:rgba(82,214,255,.08);border:1px solid rgba(82,214,255,.28);border-radius:14px;padding:1rem 1.2rem;margin-bottom:1.5rem}.advisory strong{color:var(--cyan)}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:rgba(255,255,255,.04);color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}tr:hover{background:rgba(255,255,255,.025)}
.badge{padding:3px 9px;border-radius:999px;font-size:.75rem;font-weight:700;display:inline-block}.badge.pass{background:rgba(73,209,125,.14);color:var(--green)}.badge.warn{background:rgba(240,196,92,.14);color:var(--yellow)}.badge.fail{background:rgba(255,107,107,.14);color:var(--red)}.badge.info{background:rgba(82,214,255,.14);color:var(--cyan)}
.mono{font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}.note{color:var(--muted);font-style:italic;font-size:.85rem;margin:.5rem 0}.empty{color:var(--muted);text-align:center;padding:1rem}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}.summary-metric{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));border:1px solid var(--border);border-radius:14px;padding:1.2rem 1rem;text-align:center;backdrop-filter:blur(8px)}.summary-metric .metric-value{font-size:2.2rem;font-weight:800;line-height:1.1}.summary-metric .metric-label{color:var(--muted);font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.6px}
.section-nav{position:sticky;top:0;background:rgba(9,17,31,.84);backdrop-filter:blur(10px);padding:.8rem 0;z-index:100;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:.8rem;font-size:.85rem;padding:.45rem .7rem;border:1px solid rgba(104,195,255,.15);border-radius:999px;background:rgba(255,255,255,.02)}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.step-card{background:linear-gradient(180deg,var(--card),var(--card-2));border:1px solid var(--border);border-radius:14px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start}.step-number{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#08101c;width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.85rem;flex-shrink:0}.step-text{font-size:.85rem;line-height:1.5}.step-text strong{color:var(--accent)}
.error-alert{background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.28);border-radius:14px;padding:1rem 1.5rem;margin-bottom:1.5rem}.warning-alert{background:rgba(240,196,92,.08);border:1px solid rgba(240,196,92,.28);border-radius:14px;padding:1rem 1.5rem;margin-bottom:1.5rem}
</style></head><body><div class="container">
<div class="hero"><h1>Kerberos Encryption Audit Report</h1><p class="subtitle">Domain: $(HtmlEncode $Results.DomainName) | Generated: $timestamp | Window: last $($Results.Hours) hour(s)</p><p style="margin-top:.85rem;"><strong>Focus:</strong> correlate KDC defaults, directory encryption posture, and live Kerberos ticket behavior to spot RC4 that still matters.</p></div>
<nav class="section-nav"><a href="#summary">Summary</a><a href="#backlog">Backlog</a><a href="#kdc">KDC Default</a><a href="#phase">Phase</a><a href="#kdcsvc">Kdcsvc</a><a href="#accounts">Accounts</a><a href="#trusts">Trusts</a><a href="#tickets">Tickets</a><a href="#rc4">RC4 Hotspots</a><a href="#artifacts">Artifacts</a>$(if($warningCount -gt 0){'<a href="#warnings" style="color:var(--yellow);">Warnings</a>'})$(if($errorCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2>Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid var(--accent)"><div class="metric-value" style="color:var(--accent)">$($Results.DomainControllers.Count)</div><div class="metric-label">DCs Audited</div></div>
<div class="summary-metric" style="border-top:3px solid var(--yellow)"><div class="metric-value" style="color:var(--yellow)">$($Results.PriorityAccounts.Count)</div><div class="metric-label">Priority Accounts</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($Results.TotalRc4Events -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($Results.TotalRc4Events -gt 0){'var(--red)'}else{'var(--green)'})">$($Results.TotalRc4Events)</div><div class="metric-label">RC4 Events</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($Results.AvoidableRc4Tgs -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($Results.AvoidableRc4Tgs -gt 0){'var(--red)'}else{'var(--green)'})">$($Results.AvoidableRc4Tgs)</div><div class="metric-label">Avoidable RC4 TGS</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($warningCount -gt 0){'var(--yellow)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($warningCount -gt 0){'var(--yellow)'}else{'var(--green)'})">$warningCount</div><div class="metric-label">Runtime Warnings</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($errorCount -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($errorCount -gt 0){'var(--red)'}else{'var(--green)'})">$errorCount</div><div class="metric-label">Runtime Errors</div></div>
</div>
<div class="advisory"><strong>Purpose:</strong> this unified audit checks the KDC default, inventories account encryption capability, inspects 4768 and 4769 ticket encryption on domain controllers, and highlights the RC4 usage you need to remove before enforcing AES-only settings.</div>
<div class="findings">$($findingItems -join "`n")</div>
<div class="card"><p class="note">These KPIs are interpretive. They combine raw data from DC registry reads, the account attribute <span class='mono'>msDS-SupportedEncryptionTypes</span>, and live 4768/4769 evidence.</p><table><thead><tr><th>KPI</th><th>Value</th><th>How to read it</th><th>Desired state</th><th>Status</th></tr></thead><tbody>$summaryRows</tbody></table></div></div>

<div id="kdc"><h2>KDC Default</h2><div class="card"><p class="note">This section reads <span class='mono'>HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes</span> on each DC. If the value is absent, patched DCs usually prefer AES, but the fallback is implicit rather than explicitly pinned to AES-only. A value of <span class='mono'>0x18</span> means AES128 + AES256 only for accounts that do not define <span class='mono'>msDS-SupportedEncryptionTypes</span>.</p><table><thead><tr><th>Domain Controller</th><th>Registry raw value</th><th>Interpreted value</th><th>Why it matters</th><th>Status</th></tr></thead><tbody>$kdcRows</tbody></table></div></div>

<div id="phase"><h2>RC4 Disablement Phase (KB5073381)</h2><div class="card"><p class="note">Reads <span class='mono'>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\RC4DefaultDisablementPhase</span> on each DC. Introduced by KB5073381 (January 2026), removed permanently in July 2026. <strong>Phase 0</strong> = silent (Kdcsvc 201-209 not produced). <strong>Phase 1</strong> = audit (warnings 201/202/206/207). <strong>Phase 2</strong> = enforce (errors 203/204/208/209). Until every DC is at Phase &gt;= 1, the Kdcsvc data below is incomplete.</p><table><thead><tr><th>Domain Controller</th><th>Registry value</th><th>Phase label</th><th>Status</th></tr></thead><tbody>$phaseRows</tbody></table></div></div>

<div id="kdcsvc"><h2>Kdcsvc Events 201-209</h2><div class="card"><p class="note">Provider <span class='mono'>Microsoft-Windows-Kerberos-Key-Distribution-Center</span> in the System log. <strong>Pattern B</strong> = client RC4-only (events 201/203/206/208). <strong>Pattern D</strong> = service has no AES key, the stale-key trap (events 202/204/207/209). <strong>Hygiene</strong> = event 205, DC has explicit insecure DefaultDomainSupportedEncTypes (fix the registry on the DC, not an account-level inventory row). See Article 1 §6 of the RC4 Hardening series for the full grid.</p><h3 style="margin-bottom:.65rem;color:var(--accent-2);font-size:1rem;">Summary by DC and event ID</h3><table><thead><tr><th>Domain Controller</th><th>Event ID</th><th>Pattern</th><th>Cause</th><th>Severity</th><th>Count</th></tr></thead><tbody>$kdcsvcSummaryRowsHtml</tbody></table></div><div class="card"><h3 style="margin-bottom:.65rem;color:var(--accent-2);font-size:1rem;">Most recent events</h3><p class="note">$kdcsvcTopRowsNote</p><table><thead><tr><th>Time</th><th>DC</th><th>Event ID</th><th>Pattern</th><th>Account</th><th>Service</th><th>Client address</th></tr></thead><tbody>$kdcsvcTopEventsRowsHtml</tbody></table></div></div>

<div id="accounts"><h2>Account Posture</h2><div class="card"><p class="note">This section is based primarily on <span class='mono'>msDS-SupportedEncryptionTypes</span>, <span class='mono'>servicePrincipalName</span>, and account category. The report does not assume every user account must be explicitly stamped. An <span class='mono'>(absent/0)</span> value is informational for non-service accounts, but it remains a review point for SPN-bearing or service identities because they directly influence TGS encryption.</p><p class="note">$priorityRowsNote</p><table><thead><tr><th>Name</th><th>Category</th><th>Enabled</th><th>Has SPN</th><th>Enc attr</th><th>Flags</th><th>Status</th></tr></thead><tbody>$priorityRows</tbody></table></div><div class="card"><table><thead><tr><th>Category</th><th>Status</th><th>Count</th></tr></thead><tbody>$accountStatusRows</tbody></table></div></div>

<div id="trusts"><h2>Trust Posture (TDOs)</h2><div class="card"><p class="note">Output of the sister script <span class='mono'>Get-TrustEncryptionAudit.ps1</span>. Classification reflects the LOCAL side of each trust only — the remote side has its own <span class='mono'>msDS-SupportedEncryptionTypes</span> and must be audited separately. <strong>AES-only</strong> = <span class='mono'>0x18</span>. <strong>Mixed</strong> = AES + RC4. <strong>RC4-only</strong> / <strong>Legacy-DES</strong> = priority finding. <strong>Unset</strong> = absent or 0, behaves like RC4 for cross-realm referrals. <em>Caveat:</em> an AES-only attribute without a recent password rotation can still emit RC4 referrals because AES keys are not materialized until the trust password is rotated post-attribute change.</p><table><thead><tr><th>Trust</th><th>Classification</th><th>EncBits</th><th>EncFlags</th><th>Last change</th></tr></thead><tbody>$trustsRowsHtml</tbody></table></div></div>

<div id="tickets"><h2>Ticket Encryption</h2><div class="card"><table><thead><tr><th>Ticket Type</th><th>Encryption</th><th>Events</th></tr></thead><tbody>$breakdownRows</tbody></table></div><div class="card"><table><thead><tr><th>Encryption</th><th>Events</th><th>Percent</th><th>Signal</th></tr></thead><tbody>$globalRows</tbody></table></div></div>

<div id="backlog"><h2>Backlog — §0 deliverable</h2><div class="card"><p class="note">Deterministic scoring of dependencies that still block AES-only enforcement. <strong>Blast radius</strong> (Critical/Important/Standard) + <strong>Exposure</strong> (Frequent/Occasional/Rare) + <strong>Fix cost</strong> (Low/Medium/High) on a 1-9 scale. Score &gt;= 8 = immediate wave. 6-7 = next wave. &lt; 6 = after quick wins or decommission candidate. Owner column populated from <span class='mono'>-OwnerMappingPath</span> (CSV: Pattern,Owner; Pattern supports <span class='mono'>*</span> wildcards).</p><p class="note">$backlogRowsNote</p><table><thead><tr><th>Dependency</th><th>Type</th><th>RC4 evidence</th><th>Blast radius</th><th>Exposure</th><th>Fix cost</th><th>Score</th><th>Owner</th><th>Action</th></tr></thead><tbody>$backlogRowsHtml</tbody></table></div></div>

<div id="rc4"><h2>RC4 Hotspots</h2><div class="advisory"><strong>How to read this:</strong> $(HtmlEncode $rc4Explanation)</div><div class="card"><h3 style="margin-bottom:.65rem;color:var(--accent-2);font-size:1rem;">Who was seen in RC4 events?</h3><p class="note">These are the identities observed as requestors in RC4-related events. This helps identify who was involved, but not necessarily which service account is the root cause.</p><table><thead><tr><th>Requestor identity</th><th>RC4 events</th><th>AD encryption setting</th><th>AD posture</th></tr></thead><tbody>$rc4AccountRows</tbody></table></div><div class="card"><h3 style="margin-bottom:.65rem;color:var(--accent-2);font-size:1rem;">Which services still received RC4 TGS tickets?</h3><p class="note">This is usually the most actionable table. It shows the target services that actually received RC4 service tickets, the resolved AD account behind them, and whether those RC4 tickets look avoidable.</p><table><thead><tr><th>Target service / SPN</th><th>Resolved AD account</th><th>RC4 TGS events</th><th>Avoidable RC4 TGS</th><th>AD encryption setting</th><th>AD posture</th></tr></thead><tbody>$rc4ServiceRows</tbody></table></div></div>

<div id="artifacts"><h2>Artifacts</h2><div class="card"><table><thead><tr><th>Type</th><th>Path</th></tr></thead><tbody>$artifactRows</tbody></table></div></div>

$(if($warningCount -gt 0){"<div id='warnings'><h2>Warnings</h2><div class='warning-alert'><table><tbody>$warningRows</tbody></table></div></div>"})
$(if($errorCount -gt 0){"<div id='errors'><h2>Errors</h2><div class='error-alert'><table><tbody>$errorRows</tbody></table></div></div>"})

<div id="nextsteps"><h2>Next Steps</h2><div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Fix priority SPN accounts</strong> - Move service identities to AES128 and AES256, then rotate the secret so the KDC can mint AES keys.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Reduce live RC4</strong> - Use the RC4 requestor and target service tables to remove the last RC4 ticket paths before enforcing AES-only defaults.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Lock the KDC default</strong> - When RC4 usage is gone, set <span class='mono'>DefaultDomainSupportedEncTypes = 0x18</span> on DCs to stop RC4-by-omission.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Harden clients</strong> - Restrict client Kerberos encryption types to AES128 and AES256 only after validating application compatibility.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by Invoke-KerberosEncryptionAudit.ps1</p>
</div></body></html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $rootDse = Get-ADRootDSE -ErrorAction Stop
} catch {
    throw "Active Directory discovery failed: $($_.Exception.Message)"
}

if (-not $DomainControllers -or $DomainControllers.Count -eq 0) {
    $DomainControllers = @(Get-ADDomainController -Filter * | Sort-Object HostName | Select-Object -ExpandProperty HostName)
}

$runtimeContext = Get-ExecutionContext
$directorySnapshot = Get-DirectorySnapshot -DomainDn $domain.DistinguishedName

$results = @{
    DomainName = $domain.DNSRoot
    DomainDistinguishedName = $domain.DistinguishedName
    ForestName = $forest.Name
    ConfigurationNamingContext = [string]$rootDse.configurationNamingContext
    Hours = $Hours
    DomainControllers = $DomainControllers
    KdcDefaults = [System.Collections.Generic.List[object]]::new()
    Rc4DisablementPhase = [System.Collections.Generic.List[object]]::new()
    KdcsvcEvents = [System.Collections.Generic.List[object]]::new()
    KdcsvcSummary = [System.Collections.Generic.List[object]]::new()
    Trusts = [System.Collections.Generic.List[object]]::new()
    Backlog = [System.Collections.Generic.List[object]]::new()
    AccountStatusSummary = [System.Collections.Generic.List[object]]::new()
    PriorityAccounts = [System.Collections.Generic.List[object]]::new()
    TicketBreakdownByType = [System.Collections.Generic.List[object]]::new()
    TicketBreakdownGlobal = [System.Collections.Generic.List[object]]::new()
    Rc4RequestorAccounts = [System.Collections.Generic.List[object]]::new()
    Rc4TargetServices = [System.Collections.Generic.List[object]]::new()
    Kpis = [System.Collections.Generic.List[object]]::new()
    Artifacts = [System.Collections.Generic.List[object]]::new()
    Warnings = [System.Collections.Generic.List[string]]::new()
    Errors = [System.Collections.Generic.List[string]]::new()
    TotalRc4Events = 0
    AvoidableRc4Tgs = 0
}

Clear-Host
Write-Banner -Title 'Kerberos Encryption Audit' -Subtitle 'Correlating KDC defaults, AD account crypto posture, and live ticket behavior'
Write-ContextBlock -Title 'Execution context' -Items ([ordered]@{
    'Started at' = $runtimeContext.StartedAt.ToString('yyyy-MM-dd HH:mm:ss')
    'User' = $runtimeContext.User
    'Computer' = $runtimeContext.ComputerName
    'FQDN' = $runtimeContext.FQDN
    'Operating system' = $runtimeContext.OS
    'PowerShell' = $runtimeContext.PowerShell
})
Write-ContextBlock -Title 'Directory context' -Items ([ordered]@{
    'Forest' = $forest.Name
    'Domain' = $results.DomainName
    'NetBIOS name' = $domain.NetBIOSName
    'Domain mode' = [string]$domain.DomainMode
    'Forest mode' = [string]$forest.ForestMode
    'Domain DN' = $domain.DistinguishedName
})
Write-ContextBlock -Title 'Launch snapshot' -Items ([ordered]@{
    'Users' = $directorySnapshot.Users
    'Computers' = $directorySnapshot.Computers
    'Groups' = $directorySnapshot.Groups
    'Lookback window' = ("{0} hour(s)" -f $Hours)
    'Output folder' = $OutputDir
    'CSV export' = $(if ($ExportCsv) { 'Enabled' } else { 'Disabled' })
    'Auto-open report' = $(if ($OpenReport) { 'Enabled' } else { 'Disabled' })
    'Trust inventory' = $(if ($IncludeTrusts) { 'Enabled' } else { 'Disabled (use -IncludeTrusts)' })
    'Owner mapping' = $(if ($OwnerMappingPath) { $OwnerMappingPath } else { '(none, owners default to TBD)' })
    'Target DCs' = [string]$DomainControllers.Count
})
Write-StatusLine -Label 'Domain controllers' -Value ($DomainControllers -join ', ') -Color Gray

Write-Step -Number 1 -Title 'DC posture audit' -Hint 'Reading DefaultDomainSupportedEncTypes and RC4DefaultDisablementPhase on each domain controller'
$kdcDefaults = Get-KdcDefaultAudit -Dcs $DomainControllers
$kdcDefaults | ForEach-Object { $results.KdcDefaults.Add($_) | Out-Null }
Write-StatusLine -Label 'DCs audited (KDC default)' -Value ([string]$results.KdcDefaults.Count) -Color Green

$phaseRowsCollected = Get-Rc4DisablementPhaseAudit -Dcs $DomainControllers
$phaseRowsCollected | ForEach-Object { $results.Rc4DisablementPhase.Add($_) | Out-Null }
Write-StatusLine -Label 'DCs at Phase >= 1' -Value ([string](@($results.Rc4DisablementPhase | Where-Object { $_.Phase -ge 1 })).Count) -Color $(if ((@($results.Rc4DisablementPhase | Where-Object { $_.Phase -ge 1 })).Count -eq $results.Rc4DisablementPhase.Count -and $results.Rc4DisablementPhase.Count -gt 0) { 'Green' } else { 'Yellow' })

$kdcDefaultsExplicitAesOnly = $results.KdcDefaults.Count -gt 0 -and (@($results.KdcDefaults | Where-Object { $_.Status -like 'Compliant*' }).Count -eq $results.KdcDefaults.Count)

Write-Step -Number 2 -Title 'Account encryption capability audit' -Hint 'Inventorying users, computers, and managed service accounts'
try {
    $accountRows = @(Get-AccountKerberosAudit -KdcDefaultsExplicitAesOnly $kdcDefaultsExplicitAesOnly)
} catch {
    throw "Account audit failed: $($_.Exception.Message)"
}

$statusSummary = $accountRows |
    Group-Object Category, Status |
    ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Group[0].Category
            Status = $_.Group[0].Status
            Count = $_.Count
        }
    } | Sort-Object Category, Status

$statusSummary | ForEach-Object { $results.AccountStatusSummary.Add($_) | Out-Null }

$priorityAccounts = $accountRows |
    Where-Object {
        $_.Name -ne 'krbtgt' -and (
            ($_.HasSPN -and $_.Status -ne 'Compliant (AES present)') -or
            ($_.Category -in @('gMSA', 'sMSA') -and $_.Status -ne 'Compliant (AES present)')
        )
    } |
    Sort-Object Status, Category, Name

$priorityAccounts | ForEach-Object { $results.PriorityAccounts.Add($_) | Out-Null }
Write-StatusLine -Label 'Accounts analyzed' -Value ([string]$accountRows.Count) -Color Green
Write-StatusLine -Label 'Priority accounts' -Value ([string]$results.PriorityAccounts.Count) -Color $(if ($results.PriorityAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Step -Number 3 -Title 'Kerberos event log audit' -Hint 'Collecting 4768/4769 from Security log + Kdcsvc 201-209 from System log'
$eventAudit = Get-KerberosEventAudit -Dcs $DomainControllers -LookbackHours $Hours -MaxEvents $MaxEventsPerDc
$eventAudit.Errors | ForEach-Object { $results.Errors.Add($_) | Out-Null }

$events = if ($eventAudit -and $null -ne $eventAudit.RawEvents) { @($eventAudit.RawEvents) } else { @() }
$events = @($events | Where-Object { $null -ne $_ })

if ($events.Count -eq 0) {
    $results.Warnings.Add('No 4768/4769 events were collected for the selected time window. This can happen with low activity, insufficient Security log retention, or remoting/read permissions on DCs.') | Out-Null
}

$rc4Events = @($events | Where-Object { $_.EncType -eq 'RC4-HMAC' })
$results.TotalRc4Events = $rc4Events.Count
$results.AvoidableRc4Tgs = (@($rc4Events | Where-Object { $_.TicketType -eq 'TGS' -and $_.RC4ChosenWhileAESAvailable })).Count

$byType = $events |
    Group-Object TicketType, EncType |
    ForEach-Object {
        [PSCustomObject]@{
            TicketType = $_.Group[0].TicketType
            EncType = $_.Group[0].EncType
            Events = $_.Count
        }
    } | Sort-Object TicketType, EncType
$byType | ForEach-Object { $results.TicketBreakdownByType.Add($_) | Out-Null }

$globalBreakdown = $events |
    Group-Object EncType |
    ForEach-Object {
        [PSCustomObject]@{
            EncType = $_.Name
            Events = $_.Count
            Percent = if ($events.Count -gt 0) { [math]::Round(100 * ($_.Count / $events.Count), 2) } else { 0 }
        }
    } | Sort-Object Events -Descending
$globalBreakdown | ForEach-Object { $results.TicketBreakdownGlobal.Add($_) | Out-Null }

$rc4AccountGroups = $rc4Events |
    Group-Object Account |
    Sort-Object Count -Descending |
    Select-Object -First 20
foreach ($group in $rc4AccountGroups) {
    $detail = Resolve-AdPrincipalSummary -Identity $group.Name
    $results.Rc4RequestorAccounts.Add([PSCustomObject]@{
        Account = $group.Name
        Events = $group.Count
        EncHex = if ($detail) { $detail.EncHex } else { '(unresolved)' }
        Status = if ($detail) { $detail.Status } else { 'Info' }
        DistinguishedName = if ($detail) { $detail.DistinguishedName } else { '' }
    }) | Out-Null
}

$rc4ServiceGroups = $rc4Events |
    Where-Object { $_.TicketType -eq 'TGS' } |
    Group-Object Service, ServiceSid |
    Sort-Object Count -Descending |
    Select-Object -First 20
foreach ($group in $rc4ServiceGroups) {
    $sample = $group.Group | Select-Object -First 1
    $detail = Resolve-AdServiceTargetSummary -ServiceSid $sample.ServiceSid -ServiceSpn $sample.Service
    $results.Rc4TargetServices.Add([PSCustomObject]@{
        Service = $sample.Service
        SamAccountName = if ($detail) { $detail.SamAccountName } else { '' }
        Events = $group.Count
        AvoidableRc4Events = (@($group.Group | Where-Object { $_.RC4ChosenWhileAESAvailable })).Count
        EncHex = if ($detail) { $detail.EncHex } else { '(unresolved)' }
        Status = if ($detail) { $detail.Status } else { 'Info' }
        DistinguishedName = if ($detail) { $detail.DistinguishedName } else { '' }
    }) | Out-Null
}

Write-StatusLine -Label 'Total events parsed' -Value ([string]$events.Count) -Color Green
Write-StatusLine -Label 'RC4 events' -Value ([string]$results.TotalRc4Events) -Color $(if ($results.TotalRc4Events -gt 0) { 'Yellow' } else { 'Green' })

# Kdcsvc 201-209 collection (KB5073381 / Jan 2026)
$kdcsvcAudit = Get-KdcsvcEventAudit -Dcs $DomainControllers -LookbackHours $Hours -MaxEvents $MaxEventsPerDc
$kdcsvcAudit.Errors | ForEach-Object { $results.Errors.Add($_) | Out-Null }
$kdcsvcEventsRaw = if ($kdcsvcAudit -and $null -ne $kdcsvcAudit.RawEvents) { @($kdcsvcAudit.RawEvents) } else { @() }
$kdcsvcEventsRaw = @($kdcsvcEventsRaw | Where-Object { $null -ne $_ })
$kdcsvcEventsRaw | ForEach-Object { $results.KdcsvcEvents.Add($_) | Out-Null }

$kdcsvcSummaryRows = $kdcsvcEventsRaw |
    Group-Object DC, EventId |
    ForEach-Object {
        [PSCustomObject]@{
            DC       = $_.Group[0].DC
            EventId  = $_.Group[0].EventId
            Pattern  = $_.Group[0].Pattern
            Cause    = $_.Group[0].Cause
            Severity = $_.Group[0].Severity
            Count    = $_.Count
        }
    } | Sort-Object DC, EventId
$kdcsvcSummaryRows | ForEach-Object { $results.KdcsvcSummary.Add($_) | Out-Null }

Write-StatusLine -Label 'Kdcsvc 201-209 events' -Value ([string]$results.KdcsvcEvents.Count) -Color $(if ($results.KdcsvcEvents.Count -eq 0) { 'Green' } else { 'Yellow' })
Write-StatusLine -Label 'Collection warnings/errors' -Value ([string]$results.Errors.Count) -Color $(if ($results.Errors.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Step -Number 4 -Title 'Trust posture audit' -Hint 'Inventorying TDOs (msDS-SupportedEncryptionTypes + classification)'
if ($IncludeTrusts) {
    $sisterScript = Join-Path -Path $PSScriptRoot -ChildPath '..\Hardening Kerberos Encryption on AD Trusts\Get-TrustEncryptionAudit.ps1'
    $trustAudit = Invoke-TrustEncryptionAudit -SisterScriptPath $sisterScript
    $trustAudit.Errors | ForEach-Object { $results.Errors.Add($_) | Out-Null }
    foreach ($trust in $trustAudit.Rows) {
        $results.Trusts.Add($trust) | Out-Null
    }
    Write-StatusLine -Label 'Trusts inventoried' -Value ([string]$results.Trusts.Count) -Color Green
} else {
    Write-TaskMessage -Message 'Skipped (use -IncludeTrusts to invoke the sister script Get-TrustEncryptionAudit.ps1)' -Color DarkGray
}

Write-Step -Number 5 -Title 'Build report' -Hint 'Generating JSON and HTML output artifacts'

$kdcCompliant = (@($results.KdcDefaults | Where-Object { $_.Status -like 'Compliant*' })).Count
$spnFailed = (@($priorityAccounts | Where-Object { $_.HasSPN -and $_.Status -like 'Failed*' })).Count
$spnUnset = (@($priorityAccounts | Where-Object { $_.HasSPN -and ($_.EncValue -eq $null -or $_.EncValue -eq 0) })).Count

$results.Kpis.Add([PSCustomObject]@{
    Name = 'DCs with AES-only KDC default'
    Value = "$kdcCompliant/$($results.KdcDefaults.Count)"
    Target = 'Every DC explicitly set to 0x18'
    Description = 'Reads DefaultDomainSupportedEncTypes on each DC. If this is not 100%, some accounts with unset msDS-SupportedEncryptionTypes still rely on an implicit or mixed KDC fallback.'
    Status = if ($kdcCompliant -eq $results.KdcDefaults.Count) { 'OK' } else { 'Warning' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'SPN accounts failed (RC4 or no AES)'
    Value = $spnFailed
    Target = '0 SPN-bearing accounts'
    Description = 'SPN-bearing identities where msDS-SupportedEncryptionTypes still lacks AES or is explicitly RC4-only. These are the cleanest directory-side blockers for AES-only service tickets.'
    Status = if ($spnFailed -eq 0) { 'OK' } else { 'Critical' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'SPN accounts unset'
    Value = $spnUnset
    Target = '0 critical SPN-bearing accounts left implicit'
    Description = 'SPN-bearing identities with msDS-SupportedEncryptionTypes absent or 0. They may still work, but ticket behavior depends on the KDC fallback instead of an explicit per-account declaration.'
    Status = if ($spnUnset -eq 0) { 'OK' } else { 'Warning' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'RC4 events'
    Value = $results.TotalRc4Events
    Target = '0 observed RC4 events'
    Description = 'Live 4768/4769 events that actually used RC4 during the selected window. This is stronger evidence than configuration alone.'
    Status = if ($results.TotalRc4Events -eq 0) { 'OK' } else { 'Critical' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'Avoidable RC4 TGS'
    Value = $results.AvoidableRc4Tgs
    Target = '0 avoidable RC4 TGS events'
    Description = 'RC4 TGS events where the event fields suggest AES support was already available end to end. These are usually the first RC4 cases to remediate.'
    Status = if ($results.AvoidableRc4Tgs -eq 0) { 'OK' } else { 'Critical' }
}) | Out-Null

# KB5073381 / Jan 2026 KPIs
$phaseAtLeast1 = (@($results.Rc4DisablementPhase | Where-Object { $_.Phase -ge 1 })).Count
$phaseTotal = $results.Rc4DisablementPhase.Count
$kdcsvc205Count = (@($results.KdcsvcEvents | Where-Object { $_.EventId -eq 205 })).Count

$results.Kpis.Add([PSCustomObject]@{
    Name = 'DCs at Phase >= 1 (RC4DefaultDisablementPhase)'
    Value = "$phaseAtLeast1/$phaseTotal"
    Target = 'Every DC at Phase >= 1 (audit) or higher'
    Description = 'KB5073381 (Jan 2026) introduced HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\RC4DefaultDisablementPhase. Phase 0 = silent (Kdcsvc 201-209 not produced). Phase 1 = audit (warnings). Phase 2 = enforce (errors). Phase 0 or registry absent = inventory blind spot.'
    Status = if ($phaseAtLeast1 -eq $phaseTotal -and $phaseTotal -gt 0) { 'OK' } else { 'Warning' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'Kdcsvc 201-209 events observed'
    Value = $results.KdcsvcEvents.Count
    Target = '0 events (post AES migration)'
    Description = 'Total Kdcsvc events 201-209 collected from the System log on DCs at Phase >= 1. Each event is a direct KDC-side flag of an RC4 negotiation, with the offending account pre-extracted. Pattern B (clients RC4-only) and Pattern D (services without AES keys) collapse onto these events.'
    Status = if ($results.KdcsvcEvents.Count -eq 0) { 'OK' } else { 'Warning' }
}) | Out-Null
$results.Kpis.Add([PSCustomObject]@{
    Name = 'Kdcsvc 205 hygiene findings'
    Value = $kdcsvc205Count
    Target = '0 events 205'
    Description = 'Event 205 is logged once per Kdcsvc start when a DC has an explicit insecure DefaultDomainSupportedEncTypes (e.g. RC4 bit set). DC-side hygiene finding, not an account-level inventory row. Fix the registry on the offending DC.'
    Status = if ($kdcsvc205Count -eq 0) { 'OK' } else { 'Critical' }
}) | Out-Null

if ($IncludeTrusts) {
    $trustsRc4Vulnerable = (@($results.Trusts | Where-Object { $_.Classification -in @('RC4-only', 'Mixed', 'Unset', 'Legacy-DES') })).Count
    $trustsAesOnly = (@($results.Trusts | Where-Object { $_.Classification -eq 'AES-only' })).Count
    $trustsTotal = $results.Trusts.Count
    $results.Kpis.Add([PSCustomObject]@{
        Name = 'Trusts at AES-only (TDO attribute)'
        Value = "$trustsAesOnly/$trustsTotal"
        Target = 'Every trust at msDS-SupportedEncryptionTypes = 0x18'
        Description = 'TDO posture from sister script Get-TrustEncryptionAudit.ps1. Counts only the LOCAL side of each trust. Note: an AES-only attribute without a recent password rotation can still emit RC4 referrals because AES keys are not materialized until the trust password is rotated post-attribute change.'
        Status = if ($trustsTotal -eq 0) { 'Info' } elseif ($trustsAesOnly -eq $trustsTotal) { 'OK' } else { 'Warning' }
    }) | Out-Null
    $results.Kpis.Add([PSCustomObject]@{
        Name = 'Trusts with RC4 / DES / Unset capability'
        Value = $trustsRc4Vulnerable
        Target = '0 trusts in RC4-only / Mixed / Unset / Legacy-DES'
        Description = 'Count of TDOs whose msDS-SupportedEncryptionTypes still allows RC4, DES, or is absent (which behaves like RC4 for cross-realm). Each one is a candidate for trust-side remediation in Article 3.'
        Status = if ($trustsRc4Vulnerable -eq 0) { 'OK' } else { 'Warning' }
    }) | Out-Null
}

# Build the unified backlog (the §0 deliverable)
$ownerMapping = @{}
if ($OwnerMappingPath) {
    if (Test-Path -Path $OwnerMappingPath) {
        try {
            Import-Csv -Path $OwnerMappingPath | ForEach-Object {
                if ($_.Pattern -and $_.Owner) {
                    $ownerMapping[[string]$_.Pattern] = [string]$_.Owner
                }
            }
            Write-TaskMessage -Message ("Owner mapping loaded: {0} pattern(s)" -f $ownerMapping.Count) -Color DarkGray
        } catch {
            $results.Warnings.Add("Failed to load owner mapping from ${OwnerMappingPath}: $($_.Exception.Message)") | Out-Null
        }
    } else {
        $results.Warnings.Add("Owner mapping file not found: $OwnerMappingPath") | Out-Null
    }
}

$backlogRows = Build-Rc4Backlog -Results $results -OwnerMapping $ownerMapping
foreach ($row in $backlogRows) { $results.Backlog.Add($row) | Out-Null }
Write-StatusLine -Label 'Backlog rows scored' -Value ([string]$results.Backlog.Count) -Color $(if ($results.Backlog.Count -eq 0) { 'Green' } else { 'Yellow' })

$backlogTop = (@($results.Backlog | Where-Object { $_.Score -ge 8 })).Count
$results.Kpis.Add([PSCustomObject]@{
    Name = 'Backlog rows at score 8-9 (immediate wave)'
    Value = "$backlogTop/$($results.Backlog.Count)"
    Target = '0 immediate-wave rows after remediation'
    Description = 'Deterministic scoring against the §0 deliverable: Blast radius (Critical/Important/Standard) + Exposure (Frequent/Occasional/Rare) + Fix cost (Low/Medium/High). Score >= 8 means dedicated change window required. Owner column populated from -OwnerMappingPath when supplied (CSV with columns Pattern,Owner; Pattern supports * wildcards).'
    Status = if ($backlogTop -eq 0) { 'OK' } else { 'Warning' }
}) | Out-Null

if ($results.TotalRc4Events -gt 0 -and $results.Rc4TargetServices.Count -eq 0) {
    $results.Warnings.Add('RC4 events were found, but no RC4 target service could be resolved from AD. Check ServiceSid, SPN, or application-side SPN registration.') | Out-Null
}

$jsonPath = Join-Path -Path $OutputDir -ChildPath 'KerberosEncryptionAudit.json'
$htmlPath = Join-Path -Path $OutputDir -ChildPath 'KerberosEncryptionAudit.html'

$results.Artifacts.Add([PSCustomObject]@{ Type = 'HTML report'; Path = $htmlPath }) | Out-Null
$results.Artifacts.Add([PSCustomObject]@{ Type = 'JSON report'; Path = $jsonPath }) | Out-Null

if ($ExportCsv) {
    $csvDefinitions = @(
        @{ Name = 'KdcDefaults.csv'; Data = $results.KdcDefaults },
        @{ Name = 'Rc4DisablementPhase.csv'; Data = $results.Rc4DisablementPhase },
        @{ Name = 'KdcsvcEvents.csv'; Data = $results.KdcsvcEvents },
        @{ Name = 'KdcsvcSummary.csv'; Data = $results.KdcsvcSummary },
        @{ Name = 'PriorityAccounts.csv'; Data = $results.PriorityAccounts },
        @{ Name = 'TicketBreakdownByType.csv'; Data = $results.TicketBreakdownByType },
        @{ Name = 'TicketBreakdownGlobal.csv'; Data = $results.TicketBreakdownGlobal },
        @{ Name = 'Rc4RequestorAccounts.csv'; Data = $results.Rc4RequestorAccounts },
        @{ Name = 'Rc4TargetServices.csv'; Data = $results.Rc4TargetServices },
        @{ Name = 'Trusts.csv'; Data = $results.Trusts },
        @{ Name = 'Backlog.csv'; Data = $results.Backlog },
        @{ Name = 'AllTicketEvents.csv'; Data = $events }
    )

    foreach ($definition in $csvDefinitions) {
        $csvPath = Join-Path -Path $OutputDir -ChildPath $definition.Name
        $definition.Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $results.Artifacts.Add([PSCustomObject]@{ Type = 'CSV export'; Path = $csvPath }) | Out-Null
    }
}

$results | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

# Always export Backlog.csv (the §0 deliverable) regardless of -ExportCsv
if ($results.Backlog.Count -gt 0) {
    $backlogCsvPath = Join-Path -Path $OutputDir -ChildPath 'Backlog.csv'
    $results.Backlog | Export-Csv -Path $backlogCsvPath -NoTypeInformation -Encoding UTF8
    if (-not $ExportCsv) {
        $results.Artifacts.Add([PSCustomObject]@{ Type = 'Backlog CSV (§0 deliverable)'; Path = $backlogCsvPath }) | Out-Null
    }
}

Build-HtmlReport -Results $results -OutputPath $htmlPath

Write-Section -Title '=== Run complete ===' -Color Green
Write-Section -Title '=== Mini-dashboard ===' -Color Cyan
Write-MetricDashboard -Items @(
    [PSCustomObject]@{ Label = 'Domain'; Value = $results.DomainName; Color = 'Cyan' },
    [PSCustomObject]@{ Label = 'DCs audited'; Value = [string]$results.KdcDefaults.Count; Color = 'Green' },
    [PSCustomObject]@{ Label = 'Accounts analyzed'; Value = [string]$accountRows.Count; Color = 'Green' },
    [PSCustomObject]@{ Label = 'Priority accounts'; Value = [string]$results.PriorityAccounts.Count; Color = $(if ($results.PriorityAccounts.Count -gt 0) { 'Yellow' } else { 'Green' }) },
    [PSCustomObject]@{ Label = 'Events parsed'; Value = [string]$events.Count; Color = $(if ($events.Count -gt 0) { 'Green' } else { 'Yellow' }) },
    [PSCustomObject]@{ Label = 'RC4 events'; Value = [string]$results.TotalRc4Events; Color = $(if ($results.TotalRc4Events -gt 0) { 'Yellow' } else { 'Green' }) },
    [PSCustomObject]@{ Label = 'Avoidable RC4 TGS'; Value = [string]$results.AvoidableRc4Tgs; Color = $(if ($results.AvoidableRc4Tgs -gt 0) { 'Yellow' } else { 'Green' }) },
    [PSCustomObject]@{ Label = 'Warnings'; Value = [string]$results.Warnings.Count; Color = $(if ($results.Warnings.Count -gt 0) { 'Yellow' } else { 'Green' }) },
    [PSCustomObject]@{ Label = 'Errors'; Value = [string]$results.Errors.Count; Color = $(if ($results.Errors.Count -gt 0) { 'Yellow' } else { 'Green' }) }
) -Columns 3 -Width 24
Write-StatusLine -Label 'HTML report' -Value $htmlPath -Color Cyan
Write-StatusLine -Label 'JSON report' -Value $jsonPath -Color Cyan
Write-StatusLine -Label 'Warnings' -Value ([string]$results.Warnings.Count) -Color $(if ($results.Warnings.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-StatusLine -Label 'Errors' -Value ([string]$results.Errors.Count) -Color $(if ($results.Errors.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($OpenReport) {
    Write-TaskMessage -Message 'Opening HTML report in the default browser...' -Color Cyan
    Start-Process $htmlPath
}