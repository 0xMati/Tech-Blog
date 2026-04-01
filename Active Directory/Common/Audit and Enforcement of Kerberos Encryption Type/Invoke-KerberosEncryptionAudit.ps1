# Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string[]]$DomainControllers,
    [int]$MaxEventsPerDc = 5000,
    [switch]$ExportCsv,
    [switch]$OpenReport,
    [string]$OutputDir = $(Join-Path -Path $PSScriptRoot -ChildPath ("Outputs\KerberosEncryptionAudit_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
)

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
    Write-Host ('[{0}/4] {1}' -f $Number, $Title) -ForegroundColor Yellow
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
    param([Nullable[int]]$Value)

    $hasAes128 = ($Value -ne $null) -and (($Value -band 0x08) -ne 0)
    $hasAes256 = ($Value -ne $null) -and (($Value -band 0x10) -ne 0)
    $hasAes = $hasAes128 -or $hasAes256
    $hasRc4 = ($Value -ne $null) -and (($Value -band 0x04) -ne 0)
    $hasDes = ($Value -ne $null) -and ((($Value -band 0x01) -ne 0) -or (($Value -band 0x02) -ne 0))

    if ($Value -eq $null -or $Value -eq 0) {
        return 'Warning (Unset/0)'
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

function Get-StatusBadgeClass {
    param([string]$Status)

    if ($Status -like 'Compliant*' -or $Status -eq 'OK') { return 'pass' }
    if ($Status -like 'Warning*') { return 'warn' }
    if ($Status -like 'Failed*' -or $Status -eq 'Critical') { return 'fail' }
    return 'info'
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

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dc in $Dcs) {
        Write-TaskMessage -Message ("Querying KDC default on {0}" -f $dc) -Color DarkGray
        try {
            $rawResult = Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ErrorAction Stop
            $status = Get-KdcDefaultStatus -Value $rawResult.RawValue
            Write-TaskMessage -Message ("{0} -> {1}" -f $rawResult.Computer, $status) -Color $(if ($status -like 'Compliant*') { 'Green' } else { 'Yellow' })
            $rows.Add([PSCustomObject]@{
                Computer = $rawResult.Computer
                RawValue = if ($null -ne $rawResult.RawValue) { '0x{0:X}' -f [int]$rawResult.RawValue } else { '(absent)' }
                Decoded  = Convert-EncryptionFlagsToText -Value $rawResult.RawValue
                Status   = $status
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
            }) | Out-Null
        } catch {
            Write-TaskMessage -Message ("{0} -> failed to query registry" -f $dc) -Color Red
            $rows.Add([PSCustomObject]@{
                Computer = $dc
                RawValue = '(n/a)'
                Decoded  = '(error)'
                Status   = 'Failed'
                RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
            }) | Out-Null
        }
    }

    return $rows
}

function Get-AccountKerberosAudit {
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
            Status = Get-EncStatus -Value $encValue
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
            Status = Get-EncStatus -Value $encValue
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
                Status = Get-EncStatus -Value $encValue
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
            }
        }

        return $output
    }

    foreach ($dc in $Dcs) {
        Write-TaskMessage -Message ("Collecting 4768/4769 from {0}" -f $dc) -Color DarkGray
        try {
            $dcEvents = @(Invoke-Command -ComputerName $dc -ScriptBlock $remoteScript -ArgumentList $LookbackHours, $MaxEvents -ErrorAction Stop)
            if ($dcEvents.Count -gt 0) {
                $rawEvents += $dcEvents
            }
            Write-TaskMessage -Message ("{0} -> {1} event(s) collected" -f $dc, $dcEvents.Count) -Color Green
        } catch {
            $errors += "Failed to collect 4768/4769 from ${dc}: $($_.Exception.Message)"
            Write-TaskMessage -Message ("{0} -> collection failed" -f $dc) -Color Yellow
        }
    }

    foreach ($item in @($rawEvents)) {
        Add-Member -InputObject $item -MemberType NoteProperty -Name EncType -Value (Get-EncTypeLabel -Value $item.EncHex) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name ClientSupportsAES -Value ([bool]($item.ClientAdvertizedEncryption -match 'AES')) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name ServiceHasAESKeys -Value ([bool]($item.ServiceAvailableKeys -match 'AES')) -Force
        Add-Member -InputObject $item -MemberType NoteProperty -Name DCSupportsAES -Value ([bool]($item.DCSupportedEncryptionTypes -match 'AES')) -Force
        $avoidable = ($item.TicketType -eq 'TGS' -and $item.EncType -eq 'RC4-HMAC' -and $item.ClientSupportsAES -and $item.ServiceHasAESKeys -and $item.DCSupportsAES)
        Add-Member -InputObject $item -MemberType NoteProperty -Name RC4ChosenWhileAESAvailable -Value $avoidable -Force
    }

    return [PSCustomObject]@{
        RawEvents = @($rawEvents)
        Errors = @($errors)
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
        Status = Get-EncStatus -Value $encValue
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
        Status = Get-EncStatus -Value $encValue
        PasswordLastSet = if ($principal.PSObject.Properties['pwdLastSet'] -and $principal.pwdLastSet) { [datetime]::FromFileTime([int64]$principal.pwdLastSet) } else { $null }
        LastLogonDate = if ($principal.PSObject.Properties['lastLogonDate']) { $principal.lastLogonDate } else { $null }
        SPNs = if ($principal.PSObject.Properties['servicePrincipalName'] -and $principal.servicePrincipalName) { $principal.servicePrincipalName -join '; ' } else { '' }
    }
}

function New-HtmlReport {
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
        $summaryRows += "<tr><td>$(HtmlEncode $kpi.Name)</td><td style='font-weight:700;'>$(HtmlEncode ([string]$kpi.Value))</td><td>$(HtmlEncode ([string]$kpi.Target))</td><td><span class='badge $badgeClass'>$(HtmlEncode $kpi.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($summaryRows)) {
        $summaryRows = "<tr><td colspan='4' class='empty'>No KPI data available.</td></tr>"
    }

    $kdcRows = ''
    foreach ($row in $Results.KdcDefaults) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $kdcRows += "<tr><td>$(HtmlEncode $row.Computer)</td><td>$(HtmlEncode $row.RawValue)</td><td>$(HtmlEncode $row.Decoded)</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($kdcRows)) {
        $kdcRows = "<tr><td colspan='4' class='empty'>No KDC data collected.</td></tr>"
    }

    $priorityRows = ''
    foreach ($row in $Results.PriorityAccounts) {
        $badgeClass = Get-StatusBadgeClass -Status $row.Status
        $priorityRows += "<tr><td>$(HtmlEncode $row.Name)</td><td>$(HtmlEncode $row.Category)</td><td>$($row.Enabled)</td><td>$($row.HasSPN)</td><td>$(HtmlEncode $row.EncHex)</td><td>$(HtmlEncode $row.Flags)</td><td><span class='badge $badgeClass'>$(HtmlEncode $row.Status)</span></td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($priorityRows)) {
        $priorityRows = "<tr><td colspan='7' class='empty'>No priority accounts identified.</td></tr>"
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
<nav class="section-nav"><a href="#summary">Summary</a><a href="#kdc">KDC Default</a><a href="#accounts">Accounts</a><a href="#tickets">Tickets</a><a href="#rc4">RC4 Hotspots</a><a href="#artifacts">Artifacts</a>$(if($warningCount -gt 0){'<a href="#warnings" style="color:var(--yellow);">Warnings</a>'})$(if($errorCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})<a href="#nextsteps">Next Steps</a></nav>

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
<div class="card"><table><thead><tr><th>KPI</th><th>Value</th><th>Target</th><th>Status</th></tr></thead><tbody>$summaryRows</tbody></table></div></div>

<div id="kdc"><h2>KDC Default</h2><div class="card"><table><thead><tr><th>Domain Controller</th><th>Raw</th><th>Decoded</th><th>Status</th></tr></thead><tbody>$kdcRows</tbody></table></div></div>

<div id="accounts"><h2>Account Posture</h2><div class="card"><p class="note">Priority accounts are SPN-bearing identities or service accounts that still allow RC4 or do not declare AES explicitly.</p><table><thead><tr><th>Name</th><th>Category</th><th>Enabled</th><th>Has SPN</th><th>Enc</th><th>Flags</th><th>Status</th></tr></thead><tbody>$priorityRows</tbody></table></div><div class="card"><table><thead><tr><th>Category</th><th>Status</th><th>Count</th></tr></thead><tbody>$accountStatusRows</tbody></table></div></div>

<div id="tickets"><h2>Ticket Encryption</h2><div class="card"><table><thead><tr><th>Ticket Type</th><th>Encryption</th><th>Events</th></tr></thead><tbody>$breakdownRows</tbody></table></div><div class="card"><table><thead><tr><th>Encryption</th><th>Events</th><th>Percent</th><th>Signal</th></tr></thead><tbody>$globalRows</tbody></table></div></div>

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
    'Target DCs' = [string]$DomainControllers.Count
})
Write-StatusLine -Label 'Domain controllers' -Value ($DomainControllers -join ', ') -Color Gray

Write-Step -Number 1 -Title 'KDC default audit' -Hint 'Checking DefaultDomainSupportedEncTypes on each domain controller'
$kdcDefaults = Get-KdcDefaultAudit -Dcs $DomainControllers
$kdcDefaults | ForEach-Object { $results.KdcDefaults.Add($_) | Out-Null }
Write-StatusLine -Label 'DCs audited' -Value ([string]$results.KdcDefaults.Count) -Color Green

Write-Step -Number 2 -Title 'Account encryption capability audit' -Hint 'Inventorying users, computers, and managed service accounts'
try {
    $accountRows = @(Get-AccountKerberosAudit)
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

Write-Step -Number 3 -Title 'Kerberos event log audit' -Hint 'Collecting 4768 and 4769 from DC Security logs'
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
Write-StatusLine -Label 'Collection warnings/errors' -Value ([string]$results.Errors.Count) -Color $(if ($results.Errors.Count -gt 0) { 'Yellow' } else { 'Green' })

Write-Step -Number 4 -Title 'Build report' -Hint 'Generating JSON and HTML output artifacts'

$kdcCompliant = (@($results.KdcDefaults | Where-Object { $_.Status -like 'Compliant*' })).Count
$spnFailed = (@($priorityAccounts | Where-Object { $_.HasSPN -and $_.Status -like 'Failed*' })).Count
$spnUnset = (@($priorityAccounts | Where-Object { $_.HasSPN -and $_.Status -like 'Warning*' })).Count

$results.Kpis.Add([PSCustomObject]@{ Name = 'DCs with AES-only KDC default'; Value = "$kdcCompliant/$($results.KdcDefaults.Count)"; Target = 'All DCs'; Status = if ($kdcCompliant -eq $results.KdcDefaults.Count) { 'OK' } else { 'Warning' } }) | Out-Null
$results.Kpis.Add([PSCustomObject]@{ Name = 'SPN accounts failed (RC4 or no AES)'; Value = $spnFailed; Target = '0'; Status = if ($spnFailed -eq 0) { 'OK' } else { 'Critical' } }) | Out-Null
$results.Kpis.Add([PSCustomObject]@{ Name = 'SPN accounts unset'; Value = $spnUnset; Target = '0'; Status = if ($spnUnset -eq 0) { 'OK' } else { 'Warning' } }) | Out-Null
$results.Kpis.Add([PSCustomObject]@{ Name = 'RC4 events'; Value = $results.TotalRc4Events; Target = '0'; Status = if ($results.TotalRc4Events -eq 0) { 'OK' } else { 'Critical' } }) | Out-Null
$results.Kpis.Add([PSCustomObject]@{ Name = 'Avoidable RC4 TGS'; Value = $results.AvoidableRc4Tgs; Target = '0'; Status = if ($results.AvoidableRc4Tgs -eq 0) { 'OK' } else { 'Critical' } }) | Out-Null

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
        @{ Name = 'PriorityAccounts.csv'; Data = $results.PriorityAccounts },
        @{ Name = 'TicketBreakdownByType.csv'; Data = $results.TicketBreakdownByType },
        @{ Name = 'TicketBreakdownGlobal.csv'; Data = $results.TicketBreakdownGlobal },
        @{ Name = 'Rc4RequestorAccounts.csv'; Data = $results.Rc4RequestorAccounts },
        @{ Name = 'Rc4TargetServices.csv'; Data = $results.Rc4TargetServices },
        @{ Name = 'AllTicketEvents.csv'; Data = $events }
    )

    foreach ($definition in $csvDefinitions) {
        $csvPath = Join-Path -Path $OutputDir -ChildPath $definition.Name
        $definition.Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $results.Artifacts.Add([PSCustomObject]@{ Type = 'CSV export'; Path = $csvPath }) | Out-Null
    }
}

$results | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
New-HtmlReport -Results $results -OutputPath $htmlPath

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