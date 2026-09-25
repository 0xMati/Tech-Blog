#Requires -Version 5.1

Set-StrictMode -Version Latest
Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop

function Assert-DCNativeProperties {
    param([string]$Resource, [pscustomobject]$Properties)
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot "$Resource.dsc.resource.json") -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    $schema = $manifest.schema.embedded
    foreach ($required in $schema.required) {
        if ($null -eq $Properties.PSObject.Properties[$required] -or $null -eq $Properties.$required) { throw "Missing resource property '$required'." }
    }
    foreach ($property in $Properties.PSObject.Properties) {
        $definition = $schema.properties.PSObject.Properties[$property.Name]
        if ($null -eq $definition) { throw "Unknown resource property '$($property.Name)'." }
        $rule = $definition.Value
        $value = $property.Value
        $validType = switch ($rule.type) {
            'string' { $value -is [string] }
            'boolean' { $value -is [bool] }
            'integer' { $value -is [int] -or $value -is [long] }
            default { $false }
        }
        if (-not $validType) { throw "Invalid type for '$($property.Name)'." }
        if ($rule.PSObject.Properties['const'] -and $value -cne $rule.const) { throw "Unsupported '$($property.Name)' value." }
        if ($rule.PSObject.Properties['enum'] -and $value -cnotin $rule.enum) { throw "Unsupported '$($property.Name)' value." }
        if ($rule.PSObject.Properties['minimum'] -and $value -lt $rule.minimum) { throw "'$($property.Name)' is below the minimum." }
        if ($rule.PSObject.Properties['multipleOf'] -and $value % $rule.multipleOf -ne 0) { throw "'$($property.Name)' must be a multiple of $($rule.multipleOf)." }
    }
}

function Get-DCSpoolerState {
    $service = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='Spooler'" -ErrorAction Stop)
    if ($service.Count -ne 1) { throw 'The Print Spooler service could not be read.' }
    $startupType = switch ($service[0].StartMode) {
        'Auto' { 'Automatic' }
        'Manual' { 'Manual' }
        'Disabled' { 'Disabled' }
        default { throw "Unexpected service start mode: $($service[0].StartMode)." }
    }
    if ($service[0].State -cnotin @('Running', 'Stopped')) { throw "Spooler is in a transitional or unsupported state: $($service[0].State)." }
    [pscustomobject][ordered]@{ Name = 'Spooler'; State = [string]$service[0].State; StartupType = $startupType }
}

function Set-DCSpoolerState {
    param([pscustomobject]$Properties)
    foreach ($required in @('State', 'StartupType')) {
        if (-not $Properties.PSObject.Properties[$required]) { throw "Set requires '$required'." }
    }
    if ($Properties.State -ceq 'Running' -and $Properties.StartupType -ceq 'Disabled') { throw 'A disabled service cannot be requested in the Running state.' }
    $current = Get-DCSpoolerState
    $controller = Get-Service -Name Spooler -ErrorAction Stop
    try {
        if ($Properties.State -ceq 'Stopped' -and $current.State -cne 'Stopped') {
            $controller.Stop()
            $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [timespan]::FromSeconds(30))
        }
        if ($current.StartupType -cne $Properties.StartupType) {
            Set-Service -Name Spooler -StartupType $Properties.StartupType -ErrorAction Stop
        }
        if ($Properties.State -ceq 'Running' -and $current.State -cne 'Running') {
            $controller.Start()
            $controller.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [timespan]::FromSeconds(30))
        }
    }
    finally { $controller.Dispose() }
    Get-DCSpoolerState
}

function Get-DCSmbServerState {
    $configuration = Get-SmbServerConfiguration -ErrorAction Stop
    [pscustomobject][ordered]@{
        Name = 'Server'
        EnableSMB1Protocol = [bool]$configuration.EnableSMB1Protocol
        RequireSecuritySignature = [bool]$configuration.RequireSecuritySignature
    }
}

function Get-DCAuditFlags {
    param([guid]$Subcategory)
    if (-not ('Blog.DC.NativeAudit' -as [type])) {
        Add-Type -Path (Join-Path $PSScriptRoot 'NativeAudit.cs') -ErrorAction Stop
    }
    [Blog.DC.NativeAudit]::Query($Subcategory)
}

function Get-DCAuditPolicyState {
    param([string]$Name)
    $subcategories = @{
        'Logon' = '0cce9215-69ae-11d9-bed3-505054503030'
        'User Account Management' = '0cce9235-69ae-11d9-bed3-505054503030'
        'Directory Service Changes' = '0cce923c-69ae-11d9-bed3-505054503030'
    }
    $flags = [uint32](Get-DCAuditFlags -Subcategory $subcategories[$Name])
    if ($flags -gt 4) { throw "Unexpected audit policy flags $flags for '$Name'." }
    [pscustomobject][ordered]@{ Name = $Name; AuditSuccess = [bool]($flags -band 1); AuditFailure = [bool]($flags -band 2) }
}

function New-DCEventLogConfiguration {
    param([string]$LogName)
    [System.Diagnostics.Eventing.Reader.EventLogConfiguration]::new($LogName)
}

function Get-DCEventLogState {
    param([string]$LogName)
    $configuration = New-DCEventLogConfiguration $LogName
    try {
        [pscustomobject][ordered]@{ LogName = $LogName; MaximumSizeInBytes = [long]$configuration.MaximumSizeInBytes; LogMode = [string]$configuration.LogMode }
    }
    finally { $configuration.Dispose() }
}

function Set-DCEventLogState {
    param([pscustomobject]$Properties)
    foreach ($required in @('MaximumSizeInBytes', 'LogMode')) {
        if (-not $Properties.PSObject.Properties[$required]) { throw "Set requires '$required'." }
    }
    $configuration = New-DCEventLogConfiguration $Properties.LogName
    try {
        if ($configuration.MaximumSizeInBytes -ne $Properties.MaximumSizeInBytes -or [string]$configuration.LogMode -cne $Properties.LogMode) {
            $configuration.MaximumSizeInBytes = [long]$Properties.MaximumSizeInBytes
            $configuration.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]$Properties.LogMode
            $configuration.SaveChanges()
        }
    }
    finally { $configuration.Dispose() }
    Get-DCEventLogState $Properties.LogName
}

function Get-DCLdapPolicyState {
    param([string]$ValueName)
    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $baseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\NTDS\Parameters', $false)
        $exists = $null -ne $key -and $key.GetValueNames() -contains $ValueName
        $kind = if ($exists) { [string]$key.GetValueKind($ValueName) } else { 'Missing' }
        $value = if ($kind -ceq 'DWord') { [long]$key.GetValue($ValueName) -band 4294967295L } else { -1L }
        [pscustomobject][ordered]@{ ValueName = $ValueName; Exists = [bool]$exists; ValueType = $kind; ValueData = $value }
    }
    finally {
        if ($null -ne $key) { $key.Dispose() }
        $baseKey.Dispose()
    }
}

function Invoke-DCNativeResource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Spooler', 'SmbServer', 'AuditPolicy', 'EventLog', 'LdapPolicy')][string]$Resource,
        [Parameter(Mandatory)][ValidateSet('Get', 'Set')][string]$Operation,
        [Parameter(Mandatory)][pscustomobject]$Properties
    )
    Assert-DCNativeProperties $Resource $Properties
    if ($Operation -eq 'Set') {
        switch ($Resource) {
            'Spooler' { return Set-DCSpoolerState $Properties }
            'EventLog' { return Set-DCEventLogState $Properties }
            default { throw "Resource '$Resource' is read-only and does not implement Set." }
        }
    }
    switch ($Resource) {
        'Spooler' { Get-DCSpoolerState }
        'SmbServer' { Get-DCSmbServerState }
        'AuditPolicy' { Get-DCAuditPolicyState $Properties.Name }
        'EventLog' { Get-DCEventLogState $Properties.LogName }
        'LdapPolicy' { Get-DCLdapPolicyState $Properties.ValueName }
    }
}

Export-ModuleMember -Function Invoke-DCNativeResource