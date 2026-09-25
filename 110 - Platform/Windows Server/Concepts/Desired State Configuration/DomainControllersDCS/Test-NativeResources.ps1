#Requires -Version 5.1

[CmdletBinding()]
param([string]$DscExecutable)

$ErrorActionPreference = 'Stop'
$nativeTokens = $null
$nativeParseErrors = $null
$nativeScript = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Invoke-DCResource.ps1'), [ref]$nativeTokens, [ref]$nativeParseErrors)
if ($nativeParseErrors.Count) { throw 'The production native-process wrapper has syntax errors.' }
$nativeProcessFunction = $nativeScript.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-DCNativeProcess' }, $true)
if ($null -eq $nativeProcessFunction) { throw 'The production native-process wrapper was not found.' }
. ([scriptblock]::Create($nativeProcessFunction.Extent.Text))
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('DCNative-Test-' + [guid]::NewGuid().ToString('N'))
$module = Import-Module (Join-Path $PSScriptRoot 'Resources\NativeResources.psm1') -Force -PassThru
try {
    & $module {
        function Get-CimInstance {
            param($ClassName, $Filter, $ErrorAction)
            if ($ClassName -ne 'Win32_Service' -or $Filter -ne "Name='Spooler'") { throw 'Unexpected service lookup.' }
            [pscustomobject]@{ State = 'Running'; StartMode = 'Auto' }
        }
        $state = Invoke-DCNativeResource -Resource Spooler -Operation Get -Properties ([pscustomobject]@{ Name = 'Spooler' })
        if ($state.State -cne 'Running' -or $state.StartupType -cne 'Automatic') { throw 'Native Spooler state did not match Windows state.' }
        function Get-SmbServerConfiguration {
            param($ErrorAction)
            [pscustomobject]@{ EnableSMB1Protocol = $false; RequireSecuritySignature = $true }
        }
        $smb = Invoke-DCNativeResource SmbServer Get ([pscustomobject]@{ Name = 'Server' })
        if ($smb.EnableSMB1Protocol -isnot [bool] -or $smb.EnableSMB1Protocol -or -not $smb.RequireSecuritySignature) { throw 'Invalid SMB state.' }
        function Get-SmbServerConfiguration { param($ErrorAction) [pscustomobject]@{ EnableSMB1Protocol = $null; RequireSecuritySignature = $true } }
        $rejected = $false
        try { Invoke-DCNativeResource SmbServer Get ([pscustomobject]@{ Name = 'Server' }) }
        catch { $rejected = $_.Exception.Message -like '*Boolean settings*' }
        if (-not $rejected) { throw 'An unknown SMB1 state was treated as disabled.' }
        function Get-DCAuditFlags {
            param([guid]$Subcategory)
            if ($Subcategory -ne [guid]'0cce9215-69ae-11d9-bed3-505054503030') { throw 'Unexpected audit GUID.' }
            3
        }
        $audit = Invoke-DCNativeResource AuditPolicy Get ([pscustomobject]@{ Name = 'Logon' })
        if (-not $audit.AuditSuccess -or -not $audit.AuditFailure) { throw 'Invalid audit flags.' }
        foreach ($flags in @(0, 1, 2, 3, 4)) {
            function Get-DCAuditFlags { param($Subcategory) $flags }
            $audit = Invoke-DCNativeResource AuditPolicy Get ([pscustomobject]@{ Name = 'Directory Service Changes' })
            if ($audit.AuditSuccess -ne [bool]($flags -band 1) -or $audit.AuditFailure -ne [bool]($flags -band 2)) { throw "Incorrect audit flag mapping for $flags." }
        }
        function Get-DCAuditFlags { param($Subcategory) throw 'AuditQuerySystemPolicy failed (Win32 5): Access is denied.' }
        $rejected = $false
        try { Invoke-DCNativeResource AuditPolicy Get ([pscustomobject]@{ Name = 'Logon' }) }
        catch { $rejected = $_.Exception.Message -like '*Win32 5*' }
        if (-not $rejected) { throw 'The native audit error code was lost.' }
        $serviceState = [pscustomobject]@{ State = 'Running'; StartMode = 'Auto'; StartupType = 'Automatic' }
        $serviceActions = [System.Collections.Generic.List[string]]::new()
        function Get-CimInstance { param($ClassName, $Filter, $ErrorAction) $serviceState }
        function Set-Service {
            param($Name, $StartupType, $ErrorAction)
            $serviceActions.Add("Startup:$StartupType")
            $serviceState.StartMode = if ($StartupType -eq 'Automatic') { 'Auto' } else { $StartupType }
        }
        function Get-Service {
            param($Name, $ErrorAction)
            $controller = [pscustomobject]@{ State = $serviceState; Actions = $serviceActions }
            $controller | Add-Member ScriptMethod Stop { $this.State.State = 'Stopped'; $this.Actions.Add('Stop') }
            $controller | Add-Member ScriptMethod Start { $this.State.State = 'Running'; $this.Actions.Add('Start') }
            $controller | Add-Member ScriptMethod WaitForStatus { param($Status, $Timeout) if ($this.State.State -ne [string]$Status) { throw 'Unexpected wait.' } }
            $controller | Add-Member ScriptMethod Dispose { }
            $controller
        }
        $desired = [pscustomobject]@{ Name = 'Spooler'; State = 'Stopped'; StartupType = 'Disabled' }
        $changed = Invoke-DCNativeResource Spooler Set $desired
        if ($changed.State -ne 'Stopped' -or $changed.StartupType -ne 'Disabled' -or ($serviceActions -join ',') -ne 'Stop,Startup:Disabled') { throw 'Spooler Set order or state is incorrect.' }
        $null = Invoke-DCNativeResource Spooler Set $desired
        if ($serviceActions.Count -ne 2) { throw 'Spooler Set is not idempotent.' }
        $eventConfiguration = [pscustomobject]@{ MaximumSizeInBytes = 65536L; LogMode = 'Circular'; Saves = 0 }
        $eventConfiguration | Add-Member ScriptMethod SaveChanges { $this.Saves++ }
        $eventConfiguration | Add-Member ScriptMethod Dispose { }
        function New-DCEventLogConfiguration { param($LogName) $eventConfiguration }
        $log = Invoke-DCNativeResource EventLog Set ([pscustomobject]@{ LogName = 'Security'; MaximumSizeInBytes = 1073741824L; LogMode = 'Circular' })
        if ($log.MaximumSizeInBytes -ne 1073741824 -or $eventConfiguration.Saves -ne 1) { throw 'Event-log Set did not save the requested state.' }
        $null = Invoke-DCNativeResource EventLog Set $log
        if ($eventConfiguration.Saves -ne 1) { throw 'Event-log Set is not idempotent.' }
        $rejected = $false
        try { Invoke-DCNativeResource EventLog Set ([pscustomobject]@{ LogName = 'Security'; MaximumSizeInBytes = 1052672L; LogMode = 'Circular' }) }
        catch { $rejected = $_.Exception.Message -like '*64 KiB*' }
        if (-not $rejected -or $eventConfiguration.Saves -ne 1) { throw 'Invalid event-log Set size was accepted.' }
        foreach ($resource in @('SmbServer', 'AuditPolicy', 'LdapPolicy')) {
            $properties = switch ($resource) {
                'SmbServer' { [pscustomobject]@{ Name = 'Server' } }
                'AuditPolicy' { [pscustomobject]@{ Name = 'Logon' } }
                'LdapPolicy' { [pscustomobject]@{ ValueName = 'LDAPServerIntegrity' } }
            }
            $rejected = $false
            try { Invoke-DCNativeResource $resource Set $properties }
            catch { $rejected = $_.Exception.Message -like '*read-only*' }
            if (-not $rejected) { throw "Set was not rejected for $resource." }
        }
        $rejected = $false
        try { Invoke-DCNativeResource Spooler Set ([pscustomobject]@{ Name = 'Spooler'; State = 'Running'; StartupType = 'Disabled' }) }
        catch { $rejected = $_.Exception.Message -like '*disabled service*' }
        if (-not $rejected) { throw 'An impossible Spooler state was accepted.' }
    }
    $manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Resources\Spooler.dsc.resource.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($manifest.type -cne 'Blog.DC/Spooler' -or $manifest.kind -cne 'resource' -or $manifest.get.input -cne 'stdin') { throw 'Invalid native resource manifest contract.' }
    Add-Type -Path (Join-Path $PSScriptRoot 'Resources\NativeAudit.cs') -ErrorAction Stop
    foreach ($file in (Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Resources') -Filter '*.dsc.resource.json')) {
        $resourceManifest = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($resourceManifest.kind -cne 'resource' -or $resourceManifest.PSObject.Properties['adapter']) { throw 'An adapter was found in the native resource package.' }
    }
    'PASS: Native Get contracts, read-only Set rejection, invalid Spooler state, manifests and audit interop compilation; Windows operations mocked.'
    $null = New-Item -Path $temporaryRoot -ItemType Directory -Force
    $preflightRoot = Join-Path $temporaryRoot 'PreflightResources'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Resources') -Destination $preflightRoot -Recurse
    $preflightFiles = @(
        foreach ($file in (Get-ChildItem -LiteralPath $preflightRoot -File)) {
            [pscustomobject]@{ Name = $file.Name; Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash }
        }
    )
    $preflightBranch = $nativeScript.Find({ param($node) $node -is [System.Management.Automation.Language.IfStatementAst] -and $node.Clauses[0].Item1.Extent.Text -eq '$request.Operation -eq ''Preflight''' }, $true)
    if ($null -eq $preflightBranch) { throw 'The production preflight block was not found.' }
    $preflightBlock = [scriptblock]::Create(($preflightBranch.Clauses[0].Item2.Statements | ForEach-Object { $_.Extent.Text }) -join "`n")
    function Invoke-PreflightFixture {
        param([switch]$WithAdapter)
        $settings = [pscustomobject]@{ ResourceDirectory = $preflightRoot; ResourceVersion = '1.0.0'; DscExecutable = 'fixture-dsc.exe'; DscVersion = '3.2.3' }
        $request = [pscustomobject]@{ ResourceFiles = $preflightFiles; ResourceTypes = @('Blog.DC/Spooler', 'Blog.DC/SmbServer', 'Blog.DC/AuditPolicy', 'Blog.DC/EventLog', 'Blog.DC/LdapPolicy') }
        $nativeEnvironment = @{}
        $actualHostName = 'dc.fixture.test'
        $operatingSystem = [pscustomobject]@{ Caption = 'Windows Server fixture'; BuildNumber = '26100' }
        $identity = [pscustomobject]@{ Name = 'fixture\operator' }
        function Invoke-DCNativeProcess {
            param($Executable, $Arguments, $Environment)
            if ($Arguments -eq '--version') { return [pscustomobject]@{ ExitCode = 0; StdOut = 'dsc 3.2.3'; StdErr = '' } }
            if ($Arguments -cne 'resource list Blog.DC/* --output-format json') { throw 'Preflight used another discovery command.' }
            $entries = foreach ($resourceType in $request.ResourceTypes) {
                [pscustomobject]@{ type = $resourceType; version = '1.0.0'; kind = 'resource'; requireAdapter = $(if ($WithAdapter) { 'Fixture/Adapter' } else { $null }) } | ConvertTo-Json -Compress
            }
            [pscustomobject]@{ ExitCode = 0; StdOut = $entries -join "`n"; StdErr = '' }
        }
        & $preflightBlock
    }
    $preflight = @(Invoke-PreflightFixture)
    if ($preflight.Count -ne 1 -or $preflight[0].ResourceVersions.Count -ne 5 -or $preflight[0].ResourceFileHashes.Count -ne 8) { throw 'Native preflight lost resource identities or hashes.' }
    $rejected = $false
    try { Invoke-PreflightFixture -WithAdapter }
    catch { $rejected = $_.Exception.Message -like '*did not discover native*' }
    if (-not $rejected) { throw 'Native preflight accepted an adapter-based resource.' }
    $changedFile = Join-Path $preflightRoot 'Invoke-NativeResource.ps1'
    [System.IO.File]::AppendAllText($changedFile, "`n ")
    $rejected = $false
    try { Invoke-PreflightFixture }
    catch { $rejected = $_.Exception.Message -like '*differs from the orchestration package*' }
    if (-not $rejected) { throw 'Native preflight accepted an altered resource file.' }
    'PASS: Production preflight accepts eight hashed native files and rejects adapter discovery or changed content; no remote execution.'
    if ($DscExecutable) {
        $fixtureRoot = Join-Path $temporaryRoot 'Resources'
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Resources') -Destination $fixtureRoot -Recurse
        $fixtureModule = @'
function Invoke-DCNativeResource {
    param($Resource, $Operation, $Properties)
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'fail.flag')) { throw 'Fixture Windows API failure (Win32 5).' }
    $path = Join-Path $PSScriptRoot ($Resource + '.state.json')
    if ($Operation -eq 'Set') { [System.IO.File]::WriteAllText($path, (ConvertTo-Json -InputObject $Properties -Compress)) }
    Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
}
Export-ModuleMember -Function Invoke-DCNativeResource
'@
        [System.IO.File]::WriteAllText((Join-Path $fixtureRoot 'NativeResources.psm1'), $fixtureModule)
        $states = @{
            Spooler = @{ Name = 'Spooler'; State = 'Running'; StartupType = 'Automatic' }
            SmbServer = @{ Name = 'Server'; EnableSMB1Protocol = $false; RequireSecuritySignature = $true }
            AuditPolicy = @{ Name = 'Logon'; AuditSuccess = $true; AuditFailure = $false }
            EventLog = @{ LogName = 'Directory Service'; MaximumSizeInBytes = 1052672; LogMode = 'Circular' }
            LdapPolicy = @{ ValueName = 'LDAPServerIntegrity'; Exists = $false; ValueType = 'Missing'; ValueData = -1 }
        }
        foreach ($name in $states.Keys) {
            [System.IO.File]::WriteAllText((Join-Path $fixtureRoot ($name + '.state.json')), (ConvertTo-Json -InputObject $states[$name]))
        }
        function Invoke-NativeFixture {
            param([string]$Operation, [string]$Resource, [hashtable]$Properties)
            $configuration = @{ '$schema' = 'https://aka.ms/dsc/schemas/v3/bundled/config/document.json'; resources = @(@{ name = 'native-fixture'; type = "Blog.DC/$Resource"; properties = $Properties }) }
            $configurationPath = Join-Path $temporaryRoot 'configuration.json'
            [System.IO.File]::WriteAllText($configurationPath, (ConvertTo-Json -InputObject $configuration -Depth 12))
            $environment = @{
                DSC_RESOURCE_PATH = $fixtureRoot + ';' + (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0')
                PATH = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0') + ';' + $env:PATH
            }
            Invoke-DCNativeProcess -Executable $DscExecutable -Arguments ('config {0} --file "{1}" --output-format json' -f $Operation, $configurationPath) -Environment $environment -TimeoutSeconds 30
        }
        foreach ($name in $states.Keys) {
            $response = Invoke-NativeFixture test $name $states[$name]
            if ($response.ExitCode -ne 0) { throw "DSC fixture failed for ${name}: $($response.StdErr)" }
            $output = $response.StdOut | ConvertFrom-Json
            if ($output.hadErrors -or -not $output.results[0].result.inDesiredState) { throw "DSC did not synthesize a successful Test for $name." }
        }
        $logTest = Invoke-NativeFixture test EventLog @{ LogName = 'Directory Service'; MaximumSizeInBytes = 1073741824; LogMode = 'Circular' }
        if ($logTest.ExitCode -ne 0 -or ($logTest.StdOut | ConvertFrom-Json).results[0].result.inDesiredState) { throw 'A non-aligned observed log size became an error or false compliance.' }
        $ldapTest = Invoke-NativeFixture test LdapPolicy @{ ValueName = 'LDAPServerIntegrity'; Exists = $true; ValueType = 'DWord'; ValueData = 2 }
        if ($ldapTest.ExitCode -ne 0 -or ($ldapTest.StdOut | ConvertFrom-Json).results[0].result.inDesiredState) { throw 'A missing LDAP value became an error or false compliance.' }
        $desired = @{ Name = 'Spooler'; State = 'Stopped'; StartupType = 'Disabled' }
        $test = Invoke-NativeFixture test Spooler $desired
        $state = ($test.StdOut | ConvertFrom-Json).results[0].result
        if ($state.inDesiredState -or ($state.differingProperties -join ',') -notmatch 'State' -or $state.actualState.State -ne 'Running') { throw 'DSC synthetic Test failed to detect drift.' }
        $set = Invoke-NativeFixture set Spooler $desired
        if ($set.ExitCode -ne 0 -or ($set.StdOut | ConvertFrom-Json).hadErrors) { throw "DSC fixture Set failed: $($set.StdErr)" }
        $after = Invoke-NativeFixture test Spooler $desired
        if (-not ($after.StdOut | ConvertFrom-Json).results[0].result.inDesiredState) { throw 'Test after fixture Set did not verify state.' }
        $rejected = Invoke-NativeFixture set SmbServer @{ Name = 'Server'; EnableSMB1Protocol = $true }
        if ($rejected.ExitCode -eq 0 -and -not ($rejected.StdOut | ConvertFrom-Json).hadErrors) { throw 'DSC accepted Set on a read-only resource.' }
        $rejected = Invoke-NativeFixture test Spooler @{ Name = 'OtherService' }
        if ($rejected.ExitCode -eq 0 -and -not ($rejected.StdOut | ConvertFrom-Json).hadErrors) { throw 'DSC did not validate the native resource schema.' }
        [System.IO.File]::WriteAllText((Join-Path $fixtureRoot 'fail.flag'), 'fail')
        $failed = Invoke-NativeFixture test Spooler $desired
        if ($failed.ExitCode -eq 0 -or $failed.StdErr -notlike '*Win32 5*') { throw 'DSC did not preserve a native command failure.' }
        'PASS: Real DSC command discovery, synthetic Test for all five resources, drift, fixture Test/Set/Test, schema validation and command errors; no Windows settings changed.'
    }
    else { 'SKIP: Native DSC process integration (supply -DscExecutable to run it).' }
}
finally {
    Remove-Module $module -Force
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}