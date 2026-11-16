---
title: "DSC v3 — Deployment and Remote Checks Cheat Sheet"
date: 2026-11-16
---

# DSC v3 — Deployment and Remote Checks Cheat Sheet

- **Goal:** deploy DSC v3, then add configuration checks against remote servers.
- **Format:** bullet points, commands, expected results, and essential caveats.
- **Status:** working draft; detailed steps and results will be added as the lab progresses.

## Administration Server

- **Role:** deploy DSC and launch checks against remote servers.
- **Internet access:** direct, to download the runtime and required resource packages.
- **Responsibilities:** keep configuration documents, prepare targets, start remote checks, and collect results.
- **Execution model:** the administration server orchestrates; the DSC engine and resources execute on each target being checked.
- **Local DSC installation:** used here for local tests; optional for orchestration alone. Installing DSC here does not install it on the targets.

## 1. Prepare the Administration Server

- **Run on:** the administration server.
- **Console:** elevated, 64-bit Windows PowerShell 5.1 on an x64 Windows Server.
- **Method:** official ZIP package; no dependency on WinGet or the Microsoft Store.
- **Version:** DSC **3.2.3 x64**, pinned to match the other DSC walkthroughs, not an assertion that it is the latest release.
- **Session:** run the blocks in order in the same console. Stop if a step fails.
- **Scope:** local preparation only; no target deployment or Windows configuration enforcement yet.

### 1.1. Create the Working Directories

```powershell
$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess) {
    throw 'Open a 64-bit Windows PowerShell console.'
}

New-Item -ItemType Directory -Path @(
    'C:\DSC\Packages'
    'C:\DSC\Configurations'
    'C:\DSC\Reports'
) -Force | Out-Null
```

- **Packages:** downloaded archives, reusable for later target preparation.
- **Configurations:** desired-state documents.
- **Reports:** results from future checks.
- **Permissions:** restrict modification of these directories and the runtime to authorized administrators.

### 1.2. Download and Verify DSC

- **Source:** [official DSC 3.2.3 release](https://github.com/PowerShell/DSC/releases/tag/v3.2.3).
- **Download:** the complete Windows x64 ZIP, not just `dsc.exe`.
- **Integrity:** compare its SHA256 with the pinned release asset digest.

```powershell
$zipPath = 'C:\DSC\Packages\DSC-3.2.3-x86_64-pc-windows-msvc.zip'

if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    Invoke-WebRequest `
        -Uri 'https://github.com/PowerShell/DSC/releases/download/v3.2.3/DSC-3.2.3-x86_64-pc-windows-msvc.zip' `
        -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
}

$expectedHash = 'E1E48218014C166BBBE0EE6364D1E9C2AB20AB5515CEDA4EABD529A4BFD49881'
if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'DSC archive hash mismatch. Do not extract it; inspect the cached download before retrying.'
}

Write-Output 'DSC archive SHA256 verified.'
```

- **Expected:** `DSC archive SHA256 verified.`
- **Repeat runs:** reuse the cached archive only if its hash matches.
- **Version changes:** update the URL, filename, expected hash, and version verification together.

### 1.3. Extract the Local Runtime

```powershell
if (Test-Path -LiteralPath 'C:\DSC\Runtime') {
    throw 'Runtime directory already exists. Verify/reuse the installation or choose a new destination.'
}

Expand-Archive -LiteralPath $zipPath -DestinationPath 'C:\DSC\Runtime' -ErrorAction Stop
```

- **Expected:** `C:\DSC\Runtime\dsc.exe` and the other bundled files are present.
- **Existing installation:** skip extraction and verify it below; do not overwrite another version.
- **Keep:** the entire extracted package, including bundled tools and resource manifests.

### 1.4. Verify the Engine and a Local Read

```powershell
$env:PATH = "C:\DSC\Runtime;$env:PATH"
$dsc = 'C:\DSC\Runtime\dsc.exe'

$version = & $dsc --version
if ($LASTEXITCODE -ne 0 -or $version -ne 'dsc 3.2.3') {
    throw 'Expected DSC 3.2.3 at C:\DSC\Runtime\dsc.exe.'
}
$version

& $dsc resource get --resource Microsoft/OSInfo --output-format yaml
if ($LASTEXITCODE -ne 0) {
    throw "DSC local read failed with exit code $LASTEXITCODE."
}
```

- **Expected:** `dsc 3.2.3`, then `actualState` describing the administration server's OS.
- **Effect:** read-only local verification; no remote server is contacted.
- **PATH:** changed for this console only. Repeat the PATH line in a new console; no machine-wide PATH change is needed here.
- **No extra module:** `Microsoft/OSInfo` is bundled with DSC.
- **Not needed yet:** PowerShell 7, Gallery resource modules, or inbound WinRM configuration on the administration server.
- **Ready for the next step:** the ZIP is cached, the local engine runs, and a bundled resource returns state.
- **Lab checkpoint:** administration-server commands completed successfully, as confirmed by the operator. Remote DSC deployment and configuration checks are not yet validated.

## 2. Prepare Remote Execution

- **Run on:** the administration server.
- **Context:** a Windows Server target in the same AD domain.
- **Authentication:** Kerberos with the current domain account; use the target's FQDN, not an IP address.
- **Permissions:** the account must be allowed to use the target endpoint and have administrator rights there for the later deployment.
- **Transport below:** the existing WinRM HTTP listener on port 5985. For an HTTPS-only endpoint, add `-UseSSL` to `Test-WSMan`, `New-PSSession`, and `Invoke-Command` calls using `-ComputerName` to use port 5986.
- **Session:** run these blocks in order in the same console.
- **Scope:** steps 2.1-2.3 test the connection without changing configuration; step 2.4 installs the runtime files; step 2.5 verifies them with a read-only DSC operation.

### 2.1. Select the First Target and Check DNS

- **Replace:** `server01.contoso.com` with the target's FQDN.

```powershell
$ErrorActionPreference = 'Stop'
$target = 'server01.contoso.com'

Resolve-DnsName -Name $target -ErrorAction Stop
```

- **Expected:** the name resolves to the intended target's address.

### 2.2. Check WinRM with Kerberos

```powershell
Test-WSMan -ComputerName $target -Authentication Kerberos -ErrorAction Stop
```

- **Expected:** a WinRM identification response without authentication or connection errors.
- **Limit:** this alone does not prove access to a PowerShell session or sufficient privileges.

### 2.3. Check the Remote PowerShell Context

```powershell
$remoteInfo = Invoke-Command -ComputerName $target `
    -ConfigurationName 'Microsoft.PowerShell' `
    -Authentication Kerberos -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Account = $identity.Name
            OperatingSystem = $os.Caption
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Is64BitProcess = [Environment]::Is64BitProcess
            IsAdministrator = $principal.IsInRole(
                [System.Security.Principal.WindowsBuiltInRole]::Administrator
            )
        }
    }

$remoteInfo | Format-List

if ($remoteInfo.PowerShellVersion -notlike '5.1.*' -or
    $remoteInfo.Is64BitProcess -ne $true -or
    $remoteInfo.IsAdministrator -ne $true) {
    throw 'Expected an elevated, 64-bit Windows PowerShell 5.1 target session.'
}
```

- **Expected:** the target's name and OS, the intended domain account, PowerShell `5.1.*`, and both boolean properties set to `True`.
- **Effect:** reads the execution context and OS only; no installation or configuration change.
- **On failure:** stop and investigate DNS, the existing listener, firewall, authentication, or endpoint permissions. Do not bypass the problem with wildcard TrustedHosts, disabled certificate validation, or weaker authentication.
- **Lab checkpoint:** steps 2.1-2.3 completed successfully on the first target, as confirmed by the operator.

### 2.4. Deploy the Runtime from the Administration Server

- **Run on:** the administration server; the session commands execute on `$target`.
- **Reuse:** `$target` from step 2.1, and `$zipPath` and `$expectedHash` from step 1.2. In a new console, rerun those steps first.
- **Transfer:** WinRM only; no SMB share or Internet access from the target is needed.
- **Effects on the target:** create `C:\DSC\Packages`, copy the verified archive, and extract the complete package into `C:\DSC\Runtime`.
- **Existing runtime:** skip this deployment and run step 2.5 instead. This procedure refuses to overwrite an existing Runtime directory.

```powershell
$ErrorActionPreference = 'Stop'

if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $expectedHash) {
    throw 'The administration server archive does not match the pinned SHA256.'
}

$remoteZipPath = 'C:\DSC\Packages\' + (Split-Path -Path $zipPath -Leaf)
$session = New-PSSession -ComputerName $target `
    -ConfigurationName 'Microsoft.PowerShell' `
    -Authentication Kerberos -ErrorAction Stop

try {
    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        if (Test-Path -LiteralPath 'C:\DSC\Runtime') {
            throw 'The target Runtime directory already exists. Verify it with step 2.5; it was not overwritten.'
        }
        New-Item -ItemType Directory -Path 'C:\DSC\Packages' -Force | Out-Null
    }

    Copy-Item -LiteralPath $zipPath -Destination $remoteZipPath `
        -ToSession $session -ErrorAction Stop

    Invoke-Command -Session $session -ArgumentList $remoteZipPath, $expectedHash `
        -ErrorAction Stop -ScriptBlock {
            param([string]$ZipPath, [string]$ExpectedHash)
            $ErrorActionPreference = 'Stop'

            if ((Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash -ne $ExpectedHash) {
                throw 'The transferred DSC archive failed SHA256 verification.'
            }

            Expand-Archive -LiteralPath $ZipPath -DestinationPath 'C:\DSC\Runtime' -ErrorAction Stop
            Write-Output "Runtime extracted on $env:COMPUTERNAME."
        }
}
finally {
    Remove-PSSession -Session $session
}
```

- **Expected:** `Runtime extracted on <target name>.`
- **Installation only:** no service, registry setting, security policy, or scheduled task is configured.
- **On failure:** stop and inspect the error and any partial Runtime directory before retrying; successful extraction is not yet a working-engine verdict.

### 2.5. Verify DSC on the Target

- **Run on:** the administration server; DSC executes on `$target`, not locally.

```powershell
Invoke-Command -ComputerName $target -ConfigurationName 'Microsoft.PowerShell' `
    -Authentication Kerberos -ErrorAction Stop -ScriptBlock {
        $ErrorActionPreference = 'Stop'
        $env:PATH = "C:\DSC\Runtime;$env:PATH"
        $dsc = 'C:\DSC\Runtime\dsc.exe'

        Write-Output "Server: $env:COMPUTERNAME"
        $version = & $dsc --version
        if ($LASTEXITCODE -ne 0 -or $version -ne 'dsc 3.2.3') {
            throw 'Expected DSC 3.2.3 at C:\DSC\Runtime\dsc.exe on the target.'
        }
        $version

        & $dsc resource get --resource Microsoft/OSInfo --output-format yaml
        if ($LASTEXITCODE -ne 0) {
            throw "Remote DSC read failed with exit code $LASTEXITCODE."
        }
    }
```

- **Expected:** the target's name, `dsc 3.2.3`, and `actualState` describing the target OS.
- **Resource:** `Microsoft/OSInfo` comes with the copied package; no additional resource module is needed.
- **Effect:** read-only; the PATH change applies only to this remote session.
- **Next checkpoint:** confirm this result before adding the first configuration compliance check.

## 3. Add Remote Checks

- [ ] Start with one target and one setting.
- [ ] Define the desired state in a configuration document.
- [ ] Run a compliance test and inspect the observed state and differences.
- [ ] Record the command and expected result.
- [ ] Add further checks one at a time.

## Format for Each Detailed Step

- **Run on:** the machine where the command starts.
- **Prerequisites:** only what the step requires.
- **Commands:** copyable command blocks.
- **Verify:** expected output or state.
- **Watch out:** a short caveat when needed.

## Sources

- [Microsoft DSC installation guide](https://learn.microsoft.com/en-us/powershell/dsc/install?view=dsc-3.0).
- [DSC 3.2.3 release and packages](https://github.com/PowerShell/DSC/releases/tag/v3.2.3).
- [Windows PowerShell remoting requirements](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-5.1).
si besoin 