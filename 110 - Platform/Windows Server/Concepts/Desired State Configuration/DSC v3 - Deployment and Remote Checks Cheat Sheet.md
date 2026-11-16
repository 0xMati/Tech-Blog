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

## 2. Prepare Remote Execution

- [ ] Identify the administration server and first target.
- [ ] Verify name resolution, connectivity, and remote execution permissions.
- [ ] Prepare DSC and the required resources on the target where checks will execute.
- [ ] Verify a read-only remote run.

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
si besoin 