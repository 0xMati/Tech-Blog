# Collectors\Get-MATIGPOSettings.ps1
# MATIv2 - Parses GPO security settings from SYSVOL (GptTmpl.inf + Registry.pol)
# for GPOs linked to Domain Controllers OU and domain root.

function Get-MATIGPOSettings {
    <#
    .SYNOPSIS
        Parses GPO files from SYSVOL to extract effective security settings
        applied to Domain Controllers (DC OU + inherited domain-level GPOs).
    .OUTPUTS
        [hashtable] with PerDomain → each domain has RegistryPolicies,
        AuditPolicy, SecurityOptions, SystemAccess, RestrictedGroups, ServiceSettings.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest   = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $domCache = $Config['_DomainCache'] ?? @{}

    # ==================================================================
    # Helper: Parse GptTmpl.inf (INI format, typically UTF-16LE)
    # ==================================================================
    function ConvertFrom-GptTmplInf {
        param([string]$Path)
        if (-not (Test-Path $Path)) { return @{} }

        $content = $null
        try { $content = Get-Content -Path $Path -Encoding Unicode -ErrorAction Stop } catch { }
        if (-not $content) {
            try { $content = Get-Content -Path $Path -Encoding UTF8 -ErrorAction Stop } catch { return @{} }
        }
        if (-not $content) { return @{} }

        $result = @{}
        $currentSection = $null
        foreach ($line in $content) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
            if ($trimmed -match '^\[(.+)\]$') {
                $currentSection = $Matches[1]
                if (-not $result.ContainsKey($currentSection)) {
                    $result[$currentSection] = [ordered]@{}
                }
                continue
            }
            if ($currentSection -and $trimmed -match '^(.+?)\s*=\s*(.*)$') {
                $result[$currentSection][$Matches[1].Trim()] = $Matches[2].Trim()
            }
        }
        return $result
    }

    # ==================================================================
    # Helper: Parse Registry.pol binary file (MS-GPREG / PReg format)
    # ==================================================================
    function ConvertFrom-RegistryPol {
        param([string]$Path)
        if (-not (Test-Path $Path)) { return @() }

        try { $bytes = [System.IO.File]::ReadAllBytes($Path) } catch { return @() }
        if ($bytes.Length -lt 8) { return @() }

        # Verify PReg signature (0x50 0x52 0x65 0x67)
        if ($bytes[0] -ne 0x50 -or $bytes[1] -ne 0x52 -or $bytes[2] -ne 0x65 -or $bytes[3] -ne 0x67) {
            return @()
        }

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $pos = 8   # skip 4-byte signature + 4-byte version

        while ($pos -lt ($bytes.Length - 2)) {
            # Expect opening bracket '[' = 0x5B 0x00 (UTF-16LE)
            if ($bytes[$pos] -ne 0x5B -or $bytes[$pos + 1] -ne 0x00) { $pos++; continue }
            $pos += 2

            # --- Read Key (null-terminated UTF-16LE) ---
            $start = $pos
            while (($pos + 1) -lt $bytes.Length -and -not ($bytes[$pos] -eq 0x00 -and $bytes[$pos + 1] -eq 0x00)) {
                $pos += 2
            }
            $key = [System.Text.Encoding]::Unicode.GetString($bytes, $start, $pos - $start)
            $pos += 2  # skip null terminator
            $pos += 2  # skip semicolon (0x3B 0x00)

            # --- Read ValueName (null-terminated UTF-16LE) ---
            $start = $pos
            while (($pos + 1) -lt $bytes.Length -and -not ($bytes[$pos] -eq 0x00 -and $bytes[$pos + 1] -eq 0x00)) {
                $pos += 2
            }
            $valueName = [System.Text.Encoding]::Unicode.GetString($bytes, $start, $pos - $start)
            $pos += 2  # skip null terminator
            $pos += 2  # skip semicolon

            # --- Read Type (4-byte DWORD LE) ---
            if (($pos + 4) -gt $bytes.Length) { break }
            $regType = [BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            $pos += 2  # skip semicolon

            # --- Read Size (4-byte DWORD LE) ---
            if (($pos + 4) -gt $bytes.Length) { break }
            $dataSize = [BitConverter]::ToUInt32($bytes, $pos)
            $pos += 4
            $pos += 2  # skip semicolon

            # --- Read Data ---
            $data = $null
            if ($dataSize -gt 0 -and ($pos + $dataSize) -le $bytes.Length) {
                switch ($regType) {
                    1  { $data = [System.Text.Encoding]::Unicode.GetString($bytes, $pos, $dataSize).TrimEnd("`0") }
                    2  { $data = [System.Text.Encoding]::Unicode.GetString($bytes, $pos, $dataSize).TrimEnd("`0") }
                    3  { $data = [byte[]]$bytes[$pos..($pos + $dataSize - 1)] }
                    4  { if ($dataSize -ge 4) { $data = [BitConverter]::ToUInt32($bytes, $pos) } }
                    7  { $data = [System.Text.Encoding]::Unicode.GetString($bytes, $pos, $dataSize).TrimEnd("`0").Split("`0") }
                    11 { if ($dataSize -ge 8) { $data = [BitConverter]::ToUInt64($bytes, $pos) } }
                    default { $data = [byte[]]$bytes[$pos..($pos + $dataSize - 1)] }
                }
            }
            $pos += $dataSize

            # Skip closing bracket ']' = 0x5D 0x00
            if (($pos + 1) -lt $bytes.Length) { $pos += 2 }

            $results.Add([PSCustomObject]@{
                Key       = $key
                ValueName = $valueName
                Type      = $regType
                Data      = $data
            })
        }
        return $results
    }

    # ==================================================================
    # Helper: Parse gpLink attribute into ordered list of GPO links
    # ==================================================================
    function ConvertFrom-GpLink {
        param([string]$GpLink)
        if (-not $GpLink) { return @() }

        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $linkMatches = [regex]::Matches($GpLink, '\[LDAP://([^;]+);(\d+)\]', 'IgnoreCase')
        foreach ($m in $linkMatches) {
            $gpoDN   = $m.Groups[1].Value
            $options = [int]$m.Groups[2].Value
            $enabled  = ($options -band 1) -eq 0
            $enforced = ($options -band 2) -ne 0

            $guid = $null
            if ($gpoDN -match 'CN=(\{[0-9a-fA-F\-]+\})') { $guid = $Matches[1] }

            $results.Add([PSCustomObject]@{
                DN       = $gpoDN
                GUID     = $guid
                Enabled  = $enabled
                Enforced = $enforced
            })
        }
        return $results
    }

    # ==================================================================
    # Main: Process each domain
    # ==================================================================
    $perDomain = @{}

    foreach ($domainDns in $forest.Domains) {
        try {
            $domObj = $domCache[$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)
            $domDN  = $domObj.DistinguishedName
            $dcOUdn = "OU=Domain Controllers,$domDN"

            # Read gpLink from DC OU and domain root
            $dcOUObj    = $null
            $domRootObj = $null
            try { $dcOUObj    = Get-ADObject -Identity $dcOUdn -Properties gpLink, gpOptions -Server $domainDns -ErrorAction Stop } catch { }
            try { $domRootObj = Get-ADObject -Identity $domDN  -Properties gpLink -Server $domainDns -ErrorAction Stop } catch { }

            $dcGPOLinks  = ConvertFrom-GpLink -GpLink $dcOUObj.gpLink
            $domGPOLinks = ConvertFrom-GpLink -GpLink $domRootObj.gpLink
            $dcBlockInherit = ($dcOUObj.gpOptions -eq 1)

            # Build effective GPO list for DCs (lower precedence first → higher precedence last)
            # Domain GPOs are inherited; DC OU GPOs override; enforced GPOs always apply
            $effectiveGPOs = [System.Collections.Generic.List[PSCustomObject]]::new()
            if (-not $dcBlockInherit) {
                foreach ($g in $domGPOLinks) {
                    if ($g.Enabled) {
                        $effectiveGPOs.Add([PSCustomObject]@{ GUID = $g.GUID; DN = $g.DN; LinkedTo = 'Domain'; Enforced = $g.Enforced })
                    }
                }
            } else {
                foreach ($g in $domGPOLinks) {
                    if ($g.Enabled -and $g.Enforced) {
                        $effectiveGPOs.Add([PSCustomObject]@{ GUID = $g.GUID; DN = $g.DN; LinkedTo = 'Domain'; Enforced = $true })
                    }
                }
            }
            foreach ($g in $dcGPOLinks) {
                if ($g.Enabled) {
                    $effectiveGPOs.Add([PSCustomObject]@{ GUID = $g.GUID; DN = $g.DN; LinkedTo = 'DomainControllers'; Enforced = $g.Enforced })
                }
            }

            # Parse GPO files from SYSVOL
            $sysvolBase      = "\\$domainDns\SYSVOL\$domainDns\Policies"
            $allRegPolicies  = [System.Collections.Generic.List[PSCustomObject]]::new()
            $mergedAudit     = [ordered]@{}
            $mergedSecOpts   = [ordered]@{}
            $mergedSysAccess = [ordered]@{}
            $mergedGroups    = [ordered]@{}
            $mergedServices  = [ordered]@{}
            $gpoNames        = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($gpo in $effectiveGPOs) {
                if (-not $gpo.GUID) { continue }
                $gpoPath = Join-Path $sysvolBase $gpo.GUID

                $gpoDisplayName = $null
                try {
                    $gpoAD = Get-ADObject -Identity $gpo.DN -Properties displayName -Server $domainDns -ErrorAction SilentlyContinue
                    $gpoDisplayName = $gpoAD.displayName
                } catch { }
                $gpoLabel = $gpoDisplayName ?? $gpo.GUID
                $gpoNames.Add([PSCustomObject]@{ GUID = $gpo.GUID; DisplayName = $gpoDisplayName; LinkedTo = $gpo.LinkedTo })

                # ---- Parse GptTmpl.inf ----
                $infPath = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
                if (Test-Path $infPath) {
                    $inf = ConvertFrom-GptTmplInf -Path $infPath

                    if ($inf.ContainsKey('Event Audit')) {
                        foreach ($kv in $inf['Event Audit'].GetEnumerator()) { $mergedAudit[$kv.Key] = $kv.Value }
                    }
                    if ($inf.ContainsKey('Registry Values')) {
                        foreach ($kv in $inf['Registry Values'].GetEnumerator()) { $mergedSecOpts[$kv.Key] = $kv.Value }
                    }
                    if ($inf.ContainsKey('System Access')) {
                        foreach ($kv in $inf['System Access'].GetEnumerator()) { $mergedSysAccess[$kv.Key] = $kv.Value }
                    }
                    if ($inf.ContainsKey('Group Membership')) {
                        foreach ($kv in $inf['Group Membership'].GetEnumerator()) { $mergedGroups[$kv.Key] = $kv.Value }
                    }
                    if ($inf.ContainsKey('Service General Setting')) {
                        foreach ($kv in $inf['Service General Setting'].GetEnumerator()) { $mergedServices[$kv.Key] = $kv.Value }
                    }
                }

                # ---- Parse Machine Registry.pol ----
                $polPath = Join-Path $gpoPath 'Machine\Registry.pol'
                if (Test-Path $polPath) {
                    $polEntries = ConvertFrom-RegistryPol -Path $polPath
                    foreach ($entry in $polEntries) {
                        $allRegPolicies.Add([PSCustomObject]@{
                            GPO       = $gpoLabel
                            LinkedTo  = $gpo.LinkedTo
                            Key       = $entry.Key
                            ValueName = $entry.ValueName
                            Type      = $entry.Type
                            Data      = $entry.Data
                        })
                    }
                }
            }

            $perDomain[$domainDns] = @{
                EffectiveGPOs    = @($gpoNames)
                RegistryPolicies = @($allRegPolicies)
                AuditPolicy      = $mergedAudit
                SecurityOptions  = $mergedSecOpts
                SystemAccess     = $mergedSysAccess
                RestrictedGroups = $mergedGroups
                ServiceSettings  = $mergedServices
            }

            Write-Host "    $domainDns : $($effectiveGPOs.Count) DC GPOs, $($allRegPolicies.Count) registry policies, $($mergedSecOpts.Count) security options" -ForegroundColor DarkGray

        } catch {
            Write-Warning "    Cannot parse GPO settings for $domainDns : $($_.Exception.Message)"
            $perDomain[$domainDns] = @{
                EffectiveGPOs    = @()
                RegistryPolicies = @()
                AuditPolicy      = @{}
                SecurityOptions  = @{}
                SystemAccess     = @{}
                RestrictedGroups = @{}
                ServiceSettings  = @{}
            }
        }
    }

    return @{ PerDomain = $perDomain }
}
