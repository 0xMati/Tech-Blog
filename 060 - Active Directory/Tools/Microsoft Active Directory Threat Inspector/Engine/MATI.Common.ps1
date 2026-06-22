# Engine\MATI.Common.ps1
# MATIv2 - Shared helper functions used across collectors, engine and scoring.
#
# These helpers exist primarily to make MATI resilient when the ActiveDirectory
# module is loaded through the Windows PowerShell compatibility layer
# (WinPSCompatSession) - e.g. when MATI runs from a workstation under PowerShell 7
# instead of directly on a domain controller. In that mode AD objects come back
# DESERIALIZED, which breaks naive casts like [int]$dom.DomainMode and
# property access like $dom.DomainSID.Value.

function Get-MATIFunctionalLevelNumeric {
    <#
    .SYNOPSIS
        Converts a domain/forest functional level (enum, int or deserialized
        string such as 'Windows2016Domain') to a comparable numeric level.
    .OUTPUTS
        [int] numeric level, or -1 when it cannot be determined.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        $Mode
    )

    if ($null -eq $Mode) { return -1 }

    # Native enum / integer
    if ($Mode -is [int]) { return [int]$Mode }

    $s = [string]$Mode
    if ([string]::IsNullOrWhiteSpace($s)) { return -1 }

    # Plain integer string
    $n = 0
    if ([int]::TryParse($s, [ref]$n)) { return $n }

    # Enum / deserialized string forms (e.g. 'Windows2016Domain', 'Windows2016Forest').
    # Order matters: more specific variants (Interim / R2) are tested first because
    # 'return' exits the function on the first match.
    switch -Regex ($s) {
        'Windows2000'        { return 0 }
        'Windows2003Interim' { return 1 }
        'Windows2003'        { return 2 }
        'Windows2008R2'      { return 4 }
        'Windows2008'        { return 3 }
        'Windows2012R2'      { return 6 }
        'Windows2012'        { return 5 }
        'Windows2016'        { return 7 }
        'Windows2019'        { return 7 }   # no distinct DFL beyond 2016
        'Windows2022'        { return 7 }
        'Windows2025'        { return 10 }
        default              { return -1 }
    }
}

function Get-MATIDomainSidString {
    <#
    .SYNOPSIS
        Robustly extracts a domain SID string (S-1-5-21-...) from an AD object's
        DomainSID property, whether native (SecurityIdentifier) or deserialized
        (string / PSObject) under WinPSCompat.
    .OUTPUTS
        [string] the domain SID, or $null when it is not a valid domain SID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        $DomainSID
    )

    if ($null -eq $DomainSID) { return $null }

    if ($DomainSID -is [System.Security.Principal.SecurityIdentifier]) {
        return $DomainSID.Value
    }

    # Deserialized objects may surface .Value as a NoteProperty; otherwise the
    # object itself stringifies to the SID (its preserved ToString()).
    $val = $null
    try { $val = $DomainSID.Value } catch { $val = $null }
    $sid = if ($val) { [string]$val } else { [string]$DomainSID }

    if ($sid -match '^S-1-5-21-\d') { return $sid }
    return $null
}

function Test-MATIWinPSCompat {
    <#
    .SYNOPSIS
        Returns $true when the ActiveDirectory module is being served through the
        Windows PowerShell compatibility layer (implicit remoting), which returns
        deserialized objects and disables the AD: PSProvider locally.
    #>
    [CmdletBinding()]
    param()

    # The compatibility layer creates an implicit remoting session named
    # 'WinPSCompatSession'. Its presence is the most reliable signal.
    if (Get-PSSession -Name 'WinPSCompatSession' -ErrorAction SilentlyContinue) {
        return $true
    }

    # Secondary signal: the AD provider is registered natively only when the
    # module is loaded in-process (native), not via compatibility remoting.
    if (-not (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction SilentlyContinue)) {
        return $true
    }

    return $false
}

function Get-MATIObjectAcl {
    <#
    .SYNOPSIS
        Reads the security descriptor of an AD object in a way that works both
        on a domain controller (native AD: PSProvider) and from a workstation
        where the ActiveDirectory module is served via the compatibility layer
        (provider unavailable -> System.DirectoryServices fallback).
    .PARAMETER DistinguishedName
        The DN of the object to read.
    .PARAMETER Server
        Optional DC / domain to target (avoids LDAP referrals on child domains).
    .OUTPUTS
        [System.DirectoryServices.ActiveDirectorySecurity] (has .Access / .Owner).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName,

        [string]$Server
    )

    # Preferred path: native AD: PSProvider (DC / in-process RSAT).
    if (Get-PSProvider -PSProvider ActiveDirectory -ErrorAction SilentlyContinue) {
        if ($Server) {
            $driveName = "MATIAcl_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            try {
                New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "" -Server $Server -ErrorAction Stop | Out-Null
                return Get-Acl -Path "${driveName}:\$DistinguishedName" -ErrorAction Stop
            }
            finally {
                Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue
            }
        }
        return Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
    }

    # Fallback path: read the security descriptor directly via LDAP/ADSI.
    $entry = $null
    try {
        $ldapPath = if ($Server) { "LDAP://$Server/$DistinguishedName" } else { "LDAP://$DistinguishedName" }
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        $null = $entry.RefreshCache(@('nTSecurityDescriptor'))
        $sd = $entry.ObjectSecurity
        if ($null -eq $sd) {
            throw "No security descriptor returned for $DistinguishedName"
        }
        return $sd
    }
    finally {
        if ($entry) { $entry.Dispose() }
    }
}
