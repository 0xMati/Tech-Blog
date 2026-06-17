# Collectors\Get-MATIGPPPasswords.ps1
# MATIv2 - Scans SYSVOL Group Policy Preferences XML files for the 'cpassword'
# attribute (MS14-025). cpassword values are AES-256 encrypted with a key that
# Microsoft published, so any cpassword present is trivially recoverable by any
# authenticated user able to read SYSVOL.

function Get-MATIGPPPasswords {
    <#
    .SYNOPSIS
        Walks every GPO folder in SYSVOL and reports Group Policy Preferences
        files that contain a non-empty 'cpassword' attribute (MS14-025).
    .OUTPUTS
        [hashtable] with keys: Findings (list), Errors (list)
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $errors   = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Microsoft-published 32-byte AES key for GPP cpassword (MS14-025).
    $aesKey = [byte[]](
        0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
        0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
    )

    # Attributes that, when present on the same element, indicate the account
    # the cpassword belongs to (varies by preference type).
    $accountAttrs = @('userName','newName','accountName','runAs','username','name')

    function Get-MATIDecryptedCPassword {
        param([string]$Cpassword, [byte[]]$Key)
        if ([string]::IsNullOrWhiteSpace($Cpassword)) { return $null }
        try {
            # Base64 in the XML omits padding; restore it.
            $mod = $Cpassword.Length % 4
            if ($mod -ne 0) { $Cpassword = $Cpassword.PadRight($Cpassword.Length + (4 - $mod), '=') }
            $cipher = [Convert]::FromBase64String($Cpassword)

            $aes = [System.Security.Cryptography.Aes]::Create()
            $aes.Key     = $Key
            $aes.IV      = New-Object byte[] 16   # GPP uses a zero IV
            $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            $decryptor = $aes.CreateDecryptor()
            $plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)
            $decryptor.Dispose(); $aes.Dispose()
            return [System.Text.Encoding]::Unicode.GetString($plain)
        } catch {
            return $null
        }
    }

    foreach ($domainDns in $forest.Domains) {
        $policiesPath = "\\$domainDns\SYSVOL\$domainDns\Policies"
        if (-not (Test-Path $policiesPath)) {
            $errors.Add([PSCustomObject]@{ Domain = $domainDns; Error = "SYSVOL Policies path not reachable: $policiesPath" })
            continue
        }

        try {
            # Only preference XML files can carry cpassword; restrict the walk to them.
            $xmlFiles = Get-ChildItem -Path $policiesPath -Recurse -File -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue
        } catch {
            $errors.Add([PSCustomObject]@{ Domain = $domainDns; Error = "Failed to enumerate SYSVOL: $($_.Exception.Message)" })
            continue
        }

        foreach ($file in $xmlFiles) {
            try {
                [xml]$xml = Get-Content -Path $file.FullName -Raw -ErrorAction Stop
            } catch { continue }

            # Find every element that carries a non-empty cpassword attribute.
            $nodes = $xml.SelectNodes('//*[@cpassword]')
            if (-not $nodes -or $nodes.Count -eq 0) { continue }

            # Resolve the GPO GUID from the path (...\Policies\{GUID}\...).
            $guid = $null
            if ($file.FullName -match '\\Policies\\(\{[0-9A-Fa-f\-]+\})\\') { $guid = $Matches[1] }

            foreach ($node in $nodes) {
                $cpw = $node.GetAttribute('cpassword')
                if ([string]::IsNullOrWhiteSpace($cpw)) { continue }

                # Best-effort account name (check the element and its Properties child).
                $account = $null
                foreach ($a in $accountAttrs) {
                    $val = $node.GetAttribute($a)
                    if ($val) { $account = $val; break }
                }
                if (-not $account -and $node.ParentNode) {
                    foreach ($a in $accountAttrs) {
                        $val = $node.ParentNode.GetAttribute($a)
                        if ($val) { $account = $val; break }
                    }
                }

                $plain = Get-MATIDecryptedCPassword -Cpassword $cpw -Key $aesKey

                $findings.Add([PSCustomObject]@{
                    Domain        = $domainDns
                    GPOGuid       = $guid
                    FileType      = $file.Name
                    FilePath      = $file.FullName
                    Element       = $node.LocalName
                    AccountName   = $account
                    # Do not store the plaintext in reports; recording that it is
                    # recoverable (and its length) is enough to prove the exposure.
                    Recoverable   = [bool]$plain
                    PasswordLength = if ($plain) { $plain.Length } else { $null }
                })
            }
        }
    }

    return @{
        Findings = @($findings)
        Errors   = @($errors)
    }
}
