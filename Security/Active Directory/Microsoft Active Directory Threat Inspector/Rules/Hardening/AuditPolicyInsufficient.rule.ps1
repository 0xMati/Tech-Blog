# Rules\Hardening\AuditPolicyInsufficient.rule.ps1
# Flags DCs where critical audit subcategories are not configured.

@{
    Id          = 'MATI-HARD-023'
    Title       = 'Insufficient audit policy on Domain Controller'
    Severity    = 'Medium'
    Description = "Critical audit subcategories on one or more Domain Controllers do not meet the minimum configured audit mode. The rule compares the observed advanced audit policy to the expected baseline defined in the MATI configuration."
    Remediation = "Configure Advanced Audit Policy via GPO so each required subcategory meets or exceeds the baseline defined in Config\\MATI.config.psd1 under Thresholds.RequiredAuditSubcategories."
    Collectors  = @('ProtocolConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        function Convert-MATIAuditSetting {
            param([string]$Setting)

            $value = ($Setting ?? '').Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { return 'None' }

            switch -Regex ($value) {
                '^(Success and Failure|Succ[eè]s et [eé]chec)$' { return 'SuccessAndFailure' }
                '^(Success|Succ[eè]s)$'                          { return 'Success' }
                '^(Failure|[EÉ]chec)$'                           { return 'Failure' }
                '^(No Auditing|Aucun audit)$'                    { return 'None' }
                default                                          { return 'Unknown' }
            }
        }

        function Test-MATIAuditRequirement {
            param(
                [string]$Actual,
                [string]$Required
            )

            switch ($Required) {
                'SuccessAndFailure' { return $Actual -eq 'SuccessAndFailure' }
                'Success'           { return $Actual -in @('Success', 'SuccessAndFailure') }
                'Failure'           { return $Actual -in @('Failure', 'SuccessAndFailure') }
                'Any'               { return $Actual -notin @('None', 'Unknown') }
                default             { return $Actual -eq $Required }
            }
        }

        $requiredSubcategories = if ($Config.Thresholds.RequiredAuditSubcategories -is [hashtable] -and
            $Config.Thresholds.RequiredAuditSubcategories.Count -gt 0) {
            $Config.Thresholds.RequiredAuditSubcategories
        } else {
            @{
                '{0CCE9215-69AE-11D9-BED3-505054503030}' = @{ Name = 'Logon'; Requirement = 'SuccessAndFailure' }
                '{0CCE9216-69AE-11D9-BED3-505054503030}' = @{ Name = 'Logoff'; Requirement = 'Success' }
                '{0CCE921B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Special Logon'; Requirement = 'Success' }
                '{0CCE922F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Policy Change'; Requirement = 'SuccessAndFailure' }
                '{0CCE9230-69AE-11D9-BED3-505054503030}' = @{ Name = 'Authentication Policy Change'; Requirement = 'SuccessAndFailure' }
                '{0CCE9235-69AE-11D9-BED3-505054503030}' = @{ Name = 'User Account Management'; Requirement = 'SuccessAndFailure' }
                '{0CCE9236-69AE-11D9-BED3-505054503030}' = @{ Name = 'Computer Account Management'; Requirement = 'SuccessAndFailure' }
                '{0CCE9237-69AE-11D9-BED3-505054503030}' = @{ Name = 'Security Group Management'; Requirement = 'SuccessAndFailure' }
                '{0CCE923B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Directory Service Access'; Requirement = 'Success' }
                '{0CCE923C-69AE-11D9-BED3-505054503030}' = @{ Name = 'Directory Service Changes'; Requirement = 'SuccessAndFailure' }
                '{0CCE923F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Credential Validation'; Requirement = 'SuccessAndFailure' }
                '{0CCE9240-69AE-11D9-BED3-505054503030}' = @{ Name = 'Kerberos Service Ticket Operations'; Requirement = 'SuccessAndFailure' }
                '{0CCE9242-69AE-11D9-BED3-505054503030}' = @{ Name = 'Kerberos Authentication Service'; Requirement = 'SuccessAndFailure' }
            }
        }

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if (-not $dc.AuditPolicySub -or $dc.AuditPolicySub.Count -eq 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName        = $dc.DCName
                        Issue         = if ([string]::IsNullOrWhiteSpace($dc.AuditPolicyReadError)) { 'Could not read advanced audit policy from DC' } else { "$($dc.AuditPolicyReadError)" }
                        MissingCount  = $requiredSubcategories.Count
                    }
                }
                continue
            }

            $missingAudits = @()
            foreach ($subcatGuid in ($requiredSubcategories.Keys | Sort-Object)) {
                $expectedDef = $requiredSubcategories[$subcatGuid]
                $expectedName = if ($expectedDef -is [hashtable]) { [string]$expectedDef.Name } else { $subcatGuid }
                $required = if ($expectedDef -is [hashtable]) { [string]$expectedDef.Requirement } else { [string]$expectedDef }

                $observed = $dc.AuditPolicySub[$subcatGuid]
                $rawSetting = if ($observed) { [string]$observed.InclusionSetting } else { '' }
                $observedName = if ($observed -and $observed.Name) { [string]$observed.Name } else { $expectedName }
                $actual = Convert-MATIAuditSetting -Setting $rawSetting

                if (-not (Test-MATIAuditRequirement -Actual $actual -Required $required)) {
                    $displayActual = if ([string]::IsNullOrWhiteSpace($rawSetting)) { 'Missing' } else { $rawSetting }
                    $missingAudits += "$observedName (expected: $required, current: $displayActual)"
                }
            }

            if ($missingAudits.Count -gt 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.DCName
                        MissingAudits   = ($missingAudits -join ', ')
                        MissingCount    = $missingAudits.Count
                    }
                }
            }
        }
        return $findings
    }
}
