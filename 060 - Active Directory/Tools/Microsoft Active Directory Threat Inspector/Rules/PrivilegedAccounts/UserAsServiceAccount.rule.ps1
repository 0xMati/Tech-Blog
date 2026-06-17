# Rules\PrivilegedAccounts\UserAsServiceAccount.rule.ps1
# Flags regular user accounts that are (very likely) used as service accounts.
# Mirrors the confidence scoring of Invoke-AdUserServiceAccountDiscovery.ps1.
# Governance angle: these accounts should be migrated to gMSA / managed service
# accounts. SPN-only Kerberoasting / RC4 exposure is already covered by
# MATI-KERB-003 and MATI-KERB-010 — this rule adds the *non-SPN* behavioural
# signals (observed Type-5/4 logons, password hygiene, delegation, naming, OU).

@{
    Id          = 'MATI-ADMIN-020'
    Category    = 'Governance'
    Title       = 'User account used as a service account (non-gMSA)'
    Severity    = 'Medium'
    Description = "One or more enabled user accounts show strong evidence of being used as service accounts (service principal names, non-expiring passwords, service-like naming, delegation, RC4-without-AES, and/or observed service (Type 5) or batch (Type 4) logons in the security event log). Running services under regular user identities prevents automatic password rotation, complicates accountability, and widens the credential-theft attack surface."
    Remediation = "Migrate these workloads to group Managed Service Accounts (gMSA) or standalone Managed Service Accounts (sMSA) so that passwords are managed and rotated automatically by AD. Where gMSA is not possible, enforce long randomized passwords with regular rotation, remove unconstrained/constrained delegation that is not required, set msDS-SupportedEncryptionTypes to AES-only, and move the accounts into a dedicated, monitored service-account OU."
    Collectors  = @('UserAccounts', 'LegacyProtocolAudit')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview',
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $thr = $Config.Thresholds.ServiceAccountDiscovery
        $highThreshold   = if ($thr -and $thr.HighConfidence)   { [int]$thr.HighConfidence }   else { 70 }
        $mediumThreshold = if ($thr -and $thr.MediumConfidence) { [int]$thr.MediumConfidence } else { 45 }
        $oldPwdDays      = if ($thr -and $thr.OldPasswordDays)   { [int]$thr.OldPasswordDays }   else { 365 }

        $now = Get-Date

        # Analysis window for "recent / observed" signals = legacy audit window
        $auditHours = if ($Data.LegacyProtocolAudit.AuditHours) { [double]$Data.LegacyProtocolAudit.AuditHours } else { 24 }
        $since = $now.AddHours(-$auditHours)

        # ----- Build observed-logon lookup from 4624 Type 5/4/2/10/11 -----
        $usageBySam = @{}
        foreach ($u in @($Data.LegacyProtocolAudit.LogonTypeUsage)) {
            if (-not $u -or -not $u.Account) { continue }
            $k = ([string]$u.Account).ToUpperInvariant()
            if (-not $usageBySam.ContainsKey($k)) {
                $usageBySam[$k] = @{ Service = 0; Batch = 0; Interactive = 0 }
            }
            $usageBySam[$k].Service     += [int]$u.ServiceLogons
            $usageBySam[$k].Batch       += [int]$u.BatchLogons
            $usageBySam[$k].Interactive += [int]$u.InteractiveLogons
        }

        $keywordRegex = '(?i)(^svc[_\-\.]|[_\-\.]svc$|service|sql|iis|app|batch|job|task|daemon|runas|api)'
        $ouRegex      = '(?i)OU=[^,]*(service|svc)'

        foreach ($user in @($Data.UserAccounts)) {
            if (-not $user) { continue }
            if ($user.Enabled -ne $true) { continue }

            $score   = 0
            $reasons = @()

            # --- SPN present (+35) ---
            $spns = @($user.ServicePrincipalName | Where-Object { $_ })
            $spnCount = $spns.Count
            if ($spnCount -gt 0) { $score += 35; $reasons += "SPN present ($spnCount)" }

            # --- PasswordNeverExpires (+15) ---
            if ($user.PasswordNeverExpires -eq $true) { $score += 15; $reasons += 'PasswordNeverExpires' }

            # --- CannotChangePassword (+8) ---
            if ($user.CannotChangePassword -eq $true) { $score += 8; $reasons += 'CannotChangePassword' }

            # --- Service-like naming / description (+12) ---
            $text = @($user.SamAccountName, $user.Name, $user.DisplayName, $user.Description) -join ' '
            if ($text -match $keywordRegex) { $score += 12; $reasons += 'Service-like naming/description' }

            # --- Old password (>= oldPwdDays) (+8) ---
            $pwdAgeDays = $null
            if ($user.PasswordLastSet) {
                $pwdAgeDays = [int]([math]::Floor(($now - [datetime]$user.PasswordLastSet).TotalDays))
                if ($pwdAgeDays -ge $oldPwdDays) { $score += 8; $reasons += "Old password (${pwdAgeDays}d)" }
            }

            # --- Observed logons from 4624 ---
            $samKey = ([string]$user.SamAccountName).ToUpperInvariant()
            $svcLogons = 0; $batchLogons = 0; $interactiveLogons = 0
            if ($usageBySam.ContainsKey($samKey)) {
                $svcLogons         = [int]$usageBySam[$samKey].Service
                $batchLogons       = [int]$usageBySam[$samKey].Batch
                $interactiveLogons = [int]$usageBySam[$samKey].Interactive
            }
            if ($svcLogons   -gt 0) { $score += 35; $reasons += "Observed service logons (Type 5: $svcLogons)" }
            if ($batchLogons -gt 0) { $score += 12; $reasons += "Observed batch logons (Type 4: $batchLogons)" }

            # --- Delegation (+20) ---
            $allowedToDelegate = @($user.AllowedToDelegateTo | Where-Object { $_ })
            $hasDelegation = ($user.TrustedForDelegation -eq $true) -or
                             ($user.TrustedToAuthForDelegation -eq $true) -or
                             ($allowedToDelegate.Count -gt 0)
            if ($hasDelegation) { $score += 20; $reasons += 'Delegation configured' }

            # --- Privileged (+10) — AdminCount==1 (subset of script's MemberOf check) ---
            if ($user.AdminCount -eq 1) { $score += 10; $reasons += 'Privileged (AdminCount=1)' }

            # --- OU naming hint (+10) ---
            if ([string]$user.DistinguishedName -match $ouRegex) { $score += 10; $reasons += 'Service/SVC OU' }

            # --- Encryption type signals ---
            $enc = $user.SupportedEncryptionTypes
            $encSet = ($null -ne $enc -and [int]$enc -ne 0)
            if ($encSet) {
                $score += 8; $reasons += 'msDS-SupportedEncryptionTypes explicitly set'
                $hasRc4 = (([int]$enc -band 0x04) -ne 0)
                $hasAes = ((([int]$enc -band 0x08) -ne 0) -or (([int]$enc -band 0x10) -ne 0))
                if ($hasRc4 -and -not $hasAes) { $score += 10; $reasons += 'RC4 without AES' }
            }

            # --- PasswordNotRequired (+5) ---
            if ($user.PasswordNotRequired -eq $true) { $score += 5; $reasons += 'PasswordNotRequired' }

            # --- Recent logon within window (+5) ---
            if ($user.LastLogonDate -and ([datetime]$user.LastLogonDate) -ge $since) {
                $score += 5; $reasons += 'Recent logon'
            }

            # --- SmartcardLogonRequired (-25, likely human) ---
            if ($user.SmartcardLogonRequired -eq $true) { $score -= 25; $reasons += 'SmartcardLogonRequired (likely human)' }

            # --- Interactive-only usage (-15, likely human) ---
            if ($interactiveLogons -gt 0 -and $svcLogons -eq 0 -and $batchLogons -eq 0) {
                $score -= 15; $reasons += 'Interactive-only logons (likely human)'
            }

            # --- Clamp 0..100 ---
            if ($score -lt 0)   { $score = 0 }
            if ($score -gt 100) { $score = 100 }

            if ($score -lt $mediumThreshold) { continue }

            $confidence = if ($score -ge $highThreshold) { 'High' } else { 'Medium' }
            $severity   = if ($score -ge $highThreshold) { 'High' } else { 'Medium' }

            $findings += @{
                ObjectDN = $user.DistinguishedName
                Domain   = $user.Domain
                Severity = $severity
                Details  = @{
                    SamAccountName    = $user.SamAccountName
                    ConfidenceScore   = "$score / 100"
                    Confidence        = $confidence
                    Signals           = ($reasons -join '; ')
                    SpnCount          = "$spnCount"
                    ServiceLogonsType5 = "$svcLogons"
                    BatchLogonsType4  = "$batchLogons"
                    Delegation        = if ($hasDelegation) { 'Yes' } else { 'No' }
                    PasswordNeverExpires = if ($user.PasswordNeverExpires -eq $true) { 'Yes' } else { 'No' }
                }
            }
        }

        return $findings
    }
}
