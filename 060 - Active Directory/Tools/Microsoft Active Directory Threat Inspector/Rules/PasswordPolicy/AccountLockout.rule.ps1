# Rules\PasswordPolicy\AccountLockout.rule.ps1
# Flags weak or missing account lockout settings in the default domain policy.
# Complements PWD-001 (which checks length/complexity/history but NOT lockout).

@{
    Id          = 'MATI-PWD-004'
    Title       = 'Weak or disabled account lockout policy'
    Severity    = 'Medium'
    Description = "The account lockout policy does not provide effective protection against online password brute-force and password-spraying attacks. A lockout threshold of 0 means lockout is disabled entirely, allowing unlimited authentication attempts. A threshold that is too high, or a lockout duration that is too short, significantly weakens this protection."
    Remediation = "Configure the Default Domain Policy (or a Fine-Grained Password Policy for sensitive accounts) with an account lockout threshold of around 5-10 invalid attempts, a lockout duration of at least 15 minutes (or 0 for manual admin unlock on Tier 0), and a reset-counter (observation) window of at least 15 minutes. Beware setting the threshold too low, which can enable denial-of-service lockouts."
    Collectors  = @('PasswordPolicy')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy',
        'https://www.cisecurity.org/benchmark/microsoft_windows_server'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $cfg = $Config.Thresholds.AccountLockout
        $maxThreshold = if ($cfg -and $cfg.MaxLockoutThreshold)       { [int]$cfg.MaxLockoutThreshold }       else { 10 }
        $minDuration  = if ($cfg -and $cfg.MinLockoutDurationMinutes) { [int]$cfg.MinLockoutDurationMinutes } else { 15 }
        $minObserve   = if ($cfg -and $cfg.MinObservationMinutes)     { [int]$cfg.MinObservationMinutes }     else { 15 }

        # Helper: normalize a lockout TimeSpan-or-minutes value to whole minutes.
        $toMinutes = {
            param($v)
            if ($null -eq $v) { return $null }
            if ($v -is [timespan]) { return [int]$v.TotalMinutes }
            # Some sources expose duration as minutes already, or as a negative
            # 100ns interval (raw lockoutDuration). Treat plain numbers as minutes.
            try { return [int]$v } catch { return $null }
        }

        foreach ($policy in $Data.PasswordPolicy.DefaultPolicies) {
            $issues = @()

            $threshold   = $policy.LockoutThreshold
            $durationMin = & $toMinutes $policy.LockoutDuration
            $observeMin  = & $toMinutes $policy.LockoutObservationWindow

            if ($null -eq $threshold -or [int]$threshold -eq 0) {
                $issues += 'Lockout disabled (threshold = 0): unlimited password attempts allowed'
            }
            elseif ([int]$threshold -gt $maxThreshold) {
                $issues += "Lockout threshold too high ($threshold; expected <= $maxThreshold)"
            }

            # Only evaluate duration/observation when lockout is actually enabled.
            if ($null -ne $threshold -and [int]$threshold -gt 0) {
                # Duration 0 = "until an admin unlocks" — that is acceptable (stronger),
                # so only flag a positive-but-too-short duration.
                if ($null -ne $durationMin -and $durationMin -gt 0 -and $durationMin -lt $minDuration) {
                    $issues += "Lockout duration too short ($durationMin min; expected >= $minDuration min or 0 for manual unlock)"
                }
                if ($null -ne $observeMin -and $observeMin -gt 0 -and $observeMin -lt $minObserve) {
                    $issues += "Reset-counter window too short ($observeMin min; expected >= $minObserve min)"
                }
            }

            if ($issues.Count -gt 0) {
                # Disabled lockout is the most serious case.
                $severity = if ($null -eq $threshold -or [int]$threshold -eq 0) { 'High' } else { 'Medium' }
                $findings += @{
                    ObjectDN = $policy.Domain
                    Domain   = $policy.Domain
                    Severity = $severity
                    Details  = @{
                        LockoutThreshold        = "$threshold"
                        LockoutDurationMinutes  = if ($null -ne $durationMin) { "$durationMin" } else { 'n/a' }
                        ObservationWindowMinutes = if ($null -ne $observeMin) { "$observeMin" } else { 'n/a' }
                        Issues                  = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}
