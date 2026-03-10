# Config\MATI.config.psd1
# MATIv2 - Declarative configuration file
# All thresholds, scoring weights, and exclusions are defined here.
# This file is loaded once at startup by Initialize-MATIEngine.

@{
    # ----------------------------------------------------------------
    # General settings
    # ----------------------------------------------------------------
    General = @{
        ToolName    = 'MATI - Microsoft Active Directory Threat Inspector'
        Version     = '2.0.0'
        Author      = 'mamotron'
        # Maximum parallel jobs for collectors (0 = sequential)
        MaxParallel = 0
    }

    # ----------------------------------------------------------------
    # Scoring configuration  (Multiplicative Decay Model)
    #
    # How it works:
    #   1. Each category has a "budget" representing its share of the
    #      total 100-point score.
    #   2. Each distinct rule that fires reduces its category's
    #      remaining budget by a percentage (SeverityImpact).
    #   3. Multiplicative decay ensures natural diminishing returns:
    #      the first rule hurts the most; each subsequent one has
    #      less room to deduct.
    #   4. Score = BaseScore - SUM(category deductions).
    # ----------------------------------------------------------------
    Scoring = @{
        BaseScore = 100

        # Percentage of remaining category budget consumed per rule.
        # e.g., Critical = 35 means each Critical rule eats 35 %
        # of whatever remains in that category.
        SeverityImpact = @{
            Critical      = 35
            High          = 20
            Medium        = 8
            Low           = 3
            Informational = 0
        }

        # Category budgets (max possible deduction per category).
        # The sum defines the theoretical floor of the score.
        CategoryWeights = @{
            ACL                = 15
            ADCS               = 8
            Config             = 10
            Delegation         = 8
            Hardening          = 15
            Kerberos           = 12
            PasswordPolicy     = 10
            PrivilegedAccounts = 10
            StaleObjects       = 7
            RODC               = 5
        }

        # Fallback budget for categories not listed above
        DefaultCategoryWeight = 8

        # Grade thresholds (score >= threshold = grade)
        Grades = @{
            A = 85
            B = 70
            C = 50
            D = 30
            E = 0
        }
    }

    # ----------------------------------------------------------------
    # Thresholds used by rules (adjustable per environment)
    # ----------------------------------------------------------------
    Thresholds = @{
        # Stale accounts
        StaleAccountDays = @{
            Medium   = 90
            High     = 180
            Critical = 365
        }

        # Max members in privileged groups before alert
        PrivilegedGroupMaxMembers = @{
            'Domain Admins'     = 5
            'Enterprise Admins' = 3
            'Schema Admins'     = 1
        }

        # Password age for privileged accounts (days)
        PrivilegedPasswordMaxAge = 180

        # KRBTGT password max age (days)
        KrbtgtPasswordMaxAge = 180

        # Minimum domain functional level (numeric: 7 = 2016)
        MinDomainFunctionalLevel = 7

        # Minimum forest functional level
        MinForestFunctionalLevel = 7

        # Tombstone lifetime minimum (days)
        MinTombstoneLifetime = 60

        # Inactive days before a privileged account is flagged
        PrivilegedInactiveDays = 90

        # Minimum password length for default domain policy (PWD-001)
        MinPasswordLength = 12

        # Maximum MachineAccountQuota before flagged (HARD-003)
        MaxMachineAccountQuota = 0

        # Trust inactivity threshold in days (CONFIG-014)
        TrustInactiveDays = 365

        # Legacy OS patterns considered critical / high / medium
        LegacyOS = @{
            Critical = @('2008', '2003', 'Windows 7', 'Windows 8', 'Windows XP', 'Windows Vista')
            High     = @('2012')
            Medium   = @('2016', 'Windows 10')
        }

        # LAPS coverage minimum percentage before flagging (HARD-017)
        LAPSMinCoverage = 80

        # DC machine account password max age in days (CONFIG-017)
        DCPasswordMaxAge = 60

        # CA certificate expiration warning in days (ADCS-009)
        CACertExpiryWarningDays = 180

        # Maximum number of non-privileged PwdNeverExpires accounts (HARD-025)
        MaxPwdNeverExpiresNonPriv = 20

        # Audit policy subcategories that must be enabled (HARD-023)
        RequiredAuditSubcategories = @(
            'Logon'
            'Logoff'
            'Credential Validation'
            'Security Group Management'
            'User Account Management'
            'Computer Account Management'
            'Directory Service Access'
            'Directory Service Changes'
            'Kerberos Authentication Service'
            'Kerberos Service Ticket Operations'
            'Special Logon'
            'Other Object Access Events'
        )

        # Legacy Protocol Audit — event-log based analysis on DCs
        EventLogAudit = @{
            # Hours of event history to collect (default: 24)
            Hours = 24
            # Max entries returned per top-N list (accounts, services, IPs)
            TopN  = 15
        }
    }

    # ----------------------------------------------------------------
    # Exclusions - objects or rules to ignore
    # ----------------------------------------------------------------
    Exclusions = @{
        # Distinguished Names to exclude from findings (exact match)
        ExcludedDNs = @()

        # SamAccountNames to exclude
        ExcludedSamAccountNames = @()

        # Rule IDs to disable entirely
        DisabledRules = @()

        # Categories to skip entirely
        DisabledCategories = @()
    }

    # ----------------------------------------------------------------
    # Collectors configuration
    # ----------------------------------------------------------------
    Collectors = @{
        # Properties to request via Get-ADUser (performance optimization)
        UserProperties = @(
            'SamAccountName', 'DistinguishedName', 'Enabled', 'LastLogonTimestamp',
            'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
            'DoesNotRequirePreAuth', 'AdminCount', 'SIDHistory', 'PrimaryGroupID',
            'ServicePrincipalName', 'UserAccountControl', 'MemberOf',
            'msDS-SupportedEncryptionTypes', 'WhenCreated', 'Description',
            'TrustedForDelegation', 'TrustedToAuthForDelegation',
            'msDS-AllowedToDelegateTo',
            'msDS-KeyCredentialLink'
        )

        # Properties to request via Get-ADComputer
        ComputerProperties = @(
            'SamAccountName', 'DistinguishedName', 'Enabled', 'LastLogonTimestamp',
            'PasswordLastSet', 'OperatingSystem', 'OperatingSystemVersion',
            'IPv4Address', 'DNSHostName', 'ServicePrincipalName',
            'TrustedForDelegation', 'TrustedToAuthForDelegation',
            'msDS-AllowedToDelegateTo', 'msDS-SupportedEncryptionTypes',
            'UserAccountControl', 'WhenCreated', 'Description', 'AdminCount',
            'PrimaryGroupID',
            'msDS-AllowedToActOnBehalfOfOtherIdentity',
            'msDS-KeyCredentialLink'
        )
    }

    # ----------------------------------------------------------------
    # Report settings
    # ----------------------------------------------------------------
    Report = @{
        # Which reporters to run (CSV, HTML, JSON)
        EnabledFormats = @('CSV', 'HTML', 'JSON')

        # Company name shown in the HTML report header
        CompanyName = ''

        # Date format for report display
        DateFormat = 'yyyy-MM-dd HH:mm:ss'
    }
}
