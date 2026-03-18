# Config\Tiering.config.psd1
# MATI - Tiering Model Implementation Configuration
# Customize naming conventions, OU structure, and deployment options.

@{
    # ----------------------------------------------------------------
    # Naming conventions
    # ----------------------------------------------------------------
    Naming = @{
        # Admin account prefix per tier
        AccountPrefix = @{
            Tier0 = 't0'
            Tier1 = 't1'
            Tier2 = 't2'
        }

        # Group name prefix (e.g. T0-Admins, T1-Servers)
        GroupPrefix = 'T'

        # GPO name prefix
        GPOPrefix = 'Tiering'

        # Break-glass account base name
        BreakGlassBaseName = 'BreakGlass'
    }

    # ----------------------------------------------------------------
    # OU structure (names are customizable)
    # ----------------------------------------------------------------
    OUStructure = @{
        # Container OU name (used when deploying under a sub-OU instead of domain root)
        ContainerOU    = 'Tiering Model'

        Tier0          = 'Tier 0'
        Tier1          = 'Tier 1'
        Tier2          = 'Tier 2'
        Quarantine     = 'Quarantine'
        Disabled       = 'Disabled'
        StandardUsers  = 'Standard Users'

        # Sub-OUs under each tier
        SubOUs = @{
            Tier0 = @('Accounts', 'Groups', 'Service Accounts', 'Servers', 'PAW')
            Tier1 = @('Accounts', 'Groups', 'Service Accounts', 'Servers', 'PAW')
            Tier2 = @('Accounts', 'Groups', 'Service Accounts', 'Workstations')
        }

        # Sub-OUs under other containers
        QuarantineSubOUs = @('Computers')
        DisabledSubOUs   = @('Users', 'Computers')
    }

    # ----------------------------------------------------------------
    # Security groups to create per tier
    # ----------------------------------------------------------------
    Groups = @{
        # For each tier, groups are auto-created with the tier prefix
        # Scope: Global for identity groups, DomainLocal for deny groups
        PerTier = @(
            @{ Suffix = 'Admins';           Scope = 'Global';      Description = 'Admin accounts for this tier' }
            @{ Suffix = 'Servers';           Scope = 'Global';      Description = 'Server objects for this tier' }
            @{ Suffix = 'ServiceAccounts';   Scope = 'Global';      Description = 'Service accounts for this tier' }
        )

        # Tier-specific extras
        Tier0Extra = @(
            @{ Suffix = 'PAW-Computers';     Scope = 'Global';      Description = 'Tier 0 PAW workstations' }
        )
        Tier1Extra = @(
            @{ Suffix = 'PAW-Computers';     Scope = 'Global';      Description = 'Tier 1 PAW workstations' }
        )
        Tier2Extra = @(
            @{ Suffix = 'Workstations';      Scope = 'Global';      Description = 'Tier 2 workstations' }
        )

        # Deny logon groups (DomainLocal) — auto-generated cross-tier
        # T0-DenyLogon-T1, T0-DenyLogon-T2, T1-DenyLogon-T0, etc.
        DenyLogonSuffix = 'DenyLogon'
    }

    # ----------------------------------------------------------------
    # Authentication Policy & Silo
    # ----------------------------------------------------------------
    AuthPolicy = @{
        T0TGTLifetimeMinutes = 240
        SiloName             = 'T0-Silo'
        PolicyName           = 'T0-AuthPolicy'
        ComputerPolicyName   = 'T0-ComputerAuthPolicy'
    }

    # ----------------------------------------------------------------
    # GPO templates
    # ----------------------------------------------------------------
    GPO = @{
        # Deny logon GPO settings (applied per cross-tier pair)
        DenyLogonRights = @(
            'SeDenyInteractiveLogonRight'
            'SeDenyRemoteInteractiveLogonRight'
            'SeDenyNetworkLogonRight'
            'SeDenyBatchLogonRight'
            'SeDenyServiceLogonRight'
        )
    }

    # ----------------------------------------------------------------
    # LAPS
    # ----------------------------------------------------------------
    LAPS = @{
        PasswordLength     = 24
        PasswordAgeDays    = 30
        UseWindowsLAPS     = $true
    }

    # ----------------------------------------------------------------
    # Tier classification rules (auto-classification of existing objects)
    # ----------------------------------------------------------------
    Classification = @{
        # Tier 0 — any computer matching these criteria is T0
        Tier0 = @{
            # Server roles / SPNs that indicate Tier 0
            SPNPatterns = @(
                'ldap/*'          # Domain Controllers (auto-detected)
                'ADFS/*'          # AD FS servers
                'http/*adfs*'     # AD FS web
                'http/*sts*'      # Federation services
            )
            # OU name patterns (case-insensitive contains)
            OUPatterns = @(
                'Domain Controllers'
                'Tier 0'
                'Tier0'
                'T0'
            )
            # Server descriptions / names
            NamePatterns = @(
                '*ADFS*'
                '*PKI*'
                '*CA*'
                '*AADConnect*'
                '*EntraConnect*'
            )
            # Well-known server roles
            Roles = @('DomainController', 'ADFS', 'ADCS', 'AADConnect', 'PAM')
        }

        Tier1 = @{
            SPNPatterns = @(
                'MSSQLSvc/*'       # SQL Servers
                'HTTP/*'           # Web / App servers
                'exchangeMDB/*'    # Exchange
                'IMAP/*'
                'SMTP/*'
            )
            OUPatterns = @(
                'Tier 1'
                'Tier1'
                'T1'
                'Servers'
                'Member Servers'
            )
            NamePatterns = @(
                '*SQL*'
                '*APP*'
                '*WEB*'
                '*EXCH*'
                '*SCCM*'
                '*MECM*'
                '*SCOM*'
            )
        }

        # Tier 2 = everything else (workstations)
        Tier2 = @{
            OUPatterns = @(
                'Tier 2'
                'Tier2'
                'T2'
                'Workstations'
                'Desktops'
                'Laptops'
            )
        }
    }

    # ----------------------------------------------------------------
    # Phase execution control
    # ----------------------------------------------------------------
    Phases = @{
        # Phases to enable (0-9)
        Enabled = @(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
    }
}
