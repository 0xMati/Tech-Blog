#
# =============================================================================
#  Entra ID Simple Tenant Migration Tool - Sample Configuration
# =============================================================================
#
#  HOW TO USE
#  ----------
#  1. Copy this file to "config.psd1" in the same folder.
#  2. Replace the placeholder values below with your own tenants / preferences.
#  3. Launch  .\Start-EIDMigrationTool.ps1
#
#  This file is a PowerShell data file (.psd1). It must contain a single
#  hashtable literal - no logic, no variables, no script blocks.
#
# =============================================================================

@{

    # -------------------------------------------------------------------------
    # Run = Output and working folders for migration runs.
    # -------------------------------------------------------------------------
    Run = @{

        # Root folder where each migration run creates its own dated sub-folder
        # (logs, CSVs, run_state.csv, etc.).
        # Relative paths are resolved from the tool root folder.
        OutputRoot = '.\output\runs'
    }

    # -------------------------------------------------------------------------
    # Tenants = Source and Target Entra ID tenants involved in the migration.
    # -------------------------------------------------------------------------
    Tenants = @{

        # SOURCE tenant: the tenant users / mailboxes / OneDrive / SharePoint
        # are migrated FROM. Accepts either:
        #   - the verified domain name (e.g. 'contoso.onmicrosoft.com')
        #   - the tenant GUID         (e.g. 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        Source = @{ TenantIdOrDomain = 'contoso.onmicrosoft.com' }

        # TARGET tenant: the tenant content is migrated TO.
        Target = @{ TenantIdOrDomain = 'fabrikam.onmicrosoft.com' }
    }

    # -------------------------------------------------------------------------
    # Workloads = Which phases of the migration are enabled.
    # -------------------------------------------------------------------------
    #
    # Set a workload to $false to hide it from the menu and skip its
    # prerequisite checks at startup. This is useful when a customer has no
    # on-prem AD, no SharePoint, etc.
    #
    # -------------------------------------------------------------------------
    Workloads = @{

        # Phase 01 - Discovery of source tenant (recipients, mailboxes, etc.).
        # Almost always $true.
        Discovery           = $true

        # Phase 02 - Identity Preparation in the TARGET tenant.
        # If $true, the tool will also require the ActiveDirectory RSAT module
        # and a writable Domain Controller to provision on-prem accounts that
        # synchronise to the target tenant via Entra Connect.
        # Set to $false for pure cloud-only target tenants.
        IdentityPreparation = $true

        # Phase 03 + 04 - Exchange Online mailbox migration (plan + execution).
        # Requires the ExchangeOnlineManagement module.
        ExchangeMigration   = $true

        # Phase 05 + 06 - OneDrive for Business cross-tenant migration.
        # Requires the Microsoft.Online.SharePoint.PowerShell module and a
        # configured cross-tenant trust (MnA).
        OneDriveMigration   = $true

        # Phase 07 + 08 - SharePoint cross-tenant site migration.
        # Same prerequisites as OneDrive.
        SharePointMigration = $true
    }

    # -------------------------------------------------------------------------
    # OnPremIdentity = Local cache used by Phase 02 (Identity Preparation).
    # -------------------------------------------------------------------------
    OnPremIdentity = @{

        # Last on-prem AD OU used as the default target for new accounts.
        # Leave empty on first run - the tool prompts for an OU during
        # Phase 02 and writes the chosen DN back here automatically, so
        # the next run can re-use it as the default.
        # Example after first run: 'OU=Migrated Users,DC=corp,DC=contoso,DC=com'
        LastUsedTargetOU = ''
    }
}
