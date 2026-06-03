# ADFS to Entra ID Relying Party Migration Assessment Tool

PowerShell tool that analyses every Relying Party Trust on an AD FS farm and reports its readiness to be migrated to **Microsoft Entra ID**.

Inspired by the now-archived Microsoft module [`ADFSAADMigrationUtils.psm1`](https://github.com/AzureAD/Deployment-Plans/tree/master/ADFS%20to%20AzureAD%20App%20Migration) (last updated 2022) and the validation tests documented in [Microsoft Entra AD FS application migration overview](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-ad-fs-application-overview).

This tool reproduces locally (no Entra Connect Health, no P1/P2 license required) what the **Entra portal → Usage & insights → AD FS application migration** dashboard does in the cloud.

## Why this tool

| Use case | Use this tool |
|---|---|
| ADFS not connected to Entra Connect Health | ✅ |
| No Entra ID P1/P2 license | ✅ |
| Air-gapped / offline ADFS farm | ✅ |
| Want a portable HTML report (no Excel/macros) | ✅ |
| Want updated tests reflecting Entra capabilities in 2026 | ✅ |

If you already have Entra Connect Health for AD FS deployed, the **portal feature is preferable** (continuously refreshed every 24h, integrated one-click migration).

## What it does

1. Reads every `Get-AdfsRelyingPartyTrust` on the local farm
2. Excludes Microsoft-internal RPs (`urn:federation:MicrosoftOnline`, `microsoftonline`, etc.)
3. Runs 16 validation tests (same set as the Entra portal)
4. Parses claim rules (issuance / authorization / delegation / impersonation) and flags non-migratable patterns
5. Optionally aggregates sign-in usage from the AD FS Security event log
6. Produces a **single self-contained HTML report** with:
   - Dashboard KPIs (Ready / Needs Review / Additional Steps)
   - Sortable, filterable table of all RPs
   - Drill-down per RP: tests, parsed claim rules, migration playbook
   - **Persistent checklist** (`localStorage`) to track migration progress per RP
7. Also outputs JSON + CSV for machine processing

## Tests implemented

All 16 `Test-ADFSRP*` validation tests from the Entra portal:

| Test | Default verdict | Updated for 2026 |
|---|---|---|
| `AdditionalAuthenticationRules` | Warning | — |
| `AdditionalWSFedEndpoint` | Fail | — |
| `AllowedAuthenticationClassReferences` | Fail | — |
| `AlwaysRequireAuthentication` | Fail | — |
| `AutoUpdateEnabled` | Warning | — |
| `ClaimsProviderName` (non-AD) | Fail | — |
| `DelegationAuthorizationRules` | Fail | — |
| `EncryptClaims` | **Pass** | ✅ Was Fail in 2022 — Entra now supports SAML token encryption |
| `EncryptedNameIdRequired` | Fail | — |
| `ImpersonationAuthorizationRules` | Warning | — |
| `IssuanceAuthorizationRules` | Warning | — |
| `IssuanceTransformRules` | Warning | — |
| `MonitoringEnabled` | Warning | — |
| `NotBeforeSkew` | Warning | — |
| `RequestMFAFromClaimsProviders` | Warning | — |
| `SignedSamlRequestsRequired` | **Warning** | ✅ Was Fail in 2022 — Entra accepts signed requests (does not verify) |
| `TokenLifetime` | Warning | — |

Verdict aggregation:
- **Ready** — all tests Pass
- **Needs review** — at least one Warning, no Fail
- **Additional steps required** — at least one Fail

## Requirements

- Windows Server with the **AD FS** role installed (the `ADFS` PowerShell module must be available)
- PowerShell **5.1** or **7+**
- Run as a member of `BUILTIN\Administrators` on the AD FS server
- Modern browser to view the HTML report (no internet needed — all assets inlined)

## Usage

```powershell
# Basic run — output goes to .\output next to the script
.\Invoke-AdfsRpMigrationAssessment.ps1

# Override output path
.\Invoke-AdfsRpMigrationAssessment.ps1 -OutputPath C:\Temp\AdfsReport

# With sign-in usage stats from the Security event log
.\Invoke-AdfsRpMigrationAssessment.ps1 -OutputPath C:\Temp\AdfsReport -IncludeUsageStats -UsageDays 30

# Filter to specific RPs by name
.\Invoke-AdfsRpMigrationAssessment.ps1 -RelyingPartyName 'MyApp1','MyApp2'

# Include Microsoft-internal RPs (Office 365, etc.)
.\Invoke-AdfsRpMigrationAssessment.ps1 -IncludeMicrosoftRPs

# Multi-server farm — auto-discovers members via Get-AdfsFarmInformation
.\Invoke-AdfsRpMigrationAssessment.ps1 -IncludeUsageStats

# Multi-server farm — explicit list (bypasses discovery)
.\Invoke-AdfsRpMigrationAssessment.ps1 -IncludeUsageStats -FarmServers adfs01.contoso.com,adfs02.contoso.com,adfs03.contoso.com
```

### Multi-server farms

- **RP configuration** is replicated across the farm (WID or SQL) — the script reads it once on the local server, no remoting needed.
- **Sign-in usage stats** are *not* replicated: each ADFS server logs event 1200 only for the sign-ins it personally handled (NLB distributes traffic). For accurate stats you must aggregate across **all** farm members.
  - When `-IncludeUsageStats` is set, the script auto-runs `Get-AdfsFarmInformation` and queries the Security event log of every farm node.
  - Use `-FarmServers <fqdn>,<fqdn>,...` to override the list (useful in SQL-farm scenarios where discovery is incomplete, or when targeting only a subset).
  - Requires either WinRM (PSRemoting) or SMB+RPC access to remote servers, with rights to read the Security log.
  - The HTML report header shows how many servers were successfully reached (`X/Y reached for usage`).
- If a server is unreachable, the script logs a warning and continues with the others — partial stats are still produced.

### Outputs

```
<OutputPath>\
├── AdfsAssessment-Report.html     # Self-contained interactive report (open in browser)
├── AdfsAssessment-Data.json       # Full results, machine-readable
├── AdfsAssessment-Data.csv        # Tabular summary (1 row per RP)
└── Raw\
    └── <RPName>.xml               # Per-RP raw export (Export-Clixml)
```

## HTML report features

- Dashboard with verdict KPIs
- Search box (filters by name / identifier)
- Verdict filter dropdown
- Click a row → drill-down panel:
  - RP configuration summary
  - All 16 tests with Pass/Warning/Fail badges and explanation
  - Parsed claim rules with migratability flag
  - **Migration checklist** with checkboxes — state saved in browser `localStorage` per RP identifier
- Print-friendly stylesheet
- 100% offline — no CDN, no external assets

## Security considerations

- Read-only on AD FS configuration (`Get-AdfsRelyingPartyTrust`, event log read)
- No data leaves the AD FS server
- The HTML report contains your RP configuration (identifiers, claim rules, AD attribute names) — **treat it as sensitive** and do not publish externally without review

## Limitations

- Claim rule parser handles the most common patterns (~90%); exotic rules are flagged as `NeedsManualReview`
- Tests reflect Entra ID capabilities as of June 2026 — update when MS publishes new features
- Usage stats require AD FS Security audit logging to be enabled on **every** farm member (`auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable`)
- Remote event log access requires the calling account to be `BUILTIN\Event Log Readers` (or local admin) on each farm member, plus WinRM or RPC reachability

## References

- [Microsoft archived module — ADFSAADMigrationUtils](https://github.com/AzureAD/Deployment-Plans/tree/master/ADFS%20to%20AzureAD%20App%20Migration)
- [Entra portal AD FS application migration overview](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-ad-fs-application-overview)
- [Migrate AD FS apps to Entra ID — how to](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/migrate-ad-fs-application-howto)
- [Customize claims issued in the SAML token](https://learn.microsoft.com/en-us/entra/identity-platform/saml-claims-customization)
