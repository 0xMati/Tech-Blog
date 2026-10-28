# AD Tiering Toolkit (ADTT)

ADTT is a standalone PowerShell toolkit for discovering an Active Directory
environment and deploying a tiered administration model. It was extracted
from MATI without redesigning the existing deployment phases.

**MATI assesses security; ADTT implements tiering.** Each tool can be copied
and run independently. ADTT does not load MATI's detection engine, rules,
scoring or configuration.

## Safety and prerequisites

- Windows and PowerShell 7 or later.
- The ActiveDirectory RSAT module, a reachable domain and an AD account
  with the permissions required for the selected phase.
- The GroupPolicy module for GPO-related phases, and NetSecurity commands
  for the PAW firewall configuration.
- Use a lab first. Review every setting and the proposed scope, confirm
  restorable AD/GPO backups and prepare a recovery procedure before deployment.

**Phase 0 is read-only with respect to AD. Deployment phases can create or
modify OUs, groups, accounts, GPOs, authentication policies and silos.**
They retain their existing interactive confirmations; there is no global
`-WhatIf`, transactional deployment or automatic rollback.

The toolkit uses the current account's AD context. It does not expose MATI's
`-TargetForest` option. Verify the domain displayed at startup and the scope
displayed by each phase before confirming any changes.

## Start

Copy this entire directory to the administrative host, review
[the configuration](Config/Tiering.config.psd1), then run:

```powershell
.\Invoke-ADTT.ps1

# Optional alternative tiering configuration
.\Invoke-ADTT.ps1 -ConfigPath .\Config\custom-tiering.psd1
```

The launcher checks AD access, records the operator, host and domain, and
opens the tiering menu. It does not deploy a phase automatically.

## Existing phases

| Phase | Purpose |
|---|---|
| 0 | Discovery and proposed tier classification; review uncertain classifications |
| 1 | OU structure, groups and optional default-container redirection |
| 2 | Tiered administrative accounts |
| 3 | Cross-tier deny-logon GPOs |
| 4 | Authentication policies and silos |
| 5 | PAW hardening GPOs |
| 6 | Hardening GPOs per tier |
| 7 | Tier 0 object protection |
| 8 | Monitoring and detection configuration |
| 9 | Health checks and ongoing operations |

Phase availability is not a statement that a production deployment has been
validated. Review the actual changes and reports for every phase. The menu's
deployment-status review remains unavailable, as before the extraction.

## Outputs and resuming an existing deployment

- HTML/JSON reports: `Outputs\Tiering\<timestamp>\`.
- Session transcripts: `Outputs\Tiering\ADTT.transcript.<timestamp>.txt`.
- Phase 2 account templates: `Outputs\Tiering\Templates\`.
- Latest phase 1 state: `Outputs\Tiering\MATI-Tiering-Phase1-Latest.json`.

The legacy phase 1 state filename, template filename, default AD object
names and managed-setting identifiers are deliberately preserved. They are
data compatibility identifiers, not dependencies on the MATI directory.
New assessment/deployment reports use the ADTT name.

Previous tiering reports and state remain in the original MATI
`Outputs\Tiering` directory; the extraction does not delete or automatically
import them. Before resuming an existing deployment, verify that the stored
domain, placement and OU DNs still match the intended environment, then copy
the existing `MATI-Tiering-Phase1-Latest.json` into this tool's
`Outputs\Tiering` directory. Review and reuse any customized tiering
configuration rather than silently reverting to defaults.

Treat reports, transcripts and account templates as sensitive administrative
data. Restrict access and keep generated output out of public source control.

## Separation from MATI

MATI retains security detections concerning privileged access, delegation
and isolation. ADTT retains the discovery and operational checks needed by
its deployment workflow; it does not replace MATI's security assessment.

The extraction changes the launcher, module locations and report branding,
not the deployment logic, default object naming, detection rules or scoring.

## Local regression tests

With Pester available, run:

```powershell
Invoke-Pester -Script .\Tests\Standalone.Tests.ps1
```

These tests use isolated temporary copies and synthetic data. AD calls and
deployment phases are replaced with test doubles; no deployment is executed.
They cover standalone module loading, menu routing, configuration errors,
transcript cleanup, discovery summaries and HTML report generation.
An actual AD/GPO lab validation is still required before production use.
