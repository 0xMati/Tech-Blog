---
title: "Entra ID Connect Sync Rules Order Editor"
date: 2026-09-04
---

# Entra ID Connect Sync Rules Order Editor

Published: 2026-09-04

<p align="center">
    <img src="./assets/EntraIDConnectSyncRulesOrderEditor.png" alt="Entra ID Connect Sync Rules Order Editor icon" width="128">
</p>

## Why this exists

Reordering synchronization rules in Entra ID Connect sounds easy until the engine has a few hundred rules, several connectors, and no interest in making bulk changes pleasant.

Changing random precedence numbers is also a good way to turn a five-minute task into a long evening with Synchronization Service Manager.

**Entra ID Connect Sync Rules Order Editor** reads the live rules from the local ADSync engine, lets you build the desired order visually, and applies only the relative moves required to reach it.

> Test rule-order changes on a staging server first. Precedence changes can alter joins, projections, scoping, and attribute authority during the next synchronization.

![](<./assets/Entra ID Connect Sync Rules Order Editor/2026-09-04-16-09-36.png>)

## What the tool does

- Reads all live synchronization rules from the local ADSync engine.
- Displays active and disabled rules in global precedence order.
- Keeps all grid changes in memory until `Apply live...` is confirmed.
- Moves one rule at a time without guessing functional groups or dependencies.
- Supports moves by one row, ten rows, first/last position, or exact position.
- Highlights rules involved in the relative move plan.
- Exports the proposed plan to CSV for review.
- Creates integrity-protected safety snapshots before and after important operations.
- Detects external rule changes between load and Apply.
- Blocks Apply while an ADSync cycle is running.
- Temporarily pauses an enabled scheduler during Apply and restores its previous state afterward.
- Attempts rollback in reverse order if an Apply operation fails.
- Never starts an Import, Synchronization, or Export run profile.

## What the tool does not do

- It does not edit rule mappings, scopes, joins, expressions, or descriptions.
- It does not validate whether the planned business logic is correct.
- It does not group rules automatically.
- It does not run a Full or Delta Synchronization after Apply.
- It does not restore an Entra ID Connect configuration.
- It does not replace a supported Entra ID Connect backup and disaster-recovery process.

The tool manages **rule order**. It is not Synchronization Rules Editor wearing a larger hat.

## Files

- [`EntraIDConnectSyncRulesOrderEditor.ps1`](./EntraIDConnectSyncRulesOrderEditor.ps1): WPF interface and workflow.
- [`EntraIDConnectSyncRulesOrder.Engine.psm1`](./EntraIDConnectSyncRulesOrder.Engine.psm1): snapshots, planning, Apply, verification, and rollback logic.

Keep both files in the same directory.

## Requirements

- Microsoft Entra ID Connect installed on the local server.
- Windows PowerShell 5.1. Do not launch it with PowerShell 7.
- The local `ADSync` PowerShell module.
- An interactive Windows session for the WPF interface.
- An account allowed to administer the local synchronization engine.
- No synchronization cycle in progress when applying a plan.

Use a staging server for initial validation. The tool can operate on an active server, but that path deliberately requires a stronger confirmation token.

## Quick start

Copy the complete folder to the Entra ID Connect server, open **Windows PowerShell 5.1**, and run:

```powershell
Set-Location 'C:\Tools\Entra ID Connect Sync Rules Order Editor'
.\EntraIDConnectSyncRulesOrderEditor.ps1
```

To store safety snapshots somewhere else:

```powershell
.\EntraIDConnectSyncRulesOrderEditor.ps1 `
    -BackupRoot 'D:\ADSync-Audit\RuleOrderSnapshots'
```

At startup, the editor:

1. checks that the required ADSync commands are available;
2. reads the scheduler and staging state;
3. creates an initial safety snapshot;
4. loads the live rule inventory;
5. calculates a fingerprint of the loaded state.

Nothing is changed in ADSync during this phase.

## Reading the interface

The top status bar shows:

- the local server name;
- `STAGING` or `ACTIVE - LIVE EXPORTS ENABLED`;
- the scheduler state and the time it was last checked;
- the latest safety-snapshot path.

The scheduler status is red while a cycle is running and green while idle. The displayed state is an observation, not a force field: the engine checks it again immediately before Apply.

The main grid separates:

| Column | Meaning |
| --- | --- |
| `Loaded order` | Position read from the live engine |
| `Planned order` | Position currently proposed in the grid |
| `Position change` | `Up N`, `Down N`, or no change |
| `Operation` | Rule involved in the calculated relative plan |
| `Live prec.` | Precedence value loaded from ADSync |

Disabled rules are grey. Rules involved in the plan are highlighted.

## Building an order plan

Select one rule, then use any of these controls:

- `Move up` / `Move down`;
- `Move up 10` / `Move down 10`;
- `Move to top` / `Move to bottom`;
- enter an exact planned position and press `Enter`.

Keyboard shortcuts:

| Shortcut | Action |
| --- | --- |
| `Ctrl+Up` / `Ctrl+Down` | Move by one position |
| `Ctrl+PageUp` / `Ctrl+PageDown` | Move by ten positions |
| `Ctrl+Home` / `Ctrl+End` | Move to the first or last position |

Moving one rule shifts the intervening rows, but their relative order remains unchanged. The engine then reduces the desired result to operations such as:

```text
Move Rule D before Rule B
```

`Discard plan` returns the grid to the order loaded from ADSync. It does not modify the live engine.

## Applying the plan

Before Apply, review the highlighted rows and optionally use `Export plan...` to retain the relative operations as CSV.

The Apply workflow performs these checks and actions:

1. reads the scheduler state again;
2. requires the current cycle to be idle;
3. asks for an explicit server-specific confirmation token;
4. verifies that the live rule fingerprint still matches the loaded state;
5. creates a `PreApply` safety snapshot;
6. pauses the scheduler if it was enabled;
7. rechecks the scheduler and fingerprint immediately before mutation;
8. performs and verifies each relative move;
9. attempts reverse-order rollback if an operation fails;
10. restores the scheduler to its previous enabled state;
11. reloads the live rules and creates a `PostApply` safety snapshot after success.

Confirmation tokens are case-sensitive:

```text
Staging server: APPLY <COMPUTERNAME>
Active server:  APPLY ACTIVE <COMPUTERNAME>
```

> The tool does not start a synchronization profile after Apply. Run and review the required Full Synchronization manually according to your change procedure.

## What moving a rule really means

Entra ID Connect does not provide a harmless drag-and-drop API for precedence. The tool uses `PrecedenceBefore` and reconstructs the moved rule.

For a custom rule:

- the original rule is removed;
- an equivalent rule is created before the anchor rule;
- mappings, scopes, joins, state, and key properties are compared;
- the recreated rule receives a new GUID.

For a Microsoft standard rule:

- a custom clone is created at the requested position;
- the clone is verified;
- the original Microsoft rule is disabled only after verification;
- the original standard rule remains present for rollback.

This is why a precedence change deserves the same review discipline as any other synchronization-rule change. The GUI is smoother; the engine is still real.

## Safety snapshots

`Safety snapshot` creates a timestamped evidence folder containing:

- `Get-ADSyncServerConfiguration` output;
- `Rules.clixml`;
- `Connectors.clixml`;
- `Scheduler.clixml`;
- a documentary `Rules.csv` inventory;
- a SHA-256 manifest.

Snapshots are also created automatically during initial load, before Apply, and after a successful Apply.

These files support integrity checks, audit, troubleshooting, and the guarded rule-order workflow. They are **not** exposed as a complete Entra ID Connect restore mechanism.

Do not treat a green hash manifest as a disaster-recovery strategy. It proves that files did not change; it does not prove that your server can be rebuilt from them.

## Restoring a saved rule order

`Restore rule order...` does exactly what its name says: it loads the relative order recorded in a safety snapshot as a new plan.

It does not immediately modify ADSync. You must still review the grid and use the normal Apply workflow.

Before loading the order, the tool verifies:

- every file listed in the SHA-256 manifest;
- the number of live and saved rules;
- exact rule GUIDs where available;
- a unique logical match when a custom rule was recreated with a new GUID.

The restore is blocked if the snapshot is incomplete, altered, ambiguous, or no longer matches the live inventory.

It does **not** restore:

- missing or deleted rules;
- mappings, scopes, joins, or expressions;
- enabled or disabled states;
- connectors or scheduler settings;
- exact historical precedence numbers;
- any other Entra ID Connect configuration.

Moving a Microsoft standard rule adds a custom clone while retaining the disabled original. Because that changes the rule inventory count, an older order snapshot may be intentionally rejected rather than guessed back into place.

## Recommended workflow

1. Start on an Entra ID Connect staging server.
2. Confirm that no cycle is running.
3. Load the live rules and retain the initial snapshot.
4. Move only the rules required by the approved change.
5. Export and review the plan.
6. Apply the plan.
7. Confirm that the grid reloads with `No pending plan`.
8. Run the required synchronization manually.
9. Review synchronization errors and pending exports before any active-server rollout.

A successful Apply proves that the rules were reordered and structurally verified. It does not prove that the resulting synchronization behavior is correct for every object in the directory.

## Troubleshooting

### Apply is locked: cycle in progress

Wait for the current cycle to finish, then select `Reload live`. Do not try to race the scheduler. It has more threads and less anxiety.

### The live rule set changed

Another process or administrator changed ADSync after the editor loaded it. Reload the live state, rebuild the plan, and review it again.

### The window temporarily shows Not Responding

Snapshot creation, live reload, and Apply currently run synchronously on the WPF thread. Windows may temporarily mark the window as unresponsive while the operation completes.

Do not terminate the process while the status says that an Apply is running. For a large configuration, allow the snapshot or reload to finish.

### Restore rule order is rejected

The snapshot failed integrity validation, the rule count changed, or one saved rule could not be matched uniquely. The tool stops instead of inventing a match. That is a feature.

## Validation status

The current version has been exercised on an Entra ID Connect staging server with 231 live rules. A three-operation relative plan was applied successfully, followed by a live reload and `PostApply` snapshot. No synchronization profile was started by the tool.

Production use still requires the usual engineering work: staging validation, controlled Full Synchronization, pending-export review, rollback criteria, and change approval.
