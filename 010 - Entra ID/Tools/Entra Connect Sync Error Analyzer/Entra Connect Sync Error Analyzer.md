---
title: "Entra Connect Sync Error Analyzer"
date: 2026-10-19
---

# Entra Connect Sync Error Analyzer

Troubleshooting Microsoft Entra Connect often starts in **Synchronization Service Manager**: find the connector, locate an object in error, open its properties and inspect the technical message. This works for individual objects, but reviewing several connectors and sharing the results quickly becomes repetitive.

The **Entra Connect Sync Error Analyzer** collects the object errors currently retained in the Connector Spaces and presents them in a searchable HTML report. Each entry identifies the connector and object, preserves the technical message and adds troubleshooting guidance when the error is recognized. CSV, JSON and native XML exports are also available for further investigation.

The script is **read-only**. It does not start a synchronization cycle, change configuration, query the ADSync database directly or apply a correction. It reads current object errors, not run history.

Download the [Export-EntraConnectSyncErrorReport.ps1 script](Export-EntraConnectSyncErrorReport.ps1).

> **Validation status:** XML parsing and report generation have been tested with synthetic data and one production collection containing 686 errors from a single AD connector. Object IDs, DNs, error types and timestamps matched the native XML. This does not establish coverage for every connector or error format. The generated HTML labels and diagnostic guidance are currently in French.

## Prerequisites

- **Windows PowerShell 5.1** on the Entra Connect server for live collection.
- The **ADSync service running**, with the `ADSync` module and `csexport.exe` installed.
- An account authorized to read the synchronization engine, following the server's administration policy.
- Write access to the output directory and enough disk space for the filtered XML exports and reports.

The script uses the local installation. It does not install modules or require a Microsoft Graph connection. By default, it looks for `csexport.exe` under `C:\Program Files\Microsoft Azure AD Sync\Bin`; a different installation path can be supplied with `-CsExportPath`.

## Collect current errors

Run the script from its directory on the Entra Connect server:

```powershell
$result = .\Export-EntraConnectSyncErrorReport.ps1
$result | Format-List
Invoke-Item -LiteralPath $result.Html
```

By default, it processes every connector returned by `Get-ADSyncConnector`. Each execution creates a uniquely named subdirectory under `Reports`, **next to the script**, rather than in the shell's current directory. The returned object provides the output paths, error count, distinct object count and collection status.

To select specific connectors and a different output location, use their exact names as displayed in Synchronization Service Manager:

```powershell
$result = .\Export-EntraConnectSyncErrorReport.ps1 `
	-ConnectorName 'contoso.com', 'contoso.onmicrosoft.com - AAD' `
	-OutputDirectory 'C:\Temp\EntraConnectErrors'
```

For a non-default installation path:

```powershell
$result = .\Export-EntraConnectSyncErrorReport.ps1 `
	-CsExportPath 'D:\Applications\Microsoft Azure AD Sync\Bin\csexport.exe'
```

### What does "current" mean?

The source is the **error state retained by the synchronization engine at collection time**. An error first recorded yesterday is included if it is still present today. There is no date filter: the age of an error does not establish whether it has been resolved.

Conversely, correcting a value in Active Directory does not immediately clear the engine's error state. The relevant synchronization processing must reevaluate the object. This script does not trigger that processing or independently validate the object against the target directory.

Connectors are read sequentially, so the report records collection start and end times in UTC. It is a point-in-time collection window, not a simultaneous transactional snapshot of every connector.

## How collection works

For each selected connector, also called a **Management Agent (MA)**, the script runs two filtered native exports:

| Filter | Data collected |
| --- | --- |
| `/f:i` | Objects with import or synchronization errors. |
| `/f:e` | Objects with export errors. |

Only the objects returned by these error filters are parsed; the script does not dump the entire Connector Space. The XML is read one object at a time, and the native files are retained for verification.

Each supported error-detail block becomes a report entry. Import and synchronization errors remain grouped when the XML does not distinguish their stage. Export details are read separately from import/synchronization details to avoid mixing their diagnostic information.

If an export fails or an object returned by an error filter has no supported error details, that collection is marked **Failed**. The report is then **Incomplete**, rather than incorrectly reporting that the connector has no errors.

## Read the report

Start with the **collection status**, then the summary by connector, stage and error type. An incomplete collection must be investigated before interpreting the error totals: those totals cover only the successfully parsed exports.

The object table provides the information needed to locate and investigate each error:

| Information | How to use it |
| --- | --- |
| Connector and stage | Identify the MA and whether the error concerns export or import/synchronization. |
| DN, UPN and Connector Space object ID | Locate the object in Synchronization Service Manager. UPN is shown only when available in the export. |
| Error type, code and attribute | Identify the reported failure. Attribute information is shown only when supplied by the error details. |
| Technical message | Read the engine's error text, including additional details or an extension call stack when present. |
| Category and explanation | Read a human-readable classification, the engine's reported condition and the suggested checks. These are not a confirmed root cause or an automatic fix. |
| Conflicting object and detected signature | Locate the other DN when it can be extracted, and inspect the precise text that triggered the classification. |
| Internal step, extension and metaverse ID | Locate the processing context without reading the full attribute dump. The internal step, such as `provisioning`, is not a run profile such as Delta Import. |
| Failing rule and cited rules | Distinguish the rule explicitly reported with an evaluation failure from the rules listed as involved in a conflict. Listed rules are not automatically faulty. |
| First/last occurrence and retries | Assess persistence using the error details retained by the engine. Occurrence timestamps are displayed as supplied, without assuming their timezone; collection timestamps are UTC. |
| Technical XML | Expand the original error details when the normalized fields are insufficient. |

The compact record keeps context and diagnostic checks visible. The exact message, detected signature and native XML are collapsed but remain searchable.

Use the search field for a DN, UPN, code or message, and combine it with the **connector, stage, category, technical type, code, attribute and related-conflict group** selectors. All selected conditions must match. `(Non precise)` selects entries where the code or attribute was not supplied or identified. These filters change the displayed rows, not the data retained in the exported files.

### Investigate related conflicts

The **Conflits lies** table highlights explicit targets shared by at least two distinct source objects. Metaverse join conflicts are grouped by source connector and metaverse ID; target-DN conflicts are grouped by target connector and conflicting DN. Repeated error blocks for a single source object do not create a multi-object group. Group identifiers are local to this report, not persistent incident IDs.

Select a group in the related-conflict filter to review its source objects together. Sharing a target is an investigation lead, not proof that every member has the same root cause. Errors without an explicit supported target stay separate. In the production sample, only seven of the 686 objects shared a target across three groups.

For a join conflict, start with the source DN or Connector Space ID in **Search Connector Space**, follow its metaverse link and compare it with the reported target and already-connected object. For an anchor-change failure, inspect the reported rule and compare `sourceAnchor` with `cloudSourceAnchor` in the metaverse before tracing the contributing flows. Do not disconnect objects or replace anchors solely to bypass an error.

### Export the filtered selection

**Exporter CSV** downloads only the visible error records, including their diagnostic context and exact messages. It omits native XML; the complete `Errors.csv` generated by the script retains that field. The button is disabled when no rows match. Formula-leading values receive a protective apostrophe in the browser export; treat columns as text when opening any identity-data CSV in a spreadsheet.

### Understand the explanation

For example, **AttributeValueMustBeUnique** indicates that a value required to be unique is already in use. The next step is to identify the attribute and value in the technical message, then locate the conflicting objects in AD and Entra ID. The code alone does not establish which object should keep the value.

For **InvalidSoftMatch**, the investigation instead concerns object matching: compare the source anchor, cloud ImmutableId and the UPN or proxy addresses involved. Removing a duplicate address without checking the intended identity could address the wrong problem.

Some technical types are too broad to explain the failure. For `sync-generic-failure`, the script also checks precise message signatures to distinguish a **metaverse join conflict** from a **target DN conflict**. It extracts the conflicting DN when the corresponding message supplies it. A generic word such as "duplicate" is not sufficient to classify either condition.

The script also provides guidance for hard-match protection, object-type conflicts, data validation, size limits, permissions, source-anchor changes and rule or extension failures. Attributes come from the XML error details, an explicitly named attribute in the message or the recognized source-anchor-change signature, not from a guess about the cause. Unrecognized errors retain their technical details and are classified as **Erreur non classee**. Confirm the cause before planning a correction.

### Errors and distinct objects

The two counts answer different questions. **Errors** counts the collected error-detail blocks; **distinct objects** counts Connector Space objects within each connector. One object can have more than one error, and the same person represented in two connectors is not counted as a single cross-directory identity.

## Exported files

| File | Purpose |
| --- | --- |
| `Report.html` | Searchable report with object details, guidance and collection coverage. Opens locally without a web server or external resources. |
| `Errors.csv` | Normalized errors for tabular analysis. |
| `Report.json` | Errors, summary and status of each filtered collection. |
| `Snapshot.clixml` | Collected results for regenerating this report offline. |
| `Raw/*.xml` | Native filtered exports for checking the parser or investigating additional details. |

Protect these files: they contain identity information and may include attribute values. The default `Reports` folder is ignored by Git, but a custom output directory needs its own access controls and version-control exclusions. Import CSV columns as text; opening raw values directly in a spreadsheet can cause formula interpretation.

### Regenerate a report offline

An existing collection can be reopened without access to the Entra Connect server:

```powershell
$result = .\Export-EntraConnectSyncErrorReport.ps1 `
	-InputPath 'C:\Temp\EntraConnectErrors\EntraConnectErrors_EXAMPLE\Snapshot.clixml'
Invoke-Item -LiteralPath $result.Html
```

This mode works with Windows PowerShell 5.1 or PowerShell 7 and does not require ADSync. It regenerates the report from that collection and recalculates classifications with the current diagnostic rules, including for existing schema-2 snapshots; it does **not refresh the error state**. The report explicitly labels offline review and retains the original collection timestamps. Use only snapshots from a trusted source. Native XML files are preserved in the original collection directory, not copied into the regenerated report directory.

## Scope and validation

This is an **object-error review tool**, not a complete Entra Connect health assessment. Connection failures, global run failures and password synchronization issues that are not attached to Connector Space objects are outside its scope. No returned object errors does not prove that synchronization is healthy.

Before relying on the report operationally:

1. Compare the selected MAs with **Search Connector Space** in Synchronization Service Manager.
2. Check a known export error, an import/synchronization error and a connector without object errors.
3. Compare object IDs, DNs, codes, messages and distinct-object counts, and verify both filter results in the coverage table.
4. Investigate any failed export or unsupported XML structure before considering the collection complete for this scope.

## Useful links

- [Microsoft Entra Connect: Troubleshoot errors during synchronization](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-sync-errors)
- [ADSyncTools function using a synchronization-error Connector Space export](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-adsynctools#get-adsynctoolsduplicateuserssourceanchor)
- [Connector Space XML: export error details](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/forefront-2010/ms696485(v=vs.100))