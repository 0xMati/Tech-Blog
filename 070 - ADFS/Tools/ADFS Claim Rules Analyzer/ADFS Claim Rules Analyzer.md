# ADFS Claim Rules Analyzer

PowerShell tool that explains both AD FS authorization claim rules and Issuance Transform Rules, detects suspicious policy patterns, and reconstructs how each rule evaluates against real **AD FS Auditing** events.

Current version: **0.6.0**. The version is displayed in the console, HTML report, and JSON export so that copied deployments can be identified.

The goal is to provide an AD FS equivalent of a Conditional Access troubleshooting view while remaining honest about the available evidence. AD FS does not natively record a structured `Rule A = Match / Rule B = No match` result, so the tool rebuilds that result from request context, caller claims, rule order, and intermediate claims.

## Why this tool

Complex AD FS policies commonly contain:

- WAP checks using `x-ms-proxy`
- internal/external location checks using `insidecorporatenetwork`
- endpoint and client application filters
- User-Agent regular expressions
- Active Directory group SID exceptions
- temporary markers created with `add()` and consumed by later rules
- a final permit or deny rule

The standard AD FS events show whether authentication or token issuance succeeded, but they do not name one "winning rule." All rules run in order, and several rules can match the same request.

ADFS Claim Rules Analyzer combines the policy and audit evidence to answer:

1. What does each rule test and produce?
2. Does a rule contain a likely contradiction or a broad exception?
3. For an observed AD FS transaction, did the rule `MATCH`, `NO MATCH`, or remain `INDETERMINATE`?
4. Which temporary claims were created and used by later rules?
5. What authorization decision does the full rule set reconstruct?
6. Which claims does each Issuance Policy consume and emit?
7. Do the expected output claim types appear in event `500`?

## What it does

1. Inventories all selected AD FS relying party trusts and their authorization source.
2. Reads and parses `IssuanceAuthorizationRules` and `IssuanceTransformRules`.
3. Converts the built-in `Permit everyone` Access Control Policy into an explicit unconditional permit rule.
4. Produces a human-readable condition and action summary.
5. Detects initial policy findings, including:
   - WAP required while `insidecorporatenetwork=false` must be absent
   - security decisions based on a client-controlled User-Agent
   - external group exceptions with no endpoint or application restriction
   - syntax that this version cannot safely evaluate
6. Reads AD FS Auditing events from every farm node by default, or from exported EVTX files.
7. Correlates events by Activity ID and linked Instance ID.
8. Excludes context-only WAP maintenance and portal traffic from policy evaluation.
9. Resolves RP evidence by exact identifier or a unique URI authority match.
10. Reconstructs request context, caller claims, issued claims, and the observed result.
11. Executes rules sequentially, including static claims created with `add()` or `issue()`.
12. Exports a self-contained HTML report plus CSV, JSON, and an offline configuration snapshot.

The tool is read-only. It never enables auditing or changes AD FS configuration.

## Evaluation states

| State | Meaning |
|---|---|
| `MATCH` | All conditions are proven true by the available evidence. |
| `NO MATCH` | At least one condition is proven false. |
| `INDETERMINATE` | A required claim is missing from the audit evidence, or the rule uses unsupported syntax. |

`INDETERMINATE` is not equivalent to `NO MATCH`. This distinction prevents incomplete audit logs from creating false conclusions.

## Policy scopes

| Policy scope | AD FS property | Analyzer result |
|---|---|---|
| Authorization | `IssuanceAuthorizationRules` or an Access Control Policy | Reconstructs `PERMIT`, `DENY`, or `INDETERMINATE`. |
| Issuance Policy | `IssuanceTransformRules` | Reconstructs rule conditions and generated claims without changing the authorization decision. |

AD FS executes these as separate rule sets:

- each rule set has its own input and output claim sets
- `add()` adds a claim only to the shared input set for consumption by later rules
- `issue()` adds a claim to both the input and output sets
- authorization output determines whether the Issuance Policy runs; permit/deny claims are not passed into the Issuance Transform Rule set

For Issuance Transform Rules, `OutputObserved` compares expected output claim types with event `500`:

| State | Meaning |
|---|---|
| `ALL TYPES OBSERVED` | Every expected output type appears in the issued claims. |
| `PARTIAL` | Only part of the expected output type set appears. |
| `NONE` | Event `500` is complete, but none of the expected output types appears. |
| `UNKNOWN` | Event `500` is unavailable or the output type cannot be determined safely. |
| `INTERNAL ONLY` | The rule uses `add()`: the claim feeds later rules but is not expected in the outgoing token. |
| `N/A` | The rule is not an Issuance Transform Rule or its condition did not match. |

Output-type presence confirms correlation, not causality: another rule can emit the same claim type.

## Requirements

- Windows PowerShell 5.1
- Run live configuration collection on an AD FS server with the `ADFS` PowerShell module
- Local administrator rights to read AD FS configuration
- Rights to read the Security event log on every queried farm node
- WinRM or Remote Event Log connectivity for multi-node live collection
- A modern browser for the HTML report; no internet connection is required

## AD FS auditing prerequisites

Static policy analysis works without audit events. Event-based reconstruction requires AD FS Auditing in the Security log.

Check the current state:

```powershell
Get-AdfsProperties | Select-Object AuditLevel
auditpol.exe /get /subcategory:"Application Generated"
```

For a temporary observation window, configure verbose AD FS auditing and success/failure auditing:

```powershell
Set-AdfsProperties -AuditLevel Verbose

auditpol.exe /set /subcategory:"Application Generated" `
    /success:enable /failure:enable
```

The AD FS service account must also hold the **Generate security audits** user right. In a managed environment, configure that right through the appropriate GPO.

Verbose auditing can generate significant volume. Forward the Security events to WEF or a SIEM for longer observation periods, and return AD FS to the organization's normal audit level after a short diagnostic capture when continuous verbose auditing is not required.

## Usage

### Parameter reference

| Parameter | Default | Description |
|---|---:|---|
| `-OutputPath <path>` | `<script folder>\output` | Destination for generated reports and the reusable CLIXML snapshot. |
| `-RelyingPartyName <name[]>` | `*` | RP name or wildcard patterns included in live mode. Multiple values are accepted. |
| `-ConfigurationPath <file>` | None | CLIXML configuration snapshot used instead of live AD FS configuration. Activates offline mode. |
| `-IncludeEvents` | Enabled implicitly in live mode | Compatibility switch that explicitly requests live Security log collection. It is no longer required for a normal live run. |
| `-StaticOnly` | Disabled | Reads live RP configuration without collecting audit events. Cannot be combined with `-IncludeEvents` or `-EventLogPath`. |
| `-FarmServers <server[]>` | Farm discovery | Overrides `Get-AdfsFarmInformation` with one or more AD FS servers for live event collection. |
| `-EventLogPath <file[]>` | None | Reads one or more exported Security EVTX files. Normally combined with `-ConfigurationPath`. |
| `-LookbackDays <1-3650>` | `1` | Keeps events from the selected number of days, for both live logs and EVTX files. |
| `-NoHtml` | Disabled | Suppresses the HTML report. |
| `-NoCsv` | Disabled | Suppresses all CSV exports. The CLIXML snapshot is still created. |
| `-NoJson` | Disabled | Suppresses the JSON export. |
| `-MaxHtmlTransactions <0-100000>` | `2000` | Limits recent transactions embedded in HTML. `0` includes all; CSV and JSON remain complete. |
| `-OpenReport` | Automatic only without parameters | Opens the HTML report. Add it explicitly whenever other parameters are supplied. Cannot be combined with `-NoHtml`. |
| `-SelfTest` | Disabled | Runs internal parser, correlation, and evaluator tests without requiring AD FS. |

The same reference is available directly in PowerShell:

```powershell
Get-Help .\Invoke-AdfsClaimRulesAnalyzer.ps1 -Full
Get-Help .\Invoke-AdfsClaimRulesAnalyzer.ps1 -Examples
```

### Invocation modes

| Invocation | Configuration | Audit evidence | Browser |
|---|---|---|---|
| `.\Invoke-AdfsClaimRulesAnalyzer.ps1` | Live, all RPs | Live farm, last 24 hours | Opens automatically |
| `.\Invoke-AdfsClaimRulesAnalyzer.ps1 -StaticOnly` | Live, all RPs | None | Add `-OpenReport` to open |
| `.\Invoke-AdfsClaimRulesAnalyzer.ps1 -RelyingPartyName 'Name'` | Live, selected RP | Live farm, last 24 hours | Add `-OpenReport` to open |
| `.\Invoke-AdfsClaimRulesAnalyzer.ps1 -ConfigurationPath config.clixml` | Offline snapshot | None | Add `-OpenReport` to open |
| `.\Invoke-AdfsClaimRulesAnalyzer.ps1 -ConfigurationPath config.clixml -EventLogPath security.evtx` | Offline snapshot | Exported EVTX | Add `-OpenReport` to open |

### Static analysis of all relying parties

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 -StaticOnly
```

This mode analyzes configuration only. It does not collect transactions or calculate observed matches.

### Complete analysis directly on an AD FS server

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1
```

With no parameter, version 0.6 performs the complete workflow:

- reads all relying party trusts
- discovers the AD FS farm nodes
- collects the last 24 hours of AD FS Auditing events
- generates all reports below the script folder
- opens the HTML report

### Analyze one relying party

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -RelyingPartyName 'Microsoft Office 365 Identity Platform'
```

### Analyze a longer live audit period

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -RelyingPartyName 'Microsoft Office 365 Identity Platform' `
    -LookbackDays 7 `
    -OpenReport
```

This is the recommended first end-to-end test. It requires AD FS Auditing events in the Security log during the selected period.

### Interpret an empty first report

The report now distinguishes these cases:

| Report status | Meaning |
|---|---|
| `Static configuration analysis` | No audit source was requested. In live mode, omit `-StaticOnly`; in offline mode, add `-EventLogPath`. |
| `ANALYZED - BUILT-IN ACCESS CONTROL POLICY` | The RP uses the built-in `Permit everyone` policy, reconstructed as an unconditional permit rule. |
| `NOT ANALYZED - ACCESS CONTROL POLICY` | The RP uses another AD FS Access Control Policy. Version 0.6 inventories it but does not infer unsupported policy metadata. |
| `PARTIAL - n RULE(S) REQUIRE MANUAL REVIEW` | Issuance rules were inventoried, but one or more actions require an external attribute store or unsupported expression. |
| `NO AUTHORIZATION RULES EXPOSED` | The RP exposes neither classic authorization rules nor an Access Control Policy name. |
| `Audit collection returned no events` | No supported `AD FS Auditing` event was found in the requested period. Check auditing and generate a fresh authentication. |
| `Audit events could not be correlated` | Events were read, but none contained an Activity ID usable for reconstruction. |

You can inspect the authorization source directly before running the analyzer:

```powershell
Get-AdfsRelyingPartyTrust |
    Select-Object Name, Enabled, AccessControlPolicyName,
        @{Name = 'HasClassicAuthorizationRules'; Expression = {
            -not [string]::IsNullOrWhiteSpace([string]$_.IssuanceAuthorizationRules)
        }}
```

### Explicit multi-node farm collection

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -IncludeEvents `
    -FarmServers adfs01.contoso.com, adfs02.contoso.com `
    -LookbackDays 30
```

If `-FarmServers` is omitted, the script uses `Get-AdfsFarmInformation` and falls back to the local server if discovery fails.

### Offline analysis

First run a static analysis on an AD FS server. The tool creates:

```text
output\Raw\AdfsClaimRulesAnalyzer-Configuration.clixml
```

Export the Security event log from each AD FS server to EVTX, then analyze the files from another Windows machine:

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -ConfigurationPath .\AdfsClaimRulesAnalyzer-Configuration.clixml `
    -EventLogPath .\ADFS01-Security.evtx, .\ADFS02-Security.evtx `
    -OutputPath C:\Temp\AdfsClaimRulesReport
```

The EVTX files can contain the complete Security log. The script keeps only provider `AD FS Auditing`, the supported event IDs, and the requested lookback window.

### Run the built-in tests

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 -SelfTest
```

The tests validate:

- rule splitting and common syntax parsing
- WAP and Windows User-Agent matching
- detection of a contradictory WAP/location rule
- `INDETERMINATE` behavior with missing evidence
- Activity ID and Instance ID event correlation
- sequential `add()` and `issue()` processing
- unconditional permit or deny rules
- unsupported dynamic-action handling
- RP mapping from `relyingpartytrustid`
- context-only traffic exclusion
- built-in `Permit everyone` Access Control Policy handling
- separate authorization and Issuance Transform pipelines
- pass-through, copied-value, static, and `RegExReplace` issuance actions
- event `500` output-type correlation
- final permit/deny reconstruction

## Outputs

```text
<OutputPath>\
|-- AdfsClaimRulesAnalyzer-Report.html
|-- AdfsClaimRulesAnalyzer-RelyingParties.csv
|-- AdfsClaimRulesAnalyzer-Rules.csv
|-- AdfsClaimRulesAnalyzer-Evaluations.csv
|-- AdfsClaimRulesAnalyzer-Transactions.csv
|-- AdfsClaimRulesAnalyzer-Data.json
`-- Raw\
    `-- AdfsClaimRulesAnalyzer-Configuration.clixml
```

| File | Purpose |
|---|---|
| `AdfsClaimRulesAnalyzer-Report.html` | Pedagogical offline report with run interpretation, policy inventory, sign-in narratives, rule evidence, and emitted claim values. |
| `AdfsClaimRulesAnalyzer-RelyingParties.csv` | One row per selected RP with authorization source, assigned Access Control Policy, rule count, and analysis status. |
| `AdfsClaimRulesAnalyzer-Rules.csv` | One row per authorization or issuance rule with policy type, input/output claims, action kind, store, findings, and match counts. |
| `AdfsClaimRulesAnalyzer-Evaluations.csv` | One row per transaction and rule, including policy type, result, action, expected output, `OutputObserved`, confidence, and evidence. |
| `AdfsClaimRulesAnalyzer-Transactions.csv` | One row per policy-relevant Activity ID with request context, issued claim types, and observed/reconstructed authorization decisions. |
| `AdfsClaimRulesAnalyzer-Data.json` | Full machine-readable data, including parsed conditions and observed claims. |
| Configuration CLIXML | Portable relying party snapshot for offline analysis. |

### Reading the HTML report

The report is organized from interpretation to technical evidence:

#### Report overview

The opening view summarizes the configuration scope, observed transactions, ignored context-only traffic, findings, manual-review items, and matching rules. **What this run shows** separates authorization from issuance, while **Evidence semantics** defines `MATCH`, `NO MATCH`, `INDETERMINATE`, `ALL TYPES OBSERVED`, and `INTERNAL ONLY` directly in the report.

![AD FS Claim Rules Analyzer report overview with metrics and evidence semantics](<./assets/report-overview.png>)

*The opening view provides the analysis scope and evidence quality before displaying technical rule details.*

#### Relying party scope

**Relying party scope** shows the authorization source and Issuance Transform coverage for every selected RP. Authorization and issuance are reported independently because an RP can use a supported Access Control Policy while still containing attribute-store rules that require manual review.

![ClaimsApp relying party authorization and issuance analysis status](<./assets/relying-party-scope-claimsapp.png>)

![ClaimsXray and Microsoft Office 365 relying party analysis status](<./assets/relying-party-scope-office365.png>)

*Each RP displays its authorization policy, Issuance Transform rule count, analysis status, and identifiers.*

#### Policy inventory

**Policy inventory** retains the complete technical rule set, raw rule language, input and output claim types, action type, attribute store, parser status, findings, and observed evaluation counts. The search field can filter any visible or collapsed rule content.

![Authorization and Issuance Transform policy inventory](<./assets/policy-inventory.png>)

*Authorization policies use green stage labels, while Issuance Transform Rules use orange labels. Attribute-store queries are identified explicitly for manual review.*

#### Sign-in explanation

**Sign-in explanations** present each policy-relevant transaction as a three-step flow: request evidence, authorization decision, and claim issuance. Matching and indeterminate rules appear first under **Rules that shaped this sign-in**; `NO MATCH` rules remain available in **Rules that did not apply**. **Outgoing claims captured in event 500** lists the friendly claim name, full type URI, and observed value in a collapsed sensitive-data section.

![User sign-in explanation with request, authorization, issuance, and matching rules](<./assets/sign-in-explanation.jpg>)

*The sign-in card ties the observed AD FS result to the reconstructed authorization decision and the rules that shaped the outgoing token.*

The first transaction is expanded automatically. Additional transactions, non-applicable rules, raw evidence, and emitted claim values remain collapsible so that large reports stay readable.

The visual language is semantic rather than decorative:

| Color | Meaning |
|---|---|
| Blue | RP scope and request evidence |
| Green | Authorization, successful decisions, and matching conditions |
| Orange | Issuance Transform Rules and outgoing-claim processing |
| Cyan | Audit evidence and output types observed in event `500` |
| Amber | Indeterminate results, warnings, and manual review |
| Red | Denials, failures, and high-severity findings |
| Gray | Non-matching rules, unavailable evidence, or ignored traffic |

Metric cards, policy-stage badges, the Request → Authorization → Issuance flow, transaction borders, and evidence statuses all reuse these colors consistently. Text contrast remains suitable for both desktop and mobile layouts.

Both search fields:

- update their result count immediately
- display an explicit message when nothing matches
- ignore case, accents, spaces, slashes, periods, hyphens and underscores
- search collapsed content, including raw evidence and outgoing claim values

For example, `IssuanceTransformRules` and `Issuance Transform Rules` return the same policy rows, while `FormsAuthentication` can locate a sign-in even when its outgoing-claims section is closed.

CSV files use `;` as delimiter. By default, HTML displays the 2,000 most recent transactions while CSV and JSON retain all records. Use `-MaxHtmlTransactions 0` to include every transaction in HTML.

### Output selection examples

Generate only HTML and the mandatory CLIXML snapshot:

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -NoCsv `
    -NoJson `
    -OpenReport
```

Generate CSV and JSON without HTML:

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -NoHtml
```

Choose the output folder and keep every transaction in HTML:

```powershell
.\Invoke-AdfsClaimRulesAnalyzer.ps1 `
    -OutputPath C:\Temp\AdfsClaimRulesReport `
    -MaxHtmlTransactions 0 `
    -OpenReport
```

## Audit events used

The first version recognizes the following AD FS Auditing events when available:

| Events | Use |
|---|---|
| `403`, `410` | HTTP request, User-Agent, endpoint, WAP and forwarded-client context |
| `412`, `501`, `502` | authenticated caller and claims |
| `299`, `500` | issued token and outgoing claims |
| `324` | authorization failure |
| `1200`, `1201` | application token success or failure |
| `1202`, `1203` | fresh credential validation success or failure |

Events that contain only an Instance ID are linked back to the Activity ID before the transaction is evaluated.

Activities containing no token, authorization, or RP evidence are counted as **Ignored traffic** and excluded from transaction evaluation. This removes WAP configuration polling and AD FS portal asset requests without treating them as failed sign-ins.

## Supported rule syntax in version 0.6

The evaluator supports this common authorization and issuance-rule subset:

- claim selectors with or without aliases such as `c:[...]`
- `exists(...)` and `NOT exists(...)`
- predicate operators `==`, `!=`, `=~`, and `!~`
- conditions joined by `&&`
- static `add(Type=..., Value=...)`
- static `issue(Type=..., Value=...)`
- pass-through `issue(claim=c)`
- copied values such as `issue(Type=..., Value=c.Value)`
- simple `RegExReplace(c.Value, "pattern", "replacement")`

Attribute-store actions such as `issue(store="Active Directory", types=(...), query=..., param=...)` are inventoried. Their input types, output types, store and raw rule are reported, but the external query is not executed.

Unsupported constructs are retained in the report and marked for manual review rather than guessed.

## Important limitations

- Version 0.6 analyzes `IssuanceAuthorizationRules` and `IssuanceTransformRules`; delegation, impersonation, acceptance transform, and additional authentication rules are future work.
- The built-in `Permit everyone` Access Control Policy is analyzed. Other Access Control Policies are inventoried by name but their policy metadata is not inferred.
- OR expressions, aggregate expressions such as `COUNT()`, attribute-store query results, and complex dynamic actions are not evaluated.
- Attribute-store rules can show `MATCH` for their input conditions and `ALL TYPES OBSERVED` for event `500`, but their returned values cannot be predicted without querying the store.
- Regular expressions from policy are evaluated with a two-second timeout per comparison. Invalid or timed-out expressions produce `INDETERMINATE` instead of blocking the analysis.
- AD FS does not log a native per-rule Boolean result. Results are reconstructed from evidence and can remain `INDETERMINATE`.
- Request headers such as User-Agent are client-controlled. A match describes policy behavior; it does not make the signal trustworthy.
- A single Activity ID can include multiple HTTP steps. This version produces a consolidated activity transaction rather than a Conditional Access-style sign-in object.
- Historical analysis reflects claims captured at request time. Current group membership must not be substituted for missing historical claims.
- Audit schemas vary slightly across AD FS and Windows Server versions. Message parsing and event-property parsing are both used, but unfamiliar schemas require validation.
- A reconstructed decision should be compared with the observed success or failure. A discrepancy is a reason to inspect the raw events, not proof that AD FS behaved incorrectly.

## Security considerations

The generated files can contain:

- usernames and group SIDs
- client and proxy IP addresses
- User-Agent and endpoint information
- relying party identifiers
- outgoing claim types and their observed values
- complete authorization and issuance rule text

Treat the output, configuration snapshot, and exported Security logs as sensitive. Store them in an access-controlled location and remove them according to the customer's data-retention requirements.

## References

- [Troubleshoot AD FS with events and logging](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging)
- [AD FS troubleshooting - claim rules](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-claims-rules)
- [The role of the claim rule language](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/the-role-of-the-claim-rule-language)
- [The role of the claims engine](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/the-role-of-the-claims-engine)
- [Access Control Policies in AD FS](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/access-control-policies-w2k12)
- [Microsoft AD FS Events Module](https://github.com/microsoft/adfsToolbox/tree/master/eventsModule)