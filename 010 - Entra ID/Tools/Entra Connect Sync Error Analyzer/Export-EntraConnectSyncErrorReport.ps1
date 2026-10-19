#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
    [Parameter(ParameterSetName = 'Collect')]
    [string[]]$ConnectorName,
    [Parameter(ParameterSetName = 'Collect')]
    [string]$CsExportPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Offline')]
    [string]$InputPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'Reports')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-XmlText {
    param([System.Xml.XmlNode]$Node, [string]$XPath)
    $found = $Node.SelectSingleNode($XPath)
    if ($found -is [System.Xml.XmlAttribute]) { return $found.Value }
    if ($null -ne $found) { return $found.InnerText }
    return ''
}

function Get-ErrorGuidance {
    param([string]$Text)
    switch -Regex ($Text) {
        'AttributeValueMustBeUnique' {
            return 'Une valeur devant etre unique est deja utilisee. Identifier l attribut, la valeur et les objets en conflit dans AD et Entra ID.'
        }
        'InvalidSoftMatch' {
            return 'Rapprochement refuse : un objet existant porte un ancrage different. Comparer sourceAnchor/ImmutableId, UPN et proxyAddresses des objets concernes.'
        }
        'InvalidHardMatch' {
            return 'Rapprochement par ancrage refuse. Verifier le motif exact, les associations existantes et les protections des comptes privilegies, sans les contourner automatiquement.'
        }
        'ObjectTypeMismatch' {
            return 'Conflit entre types d objets. Comparer utilisateur/groupe/contact et les adresses utilisees pour le rapprochement.'
        }
        'IdentityDataValidationFailed|DataValidationFailed' {
            return 'Valeur ou modification refusee par le service cible. Verifier l attribut cite, son format, ses caracteres et les contraintes de rapprochement.'
        }
        'LargeObject|ExceededAllowedLength' {
            return 'Limite de taille depassee. Examiner les attributs cites, notamment certificats, photo et adresses multiples.'
        }
        'permission-issue|insufficient.access|access.denied' {
            return 'Refus d acces. Verifier le compte du connecteur, les droits effectifs, les ACL et l inheritance sur l objet cible.'
        }
        'SourceAnchor attribute has changed' {
            return 'Changement d ancrage signale. Comparer l ancrage AD, metaverse et cloud et verifier les regles avant toute modification.'
        }
        'sync-rule-error|extension-dll-exception|extension-error' {
            return 'Echec de regle ou d extension. Lire la pile technique et verifier les attributs sources et la transformation concernee.'
        }
        default {
            return 'Code non reconnu automatiquement. Lire le message et le XML, puis consulter cet objet dans Search Connector Space. Aucune cause racine deduite.'
        }
    }
}

function Read-ConnectorErrors {
    param([string]$Path, [string]$MA, [string]$Filter, [string]$ObservedAtUtc)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    try {
        $reader.MoveToContent() | Out-Null
        if ($reader.LocalName -ne 'cs-objects') { throw 'Expected a cs-objects document.' }
        while (-not $reader.EOF) {
            if ($reader.NodeType -ne [System.Xml.XmlNodeType]::Element -or $reader.LocalName -ne 'cs-object') {
                $reader.Read() | Out-Null
                continue
            }
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.LoadXml($reader.ReadOuterXml())
            $objectNode = $document.DocumentElement
            $detailPath = './*[local-name()="import-errordetail" or local-name()="synchronization-errordetail"]'
            if ($Filter -eq 'e') { $detailPath = './*[local-name()="export-errordetail"]' }
            $details = @($objectNode.SelectNodes($detailPath))
            if ($details.Count -eq 0) { throw 'An object returned by the error filter has no supported error detail. Coverage cannot be confirmed.' }
            foreach ($detail in $details) {
                $dn = Get-XmlText $objectNode '@cs-dn'
                if (-not $dn) { $dn = Get-XmlText $objectNode './/*[local-name()="entry"]/@dn' }
                $identifier = Get-XmlText $objectNode '@id'
                if (-not $identifier -and -not $dn) { throw 'Error object has neither ID nor DN.' }
                $type = Get-XmlText $detail './/@error-type | .//*[local-name()="error-type"]'
                $code = Get-XmlText $detail './/*[local-name()="error-code"] | .//@error-code'
                $messages = @($detail.SelectNodes('.//*[not(*) and normalize-space(.)!=""]') | ForEach-Object {
                    '{0}: {1}' -f $_.LocalName, $_.InnerText
                })
                if ($messages.Count -eq 0) { $messages = @('Voir les attributs du XML technique.') }
                $stage = 'Import / Synchronisation'
                if ($detail.LocalName -eq 'export-errordetail') { $stage = 'Export' }
                if ($detail.LocalName -eq 'synchronization-errordetail') { $stage = 'Synchronisation' }
                [pscustomobject]@{
                    Connector = $MA; Stage = $stage; DN = $dn; CsObjectId = $identifier
                    UPN = Get-XmlText $objectNode './/*[local-name()="attr" and @name="userPrincipalName"]/*[local-name()="value"]'
                    ErrorType = $type; ErrorCode = $code
                    Attribute = Get-XmlText $detail './/*[local-name()="attribute-name"] | .//@attribute-name'
                    Message = $messages -join "`n"
                    Guidance = Get-ErrorGuidance ($type + ' ' + $code + ' ' + $detail.InnerText)
                    FirstOccurred = Get-XmlText $detail './/@first-occurred'
                    LastOccurred = Get-XmlText $detail './/@date-occurred'
                    ObservedAtUtc = $ObservedAtUtc; SourceFilter = $Filter; RawXml = $detail.OuterXml
                }
            }
        }
    }
    finally { $reader.Dispose() }
}

function ConvertTo-HtmlText {
    param($Value)
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

$runName = 'EntraConnectErrors_{0}_{1}' -f ([datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$destination = Join-Path $OutputDirectory $runName
if ($PSCmdlet.ParameterSetName -eq 'Offline') {
    $snapshot = Import-Clixml -LiteralPath $InputPath
    if ($null -eq $snapshot.PSObject.Properties['SchemaVersion'] -or $snapshot.SchemaVersion -ne 2 -or
        $null -eq $snapshot.PSObject.Properties['Errors'] -or $null -eq $snapshot.PSObject.Properties['Collections']) {
        throw 'Expected a current-error Snapshot.clixml (schema 2). Old cycle snapshots are not supported.'
    }
    New-Item -Path $destination -ItemType Directory | Out-Null
}
else {
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'Use Windows PowerShell 5.1 on the Entra Connect server for live collection.' }
    Import-Module ADSync -ErrorAction Stop
    if ((Get-Service ADSync).Status -ne 'Running') { throw 'ADSync must be running.' }
    if (-not $CsExportPath) { $CsExportPath = Join-Path $env:ProgramFiles 'Microsoft Azure AD Sync\Bin\csexport.exe' }
    if (-not (Test-Path -LiteralPath $CsExportPath -PathType Leaf)) { throw 'csexport.exe not found. Specify its installed path with -CsExportPath.' }
    $connectors = @(Get-ADSyncConnector -ErrorAction Stop)
    if ($ConnectorName) {
        foreach ($name in $ConnectorName) {
            if ($name -notin $connectors.Name) { throw "Unknown connector: $name" }
        }
        $connectors = @($connectors | Where-Object { $_.Name -in $ConnectorName })
    }
    if ($connectors.Count -eq 0) { throw 'No connectors found. Nothing was collected.' }
    $rawDirectory = Join-Path $destination 'Raw'
    New-Item -Path $rawDirectory -ItemType Directory -Force | Out-Null
    $started = [datetime]::UtcNow.ToString('o')
    $errors = [System.Collections.Generic.List[object]]::new()
    $collections = [System.Collections.Generic.List[object]]::new()
    foreach ($connector in $connectors) {
        foreach ($filter in @('i', 'e')) {
            $captureStarted = [datetime]::UtcNow.ToString('o')
            $path = Join-Path $rawDirectory (([guid]::NewGuid().ToString('N')) + '.xml')
            $status = 'Complete'; $failure = ''; $count = 0
            try {
                Write-Verbose "Collecting $($connector.Name), /f:$filter"
                $nativeOutput = & $CsExportPath $connector.Name $path "/f:$filter" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "csexport exit code $LASTEXITCODE. $($nativeOutput -join ' ')" }
                $rows = @(Read-ConnectorErrors -Path $path -MA $connector.Name -Filter $filter -ObservedAtUtc ([datetime]::UtcNow.ToString('o')))
                foreach ($row in $rows) { $errors.Add($row) }
                $count = $rows.Count
            }
            catch {
                $status = 'Failed'; $failure = $_.Exception.Message
                Write-Warning "Collection failed for $($connector.Name), /f:$filter : $failure"
            }
            $collections.Add([pscustomobject]@{
                Connector = $connector.Name; Filter = $filter; Status = $status; Error = $failure
                StartedUtc = $captureStarted; FinishedUtc = [datetime]::UtcNow.ToString('o')
                ErrorRows = $count; RawFile = 'Raw/' + [IO.Path]::GetFileName($path)
            })
        }
    }
    $snapshot = [pscustomobject]@{
        SchemaVersion = 2; Server = $env:COMPUTERNAME; CollectionStartedUtc = $started
        CollectedAtUtc = [datetime]::UtcNow.ToString('o'); Errors = $errors.ToArray(); Collections = $collections.ToArray()
    }
}

$errorRows = @($snapshot.Errors)
$completeness = 'Complete'
if (@($snapshot.Collections).Count -eq 0 -or @($snapshot.Collections | Where-Object Status -ne 'Complete').Count -gt 0) { $completeness = 'Incomplete' }
$uniqueObjects = @($errorRows | Group-Object Connector | ForEach-Object {
    $_.Group | ForEach-Object { if ($_.CsObjectId) { $_.CsObjectId } else { $_.DN } } | Sort-Object -Unique
}).Count
$summary = @($errorRows | Group-Object Connector, Stage, ErrorType | ForEach-Object {
    [pscustomobject]@{ Connector = $_.Group[0].Connector; Stage = $_.Group[0].Stage; ErrorType = $_.Group[0].ErrorType; Count = $_.Count }
})
$report = [pscustomobject]@{
    SchemaVersion = 2; Server = $snapshot.Server; CollectionStartedUtc = $snapshot.CollectionStartedUtc
    CollectedAtUtc = $snapshot.CollectedAtUtc; Completeness = $completeness; UniqueObjects = $uniqueObjects
    Scope = 'Object errors retained in Connector Spaces at collection time; no cycle history or fresh target validation.'
    Errors = $errorRows; Summary = $summary; Collections = @($snapshot.Collections)
}
$snapshot | Export-Clixml -LiteralPath (Join-Path $destination 'Snapshot.clixml') -Depth 100 -Encoding UTF8
ConvertTo-Json -InputObject $report -Depth 30 | Set-Content -LiteralPath (Join-Path $destination 'Report.json') -Encoding UTF8
$columns = @('Connector','Stage','DN','UPN','CsObjectId','ErrorType','ErrorCode','Attribute','Message','Guidance','FirstOccurred','LastOccurred','ObservedAtUtc','SourceFilter','RawXml')
if ($errorRows.Count) {
    $errorRows | Select-Object $columns | Export-Csv -LiteralPath (Join-Path $destination 'Errors.csv') -NoTypeInformation -Encoding UTF8
}
else {
    (($columns | ForEach-Object { '"' + $_ + '"' }) -join ',') | Set-Content -LiteralPath (Join-Path $destination 'Errors.csv') -Encoding UTF8
}
$rowsHtml = foreach ($row in $errorRows) {
    '<tr><td>{0}</td><td>{1}</td><td><strong>{2}</strong><p>{3}</p><small>{4}</small></td><td>{5}<p>{6}</p><small>{7}</small></td><td><pre>{8}</pre><details><summary>XML technique</summary><pre>{9}</pre></details></td><td>{10}</td></tr>' -f
        (ConvertTo-HtmlText $row.Connector), (ConvertTo-HtmlText $row.Stage), (ConvertTo-HtmlText $row.DN),
        (ConvertTo-HtmlText $row.UPN), (ConvertTo-HtmlText $row.CsObjectId), (ConvertTo-HtmlText $row.ErrorType),
        (ConvertTo-HtmlText $row.ErrorCode), (ConvertTo-HtmlText $row.Attribute), (ConvertTo-HtmlText $row.Message),
        (ConvertTo-HtmlText $row.RawXml), (ConvertTo-HtmlText $row.Guidance)
}
$summaryHtml = foreach ($group in $summary) {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>' -f
        (ConvertTo-HtmlText $group.Connector), (ConvertTo-HtmlText $group.Stage), (ConvertTo-HtmlText $group.ErrorType), $group.Count
}
$coverageHtml = foreach ($capture in $snapshot.Collections) {
    '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>' -f
        (ConvertTo-HtmlText $capture.Connector), (ConvertTo-HtmlText $capture.Filter), (ConvertTo-HtmlText $capture.Status),
        (ConvertTo-HtmlText $capture.FinishedUtc), (ConvertTo-HtmlText $capture.Error)
}
$stateText = "$($errorRows.Count) erreurs sur $uniqueObjects objets"
if ($completeness -ne 'Complete') { $stateText = 'COLLECTE INCOMPLETE : ne pas conclure a une absence d erreurs. ' + $stateText }
elseif ($errorRows.Count -eq 0) { $stateText = 'Aucune erreur objet retournee par les filtres des connecteurs collectes.' }
$modeText = 'Collecte locale'
if ($PSCmdlet.ParameterSetName -eq 'Offline') { $modeText = 'Relecture de la collecte datee ci-dessous, pas un etat rafraichi' }
$html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra Connect - Erreurs actuelles</title><style>
:root{--ink:#202622;--line:#ccd5ce;--accent:#166546}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:#f5f7f5;font:14px 'Segoe UI',sans-serif}
header{padding:24px;background:white;border-bottom:3px solid var(--accent)}h1{font-size:24px;margin:0 0 10px}h2{font-size:18px}main{padding:0 24px 30px;max-width:1800px;margin:auto}
.notice{padding:14px;border-left:4px solid #ae5813;background:#fff3db}.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:18px 0}input,select{max-width:100%;padding:8px;font:inherit;border:1px solid var(--line)}input{width:300px}
.scroll{overflow:auto}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{background:#e3eee7}#errors{table-layout:fixed;min-width:1000px}#errors th:nth-child(1){width:11%}#errors th:nth-child(2){width:10%}#errors th:nth-child(3){width:19%}#errors th:nth-child(4){width:14%}#errors th:nth-child(5){width:23%}#errors th:nth-child(6){width:23%}
pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:350px;overflow:auto;font-size:12px}summary{cursor:pointer;color:var(--accent)}tr[hidden]{display:none}small{color:#526055}p{line-height:1.5}
@media(max-width:640px){header{padding:16px}main{padding:0 16px 24px}h1{font-size:21px}}
</style></head><body><header><h1>Entra Connect - Erreurs actuelles</h1><div>$(ConvertTo-HtmlText $snapshot.Server) | $(ConvertTo-HtmlText $modeText)</div><p>Debut UTC : $(ConvertTo-HtmlText $snapshot.CollectionStartedUtc) | Fin UTC : $(ConvertTo-HtmlText $snapshot.CollectedAtUtc)</p></header>
<main><p class="notice">$(ConvertTo-HtmlText $stateText)</p><p>Erreurs conservees par le moteur. Une date ancienne ne signifie pas que l erreur est resolue. Les explications sont des pistes, pas une cause racine prouvee. Aucun traitement de synchronisation n est relance.</p>
<h2>Synthese</h2><div class="scroll"><table><thead><tr><th>Connecteur</th><th>Etape</th><th>Type</th><th>Erreurs</th></tr></thead><tbody>$($summaryHtml -join "`n")</tbody></table></div>
<h2>Erreurs par objet</h2><div class="controls"><input id="search" type="search" aria-label="Rechercher" placeholder="DN, UPN, code, message"><select id="connector" aria-label="Connecteur"><option value="">Tous les connecteurs</option></select><select id="stage" aria-label="Etape"><option value="">Toutes les etapes</option></select><span id="count" aria-live="polite"></span></div>
<div class="scroll"><table id="errors"><thead><tr><th>Connecteur</th><th>Etape</th><th>Objet</th><th>Code / attribut</th><th>Message exact</th><th>Explication et verification</th></tr></thead><tbody>$($rowsHtml -join "`n")</tbody></table></div>
<h2>Couverture de la collecte</h2><div class="scroll"><table><thead><tr><th>Connecteur</th><th>Filtre</th><th>Etat</th><th>Fin UTC</th><th>Echec de collecte</th></tr></thead><tbody>$($coverageHtml -join "`n")</tbody></table></div>
<p><a href="https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-sync-errors">Reference Microsoft sur les erreurs de synchronisation</a></p>
</main><script>
const rows=Array.from(document.querySelectorAll('#errors tbody tr'));
const search=document.getElementById('search'), connector=document.getElementById('connector'), stage=document.getElementById('stage');
for(const [select,index] of [[connector,0],[stage,1]]){
 for(const value of [...new Set(rows.map(row=>row.cells[index].textContent))].sort()){
  const option=document.createElement('option');option.value=value;option.textContent=value;select.appendChild(option);
 }
}
function filterRows(){let visible=0;for(const row of rows){row.hidden=!!((connector.value && row.cells[0].textContent!==connector.value)||(stage.value && row.cells[1].textContent!==stage.value)||!row.textContent.toLowerCase().includes(search.value.toLowerCase()));if(!row.hidden)visible++;}document.getElementById('count').textContent=visible+' / '+rows.length;}
search.addEventListener('input',filterRows);connector.addEventListener('change',filterRows);stage.addEventListener('change',filterRows);filterRows();
</script></body></html>
"@
$html | Set-Content -LiteralPath (Join-Path $destination 'Report.html') -Encoding UTF8
Write-Warning 'Identity data: restrict report access. Import CSV columns as text to avoid spreadsheet formula execution.'
if ($completeness -ne 'Complete') { Write-Warning 'Collection incomplete. Check the coverage table and Report.json.' }
[pscustomobject]@{
    Directory = [IO.Path]::GetFullPath($destination); Html = [IO.Path]::GetFullPath((Join-Path $destination 'Report.html'))
    Errors = $errorRows.Count; UniqueObjects = $uniqueObjects; Completeness = $completeness
}