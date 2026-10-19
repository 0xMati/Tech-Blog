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

function Get-ErrorAnalysis {
    param([string]$Type, [string]$Code, [string]$Message, [string]$Attribute, [string]$RawXml)
    $text = $Type + ' ' + $Code + ' ' + $Message
    $category = 'Erreur non classee'
    $evidence = ''
    $conflictingObject = ''
    $explanation = 'Le message ne correspond pas a une signature connue.'
    $checks = Get-ErrorGuidance $text
    if ($Type -eq 'sync-generic-failure' -and $Message -match '(?im)\bCurrent Object DN: "[^"\r\n]+" is trying to connect to the MV object id: "\{[0-9a-f-]+\}", which is already connected to at\s*least one other object\.') {
        $category = 'Conflit de jointure metaverse'
        $evidence = $Matches[0]
        $explanation = 'Le moteur tente de joindre un objet metaverse deja connecte a un autre objet source.'
        if ($Message -match '(?im)^DN of the connected object:\s*"([^"\r\n]+)"') { $conflictingObject = $Matches[1] }
        $checks = 'Comparer les deux objets sources, leurs criteres de jointure et leurs liens metaverse dans Search Connector Space et Metaverse Search. Verifier les regles citees et l identite attendue avant de changer une valeur ou une jointure. Le message ne determine pas quel objet conserver.'
    }
    elseif ($Type -eq 'sync-generic-failure' -and $Message -match '(?im)\bThe Connector [^\r\n]+ contains another object with the same DN which is already connected to MV\b') {
        $category = 'Conflit de DN cible'
        $evidence = $Matches[0]
        $explanation = 'Le provisionnement rencontre dans le connecteur cible un objet de meme DN deja connecte au metaverse.'
        if ($Message -match '(?is)\bExisting Object\s*:\s*Pipeline Object \[[^\]]+\]:[^\r\n]*?\bDN=([^\r\n]+?), NSID=') { $conflictingObject = $Matches[1] }
        $checks = 'Rechercher le DN dans le connecteur cible cite, examiner son lien metaverse et comparer les ancrages et les regles de provisionnement des objets en conflit. Confirmer l identite attendue avant toute suppression, deconnexion ou modification d ancrage.'
    }
    else {
        $categories = @(
            @('SourceAnchor attribute has changed', 'Changement d ancrage'),
            @('AttributeValueMustBeUnique', 'Valeur non unique'),
            @('InvalidSoftMatch', 'Conflit de rapprochement souple'),
            @('InvalidHardMatch', 'Rapprochement par ancrage refuse'),
            @('ObjectTypeMismatch', 'Conflit de type d objet'),
            @('IdentityDataValidationFailed|DataValidationFailed', 'Validation des donnees'),
            @('LargeObject|ExceededAllowedLength', 'Limite de taille'),
            @('permission-issue|insufficient.access|access.denied', 'Permissions insuffisantes'),
            @('sync-rule-error|extension-dll-exception|extension-error', 'Regle ou extension')
        )
        foreach ($signature in $categories) {
            if ($text -match $signature[0]) {
                $category = $signature[1]; $evidence = $Matches[0]
                $explanation = $checks
                $checks = 'Confirmer le diagnostic avec le message exact, le XML et les proprietes de l objet avant toute correction.'
                break
            }
        }
        if (-not $Attribute -and $category -eq 'Changement d ancrage') { $Attribute = 'sourceAnchor' }
    }
    if (-not $Attribute -and $Message -match '(?i)\battribute(?:-name| name)?\s*[:=]\s*["\x27]([a-z][a-z0-9_-]*)["\x27]') { $Attribute = $Matches[1] }
    $metaverseId = ''; $targetConnector = ''; $failingRule = ''; $destinationAttribute = ''
    if ($category -eq 'Conflit de jointure metaverse' -and $Message -match '(?i)trying to connect to the MV object id: "(\{[0-9a-f-]+\})"') { $metaverseId = $Matches[1] }
    if ($category -eq 'Conflit de DN cible' -and $Message -match '(?im)\bThe Connector ([^\r\n]+) contains another object with the same DN') { $targetConnector = $Matches[1].Trim() }
    $header = ($Message -split '(?im)^\s*Object info\s*:', 2)[0]
    if ($header -match '(?m)^\s*\. Sync Rule:\s*([^\r\n]+)') { $failingRule = $Matches[1].Trim() }
    if ($header -match '(?m)^\s*Destination:\s*([^\r\n]+)') { $destinationAttribute = $Matches[1].Trim() }
    $citedRules = @()
    if ($Message -match '(?im)^Conflicting sync rules:\s*\r?\n((?:--[^\r\n]+(?:\r?\n|$))+)') {
        $citedRules = @($Matches[1] -split '\r?\n' | Where-Object { $_ -like '--*' } | ForEach-Object { $_.Substring(2).Trim() } | Sort-Object -Unique)
    }
    $internalStep = ''; $extension = ''; $retryCount = ''
    if ($RawXml) {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $stringReader = [System.IO.StringReader]::new($RawXml)
        $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        try {
            $document = [System.Xml.XmlDocument]::new(); $document.XmlResolver = $null
            $document.Load($reader)
            $internalStep = Get-XmlText $document '//*[local-name()="algorithm-step"]'
            $extension = Get-XmlText $document '//*[local-name()="extension-name"]'
            $retryCount = Get-XmlText $document '/*/@retry-count | /*/*/@retry-count'
        }
        finally { $reader.Dispose(); $stringReader.Dispose() }
    }
    if ($category -eq 'Changement d ancrage') {
        $checks = 'Dans Search Connector Space, ouvrir l objet source et son lien metaverse. Dans Metaverse Search, comparer sourceAnchor et cloudSourceAnchor, puis examiner la regle signalee et les flux qui alimentent ces valeurs. Confirmer l identite attendue ; ne pas remplacer un ancrage pour contourner cette protection.'
    }
    [pscustomobject]@{
        Category = $category; Explanation = $explanation; Checks = $checks
        Evidence = $evidence; ConflictingObject = $conflictingObject; Attribute = $Attribute
        MetaverseId = $metaverseId; TargetConnector = $targetConnector
        FailingRule = $failingRule; CitedRules = $citedRules -join "`n"; DestinationAttribute = $destinationAttribute
        InternalStep = $internalStep; Extension = $extension; RetryCount = $retryCount
        Guidance = $explanation + ' Verifications : ' + $checks
    }
}

function Get-ConflictGroups {
    param([object[]]$Errors)
    $buckets = @{}
    foreach ($entry in $Errors) {
        $entry | Add-Member -MemberType NoteProperty -Name ConflictGroup -Value '' -Force
        $identity = @()
        if ($entry.Category -eq 'Conflit de jointure metaverse' -and $entry.MetaverseId) {
            $identity = @('MV', $entry.Connector, $entry.MetaverseId)
        }
        elseif ($entry.Category -eq 'Conflit de DN cible' -and $entry.TargetConnector -and $entry.ConflictingObject) {
            $identity = @('DN', $entry.TargetConnector, $entry.ConflictingObject)
        }
        if ($identity.Count -eq 0) { continue }
        $key = ConvertTo-Json -InputObject $identity -Compress
        if (-not $buckets.ContainsKey($key)) { $buckets[$key] = [System.Collections.Generic.List[object]]::new() }
        $buckets[$key].Add($entry)
    }
    $groupNumber = 0
    foreach ($key in @($buckets.Keys | Sort-Object)) {
        $members = $buckets[$key]
        $objectCount = @($members | ForEach-Object {
            $identifier = $_.CsObjectId
            if (-not $identifier) { $identifier = $_.DN }
            ConvertTo-Json -InputObject @($_.Connector, $identifier) -Compress
        } | Sort-Object -Unique).Count
        if ($objectCount -lt 2) { continue }
        $groupNumber++
        $groupId = 'Conflit-{0:D3}' -f $groupNumber
        foreach ($member in $members) { $member.ConflictGroup = $groupId }
        $first = $members[0]
        $target = $first.MetaverseId; $scope = $first.Connector
        if ($first.Category -eq 'Conflit de DN cible') { $target = $first.ConflictingObject; $scope = $first.TargetConnector }
        [pscustomobject]@{ Id = $groupId; Category = $first.Category; Connector = $scope; Target = $target; Objects = $objectCount; Errors = $members.Count }
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

foreach ($errorRow in $snapshot.Errors) {
    $analysis = Get-ErrorAnalysis -Type $errorRow.ErrorType -Code $errorRow.ErrorCode -Message $errorRow.Message -Attribute $errorRow.Attribute -RawXml $errorRow.RawXml
    foreach ($property in $analysis.PSObject.Properties) {
        $errorRow | Add-Member -MemberType NoteProperty -Name $property.Name -Value $property.Value -Force
    }
}
$errorRows = @($snapshot.Errors)
$conflictGroups = @(Get-ConflictGroups -Errors $errorRows)
$completeness = 'Complete'
if (@($snapshot.Collections).Count -eq 0 -or @($snapshot.Collections | Where-Object Status -ne 'Complete').Count -gt 0) { $completeness = 'Incomplete' }
$uniqueObjects = @($errorRows | Group-Object Connector | ForEach-Object {
    $_.Group | ForEach-Object { if ($_.CsObjectId) { $_.CsObjectId } else { $_.DN } } | Sort-Object -Unique
}).Count
$summary = @($errorRows | Group-Object Connector, Stage, Category, ErrorType | ForEach-Object {
    [pscustomobject]@{ Connector = $_.Group[0].Connector; Stage = $_.Group[0].Stage; Category = $_.Group[0].Category; ErrorType = $_.Group[0].ErrorType; Count = $_.Count }
})
$report = [pscustomobject]@{
    SchemaVersion = 2; Server = $snapshot.Server; CollectionStartedUtc = $snapshot.CollectionStartedUtc
    CollectedAtUtc = $snapshot.CollectedAtUtc; Completeness = $completeness; UniqueObjects = $uniqueObjects
    Scope = 'Object errors retained in Connector Spaces at collection time; no cycle history or fresh target validation.'
    Errors = $errorRows; Summary = $summary; ConflictGroups = $conflictGroups; Collections = @($snapshot.Collections)
}
$snapshot | Export-Clixml -LiteralPath (Join-Path $destination 'Snapshot.clixml') -Depth 100 -Encoding UTF8
ConvertTo-Json -InputObject $report -Depth 30 | Set-Content -LiteralPath (Join-Path $destination 'Report.json') -Encoding UTF8
$columns = @('Connector','Stage','DN','UPN','CsObjectId','ErrorType','ErrorCode','Attribute','Category','Explanation','Checks','Evidence','ConflictingObject','MetaverseId','TargetConnector','InternalStep','Extension','FailingRule','CitedRules','DestinationAttribute','RetryCount','ConflictGroup','Message','Guidance','FirstOccurred','LastOccurred','ObservedAtUtc','SourceFilter','RawXml')
if ($errorRows.Count) {
    $errorRows | Select-Object $columns | Export-Csv -LiteralPath (Join-Path $destination 'Errors.csv') -NoTypeInformation -Encoding UTF8
}
else {
    (($columns | ForEach-Object { '"' + $_ + '"' }) -join ',') | Set-Content -LiteralPath (Join-Path $destination 'Errors.csv') -Encoding UTF8
}
$rowsHtml = foreach ($row in $errorRows) {
    $attributeText = $row.Attribute
    if (-not $attributeText) { $attributeText = '(Non precise)' }
    $codeText = $row.ErrorCode
    if (-not $codeText) { $codeText = '(Non precise)' }
    $conflictHtml = ''
    if ($row.ConflictingObject) { $conflictHtml = '<p><strong>Objet en conflit :</strong> {0}</p>' -f (ConvertTo-HtmlText $row.ConflictingObject) }
    $contextHtml = foreach ($field in @(
        @('Etape interne', 'InternalStep'), @('Extension', 'Extension'), @('Objet metaverse', 'MetaverseId'),
        @('Connecteur cible', 'TargetConnector'), @('Regle en echec', 'FailingRule'), @('Attribut destination', 'DestinationAttribute'),
        @('Regles citees (non prouvees en echec)', 'CitedRules'), @('Premiere occurrence', 'FirstOccurred'),
        @('Derniere occurrence', 'LastOccurred'), @('Tentatives', 'RetryCount'), @('Conflit lie', 'ConflictGroup')
    )) {
        $value = $row.($field[1])
        if ($value -ne '') { '<dt>{0}</dt><dd>{1}</dd>' -f (ConvertTo-HtmlText $field[0]), (ConvertTo-HtmlText $value) }
    }
    $exportData = ConvertTo-Json -InputObject ($row | Select-Object ($columns | Where-Object { $_ -notin @('Message','RawXml') })) -Compress
    '<tr data-category="{10}" data-error-type="{5}" data-error-code="{6}" data-attribute="{7}" data-conflict-group="{16}" data-export="{17}"><td>{0}</td><td>{1}</td><td><strong>{2}</strong><p>{3}</p><small>{4}</small>{14}</td><td>{5}<p>{6}</p><small>{7}</small></td><td><dl>{15}</dl></td><td><strong>{10}</strong><p>{11}</p><p><strong>A verifier :</strong> {12}</p><details><summary>Signature detectee</summary><pre>{13}</pre></details><details><summary>Message exact</summary><pre class="message">{8}</pre></details><details><summary>XML technique</summary><pre>{9}</pre></details></td></tr>' -f
        (ConvertTo-HtmlText $row.Connector), (ConvertTo-HtmlText $row.Stage), (ConvertTo-HtmlText $row.DN),
        (ConvertTo-HtmlText $row.UPN), (ConvertTo-HtmlText $row.CsObjectId), (ConvertTo-HtmlText $row.ErrorType),
        (ConvertTo-HtmlText $codeText), (ConvertTo-HtmlText $attributeText), (ConvertTo-HtmlText $row.Message),
        (ConvertTo-HtmlText $row.RawXml), (ConvertTo-HtmlText $row.Category),
        (ConvertTo-HtmlText $row.Explanation), (ConvertTo-HtmlText $row.Checks), (ConvertTo-HtmlText $row.Evidence), $conflictHtml,
        ($contextHtml -join ''), (ConvertTo-HtmlText $row.ConflictGroup), (ConvertTo-HtmlText $exportData)
}
$conflictsHtml = foreach ($group in $conflictGroups) {
    '<tr data-category="{1}"><td><span class="group-badge">{0}</span></td><td><span class="category-badge">{1}</span></td><td>{2}</td><td class="technical">{3}</td><td class="numeric">{4}</td><td class="numeric">{5}</td></tr>' -f
        (ConvertTo-HtmlText $group.Id), (ConvertTo-HtmlText $group.Category), (ConvertTo-HtmlText $group.Connector),
        (ConvertTo-HtmlText $group.Target), $group.Objects, $group.Errors
}
if ($conflictGroups.Count -eq 0) { $conflictsHtml = @('<tr><td colspan="6">Aucune cible explicite partagee par plusieurs objets sources dans cette collecte.</td></tr>') }
$summaryHtml = foreach ($group in $summary) {
    '<tr data-category="{2}"><td>{0}</td><td>{1}</td><td><span class="category-badge">{2}</span></td><td class="technical">{3}</td><td class="numeric">{4}</td></tr>' -f
        (ConvertTo-HtmlText $group.Connector), (ConvertTo-HtmlText $group.Stage), (ConvertTo-HtmlText $group.Category), (ConvertTo-HtmlText $group.ErrorType), $group.Count
}
$coverageHtml = foreach ($capture in $snapshot.Collections) {
    '<tr><td>{0}</td><td class="technical">/f:{1}</td><td><span class="status-badge" data-status="{2}">{2}</span></td><td>{3}</td><td>{4}</td></tr>' -f
        (ConvertTo-HtmlText $capture.Connector), (ConvertTo-HtmlText $capture.Filter), (ConvertTo-HtmlText $capture.Status),
        (ConvertTo-HtmlText $capture.FinishedUtc), (ConvertTo-HtmlText $capture.Error)
}
$stateText = "$($errorRows.Count) erreurs sur $uniqueObjects objets"
if ($completeness -ne 'Complete') { $stateText = 'COLLECTE INCOMPLETE : ne pas conclure a une absence d erreurs. ' + $stateText }
elseif ($errorRows.Count -eq 0) { $stateText = 'Aucune erreur objet retournee par les filtres des connecteurs collectes.' }
$modeText = 'Collecte locale'
if ($PSCmdlet.ParameterSetName -eq 'Offline') { $modeText = 'Relecture de la collecte datee ci-dessous, pas un etat rafraichi' }
$categoryCount = @($errorRows | Select-Object -ExpandProperty Category -Unique).Count
$html = @"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra Connect - Erreurs actuelles</title><style>
:root{--ink:#26312f;--muted:#5e6d69;--line:#dce4e0;--accent:#12684f;--blue:#185ca0;--rose:#a03358;--amber:#95520b;--tone:#52635d;--tint:#edf1ef}*{box-sizing:border-box;letter-spacing:0}body{margin:0;color:var(--ink);background:linear-gradient(180deg,#edf4f0 0,#f7f9f8 420px);font:14px 'Segoe UI',sans-serif;line-height:1.5}
header{padding:28px 32px 24px;background:#fff;border-top:5px solid var(--accent);border-bottom:1px solid var(--line)}.header-inner{max-width:1836px;margin:auto}.eyebrow{font-size:12px;font-weight:700;color:var(--accent);margin:0 0 6px}h1{font:600 28px 'Bahnschrift','Segoe UI',sans-serif;margin:0 0 14px;line-height:1.2}h2{font:600 19px 'Bahnschrift','Segoe UI',sans-serif;margin:30px 0 14px;display:flex;align-items:center;gap:10px}h2:before{content:'';width:4px;height:20px;background:var(--accent);flex-shrink:0}.header-meta{display:flex;gap:10px;align-items:center;flex-wrap:wrap;color:var(--muted)}.server-badge{background:#edf4f0;color:#16553f;font-weight:700;padding:5px 10px;border-radius:4px}.timestamps{color:var(--muted);font-size:12px;margin:12px 0 0}main{padding:24px 32px 40px;max-width:1900px;margin:auto}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));background:#fff;border:1px solid var(--line);margin-bottom:20px}.metric{padding:16px 20px;border-top:3px solid var(--tone);border-right:1px solid var(--line);min-width:0}.metric:last-child{border-right:0}.metric:nth-child(1){--tone:var(--rose)}.metric:nth-child(2){--tone:var(--blue)}.metric:nth-child(3){--tone:var(--accent)}.metric:nth-child(4){--tone:var(--amber)}.metric strong{display:block;font:600 30px 'Bahnschrift','Segoe UI',sans-serif;color:var(--tone);font-variant-numeric:tabular-nums}.metric span{font-size:12px;color:var(--muted)}
.notice{padding:12px 16px;border:1px solid #ead7b4;border-left:4px solid var(--amber);background:#fff8e9;margin:0 0 12px;border-radius:0 4px 4px 0;font-weight:600}.notice[data-state="Incomplete"]{background:#fff0f0;border-color:#e7babc;border-left-color:#ae303d;color:#8a2530}.scope{color:var(--muted);font-size:12px;max-width:1100px}.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin:0;padding:16px 0;border-top:1px solid var(--line)}.controls label{display:flex;flex-direction:column;gap:5px;max-width:100%;min-width:0;color:var(--muted);font-size:12px;font-weight:600}input,select,button{max-width:100%;min-height:38px;padding:8px 10px;font:14px 'Segoe UI',sans-serif;border:1px solid #bdccc4;border-radius:4px;background:#fff;color:var(--ink)}input{width:280px}input:focus-visible,select:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--blue);outline-offset:2px}button{cursor:pointer;background:var(--accent);color:white;border-color:var(--accent);font-weight:600}button:hover{background:#0c513d}button:disabled{opacity:.45;cursor:default}#count{padding:8px 10px;font-size:12px;white-space:nowrap;font-variant-numeric:tabular-nums;border-radius:4px;background:#e8eeeb;color:#375246}
.scroll{overflow:auto;border:1px solid var(--line)}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;vertical-align:top;padding:13px 14px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{background:#eef3f0;color:#53665d;font-size:11px;font-weight:700}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#f8faf9}.numeric{font-weight:700;font-variant-numeric:tabular-nums}.technical,pre{font-family:Consolas,'Courier New',monospace}.technical{font-size:12px}#errors{table-layout:fixed;min-width:1150px}#errors th:nth-child(1){width:10%}#errors th:nth-child(2){width:8%}#errors th:nth-child(3){width:22%}#errors th:nth-child(4){width:13%}#errors th:nth-child(5){width:20%}#errors th:nth-child(6){width:27%}#errors tbody td{padding-top:20px;padding-bottom:20px}#errors tbody td:first-child{box-shadow:inset 3px 0 var(--tone);font-weight:600}#errors td:nth-child(3)>strong{font-size:12px;font-family:Consolas,'Courier New',monospace}#errors td:nth-child(3) p{margin:10px 0}#errors td:nth-child(4){font-family:Consolas,'Courier New',monospace;font-size:12px}
[data-tone="blue"]{--tone:#185ca0;--tint:#eaf2fc}[data-tone="amber"]{--tone:#95520b;--tint:#fff3df}[data-tone="rose"]{--tone:#a03358;--tint:#fbeef3}[data-tone="green"]{--tone:#12684f;--tint:#e9f5ef}.category-badge,.group-badge,.status-badge{display:inline-block;font:600 12px 'Segoe UI',sans-serif;padding:5px 9px;border-radius:4px;line-height:1.4;max-width:100%;overflow-wrap:anywhere}.category-badge{background:var(--tint);color:var(--tone);border:1px solid color-mix(in srgb,var(--tone) 20%,transparent)}.group-badge{background:#edf1ef;color:#38584a;font-family:Consolas,'Courier New',monospace}.status-badge[data-status="Complete"]{background:#e8f5ed;color:#176240}.status-badge[data-status="Failed"]{background:#ffeded;color:#a12d38}
dl{margin:0}dt{font-size:11px;color:var(--muted)}dd{margin:2px 0 12px;white-space:pre-line;font-size:12px}dd:last-child{margin-bottom:0}details{margin-top:10px;border-top:1px solid var(--line);padding-top:8px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:350px;overflow:auto;font-size:12px;padding:10px;background:#f3f6f4;border-radius:4px}summary{cursor:pointer;color:var(--accent);font-size:12px;font-weight:600}tr[hidden]{display:none}small{color:var(--muted);font-size:11px}p{line-height:1.5}a{color:var(--accent)}
@media(max-width:640px){header{padding:20px 16px}main{padding:18px 16px 28px}h1{font-size:23px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric{padding:12px 14px}.metric:nth-child(2){border-right:0}.metric strong{font-size:26px}.header-meta{align-items:flex-start}.controls label{flex:1 1 140px}.controls label:first-child{flex-basis:100%}input{width:100%}table{min-width:760px}td,th{padding:10px}th{white-space:nowrap}.timestamps{overflow-wrap:anywhere}}
@media print{body{background:white}.controls{display:none}main,header{padding:12px}.scroll{overflow:visible}#errors{min-width:0}td,th{padding:6px}pre{max-height:none}}
</style></head><body><header><div class="header-inner"><p class="eyebrow">DIAGNOSTIC / ENTRA CONNECT</p><h1>Erreurs de synchronisation</h1><div class="header-meta"><span class="server-badge">$(ConvertTo-HtmlText $snapshot.Server)</span><span>$(ConvertTo-HtmlText $modeText)</span><span class="status-badge" data-status="$(ConvertTo-HtmlText $completeness)">$(ConvertTo-HtmlText $completeness)</span></div><p class="timestamps">Debut UTC : $(ConvertTo-HtmlText $snapshot.CollectionStartedUtc) &nbsp;|&nbsp; Fin UTC : $(ConvertTo-HtmlText $snapshot.CollectedAtUtc)</p></div></header>
<main><div class="metrics" aria-label="Synthese de la collecte"><div class="metric"><strong>$($errorRows.Count)</strong><span>Erreurs collectees</span></div><div class="metric"><strong>$uniqueObjects</strong><span>Objets distincts</span></div><div class="metric"><strong>$categoryCount</strong><span>Categories</span></div><div class="metric"><strong>$($conflictGroups.Count)</strong><span>Cibles partagees</span></div></div><p class="notice" data-state="$(ConvertTo-HtmlText $completeness)">$(ConvertTo-HtmlText $stateText)</p><p class="scope">Erreurs conservees par le moteur. Une date ancienne ne signifie pas que l erreur est resolue. Les explications sont des pistes, pas une cause racine prouvee. Aucun traitement de synchronisation n est relance.</p>
<h2>Synthese</h2><div class="scroll"><table><thead><tr><th>Connecteur</th><th>Etape</th><th>Categorie</th><th>Type</th><th>Erreurs</th></tr></thead><tbody>$($summaryHtml -join "`n")</tbody></table></div>
<h2>Conflits lies</h2><div class="scroll"><table id="conflicts"><thead><tr><th>Groupe</th><th>Categorie</th><th>Perimetre connecteur</th><th>Cible partagee</th><th>Objets sources</th><th>Erreurs</th></tr></thead><tbody>$($conflictsHtml -join "`n")</tbody></table></div>
<h2>Erreurs par objet</h2><div class="controls"><label>Recherche<input id="search" type="search" placeholder="DN, UPN, code, message"></label><label>Connecteur<select id="connector"><option value="">Tous</option></select></label><label>Etape<select id="stage"><option value="">Toutes</option></select></label><label>Categorie<select id="category"><option value="">Toutes</option></select></label><label>Type technique<select id="errorType"><option value="">Tous</option></select></label><label>Code<select id="errorCode"><option value="">Tous</option></select></label><label>Attribut<select id="attribute"><option value="">Tous</option></select></label><label>Conflit lie<select id="conflictGroup"><option value="">Tous</option></select></label><span id="count" aria-live="polite"></span><button id="exportCsv" type="button" title="Exporter les erreurs visibles au format CSV">&#8595; Exporter CSV</button></div>
<div class="scroll"><table id="errors"><thead><tr><th>Connecteur</th><th>Etape</th><th>Objets</th><th>Code / attribut</th><th>Contexte et persistance</th><th>Diagnostic</th></tr></thead><tbody>$($rowsHtml -join "`n")</tbody></table></div>
<h2>Couverture de la collecte</h2><div class="scroll"><table><thead><tr><th>Connecteur</th><th>Filtre</th><th>Etat</th><th>Fin UTC</th><th>Echec de collecte</th></tr></thead><tbody>$($coverageHtml -join "`n")</tbody></table></div>
<p><a href="https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-sync-errors">Reference Microsoft sur les erreurs de synchronisation</a></p>
</main><script>
for(const row of document.querySelectorAll('tr[data-category]')){
 const category=row.dataset.category;
 row.dataset.tone=category==='Conflit de jointure metaverse'?'blue':category==='Conflit de DN cible'?'amber':category==='Changement d ancrage'?'rose':category==='Erreur non classee'?'neutral':'green';
 if(row.closest('#errors'))row.cells[5].querySelector('strong').classList.add('category-badge');
}
const rows=Array.from(document.querySelectorAll('#errors tbody tr'));
const search=document.getElementById('search');
const exportButton=document.getElementById('exportCsv');
const filters=[['connector',row=>row.cells[0].textContent],['stage',row=>row.cells[1].textContent],...['category','errorType','errorCode','attribute','conflictGroup'].map(key=>[key,row=>row.dataset[key]])].map(([id,valueOf])=>({select:document.getElementById(id),valueOf}));
for(const {select,valueOf} of filters){
 for(const value of [...new Set(rows.map(valueOf))].filter(Boolean).sort()){
  const option=document.createElement('option');option.value=value;option.textContent=value;select.appendChild(option);
 }
}
function filterRows(){let visible=0;const query=search.value.toLowerCase();for(const row of rows){row.hidden=filters.some(({select,valueOf})=>select.value && valueOf(row)!==select.value)||!row.textContent.toLowerCase().includes(query);if(!row.hidden)visible++;}document.getElementById('count').textContent=visible+' / '+rows.length;exportButton.disabled=visible===0;}
function csvCell(value){let text=String(value??'');if(/^[=+\-@\t\r\n]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';}
exportButton.addEventListener('click',()=>{
 const visible=rows.filter(row=>!row.hidden).map(row=>({...JSON.parse(row.dataset.export),Message:row.querySelector('.message').textContent}));
 if(!visible.length)return;
 const columns=Object.keys(visible[0]);
 const csv=[columns.map(csvCell).join(','),...visible.map(record=>columns.map(key=>csvCell(record[key])).join(','))].join('\r\n');
 const url=URL.createObjectURL(new Blob(['\uFEFF',csv],{type:'text/csv;charset=utf-8'}));
 const link=document.createElement('a');link.href=url;link.download='EntraConnectErrors-filtered.csv';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
});
search.addEventListener('input',filterRows);for(const {select} of filters)select.addEventListener('change',filterRows);filterRows();
</script></body></html>
"@
$html | Set-Content -LiteralPath (Join-Path $destination 'Report.html') -Encoding UTF8
Write-Warning 'Identity data: restrict report access. Import CSV columns as text to avoid spreadsheet formula execution.'
if ($completeness -ne 'Complete') { Write-Warning 'Collection incomplete. Check the coverage table and Report.json.' }
[pscustomobject]@{
    Directory = [IO.Path]::GetFullPath($destination); Html = [IO.Path]::GetFullPath((Join-Path $destination 'Report.html'))
    Errors = $errorRows.Count; UniqueObjects = $uniqueObjects; Completeness = $completeness
}