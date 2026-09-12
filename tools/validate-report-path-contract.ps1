[CmdletBinding()]
param(
    [string] $ReportRoot,
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ContractId = 'JUST-PROD-D009-V1'
$SchemaVersion = 'JUST-REPORT-PATH-CONTRACT-V1'
$TraceFields = @(
    'application_entry_class',
    'application_entry_method',
    'application_site_class',
    'application_site_method',
    'application_site_kind',
    'join_kind',
    'chain_entry_method',
    'entry_prefix_path'
)

function Read-JsonStrict([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "MISSING_JSON:$Path" }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        return ConvertFrom-Json -InputObject ([string]$raw)
    }
    catch { throw "INVALID_JSON:${Path}:$($_.Exception.Message):$($_.ScriptStackTrace)" }
}

function Get-PropertyValue($Object, [string] $Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { return $null }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-Text($Object, [string] $Name) {
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return '' }
    return [string]$value
}

function Get-TraceText($Object, [string] $Name) {
    $value = Get-Text $Object $Name
    if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
    $alias = switch ($Name) {
        'join_kind' { 'application_join_kind' }
        'chain_entry_method' { 'application_chain_entry_method' }
        'entry_prefix_path' { 'application_entry_prefix_path' }
        default { '' }
    }
    if ([string]::IsNullOrWhiteSpace($alias)) { return '' }
    return Get-Text $Object $alias
}

function Get-Array($Object) {
    if ($null -eq $Object) { return @() }
    if ($Object -is [Array]) { return @($Object) }
    return @($Object)
}

function Add-IndexValue($Index, [string] $Key, $Value) {
    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    if (-not $Index.ContainsKey($Key)) { $Index[$Key] = [Collections.Generic.List[object]]::new() }
    $Index[$Key].Add($Value) | Out-Null
}

function Normalize-Class([string] $Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return $Value.Replace('.', '/')
}

function Get-ShortChainId([string] $ChainKey) {
    $sha = [Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($ChainKey)
        return (([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()).Substring(0, 8)
    } finally {
        $sha.Dispose()
    }
}

function Add-Issue([Collections.Generic.List[string]] $Issues, [string] $Code) {
    if (-not $Issues.Contains($Code)) { $Issues.Add($Code) | Out-Null }
}

function Test-TraceComplete($Trace, [string] $Prefix, [Collections.Generic.List[string]] $Issues) {
    if ($null -eq $Trace) {
        Add-Issue $Issues ($Prefix + 'TRACE_MISSING')
        return $false
    }
    $valid = $true
    foreach ($field in $TraceFields) {
        if ([string]::IsNullOrWhiteSpace((Get-TraceText $Trace $field))) {
            Add-Issue $Issues ($Prefix + 'TRACE_FIELD_' + $field.ToUpperInvariant())
            $valid = $false
        }
    }
    return $valid
}

function Test-TraceEqual($Expected, $Actual) {
    if ($null -eq $Expected -or $null -eq $Actual) { return $false }
    foreach ($field in $TraceFields) {
        if ((Get-TraceText $Expected $field) -ne (Get-TraceText $Actual $field)) { return $false }
    }
    return $true
}

function Test-TraceAndPathEqual($ExpectedTrace, [string] $ExpectedPath, $Rendered) {
    if (-not (Test-TraceEqual $ExpectedTrace $Rendered)) { return $false }
    if ([string]::IsNullOrWhiteSpace($ExpectedPath)) { return $false }
    return (Get-Text $Rendered 'application_path') -eq $ExpectedPath
}

function Get-TraceKey($Object) {
    $separator = [char]0x1f
    $parts = [Collections.Generic.List[string]]::new()
    foreach ($field in $TraceFields) { $parts.Add((Get-TraceText $Object $field)) | Out-Null }
    return ($parts -join $separator)
}

function Get-GroupKey($Object) {
    $separator = [char]0x1e
    $parts = [Collections.Generic.List[string]]::new()
    $nestedTrace = Get-PropertyValue $Object 'application_trace'
    $traceSource = if ($null -eq $nestedTrace) { $Object } else { $nestedTrace }
    $parts.Add((Get-Text $Object 'rule_id')) | Out-Null
    foreach ($field in @('entry_class', 'entry_method', 'sink_class', 'sink_method')) {
        $value = Get-Text $Object $field
        if ($field -eq 'entry_class' -or $field -eq 'sink_class') { $value = Normalize-Class $value }
        $parts.Add($value) | Out-Null
    }
    $parts.Add((Get-TraceKey $traceSource)) | Out-Null
    return ($parts -join $separator)
}

function Get-TraceRuleKey($Object, [string] $RuleId) {
    return ($RuleId + ([char]0x1e) + (Get-TraceKey $Object))
}

function Test-CoreEqual($Canonical, $Rendered, [bool] $RequireCore) {
    if ($null -eq $Canonical -or $null -eq $Rendered) { return $false }
    if ((Get-Text $Canonical 'rule_id') -ne (Get-Text $Rendered 'rule_id')) { return $false }
    if (-not $RequireCore) { return $true }
    foreach ($field in @('entry_class', 'entry_method', 'sink_class', 'sink_method')) {
        $left = Get-Text $Canonical $field
        $right = Get-Text $Rendered $field
        if ($field -eq 'entry_class' -or $field -eq 'sink_class') {
            $left = Normalize-Class $left
            $right = Normalize-Class $right
        }
        if ($left -ne $right) { return $false }
    }
    return $true
}

function Test-RenderedTrace($Canonical, $Rendered, [bool] $RequireCore) {
    if (-not (Test-CoreEqual $Canonical $Rendered $RequireCore)) { return $false }
    return Test-TraceEqual (Get-PropertyValue $Canonical 'application_trace') $Rendered
}

function Read-CsvStrict([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "MISSING_CSV:$Path" }
    try { return @(Import-Csv -LiteralPath $Path) }
    catch { throw "INVALID_CSV:${Path}:$($_.Exception.Message)" }
}

function Test-ReportRoot([string] $Root) {
    $issues = [Collections.Generic.List[string]]::new()
    $rootFull = [IO.Path]::GetFullPath($Root)
    $required = @(
        'meta/application-chain-evidence.json',
        'meta/finding-output.json',
        'findings/findings.json',
        'findings/findings.sarif',
        'findings/findings.csv',
        'evidence/chains.csv'
    )
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $rootFull $relative) -PathType Leaf)) {
            Add-Issue $issues ('MISSING_' + $relative.Replace('/', '_').Replace('.', '_').ToUpperInvariant())
        }
    }
    if ($issues.Count -gt 0) {
        return [ordered]@{
            schema_version = $SchemaVersion
            contract_id = $ContractId
            valid = $false
            status = 'FAIL'
            report_root = $rootFull
            joined_count = 0
            exported_joined_count = 0
            renderer_counts = [ordered]@{}
            failures = @($issues.ToArray())
        }
    }

    try {
        $evidence = Read-JsonStrict (Join-Path $rootFull 'meta/application-chain-evidence.json')
        $findingOutput = Read-JsonStrict (Join-Path $rootFull 'meta/finding-output.json')
        $findingsJson = Read-JsonStrict (Join-Path $rootFull 'findings/findings.json')
        $sarif = Read-JsonStrict (Join-Path $rootFull 'findings/findings.sarif')
        # Wrap function results explicitly: Windows PowerShell unwraps a one-item
        # array on assignment, which would make Count unavailable under StrictMode.
        $findingsCsv = @(Read-CsvStrict (Join-Path $rootFull 'findings/findings.csv'))
        $chainsCsv = @(Read-CsvStrict (Join-Path $rootFull 'evidence/chains.csv'))
    } catch {
        Add-Issue $issues ('READ_ERROR_' + $_.Exception.Message)
        return [ordered]@{
            schema_version = $SchemaVersion
            contract_id = $ContractId
            valid = $false
            status = 'FAIL'
            report_root = $rootFull
            joined_count = 0
            exported_joined_count = 0
            renderer_counts = [ordered]@{}
            failures = @($issues.ToArray())
        }
    }

    $decisionProperties = @()
    $decisionObject = Get-PropertyValue $evidence 'decisions'
    if ($null -ne $decisionObject) { $decisionProperties = @($decisionObject.PSObject.Properties) }
    $joinedKeys = @($decisionProperties | Where-Object { [string]$_.Value -eq 'JOINED' } | ForEach-Object { [string]$_.Name })
    if ($joinedKeys.Count -eq 0) { Add-Issue $issues 'NO_JOINED_DECISIONS' }

    $canonicalFindings = @(Get-Array (Get-PropertyValue $findingOutput 'findings'))
    $jsonRows = @(Get-Array $findingsJson)
    $sarifResults = @()
    foreach ($run in (Get-Array (Get-PropertyValue $sarif 'runs'))) {
        $sarifResults += Get-Array (Get-PropertyValue $run 'results')
    }
    # Index the large renderers once.  A report can contain thousands of kernel
    # variants; repeatedly piping the whole arrays through Where-Object made this
    # validator itself quadratic on Windows PowerShell.
    $canonicalByKey = @{}
    foreach ($canonical in $canonicalFindings) {
        Add-IndexValue $canonicalByKey (Get-Text $canonical 'chain_key') $canonical
    }
    $chainsByVariant = @{}
    foreach ($row in $chainsCsv) {
        Add-IndexValue $chainsByVariant (Get-Text $row 'variant_id') $row
    }
    $jsonByTrace = @{}
    foreach ($row in $jsonRows) {
        if (-not [string]::IsNullOrWhiteSpace((Get-Text $row 'application_entry_class'))) {
            Add-IndexValue $jsonByTrace (Get-GroupKey $row) $row
        }
    }
    $csvByTrace = @{}
    foreach ($row in $findingsCsv) {
        if (-not [string]::IsNullOrWhiteSpace((Get-Text $row 'application_entry_class'))) {
            Add-IndexValue $csvByTrace (Get-GroupKey $row) $row
        }
    }
    $sarifByTrace = @{}
    foreach ($result in $sarifResults) {
        $properties = Get-PropertyValue $result 'properties'
        if (-not [string]::IsNullOrWhiteSpace((Get-Text $properties 'application_entry_class'))) {
            Add-IndexValue $sarifByTrace (Get-TraceRuleKey $properties (Get-Text $result 'ruleId')) $result
        }
    }
    $exportedGroupKeys = [Collections.Generic.HashSet[string]]::new()
    $exportedTraceRuleKeys = [Collections.Generic.HashSet[string]]::new()
    $pathsByGroup = @{}
    $exportedTraces = [Collections.Generic.List[object]]::new()
    $exportedJoined = 0
    $joinedRecords = [Collections.Generic.List[object]]::new()

    foreach ($chainKey in $joinedKeys) {
        $matches = @()
        if ($canonicalByKey.ContainsKey($chainKey)) { $matches = @($canonicalByKey[$chainKey]) }
        if ($matches.Count -eq 0) {
            Add-Issue $issues ('JOINED_CANONICAL_MISSING_' + (Get-ShortChainId $chainKey))
            continue
        }
        if ($matches.Count -gt 1) { Add-Issue $issues ('JOINED_CANONICAL_DUPLICATE_' + (Get-ShortChainId $chainKey)) }
        $canonical = $matches[0]
        $trace = Get-PropertyValue $canonical 'application_trace'
        $traceValid = Test-TraceComplete $trace ('CANONICAL_' + (Get-ShortChainId $chainKey) + '_') $issues

        $shortId = Get-ShortChainId $chainKey
        $evidenceRows = @()
        if ($chainsByVariant.ContainsKey($shortId)) { $evidenceRows = @($chainsByVariant[$shortId]) }
        $expectedPath = ''
        if ($evidenceRows.Count -eq 0) {
            Add-Issue $issues ('EVIDENCE_CHAIN_ROW_MISSING_' + $shortId)
        } elseif ($traceValid) {
            $expectedPath = Get-Text $evidenceRows[0] 'application_path'
            if ([string]::IsNullOrWhiteSpace($expectedPath)) {
                Add-Issue $issues ('EVIDENCE_APPLICATION_PATH_MISSING_' + $shortId)
            }
            foreach ($row in $evidenceRows) {
                if (-not (Test-TraceEqual $trace $row)) { Add-Issue $issues ('EVIDENCE_TRACE_MISMATCH_' + $shortId) }
                $rowPath = Get-Text $row 'application_path'
                if ((-not [string]::IsNullOrWhiteSpace($expectedPath)) -and ($rowPath -ne $expectedPath)) {
                    Add-Issue $issues ('EVIDENCE_APPLICATION_PATH_MISMATCH_' + $shortId)
                }
            }
        }

        $groupKey = Get-GroupKey $canonical
        if (-not $pathsByGroup.ContainsKey($groupKey)) { $pathsByGroup[$groupKey] = [Collections.Generic.HashSet[string]]::new() }
        if (-not [string]::IsNullOrWhiteSpace($expectedPath)) { $pathsByGroup[$groupKey].Add($expectedPath) | Out-Null }

        if ($traceValid -and [bool](Get-PropertyValue $canonical 'exported')) {
            $exportedJoined++
            $exportedTraces.Add([pscustomobject]@{ canonical = $canonical; trace = $trace; expected_path = $expectedPath }) | Out-Null
            $exportedGroupKeys.Add($groupKey) | Out-Null
            $exportedTraceRuleKeys.Add((Get-TraceRuleKey $trace (Get-Text $canonical 'rule_id'))) | Out-Null
        }

        $joinedRecords.Add([pscustomobject]@{
            chain_key = $chainKey
            short_id = $shortId
            canonical = $canonical
            trace = $trace
            trace_valid = $traceValid
            exported = [bool](Get-PropertyValue $canonical 'exported')
            evidence_rows = $evidenceRows.Count
            expected_path = $expectedPath
        }) | Out-Null
    }

    # Any canonical application trace must be backed by a typed JOINED decision.
    foreach ($canonical in $canonicalFindings) {
        $trace = Get-PropertyValue $canonical 'application_trace'
        if ($null -eq $trace) { continue }
        $key = Get-Text $canonical 'chain_key'
        if ($joinedKeys -notcontains $key) { Add-Issue $issues ('ORPHAN_CANONICAL_TRACE_' + (Get-ShortChainId $key)) }
    }

    foreach ($record in $joinedRecords | Where-Object { $_.trace_valid -and $_.exported }) {
        $canonical = $record.canonical
        $trace = $record.trace
        $groupKey = Get-GroupKey $canonical
        $groupPaths = if ($pathsByGroup.ContainsKey($groupKey)) { $pathsByGroup[$groupKey] } else { [Collections.Generic.HashSet[string]]::new() }
        $jsonCandidates = @()
        if ($jsonByTrace.ContainsKey($groupKey)) { $jsonCandidates = @($jsonByTrace[$groupKey]) }
        $jsonMatches = @($jsonCandidates | Where-Object {
            (Test-CoreEqual $canonical $_ $true) -and (Test-TraceEqual $trace $_) -and $groupPaths.Contains((Get-Text $_ 'application_path'))
        })
        if ($jsonMatches.Count -eq 0) { Add-Issue $issues ('FINDINGS_JSON_MISSING_' + $record.short_id) }

        $csvCandidates = @()
        if ($csvByTrace.ContainsKey($groupKey)) { $csvCandidates = @($csvByTrace[$groupKey]) }
        $csvMatches = @($csvCandidates | Where-Object {
            (Test-TraceEqual $trace $_) -and $groupPaths.Contains((Get-Text $_ 'application_path')) -and (Test-CoreEqual $canonical $_ $true)
        })
        if ($csvMatches.Count -eq 0) { Add-Issue $issues ('FINDINGS_CSV_MISSING_' + $record.short_id) }

        $sarifCandidates = @()
        $traceRuleKey = Get-TraceRuleKey $trace (Get-Text $canonical 'rule_id')
        if ($sarifByTrace.ContainsKey($traceRuleKey)) { $sarifCandidates = @($sarifByTrace[$traceRuleKey]) }
        $sarifMatches = @($sarifCandidates | Where-Object {
            ((Get-Text $_ 'ruleId') -eq (Get-Text $canonical 'rule_id')) -and (Test-TraceEqual $trace (Get-PropertyValue $_ 'properties')) -and $groupPaths.Contains((Get-Text (Get-PropertyValue $_ 'properties') 'application_path'))
        })
        if ($sarifMatches.Count -eq 0) { Add-Issue $issues ('SARIF_MISSING_' + $record.short_id) }
    }

    # Renderer rows carrying an application path must resolve to an exported canonical trace;
    # this catches both blank projections and cross-chain contamination.
    foreach ($row in $jsonRows) {
        if ([string]::IsNullOrWhiteSpace((Get-Text $row 'application_entry_class'))) { continue }
        $ok = $exportedGroupKeys.Contains((Get-GroupKey $row))
        if (-not $ok) { Add-Issue $issues 'ORPHAN_FINDINGS_JSON_APPLICATION_TRACE' }
    }
    foreach ($row in $findingsCsv) {
        if ([string]::IsNullOrWhiteSpace((Get-Text $row 'application_entry_class'))) { continue }
        $ok = $exportedGroupKeys.Contains((Get-GroupKey $row))
        if (-not $ok) { Add-Issue $issues 'ORPHAN_FINDINGS_CSV_APPLICATION_TRACE' }
    }
    foreach ($result in $sarifResults) {
        $properties = Get-PropertyValue $result 'properties'
        if ([string]::IsNullOrWhiteSpace((Get-Text $properties 'application_entry_class'))) { continue }
        $ok = $exportedTraceRuleKeys.Contains((Get-TraceRuleKey $properties (Get-Text $result 'ruleId')))
        if (-not $ok) { Add-Issue $issues 'ORPHAN_SARIF_APPLICATION_TRACE' }
    }

    $rendererCounts = [ordered]@{
        canonical_findings = $canonicalFindings.Count
        joined_decisions = $joinedKeys.Count
        evidence_chain_rows = $chainsCsv.Count
        findings_json_rows = $jsonRows.Count
        findings_csv_rows = $findingsCsv.Count
        sarif_results = $sarifResults.Count
    }
    $valid = $issues.Count -eq 0
    return [ordered]@{
        schema_version = $SchemaVersion
        contract_id = $ContractId
        valid = $valid
        status = if ($valid) { 'PASS' } else { 'FAIL' }
        report_root = $rootFull
        joined_count = $joinedKeys.Count
        exported_joined_count = $exportedJoined
        renderer_counts = $rendererCounts
        checks = [ordered]@{
            typed_joined_key_to_canonical_trace = ($issues -notcontains 'NO_JOINED_DECISIONS')
            joined_key_to_evidence_chain_row = (@($joinedRecords | Where-Object { $_.evidence_rows -gt 0 }).Count -eq $joinedKeys.Count)
            exported_joined_key_to_json = (@($issues | Where-Object { $_ -like 'FINDINGS_JSON_MISSING_*' }).Count -eq 0)
            exported_joined_key_to_csv = (@($issues | Where-Object { $_ -like 'FINDINGS_CSV_MISSING_*' }).Count -eq 0)
            exported_joined_key_to_sarif = (@($issues | Where-Object { $_ -like 'SARIF_MISSING_*' }).Count -eq 0)
            no_orphan_application_projection = (@($issues | Where-Object { $_ -like 'ORPHAN_*APPLICATION_TRACE*' }).Count -eq 0)
        }
        failures = @($issues.ToArray())
    }
}

function Invoke-SelfTest {
    $key = 'JUST-SELFTEST|COMMAND_EXEC|HIGH|deserialize|app/Entry|run|java/lang/ProcessBuilder|start|()Ljava/lang/Process;|TERMINAL|CONTROLLED_EFFECT||app/Entry|run|app/Entry|run|ENTRY|<null>|()V|<null>|<null>|'
    $trace = [ordered]@{
        application_entry_class = 'app/Api'
        application_entry_method = 'handle()V'
        application_site_class = 'app/Api'
        application_site_method = 'handle()V'
        application_site_kind = 'BINDING_SITE'
        join_kind = 'TYPED_BINDING_TARGET'
        chain_entry_method = 'app/Entry#run()V'
        entry_prefix_path = 'app/Api#handle()V'
        application_path = 'app/Api#handle()V -> app/Entry.run'
    }
    if ((Get-ShortChainId $key).Length -ne 8) { throw 'SELFTEST_SHORT_ID' }
    $issues = [Collections.Generic.List[string]]::new()
    if (-not (Test-TraceComplete $trace 'SELFTEST_' $issues) -or $issues.Count -ne 0) { throw 'SELFTEST_TRACE_COMPLETE' }
    if (-not (Test-TraceEqual $trace $trace)) { throw 'SELFTEST_TRACE_EQUAL' }
    $bad = [ordered]@{} + $trace
    $bad.chain_entry_method = 'wrong'
    if (Test-TraceEqual $trace $bad) { throw 'SELFTEST_TRACE_MISMATCH' }
    return [ordered]@{ status = 'PASS'; tests = @('stable-short-id', 'typed-trace-fields', 'mismatch-rejected') }
}

try {
    if ($SelfTest) {
        $result = Invoke-SelfTest
        if ($Json) { $result | ConvertTo-Json -Depth 10 } else { Write-Output ('REPORT_PATH_VALIDATOR_SELF_TEST=' + $result.status); Write-Output ('tests=' + ($result.tests -join ',')) }
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($ReportRoot)) { throw 'REPORT_ROOT_REQUIRED' }
    $result = Test-ReportRoot $ReportRoot
    if ($Json) { $result | ConvertTo-Json -Depth 20 } else {
        Write-Output ('REPORT_PATH_CONTRACT_VALID=' + $result.valid)
        Write-Output ('joined=' + $result.joined_count + ';exported_joined=' + $result.exported_joined_count)
        Write-Output ('failures=' + (@($result.failures) -join ','))
    }
    if (-not $result.valid) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('REPORT_PATH_VALIDATOR_ERROR: ' + $_.Exception.Message + ':' + $_.ScriptStackTrace))
    exit 2
}
