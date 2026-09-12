[CmdletBinding()]
param(
    [string] $SummaryPath,
    [string] $SchemaPath,
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedContractId = 'JUST-PROD-D009-V1'
$SchemaPath = if ([string]::IsNullOrWhiteSpace($SchemaPath)) { Join-Path $PSScriptRoot 'acceptance-summary-v2.schema.json' } else { [IO.Path]::GetFullPath($SchemaPath) }
$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$FixedGateIds = @(
    'PLAN_INTEGRITY', 'BUILD_REPRODUCIBLE', 'FAST_TESTS', 'ARCHITECTURE',
    'ENTRY_ANCHOR_POLICY', 'GLEIPNER_KERNEL', 'WP8_STATIC', 'WP8_DYNAMIC',
    'DYNAMIC_TRIAGE', 'APACHE_APPLICATION_CHAIN', 'WINDOWS_CONTAINMENT',
    'JDK_MATRIX', 'PERFORMANCE', 'DETERMINISM', 'HOSTILE_INPUT_SAFETY',
    'CLI_OFFLINE_CONTRACT', 'OUTPUT_AND_BASELINE', 'ROBUSTNESS_SOAK',
    'USABILITY', 'RELEASE_SUPPLY_CHAIN', 'DOCS_RELEASE'
)

function Get-JsonIfPresent {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Get-StringValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [string] $Default = '')
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name) -or $null -eq $Object[$Name]) { return $Default }
        return [string]$Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return [string]$property.Value
}

function Get-BooleanValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [bool] $Default = $false)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name) -or $null -eq $Object[$Name]) { return $Default }
        return [bool]$Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return [bool]$property.Value
}

function Get-RelativeOrAbsolutePath {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base)
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $Base $Value))
}

function Get-AggregateStatus {
    param([Parameter(Mandatory = $true)] [object[]] $Gates)
    if (@($Gates | Where-Object { $_.status -eq 'FAIL' }).Length -gt 0) { return 'FAIL' }
    if (@($Gates | Where-Object { $_.status -eq 'INCOMPARABLE' }).Length -gt 0) { return 'INCOMPARABLE' }
    if (@($Gates | Where-Object { $_.status -eq 'NOT_RUN' }).Length -gt 0) { return 'NOT_RUN' }
    return 'PASS'
}

function Test-Summary {
    param([AllowNull()] $Document, [string] $BasePath)
    $issues = [Collections.Generic.List[string]]::new()
    if ($null -eq $Document) { $issues.Add('SUMMARY_JSON_INVALID') | Out-Null; return [ordered]@{ valid = $false; issues = @($issues.ToArray()) } }
    if ([int]$Document.schema_version -ne 2) { $issues.Add('SCHEMA_VERSION') | Out-Null }
    if ((Get-StringValue $Document 'contract_id' '') -ne $ExpectedContractId) { $issues.Add('CONTRACT_ID') | Out-Null }
    if ((Get-StringValue $Document 'kind' '') -ne 'acceptance-summary') { $issues.Add('KIND') | Out-Null }
    if (@('smoke', 'phase', 'release') -notcontains (Get-StringValue $Document 'profile' '')) { $issues.Add('PROFILE') | Out-Null }
    if (@('PASS', 'FAIL', 'NOT_RUN', 'INCOMPARABLE') -notcontains (Get-StringValue $Document 'status' '')) { $issues.Add('STATUS') | Out-Null }
    if ($null -eq $Document.plan -or [string]::IsNullOrWhiteSpace((Get-StringValue $Document.plan 'path' ''))) { $issues.Add('PLAN_BLOCK') | Out-Null }
    $gates = @($Document.gates)
    if ($gates.Length -ne $FixedGateIds.Length) { $issues.Add('FIXED_GATE_COUNT') | Out-Null }
    $ids = @($gates | ForEach-Object { Get-StringValue $_ 'id' '' })
    if (@($ids | Sort-Object -Unique).Length -ne $FixedGateIds.Length) { $issues.Add('DUPLICATE_GATE_ID') | Out-Null }
    for ($i = 0; $i -lt [Math]::Min($gates.Length, $FixedGateIds.Length); $i++) { if ($ids[$i] -ne $FixedGateIds[$i]) { $issues.Add('GATE_ORDER_OR_ID_' + $i) | Out-Null } }
    foreach ($gate in $gates) {
        if (@('PASS', 'FAIL', 'NOT_RUN', 'INCOMPARABLE') -notcontains (Get-StringValue $gate 'status' '')) { $issues.Add('GATE_STATUS') | Out-Null }
        if ([string]::IsNullOrWhiteSpace((Get-StringValue $gate 'reason_code' ''))) { $issues.Add('GATE_REASON') | Out-Null }
        if (@($gate.evidence).Length -lt 1) { $issues.Add('GATE_EVIDENCE') | Out-Null }
        foreach ($evidence in @($gate.evidence)) {
            $path = Get-RelativeOrAbsolutePath ([string]$evidence) $BasePath
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $issues.Add('MISSING_EVIDENCE_' + (Get-StringValue $gate 'id' 'UNKNOWN')) | Out-Null }
        }
    }
    if ($null -eq $Document.summary) { $issues.Add('SUMMARY_BLOCK') | Out-Null } else {
        $expected = Get-AggregateStatus $gates
        if ((Get-StringValue $Document.summary 'status' '') -ne $expected) { $issues.Add('SUMMARY_STATUS') | Out-Null }
        if ((Get-StringValue $Document 'status' '') -ne $expected) { $issues.Add('ROOT_STATUS') | Out-Null }
        if ([int]$Document.summary.gate_count -ne $gates.Length) { $issues.Add('SUMMARY_GATE_COUNT') | Out-Null }
        $pass = @($gates | Where-Object { $_.status -eq 'PASS' }).Length
        $fail = @($gates | Where-Object { $_.status -eq 'FAIL' }).Length
        $notRun = @($gates | Where-Object { $_.status -eq 'NOT_RUN' }).Length
        $incomp = @($gates | Where-Object { $_.status -eq 'INCOMPARABLE' }).Length
        if ([int]$Document.summary.pass_count -ne $pass -or [int]$Document.summary.fail_count -ne $fail -or [int]$Document.summary.not_run_count -ne $notRun -or [int]$Document.summary.incomparable_count -ne $incomp) { $issues.Add('SUMMARY_COUNTS') | Out-Null }
    }
    if ($null -eq $Document.safety) {
        $issues.Add('SAFETY_BLOCK') | Out-Null
    } else {
        $mode = Get-StringValue $Document.safety 'verification_mode' ''
        $possible = Get-BooleanValue $Document.safety 'target_code_execution_possible' $false
        $executed = Get-StringValue $Document.safety 'target_code_executed' ''
        $trust = Get-StringValue $Document.safety 'target_trust' ''
        if (@('AUTO', 'STATIC_ONLY') -notcontains $mode) { $issues.Add('SAFETY_MODE') | Out-Null }
        if (@('TRUSTED_LOCAL_TARGET_REQUIRED', 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH') -notcontains $trust) { $issues.Add('SAFETY_TARGET_TRUST') | Out-Null }
        if (-not (Get-BooleanValue $Document.safety 'resource_containment_only' $false)) { $issues.Add('SAFETY_CONTAINMENT_OVERCLAIM') | Out-Null }
        if (Get-BooleanValue $Document.safety 'filesystem_isolation' $true) { $issues.Add('SAFETY_FILESYSTEM_ISOLATION_OVERCLAIM') | Out-Null }
        if (Get-BooleanValue $Document.safety 'network_isolation' $true) { $issues.Add('SAFETY_NETWORK_ISOLATION_OVERCLAIM') | Out-Null }
        if (-not (Get-BooleanValue $Document.safety 'fail_closed_on_isolation_failure' $false)) { $issues.Add('SAFETY_FAIL_OPEN') | Out-Null }
        if ($mode -eq 'AUTO' -and -not $possible) { $issues.Add('SAFETY_AUTO_POSSIBILITY') | Out-Null }
        if ($mode -eq 'STATIC_ONLY' -and $possible) { $issues.Add('SAFETY_STATIC_POSSIBILITY') | Out-Null }
        # Possibility and observation are independent axes: AUTO may permit target loading while
        # an isolation failure or an empty plan correctly records NO. Reject only the impossible
        # positive claim and malformed/empty observations.
        if ([string]::IsNullOrWhiteSpace($executed) -or (-not $possible -and $executed -eq 'YES')) {
            $issues.Add('SAFETY_EXECUTION_CLAIM') | Out-Null
        }
    }
    if ($null -ne $Document.safety -and $null -ne $Document.safety.job_object) {
        if (Get-BooleanValue $Document.safety.job_object 'complete_sandbox' $true) { $issues.Add('JOB_OBJECT_OVERCLAIM') | Out-Null }
        if ((Get-StringValue $Document.safety.job_object 'capability' '') -ne 'RESOURCE_CONTAINMENT_ONLY') { $issues.Add('JOB_OBJECT_CAPABILITY') | Out-Null }
        if (-not (Get-BooleanValue $Document.safety.job_object 'fail_closed_required' $false)) { $issues.Add('JOB_OBJECT_FAIL_OPEN') | Out-Null }
    }
    return [ordered]@{ valid = ($issues.Count -eq 0); issues = @($issues.ToArray()); contract_id = $ExpectedContractId; fixed_gate_count = $FixedGateIds.Length }
}

function Invoke-SelfTest {
    $temp = Join-Path ([IO.Path]::GetTempPath()) ('just-acceptance-validator-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $temp 'evidence') -Force | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $temp 'evidence\one.json') -Value '{}' -Encoding UTF8
        $gates = [Collections.Generic.List[object]]::new()
        foreach ($id in $FixedGateIds) { $gates.Add([ordered]@{ id = $id; required = $true; status = 'PASS'; reason_code = 'SELFTEST'; evidence = @('evidence/one.json'); commands = @() }) | Out-Null }
        $doc = [ordered]@{ schema_version = 2; contract_id = $ExpectedContractId; kind = 'acceptance-summary'; profile = 'smoke'; status = 'PASS'; started_at = 'x'; finished_at = 'x'; plan = [ordered]@{ status = 'PASS'; path = 'evidence/one.json'; contract_id = $ExpectedContractId; state = 'COMPLETE'; next_item = 'COMPLETE'; evidence = @('evidence/one.json') }; gates = @($gates.ToArray()); summary = [ordered]@{ status = 'PASS'; gate_count = 21; required_count = 21; pass_count = 21; fail_count = 0; not_run_count = 0; incomparable_count = 0; required_failures = @(); required_not_run = @(); required_incomparable = @() }; tooling = [ordered]@{}; safety = [ordered]@{ verification_mode = 'STATIC_ONLY'; target_code_execution_possible = $false; target_code_executed = 'NO'; resource_containment_only = $true; filesystem_isolation = $false; network_isolation = $false; recommended_for_untrusted_artifacts = $true; target_trust = 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH'; fail_closed_on_isolation_failure = $true; dangerous_sink = 'NOT_INVOKED'; network = 'NOT_REQUESTED'; file_write = 'NONE'; job_object = [ordered]@{ capability = 'RESOURCE_CONTAINMENT_ONLY'; complete_sandbox = $false; fail_closed_required = $true } } }
        $valid = Test-Summary $doc $temp
        if (-not $valid.valid) { throw ('SELFTEST_VALID_SUMMARY:' + (@($valid.issues) -join ',')) }
        $gates[1].id = $gates[0].id
        $invalid = Test-Summary $doc $temp
        if ($invalid.valid -or @($invalid.issues | Where-Object { $_ -eq 'DUPLICATE_GATE_ID' }).Length -eq 0) { throw 'SELFTEST_DUPLICATE_GATE' }
        $gates[1].id = $FixedGateIds[1]
        $doc.safety.target_code_execution_possible = $false
        $doc.safety.target_code_executed = 'YES'
        $unsafe = Test-Summary $doc $temp
        if ($unsafe.valid -or @($unsafe.issues | Where-Object { $_ -eq 'SAFETY_EXECUTION_CLAIM' }).Length -eq 0) { throw 'SELFTEST_SAFETY_CLAIM' }
        return [ordered]@{ status = 'PASS'; tests = @('schema-contract', 'valid-summary', 'duplicate-gate-rejected', 'safety-claim-rejected') }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force } }
}

try {
    if ($SelfTest) {
        $self = Invoke-SelfTest
        if ($Json) { $self | ConvertTo-Json -Depth 20 } else { Write-Output ('ACCEPTANCE_SUMMARY_VALIDATOR_SELF_TEST=' + $self.status); Write-Output ('tests=' + ($self.tests -join ',')) }
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($SummaryPath)) { throw 'SUMMARY_REQUIRED' }
    $full = if ([IO.Path]::IsPathRooted($SummaryPath)) { [IO.Path]::GetFullPath($SummaryPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $SummaryPath)) }
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'SUMMARY_SCHEMA_MISSING' }
    $schema = Get-JsonIfPresent $SchemaPath
    if ($null -eq $schema -or [int]$schema.properties.schema_version.const -ne 2 -or (Get-StringValue $schema.properties.contract_id 'const' '') -ne $ExpectedContractId) { throw 'SUMMARY_SCHEMA_CONTRACT_INVALID' }
    $result = Test-Summary (Get-JsonIfPresent $full) $RepositoryRoot
    if ($Json) { $result | ConvertTo-Json -Depth 20 } else { Write-Output ('ACCEPTANCE_SUMMARY_VALID=' + $result.valid); Write-Output ('issues=' + (@($result.issues) -join ',')) }
    if (-not $result.valid) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('ACCEPTANCE_SUMMARY_VALIDATOR_ERROR: ' + $_.Exception.Message))
    exit 2
}
