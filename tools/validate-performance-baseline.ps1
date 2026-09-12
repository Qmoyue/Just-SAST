[CmdletBinding()]
param(
    [string] $BaselinePath,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedContractId = 'JUST-PROD-D009-V1'
$Hex64 = '^[0-9a-f]{64}$'

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    if ($null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-StringValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [string] $Default = '')
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Add-Issue {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $Issues, [Parameter(Mandatory = $true)] [string] $Message)
    $Issues.Add($Message) | Out-Null
}

function Assert-Baseline {
    param([Parameter(Mandatory = $true)] $Baseline)
    $issues = [System.Collections.Generic.List[string]]::new()
    if ([int](Get-PropertyValue $Baseline 'schema_version') -ne 2) { Add-Issue $issues 'schema_version must be 2' }
    if ((Get-StringValue $Baseline 'contract_id' '') -ne $ExpectedContractId) { Add-Issue $issues 'contract_id mismatch' }
    if ((Get-StringValue $Baseline 'kind' '') -ne 'performance-baseline') { Add-Issue $issues 'kind must be performance-baseline' }
    if ((Get-StringValue $Baseline 'status' '') -notin @('OBSERVED', 'NOT_RUN', 'FAILED')) { Add-Issue $issues 'invalid baseline status' }
    foreach ($field in @('comparison_fingerprint', 'semantic_digest')) {
        $value = Get-StringValue $Baseline $field ''
        if ($value -notmatch $Hex64 -and $value -ne 'UNKNOWN') { Add-Issue $issues "$field must be a lowercase SHA-256 or UNKNOWN" }
    }
    $machine = Get-PropertyValue $Baseline 'reference_machine'
    if ($null -eq $machine) { Add-Issue $issues 'reference_machine is required' } else {
        if ([string]::IsNullOrWhiteSpace((Get-StringValue $machine 'fingerprint' ''))) { Add-Issue $issues 'reference_machine.fingerprint is required' }
        $memory = [long](Get-PropertyValue $machine 'memory_total_mb')
        $memoryStatus = Get-StringValue $machine 'memory_status' ''
        if ($memory -lt -1) { Add-Issue $issues 'memory_total_mb must be -1 or non-negative' }
        if ([string]::IsNullOrWhiteSpace($memoryStatus)) { Add-Issue $issues 'memory_status is required' }
    }
    $schedule = Get-PropertyValue $Baseline 'schedule'
    if ($null -eq $schedule) { Add-Issue $issues 'schedule is required' } else {
        $tier = Get-StringValue $Baseline 'tier' ''
        $modes = @((Get-PropertyValue $schedule 'modes')) | ForEach-Object { [string]$_ }
        if ($tier -eq 'SMOKE' -and ((Get-PropertyValue $schedule 'cold_runs') -ne 1 -or (Get-PropertyValue $schedule 'warm_runs') -ne 3)) { Add-Issue $issues 'SMOKE schedule must be 1 cold + 3 warm' }
        if ($tier -eq 'PHASE' -and ((Get-PropertyValue $schedule 'cold_runs') -ne 1 -or (Get-PropertyValue $schedule 'warm_runs') -ne 5)) { Add-Issue $issues 'PHASE schedule must be 1 cold + 5 warm' }
        if ($tier -eq 'RELEASE' -and ((Get-PropertyValue $schedule 'representative_cold_runs') -ne 5 -or (Get-PropertyValue $schedule 'representative_warm_runs') -ne 20)) { Add-Issue $issues 'RELEASE representative schedule must be 5 cold + 20 warm' }
        if ($tier -eq 'MICRO' -and ($modes -notcontains 'micro')) { Add-Issue $issues 'MICRO schedule must use micro mode' }
    }
    $records = @((Get-PropertyValue $Baseline 'records'))
    foreach ($record in $records) {
        $recordStatus = Get-StringValue $record 'status' ''
        if ($recordStatus -notin @('OBSERVED', 'NOT_RUN', 'FAILED', 'SEMANTIC_MISMATCH')) { Add-Issue $issues "invalid record status: $(Get-StringValue $record 'id' 'UNKNOWN')/$(Get-StringValue $record 'mode' 'UNKNOWN')" }
        $samples = @((Get-PropertyValue $record 'samples'))
        $semantic = Get-PropertyValue $record 'semantic'
        if ($recordStatus -eq 'OBSERVED') {
            if ($samples.Count -le 0) { Add-Issue $issues "OBSERVED record has no samples: $(Get-StringValue $record 'id' 'UNKNOWN')" }
            if ($null -eq $semantic -or -not [bool](Get-PropertyValue $semantic 'stable')) { Add-Issue $issues "OBSERVED record semantic stability missing: $(Get-StringValue $record 'id' 'UNKNOWN')" }
            $digests = @($samples | ForEach-Object { Get-StringValue $_ 'result_digest' 'UNKNOWN' } | Sort-Object -Unique)
            if ($digests.Count -ne 1 -or $digests[0] -eq 'UNKNOWN') { Add-Issue $issues "record result digest is not stable: $(Get-StringValue $record 'id' 'UNKNOWN')" }
        }
        $execution = Get-PropertyValue $record 'execution'; $tree = Get-PropertyValue $execution 'process_tree'; $treeStatus = Get-StringValue $tree 'status' ''
        if ($treeStatus -eq 'SAMPLED' -and [long](Get-PropertyValue $tree 'sample_count') -le 0) { Add-Issue $issues "SAMPLED tree has no samples: $(Get-StringValue $record 'id' 'UNKNOWN')" }
        if ($treeStatus -eq 'NOT_SAMPLED' -and [string]::IsNullOrWhiteSpace((Get-StringValue $tree 'reason_code' ''))) { Add-Issue $issues "NOT_SAMPLED tree needs reason: $(Get-StringValue $record 'id' 'UNKNOWN')" }
        $dynamic = Get-PropertyValue $record 'dynamic'
        if ($null -eq $dynamic) { Add-Issue $issues "dynamic safety contract missing: $(Get-StringValue $record 'id' 'UNKNOWN')" } else {
            if ([bool](Get-PropertyValue $dynamic 'target_code_execution_possible') -and (Get-StringValue $dynamic 'target_code_executed' '') -eq 'NO') { Add-Issue $issues "target execution cannot be NO when possible: $(Get-StringValue $record 'id' 'UNKNOWN')" }
            $job = Get-PropertyValue $dynamic 'job_object'
            if ($null -eq $job -or [bool](Get-PropertyValue $job 'complete_sandbox')) { Add-Issue $issues "Job Object must not be advertised as complete sandbox: $(Get-StringValue $record 'id' 'UNKNOWN')" }
        }
    }
    foreach ($case in @((Get-PropertyValue $Baseline 'cases'))) {
        $summary = Get-PropertyValue $case 'summary'; $count = [int](Get-PropertyValue $summary 'sample_count'); $eligible = [bool](Get-PropertyValue $summary 'p95_eligible'); $p95 = Get-PropertyValue $summary 'wall_p95_ms'
        if ($count -lt 20 -and ($eligible -or $null -ne $p95)) { Add-Issue $issues "p95 must be absent below 20 samples: $(Get-StringValue $case 'id' 'UNKNOWN')/$(Get-StringValue $case 'mode' 'UNKNOWN')" }
        if ($count -ge 20 -and (-not $eligible -or $null -eq $p95)) { Add-Issue $issues "p95 must be present at 20+ samples: $(Get-StringValue $case 'id' 'UNKNOWN')/$(Get-StringValue $case 'mode' 'UNKNOWN')" }
    }
    $slo = Get-PropertyValue $Baseline 'slo'
    if ($null -eq $slo) { Add-Issue $issues 'slo is required' } elseif ((Get-StringValue $slo 'status' '') -notin @('PASS', 'FAIL', 'NOT_APPLICABLE', 'NOT_RUN')) { Add-Issue $issues 'invalid slo status' }
    return $issues
}

function Invoke-SelfTest {
    $valid = [pscustomobject]@{ schema_version = 2; contract_id = $ExpectedContractId; kind = 'performance-baseline'; status = 'OBSERVED'; comparison_fingerprint = ('a' * 64); semantic_digest = ('b' * 64); reference_machine = [pscustomobject]@{ fingerprint = 'm'; memory_total_mb = -1; memory_status = 'UNKNOWN' }; tier = 'SMOKE'; schedule = [pscustomobject]@{ modes = @('cold', 'hot'); cold_runs = 1; warm_runs = 3 }; records = @(); cases = @(); slo = [pscustomobject]@{ status = 'FAIL' } }
    if (@(Assert-Baseline $valid).Count -ne 0) { throw 'PERFORMANCE_BASELINE_VALID_FIXTURE_FAILED' }
    $invalid = [pscustomobject]@{ schema_version = 2; contract_id = $ExpectedContractId; kind = 'performance-baseline'; status = 'OBSERVED'; comparison_fingerprint = ('a' * 64); semantic_digest = ('b' * 64); reference_machine = $valid.reference_machine; tier = 'SMOKE'; schedule = $valid.schedule; records = @(); cases = @([pscustomobject]@{ id = 'x'; mode = 'hot'; summary = [pscustomobject]@{ sample_count = 3; p95_eligible = $true; wall_p95_ms = 10 } }); slo = [pscustomobject]@{ status = 'FAIL' } }
    if (@(Assert-Baseline $invalid).Count -eq 0) { throw 'PERFORMANCE_BASELINE_P95_RULE_NOT_ENFORCED' }
    return @('schema', 'reference-machine', 'schedule', 'p95-sample-floor', 'safety')
}

try {
    if ($SelfTest) { Write-Output 'PERFORMANCE_BASELINE_VALIDATOR_SELF_TEST=PASS'; Write-Output ('tests=' + ((Invoke-SelfTest) -join ',')); exit 0 }
    if ([string]::IsNullOrWhiteSpace($BaselinePath)) { throw 'BASELINE_REQUIRED' }
    $path = [IO.Path]::GetFullPath($BaselinePath)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "BASELINE_MISSING: $path" }
    $baseline = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $issues = @(Assert-Baseline $baseline)
    if ($issues.Count -gt 0) { Write-Output ('PERFORMANCE_BASELINE_INVALID=' + ($issues -join '|')); exit 1 }
    Write-Output 'PERFORMANCE_BASELINE_VALID=PASS'; exit 0
} catch {
    [Console]::Error.WriteLine(('PERFORMANCE_BASELINE_VALIDATOR_ERROR: ' + $_.Exception.Message)); exit 2
}
