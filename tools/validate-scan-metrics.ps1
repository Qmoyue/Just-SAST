[CmdletBinding()]
param(
    [string] $MetadataPath,
    [string] $RunManifestPath,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ClosedStatuses = @('OBSERVED', 'CANDIDATE_ONLY', 'UNKNOWN', 'NOT_APPLICABLE', 'NOT_REQUESTED')
$RequiredMetricNames = @(
    'application_entry_candidates', 'application_entry_sites_candidates', 'application_sites',
    'candidate_joins', 'validated_joins', 'joined_dependency_segments',
    'complete_anchored_chains', 'anchored_candidates', 'unresolved_bridges',
    'avoided_states', 'materialized_states', 'dag_nodes', 'dag_edges',
    'representative_paths', 'kernel_only_results', 'chain_candidate_count',
    'chain_structurally_complete_count', 'chain_unresolved_count', 'chain_terminal_count',
    'chain_hop_total', 'chain_hop_max', 'chain_bridge_hop_count', 'chain_note_count',
    'pass_frontend_time_ms', 'pass_frontend_rss_peak_mb', 'pass_frontend_cache_hits',
    'pass_cpg_time_ms', 'pass_cpg_rss_peak_mb', 'pass_cpg_cache_hits',
    'pass_analysis_time_ms', 'pass_analysis_rss_peak_mb', 'pass_analysis_cache_hits',
    'pass_calibration_time_ms', 'pass_calibration_rss_peak_mb', 'pass_calibration_cache_hits',
    'pass_composition_time_ms', 'pass_composition_rss_peak_mb', 'pass_composition_cache_hits',
    'pass_verification_time_ms', 'pass_verification_rss_peak_mb', 'pass_verification_cache_hits',
    'pass_report_time_ms', 'pass_report_rss_peak_mb', 'pass_report_cache_hits'
)
$RequiredNamespaces = @('analysis', 'application', 'kernel')

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
        return $Object[$Name]
    }
    if ($null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Add-Issue {
    param([Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]] $Issues,
          [Parameter(Mandatory = $true)] [string] $Message)
    $Issues.Add($Message) | Out-Null
}

function Get-Properties {
    param([AllowNull()] $Object)
    if ($null -eq $Object) { return @() }
    if ($Object -is [System.Collections.IDictionary]) {
        return @($Object.Keys | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_; Value = $Object[$_] }
            })
    }
    return @($Object.PSObject.Properties)
}

function Assert-MetricMetadata {
    param([Parameter(Mandatory = $true)] $Metadata)
    $issues = [System.Collections.Generic.List[string]]::new()
    if ([int](Get-PropertyValue $Metadata 'schema_version') -ne 1) {
        Add-Issue $issues 'schema_version must be 1'
    }
    $metrics = Get-PropertyValue $Metadata 'metrics'
    $statuses = Get-PropertyValue $Metadata 'metric_status'
    $namespaces = Get-PropertyValue $Metadata 'metric_namespaces'
    $namespaceStatuses = Get-PropertyValue $Metadata 'metric_namespace_status'
    if ($null -eq $metrics -or $null -eq $statuses) {
        Add-Issue $issues 'metrics and metric_status are required'
    } else {
        foreach ($name in $RequiredMetricNames) {
            $value = Get-PropertyValue $metrics $name
            $status = [string](Get-PropertyValue $statuses $name)
            if ($null -eq $value) { Add-Issue $issues "missing metric: $name"; continue }
            if ([string]::IsNullOrWhiteSpace($status)) { Add-Issue $issues "missing metric status: $name"; continue }
            $status = $status.ToUpperInvariant()
            if ($ClosedStatuses -notcontains $status) { Add-Issue $issues "open metric status: $name=$status" }
            $number = 0L
            if (-not [long]::TryParse([string]$value, [ref]$number)) {
                Add-Issue $issues "metric is not integer: $name"
            } elseif ($status -eq 'UNKNOWN' -and $number -ne -1L) {
                Add-Issue $issues "UNKNOWN metric must be -1: $name=$number"
            } elseif ($status -eq 'NOT_REQUESTED' -and $number -ne -1L) {
                Add-Issue $issues "NOT_REQUESTED metric must be -1: $name=$number"
            } elseif ($status -eq 'OBSERVED' -and $number -lt 0L) {
                Add-Issue $issues "OBSERVED metric cannot be negative: $name=$number"
            }
        }
    }
    if ($null -eq $namespaces -or $null -eq $namespaceStatuses) {
        Add-Issue $issues 'metric_namespaces and metric_namespace_status are required'
    } else {
        foreach ($namespace in $RequiredNamespaces) {
            $values = Get-PropertyValue $namespaces $namespace
            $status = [string](Get-PropertyValue $namespaceStatuses $namespace)
            if ($null -eq $values) { Add-Issue $issues "missing namespace: $namespace"; continue }
            if ([string]::IsNullOrWhiteSpace($status)) { Add-Issue $issues "missing namespace status: $namespace"; continue }
            $status = $status.ToUpperInvariant()
            if ($ClosedStatuses -notcontains $status) { Add-Issue $issues "open namespace status: $namespace=$status" }
            foreach ($metric in Get-Properties $values) {
                $number = 0L
                if (-not [long]::TryParse([string]$metric.Value, [ref]$number)) {
                    Add-Issue $issues "namespace metric is not integer: $namespace.$($metric.Name)"
                } elseif (($status -eq 'UNKNOWN' -or $status -eq 'NOT_REQUESTED') -and $number -ne -1L) {
                    Add-Issue $issues "unknown namespace must use -1: $namespace.$($metric.Name)=$number"
                }
            }
        }
    }
    return $issues
}

function Assert-RunManifest {
    param([Parameter(Mandatory = $true)] $Run)
    $issues = [System.Collections.Generic.List[string]]::new()
    $cases = Get-PropertyValue $Run 'cases'
    if ($null -eq $cases) { Add-Issue $issues 'run manifest cases are required'; return $issues }
    foreach ($case in @($cases)) {
        $resources = Get-PropertyValue $case 'resources'
        $tree = Get-PropertyValue $resources 'process_tree'
        if ($null -eq $tree) {
            Add-Issue $issues "missing process_tree: $(Get-PropertyValue $case 'id')"
        } else {
            $status = [string](Get-PropertyValue $tree 'status')
            if ([string]::IsNullOrWhiteSpace($status)) { Add-Issue $issues 'process_tree status is empty' }
            if ($status -eq 'SAMPLED' -and [long](Get-PropertyValue $tree 'sample_count') -le 0) {
                Add-Issue $issues 'SAMPLED process_tree must have sample_count > 0'
            }
        }
        $semantic = Get-PropertyValue $case 'semantic'
        if ($null -ne $semantic) {
            $metricIssues = Assert-MetricMetadata ([pscustomobject]@{
                    schema_version = 1
                    metrics = Get-PropertyValue $semantic 'metrics'
                    metric_status = Get-PropertyValue $semantic 'metric_status'
                    metric_namespaces = Get-PropertyValue $semantic 'metric_namespaces'
                    metric_namespace_status = Get-PropertyValue $semantic 'metric_namespace_status'
                })
            foreach ($issue in $metricIssues) { Add-Issue $issues "case $(Get-PropertyValue $case 'id'): $issue" }
        }
    }
    return $issues
}

function Invoke-SelfTest {
    $base = [ordered]@{
        schema_version = 1
        metrics = [ordered]@{}
        metric_status = [ordered]@{}
        metric_namespaces = [ordered]@{
            analysis = [ordered]@{ raw_chain_candidates = 0; structurally_complete_chains = 0; unresolved_chain_candidates = 0; materialized_states = -1; avoided_states = -1; dag_nodes = -1; dag_edges = -1; representative_paths = -1 }
            application = [ordered]@{ entries = 0; sites = -1; candidate_joins = -1; validated_joins = -1; joined_dependency_segments = -1; complete_anchored_chains = -1; anchored_candidates = -1; unresolved_bridges = -1 }
            kernel = [ordered]@{ kernel_only_results = -1 }
        }
        metric_namespace_status = [ordered]@{ analysis = 'OBSERVED'; application = 'CANDIDATE_ONLY'; kernel = 'NOT_REQUESTED' }
    }
    foreach ($name in $RequiredMetricNames) {
        $base.metrics[$name] = if ($name -eq 'kernel_only_results' -or $name -match 'rss_peak') { -1 } elseif ($name -match 'application_entry') { 0 } elseif ($name -match 'candidate|anchored|joined|bridge|state|dag|path|site') { -1 } else { 0 }
        $base.metric_status[$name] = if ($name -eq 'kernel_only_results') { 'NOT_REQUESTED' } elseif ($name -match 'rss_peak') { 'UNKNOWN' } elseif ($name -match 'application_entry') { 'CANDIDATE_ONLY' } elseif ($name -match 'candidate|anchored|joined|bridge|state|dag|path|site') { 'UNKNOWN' } else { 'OBSERVED' }
    }
    $valid = @(Assert-MetricMetadata ([pscustomobject]$base))
    if ($valid.Count -ne 0) { throw ('SELFTEST_VALID_FIXTURE_FAILED: ' + ($valid -join '; ')) }
    $base.metrics['candidate_joins'] = 0
    $invalid = @(Assert-MetricMetadata ([pscustomobject]$base))
    if ($invalid.Count -eq 0) { throw 'SELFTEST_UNKNOWN_ZERO_NOT_REJECTED' }
    return [pscustomobject]@{ status = 'PASS'; tests = @('required-fields', 'closed-statuses', 'unknown-is-minus-one', 'namespace-separation') }
}

try {
    if ($SelfTest) {
        $result = Invoke-SelfTest
        Write-Output 'SCAN_METRICS_VALIDATOR_SELF_TEST=PASS'
        Write-Output ('tests=' + ($result.tests -join ','))
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($MetadataPath) -and [string]::IsNullOrWhiteSpace($RunManifestPath)) {
        throw 'METADATA_OR_RUN_MANIFEST_REQUIRED'
    }
    $allIssues = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($MetadataPath)) {
        $path = [IO.Path]::GetFullPath($MetadataPath)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "METADATA_MISSING: $path" }
        $metadata = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($issue in (Assert-MetricMetadata $metadata)) { Add-Issue $allIssues $issue }
    }
    if (-not [string]::IsNullOrWhiteSpace($RunManifestPath)) {
        $path = [IO.Path]::GetFullPath($RunManifestPath)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "RUN_MANIFEST_MISSING: $path" }
        $run = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($issue in (Assert-RunManifest $run)) { Add-Issue $allIssues $issue }
    }
    if ($allIssues.Count -gt 0) {
        Write-Output ('SCAN_METRICS_INVALID=' + ($allIssues -join '|'))
        exit 1
    }
    Write-Output 'SCAN_METRICS_VALID=PASS'
    exit 0
} catch {
    [Console]::Error.WriteLine(('SCAN_METRICS_VALIDATOR_ERROR: ' + $_.Exception.Message))
    exit 2
}
