[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $ReportDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allowedRootEntries = @('evidence', 'meta', 'report.json', 'report.md')
$forbiddenReportTerms = '(?i)"(?:target_code_executed|dynamic_verification|verificationMode|verification_mode|generated_bytes|payload_bytes|RCE_CONFIRMED|is_partial|partial_reason|chain_partial|execution_status)"'
$rootFields = @('schema_version', 'mode', 'result', 'findings', 'provenance')
$resultFields = @('outcome', 'coverage', 'candidates', 'exported', 'limits')
$methodFields = @('owner', 'method', 'descriptor', 'kind', 'role')
$findingFields = @('id', 'status', 'entry', 'impact', 'graph', 'proof', 'limits')
$proofFields = @('entry', 'site', 'input', 'callback', 'bridge', 'terminal', 'feasibility')
$graphRoles = @('ENTRY', 'SITE', 'SOURCE', 'DESERIALIZE', 'CALLBACK', 'BRIDGE', 'STEP', 'IMPACT', 'BOUNDARY')

function Property-Names {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) {
        return @()
    }
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name })
}

function Require-Shape {
    param(
        [AllowNull()][object] $Value,
        [string] $Label,
        [string[]] $Required,
        [string[]] $Allowed
    )
    if ($null -eq $Value) {
        throw "STATIC_REPORT_FIELD_MISSING: $Label"
    }
    $actual = @(Property-Names $Value)
    foreach ($name in $actual) {
        if ($name -notin $Allowed) {
            throw "STATIC_REPORT_UNEXPECTED_FIELD: $Label.$name"
        }
    }
    foreach ($name in $Required) {
        if ($name -notin $actual) {
            throw "STATIC_REPORT_FIELD_MISSING: $Label.$name"
        }
    }
}

function Require-Text {
    param([AllowNull()][object] $Value, [string] $Label)
    if ($null -eq $Value -or $Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
        throw "STATIC_REPORT_TEXT_INVALID: $Label"
    }
}

function Require-Enum {
    param([AllowNull()][object] $Value, [string] $Label, [string[]] $Values)
    Require-Text $Value $Label
    if ($Value -notin $Values) {
        throw "STATIC_REPORT_ENUM_INVALID: $Label=$Value"
    }
}

function Require-Limits {
    param([AllowNull()][object] $Value, [string] $Label, [bool] $Required)
    if ($null -eq $Value) {
        if ($Required) {
            throw "STATIC_REPORT_LIMITS_MISSING: $Label"
        }
        return
    }
    if ($Value -isnot [array]) {
        throw "STATIC_REPORT_LIMITS_INVALID: $Label"
    }
    $seen = @{}
    foreach ($item in @($Value)) {
        Require-Text $item "$Label[]"
        if ($seen.ContainsKey([string]$item)) {
            throw "STATIC_REPORT_LIMITS_DUPLICATE: $Label=$item"
        }
        $seen[[string]$item] = $true
    }
    if ($Required -and @($Value).Count -eq 0) {
        throw "STATIC_REPORT_LIMITS_MISSING: $Label"
    }
}

function Require-Integer {
    param([AllowNull()][object] $Value, [string] $Label)
    if ($null -eq $Value -or $Value -isnot [int] -and $Value -isnot [long]) {
        throw "STATIC_REPORT_INTEGER_INVALID: $Label"
    }
    if ([long]$Value -lt 0) {
        throw "STATIC_REPORT_INTEGER_INVALID: $Label"
    }
}

foreach ($reportPath in $ReportDirectory) {
    $resolvedReportPath = [IO.Path]::GetFullPath($reportPath)
    if (-not (Test-Path -LiteralPath $resolvedReportPath -PathType Container)) {
        throw "STATIC_REPORT_MISSING: $resolvedReportPath"
    }

    $actualRootEntries = @(Get-ChildItem -LiteralPath $resolvedReportPath -Force |
        Select-Object -ExpandProperty Name)
    $unexpectedRootEntries = @($actualRootEntries | Where-Object { $_ -notin $allowedRootEntries })
    $missingRootEntries = @($allowedRootEntries | Where-Object { $_ -notin $actualRootEntries })
    if ($unexpectedRootEntries.Count -gt 0) {
        throw "STATIC_REPORT_UNEXPECTED_ROOT: $resolvedReportPath => $($unexpectedRootEntries -join ',')"
    }
    if ($missingRootEntries.Count -gt 0) {
        throw "STATIC_REPORT_MISSING_ROOT: $resolvedReportPath => $($missingRootEntries -join ',')"
    }

    $jsonPath = Join-Path $resolvedReportPath 'report.json'
    $markdownPath = Join-Path $resolvedReportPath 'report.md'
    foreach ($requiredPath in @($jsonPath, $markdownPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "STATIC_REPORT_REQUIRED_FILE_MISSING: $requiredPath"
        }
    }

    $jsonText = Get-Content -LiteralPath $jsonPath -Raw
    if ($jsonText -match $forbiddenReportTerms) {
        throw "STATIC_REPORT_RETIRED_FIELD: $jsonPath"
    }
    try {
        $document = $jsonText | ConvertFrom-Json
    } catch {
        throw "STATIC_REPORT_INVALID_JSON: $jsonPath ($($_.Exception.Message))"
    }

    Require-Shape $document 'root' $rootFields $rootFields
    if ($document.schema_version -ne 'JUST-REPORT-V2') {
        throw "STATIC_REPORT_SCHEMA_INVALID: $jsonPath"
    }
    Require-Enum $document.mode 'mode' @('component', 'application')

    Require-Shape $document.result 'result' @('outcome', 'coverage') $resultFields
    Require-Enum $document.result.outcome 'result.outcome' @(
        'FINDINGS_AVAILABLE', 'NO_FINDINGS', 'FAILED', 'UNSUPPORTED')
    Require-Enum $document.result.coverage 'result.coverage' @('COMPLETE', 'BOUNDED', 'UNKNOWN')
    if ($null -ne $document.result.candidates) {
        Require-Integer $document.result.candidates 'result.candidates'
    }
    if ($null -ne $document.result.exported) {
        Require-Integer $document.result.exported 'result.exported'
        if ($null -ne $document.result.candidates -and
            [long]$document.result.exported -gt [long]$document.result.candidates) {
            throw 'STATIC_REPORT_RESULT_COUNTS_INVALID: exported exceeds candidates'
        }
    }
    Require-Limits $document.result.limits 'result.limits' $false

    if ($document.findings -isnot [array]) {
        throw 'STATIC_REPORT_FINDINGS_INVALID: findings must be an array'
    }
    $findingCount = @($document.findings).Count
    foreach ($finding in @($document.findings)) {
        Require-Shape $finding 'findings[]' @('id', 'status', 'entry', 'impact', 'graph', 'proof') $findingFields
        Require-Text $finding.id 'findings[].id'
        Require-Enum $finding.status 'findings[].status' @('COMPLETE', 'PARTIAL', 'UNKNOWN')

        foreach ($methodName in @('entry', 'impact')) {
            $method = $finding.$methodName
            Require-Shape $method "findings[].$methodName" @('owner', 'method', 'descriptor') $methodFields
            Require-Text $method.owner "findings[].$methodName.owner"
            Require-Text $method.method "findings[].$methodName.method"
            Require-Text $method.descriptor "findings[].$methodName.descriptor"
            if ('kind' -in @(Property-Names $method)) {
                Require-Text $method.kind "findings[].$methodName.kind"
            }
            if ('role' -in @(Property-Names $method)) {
                Require-Text $method.role "findings[].$methodName.role"
            }
        }

        if ($finding.graph -isnot [array] -or @($finding.graph).Count -eq 0) {
            throw 'STATIC_REPORT_GRAPH_INVALID: findings[].graph must be non-empty'
        }
        foreach ($node in @($finding.graph)) {
            Require-Shape $node 'findings[].graph[]' @('role', 'label') @('role', 'label')
            Require-Enum $node.role 'findings[].graph[].role' $graphRoles
            Require-Text $node.label 'findings[].graph[].label'
        }

        Require-Shape $finding.proof 'findings[].proof' $proofFields $proofFields
        foreach ($proofName in $proofFields) {
            Require-Text $finding.proof.$proofName "findings[].proof.$proofName"
        }
        $findingLimits = $null
        if ('limits' -in @(Property-Names $finding)) {
            $findingLimits = $finding.limits
        }
        Require-Limits $findingLimits 'findings[].limits' ($finding.status -ne 'COMPLETE')
        if ($finding.status -eq 'COMPLETE' -and $null -ne $findingLimits -and
            @($findingLimits).Count -gt 0) {
            throw 'STATIC_REPORT_COMPLETE_FINDING_LIMITS: complete finding has proof limits'
        }
    }

    Require-Shape $document.provenance 'provenance' @('artifact_sha256', 'detail') @('artifact_sha256', 'detail')
    Require-Text $document.provenance.artifact_sha256 'provenance.artifact_sha256'
    Require-Text $document.provenance.detail 'provenance.detail'

    $markdown = Get-Content -LiteralPath $markdownPath -Raw
    if ([string]::IsNullOrWhiteSpace($markdown) -or $markdown -notmatch '(?m)^# Just report\s*$') {
        throw "STATIC_REPORT_MARKDOWN_INVALID: $markdownPath"
    }
    if ($findingCount -gt 0 -and $markdown -notmatch '\[ENTRY\]') {
        throw "STATIC_REPORT_MARKDOWN_GRAPH_MISSING: $markdownPath"
    }
    if ($findingCount -eq 0 -and $document.result.outcome -eq 'NO_FINDINGS' -and
        $markdown -notmatch 'not proof that the artifact is safe') {
        throw "STATIC_REPORT_EMPTY_EXPLANATION_MISSING: $markdownPath"
    }
    Write-Output "STATIC_REPORT_OK $resolvedReportPath"
}
