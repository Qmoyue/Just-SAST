[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]] $ReportDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allowedRootEntries = @('evidence', 'meta', 'report.json', 'report.md')
$forbiddenReportTerms = '(?i)"(?:target_code_executed|dynamic_verification|verificationMode|generated_bytes|payload_bytes|RCE_CONFIRMED)"'

foreach ($reportPath in $ReportDirectory) {
    $resolvedReportPath = [IO.Path]::GetFullPath($reportPath)
    if (-not (Test-Path -LiteralPath $resolvedReportPath -PathType Container)) {
        throw "STATIC_REPORT_MISSING: $resolvedReportPath"
    }

    $actualRootEntries = @(Get-ChildItem -LiteralPath $resolvedReportPath -Force | Select-Object -ExpandProperty Name)
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
    $runMetadataPath = Join-Path $resolvedReportPath 'meta/run.json'
    $transactionPath = Join-Path $resolvedReportPath 'meta/transaction.json'
    foreach ($requiredPath in @($jsonPath, $markdownPath, $runMetadataPath, $transactionPath)) {
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
    if ($document.analysis.mode -ne 'STATIC_ONLY') {
        throw "STATIC_REPORT_NOT_STATIC_ONLY: $jsonPath"
    }
    foreach ($requiredRunField in @('outcome', 'coverage', 'chain_proof_coverage')) {
        if (-not ($document.run.PSObject.Properties.Name -contains $requiredRunField)) {
            throw "STATIC_REPORT_RUN_FIELD_MISSING: $jsonPath => $requiredRunField"
        }
    }
    if ((Get-Item -LiteralPath $markdownPath).Length -eq 0) {
        throw "STATIC_REPORT_EMPTY_MARKDOWN: $markdownPath"
    }
    Write-Output "STATIC_REPORT_OK $resolvedReportPath"
}
