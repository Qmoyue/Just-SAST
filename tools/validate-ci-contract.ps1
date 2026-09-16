[CmdletBinding()]
param(
    [string] $CiWorkflowPath = '.github/workflows/ci.yml',
    [string] $ReleaseWorkflowPath = '.github/workflows/release.yml',
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-LIGHT-MINING-V3'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))

function Add-Check {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Checks,
        [Parameter(Mandatory = $true)] [string] $Id,
        [Parameter(Mandatory = $true)] [bool] $Pass,
        [Parameter(Mandatory = $true)] [string] $Message,
        [string] $Severity = 'required'
    )
    $Checks.Add([pscustomobject]@{
        id = $Id
        status = if ($Pass) { 'PASS' } else { 'FAIL' }
        severity = $Severity
        message = $Message
    }) | Out-Null
}

function Read-Workflow {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path -Path $RepoRoot -ChildPath $Path))
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "WORKFLOW_MISSING: $resolved"
    }
    return (Get-Content -LiteralPath $resolved -Raw).Replace("`r`n", "`n")
}

function Has-Pattern {
    param([Parameter(Mandatory = $true)] [string] $Text,
          [Parameter(Mandatory = $true)] [string] $Pattern)
    return [regex]::IsMatch($Text, $Pattern)
}

function Test-Contracts {
    param([Parameter(Mandatory = $true)] [string] $CiText,
          [Parameter(Mandatory = $true)] [string] $ReleaseText)
    $checks = [System.Collections.Generic.List[object]]::new()

    Add-Check $checks 'CONTRACT_ID' ($ExpectedContractId -eq 'JUST-LIGHT-MINING-V3') `
        'validator is bound to the current V3 product contract.'
    Add-Check $checks 'CI_FAST_JOB' (Has-Pattern $CiText '(?m)^  fast:\s*$') `
        'CI declares the required fast job.'
    Add-Check $checks 'CI_WINDOWS_JDK17' (Has-Pattern $CiText '(?s)os:\s*windows-latest[\s\S]{0,100}java:\s*''17''') `
        'the matrix runs the product on Windows/JDK17.'
    Add-Check $checks 'CI_TRIGGERS' ((Has-Pattern $CiText '(?m)^  push:\s*$') -and `
        (Has-Pattern $CiText '(?m)^  pull_request:\s*$') -and `
        (Has-Pattern $CiText '(?m)^  workflow_dispatch:\s*$')) `
        'CI covers push, pull request, and manual execution.'
    Add-Check $checks 'CI_TESTS' (Has-Pattern $CiText '(?m)\bmvn\s+-B\s+test\b') `
        'CI runs the complete Maven test suite.'
    Add-Check $checks 'CI_PACKAGE' (Has-Pattern $CiText '(?m)\bmvn\s+-B\s+package\s+-DskipTests\b') `
        'CI packages the tested project.'
    Add-Check $checks 'CI_STATIC_SMOKE' ((Has-Pattern $CiText '(?i)Static CLI smoke') -and `
        (Has-Pattern $CiText '--mode component') -and `
        (Has-Pattern $CiText '--mode application') -and `
        (Has-Pattern $CiText '--jdk-home') -and `
        (Has-Pattern $CiText '--offline') -and `
        (Has-Pattern $CiText '--cache')) `
        'CI runs both static modes, target-JDK selection, online completion, and offline reuse.'
    Add-Check $checks 'CI_TRACKED_FIXTURE' ((Has-Pattern $CiText 'src/test/resources/ci-smoke/pom\.xml') -and `
        (Has-Pattern $CiText 'fixture/CiSmokeEntry\.class')) `
        'CI smoke uses the repository-owned harmless fixture.'
    Add-Check $checks 'CI_NO_LOCAL_TOOLS' (-not (Has-Pattern $CiText '(?i)(^|[/\\])tools[/\\]')) `
        'CI does not depend on ignored local tools.'
    Add-Check $checks 'CI_NO_PRIVATE_INPUTS' (-not (Has-Pattern $CiText '(?i)(^|[/\\])benchmark[/\\]')) `
        'CI does not require private benchmark inputs.'
    Add-Check $checks 'CI_REPORT_CONTRACT_SCRIPT' (Test-Path -LiteralPath (Join-Path $RepoRoot '.github/scripts/validate-static-report.ps1') -PathType Leaf) `
        'CI uses a tracked static report contract assertion script.'
    Add-Check $checks 'CI_REPORT_CONTRACT_CALL' ((Has-Pattern $CiText '(?i)validate-static-report\.ps1') -and `
        (Has-Pattern $ReleaseText '(?i)validate-static-report\.ps1')) `
        'CI and Release enforce the public report tree and static-only fields.'
    Add-Check $checks 'CI_ARTIFACT_ALWAYS' (Has-Pattern $CiText '(?i)if:\s*always\(\)') `
        'diagnostic build artifacts remain available when a required step fails.'
    Add-Check $checks 'CI_NO_CONTINUE_ON_ERROR' (-not (Has-Pattern $CiText '(?m)continue-on-error:\s*true')) `
        'required CI steps do not hide failures.'

    $semverTagRegex = [regex]::Escape('^v[0-9]+\.[0-9]+\.[0-9]+$')
    Add-Check $checks 'RELEASE_TAG_VALIDATION' ((Has-Pattern $ReleaseText $semverTagRegex) -and `
        (Has-Pattern $ReleaseText 'refs/tags/\$tag')) `
        'release validates a semantic version tag before publishing.'
    Add-Check $checks 'RELEASE_JDK17' (Has-Pattern $ReleaseText 'java-version:\s*''17''') `
        'release builds with JDK17.'
    Add-Check $checks 'RELEASE_SHADED_CHECKSUM' ((Has-Pattern $ReleaseText 'just-sast-\$\{\{ steps\.project\.outputs\.version \}\}-shaded\.jar') -and `
        (Has-Pattern $ReleaseText '(?i)sha256sum')) `
        'release checksums the exact shaded launcher.'
    Add-Check $checks 'RELEASE_LICENSES' ((Has-Pattern $ReleaseText 'LICENSE') -and `
        (Has-Pattern $ReleaseText 'THIRD-PARTY-NOTICES\.md')) `
        'release assets include license notices.'
    Add-Check $checks 'RELEASE_WRITE_PERMISSION' (Has-Pattern $ReleaseText '(?m)^  contents:\s*write\s*$') `
        'only the release workflow requests contents write permission.'
    Add-Check $checks 'RELEASE_ATTESTATION_PERMISSION' (Has-Pattern $ReleaseText '(?m)^  attestations:\s*write\s*$') `
        'release provenance attestation has the minimum repository permission.'
    $workflowText = $CiText + "`n" + $ReleaseText
    Add-Check $checks 'NO_RETIRED_EXECUTION_TERMS' (-not (Has-Pattern $workflowText '(?i)Job Object|SecurityManager|WindowsRealVerificationContractTest|--no-verify|verify8|payload_bytes')) `
        'workflows contain no retired execution or isolation contract.'
    return @($checks.ToArray())
}

function Invoke-SelfTest {
    $ci = @'
name: ci
on:
  push:
  pull_request:
  workflow_dispatch:
jobs:
  fast:
    strategy:
      matrix:
        include:
          - os: windows-latest
            java: '17'
    steps:
      - run: mvn -B test
      - run: mvn -B package -DskipTests
      - run: Static CLI smoke --mode component --mode application --jdk-home --offline --cache
      - run: src/test/resources/ci-smoke/pom.xml fixture/CiSmokeEntry.class
      - run: validate-static-report.ps1
      - run: if: always()
'@
    $release = @'
permissions:
  contents: write
  attestations: write
java-version: '17'
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
git ls-remote origin refs/tags/$tag
sha256sum target/just-sast-${{ steps.project.outputs.version }}-shaded.jar
pwsh -File .github/scripts/validate-static-report.ps1
LICENSE THIRD-PARTY-NOTICES.md
'@
    $failed = @(Test-Contracts $ci $release | Where-Object { $_.status -ne 'PASS' -and $_.severity -eq 'required' })
    if ($failed.Count -ne 0) {
        throw "CI_CONTRACT_SELF_TEST_FAILED: $($failed.id -join ',')"
    }
    [pscustomobject]@{ status = 'PASS'; tests = @('v3-workflow-shape', 'two-mode-target-jdk-smoke', 'offline-cache-smoke', 'retired-execution-terms') }
}

if ($SelfTest) {
    $self = Invoke-SelfTest
    if ($Json) { $self | ConvertTo-Json -Depth 8 } else { "CI_CONTRACT_SELF_TEST=$($self.status)" }
    exit 0
}

try {
    $ci = Read-Workflow $CiWorkflowPath
    $release = Read-Workflow $ReleaseWorkflowPath
    $checks = Test-Contracts $ci $release
    $failed = @($checks | Where-Object { $_.status -ne 'PASS' -and $_.severity -eq 'required' })
    $result = [pscustomobject]@{
        valid = ($failed.Count -eq 0)
        contract_id = $ExpectedContractId
        required_check_count = @($checks | Where-Object { $_.severity -eq 'required' }).Count
        failed_required_check_count = $failed.Count
        checks = @($checks)
    }
    if ($Json) { $result | ConvertTo-Json -Depth 12 } else {
        "CI_CONTRACT valid=$($result.valid) required=$($result.required_check_count) failed=$($result.failed_required_check_count)"
        foreach ($check in $checks) { "[$($check.status)] $($check.id): $($check.message)" }
    }
    if ($failed.Count -ne 0) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine("CI_VALIDATOR_ERROR: $($_.Exception.Message)")
    exit 2
}
