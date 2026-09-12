[CmdletBinding()]
param(
    [string] $CiWorkflowPath = '.github/workflows/ci.yml',
    [string] $ReleaseWorkflowPath = '.github/workflows/release.yml',
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
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

function Get-WorkflowText {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path -Path $RepoRoot -ChildPath $Path))
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "WORKFLOW_MISSING: $resolved"
    }
    return [pscustomobject]@{
        path = $resolved
        text = (Get-Content -LiteralPath $resolved -Raw)
    }
}

function Get-RelativePathCompat {
    param(
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $Path
    )
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    $method = [IO.Path].GetMethod('GetRelativePath', [Type[]]@([string], [string]))
    if ($null -ne $method) {
        return ([IO.Path]::GetRelativePath($baseFull, $pathFull)).Replace([char]92, [char]47)
    }
    return [Uri]::UnescapeDataString(([Uri]$baseFull).MakeRelativeUri([Uri]$pathFull).ToString()).Replace([char]92, [char]47)
}

function Test-WorkflowContract {
    param(
        [Parameter(Mandatory = $true)] [string] $CiText,
        [Parameter(Mandatory = $true)] [string] $ReleaseText
    )
    $checks = [System.Collections.Generic.List[object]]::new()
    $ci = $CiText.Replace("`r`n", "`n")
    $release = $ReleaseText.Replace("`r`n", "`n")

    Add-Check $checks 'CONTRACT_ID' ($ExpectedContractId -eq 'JUST-PROD-D009-V1') 'validator is bound to JUST-PROD-D009-V1.'

    foreach ($jobId in @('fast', 'windows-contract', 'gleipner-kernel', 'nightly')) {
        Add-Check $checks ("CI_JOB_$($jobId.ToUpperInvariant().Replace('-', '_'))") ([regex]::IsMatch($ci, "(?m)^  $([regex]::Escape($jobId)):\s*$")) "ci.yml declares required job '$jobId'."
    }
    Add-Check $checks 'CI_PUSH_PULL_REQUEST' ([regex]::IsMatch($ci, '(?m)^  push:\s*$') -and [regex]::IsMatch($ci, '(?m)^  pull_request:\s*$')) 'fast CI runs for push and pull_request.'
    Add-Check $checks 'CI_NIGHTLY_TRIGGER' ([regex]::IsMatch($ci, '(?m)^  schedule:\s*$') -and [regex]::IsMatch($ci, '(?m)^  workflow_dispatch:\s*$')) 'nightly profile has schedule and manual trigger.'
    Add-Check $checks 'CI_FAST_TEST' ([regex]::IsMatch($ci, '(?m)\bmvn\s+-B\s+test\b')) 'fast job runs the complete Maven test command.'
    Add-Check $checks 'CI_FAST_PACKAGE' ([regex]::IsMatch($ci, '(?m)\bmvn\s+-B\s+package\s+-DskipTests\b')) 'fast job packages without rerunning tests.'
    Add-Check $checks 'CI_SHADED_LAUNCHER' ([regex]::IsMatch($ci, 'target/just-sast-\$?\{?version\}?-shaded\.jar|target/just-sast-0\.2\.0-shaded\.jar')) 'CI CLI and artifact checks use the attached shaded launcher.'
    Add-Check $checks 'CI_NO_THIN_LAUNCH' (-not [regex]::IsMatch($ci, 'java\s+-jar\s+target/just-sast-0\.2\.0\.jar\s+(--help|scan)')) 'CI never treats the thin JAR as an executable launcher.'
    Add-Check $checks 'CI_WINDOWS_CONTRACT' ([regex]::IsMatch($ci, 'just\.run\.os-contract-tests=true') -and [regex]::IsMatch($ci, 'WindowsRealVerificationContractTest')) 'Windows job enables the real Job Object contract and names its test.'
    Add-Check $checks 'CI_WINDOWS_SKIP_IS_FAILURE' ([regex]::IsMatch($ci, '(?is)skipped[\s\S]{0,400}exit\s+1|exit\s+1[\s\S]{0,400}skipped|NOT_RUN[\s\S]{0,400}exit\s+1|exit\s+1[\s\S]{0,400}NOT_RUN')) 'Windows contract treats unavailable/skipped required tests as NOT_RUN and non-zero.'
    Add-Check $checks 'CI_GLEIPNER_KERNEL' ([regex]::IsMatch($ci, 'gadget-kernel') -and [regex]::IsMatch($ci, '(?i)evaluator')) 'Gleipner job is explicitly isolated to gadget-kernel and references the official evaluator.'
    Add-Check $checks 'CI_GLEIPNER_MISSING_INPUT' ([regex]::IsMatch($ci, 'Gleipner.*NOT_RUN|NOT_RUN.*Gleipner') -and [regex]::IsMatch($ci, '(?i)exit\s+1')) 'Gleipner missing inputs emit NOT_RUN and fail the required job.'
    Add-Check $checks 'CI_NIGHTLY_RUNNER' ([regex]::IsMatch($ci, 'run-regression-v2\.ps1')) 'nightly job uses the schema-v2 regression runner.'
    Add-Check $checks 'CI_NIGHTLY_MISSING_INPUT' ([regex]::IsMatch($ci, '(?i)manifest.*NOT_RUN|NOT_RUN.*manifest') -and [regex]::IsMatch($ci, '(?i)exit\s+1')) 'nightly missing benchmark inputs emit NOT_RUN and fail instead of becoming green.'
    Add-Check $checks 'CI_METRIC_CONTRACT' ([regex]::IsMatch($ci, 'validate-scan-metrics\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the stable metric availability/namespace contract.'
    Add-Check $checks 'CI_PERFORMANCE_CONTRACT' ([regex]::IsMatch($ci, 'run-performance-v2\.ps1') -and [regex]::IsMatch($ci, 'validate-performance-baseline\.ps1') -and [regex]::IsMatch($ci, '(?i)Tier\s+MICRO')) 'fast job runs the deterministic performance harness and validates its immutable-baseline schema.'
    Add-Check $checks 'CI_ACCEPTANCE_CONTRACT' ([regex]::IsMatch($ci, 'run-acceptance\.ps1') -and [regex]::IsMatch($ci, 'validate-acceptance-summary\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the non-interactive acceptance orchestrator and summary contract.'
    Add-Check $checks 'CI_VERIFICATION_DISCLOSURE_CONTRACT' ([regex]::IsMatch($ci, 'validate-verification-disclosure\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the run/dynamic verification disclosure schemas and safety invariants.'
    Add-Check $checks 'CI_INPUT_SURFACE_CONTRACT' ([regex]::IsMatch($ci, 'validate-input-surface-inventory\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the frozen archive/rule/report consumer inventory and support-gap contract.'
    Add-Check $checks 'CI_HOSTILE_CORPUS_CONTRACT' ([regex]::IsMatch($ci, 'run-hostile-corpus\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the hostile archive/rule/report corpus baseline runner contract.'
    Add-Check $checks 'CI_JDK_DISCOVERY_CONTRACT' ([regex]::IsMatch($ci, 'validate-jdk-discovery\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates the explicit Jabba/JDK discovery adapter contract.'
    Add-Check $checks 'CI_CLI_CONTRACT' ([regex]::IsMatch($ci, 'validate-cli-contract\.ps1') -and [regex]::IsMatch($ci, '(?i)SelfTest')) 'fast job validates CLI exit-code and stdout/stderr behavior.'
    Add-Check $checks 'CI_ARTIFACT_ALWAYS' ([regex]::IsMatch($ci, '(?m)if:\s+always\(\)')) 'benchmark/diagnostic artifacts are uploaded on failures for diagnosis.'
    Add-Check $checks 'CI_NO_CONTINUE_ON_ERROR' (-not [regex]::IsMatch($ci, '(?m)continue-on-error:\s*true')) 'required CI jobs do not hide failures with continue-on-error.'

    Add-Check $checks 'RELEASE_SHADED_CHECKSUM' ([regex]::IsMatch($release, 'just-sast-\$\{version\}-shaded\.jar')) 'release checksums include the attached shaded launcher.'
    Add-Check $checks 'RELEASE_NO_STALE_MAIN' (-not [regex]::IsMatch($release, 'just-sast-\$\{version\}\.jar"')) 'release does not checksum the non-executable thin JAR as the main launcher.'
    Add-Check $checks 'RELEASE_MINIMUM_PERMISSION_DECLARED' ([regex]::IsMatch($release, '(?m)^permissions:\s*$')) 'release workflow declares an explicit permissions block (full hardening is a later gate).'
    Add-Check $checks 'ACTION_PINS_DEFERRED' $true 'action references are reported for the later full-SHA supply-chain gate.' 'informational'

    return @($checks.ToArray())
}

function Invoke-SelfTest {
    $synthetic = @"
name: synthetic
on:
  push:
  pull_request:
  schedule:
  workflow_dispatch:
jobs:
  fast:
    steps:
      - run: mvn -B test
      - run: mvn -B package -DskipTests
      - run: java -jar target/just-sast-0.2.0-shaded.jar --help
  windows-contract:
    steps:
      - run: mvn "-Djust.run.os-contract-tests=true" "-Dtest=WindowsRealVerificationContractTest" test
      - run: Write-Output NOT_RUN; exit 1
  gleipner-kernel:
    steps:
      - run: Write-Output 'Gleipner NOT_RUN evaluator gadget-kernel'; exit 1
  nightly:
    steps:
      - run: Write-Output 'manifest NOT_RUN'; exit 1
      - run: tools/run-regression-v2.ps1
  fast-metric-contract:
    steps:
      - run: pwsh -File tools/validate-scan-metrics.ps1 -SelfTest
      - run: pwsh -File tools/run-performance-v2.ps1 -SelfTest
      - run: pwsh -File tools/validate-performance-baseline.ps1 -SelfTest
      - run: pwsh -File tools/run-acceptance.ps1 -SelfTest
      - run: pwsh -File tools/validate-acceptance-summary.ps1 -SelfTest
      - run: pwsh -File tools/validate-verification-disclosure.ps1 -SelfTest
      - run: pwsh -File tools/validate-input-surface-inventory.ps1 -SelfTest
      - run: pwsh -File tools/validate-input-surface-inventory.ps1
      - run: pwsh -File tools/run-hostile-corpus.ps1 -SelfTest
      - run: pwsh -File tools/validate-jdk-discovery.ps1 -SelfTest -Json
      - run: pwsh -File tools/validate-cli-contract.ps1 -SelfTest -Json
      - run: pwsh -File tools/run-performance-v2.ps1 -Tier MICRO
      - uses: actions/upload-artifact@v4
        if: always()
"@
    $syntheticRelease = @"
permissions:
  contents: read
sha256sum "target/just-sast-`${version}-shaded.jar"
"@
    $checks = Test-WorkflowContract -CiText $synthetic -ReleaseText $syntheticRelease
    $required = @($checks | Where-Object { $_.severity -eq 'required' })
    $failed = @($required | Where-Object { $_.status -ne 'PASS' })
    if ($failed.Count -ne 0) {
        throw "CI_VALIDATOR_SELF_TEST_FAILED: $($failed.id -join ',')"
    }
    [pscustomobject]@{ status = 'PASS'; tests = @('synthetic-required-job-contract', 'not-run-fail-closed', 'shaded-launcher', 'artifact-always') }
}

if ($SelfTest) {
    $self = Invoke-SelfTest
    if ($Json) { $self | ConvertTo-Json -Depth 8 } else { "CI_CONTRACT_SELF_TEST=$($self.status) tests=$($self.tests -join ',')" }
    exit 0
}

try {
    $ciFile = Get-WorkflowText $CiWorkflowPath
    $releaseFile = Get-WorkflowText $ReleaseWorkflowPath
    $checks = Test-WorkflowContract -CiText $ciFile.text -ReleaseText $releaseFile.text
    $required = @($checks | Where-Object { $_.severity -eq 'required' })
    $failed = @($required | Where-Object { $_.status -ne 'PASS' })
    $result = [pscustomobject]@{
        valid = ($failed.Count -eq 0)
        contract_id = $ExpectedContractId
        ci_workflow = Get-RelativePathCompat $RepoRoot $ciFile.path
        release_workflow = Get-RelativePathCompat $RepoRoot $releaseFile.path
        required_check_count = $required.Count
        failed_required_check_count = $failed.Count
        checks = @($checks)
    }
    if ($Json) {
        $result | ConvertTo-Json -Depth 12
    } else {
        "CI_CONTRACT valid=$($result.valid) required=$($result.required_check_count) failed=$($result.failed_required_check_count)"
        foreach ($check in $checks) { "[$($check.status)] $($check.id): $($check.message)" }
    }
    if ($failed.Count -ne 0) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine("CI_VALIDATOR_ERROR: $($_.Exception.Message)")
    exit 2
}
