[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string]$MavenExe = 'mvn.cmd',
    [switch]$SelfTest,
    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $repoRoot
if ($MavenExe -eq 'mvn' -and [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    # ProcessStartInfo cannot execute a .cmd shim by basename on Windows; keep the
    # user-facing override while resolving the normal Maven launcher explicitly.
    $MavenExe = 'mvn.cmd'
}
if (-not [IO.Path]::IsPathRooted($MavenExe)) {
    $resolvedMaven = Get-Command $MavenExe -ErrorAction SilentlyContinue
    if ($null -ne $resolvedMaven) {
        $MavenExe = $resolvedMaven.Source
    }
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'benchmark/runs/p012-hostile-baseline'
}

$cases = @(
    [pscustomobject]@{ id = 'archive-limits'; category = 'archive'; testClass = 'io.just.sast.util.ArchiveLimitsTest'; required = $true },
    [pscustomobject]@{ id = 'jar-reader-hostile'; category = 'archive'; testClass = 'io.just.sast.frontend.asm.JarReaderTest'; required = $true },
    [pscustomobject]@{ id = 'classfile-limits-hostile'; category = 'class-parser'; testClass = 'io.just.sast.frontend.asm.ClassFileLimitsTest'; required = $true },
    [pscustomobject]@{ id = 'nested-classpath-hostile'; category = 'classpath'; testClass = 'io.just.sast.verify.NestedClasspathTest'; required = $true },
    [pscustomobject]@{ id = 'yaml-rules-hostile'; category = 'rules'; testClass = 'io.just.sast.config.YamlRuleLoaderTest'; required = $true },
    [pscustomobject]@{ id = 'atomic-report-write'; category = 'report'; testClass = 'io.just.sast.report.AtomicFilesTest'; required = $true }
)

function New-Baseline([string]$status, [object[]]$results, [int]$exitCode, [string]$command,
                      [string]$started, [string]$ended, [string[]]$evidence) {
    [pscustomobject]@{
        schemaVersion = 'hostile-corpus-baseline-v1'
        contractId = 'JUST-PROD-D009-V1'
        status = $status
        generatedAt = $ended
        command = $command
        exitCode = $exitCode
        startedAt = $started
        endedAt = $ended
        cases = @($results)
        evidence = @($evidence)
        safety = [pscustomobject]@{
            targetCodeExecuted = 'NO'
            networkAccess = 'NOT_INVOKED'
            arbitraryPayload = 'NOT_INVOKED'
            failClosedOnFailure = $true
        }
    }
}

function Invoke-ProcessCapture([string]$exe, [string[]]$arguments, [string]$stdoutPath, [string]$stderrPath) {
    # The existing Maven runner is a command shim on Windows.  Invocation through PowerShell
    # preserves the shim resolution and, unlike Start-Process/ProcessStartInfo on Windows
    # PowerShell 5, still permits deterministic stdout/stderr redirection.
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $exe @arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    [pscustomobject]@{
        exitCode = $exitCode
        stdout = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) { Get-Content -LiteralPath $stdoutPath -Raw } else { '' }
        stderr = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) { Get-Content -LiteralPath $stderrPath -Raw } else { '' }
    }
}

function Read-TestResult([string]$reportsRoot, [string]$testClass) {
    $fileName = 'TEST-' + $testClass + '.xml'
    $path = Join-Path $reportsRoot $fileName
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ status = 'NOT_RUN'; tests = 0; failures = 0; errors = 0; skipped = 0; report = $path; reason = 'SUREFIRE_REPORT_MISSING' }
    }
    try {
        [xml]$xml = Get-Content -LiteralPath $path -Raw
        $suite = $xml.testsuite
        $tests = [int]$suite.tests
        $failures = [int]$suite.failures
        $errors = [int]$suite.errors
        $skipped = [int]$suite.skipped
        $status = if ($failures -gt 0 -or $errors -gt 0) { 'FAIL' } elseif ($skipped -gt 0) { 'NOT_RUN' } else { 'PASS' }
        $reason = if ($status -eq 'PASS') { '' } elseif ($status -eq 'NOT_RUN') { 'TEST_SKIPPED' } else { 'TEST_FAILURE' }
        return [pscustomobject]@{ status = $status; tests = $tests; failures = $failures; errors = $errors; skipped = $skipped; report = $path; reason = $reason }
    } catch {
        return [pscustomobject]@{ status = 'FAIL'; tests = 0; failures = 0; errors = 1; skipped = 0; report = $path; reason = 'SUREFIRE_REPORT_INVALID' }
    }
}

function Test-SelfContract {
    $ids = @($cases | ForEach-Object { $_.id })
    $unique = (@($ids | Sort-Object -Unique).Count -eq $ids.Count)
    $allRequired = (@($cases | Where-Object { $_.required }).Count -eq $cases.Count)
    $allClasses = (@($cases | Where-Object { -not [string]::IsNullOrWhiteSpace($_.testClass) }).Count -eq $cases.Count)
    return [pscustomobject]@{ valid = ($unique -and $allRequired -and $allClasses); checks = @('unique-case-ids','all-cases-required','test-class-bound') }
}

if ($SelfTest) {
    $self = Test-SelfContract
    if ($Json) { $self | ConvertTo-Json -Depth 8 } else { if ($self.valid) { 'PASS hostile-corpus-contract' } else { 'FAIL hostile-corpus-contract' } }
    if (-not $self.valid) { exit 1 }
    exit 0
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw "OUTPUT_EXISTS:$OutputRoot"
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$started = [DateTimeOffset]::UtcNow.ToString('o')
$testClasses = ($cases | ForEach-Object { $_.testClass }) -join ','
$arguments = @('-o', "-Dtest=$testClasses", 'test')
$command = $MavenExe + ' ' + ($arguments -join ' ')
$process = $null
try {
    $process = Invoke-ProcessCapture $MavenExe $arguments (Join-Path $OutputRoot 'maven.stdout.log') (Join-Path $OutputRoot 'maven.stderr.log')
} catch {
    $ended = [DateTimeOffset]::UtcNow.ToString('o')
    $failed = @($cases | ForEach-Object {
        [pscustomobject]@{ id = $_.id; category = $_.category; status = 'NOT_RUN'; tests = 0; failures = 0; errors = 0; skipped = 0; report = ''; reason = 'MAVEN_UNAVAILABLE' }
    })
    $baseline = New-Baseline 'NOT_RUN' $failed 127 $command $started $ended @('maven.stdout.log','maven.stderr.log')
    $baseline | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputRoot 'hostile-baseline.json') -Encoding UTF8
    if ($Json) { $baseline | ConvertTo-Json -Depth 12 } else { 'HOSTILE_BASELINE status=NOT_RUN reason=MAVEN_UNAVAILABLE' }
    exit 1
}

$reportsRoot = Join-Path $repoRoot 'target/surefire-reports'
$results = @($cases | ForEach-Object {
    $result = Read-TestResult $reportsRoot $_.testClass
    [pscustomobject]@{ id = $_.id; category = $_.category; status = $result.status; tests = $result.tests; failures = $result.failures; errors = $result.errors; skipped = $result.skipped; report = $result.report; reason = $result.reason }
})
$ended = [DateTimeOffset]::UtcNow.ToString('o')
$status = if ($process.exitCode -ne 0 -or @($results | Where-Object { $_.status -ne 'PASS' }).Count -gt 0) {
    if (@($results | Where-Object { $_.status -eq 'NOT_RUN' }).Count -gt 0 -and @($results | Where-Object { $_.status -eq 'FAIL' }).Count -eq 0) { 'NOT_RUN' } else { 'FAIL' }
} else { 'PASS' }
$evidence = @('maven.stdout.log','maven.stderr.log') + @($results | ForEach-Object { $_.report } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$baseline = New-Baseline $status $results $process.exitCode $command $started $ended $evidence
$baseline | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputRoot 'hostile-baseline.json') -Encoding UTF8
if ($Json) { $baseline | ConvertTo-Json -Depth 12 } else { "HOSTILE_BASELINE status=$status cases=$($results.Count) exit=$($process.exitCode)" }
if ($status -ne 'PASS') { exit 1 }
exit 0
