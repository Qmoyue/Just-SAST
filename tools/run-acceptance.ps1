[CmdletBinding()]
param(
    [ValidateSet('smoke', 'phase', 'release')]
    [string] $Profile = 'smoke',
    [string] $ManifestPath = 'benchmark/manifest/wp8.v2.json',
    [string] $GleipnerManifestPath = 'benchmark/manifest/gleipner.v2.json',
    [string] $ApacheManifestPath = 'benchmark/manifest/apache-heldout.v2.json',
    [string] $LauncherJar = 'target/just-sast-0.2.0-shaded.jar',
    [string] $OutputRoot,
    [string[]] $CaseId,
    [string] $JabbaExe,
    [switch] $TrustedTargetDynamic,
    [switch] $NoVerify,
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
$SchemaVersion = 2
$ToolVersion = 'acceptance-v2'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$SchemaPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'acceptance-summary-v2.schema.json'))
$FixedGateIds = @(
    'PLAN_INTEGRITY',
    'BUILD_REPRODUCIBLE',
    'FAST_TESTS',
    'ARCHITECTURE',
    'ENTRY_ANCHOR_POLICY',
    'GLEIPNER_KERNEL',
    'WP8_STATIC',
    'WP8_DYNAMIC',
    'DYNAMIC_TRIAGE',
    'APACHE_APPLICATION_CHAIN',
    'WINDOWS_CONTAINMENT',
    'JDK_MATRIX',
    'PERFORMANCE',
    'DETERMINISM',
    'HOSTILE_INPUT_SAFETY',
    'CLI_OFFLINE_CONTRACT',
    'OUTPUT_AND_BASELINE',
    'ROBUSTNESS_SOAK',
    'USABILITY',
    'RELEASE_SUPPLY_CHAIN',
    'DOCS_RELEASE'
)
$script:EvidenceRoot = $null
$script:PowerShellHost = $null

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

function Get-JsonIfPresent {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-JsonAtomic {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $temp = Join-Path $parent ('.' + [IO.Path]::GetFileName($Path) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $Value | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $temp -Encoding UTF8
        if (Test-Path -LiteralPath $Path -PathType Leaf) { Move-Item -LiteralPath $temp -Destination $Path -Force } else { Move-Item -LiteralPath $temp -Destination $Path }
    } finally {
        if (Test-Path -LiteralPath $temp -PathType Leaf) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Get-RepoRelative {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $base = [IO.Path]::GetFullPath($RepoRoot).TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    $target = [IO.Path]::GetFullPath($Path)
    try {
        $baseUri = [Uri]$base
        $targetUri = [Uri]$target
        $relative = [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($targetUri).ToString()).Replace([char]92, [char]47)
        if (-not [string]::IsNullOrWhiteSpace($relative) -and $relative -notmatch '^\.\.') { return $relative }
    } catch { }
    return $target
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)] [AllowNull()] [AllowEmptyString()] [string] $Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function Resolve-PowerShellHost {
    if ($null -ne $script:PowerShellHost -and (Test-Path -LiteralPath $script:PowerShellHost -PathType Leaf)) { return $script:PowerShellHost }
    $candidates = [Collections.Generic.List[string]]::new()
    $edition = [string]$PSVersionTable.PSEdition
    if ($edition -eq 'Core') { $candidates.Add((Join-Path $PSHOME 'pwsh.exe')) | Out-Null }
    else { $candidates.Add((Join-Path $PSHOME 'powershell.exe')) | Out-Null }
    $candidates.Add((Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')) | Out-Null
    foreach ($name in @('pwsh', 'powershell')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($null -ne $command) { $candidates.Add([IO.Path]::GetFullPath([string]$command.Source)) | Out-Null }
    }
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $script:PowerShellHost = [IO.Path]::GetFullPath($candidate)
            return $script:PowerShellHost
        }
    }
    throw 'POWERSHELL_HOST_NOT_FOUND'
}

function Invoke-ChildScript {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [string] $ScriptPath,
        [string[]] $Arguments = @(),
        [int] $TimeoutMs = 1800000
    )
    $logRoot = Join-Path $script:EvidenceRoot 'logs'
    if (-not (Test-Path -LiteralPath $logRoot -PathType Container)) { New-Item -ItemType Directory -Path $logRoot -Force | Out-Null }
    $stdout = Join-Path $logRoot ($Name + '.stdout.log')
    $stderr = Join-Path $logRoot ($Name + '.stderr.log')
    $all = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', [IO.Path]::GetFullPath($ScriptPath)) + @($Arguments)
    $argumentLine = (($all | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' ')
    $process = $null
    $stdoutTask = $null
    $stderrTask = $null
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        # Start-Process rebuilds the Windows environment dictionary and can fail
        # when both PATH and Path are exposed. ProcessStartInfo avoids that
        # mutation while keeping this orchestration layer non-interactive.
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = Resolve-PowerShellHost
        $startInfo.Arguments = $argumentLine
        $startInfo.WorkingDirectory = $RepoRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'CHILD_PROCESS_START_FAILED' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMs)) {
            try { $process.Kill() } catch { }
            $process.WaitForExit(5000) | Out-Null
            if ($null -ne $stdoutTask) { [IO.File]::WriteAllText($stdout, $stdoutTask.Result) }
            if ($null -ne $stderrTask) { [IO.File]::WriteAllText($stderr, $stderrTask.Result) }
            return [ordered]@{ name = $Name; status = 'TIMEOUT'; exit_code = 124; wall_ms = [long]$watch.ElapsedMilliseconds; stdout = Get-RepoRelative $stdout; stderr = Get-RepoRelative $stderr; command = ((Resolve-PowerShellHost) + ' ' + $argumentLine) }
        }
        if ($null -ne $stdoutTask) { [IO.File]::WriteAllText($stdout, $stdoutTask.Result) }
        if ($null -ne $stderrTask) { [IO.File]::WriteAllText($stderr, $stderrTask.Result) }
        return [ordered]@{ name = $Name; status = if ($process.ExitCode -eq 0) { 'COMPLETED' } else { 'FAILED' }; exit_code = [int]$process.ExitCode; wall_ms = [long]$watch.ElapsedMilliseconds; stdout = Get-RepoRelative $stdout; stderr = Get-RepoRelative $stderr; command = ((Resolve-PowerShellHost) + ' ' + $argumentLine) }
    } catch {
        return [ordered]@{ name = $Name; status = 'FAILED'; exit_code = -1; wall_ms = [long]$watch.ElapsedMilliseconds; stdout = Get-RepoRelative $stdout; stderr = Get-RepoRelative $stderr; command = ((Resolve-PowerShellHost) + ' ' + $argumentLine); error = $_.Exception.Message }
    } finally {
        $watch.Stop()
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Write-PreflightEvidence {
    param([Parameter(Mandatory = $true)] [string] $Name, [Parameter(Mandatory = $true)] $Value)
    $path = Join-Path (Join-Path $script:EvidenceRoot 'preflight') ($Name + '.json')
    Write-JsonAtomic $path $Value
    return Get-RepoRelative $path
}

function New-GateRecord {
    param(
        [Parameter(Mandatory = $true)] [string] $Id,
        [Parameter(Mandatory = $true)] [ValidateSet('PASS', 'FAIL', 'NOT_RUN', 'INCOMPARABLE')] [string] $Status,
        [Parameter(Mandatory = $true)] [string] $ReasonCode,
        [string[]] $Commands = @(),
        $Details = $null,
        [int] $ExitCode = $null
    )
    if ($FixedGateIds -notcontains $Id) { throw "UNKNOWN_FIXED_GATE: $Id" }
    $evidencePayload = [ordered]@{
        schema_version = $SchemaVersion
        contract_id = $ExpectedContractId
        kind = 'acceptance-gate-evidence'
        gate_id = $Id
        profile = $Profile
        status = $Status
        reason_code = $ReasonCode
        commands = @($Commands)
        details = if ($null -eq $Details) { [ordered]@{} } else { $Details }
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
    }
    $evidencePath = Join-Path (Join-Path $script:EvidenceRoot 'gates') ($Id + '.json')
    Write-JsonAtomic $evidencePath $evidencePayload
    return [ordered]@{
        id = $Id
        required = $true
        status = $Status
        reason_code = $ReasonCode
        evidence = @((Get-RepoRelative $evidencePath))
        commands = @($Commands)
        exit_code = $ExitCode
        details = if ($null -eq $Details) { [ordered]@{} } else { $Details }
    }
}

function Get-AggregateSummary {
    param([Parameter(Mandatory = $true)] [object[]] $Gates)
    $pass = @($Gates | Where-Object { $_.status -eq 'PASS' }).Length
    $fail = @($Gates | Where-Object { $_.status -eq 'FAIL' }).Length
    $notRun = @($Gates | Where-Object { $_.status -eq 'NOT_RUN' }).Length
    $incomparable = @($Gates | Where-Object { $_.status -eq 'INCOMPARABLE' }).Length
    $requiredFailures = @($Gates | Where-Object { $_.required -and $_.status -eq 'FAIL' } | ForEach-Object { $_.id })
    $requiredNotRun = @($Gates | Where-Object { $_.required -and $_.status -eq 'NOT_RUN' } | ForEach-Object { $_.id })
    $requiredIncomparable = @($Gates | Where-Object { $_.required -and $_.status -eq 'INCOMPARABLE' } | ForEach-Object { $_.id })
    $status = if ($fail -gt 0) { 'FAIL' } elseif ($incomparable -gt 0) { 'INCOMPARABLE' } elseif ($notRun -gt 0) { 'NOT_RUN' } else { 'PASS' }
    return [ordered]@{
        status = $status
        gate_count = @($Gates).Length
        required_count = @($Gates | Where-Object { $_.required }).Length
        pass_count = $pass
        fail_count = $fail
        not_run_count = $notRun
        incomparable_count = $incomparable
        required_failures = @($requiredFailures)
        required_not_run = @($requiredNotRun)
        required_incomparable = @($requiredIncomparable)
    }
}

function Invoke-PlanGate {
    $tool = Join-Path $PSScriptRoot 'validate-refactor-plan.ps1'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { return New-GateRecord 'PLAN_INTEGRITY' 'FAIL' 'PLAN_VALIDATOR_MISSING' @() }
    $run = Invoke-ChildScript 'plan-validator' $tool @('-Json') 120000
    $path = Join-Path $RepoRoot 'docs\refactor-todo.md'
    $doc = Get-JsonIfPresent (Join-Path $script:EvidenceRoot 'logs\plan-validator.stdout.log')
    $valid = ($run.status -eq 'COMPLETED' -and $run.exit_code -eq 0 -and $null -ne $doc -and (Get-BooleanValue $doc 'valid' $false) -and (Get-StringValue $doc 'contract_id' '') -eq $ExpectedContractId)
    $complete = ($valid -and (Get-StringValue $doc 'state' '') -eq 'COMPLETE' -and [int]$doc.unchecked_phase_items -eq 0)
    $status = if (-not $valid) { 'FAIL' } elseif ($complete) { 'PASS' } else { 'NOT_RUN' }
    $reason = if (-not $valid) { 'PLAN_VALIDATOR_FAILED' } elseif ($complete) { 'PLAN_COMPLETE' } else { 'PLAN_ACTIVE_OR_ITEMS_OPEN' }
    $details = [ordered]@{ validator = $run; plan_path = Get-RepoRelative $path; state = Get-StringValue $doc 'state' 'UNKNOWN'; next_item = Get-StringValue $doc 'next_item' 'UNKNOWN'; valid = $valid }
    return New-GateRecord 'PLAN_INTEGRITY' $status $reason @($run.command) $details $run.exit_code
}

function Invoke-ManifestCheck {
    param([Parameter(Mandatory = $true)] [string] $Name, [Parameter(Mandatory = $true)] [string] $Path)
    $full = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Path))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        return [ordered]@{ name = $Name; path = $Path; status = 'NOT_RUN'; reason_code = 'MANIFEST_MISSING'; run = $null; document = $null; manifest_document = $null; evidence = Write-PreflightEvidence $Name ([ordered]@{ name = $Name; path = $Path; status = 'NOT_RUN'; reason_code = 'MANIFEST_MISSING' }) }
    }
    $tool = Join-Path $PSScriptRoot 'validate-benchmark-manifest.ps1'
    $run = Invoke-ChildScript ('manifest-' + $Name) $tool @('-ManifestPath', $full, '-Json') 120000
    $doc = Get-JsonIfPresent (Join-Path $script:EvidenceRoot ('logs\manifest-' + $Name + '.stdout.log'))
    $valid = ($run.status -eq 'COMPLETED' -and $run.exit_code -eq 0 -and $null -ne $doc -and (Get-BooleanValue $doc 'valid' $false))
    $status = if ($valid) { 'PASS' } else { 'FAIL' }
    $reason = if ($valid) { 'MANIFEST_VALID' } else { 'MANIFEST_HASH_OR_SCHEMA_MISMATCH' }
    $payload = [ordered]@{ name = $Name; path = Get-RepoRelative $full; status = $status; reason_code = $reason; run = $run; validator = $doc }
    return [ordered]@{ name = $Name; path = $full; status = $status; reason_code = $reason; run = $run; document = $doc; manifest_document = Get-JsonIfPresent $full; evidence = Write-PreflightEvidence $Name $payload }
}

function Test-VerifiedApplicationTruth {
    param([AllowNull()] $Manifest)
    if ($null -eq $Manifest) { return $false }
    $cases = @($Manifest.cases)
    if ($cases.Length -eq 0) { return $false }
    foreach ($case in $cases) {
        if ((Get-StringValue $case 'status' '') -ne 'VERIFIED') { return $false }
        if ($null -eq $case.truth -or (Get-StringValue $case.truth 'status' '') -ne 'VERIFIED') { return $false }
        $entries = @($case.application_entries)
        $joins = @($case.join_evidence)
        $bridges = @($case.bridge_evidence)
        if ($entries.Length -eq 0 -or $joins.Length -eq 0) { return $false }
        if (@($entries | Where-Object { (Get-StringValue $_ 'status' '') -ne 'VERIFIED' }).Length -gt 0) { return $false }
        if (@($joins | Where-Object { (Get-StringValue $_ 'status' '') -ne 'VERIFIED' }).Length -gt 0) { return $false }
        if (@($bridges | Where-Object { (Get-BooleanValue $_ 'required' $false) -and (Get-StringValue $_ 'status' '') -ne 'VERIFIED' }).Length -gt 0) { return $false }
        if ($null -eq $case.chain_expectation -or (Get-StringValue $case.chain_expectation 'status' '') -ne 'VERIFIED') { return $false }
    }
    return $true
}

function Invoke-RegressionPlan {
    param([Parameter(Mandatory = $true)] [string] $Name, [Parameter(Mandatory = $true)] [string] $Manifest, [switch] $Apache)
    $manifestFull = [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Manifest))
    $check = if ($Apache) { $script:ApacheManifestCheck } else { $script:WpManifestCheck }
    if ($null -eq $check -or $check.status -ne 'PASS') { return [ordered]@{ name = $Name; status = 'NOT_RUN'; reason_code = 'MANIFEST_NOT_VALID'; run = $null; evidence = Write-PreflightEvidence ('regression-' + $Name) ([ordered]@{ status = 'NOT_RUN'; reason_code = 'MANIFEST_NOT_VALID' }) } }
    $root = Join-Path $script:EvidenceRoot ('regression-' + $Name)
    $args = @('-ManifestPath', $manifestFull, '-OutputRoot', $root)
    if ($Profile -eq 'smoke') { $args += @('-PlanOnly', '-Fast') } else {
        if (-not (Test-Path -LiteralPath ([IO.Path]::GetFullPath((Join-Path (Get-Location).Path $LauncherJar))) -PathType Leaf)) { return [ordered]@{ name = $Name; status = 'NOT_RUN'; reason_code = 'LAUNCHER_MISSING'; run = $null; evidence = Write-PreflightEvidence ('regression-' + $Name) ([ordered]@{ status = 'NOT_RUN'; reason_code = 'LAUNCHER_MISSING' }) } }
        $args += @('-LauncherJar', [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $LauncherJar)))
    }
    if (-not $TrustedTargetDynamic) { $args += '-NoVerify' }
    if (-not [string]::IsNullOrWhiteSpace($JabbaExe)) { $args += @('-JabbaExe', [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $JabbaExe))) }
    if (@($CaseId).Length -gt 0 -and -not $Apache) { foreach ($id in @($CaseId)) { $args += @('-CaseId', $id) } }
    $tool = Join-Path $PSScriptRoot 'run-regression-v2.ps1'
    $run = Invoke-ChildScript ('regression-' + $Name) $tool $args 7200000
    $manifestOut = Join-Path $root 'run-manifest.json'
    $doc = Get-JsonIfPresent $manifestOut
    $payload = [ordered]@{ name = $Name; status = $run.status; run = $run; output = if ($null -eq $doc) { $null } else { Get-RepoRelative $manifestOut }; state = if ($null -eq $doc) { 'UNKNOWN' } else { Get-StringValue $doc 'state' 'UNKNOWN' }; summary = if ($null -eq $doc) { $null } else { $doc.summary } }
    return [ordered]@{ name = $Name; status = if ($run.status -eq 'COMPLETED' -and $run.exit_code -eq 0 -and $null -ne $doc) { 'PASS' } else { 'FAIL' }; reason_code = if ($run.status -eq 'COMPLETED' -and $run.exit_code -eq 0 -and $null -ne $doc) { 'RUN_MANIFEST_OBSERVED' } else { 'REGRESSION_RUN_FAILED' }; run = $run; document = $doc; evidence = Write-PreflightEvidence ('regression-' + $Name) $payload }
}

function Invoke-PerformancePlan {
    $tool = Join-Path $PSScriptRoot 'run-performance-v2.ps1'
    $perfRoot = Join-Path $script:EvidenceRoot 'performance'
    $tier = $Profile.ToUpperInvariant()
    $args = @('-Tier', $tier, '-OutputRoot', $perfRoot)
    if ($tier -ne 'MICRO') { $args += @('-ManifestPath', [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ManifestPath)), '-LauncherJar', [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $LauncherJar))) }
    if (-not $TrustedTargetDynamic) { $args += '-NoVerify' }
    $run = Invoke-ChildScript 'performance' $tool $args 21600000
    $baselinePath = Join-Path $perfRoot 'performance-baseline.json'
    $doc = Get-JsonIfPresent $baselinePath
    $slo = if ($null -eq $doc) { 'UNKNOWN' } else { Get-StringValue $doc.slo 'status' 'UNKNOWN' }
    $status = if ($Profile -ne 'release') { 'NOT_RUN' } elseif ($run.status -ne 'COMPLETED' -or $run.exit_code -ne 0 -or $null -eq $doc) { 'FAIL' } elseif ($slo -ne 'PASS') { 'FAIL' } else { 'PASS' }
    $reason = if ($Profile -ne 'release') { 'PERF_RELEASE_PROFILE_REQUIRED' } elseif ($run.status -ne 'COMPLETED' -or $run.exit_code -ne 0 -or $null -eq $doc) { 'PERFORMANCE_RUN_FAILED' } elseif ($slo -ne 'PASS') { 'PERFORMANCE_SLO_FAILURE' } else { 'PERFORMANCE_RELEASE_SLO_PASS' }
    $details = [ordered]@{ run = $run; baseline = if ($null -eq $doc) { $null } else { Get-RepoRelative $baselinePath }; slo = $slo; candidate_status = if ($null -eq $doc) { 'UNKNOWN' } else { Get-StringValue $doc 'status' 'UNKNOWN' } }
    return New-GateRecord 'PERFORMANCE' $status $reason @($run.command) $details $run.exit_code
}

function Invoke-CiContractCheck {
    $tool = Join-Path $PSScriptRoot 'validate-ci-contract.ps1'
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { return [ordered]@{ status = 'NOT_RUN'; reason_code = 'CI_VALIDATOR_MISSING' } }
    $run = Invoke-ChildScript 'ci-contract' $tool @('-Json') 120000
    $doc = Get-JsonIfPresent (Join-Path $script:EvidenceRoot 'logs\ci-contract.stdout.log')
    $status = if ($run.status -eq 'COMPLETED' -and $run.exit_code -eq 0 -and $null -ne $doc -and (Get-BooleanValue $doc 'valid' $false)) { 'PASS' } else { 'FAIL' }
    $reason = if ($status -eq 'PASS') { 'CI_CONTRACT_VALID' } else { 'CI_CONTRACT_INVALID' }
    return [ordered]@{ status = $status; reason_code = $reason; run = $run; document = $doc; evidence = Write-PreflightEvidence 'ci-contract' ([ordered]@{ status = $status; reason_code = $reason; run = $run; document = $doc }) }
}

function Get-MavenFastGate {
    $reason = if ($Profile -eq 'smoke') { 'PROFILE_SMOKE_TESTS_DEFERRED' } else { 'MAVEN_TEST_ORCHESTRATION_PENDING' }
    return New-GateRecord 'FAST_TESTS' 'NOT_RUN' $reason @() ([ordered]@{ note = 'P0.10 does not duplicate Maven semantics; the release test job remains the owner.' })
}

function Invoke-SelfTest {
    $checks = [Collections.Generic.List[string]]::new()
    if (@($FixedGateIds).Length -ne 21 -or @($FixedGateIds | Sort-Object -Unique).Length -ne 21) { throw 'SELFTEST_FIXED_GATE_SET' }
    $checks.Add('fixed-gate-set') | Out-Null
    $script:EvidenceRoot = Join-Path ([IO.Path]::GetTempPath()) ('just-acceptance-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $script:EvidenceRoot 'gates') -Force | Out-Null
    $passGates = [Collections.Generic.List[object]]::new()
    foreach ($id in $FixedGateIds) { $passGates.Add([ordered]@{ id = $id; required = $true; status = 'PASS' }) | Out-Null }
    $all = Get-AggregateSummary $passGates.ToArray()
    if ($all.status -ne 'PASS' -or $all.gate_count -ne 21) { throw 'SELFTEST_AGGREGATE_PASS' }
    $checks.Add('aggregate-pass') | Out-Null
    $passGates[4].status = 'NOT_RUN'
    $notRun = Get-AggregateSummary $passGates.ToArray()
    if ($notRun.status -ne 'NOT_RUN' -or @($notRun.required_not_run).Length -ne 1) { throw 'SELFTEST_REQUIRED_NOT_RUN' }
    $checks.Add('required-not-run-fails') | Out-Null
    $passGates[4].status = 'FAIL'
    $failed = Get-AggregateSummary $passGates.ToArray()
    if ($failed.status -ne 'FAIL' -or @($failed.required_failures).Length -ne 1) { throw 'SELFTEST_REQUIRED_FAIL' }
    $checks.Add('required-fail-fails') | Out-Null
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'SELFTEST_SCHEMA_MISSING' }
    $schema = Get-JsonIfPresent $SchemaPath
    if ($null -eq $schema -or [int]$schema.properties.schema_version.const -ne 2 -or (Get-StringValue $schema.properties.contract_id 'const' '') -ne $ExpectedContractId) { throw 'SELFTEST_SCHEMA_CONTRACT' }
    $checks.Add('schema-contract') | Out-Null
    Remove-Item -LiteralPath $script:EvidenceRoot -Recurse -Force
    return [ordered]@{ status = 'PASS'; tests = @($checks.ToArray()) }
}

function Invoke-Acceptance {
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path (Join-Path $RepoRoot 'benchmark\runs') ('acceptance-' + $Profile + '-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $root = [IO.Path]::GetFullPath($OutputRoot)
    if (Test-Path -LiteralPath $root) { throw "OUTPUT_EXISTS: refusing to overwrite $root" }
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $script:EvidenceRoot = $root
    New-Item -ItemType Directory -Path (Join-Path $root 'gates') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'preflight') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force | Out-Null
    $started = (Get-Date).ToUniversalTime().ToString('o')

    # Plan validation is intentionally the first external operation.
    $planGate = Invoke-PlanGate
    $script:WpManifestCheck = Invoke-ManifestCheck 'wp8' $ManifestPath
    $script:GleipnerManifestCheck = Invoke-ManifestCheck 'gleipner' $GleipnerManifestPath
    $script:ApacheManifestCheck = Invoke-ManifestCheck 'apache' $ApacheManifestPath
    $ci = Invoke-CiContractCheck
    $wpRun = Invoke-RegressionPlan 'wp8' $ManifestPath
    $apacheRun = if ($Profile -eq 'smoke') { [ordered]@{ status = 'NOT_RUN'; reason_code = 'PROFILE_SMOKE_APACHE_DEFERRED'; run = $null; document = $null; evidence = Write-PreflightEvidence 'regression-apache' ([ordered]@{ status = 'NOT_RUN'; reason_code = 'PROFILE_SMOKE_APACHE_DEFERRED' }) } } else { Invoke-RegressionPlan 'apache' $ApacheManifestPath -Apache }
    $performanceGate = Invoke-PerformancePlan

    $gates = [Collections.Generic.List[object]]::new()
    $gates.Add($planGate) | Out-Null
    $gates.Add((New-GateRecord 'BUILD_REPRODUCIBLE' 'NOT_RUN' 'P0_10_BUILD_GATE_DEFERRED' @() ([ordered]@{}))) | Out-Null
    $gates.Add((Get-MavenFastGate)) | Out-Null
    foreach ($id in @('ARCHITECTURE', 'ENTRY_ANCHOR_POLICY')) { $gates.Add((New-GateRecord $id 'NOT_RUN' 'CONTRACT_NOT_IMPLEMENTED_IN_ACCEPTANCE_ORCHESTRATOR' @() ([ordered]@{}))) | Out-Null }
    $truthWp = Test-VerifiedApplicationTruth $script:WpManifestCheck.manifest_document
    $truthApache = Test-VerifiedApplicationTruth $script:ApacheManifestCheck.manifest_document
    $wpStaticStatus = if ($script:WpManifestCheck.status -ne 'PASS') { 'FAIL' } elseif (-not $truthWp -or $Profile -eq 'smoke' -or $wpRun.status -ne 'PASS') { 'NOT_RUN' } else { 'PASS' }
    $wpStaticReason = if ($script:WpManifestCheck.status -ne 'PASS') { 'WP_MANIFEST_INVALID' } elseif (-not $truthWp) { 'WP_TRUTH_UNVERIFIED' } elseif ($Profile -eq 'smoke') { 'PROFILE_SMOKE_PLAN_ONLY' } elseif ($wpRun.status -ne 'PASS') { 'WP_REGRESSION_FAILED' } else { 'WP_APPLICATION_CHAIN_PASS' }
    $gates.Add((New-GateRecord 'GLEIPNER_KERNEL' 'NOT_RUN' 'PROFILE_OR_TRUTH_DEFERRED' @() ([ordered]@{ manifest = $script:GleipnerManifestCheck.evidence }))) | Out-Null
    $gates.Add((New-GateRecord 'WP8_STATIC' $wpStaticStatus $wpStaticReason @() ([ordered]@{ truth_verified = $truthWp; regression = $wpRun.evidence; manifest = $script:WpManifestCheck.evidence }))) | Out-Null
    $dynamicReason = if (-not $TrustedTargetDynamic) { 'TRUSTED_TARGET_DYNAMIC_NOT_AUTHORIZED' } else { 'DYNAMIC_PLAN_COVERAGE_CONTRACT_PENDING' }
    $gates.Add((New-GateRecord 'WP8_DYNAMIC' 'NOT_RUN' $dynamicReason @() ([ordered]@{ target_code_execution_possible = [bool]$TrustedTargetDynamic; dangerous_sink = 'NOT_INVOKED' }))) | Out-Null
    $gates.Add((New-GateRecord 'DYNAMIC_TRIAGE' 'NOT_RUN' 'DYNAMIC_TRIAGE_CONTRACT_PENDING' @() ([ordered]@{}))) | Out-Null
    $apacheStaticStatus = if ($script:ApacheManifestCheck.status -ne 'PASS') { 'FAIL' } elseif (-not $truthApache -or $Profile -eq 'smoke' -or $apacheRun.status -ne 'PASS') { 'NOT_RUN' } else { 'PASS' }
    $apacheStaticReason = if ($script:ApacheManifestCheck.status -ne 'PASS') { 'APACHE_MANIFEST_INVALID' } elseif (-not $truthApache) { 'APACHE_TRUTH_UNVERIFIED' } elseif ($Profile -eq 'smoke') { 'PROFILE_SMOKE_APACHE_DEFERRED' } elseif ($apacheRun.status -ne 'PASS') { 'APACHE_REGRESSION_FAILED' } else { 'APACHE_APPLICATION_CHAIN_PASS' }
    $gates.Add((New-GateRecord 'APACHE_APPLICATION_CHAIN' $apacheStaticStatus $apacheStaticReason @() ([ordered]@{ truth_verified = $truthApache; regression = $apacheRun.evidence; manifest = $script:ApacheManifestCheck.evidence }))) | Out-Null
    foreach ($id in @('WINDOWS_CONTAINMENT', 'JDK_MATRIX', 'DETERMINISM', 'HOSTILE_INPUT_SAFETY', 'CLI_OFFLINE_CONTRACT', 'OUTPUT_AND_BASELINE', 'ROBUSTNESS_SOAK', 'USABILITY', 'RELEASE_SUPPLY_CHAIN', 'DOCS_RELEASE')) {
        $gates.Add((New-GateRecord $id 'NOT_RUN' 'CONTRACT_NOT_IMPLEMENTED_IN_ACCEPTANCE_ORCHESTRATOR' @() ([ordered]@{}))) | Out-Null
    }
    # Replace the performance placeholder at the fixed position while keeping gate order stable.
    $gates.Add($performanceGate) | Out-Null
    $ordered = [Collections.Generic.List[object]]::new()
    foreach ($id in $FixedGateIds) { $ordered.Add(@($gates | Where-Object { $_.id -eq $id })[0]) | Out-Null }
    $summary = Get-AggregateSummary $ordered.ToArray()
    $finished = (Get-Date).ToUniversalTime().ToString('o')
    $result = [ordered]@{
        schema_version = $SchemaVersion
        contract_id = $ExpectedContractId
        kind = 'acceptance-summary'
        profile = $Profile
        status = $summary.status
        started_at = $started
        finished_at = $finished
        plan = [ordered]@{ status = $planGate.status; path = Get-RepoRelative (Join-Path $RepoRoot 'docs\refactor-todo.md'); contract_id = $ExpectedContractId; state = Get-StringValue $planGate.details 'state' 'UNKNOWN'; next_item = Get-StringValue $planGate.details 'next_item' 'UNKNOWN'; evidence = @($planGate.evidence) }
        gates = @($ordered.ToArray())
        summary = $summary
        tooling = [ordered]@{ version = $ToolVersion; runner = Get-RepoRelative $PSCommandPath; runner_sha256 = Get-Sha256 $PSCommandPath; schema = Get-RepoRelative $SchemaPath; schema_sha256 = Get-Sha256 $SchemaPath; profile = $Profile; ci_contract = $ci; manifests = [ordered]@{ wp8 = $script:WpManifestCheck.evidence; gleipner = $script:GleipnerManifestCheck.evidence; apache = $script:ApacheManifestCheck.evidence }; regression = [ordered]@{ wp8 = $wpRun.evidence; apache = $apacheRun.evidence }; performance = $performanceGate.evidence }
        safety = [ordered]@{ verification_mode = if ($TrustedTargetDynamic -and $Profile -ne 'smoke') { 'AUTO' } else { 'STATIC_ONLY' }; target_code_execution_possible = [bool]($TrustedTargetDynamic -and $Profile -ne 'smoke'); target_code_executed = if ($TrustedTargetDynamic -and $Profile -ne 'smoke') { 'UNKNOWN_NOT_PROVEN' } else { 'NO' }; resource_containment_only = $true; filesystem_isolation = $false; network_isolation = $false; recommended_for_untrusted_artifacts = -not ($TrustedTargetDynamic -and $Profile -ne 'smoke'); target_trust = if ($TrustedTargetDynamic -and $Profile -ne 'smoke') { 'TRUSTED_LOCAL_TARGET_REQUIRED' } else { 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH' }; fail_closed_on_isolation_failure = $true; dangerous_sink = 'NOT_INVOKED_BY_ACCEPTANCE_CONTRACT'; network = 'NOT_REQUESTED'; file_write = 'ACCEPTANCE_ARTIFACTS_ONLY'; job_object = [ordered]@{ capability = 'RESOURCE_CONTAINMENT_ONLY'; complete_sandbox = $false; fail_closed_required = $true } }
    }
    $summaryPath = Join-Path $root 'acceptance-summary.json'
    $summaryValidator = Join-Path $PSScriptRoot 'validate-acceptance-summary.ps1'
    $result.tooling.summary_validation = [ordered]@{ status = 'PENDING'; validator = Get-RepoRelative $summaryValidator }
    Write-JsonAtomic $summaryPath $result
    $validationRun = Invoke-ChildScript 'summary-validator' $summaryValidator @('-SummaryPath', $summaryPath, '-Json') 120000
    $validationDoc = Get-JsonIfPresent (Join-Path $script:EvidenceRoot 'logs\summary-validator.stdout.log')
    $validationOk = ($validationRun.status -eq 'COMPLETED' -and $validationRun.exit_code -eq 0 -and $null -ne $validationDoc -and (Get-BooleanValue $validationDoc 'valid' $false))
    $result.tooling.summary_validation = [ordered]@{ status = if ($validationOk) { 'PASS' } else { 'FAIL' }; run = $validationRun; result = $validationDoc; validator = Get-RepoRelative $summaryValidator }
    if (-not $validationOk) { $result.status = 'FAIL'; $result.summary.status = 'FAIL' }
    Write-JsonAtomic $summaryPath $result
    if (-not $validationOk) { throw 'ACCEPTANCE_SUMMARY_SCHEMA_VALIDATION_FAILED' }
    return [ordered]@{ result = $result; path = $summaryPath }
}

try {
    if ($SelfTest) {
        $self = Invoke-SelfTest
        if ($Json) { $self | ConvertTo-Json -Depth 20 } else { Write-Output ('ACCEPTANCE_SELF_TEST=' + $self.status); Write-Output ('tests=' + ($self.tests -join ',')) }
        exit 0
    }
    if ($NoVerify) { $TrustedTargetDynamic = $false }
    $output = Invoke-Acceptance
    if ($Json) { $output.result | ConvertTo-Json -Depth 60 } else {
        Write-Output ('ACCEPTANCE_STATUS=' + $output.result.status)
        Write-Output ('ACCEPTANCE_SUMMARY=' + (Get-RepoRelative $output.path))
        foreach ($gate in @($output.result.gates)) { Write-Output ('GATE ' + $gate.id + ' ' + $gate.status + ' ' + $gate.reason_code) }
    }
    if ($output.result.status -ne 'PASS') { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('ACCEPTANCE_RUNNER_ERROR: ' + $_.Exception.Message + ' line=' + $_.InvocationInfo.ScriptLineNumber + ' position=' + $_.InvocationInfo.PositionMessage))
    exit 2
}
