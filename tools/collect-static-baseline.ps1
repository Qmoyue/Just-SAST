[CmdletBinding()]
param(
    [string] $ManifestPath,

    [string] $LauncherJar,

    [string] $OutputRoot,

    [ValidateSet('cold', 'hot', 'both')]
    [string] $Profile = 'both',

    [ValidateRange(0, 100)]
    [int] $Warmups = 0,

    [ValidateRange(1, 100)]
    [int] $Runs = 1,

    [switch] $Fast,

    [string[]] $CaseId,

    [string] $JabbaExe,

    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))
$RunnerPath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath 'run-regression-v2.ps1'))
$ValidatorPath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath 'validate-benchmark-manifest.ps1'))

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-TextValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [string] $Default = '')
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256 {
    param([AllowNull()] [string] $Text)
    $value = if ($null -eq $Text) { '' } else { $Text }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Label)
    $candidate = if ([IO.Path]::IsPathRooted($Value)) { [IO.Path]::GetFullPath($Value) } else { [IO.Path]::GetFullPath((Join-Path -Path $Base -ChildPath $Value)) }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "${Label}_MISSING: $candidate" }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item -isnot [IO.FileInfo]) { throw "${Label}_NOT_FILE: $candidate" }
    return $item.FullName
}

function Assert-OutputAvailable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path) { throw "OUTPUT_EXISTS: $Path" }
}

function Write-JsonAtomic {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Value | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $temp -Encoding UTF8
        Move-Item -LiteralPath $temp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Resolve-ProfileList {
    if ($Profile -eq 'both') { return @('cold', 'hot') }
    return @($Profile)
}

function Select-PlanCases {
    param([Parameter(Mandatory = $true)] [object[]] $Cases)
    $all = @($Cases | Sort-Object id)
    if ($null -eq $CaseId -or @($CaseId).Count -eq 0) { return $all }
    $wanted = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in @($CaseId)) {
        if (-not $wanted.Add([string]$id)) { throw "CASE_DUPLICATE: $id" }
    }
    $selected = @($all | Where-Object { $wanted.Contains((Get-TextValue $_ 'id')) })
    if ($selected.Count -ne $wanted.Count) { throw 'CASE_SELECTION_UNKNOWN_ID' }
    return $selected
}

function Invoke-Plan {
    param([Parameter(Mandatory = $true)] [string] $Manifest, [Parameter(Mandatory = $true)] [string] $Launcher, [Parameter(Mandatory = $true)] [string] $PlanRoot)
    $planOut = "$PlanRoot.plan.stdout.log"
    $planErr = "$PlanRoot.plan.stderr.log"
    $planParent = Split-Path -Parent $PlanRoot
    if (-not (Test-Path -LiteralPath $planParent -PathType Container)) { New-Item -ItemType Directory -Path $planParent -Force | Out-Null }
    $planArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $RunnerPath,
        '-ManifestPath', $Manifest, '-LauncherJar', $Launcher, '-OutputRoot', $PlanRoot,
        '-PlanOnly', '-NoVerify')
    if ($Fast) { $planArgs += '-Fast' }
    if (-not [string]::IsNullOrWhiteSpace($JabbaExe)) { $planArgs += @('-JabbaExe', $JabbaExe) }
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & powershell.exe @planArgs 1> $planOut 2> $planErr
        $exitCode = [int]$LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($exitCode -ne 0) { throw "PLAN_FAILED: exit=$exitCode stderr=$((Get-Content -LiteralPath $planErr -Raw -ErrorAction SilentlyContinue).Trim())" }
    $planManifest = Join-Path $PlanRoot 'run-manifest.json'
    if (-not (Test-Path -LiteralPath $planManifest -PathType Leaf)) { throw "PLAN_MANIFEST_MISSING: $planManifest" }
    return Get-Content -LiteralPath $planManifest -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-Perf {
    param(
        [Parameter(Mandatory = $true)] $PlanCase,
        [Parameter(Mandatory = $true)] [string] $ModeName,
        [Parameter(Mandatory = $true)] [string] $CaseRoot,
        [Parameter(Mandatory = $true)] [string] $Launcher
    )
    New-Item -ItemType Directory -Path $CaseRoot -Force | Out-Null
    $reportPath = Join-Path $CaseRoot 'performance.json'
    $stdoutPath = Join-Path $CaseRoot 'perf.stdout.log'
    $stderrPath = Join-Path $CaseRoot 'perf.stderr.log'
    $workPath = Join-Path $CaseRoot 'work'
    New-Item -ItemType Directory -Path $workPath -Force | Out-Null
    $java = Get-TextValue $PlanCase.command 'executable'
    $artifact = Get-TextValue $PlanCase.artifact 'path'
    $jdkHome = Get-TextValue $PlanCase.target_jdk 'home'
    if ([string]::IsNullOrWhiteSpace($java) -or [string]::IsNullOrWhiteSpace($artifact) -or [string]::IsNullOrWhiteSpace($jdkHome)) {
        throw "PLAN_CASE_INCOMPLETE: $(Get-TextValue $PlanCase 'id')"
    }
    $args = [Collections.Generic.List[string]]::new()
    foreach ($arg in @('-jar', $Launcher, 'perf', '--jar', $artifact, '--jdk-home', $jdkHome,
                       '--mode', $ModeName, '--warmups', [string]$Warmups, '--runs', [string]$Runs,
                       '--no-verify', '--launcher-jar', $Launcher, '--report', $reportPath,
                       '--work-dir', $workPath, '--process-timeout-ms', '1800000')) { $args.Add($arg) | Out-Null }
    if ($Fast) { $args.Add('--fast') | Out-Null }
    foreach ($dependency in @($PlanCase.dependencies)) {
        $dependencyPath = Get-TextValue $dependency 'path'
        if (-not [string]::IsNullOrWhiteSpace($dependencyPath)) {
            $args.Add('--deps') | Out-Null
            $args.Add($dependencyPath) | Out-Null
        }
    }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $exitCode = -1
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $java @($args.ToArray()) 1> $stdoutPath 2> $stderrPath
        $exitCode = [int]$LASTEXITCODE
    } finally {
        $watch.Stop()
        $ErrorActionPreference = $previous
    }
    $report = $null
    if (Test-Path -LiteralPath $reportPath -PathType Leaf) {
        try { $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $report = $null }
    }
    if ($null -eq $report) {
        $samples = @()
    } else {
        $samples = @($report.samples)
    }
    return [ordered]@{
        mode = $ModeName
        status = if ($exitCode -eq 0 -and $null -ne $report) { 'OBSERVED' } else { 'FAILED' }
        exit_code = $exitCode
        wall_ms = [long]$watch.ElapsedMilliseconds
        report = $reportPath
        report_sha256 = if (Test-Path -LiteralPath $reportPath -PathType Leaf) { Get-Sha256 $reportPath } else { $null }
        sample_count = $samples.Count
        warmups = $Warmups
        runs = $Runs
        fast = [bool]$Fast
        static_no_verify = $true
        completeness = @($samples | ForEach-Object { Get-TextValue $_ 'completeness' 'UNKNOWN' })
        chains_found = @($samples | ForEach-Object { [int](Get-PropertyValue $_ 'chains_found') })
        rss_peak_mb = @($samples | ForEach-Object { [long](Get-PropertyValue $_ 'rss_peak_mb') })
        result_digests = @($samples | ForEach-Object { Get-TextValue $_ 'result_digest' 'UNKNOWN' })
        stdout = $stdoutPath
        stderr = $stderrPath
    }
}

function Invoke-SelfTest {
    $checks = [Collections.Generic.List[object]]::new()
    $checks.Add([pscustomobject]@{ name = 'profile-both'; pass = ((Resolve-ProfileList) -join ',' -eq 'cold,hot') }) | Out-Null
    $checks.Add([pscustomobject]@{ name = 'profile-cold'; pass = $true }) | Out-Null
    if (@($checks | Where-Object { -not $_.pass }).Count -ne 0) { throw 'BASELINE_SELF_TEST_FAILED' }
    return [pscustomobject]@{ status = 'PASS'; tests = @($checks | ForEach-Object { $_.name }) }
}

if ($SelfTest) {
    $self = Invoke-SelfTest
    Write-Output "STATIC_BASELINE_SELF_TEST=$($self.status) tests=$($self.tests -join ',')"
    exit 0
}

try {
    if ([string]::IsNullOrWhiteSpace($ManifestPath) -or [string]::IsNullOrWhiteSpace($LauncherJar) -or [string]::IsNullOrWhiteSpace($OutputRoot)) {
        throw 'MANIFEST_LAUNCHER_OUTPUT_REQUIRED'
    }
    $manifestFile = Resolve-RegularFile $ManifestPath (Get-Location).Path 'manifest'
    $launcherFile = Resolve-RegularFile $LauncherJar (Get-Location).Path 'launcher'
    $manifestBase = Split-Path -Parent $manifestFile
    $manifest = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int](Get-PropertyValue $manifest 'schema_version') -ne 2) { throw 'MANIFEST_SCHEMA_UNSUPPORTED' }
    if ((Get-TextValue $manifest 'contract_id') -ne $ExpectedContractId) { throw 'CONTRACT_MISMATCH' }
    $root = [IO.Path]::GetFullPath($OutputRoot)
    Assert-OutputAvailable $root
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $planRoot = Join-Path $root '.plan'
    $plan = Invoke-Plan $manifestFile $launcherFile $planRoot
    $selected = Select-PlanCases @($plan.cases)
    $records = [Collections.Generic.List[object]]::new()
    foreach ($planCase in $selected) {
        $id = Get-TextValue $planCase 'id'
        foreach ($modeName in @(Resolve-ProfileList)) {
            $modeRoot = Join-Path $root ("$id-$modeName")
            $result = Invoke-Perf $planCase $modeName $modeRoot $launcherFile
            $records.Add([pscustomobject]@{
                id = $id
                mode = $modeName
                artifact = $planCase.artifact
                target_jdk = $planCase.target_jdk
                dependencies = @($planCase.dependencies)
                result = $result
            }) | Out-Null
            $partial = [ordered]@{
                schema_version = 1
                contract_id = $ExpectedContractId
                status = 'RUNNING'
                profile = $Profile
                fast = [bool]$Fast
                static_no_verify = $true
                manifest = [ordered]@{ path = $manifestFile; sha256 = Get-Sha256 $manifestFile; id = Get-TextValue $manifest 'manifest_id' }
                launcher = [ordered]@{ path = $launcherFile; sha256 = Get-Sha256 $launcherFile }
                cases = @($records.ToArray())
            }
            Write-JsonAtomic (Join-Path $root 'baseline.json') $partial
        }
    }
    $final = [ordered]@{
        schema_version = 1
        contract_id = $ExpectedContractId
        status = if (@($records | Where-Object { $_.result.status -ne 'OBSERVED' }).Count -eq 0) { 'COMPLETE' } else { 'FAILED' }
        profile = $Profile
        fast = [bool]$Fast
        static_no_verify = $true
        sample_count = $records.Count * $Runs
        p95_eligible = ($records.Count * $Runs -ge 20)
        manifest = [ordered]@{ path = $manifestFile; sha256 = Get-Sha256 $manifestFile; id = Get-TextValue $manifest 'manifest_id' }
        launcher = [ordered]@{ path = $launcherFile; sha256 = Get-Sha256 $launcherFile }
        tool = [ordered]@{ runner = $RunnerPath; runner_sha256 = Get-Sha256 $RunnerPath; validator = $ValidatorPath; validator_sha256 = Get-Sha256 $ValidatorPath }
        cases = @($records.ToArray())
        fingerprint = Get-TextSha256 ((@($records | ForEach-Object { "$($_.id)|$($_.mode)|$($_.result.report_sha256)|$($_.result.sample_count)" }) -join "`n"))
    }
    Write-JsonAtomic (Join-Path $root 'baseline.json') $final
    $final | ConvertTo-Json -Depth 40
    if ($final.status -ne 'COMPLETE') { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine("STATIC_BASELINE_ERROR: $($_.Exception.Message)")
    exit 2
}
