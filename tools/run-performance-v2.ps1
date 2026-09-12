[CmdletBinding()]
param(
    [ValidateSet('MICRO', 'SMOKE', 'PHASE', 'RELEASE')]
    [string] $Tier = 'SMOKE',

    [string] $ManifestPath = 'benchmark/manifest/wp8.v2.json',
    [string] $LauncherJar,
    [string] $OutputRoot,
    [string] $BaselinePath,
    [string] $DecisionLog,
    [string[]] $CaseId,
    [string[]] $RepresentativeCaseId,
    [string] $JabbaExe,
    [string] $LauncherJdkId = 'temurin@17.0.19',
    [ValidateRange(1, 30)]
    [int] $LauncherJdkFeature = 17,
    [switch] $NoVerify,
    [switch] $Fast,
    [switch] $PlanOnly,
    [switch] $UpdateBaseline,
    [ValidateRange(1, 86400000)]
    [long] $ProcessTimeoutMs = 1800000,
    [ValidateRange(1000, 100000000)]
    [int] $MicroIterations = 10000,
    [switch] $SelfTest
)

# Four-tier performance runner.  It owns scheduling, host/process telemetry and baseline
# comparison; scan semantics remain owned by the Java CLI and schema-v2 regression planner.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
$RunnerVersion = 'performance-runner-v2'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$PlanRunnerPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'run-regression-v2.ps1'))
$ManifestValidatorPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'validate-benchmark-manifest.ps1'))
$JdkDiscoveryModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'jdk-discovery-v1.psm1'))
Import-Module -Name $JdkDiscoveryModulePath -Force -DisableNameChecking -ErrorAction Stop
$Slo = [ordered]@{
    small = [ordered]@{ max_classes = 1500; warm_wall_ms = 15000; rss_mb = 1024; first_ms = 5000 }
    medium = [ordered]@{ max_classes = 5000; warm_wall_ms = 30000; rss_mb = 2048; first_ms = 10000 }
    large = [ordered]@{ max_classes = [int]::MaxValue; warm_wall_ms = 60000; rss_mb = 3072; first_ms = 20000 }
}

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
        return $Object[$Name]
    }
    if ($null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-StringValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [string] $Default = '')
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Get-LongValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [long] $Default = 0)
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { return $Default }
    try { return [long]$value } catch { return $Default }
}

function Get-BoolValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [bool] $Default = $false)
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return $Default }
    return [bool]$value
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256 {
    param([AllowNull()] [string] $Text)
    $value = if ($null -eq $Text) { '' } else { $Text }
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($value)))).Replace('-', '').ToLowerInvariant()
    } finally { $hash.Dispose() }
}

function Write-JsonAtomic {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temp = "$Path.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        $Value | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $temp -Encoding UTF8
        Move-Item -LiteralPath $temp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Assert-OutputAvailable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path) { throw "OUTPUT_EXISTS: $Path" }
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "${Label}_MISSING" }
    $candidate = if ([IO.Path]::IsPathRooted($Value)) { [IO.Path]::GetFullPath($Value) } else { [IO.Path]::GetFullPath((Join-Path $Base $Value)) }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "${Label}_MISSING: $candidate" }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item -isnot [IO.FileInfo]) { throw "${Label}_NOT_FILE: $candidate" }
    return $item.FullName
}

function Resolve-PowerShellExecutable {
    $edition = [string]$PSVersionTable.PSEdition
    $currentName = if ($edition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $current = Join-Path $PSHOME $currentName
    if (Test-Path -LiteralPath $current -PathType Leaf) { return [IO.Path]::GetFullPath($current) }
    $windows = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $windows -PathType Leaf) { return [IO.Path]::GetFullPath($windows) }
    $command = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) { return [IO.Path]::GetFullPath([string]$command.Source) }
    $command = Get-Command powershell -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) { return [IO.Path]::GetFullPath([string]$command.Source) }
    throw 'POWERSHELL_HOST_NOT_FOUND'
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    return '"' + $escaped + '"'
}

function Invoke-Capture {
    param([Parameter(Mandatory = $true)] [string] $FilePath, [Parameter(Mandatory = $true)] [string[]] $Arguments, [string] $WorkingDirectory)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        if ([string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            $lines = @(& $FilePath @Arguments 2>&1)
        } else {
            Push-Location $WorkingDirectory
            try { $lines = @(& $FilePath @Arguments 2>&1) } finally { Pop-Location }
        }
        return [pscustomobject]@{ exit_code = [int]$LASTEXITCODE; output = (($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim() }
    } finally { $ErrorActionPreference = $previous }
}

function Get-DeterministicFingerprint {
    param([Parameter(Mandatory = $true)] [string[]] $Lines)
    return Get-TextSha256 (($Lines | ForEach-Object { [string]$_ }) -join "`n")
}

function Get-NearestRank {
    param([AllowEmptyCollection()] [object[]] $Values, [double] $Quantile)
    $numbers = @($Values | ForEach-Object { [double]$_ } | Sort-Object)
    if ($numbers.Count -eq 0) { return $null }
    $rank = [int][Math]::Ceiling($Quantile * $numbers.Count)
    if ($rank -lt 1) { $rank = 1 }
    if ($rank -gt $numbers.Count) { $rank = $numbers.Count }
    return $numbers[$rank - 1]
}

function Get-Median {
    param([AllowEmptyCollection()] [object[]] $Values)
    $numbers = @($Values | ForEach-Object { [double]$_ } | Sort-Object)
    if ($numbers.Count -eq 0) { return $null }
    if (($numbers.Count % 2) -eq 1) { return $numbers[[int]($numbers.Count / 2)] }
    return ($numbers[($numbers.Count / 2) - 1] + $numbers[$numbers.Count / 2]) / 2.0
}

function Get-PercentileRecord {
    param([AllowEmptyCollection()] [object[]] $Values)
    $numbers = @($Values | ForEach-Object { [double]$_ } | Sort-Object)
    $median = Get-Median $numbers
    $eligible = $numbers.Count -ge 20
    return [ordered]@{
        sample_count = $numbers.Count
        median = $median
        max = if ($numbers.Count -eq 0) { $null } else { $numbers[-1] }
        p95 = if ($eligible) { Get-NearestRank $numbers 0.95 } else { $null }
        p95_eligible = $eligible
        p95_reason = if ($eligible) { 'NEAREST_RANK_95' } else { 'SAMPLE_COUNT_LT_20' }
        samples = @($numbers)
    }
}

function Get-TierSchedule {
    param([Parameter(Mandatory = $true)] [string] $Tier, [object[]] $Representatives)
    switch ($Tier) {
        'MICRO' { return [ordered]@{ modes = @('micro'); cold_runs = 0; warm_runs = 5; warmups = 1; representative_required = $false } }
        'SMOKE' { return [ordered]@{ modes = @('cold', 'hot'); cold_runs = 1; warm_runs = 3; warmups = 1; representative_required = $false } }
        'PHASE' { return [ordered]@{ modes = @('cold', 'hot'); cold_runs = 1; warm_runs = 5; warmups = 1; representative_required = $false } }
        'RELEASE' {
            $hasRepresentative = $null -ne $Representatives -and @($Representatives).Count -gt 0
            return [ordered]@{ modes = @('cold', 'hot'); cold_runs = 3; warm_runs = 10; warmups = 1; representative_cold_runs = 5; representative_warm_runs = 20; representative_required = $true; representative_configured = $hasRepresentative }
        }
        default { throw "TIER_UNSUPPORTED: $Tier" }
    }
}

function Normalize-RequestedCaseIds {
    param([AllowNull()] [object[]] $Values)
    $normalized = [Collections.Generic.List[string]]::new()
    foreach ($value in @($Values)) {
        if ($null -eq $value) {
            continue
        }
        $id = ([string]$value).Trim()
        if (-not [string]::IsNullOrWhiteSpace($id)) {
            $normalized.Add($id) | Out-Null
        }
    }
    return @($normalized.ToArray())
}

function Resolve-JabbaExecutable {
    param([string] $Requested)
    return Resolve-JabbaExecutableV1 -Requested $Requested -BasePath (Get-Location).Path -RepoRoot $RepoRoot
}

function Get-JdkHomeDigest {
    param([Parameter(Mandatory = $true)] [string] $JdkHomePath, [Parameter(Mandatory = $true)] [int] $Feature)
    return Get-JdkHomeDigestV1 -JdkHomePath $JdkHomePath -Feature $Feature
}

function Resolve-JdkProfile {
    param([Parameter(Mandatory = $true)] $JdkProfile, [Parameter(Mandatory = $true)] [string] $JabbaPath)
    return Resolve-JdkProfileV1 -JdkProfile $JdkProfile -JabbaPath $JabbaPath -BasePath (Get-Location).Path
}

function Get-MachineFingerprint {
    $memoryMb = -1L
    $memoryStatus = 'UNKNOWN'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        try {
            $machine = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $memoryMb = [long][Math]::Round(([double]$machine.TotalPhysicalMemory / 1MB), [MidpointRounding]::AwayFromZero)
            $memoryStatus = 'OBSERVED'
        } catch { $memoryStatus = 'ACCESS_DENIED_OR_UNAVAILABLE' }
    }
    $facts = @(
        "os=$([Environment]::OSVersion.Platform)",
        "os_version=$([Environment]::OSVersion.VersionString)",
        "arch=$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)",
        "cpu_count=$([Environment]::ProcessorCount)",
        "processor=$([string]$env:PROCESSOR_IDENTIFIER)",
        "powershell=$([string]$PSVersionTable.PSVersion)",
        "edition=$([string]$PSVersionTable.PSEdition)",
        "memory_mb=$memoryMb",
        "memory_status=$memoryStatus"
    )
    return [ordered]@{ os = [Environment]::OSVersion.Platform.ToString(); os_version = [Environment]::OSVersion.VersionString; architecture = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture; cpu_count = [int][Environment]::ProcessorCount; processor_identifier = [string]$env:PROCESSOR_IDENTIFIER; powershell = [string]$PSVersionTable.PSVersion; edition = [string]$PSVersionTable.PSEdition; memory_total_mb = $memoryMb; memory_status = $memoryStatus; fingerprint = Get-DeterministicFingerprint $facts }
}

function Get-ArchiveStats {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction Stop)
        $classes = @($files | Where-Object { $_.Name.EndsWith('.class', [StringComparison]::OrdinalIgnoreCase) })
        $bytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
        return [ordered]@{ kind = 'directory'; bytes = $bytes; classes = $classes.Count; methods = -1; instructions = -1; class_status = 'OBSERVED_DIRECTORY'; methods_status = 'NOT_OBSERVED'; instructions_status = 'NOT_OBSERVED' }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $classEntries = @($archive.Entries | Where-Object { $_.FullName.EndsWith('.class', [StringComparison]::OrdinalIgnoreCase) })
        $classBytes = [long](($classEntries | Measure-Object -Property Length -Sum).Sum)
        return [ordered]@{ kind = 'archive'; bytes = [long](Get-Item -LiteralPath $Path).Length; classes = $classEntries.Count; class_bytes = $classBytes; methods = -1; instructions = -1; class_status = 'OBSERVED_OUTER_ARCHIVE'; methods_status = 'NOT_OBSERVED_REQUIRES_BYTECODE_INDEX'; instructions_status = 'NOT_OBSERVED_REQUIRES_BYTECODE_INDEX' }
    } finally { $archive.Dispose() }
}

function New-ProcessTreeState {
    return [ordered]@{ status = 'NOT_SAMPLED'; source = 'Win32_Process+System.Diagnostics.Process'; reason_code = $null; root_pid = $null; sample_count = 0; sampling_interval_ms = 250; process_count_peak = 0; rss_peak_mb = -1; cpu_ms = -1 }
}

function Update-ProcessTreeState {
    param([Parameter(Mandatory = $true)] [System.Collections.IDictionary] $State, [Parameter(Mandatory = $true)] [int] $RootPid)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        if ($State.status -eq 'NOT_SAMPLED') { $State.status = 'UNSUPPORTED_PLATFORM'; $State.reason_code = 'PROCESS_TREE_WINDOWS_ONLY' }
        return
    }
    $State.root_pid = $RootPid
    try {
        $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId)
        $parents = @{}
        foreach ($row in $rows) {
            $pidValue = 0; $parentValue = 0
            if ([int]::TryParse([string]$row.ProcessId, [ref]$pidValue) -and [int]::TryParse([string]$row.ParentProcessId, [ref]$parentValue)) { $parents[$pidValue] = $parentValue }
        }
        $ids = [Collections.Generic.HashSet[int]]::new(); $ids.Add($RootPid) | Out-Null
        $changed = $true
        while ($changed) {
            $changed = $false
            foreach ($pair in $parents.GetEnumerator()) { if ($ids.Contains([int]$pair.Value) -and $ids.Add([int]$pair.Key)) { $changed = $true } }
        }
        $rss = [double]0; $cpu = [double]0; $observed = 0
        foreach ($pidValue in $ids) {
            try {
                $processInfo = Get-Process -Id ([int]$pidValue) -ErrorAction Stop
                $rss += [double]$processInfo.WorkingSet64
                try { $cpu += [double]$processInfo.TotalProcessorTime.TotalMilliseconds } catch { }
                $observed++
            } catch { }
        }
        if ($observed -le 0) { return }
        $State.sample_count = [int]$State.sample_count + 1
        $State.process_count_peak = [Math]::Max([int]$State.process_count_peak, $observed)
        $State.rss_peak_mb = [Math]::Max([long]$State.rss_peak_mb, [long][Math]::Ceiling($rss / 1MB))
        $State.cpu_ms = [Math]::Max([long]$State.cpu_ms, [long][Math]::Round($cpu, [MidpointRounding]::AwayFromZero))
        $State.status = 'SAMPLED'; $State.reason_code = $null
    } catch {
        if ($State.status -ne 'SAMPLED') { $State.status = 'NOT_SAMPLED'; $State.reason_code = if ($_.Exception -is [Microsoft.Management.Infrastructure.CimException]) { 'PROCESS_TREE_ACCESS_DENIED' } else { 'PROCESS_TREE_SAMPLE_FAILED' } }
    }
}

function Find-FirstResultFileMs {
    param([Parameter(Mandatory = $true)] [string] $Root, [Parameter(Mandatory = $true)] [long] $ElapsedMs)
    try {
        $files = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter 'findings.csv' -ErrorAction SilentlyContinue)
        foreach ($file in $files) {
            if ($file.Length -ge 0) { return $ElapsedMs }
        }
    } catch { }
    return -1L
}

function Invoke-PerfProcess {
    param([Parameter(Mandatory = $true)] [string] $JavaPath, [Parameter(Mandatory = $true)] [string[]] $Arguments, [Parameter(Mandatory = $true)] [string] $WorkingDirectory, [Parameter(Mandatory = $true)] [string] $StdoutPath, [Parameter(Mandatory = $true)] [string] $StderrPath, [Parameter(Mandatory = $true)] [long] $TimeoutMs, [Parameter(Mandatory = $true)] [string] $ObservationRoot)
    $quoted = @($Arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' '
    $process = $null; $stdoutTask = $null; $stderrTask = $null; $watch = [Diagnostics.Stopwatch]::StartNew(); $tree = New-ProcessTreeState; $firstResultMs = -1L; $timedOut = $false
    try {
        # Start-Process in Windows PowerShell fails when the desktop environment exposes
        # both PATH and Path variables.  ProcessStartInfo avoids rebuilding that dictionary
        # while retaining redirected streams and deterministic arguments.
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $JavaPath
        $startInfo.Arguments = $quoted
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'PERF_PROCESS_START_FAILED' }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        Update-ProcessTreeState $tree ([int]$process.Id)
        while ($true) {
            $elapsed = [long]$watch.ElapsedMilliseconds
            if ($firstResultMs -lt 0) { $candidate = Find-FirstResultFileMs $ObservationRoot $elapsed; if ($candidate -ge 0) { $firstResultMs = $candidate } }
            Update-ProcessTreeState $tree ([int]$process.Id)
            $remaining = $TimeoutMs - $elapsed
            if ($remaining -le 0) { $timedOut = $true; break }
            if ($process.WaitForExit([int][Math]::Min(100L, $remaining))) { break }
        }
        if ($timedOut) {
            try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
            $process.WaitForExit(5000) | Out-Null
        }
        if ($null -ne $stdoutTask) { [IO.File]::WriteAllText($StdoutPath, $stdoutTask.Result) }
        if ($null -ne $stderrTask) { [IO.File]::WriteAllText($StderrPath, $stderrTask.Result) }
        if ($firstResultMs -lt 0) { $candidate = Find-FirstResultFileMs $ObservationRoot ([long]$watch.ElapsedMilliseconds); if ($candidate -ge 0) { $firstResultMs = $candidate } }
        Update-ProcessTreeState $tree ([int]$process.Id)
        $tree.reason_code = if ($timedOut) { 'PROCESS_TIMEOUT' } elseif ($tree.status -eq 'NOT_SAMPLED' -and $null -eq $tree.reason_code) { 'PROCESS_TREE_NOT_OBSERVED' } else { $tree.reason_code }
        return [ordered]@{ status = if ($timedOut) { 'TIMEOUT' } elseif ($process.ExitCode -eq 0) { 'COMPLETED' } else { 'FAILED' }; exit_code = if ($timedOut) { 124 } else { [int]$process.ExitCode }; process_id = [int]$process.Id; wall_ms = [long]$watch.ElapsedMilliseconds; time_to_first_ms = $firstResultMs; process_tree = $tree }
    } catch {
        return [ordered]@{ status = 'FAILED'; exit_code = -1; process_id = if ($null -eq $process) { $null } else { [int]$process.Id }; wall_ms = [long]$watch.ElapsedMilliseconds; time_to_first_ms = $firstResultMs; process_tree = $tree; failure = $_.Exception.Message }
    } finally { $watch.Stop() }
}

function Get-PlanManifest {
    param([Parameter(Mandatory = $true)] [string] $ManifestFile, [Parameter(Mandatory = $true)] [string] $LauncherFile, [Parameter(Mandatory = $true)] [string] $PlanRoot, [object[]] $RequestedCases)
    Assert-OutputAvailable $PlanRoot
    $hostPath = Resolve-PowerShellExecutable
    $logRoot = "$PlanRoot.logs"
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $stdout = Join-Path $logRoot 'plan.stdout.log'; $stderr = Join-Path $logRoot 'plan.stderr.log'
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PlanRunnerPath, '-ManifestPath', $ManifestFile, '-LauncherJar', $LauncherFile, '-OutputRoot', $PlanRoot, '-PlanOnly', '-Fast')
    if (-not $Fast) { $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PlanRunnerPath, '-ManifestPath', $ManifestFile, '-LauncherJar', $LauncherFile, '-OutputRoot', $PlanRoot, '-PlanOnly') }
    if ($NoVerify) { $arguments += '-NoVerify' }
    foreach ($id in @(Normalize-RequestedCaseIds $RequestedCases)) { $arguments += @('-CaseId', $id) }
    if (-not [string]::IsNullOrWhiteSpace($JabbaExe)) { $arguments += @('-JabbaExe', $JabbaExe) }
    $previous = $ErrorActionPreference
    try { $ErrorActionPreference = 'Continue'; & $hostPath @arguments 1> $stdout 2> $stderr; $code = [int]$LASTEXITCODE } finally { $ErrorActionPreference = $previous }
    if ($code -ne 0) { throw "PLAN_FAILED: exit=$code" }
    $planPath = Join-Path $PlanRoot 'run-manifest.json'
    if (-not (Test-Path -LiteralPath $planPath -PathType Leaf)) { throw 'PLAN_MANIFEST_MISSING' }
    return Get-Content -LiteralPath $planPath -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Get-PlanCaseById {
    param([Parameter(Mandatory = $true)] $Plan, [Parameter(Mandatory = $true)] [string] $Id)
    foreach ($candidate in @($Plan.cases)) { if ((Get-StringValue $candidate 'id' '') -eq $Id) { return $candidate } }
    throw "PLAN_CASE_MISSING: $Id"
}

function Get-PerfArguments {
    param([Parameter(Mandatory = $true)] $PlanCase, [Parameter(Mandatory = $true)] [string] $ModeName, [Parameter(Mandatory = $true)] [int] $Runs, [Parameter(Mandatory = $true)] [int] $Warmups, [Parameter(Mandatory = $true)] [string] $LauncherFile, [Parameter(Mandatory = $true)] [string] $ReportPath, [Parameter(Mandatory = $true)] [string] $WorkDirectory)
    $arguments = [Collections.Generic.List[string]]::new()
    foreach ($value in @('-jar', $LauncherFile, 'perf', '--jar', (Get-StringValue $PlanCase.artifact 'path' ''), '--jdk-home', (Get-StringValue $PlanCase.target_jdk 'home' ''), '--mode', $ModeName, '--warmups', [string]$Warmups, '--runs', [string]$Runs, '--report', $ReportPath, '--work-dir', $WorkDirectory, '--process-timeout-ms', [string]$ProcessTimeoutMs, '--launcher-jar', $LauncherFile)) { $arguments.Add([string]$value) | Out-Null }
    if ($NoVerify) { $arguments.Add('--no-verify') | Out-Null }
    if ($Fast) { $arguments.Add('--fast') | Out-Null }
    foreach ($dependency in @($PlanCase.dependencies)) {
        $dependencyPath = Get-StringValue $dependency 'path' ''
        if (-not [string]::IsNullOrWhiteSpace($dependencyPath)) { $arguments.Add('--deps') | Out-Null; $arguments.Add($dependencyPath) | Out-Null }
    }
    return $arguments.ToArray()
}

function Get-PerformanceSamples {
    param([Parameter(Mandatory = $true)] $Report, [Parameter(Mandatory = $true)] $Execution)
    $samples = [Collections.Generic.List[object]]::new()
    foreach ($sample in @($Report.samples)) {
        $samples.Add([ordered]@{ iteration = [int](Get-LongValue $sample 'iteration' 0); wall_ms = [long](Get-LongValue $sample 'wall_ms' 0); static_ms = [long](Get-LongValue $sample 'static_ms' 0); dynamic_ms = [long](Get-LongValue $sample 'dynamic_ms' 0); heap_used_mb = [long](Get-LongValue $sample 'heap_used_mb' 0); heap_peak_mb = [long](Get-LongValue $sample 'heap_peak_mb' 0); rss_peak_mb = [long](Get-LongValue $sample 'rss_peak_mb' -1); chains_found = [long](Get-LongValue $sample 'chains_found' 0); completeness = Get-StringValue $sample 'completeness' 'UNKNOWN'; result_digest = Get-StringValue $sample 'result_digest' 'UNKNOWN'; phase_ms = Get-PropertyValue $sample 'phase_ms'; resource_metrics = Get-PropertyValue $sample 'resource_metrics'; verification_candidate_ms = Get-PropertyValue $sample 'verification_candidate_ms'; time_to_first_ms = [long](Get-LongValue $Execution 'time_to_first_ms' -1) }) | Out-Null
    }
    return @($samples.ToArray())
}

function Get-ModeRecord {
    param([Parameter(Mandatory = $true)] [string] $CaseIdValue, [Parameter(Mandatory = $true)] $PlanCase, [Parameter(Mandatory = $true)] [string] $ModeName, [Parameter(Mandatory = $true)] [int] $Runs, [Parameter(Mandatory = $true)] [int] $Warmups, [Parameter(Mandatory = $true)] [string] $CaseRoot, [Parameter(Mandatory = $true)] [string] $LauncherFile)
    New-Item -ItemType Directory -Path $CaseRoot -Force | Out-Null
    $reportPath = Join-Path $CaseRoot 'performance.json'; $stdoutPath = Join-Path $CaseRoot 'perf.stdout.log'; $stderrPath = Join-Path $CaseRoot 'perf.stderr.log'; $workDirectory = Join-Path $CaseRoot 'work'
    New-Item -ItemType Directory -Path $workDirectory -Force | Out-Null
    $arguments = Get-PerfArguments $PlanCase $ModeName $Runs $Warmups $LauncherFile $reportPath $workDirectory
    $execution = if ($PlanOnly) { [ordered]@{ status = 'NOT_RUN_PLAN_ONLY'; exit_code = $null; process_id = $null; wall_ms = 0; time_to_first_ms = -1; process_tree = [ordered]@{ status = 'NOT_RUN'; source = 'plan-only'; reason_code = 'PERF_PLAN_ONLY' } } } else { Invoke-PerfProcess (Get-StringValue $PlanCase.command 'executable' '') $arguments $RepoRoot $stdoutPath $stderrPath $ProcessTimeoutMs $workDirectory }
    $report = $null
    if (-not $PlanOnly -and (Test-Path -LiteralPath $reportPath -PathType Leaf)) { try { $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $report = $null } }
    $samples = if ($null -eq $report) { @() } else { Get-PerformanceSamples $report $execution }
    $sampleDigests = @($samples | ForEach-Object { Get-StringValue $_ 'result_digest' 'UNKNOWN' })
    $completeness = @($samples | ForEach-Object { Get-StringValue $_ 'completeness' 'UNKNOWN' })
    $chains = @($samples | ForEach-Object { [long](Get-LongValue $_ 'chains_found' 0) })
    $sampleCount = @($samples).Length
    $digestUniqueCount = @($sampleDigests | Select-Object -Unique).Length
    $completenessUniqueCount = @($completeness | Select-Object -Unique).Length
    $chainUniqueCount = @($chains | Select-Object -Unique).Length
    $semanticStable = $sampleCount -gt 0 -and $digestUniqueCount -eq 1 -and $completenessUniqueCount -eq 1 -and $chainUniqueCount -eq 1
    $status = if ($PlanOnly) { 'NOT_RUN' } elseif ($null -eq $report -or $execution.status -ne 'COMPLETED') { 'FAILED' } elseif (-not $semanticStable -or -not (Get-BoolValue $report 'result_digest_stable' $false)) { 'SEMANTIC_MISMATCH' } else { 'OBSERVED' }
    return [ordered]@{ id = $CaseIdValue; mode = $ModeName; status = $status; runs = $Runs; warmups = $Warmups; report = $reportPath; report_sha256 = if (Test-Path -LiteralPath $reportPath -PathType Leaf) { Get-Sha256 $reportPath } else { $null }; execution = $execution; samples = @($samples); semantic = [ordered]@{ stable = $semanticStable; digests = $sampleDigests; completeness = $completeness; chains_found = $chains }; dynamic = [ordered]@{ requested = if ($NoVerify) { 'DISABLED' } else { 'AUTO_TRUSTED_TARGET' }; target_code_execution_possible = -not $NoVerify; target_code_executed = if ($NoVerify) { 'NO' } else { 'UNKNOWN'; }; dangerous_sink = 'NOT_INVOKED_BY_PERFORMANCE_CONTRACT'; network = 'NOT_REQUESTED'; file_write = 'REPORT_WORK_ONLY'; job_object = [ordered]@{ capability = 'RESOURCE_CONTAINMENT_ONLY'; complete_sandbox = $false } } }
}

function Get-SemanticDigest {
    param([object[]] $ModeRecords)
    $lines = [Collections.Generic.List[string]]::new()
    foreach ($record in @($ModeRecords | Sort-Object id, mode)) {
        foreach ($sample in @($record.samples | Sort-Object iteration)) { $lines.Add("$($record.id)|$($record.mode)|$($sample.iteration)|$($sample.result_digest)|$($sample.completeness)|$($sample.chains_found)") | Out-Null }
    }
    if ($lines.Count -eq 0) { return 'UNKNOWN' }
    return Get-DeterministicFingerprint $lines.ToArray()
}

function Get-ModeSummary {
    param([object[]] $ModeRecords)
    $allSamples = @($ModeRecords | ForEach-Object { $_.samples })
    $wall = Get-PercentileRecord @($allSamples | ForEach-Object { [long](Get-LongValue $_ 'wall_ms' 0) })
    $static = Get-PercentileRecord @($allSamples | ForEach-Object { [long](Get-LongValue $_ 'static_ms' 0) })
    $first = Get-PercentileRecord @($allSamples | Where-Object { [long](Get-LongValue $_ 'time_to_first_ms' -1) -ge 0 } | ForEach-Object { [long](Get-LongValue $_ 'time_to_first_ms' -1) })
    $rss = @($ModeRecords | ForEach-Object { Get-LongValue $_.execution.process_tree 'rss_peak_mb' -1 } | Where-Object { $_ -ge 0 })
    $cpu = @($ModeRecords | ForEach-Object { Get-LongValue $_.execution.process_tree 'cpu_ms' -1 } | Where-Object { $_ -ge 0 })
    return [ordered]@{ wall_ms = $wall; static_ms = $static; time_to_first_ms = $first; rss_peak_mb = Get-PercentileRecord $rss; cpu_ms = Get-PercentileRecord $cpu; process_tree_status = @($ModeRecords | ForEach-Object { Get-StringValue $_.execution.process_tree 'status' 'UNKNOWN' } | Sort-Object -Unique); sample_count = @($allSamples).Length }
}

function Get-WorkloadClass {
    param([long] $Classes)
    if ($Classes -lt 0) { return 'UNKNOWN' }
    if ($Classes -le [long]$Slo.small.max_classes) { return 'small' }
    if ($Classes -le [long]$Slo.medium.max_classes) { return 'medium' }
    return 'large'
}

function Get-SloEvaluation {
    param([object[]] $ModeRecords, [object[]] $Workloads)
    $issues = [Collections.Generic.List[string]]::new(); $observed = [Collections.Generic.List[object]]::new()
    foreach ($workload in @($Workloads)) {
        $caseModes = @($ModeRecords | Where-Object { $_.id -eq $workload.id })
        $class = Get-WorkloadClass ([long](Get-LongValue $workload.stats 'classes' -1))
        if ($class -eq 'UNKNOWN' -or -not $Slo.Contains($class)) { $issues.Add("$($workload.id):WORKLOAD_SIZE_UNKNOWN") | Out-Null; continue }
        $target = $Slo[$class]
        $hot = @($caseModes | Where-Object { $_.mode -eq 'hot' })
        $cold = @($caseModes | Where-Object { $_.mode -eq 'cold' })
        if (@($hot).Length -eq 0) { continue }
        $hotSummary = Get-ModeSummary $hot; $coldSummary = if (@($cold).Length -gt 0) { Get-ModeSummary $cold } else { $null }
        $wallMedian = $hotSummary.wall_ms.median
        $rssMedian = $hotSummary.rss_peak_mb.median
        $firstMedian = $hotSummary.time_to_first_ms.median
        if ($null -eq $wallMedian -or $wallMedian -gt [double]$target.warm_wall_ms) { $issues.Add("$($workload.id):WARM_WALL_SLO_FAIL") | Out-Null }
        if ($null -eq $rssMedian -or $rssMedian -lt 0 -or $rssMedian -gt [double]$target.rss_mb) { $issues.Add("$($workload.id):RSS_SLO_FAIL") | Out-Null }
        if ($null -eq $firstMedian -or $firstMedian -lt 0) { $issues.Add("$($workload.id):TIME_TO_FIRST_NOT_OBSERVED") | Out-Null } elseif ($firstMedian -gt [double]$target.first_ms) { $issues.Add("$($workload.id):TIME_TO_FIRST_SLO_FAIL") | Out-Null }
        if ($null -ne $coldSummary -and $null -ne $coldSummary.wall_ms.median -and $coldSummary.wall_ms.median -gt (2.0 * [double]$target.warm_wall_ms)) { $issues.Add("$($workload.id):COLD_WALL_SLO_FAIL") | Out-Null }
        $observed.Add([ordered]@{ id = $workload.id; size_class = $class; class_count = [long](Get-LongValue $workload.stats 'classes' -1); targets = $target; hot = $hotSummary; cold = $coldSummary }) | Out-Null
    }
    return [ordered]@{ status = if ($issues.Count -eq 0) { 'PASS' } else { 'FAIL' }; issues = @($issues); cases = @($observed.ToArray()); note = 'Absolute SLO is evaluated independently from semantic correctness; current historical multi-GB/long runs are expected to remain red until solver/resource phases close them.' }
}

function Get-Comparison {
    param([Parameter(Mandatory = $true)] $Candidate, [string] $ExistingPath)
    if ([string]::IsNullOrWhiteSpace($ExistingPath) -or -not (Test-Path -LiteralPath $ExistingPath -PathType Leaf)) { return [ordered]@{ status = 'NO_LOCKED_BASELINE'; reason_code = 'BASELINE_MISSING'; cases = @() } }
    $existing = Get-Content -LiteralPath $ExistingPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ((Get-StringValue $existing 'contract_id' '') -ne $ExpectedContractId) { throw 'BASELINE_CONTRACT_MISMATCH' }
    if ((Get-StringValue $existing 'comparison_fingerprint' '') -ne (Get-StringValue $Candidate 'comparison_fingerprint' '')) { return [ordered]@{ status = 'INCOMPARABLE'; reason_code = 'WORKLOAD_OR_CONFIG_FINGERPRINT_MISMATCH'; cases = @() } }
    if ((Get-StringValue $existing 'semantic_digest' '') -ne (Get-StringValue $Candidate 'semantic_digest' '')) { return [ordered]@{ status = 'INCOMPARABLE'; reason_code = 'SEMANTIC_DIGEST_MISMATCH'; cases = @() } }
    $rows = [Collections.Generic.List[object]]::new(); $failed = $false
    foreach ($case in @($Candidate.cases)) {
        $oldCase = @($existing.cases | Where-Object { $_.id -eq $case.id -and $_.mode -eq $case.mode }) | Select-Object -First 1
        if ($null -eq $oldCase) { $rows.Add([ordered]@{ id = $case.id; mode = $case.mode; status = 'MISSING_BASELINE' }) | Out-Null; $failed = $true; continue }
        $oldMedian = Get-PropertyValue (Get-PropertyValue $oldCase 'summary') 'wall_median_ms'
        $newMedian = Get-PropertyValue (Get-PropertyValue $case 'summary') 'wall_median_ms'
        $ratio = if ($null -eq $oldMedian -or [double]$oldMedian -le 0) { $null } else { [double]$newMedian / [double]$oldMedian }
        $status = if ($null -ne $ratio -and $ratio -le 1.10) { 'PASS' } else { 'FAIL' }
        if ($status -ne 'PASS') { $failed = $true }
        $rows.Add([ordered]@{ id = $case.id; mode = $case.mode; baseline_wall_median_ms = $oldMedian; candidate_wall_median_ms = $newMedian; ratio = $ratio; status = $status; threshold = 1.10 }) | Out-Null
    }
    return [ordered]@{ status = if ($failed) { 'FAIL' } else { 'PASS' }; reason_code = if ($failed) { 'WARM_MEDIAN_REGRESSION' } else { 'WITHIN_1_10X' }; cases = @($rows.ToArray()) }
}

function Update-BaselineIfRequested {
    param([Parameter(Mandatory = $true)] $Candidate)
    if (-not $UpdateBaseline) { return [ordered]@{ status = 'NOT_REQUESTED'; path = $null; previous = $null } }
    if ([string]::IsNullOrWhiteSpace($BaselinePath)) { throw 'BASELINE_PATH_REQUIRED_FOR_UPDATE' }
    $target = [IO.Path]::GetFullPath($BaselinePath)
    $existing = $null
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        if ([string]::IsNullOrWhiteSpace($DecisionLog) -or -not (Test-Path -LiteralPath $DecisionLog -PathType Leaf)) { throw 'DECISION_LOG_REQUIRED_FOR_BASELINE_UPDATE' }
        $existing = Get-Content -LiteralPath $target -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Get-StringValue $existing 'semantic_digest' '') -ne (Get-StringValue $Candidate 'semantic_digest' '')) { throw 'BASELINE_SEMANTIC_DIGEST_MISMATCH' }
        if ((Get-StringValue $existing 'comparison_fingerprint' '') -ne (Get-StringValue $Candidate 'comparison_fingerprint' '')) { throw 'BASELINE_WORKLOAD_FINGERPRINT_MISMATCH' }
    }
    $parent = Split-Path -Parent $target
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $previousPath = $null
    if ($null -ne $existing) {
        $previousPath = "$target.previous.$((Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')).json"
        Copy-Item -LiteralPath $target -Destination $previousPath -Force
    }
    Write-JsonAtomic $target $Candidate
    return [ordered]@{ status = if ($null -eq $existing) { 'INITIALIZED' } else { 'UPDATED' }; path = $target; previous = $previousPath; decision_log = if ([string]::IsNullOrWhiteSpace($DecisionLog)) { $null } else { [IO.Path]::GetFullPath($DecisionLog) } }
}

function Invoke-Micro {
    param([Parameter(Mandatory = $true)] $Schedule)
    $records = [Collections.Generic.List[object]]::new()
    for ($i = 1; $i -le $Schedule.warm_runs; $i++) {
        $watch = [Diagnostics.Stopwatch]::StartNew(); $map = [Collections.Generic.Dictionary[string, int]]::new()
        for ($j = 0; $j -lt $MicroIterations; $j++) { $key = 'k' + ($j % 257); if ($map.ContainsKey($key)) { $map[$key] = $map[$key] + 1 } else { $map[$key] = 1 } }
        $watch.Stop(); $digest = Get-DeterministicFingerprint @('entries=' + $map.Count, 'sum=' + (($map.Values | Measure-Object -Sum).Sum), 'iterations=' + $MicroIterations)
        $records.Add([ordered]@{ id = 'synthetic-map-reducer'; mode = 'micro'; status = 'OBSERVED'; runs = $Schedule.warm_runs; warmups = $Schedule.warmups; report = $null; report_sha256 = $null; execution = [ordered]@{ status = 'COMPLETED'; exit_code = 0; process_id = $PID; wall_ms = [long]$watch.ElapsedMilliseconds; time_to_first_ms = [long]$watch.ElapsedMilliseconds; process_tree = [ordered]@{ status = 'NOT_APPLICABLE'; source = 'in-process-micro-harness'; reason_code = 'PERF_MICRO_SYNTHETIC' } }; samples = @([ordered]@{ iteration = $i; wall_ms = [long]$watch.ElapsedMilliseconds; static_ms = [long]$watch.ElapsedMilliseconds; dynamic_ms = 0; heap_used_mb = 0; heap_peak_mb = 0; rss_peak_mb = -1; chains_found = $map.Count; completeness = 'COMPLETE'; result_digest = $digest; phase_ms = @{}; resource_metrics = @{}; verification_candidate_ms = @{}; time_to_first_ms = [long]$watch.ElapsedMilliseconds }); semantic = [ordered]@{ stable = $true; digests = @($digest); completeness = @('COMPLETE'); chains_found = @($map.Count) }; dynamic = [ordered]@{ requested = 'NOT_APPLICABLE'; target_code_execution_possible = $false; target_code_executed = 'NO'; dangerous_sink = 'NOT_APPLICABLE'; network = 'NOT_REQUESTED'; file_write = 'NONE'; job_object = [ordered]@{ capability = 'NOT_APPLICABLE'; complete_sandbox = $false } } }) | Out-Null
    }
    return @($records.ToArray())
}

function Invoke-SelfTest {
    $checks = [Collections.Generic.List[string]]::new()
    $microSchedule = Get-TierSchedule 'MICRO' @(); if ($microSchedule.warm_runs -eq 5 -and $microSchedule.warmups -eq 1) { $checks.Add('micro-schedule') | Out-Null } else { throw 'SELFTEST_MICRO_SCHEDULE' }
    $smokeSchedule = Get-TierSchedule 'SMOKE' @(); if ($smokeSchedule.cold_runs -eq 1 -and $smokeSchedule.warm_runs -eq 3) { $checks.Add('smoke-schedule') | Out-Null } else { throw 'SELFTEST_SMOKE_SCHEDULE' }
    $releaseSchedule = Get-TierSchedule 'RELEASE' @('representative'); if ($releaseSchedule.representative_cold_runs -eq 5 -and $releaseSchedule.representative_warm_runs -eq 20) { $checks.Add('release-schedule') | Out-Null } else { throw 'SELFTEST_RELEASE_SCHEDULE' }
    $normalizedCases = @(Normalize-RequestedCaseIds @($null, ' ', 'babychain'))
    if ($normalizedCases.Count -ne 1 -or $normalizedCases[0] -ne 'babychain') { throw 'SELFTEST_CASE_ID_NORMALIZATION' }
    $checks.Add('case-id-normalization') | Out-Null
    $short = Get-PercentileRecord @(10, 20, 30); if ($short.p95_eligible -or $null -ne $short.p95) { throw 'SELFTEST_P95_SMALL_SAMPLE' } else { $checks.Add('p95-minimum-samples') | Out-Null }
    $longValues = 1..20; $long = Get-PercentileRecord $longValues; if (-not $long.p95_eligible -or $long.p95 -ne 19) { throw 'SELFTEST_NEAREST_RANK' } else { $checks.Add('nearest-rank-p95') | Out-Null }
    $temp = Join-Path ([IO.Path]::GetTempPath()) ('just-perf-selftest-' + [Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $temp | Out-Null
    try {
        $existing = Join-Path $temp 'baseline.json'; Set-Content -LiteralPath $existing -Value '{"contract_id":"JUST-PROD-D009-V1","semantic_digest":"old","comparison_fingerprint":"old"}' -Encoding UTF8
        $noAutomaticWrite = Update-BaselineIfRequested ([ordered]@{ semantic_digest = 'new'; comparison_fingerprint = 'new' })
        if ($noAutomaticWrite.status -ne 'NOT_REQUESTED') { throw 'SELFTEST_BASELINE_AUTO_WRITE' }
        $script:UpdateBaseline = $true; $script:BaselinePath = $existing; $script:DecisionLog = ''
        $overwriteRejected = $false
        try { Update-BaselineIfRequested ([ordered]@{ semantic_digest = 'new'; comparison_fingerprint = 'new' }) | Out-Null } catch { $overwriteRejected = $_.Exception.Message -match 'DECISION_LOG_REQUIRED_FOR_BASELINE_UPDATE' }
        if (-not $overwriteRejected) { throw 'SELFTEST_BASELINE_EXPLICIT_UPDATE' }
        $decision = Join-Path $temp 'decision.md'; Set-Content -LiteralPath $decision -Value 'self-test decision' -Encoding UTF8
        $script:DecisionLog = $decision
        $updated = Update-BaselineIfRequested ([ordered]@{ semantic_digest = 'old'; comparison_fingerprint = 'old' })
        if ($updated.status -ne 'UPDATED' -or [string]::IsNullOrWhiteSpace([string]$updated.previous) -or -not (Test-Path -LiteralPath $updated.previous -PathType Leaf)) { throw 'SELFTEST_BASELINE_BACKUP_FAILED' }
        $script:UpdateBaseline = $false; $script:BaselinePath = ''; $script:DecisionLog = ''
        $checks.Add('explicit-update-required') | Out-Null; $checks.Add('previous-value-preserved') | Out-Null
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force } }
    return [pscustomobject]@{ status = 'PASS'; tests = @($checks.ToArray()) }
}

function Invoke-Performance {
    $representatives = @($RepresentativeCaseId)
    $schedule = Get-TierSchedule $Tier $representatives
    if ($Tier -eq 'RELEASE' -and -not [bool]$schedule.representative_configured) { throw 'RELEASE_REPRESENTATIVE_CASE_REQUIRED' }
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path (Join-Path $RepoRoot 'benchmark\runs') ('p09-performance-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $root = [IO.Path]::GetFullPath($OutputRoot); Assert-OutputAvailable $root; New-Item -ItemType Directory -Path $root | Out-Null
    $machine = Get-MachineFingerprint
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $manifestFile = $null; $launcherFile = $null; $manifest = $null; $plan = $null; $planRoot = Join-Path $root '.plan'; $workloads = [Collections.Generic.List[object]]::new(); $records = [Collections.Generic.List[object]]::new()
    if ($Tier -eq 'MICRO') {
        foreach ($record in @(Invoke-Micro $schedule)) { $records.Add($record) | Out-Null }
    } else {
        $manifestFile = Resolve-RegularFile $ManifestPath (Get-Location).Path 'manifest'; $launcherFile = Resolve-RegularFile $LauncherJar (Get-Location).Path 'launcher'; $manifest = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int](Get-PropertyValue $manifest 'schema_version') -ne 2) { throw 'MANIFEST_SCHEMA_UNSUPPORTED' }
        if ((Get-StringValue $manifest 'contract_id' '') -ne $ExpectedContractId) { throw 'CONTRACT_MISMATCH' }
        $requested = @(Normalize-RequestedCaseIds $CaseId)
        if ($requested.Count -eq 0) {
            if ($Tier -eq 'SMOKE') { $requested = @((@($manifest.cases | Sort-Object id) | Select-Object -First 1 | ForEach-Object { Get-StringValue $_ 'id' '' })) }
            else { $requested = @($manifest.cases | Sort-Object id | ForEach-Object { Get-StringValue $_ 'id' '' }) }
        }
        $plan = Get-PlanManifest $manifestFile $launcherFile $planRoot $requested
        foreach ($planCase in @($plan.cases | Sort-Object id)) {
            $id = Get-StringValue $planCase 'id' ''
            $stats = Get-ArchiveStats (Get-StringValue $planCase.artifact 'path' '')
            $workloads.Add([ordered]@{ id = $id; artifact = $planCase.artifact; target_jdk = $planCase.target_jdk; dependencies = @($planCase.dependencies); stats = $stats }) | Out-Null
            foreach ($modeName in @('cold', 'hot')) {
                $runs = if ($modeName -eq 'cold') { [int]$schedule.cold_runs } else { [int]$schedule.warm_runs }
                if ($Tier -eq 'RELEASE' -and ($representatives -contains $id)) { $runs = if ($modeName -eq 'cold') { [int]$schedule.representative_cold_runs } else { [int]$schedule.representative_warm_runs } }
                $warmups = if ($modeName -eq 'hot') { [int]$schedule.warmups } else { 0 }
                $caseRoot = Join-Path $root ($id + '-' + $modeName)
                $records.Add((Get-ModeRecord $id $planCase $modeName $runs $warmups $caseRoot $launcherFile)) | Out-Null
            }
        }
    }
    $semanticDigest = if ($Tier -eq 'MICRO') { Get-SemanticDigest $records.ToArray() } else { Get-SemanticDigest $records.ToArray() }
    $rulePath = Join-Path $RepoRoot 'src\main\resources\rules\default-rules.yaml'
    $ruleHash = if (Test-Path -LiteralPath $rulePath -PathType Leaf) { Get-Sha256 $rulePath } else { 'MISSING' }
    $workloadLines = [Collections.Generic.List[string]]::new(); $workloadLines.Add("manifest=$(if ($null -eq $manifestFile) { 'MICRO' } else { Get-Sha256 $manifestFile })") | Out-Null; $workloadLines.Add("launcher=$(if ($null -eq $launcherFile) { 'MICRO' } else { Get-Sha256 $launcherFile })") | Out-Null; $workloadLines.Add("rules=$ruleHash") | Out-Null; $workloadLines.Add("tier=$Tier|no_verify=$NoVerify|fast=$Fast") | Out-Null
    foreach ($workload in @($workloads | Sort-Object id)) { $workloadLines.Add("case=$($workload.id)|artifact=$($workload.artifact.sha256)|jdk=$($workload.target_jdk.id)|jdkjava=$($workload.target_jdk.java_sha256)|classes=$($workload.stats.classes)|bytes=$($workload.stats.bytes)") | Out-Null; foreach ($dependency in @($workload.dependencies | Sort-Object id)) { $workloadLines.Add("dependency=$($workload.id)/$($dependency.id)|$($dependency.sha256)") | Out-Null } }
    $comparisonFingerprint = Get-DeterministicFingerprint $workloadLines.ToArray()
    $caseSummaries = [Collections.Generic.List[object]]::new(); foreach ($workload in @($workloads | Sort-Object id)) { foreach ($modeName in @('cold', 'hot')) { $modeRecords = @($records | Where-Object { $_.id -eq $workload.id -and $_.mode -eq $modeName }); if (@($modeRecords).Length -gt 0) { $summary = Get-ModeSummary $modeRecords; $caseSummaries.Add([ordered]@{ id = $workload.id; mode = $modeName; summary = [ordered]@{ wall_median_ms = $summary.wall_ms.median; wall_max_ms = $summary.wall_ms.max; wall_p95_ms = $summary.wall_ms.p95; rss_median_mb = $summary.rss_peak_mb.median; rss_max_mb = $summary.rss_peak_mb.max; time_to_first_median_ms = $summary.time_to_first_ms.median; sample_count = $summary.sample_count; p95_eligible = [bool]$summary.wall_ms.p95_eligible }; samples = $modeRecords[0].samples }) | Out-Null } } }
    if ($Tier -eq 'MICRO') { $caseSummaries.Add([ordered]@{ id = 'synthetic-map-reducer'; mode = 'micro'; summary = [ordered]@{ wall_median_ms = (Get-ModeSummary $records.ToArray()).wall_ms.median; wall_max_ms = (Get-ModeSummary $records.ToArray()).wall_ms.max; wall_p95_ms = (Get-ModeSummary $records.ToArray()).wall_ms.p95; rss_median_mb = -1; rss_max_mb = -1; time_to_first_median_ms = (Get-ModeSummary $records.ToArray()).time_to_first_ms.median; sample_count = $records.Count; p95_eligible = $false }; samples = $records[0].samples }) | Out-Null }
    $candidate = [ordered]@{ schema_version = 2; contract_id = $ExpectedContractId; kind = 'performance-baseline'; runner = [ordered]@{ name = $RunnerVersion; path = [IO.Path]::GetFullPath($PSCommandPath); sha256 = Get-Sha256 ([IO.Path]::GetFullPath($PSCommandPath)) }; tier = $Tier; status = if ($PlanOnly) { 'NOT_RUN' } elseif (@($records | Where-Object { $_.status -in @('FAILED', 'SEMANTIC_MISMATCH') }).Length -gt 0) { 'FAILED' } else { 'OBSERVED' }; started_at = $started; finished_at = (Get-Date).ToUniversalTime().ToString('o'); schedule = $schedule; reference_machine = $machine; manifest = if ($null -eq $manifestFile) { $null } else { [ordered]@{ path = $manifestFile; sha256 = Get-Sha256 $manifestFile; id = Get-StringValue $manifest 'manifest_id' 'UNKNOWN' } }; launcher = if ($null -eq $launcherFile) { $null } else { [ordered]@{ path = $launcherFile; sha256 = Get-Sha256 $launcherFile; bytes = [long](Get-Item -LiteralPath $launcherFile).Length } }; configuration = [ordered]@{ verify_policy = if ($NoVerify) { 'no-verify' } else { 'auto' }; trusted_target_required = -not $NoVerify; fast = [bool]$Fast; process_timeout_ms = $ProcessTimeoutMs; profiler = 'OFF'; output_format = 'canonical-findings-and-chains' }; workload_fingerprint = [ordered]@{ comparison = $comparisonFingerprint; cases = @($workloads.ToArray()) }; comparison_fingerprint = $comparisonFingerprint; semantic_digest = $semanticDigest; cases = @($caseSummaries.ToArray()); records = @($records.ToArray()); slo = if ($Tier -eq 'MICRO') { [ordered]@{ status = 'NOT_APPLICABLE'; issues = @('PERF_MICRO_SYNTHETIC_NOT_PRODUCT_SLO'); cases = @() } } else { Get-SloEvaluation $records.ToArray() $workloads.ToArray() }; comparison = Get-Comparison ([ordered]@{ comparison_fingerprint = $comparisonFingerprint; semantic_digest = $semanticDigest; cases = @($caseSummaries.ToArray()) }) $BaselinePath; baseline_update = $null }
    $update = Update-BaselineIfRequested $candidate; $candidate.baseline_update = $update
    Write-JsonAtomic (Join-Path $root 'performance-baseline.json') $candidate
    return $candidate
}

try {
    if ($SelfTest) { $self = Invoke-SelfTest; Write-Output ('PERFORMANCE_RUNNER_SELF_TEST=' + $self.status); Write-Output ('tests=' + ($self.tests -join ',')); exit 0 }
    if ($UpdateBaseline -and $PlanOnly) { throw 'PLAN_ONLY_CANNOT_UPDATE_BASELINE' }
    $result = Invoke-Performance
    $result | ConvertTo-Json -Depth 50
    if ($result.status -eq 'FAILED' -or $result.slo.status -eq 'FAIL' -or $result.comparison.status -eq 'FAIL') { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('PERFORMANCE_RUNNER_ERROR: ' + $_.Exception.Message + ' line=' + $_.InvocationInfo.ScriptLineNumber + ' position=' + $_.InvocationInfo.PositionMessage + ' stack=' + $_.ScriptStackTrace))
    exit 2
}
