[CmdletBinding()]
param(
    [Alias('Manifest')]
    [string] $ManifestPath,

    [string] $LauncherJar,

    [string] $OutputRoot,

    [string[]] $CaseId,

    [switch] $PlanOnly,

    [switch] $NoVerify,

    [switch] $Fast,

    [switch] $MeasurePerformance,

    [ValidateSet('hot', 'cold')]
    [string] $Mode = 'cold',

    [ValidateRange(0, 100000)]
    [int] $Warmups = 1,

    [ValidateRange(1, 100000)]
    [int] $Runs = 3,

    [ValidateRange(0, 2147483647)]
    [int] $VerifyBudgetOverride = -1,

    [ValidateRange(1, 86400000)]
    [long] $ProcessTimeoutMs = 900000,

    [string] $JabbaExe,

    [string] $LauncherJdkId = 'temurin@17.0.19',

    [ValidateRange(1, 30)]
    [int] $LauncherJdkFeature = 17,

    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))
$ValidatorPath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath 'validate-benchmark-manifest.ps1'))
$InputDigestValidatorPath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath 'validate-input-digest.ps1'))
$InputDigestSchemaPath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..\docs\schemas\input-digest-v1.schema.json'))
$RunSchemaVersion = 2
$JdkDiscoveryModulePath = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath 'jdk-discovery-v1.psm1'))
Import-Module -Name $JdkDiscoveryModulePath -Force -DisableNameChecking -ErrorAction Stop

function Resolve-PowerShellExecutable {
    # Do not assume that `pwsh` is healthy merely because it is on PATH.  The
    # desktop host may expose a stale Core process while Windows PowerShell is
    # available and responsive.  Prefer the current engine, then a known
    # Windows PowerShell binary, and finally PATH discovery for non-Windows CI.
    $edition = [string]$PSVersionTable.PSEdition
    $currentName = if ($edition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $current = Join-Path $PSHOME $currentName
    if (Test-Path -LiteralPath $current -PathType Leaf) {
        return [IO.Path]::GetFullPath($current)
    }
    $windows = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $windows -PathType Leaf) {
        return [IO.Path]::GetFullPath($windows)
    }
    $command = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [IO.Path]::GetFullPath([string]$command.Source)
    }
    $command = Get-Command powershell -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        return [IO.Path]::GetFullPath([string]$command.Source)
    }
    throw 'POWERSHELL_HOST_NOT_FOUND'
}

function Get-PropertyValue {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    if ($null -eq $Object) {
        return $null
    }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
        return $Object[$Name]
    }
    if ($null -eq $Object.PSObject.Properties[$Name]) {
        return $null
    }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-StringValue {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string] $Name,
        [string] $Default = ''
    )
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) {
        return $Default
    }
    return [string]$value
}

function Get-LongValue {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string] $Name,
        [long] $Default = 0
    )
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
        return $Default
    }
    try {
        return [long]$value
    } catch {
        return $Default
    }
}

function Get-BooleanValue {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string] $Name,
        [bool] $Default = $false
    )
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) {
        return $Default
    }
    return [bool]$value
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
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
    $baseUri = [Uri]$baseFull
    $pathUri = [Uri]$pathFull
    return [Uri]::UnescapeDataString($baseUri.MakeRelativeUri($pathUri).ToString()).Replace([char]92, [char]47)
}

function Get-TextSha256 {
    param([AllowNull()] [string] $Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($(if ($null -eq $Text) { '' } else { $Text }))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $Label,
        [switch] $FileOnly,
        [switch] $DirectoryOnly
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "${Label}_PATH_EMPTY: $Label path is empty"
    }
    $candidate = if ([IO.Path]::IsPathRooted($Value)) {
        [IO.Path]::GetFullPath($Value)
    } else {
        [IO.Path]::GetFullPath((Join-Path -Path $Base -ChildPath $Value))
    }
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "${Label}_MISSING: $candidate"
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($FileOnly -and $item -isnot [IO.FileInfo]) {
        throw "${Label}_NOT_FILE: $candidate"
    }
    if ($DirectoryOnly -and $item -isnot [IO.DirectoryInfo]) {
        throw "${Label}_NOT_DIRECTORY: $candidate"
    }
    return $item.FullName
}

function Resolve-RegularFile {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    return Resolve-ExistingPath $Value $Base $Label -FileOnly
}

function Assert-ArtifactDigest {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    $actualHash = Get-Sha256 $Path
    $expectedHash = Get-StringValue $Artifact 'sha256' ''
    if ([string]::IsNullOrWhiteSpace($expectedHash) -or $expectedHash -eq 'null') {
        throw "${Label}_HASH_UNPINNED: observed artifact must carry sha256"
    }
    if (-not $actualHash.Equals($expectedHash.ToLowerInvariant(), [StringComparison]::Ordinal)) {
        throw "${Label}_HASH_MISMATCH: expected=$expectedHash actual=$actualHash path=$Path"
    }
    $expectedBytes = Get-PropertyValue $Artifact 'bytes'
    if ($null -ne $expectedBytes -and [long](Get-Item -LiteralPath $Path).Length -ne [long]$expectedBytes) {
        throw "${Label}_SIZE_MISMATCH: expected=$expectedBytes actual=$((Get-Item -LiteralPath $Path).Length) path=$Path"
    }
    return [ordered]@{
        path = $Path
        relative_path = Get-RelativePathCompat $RepoRoot $Path
        kind = Get-StringValue $Artifact 'kind' 'unknown'
        sha256 = $actualHash
        bytes = [long](Get-Item -LiteralPath $Path).Length
        expected_sha256 = $expectedHash.ToLowerInvariant()
        expected_bytes = if ($null -eq $expectedBytes) { $null } else { [long]$expectedBytes }
        status = 'MATCH'
    }
}

function Invoke-Capture {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [string] $WorkingDirectory
    )
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $FilePath @Arguments 2>&1)
        $code = [int]$LASTEXITCODE
        return [pscustomobject]@{
            exit_code = $code
            output = (($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim()
        }
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Resolve-JabbaExecutable {
    param([string] $Requested)
    return Resolve-JabbaExecutableV1 -Requested $Requested -BasePath (Get-Location).Path -RepoRoot $RepoRoot
}

function Resolve-JdkProfile {
    param(
        [Parameter(Mandatory = $true)] $JdkProfile,
        [Parameter(Mandatory = $true)] [string] $JabbaPath
    )
    return Resolve-JdkProfileV1 -JdkProfile $JdkProfile -JabbaPath $JabbaPath -BasePath (Get-Location).Path
}

function Get-GitIdentity {
    $head = 'UNKNOWN'
    $statusText = ''
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        $headResult = Invoke-Capture $git.Source @('-C', $RepoRoot, 'rev-parse', 'HEAD')
        if ($headResult.exit_code -eq 0 -and -not [string]::IsNullOrWhiteSpace($headResult.output)) {
            $head = $headResult.output.Trim()
        }
        $statusResult = Invoke-Capture $git.Source @('-C', $RepoRoot, 'status', '--porcelain=v1', '--untracked-files=all')
        if ($statusResult.exit_code -eq 0) {
            $statusText = $statusResult.output
        }
    }
    $dirtyPaths = @()
    if (-not [string]::IsNullOrWhiteSpace($statusText)) {
        $dirtyPaths = @($statusText -split "`r?`n" | Where-Object { $_.Length -ge 4 } | ForEach-Object { $_.Substring(3).Trim() } | Sort-Object -Unique)
    }
    return [ordered]@{
        head = $head
        status = if ([string]::IsNullOrWhiteSpace($statusText)) { 'CLEAN' } else { 'DIRTY' }
        dirty_paths = @($dirtyPaths)
        worktree_digest = Get-TextSha256 $statusText
    }
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    $escaped = $Value.Replace('\\', '\\\\').Replace('"', '\\"')
    return '"' + $escaped + '"'
}

function New-ProcessTreeState {
    return [ordered]@{
        status = 'NOT_SAMPLED'
        source = 'Win32_Process+System.Diagnostics.Process'
        reason_code = $null
        root_pid = $null
        sample_count = 0
        sampling_interval_ms = 250
        process_count_peak = 0
        rss_peak_mb = -1
        cpu_ms = -1
    }
}

function Update-ProcessTreeState {
    param(
        [Parameter(Mandatory = $true)] [System.Collections.IDictionary] $State,
        [Parameter(Mandatory = $true)] [int] $RootPid
    )
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        if ($State.status -eq 'NOT_SAMPLED') {
            $State.status = 'UNSUPPORTED_PLATFORM'
            $State.reason_code = 'PROCESS_TREE_WINDOWS_ONLY'
        }
        return
    }
    $State.root_pid = $RootPid
    try {
        # WMI supplies parent relationships which System.Diagnostics.Process does not expose
        # on Windows PowerShell 5.  A failed/permission-denied sample remains UNKNOWN; parent
        # telemetry is still retained separately and is never presented as tree telemetry.
        $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                Select-Object ProcessId, ParentProcessId)
        $parents = @{}
        foreach ($row in $rows) {
            $pid = 0
            $parent = 0
            $parsedPid = [int]::TryParse([string]$row.ProcessId, [ref]$pid)
            $parsedParent = [int]::TryParse([string]$row.ParentProcessId, [ref]$parent)
            if ($parsedPid -and $parsedParent) {
                $parents[$pid] = $parent
            }
        }
        $ids = [Collections.Generic.HashSet[int]]::new()
        $ids.Add($RootPid) | Out-Null
        $changed = $true
        while ($changed) {
            $changed = $false
            foreach ($pair in $parents.GetEnumerator()) {
                if ($ids.Contains([int]$pair.Value) -and $ids.Add([int]$pair.Key)) {
                    $changed = $true
                }
            }
        }
        $rss = [double]0
        $cpu = [double]0
        $observed = 0
        foreach ($pid in $ids) {
            try {
                $processInfo = Get-Process -Id ([int]$pid) -ErrorAction Stop
                $rss += [double]$processInfo.WorkingSet64
                try { $cpu += [double]$processInfo.TotalProcessorTime.TotalMilliseconds } catch { }
                $observed++
            } catch {
                # A process may exit between WMI and Get-Process; retain other members.
            }
        }
        if ($observed -le 0) {
            return
        }
        $State.sample_count = [int]$State.sample_count + 1
        $State.process_count_peak = [Math]::Max([int]$State.process_count_peak, $observed)
        $rssMb = [long][Math]::Ceiling($rss / 1MB)
        $cpuMs = [long][Math]::Round($cpu, [MidpointRounding]::AwayFromZero)
        $State.rss_peak_mb = [Math]::Max([long]$State.rss_peak_mb, $rssMb)
        $State.cpu_ms = [Math]::Max([long]$State.cpu_ms, $cpuMs)
        $State.status = 'SAMPLED'
        $State.reason_code = $null
    } catch {
        if ($State.status -ne 'SAMPLED') {
            $State.status = 'NOT_SAMPLED'
            $State.reason_code = if ($_.Exception -is [Microsoft.Management.Infrastructure.CimException]) {
                'PROCESS_TREE_ACCESS_DENIED'
            } else {
                'PROCESS_TREE_SAMPLE_FAILED'
            }
        }
    }
}

function Invoke-ProcessCapture {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $StdoutPath,
        [Parameter(Mandatory = $true)] [string] $StderrPath,
        [Parameter(Mandatory = $true)] [string] $WorkingDirectory,
        [Parameter(Mandatory = $true)] [long] $TimeoutMs
    )
    $quoted = @($Arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' '
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = $null
    $timedOut = $false
    $treeState = New-ProcessTreeState
    $lastTreeSampleMs = -1L
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $quoted -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath -NoNewWindow -PassThru
        Update-ProcessTreeState $treeState ([int]$process.Id)
        while ($true) {
            $elapsed = [long]$watch.ElapsedMilliseconds
            if ($lastTreeSampleMs -lt 0 -or $elapsed - $lastTreeSampleMs -ge [long]$treeState.sampling_interval_ms) {
                Update-ProcessTreeState $treeState ([int]$process.Id)
                $lastTreeSampleMs = $elapsed
            }
            $remaining = [long]$TimeoutMs - $elapsed
            if ($remaining -le 0L) {
                $timedOut = $true
                break
            }
            $waitMs = [int][Math]::Min(100L, $remaining)
            if ($process.WaitForExit($waitMs)) {
                break
            }
        }
        if ($timedOut) {
            try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }
            $process.WaitForExit(5000) | Out-Null
        }
        $watch.Stop()
        $exitCode = if ($timedOut) { 124 } else { [int]$process.ExitCode }
        $cpuMs = -1L
        $rssMb = -1L
        try { $process.Refresh(); $cpuMs = [long]$process.TotalProcessorTime.TotalMilliseconds } catch { }
        try { $rssMb = [long][Math]::Ceiling($process.PeakWorkingSet64 / 1MB) } catch { }
        return [ordered]@{
            status = if ($timedOut) { 'TIMEOUT' } else { 'COMPLETED' }
            exit_code = $exitCode
            process_id = [int]$process.Id
            wall_ms = [long]$watch.ElapsedMilliseconds
            cpu_ms = $cpuMs
            rss_peak_mb = $rssMb
            process_tree = $treeState
            stdout = $StdoutPath
            stderr = $StderrPath
        }
    } finally {
        $watch.Stop()
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Read-JsonIfPresent {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
}

function Get-JsonFromText {
    param([AllowNull()] [string[]] $Lines)
    if ($null -eq $Lines) { return $null }
    try { return (($Lines -join "`n") | ConvertFrom-Json) } catch { return $null }
}

function Validate-InputDigestArtifact {
    param([Parameter(Mandatory = $true)] [string] $Path)
    $validatorMissing = -not (Test-Path -LiteralPath $InputDigestValidatorPath -PathType Leaf)
    $schemaMissing = -not (Test-Path -LiteralPath $InputDigestSchemaPath -PathType Leaf)
    if ($validatorMissing -or $schemaMissing) {
        return [ordered]@{ status = 'FAIL'; reason_code = 'INPUT_DIGEST_VALIDATOR_MISSING'; path = $Path; validator = $null; result = $null }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ status = 'FAIL'; reason_code = 'INPUT_DIGEST_MISSING'; path = $Path; validator = $null; result = $null }
    }
    $psHost = Resolve-PowerShellExecutable
    $output = @(& $psHost -NoProfile -ExecutionPolicy Bypass -File $InputDigestValidatorPath -InputDigestPath $Path -SchemaPath $InputDigestSchemaPath -Json)
    $exitCode = [int]$LASTEXITCODE
    $result = Get-JsonFromText $output
    $valid = ($exitCode -eq 0 -and $null -ne $result -and [bool]$result.valid)
    return [ordered]@{
        status = if ($valid) { 'PASS' } else { 'FAIL' }
        reason_code = if ($valid) { 'INPUT_DIGEST_SCHEMA_VALID' } elseif ($null -eq $result) { 'INPUT_DIGEST_VALIDATOR_INVALID_OUTPUT' } else { 'INPUT_DIGEST_SCHEMA_INVALID' }
        path = $Path
        validator = [ordered]@{ path = $InputDigestValidatorPath; schema = $InputDigestSchemaPath; exit_code = $exitCode }
        result = $result
    }
}

function Get-CanonicalEvidence {
    param([Parameter(Mandatory = $true)] [string] $OutputDirectory)
    $findingPath = Join-Path $OutputDirectory 'findings\findings.csv'
    $chainPath = Join-Path $OutputDirectory 'evidence\chains.csv'
    $files = [ordered]@{}
    $missing = [Collections.Generic.List[string]]::new()
    foreach ($entry in @([pscustomobject]@{ name = 'findings'; path = $findingPath }, [pscustomobject]@{ name = 'chains'; path = $chainPath })) {
        if (Test-Path -LiteralPath $entry.path -PathType Leaf) {
            $item = Get-Item -LiteralPath $entry.path -Force
            $lines = @(Get-Content -LiteralPath $entry.path -Encoding UTF8)
            $files[$entry.name] = [ordered]@{ path = $entry.path; bytes = [long]$item.Length; sha256 = Get-Sha256 $entry.path; rows = [Math]::Max(0, $lines.Count - 1) }
        } else {
            $missing.Add($entry.name) | Out-Null
            $files[$entry.name] = [ordered]@{ path = $entry.path; bytes = $null; sha256 = $null; rows = $null }
        }
    }
    $canonical = if ($missing.Count -gt 0) { 'MISSING' } else {
        Get-TextSha256 ("findings=$($files.findings.sha256)`nchains=$($files.chains.sha256)`n")
    }
    return [ordered]@{ status = if ($missing.Count -eq 0) { 'COMPLETE' } else { 'MISSING' }; digest = $canonical; files = $files; missing = @($missing.ToArray()) }
}

function New-CaseCommand {
    param(
        [Parameter(Mandatory = $true)] [string] $Java,
        [Parameter(Mandatory = $true)] [string] $Launcher,
        [Parameter(Mandatory = $true)] [string] $Artifact,
        [Parameter(Mandatory = $true)] [string] $Output,
        [Parameter(Mandatory = $true)] [string] $JdkHome,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]] $ExternalDependencies
    )
    $commandArgs = [Collections.Generic.List[string]]::new()
    $commandArgs.Add('-jar') | Out-Null
    $commandArgs.Add($Launcher) | Out-Null
    $commandArgs.Add('scan') | Out-Null
    $commandArgs.Add('--jar') | Out-Null
    $commandArgs.Add($Artifact) | Out-Null
    $commandArgs.Add('--output') | Out-Null
    $commandArgs.Add($Output) | Out-Null
    # The runner creates each case directory before redirecting stdout/stderr so the
    # child process can publish its run-level transaction there.  That directory is
    # guaranteed to be inside the runner's freshly-created unique OutputRoot (the
    # caller rejects pre-existing roots/case paths), therefore the CLI's explicit
    # overwrite acknowledgement is safe and keeps the runner from tripping its own
    # fail-closed "output directory exists" guard.  Do not generalize this flag to
    # user-facing CLI defaults or to arbitrary caller-selected directories.
    $commandArgs.Add('--overwrite') | Out-Null
    if ($ExternalDependencies.Count -gt 0) {
        $commandArgs.Add('--deps') | Out-Null
        $commandArgs.Add((($ExternalDependencies | ForEach-Object { [string]$_ }) -join ',')) | Out-Null
    }
    $commandArgs.Add('--jdk-home') | Out-Null
    $commandArgs.Add($JdkHome) | Out-Null
    if ($Fast) { $commandArgs.Add('--fast') | Out-Null }
    if ($NoVerify) { $commandArgs.Add('--no-verify') | Out-Null }
    if ($VerifyBudgetOverride -ge 0) {
        $commandArgs.Add('--verify-budget') | Out-Null
        $commandArgs.Add([string]$VerifyBudgetOverride) | Out-Null
    }
    return @($commandArgs.ToArray())
}

function Get-CasePlan {
    param(
        [Parameter(Mandatory = $true)] $Case,
        [Parameter(Mandatory = $true)] [string] $ManifestBase,
        [Parameter(Mandatory = $true)] [string] $JabbaPath,
        [Parameter(Mandatory = $true)] [string] $Launcher,
        [Parameter(Mandatory = $true)] [string] $LauncherJava,
        [Parameter(Mandatory = $true)] [string] $LauncherJdkProfileId,
        [Parameter(Mandatory = $true)] [string] $LauncherJdkJavaHash,
        [Parameter(Mandatory = $true)] [string] $CaseOutput
    )
    $id = Get-StringValue $Case 'id' ''
    $artifacts = @($Case.artifacts | Where-Object { (Get-StringValue $_ 'status' '') -eq 'OBSERVED' })
    if ($artifacts.Count -ne 1) {
        throw "${id}_ARTIFACT_SELECTION: expected exactly one OBSERVED artifact, got=$($artifacts.Count)"
    }
    $artifactDefinition = $artifacts[0]
    $artifactPath = Resolve-RegularFile (Get-StringValue $artifactDefinition 'path' '') $ManifestBase "$id-artifact"
    $artifactRecord = Assert-ArtifactDigest $artifactPath $artifactDefinition "$id-artifact"
    $externalRecords = [Collections.Generic.List[object]]::new()
    $externalPaths = [Collections.Generic.List[string]]::new()
    foreach ($dependency in @($Case.dependencies)) {
        if ((Get-StringValue $dependency 'scope' '') -ne 'external') { continue }
        $dependencyPath = Resolve-RegularFile (Get-StringValue $dependency 'location' '') $ManifestBase "$id-dependency"
        $dependencyRecord = Assert-ArtifactDigest $dependencyPath $dependency "$id-dependency-$(Get-StringValue $dependency 'id' 'unknown')"
        $dependencyRecord['id'] = Get-StringValue $dependency 'id' 'unknown'
        $dependencyRecord['scope'] = Get-StringValue $dependency 'scope' 'external'
        $externalRecords.Add([pscustomobject]$dependencyRecord) | Out-Null
        if ($dependencyPath.Contains(',')) { throw "${id}_DEPENDENCY_PATH_UNSUPPORTED: comma in path cannot be represented by current --deps contract" }
        $externalPaths.Add($dependencyPath) | Out-Null
    }
    $jdk = Resolve-JdkProfile $Case.target_jdk $JabbaPath
    $command = New-CaseCommand $LauncherJava $Launcher $artifactPath $CaseOutput $jdk.home @($externalPaths.ToArray())
    return [ordered]@{
        id = $id
        category = Get-StringValue $Case 'category' 'unknown'
        manifest_status = Get-StringValue $Case 'status' 'UNKNOWN'
        truth_status = Get-StringValue $Case.truth 'status' 'UNKNOWN'
        artifact = $artifactRecord
        dependencies = @($externalRecords.ToArray())
        target_jdk = $jdk
        command = [ordered]@{
            executable = $LauncherJava
            launcher_jdk_id = $LauncherJdkProfileId
            launcher_jdk_java_sha256 = $LauncherJdkJavaHash
            target_jdk_home = $jdk.home
            arguments = @($command)
            verify_policy = if ($NoVerify) { 'no-verify' } else { 'auto' }
            target_code_execution_possible = [bool](-not $NoVerify)
            trusted_target_required = [bool](-not $NoVerify)
        }
        output = $CaseOutput
        dynamic_policy = [ordered]@{
            requested = if ($NoVerify) { 'DISABLED' } else { 'AUTO' }
            allowed_level = Get-StringValue $Case.dynamic 'allowed_level' 'UNKNOWN'
            max_attempts = Get-LongValue $Case.dynamic 'max_attempts' 0
            timeout_ms = Get-LongValue $Case.dynamic 'timeout_ms' 0
            side_effect_policy = Get-StringValue $Case.dynamic 'side_effect_policy' 'UNKNOWN'
            target_code_executed = 'UNKNOWN'
            job_object = [ordered]@{ required = $false; capability = 'NOT_SAMPLED_P0.2' }
        }
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] $Value
    )
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    $temp = "$Path.$([Guid]::NewGuid().ToString('N')).partial"
    try {
        $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $temp -Encoding UTF8 -NoNewline
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = "$Path.bak"
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
            [IO.File]::Replace($temp, $Path, $backup, $true)
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        } else {
            [IO.File]::Move($temp, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
}

function Assert-OutputAvailable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path) {
        throw "OUTPUT_EXISTS: refusing to overwrite $Path"
    }
}

function Get-DeterministicFingerprint {
    param(
        [Parameter(Mandatory = $true)] [string] $ManifestHash,
        [Parameter(Mandatory = $true)] [string] $LauncherHash,
        [Parameter(Mandatory = $true)] [string] $RuleHash,
        [Parameter(Mandatory = $true)] [string] $GitHead,
        [Parameter(Mandatory = $true)] [string] $GitWorktree,
        [Parameter(Mandatory = $true)] [string] $LauncherJdkHash,
        [Parameter(Mandatory = $true)] [object[]] $Plans
    )
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add("manifest=$ManifestHash") | Out-Null
    $lines.Add("launcher=$LauncherHash") | Out-Null
    $lines.Add("rules=$RuleHash") | Out-Null
    $lines.Add("git=$GitHead/$GitWorktree") | Out-Null
    $lines.Add("launcher-jdk=$LauncherJdkHash") | Out-Null
    foreach ($plan in @($Plans | Sort-Object id)) {
        $lines.Add("case=$($plan.id)|artifact=$($plan.artifact.sha256)|jdk=$($plan.target_jdk.id)|jdkjava=$($plan.target_jdk.java_sha256)|verify=$($plan.command.verify_policy)|fast=$Fast|budget=$VerifyBudgetOverride") | Out-Null
        foreach ($dependency in @($plan.dependencies | Sort-Object id)) { $lines.Add("dependency=$($plan.id)/$($dependency.id)|$($dependency.sha256)") | Out-Null }
    }
    return Get-TextSha256 (($lines.ToArray()) -join "`n")
}

function Add-StatusCount {
    param(
        [Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Counts,
        [AllowNull()] [string] $Status
    )
    $normalized = if ([string]::IsNullOrWhiteSpace($Status)) { 'UNKNOWN' } else { $Status.ToUpperInvariant() }
    if (-not $Counts.Contains($normalized)) { $Counts[$normalized] = 0 }
    $Counts[$normalized] = [long]$Counts[$normalized] + 1L
}

function New-RunOutcome {
    param(
        [Parameter(Mandatory = $true)] [ValidateSet('SUCCESS', 'PARTIAL', 'FAILED', 'USAGE_ERROR', 'UNSUPPORTED', 'NOT_RUN')] [string] $Status,
        [Parameter(Mandatory = $true)] [ValidateSet('OK', 'USAGE', 'INTERNAL', 'UNSUPPORTED_RUNTIME')] [string] $ExitReason,
        [Parameter(Mandatory = $true)] [ValidateSet('SUPPORTED', 'PARTIAL', 'UNSUPPORTED', 'UNKNOWN', 'NOT_APPLICABLE')] [string] $SupportStatus,
        [Parameter(Mandatory = $true)] [ValidateSet('NOT_REQUESTED', 'WITHIN_LIMIT', 'EXHAUSTED', 'INVALID', 'UNKNOWN')] [string] $BudgetState,
        [long] $BudgetLimit = -1,
        [long] $BudgetConsumed = -1,
        [string[]] $ReasonCodes = @(),
        [string] $Detail = ''
    )
    $exitCode = switch ($ExitReason) {
        'OK' { 0 }
        'USAGE' { 2 }
        'INTERNAL' { 3 }
        'UNSUPPORTED_RUNTIME' { 78 }
    }
    $normalizedReasons = @($ReasonCodes | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).Trim().ToUpperInvariant().Replace(' ', '_') } |
            Sort-Object -Unique)
    if ($BudgetState -eq 'NOT_REQUESTED') {
        $BudgetLimit = -1L
        $BudgetConsumed = 0L
    } else {
        $BudgetLimit = [Math]::Max(-1L, $BudgetLimit)
        $BudgetConsumed = [Math]::Max(-1L, $BudgetConsumed)
    }
    return [ordered]@{
        schema_version = 1
        status = $Status
        exit_reason = $ExitReason
        exit_code = [int]$exitCode
        support_status = $SupportStatus
        input_budget = [ordered]@{ state = $BudgetState; limit = $BudgetLimit; consumed = $BudgetConsumed; reason_code = if ($BudgetState -eq 'WITHIN_LIMIT') { 'WITHIN_LIMIT' } elseif ($BudgetState -eq 'NOT_REQUESTED') { 'NOT_REQUESTED' } else { 'BUDGET_' + $BudgetState } }
        reason_codes = $normalizedReasons
        detail = if ($null -eq $Detail) { '' } else { [string]$Detail }
    }
}

function Get-RunOutcomeExitCode {
    param([Parameter(Mandatory = $true)] $Outcome)
    $value = Get-PropertyValue $Outcome 'exit_code'
    if ($null -eq $value) { return 3 }
    try { return [int]$value } catch { return 3 }
}

function Invoke-RunnerSelfTest {
    param([Parameter(Mandatory = $true)] [string] $Manifest)
    if (-not (Test-Path -LiteralPath $ValidatorPath -PathType Leaf)) { throw 'SELFTEST_VALIDATOR_MISSING' }
    $inputValidatorMissing = -not (Test-Path -LiteralPath $InputDigestValidatorPath -PathType Leaf)
    $inputSchemaMissing = -not (Test-Path -LiteralPath $InputDigestSchemaPath -PathType Leaf)
    if ($inputValidatorMissing -or $inputSchemaMissing) { throw 'SELFTEST_INPUT_DIGEST_VALIDATOR_MISSING' }
    $validatorHost = Resolve-PowerShellExecutable
    $validatorOutput = @(& $validatorHost -NoProfile -ExecutionPolicy Bypass -File $ValidatorPath -ManifestPath $Manifest -SelfTest)
    if ($LASTEXITCODE -ne 0 -or -not (($validatorOutput -join "`n") -match 'MANIFEST_VALIDATOR_SELF_TEST=PASS')) { throw 'SELFTEST_MANIFEST_VALIDATOR_FAILED' }
    $inputDigestOutput = @(& $validatorHost -NoProfile -ExecutionPolicy Bypass -File $InputDigestValidatorPath -SchemaPath $InputDigestSchemaPath -SelfTest)
    if ($LASTEXITCODE -ne 0 -or -not (($inputDigestOutput -join "`n") -match 'INPUT_DIGEST_VALIDATOR_SELF_TEST=PASS')) { throw 'SELFTEST_INPUT_DIGEST_VALIDATOR_FAILED' }
    $temp = Join-Path ([IO.Path]::GetTempPath()) ("just-runner-selftest-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp | Out-Null
    try {
        $fixture = Join-Path $temp 'fixture.jar'
        [IO.File]::WriteAllBytes($fixture, [Text.Encoding]::UTF8.GetBytes('runner-fixture'))
        $definition = [pscustomobject]@{ sha256 = Get-Sha256 $fixture; bytes = (Get-Item $fixture).Length; kind = 'jar' }
        $match = Assert-ArtifactDigest $fixture $definition 'selftest'
        $bad = [pscustomobject]@{ sha256 = ('0' * 64); bytes = $definition.bytes; kind = 'jar' }
        $mismatch = $false
        try { Assert-ArtifactDigest $fixture $bad 'selftest-bad' | Out-Null } catch { $mismatch = $_.Exception.Message -match 'HASH_MISMATCH' }
        if (-not $mismatch) { throw 'SELFTEST_HASH_MISMATCH_NOT_DETECTED' }
        $jdkMismatch = $false
        try {
            $jabbaForTest = Resolve-JabbaExecutable ''
            Resolve-JdkProfile ([pscustomobject]@{ id = 'temurin@8.0.482'; feature = 17 }) $jabbaForTest | Out-Null
        } catch { $jdkMismatch = $_.Exception.Message -match 'JDK_FEATURE_MISMATCH' }
        if (-not $jdkMismatch) { throw 'SELFTEST_JDK_MISMATCH_NOT_DETECTED' }
        $fingerprintA = Get-DeterministicFingerprint 'manifest' 'launcher' 'rules' 'git' 'worktree' 'launcher-jdk' @([pscustomobject]@{ id = 'a'; artifact = [pscustomobject]@{ sha256 = 'artifact' }; target_jdk = [pscustomobject]@{ id = 'jdk'; java_sha256 = 'java' }; command = [pscustomobject]@{ verify_policy = 'auto' }; dependencies = @() })
        $fingerprintB = Get-DeterministicFingerprint 'manifest' 'launcher' 'rules' 'git' 'worktree' 'launcher-jdk' @([pscustomobject]@{ id = 'a'; artifact = [pscustomobject]@{ sha256 = 'artifact' }; target_jdk = [pscustomobject]@{ id = 'jdk'; java_sha256 = 'java' }; command = [pscustomobject]@{ verify_policy = 'auto' }; dependencies = @() })
        if ($fingerprintA -ne $fingerprintB) { throw 'SELFTEST_DETERMINISTIC_FINGERPRINT_FAILED' }
        $existing = Join-Path $temp 'existing'
        New-Item -ItemType Directory -Path $existing | Out-Null
        $overwrite = $false
        try { Assert-OutputAvailable $existing } catch { $overwrite = $_.Exception.Message -match 'OUTPUT_EXISTS' }
        if (-not $overwrite) { throw 'SELFTEST_NO_OVERWRITE_FAILED' }
        [pscustomobject]@{ status = 'PASS'; tests = @('manifest-validator', 'input-digest-validator', 'hash-mismatch', 'jdk-feature-contract', 'deterministic-fingerprint', 'no-overwrite') }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

function Invoke-Runner {
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'MANIFEST_REQUIRED' }
    $manifestFile = Resolve-RegularFile $ManifestPath (Get-Location).Path 'manifest'
    $manifestBase = Split-Path -Parent $manifestFile
    $manifestText = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8
    $definition = $manifestText | ConvertFrom-Json
    if ([int](Get-PropertyValue $definition 'schema_version') -ne 2) { throw 'MANIFEST_SCHEMA_UNSUPPORTED: expected schema_version=2' }
    if (-not ([string](Get-PropertyValue $definition 'contract_id')).Equals($ExpectedContractId, [StringComparison]::Ordinal)) { throw 'CONTRACT_MISMATCH' }
    $validatorHost = Resolve-PowerShellExecutable
    $validatorOutput = @(& $validatorHost -NoProfile -ExecutionPolicy Bypass -File $ValidatorPath -ManifestPath $manifestFile -Json)
    $validatorExit = [int]$LASTEXITCODE
    if ($validatorExit -ne 0) { throw "MANIFEST_INVALID: validator_exit=$validatorExit output=$(($validatorOutput -join ' '))" }
    $validatorResult = ($validatorOutput -join "`n") | ConvertFrom-Json
    if (-not [bool]$validatorResult.valid) { throw 'MANIFEST_INVALID: validator returned valid=false' }
    $launcher = $null
    $launcherHash = 'NOT_USED'
    if (-not [string]::IsNullOrWhiteSpace($LauncherJar)) {
        $launcher = Resolve-RegularFile $LauncherJar (Get-Location).Path 'launcher'
        $launcherHash = Get-Sha256 $launcher
    } elseif (-not $PlanOnly) {
        throw 'LAUNCHER_REQUIRED: provide -LauncherJar unless -PlanOnly is selected'
    }
    $rulePath = Join-Path $RepoRoot 'src\main\resources\rules\default-rules.yaml'
    $ruleHash = if (Test-Path -LiteralPath $rulePath -PathType Leaf) { Get-Sha256 $rulePath } else { 'MISSING' }
    $git = Get-GitIdentity
    $jabba = Resolve-JabbaExecutable $JabbaExe
    $launcherRuntimeProfile = Resolve-JdkProfile ([pscustomobject]@{ id = $LauncherJdkId; feature = $LauncherJdkFeature }) $jabba
    $allCases = @($definition.cases | Sort-Object id)
    if ($allCases.Count -eq 0) { throw 'MANIFEST_CASES_EMPTY' }
    $caseIdValues = @($CaseId)
    $selected = if ($null -eq $CaseId -or $caseIdValues.Count -eq 0) { $allCases } else {
        $wanted = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($id in $caseIdValues) { if (-not $wanted.Add($id)) { throw "CASE_DUPLICATE: $id" } }
        @($allCases | Where-Object { $wanted.Contains((Get-StringValue $_ 'id' '')) })
    }
    $selected = @($selected)
    if ($selected.Count -eq 0) { throw 'CASE_SELECTION_EMPTY' }
    $selectedIds = @($selected | ForEach-Object { Get-StringValue $_ 'id' '' })
    if ($null -ne $CaseId -and $caseIdValues.Count -ne $selectedIds.Count) { throw 'CASE_SELECTION_UNKNOWN_ID' }
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
        $OutputRoot = Join-Path (Join-Path $RepoRoot 'benchmark\runs') ("run-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    $root = [IO.Path]::GetFullPath($OutputRoot)
    Assert-OutputAvailable $root
    New-Item -ItemType Directory -Path $root | Out-Null
    # Keep runner-owned redirected stdout/stderr outside every case's report tree.  On
    # Windows the child still owns those file handles while ReportTransaction commits;
    # placing them below the directory being atomically replaced makes the otherwise
    # correct fail-closed swap fail with AccessDenied.  The sibling remains inside this
    # freshly-created unique run root and is linked from the manifest, but is never part
    # of the scanner's published report transaction.
    $runnerLogRoot = Join-Path $root '_runner-logs'
    New-Item -ItemType Directory -Path $runnerLogRoot | Out-Null
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $run = [ordered]@{
        schema_version = $RunSchemaVersion
        contract_id = $ExpectedContractId
        state = 'RUNNING'
        run_id = Split-Path -Leaf $root
        started_at = $started
        finished_at = $null
        manifest = [ordered]@{ path = $manifestFile; relative_path = Get-RelativePathCompat $RepoRoot $manifestFile; sha256 = Get-TextSha256 $manifestText; id = Get-StringValue $definition 'manifest_id' 'UNKNOWN'; kind = Get-StringValue $definition 'manifest_kind' 'UNKNOWN'; validator = [ordered]@{ path = $ValidatorPath; exit_code = $validatorExit; valid = [bool]$validatorResult.valid } }
        tool = [ordered]@{ name = 'Just'; launcher = $launcher; launcher_sha256 = $launcherHash; runner = 'tools/run-regression-v2.ps1'; runner_sha256 = Get-Sha256 ([IO.Path]::GetFullPath($PSCommandPath)); rule = [ordered]@{ source = 'src/main/resources/rules/default-rules.yaml'; path = $rulePath; sha256 = $ruleHash } }
        git = $git
        jdk_resolver = [ordered]@{ executable = $jabba; policy = 'explicit-jabba-which-per-case'; no_global_use = $true; launcher_runtime = $launcherRuntimeProfile }
        configuration = [ordered]@{ mode = $Mode; warmups = $Warmups; runs = $Runs; measure_performance = [bool]$MeasurePerformance; plan_only = [bool]$PlanOnly; verify_policy = if ($NoVerify) { 'no-verify' } else { 'auto' }; fast = [bool]$Fast; verify_budget_override = if ($VerifyBudgetOverride -lt 0) { $null } else { $VerifyBudgetOverride }; process_timeout_ms = $ProcessTimeoutMs; trusted_target_required = [bool](-not $NoVerify) }
        fingerprint = $null
        cases = [Collections.Generic.List[object]]::new()
        summary = [ordered]@{ selected_cases = $selectedIds; completed = 0; failed = 0; plan_only = [bool]$PlanOnly; semantic_complete = 0; evidence_complete = 0; dynamic_attempted = 0; dynamic_unknown = 0; metric_status_counts = [ordered]@{}; metric_namespace_status_counts = [ordered]@{}; process_tree_status_counts = [ordered]@{}; performance_status = if ($MeasurePerformance) { 'NOT_IMPLEMENTED_P0.2' } else { 'NOT_REQUESTED' } }
        outcome = $null
    }
    Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    $anyFailure = $false
    $anyPartial = $false
    $plans = [Collections.Generic.List[object]]::new()
    foreach ($case in $selected) {
        $id = Get-StringValue $case 'id' ''
        $caseOutput = Join-Path $root $id
        Assert-OutputAvailable $caseOutput
        New-Item -ItemType Directory -Path $caseOutput | Out-Null
        $caseRecord = $null
        try {
            $plan = Get-CasePlan $case $manifestBase $jabba $launcher $launcherRuntimeProfile.java $launcherRuntimeProfile.id $launcherRuntimeProfile.java_sha256 $caseOutput
            $plans.Add([pscustomobject]$plan) | Out-Null
            $caseRecord = $plan
            if ($PlanOnly) {
                $caseRecord['execution'] = [ordered]@{ status = 'NOT_RUN_PLAN_ONLY'; exit_code = $null; process_id = $null; wall_ms = 0; cpu_ms = $null; rss_peak_mb = $null; stdout = $null; stderr = $null }
                $caseRecord['outcome'] = New-RunOutcome 'NOT_RUN' 'OK' 'NOT_APPLICABLE' 'NOT_REQUESTED' -ReasonCodes @('PLAN_ONLY') -Detail 'scanner not invoked'
                $caseRecord['evidence'] = [ordered]@{ status = 'NOT_RUN'; canonical_digest = $null; files = @{}; missing = @('scanner_not_invoked') }
                $caseRecord['semantic'] = [ordered]@{ status = 'NOT_RUN'; completeness = 'NOT_RUN'; chain_proof_completeness = 'NOT_RUN'; chains_found = $null; metrics = @{} }
                $caseRecord['resources'] = [ordered]@{ wall_ms = 0; cpu_ms = $null; rss_peak_mb = $null; process_id = $null; process_tree = [ordered]@{ status = 'NOT_RUN'; source = 'plan-only' } }
                $caseRecord['input_digest'] = [ordered]@{ status = 'NOT_RUN'; reason_code = 'SCANNER_NOT_INVOKED'; path = $null; validator = $null; result = $null }
                $caseRecord['dynamic_policy']['target_code_executed'] = 'NO'
                $caseRecord['dynamic'] = [ordered]@{ status = 'NOT_RUN'; requested = $caseRecord.dynamic_policy.requested; eligible_groups = $null; covered_groups = 0; attempted = 0; unique_plans = 0; attempted_plans = 0; coverage = 'NOT_RUN'; coverage_permille = -1; plan_reuse_permille = -1; confirmed = 0; refuted = 0; unknown = 0; deferred_reasons = $null; coverage_path = $null; backend = 'NOT_RUN'; isolation_level = 'NOT_RUN'; sink_distorted = $null; target_code_execution_possible = $caseRecord.command.target_code_execution_possible; target_code_executed = 'NO' }
            } else {
                $stdout = Join-Path $runnerLogRoot ($id + '.stdout.log')
                $stderr = Join-Path $runnerLogRoot ($id + '.stderr.log')
                $execution = Invoke-ProcessCapture $plan.command.executable $plan.command.arguments $stdout $stderr $RepoRoot $ProcessTimeoutMs
                $metadataPath = Join-Path $caseOutput 'meta\scan-metadata.json'
                $metadata = Read-JsonIfPresent $metadataPath
                $inputDigestPath = Join-Path $caseOutput 'meta\input-digest.json'
                $inputDigest = Validate-InputDigestArtifact $inputDigestPath
                $evidence = Get-CanonicalEvidence $caseOutput
                $phase = Get-PropertyValue $metadata 'phase_ms'
                $metrics = Get-PropertyValue $metadata 'metrics'
                $dynamicMeta = Get-PropertyValue $metadata 'dynamic_verification'
                $coveragePath = Join-Path $caseOutput 'meta\verification-coverage.json'
                $coverage = Read-JsonIfPresent $coveragePath
                $verification = Get-StringValue $metadata 'verification' 'UNKNOWN'
                $caseRecord['execution'] = $execution
                $caseRecord['metadata'] = [ordered]@{ status = if ($null -eq $metadata) { 'MISSING' } else { 'PRESENT' }; path = $metadataPath }
                $caseRecord['input_digest'] = $inputDigest
                $caseRecord['evidence'] = $evidence
                $metadataOutcome = Get-PropertyValue $metadata 'run_outcome'
                if ($null -eq $metadataOutcome) {
                    $metadataOutcome = New-RunOutcome 'FAILED' 'INTERNAL' 'UNKNOWN' 'UNKNOWN' -ReasonCodes @('SCAN_OUTCOME_MISSING') -Detail 'scan-metadata.json has no run_outcome'
                }
                $caseRecord['outcome'] = $metadataOutcome
                $metadataRss = Get-LongValue $metrics 'parent_rss_mb' -1
                if ([long]$execution.rss_peak_mb -le 0 -and $metadataRss -ge 0) { $execution.rss_peak_mb = $metadataRss }
                $metadataCpu = Get-LongValue $metrics 'parent_cpu_ms' -1
                if ([long]$execution.cpu_ms -le 0 -and $metadataCpu -ge 0) { $execution.cpu_ms = $metadataCpu }
                $reasons = @((Get-PropertyValue $metadata 'completeness_reasons') | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
                $tree = Get-PropertyValue $execution 'process_tree'
                $caseRecord['resources'] = [ordered]@{ wall_ms = [long]$execution.wall_ms; cpu_ms = [long]$execution.cpu_ms; rss_peak_mb = [long]$execution.rss_peak_mb; process_id = [int]$execution.process_id; process_tree = if ($null -eq $tree) { [ordered]@{ status = 'NOT_SAMPLED'; source = 'runner-missing-tree-snapshot'; reason_code = 'PROCESS_TREE_SAMPLE_MISSING' } } else { $tree } }
                $metricStatus = Get-PropertyValue $metadata 'metric_status'
                $metricNamespaces = Get-PropertyValue $metadata 'metric_namespaces'
                $metricNamespaceStatus = Get-PropertyValue $metadata 'metric_namespace_status'
                $caseRecord['semantic'] = [ordered]@{ status = if ($null -eq $metadata) { 'MISSING' } else { 'OBSERVED' }; completeness = Get-StringValue $metadata 'completeness' 'UNKNOWN'; chain_proof_completeness = Get-StringValue $metadata 'chain_proof_completeness' 'UNKNOWN'; completeness_reasons = $reasons; chains_found = Get-LongValue $metadata 'chains_found' 0; phase_ms = if ($null -eq $phase) { @{} } else { $phase }; metrics = if ($null -eq $metrics) { @{} } else { $metrics }; metric_status = if ($null -eq $metricStatus) { @{} } else { $metricStatus }; metric_namespaces = if ($null -eq $metricNamespaces) { @{} } else { $metricNamespaces }; metric_namespace_status = if ($null -eq $metricNamespaceStatus) { @{} } else { $metricNamespaceStatus } }
                $statusCounts = Get-PropertyValue $dynamicMeta 'status_counts'
                $selectedCount = Get-LongValue $dynamicMeta 'selected' 0
                $caseRecord['dynamic_policy']['target_code_executed'] = if ($NoVerify) { 'NO' } else { 'UNKNOWN' }
                $coverageStatus = Get-StringValue $coverage 'status' 'UNKNOWN'
                $coverageEligible = Get-LongValue $coverage 'eligible_finding_groups' 0
                $coverageCovered = Get-LongValue $coverage 'covered_finding_groups' 0
                $coverageAttempted = Get-LongValue $coverage 'attempted_plans' $selectedCount
                $caseRecord['dynamic'] = [ordered]@{ status = $verification; requested = $caseRecord.command.verify_policy; eligible_groups = $coverageEligible; covered_groups = $coverageCovered; attempted = $coverageAttempted; unique_plans = Get-LongValue $coverage 'unique_plans' 0; attempted_plans = $coverageAttempted; coverage = $coverageStatus; coverage_permille = Get-LongValue $coverage 'coverage_permille' -1; plan_reuse_permille = Get-LongValue $coverage 'plan_reuse_permille' -1; confirmed = Get-LongValue $coverage 'confirmed_groups' 0; refuted = 0; unknown = Get-LongValue $coverage 'no_observation_groups' 0; deferred_reasons = Get-PropertyValue $coverage 'deferred_reasons'; coverage_path = if ($null -eq $coverage) { $null } else { $coveragePath }; backend = Get-StringValue $dynamicMeta 'backend' 'UNKNOWN'; isolation_level = Get-StringValue $dynamicMeta 'isolation_level' 'UNKNOWN'; cleanup = Get-StringValue $dynamicMeta 'cleanup' 'UNKNOWN'; sink_distorted = Get-BooleanValue $dynamicMeta 'sink_distorted' $false; sandbox_ready = Get-BooleanValue $dynamicMeta 'sandbox_ready' $false; status_counts = if ($null -eq $statusCounts) { @{} } else { $statusCounts }; target_code_execution_possible = $caseRecord.command.target_code_execution_possible; target_code_executed = $caseRecord.dynamic_policy.target_code_executed }
                $caseOutcomeStatus = Get-StringValue $metadataOutcome 'status' 'NOT_RUN'
                $caseFailed = ($execution.exit_code -ne 0) -or ($evidence.status -ne 'COMPLETE') -or ($null -eq $metadata) -or ($inputDigest.status -ne 'PASS') -or ($caseOutcomeStatus -in @('FAILED', 'USAGE_ERROR', 'UNSUPPORTED', 'NOT_RUN'))
                if ($caseFailed) { $anyFailure = $true }
                if ($caseOutcomeStatus -eq 'PARTIAL') { $anyPartial = $true }
            }
        } catch {
            $anyFailure = $true
            $caseRecord['outcome'] = New-RunOutcome 'FAILED' 'INTERNAL' 'UNKNOWN' 'UNKNOWN' -ReasonCodes @('RUNNER_CASE_FAILURE') -Detail $_.Exception.Message
        }
        if ($caseRecord.semantic.status -eq 'OBSERVED' -and $caseRecord.semantic.completeness -eq 'COMPLETE') { $run.summary.semantic_complete++ }
        if ($caseRecord.evidence.status -eq 'COMPLETE') { $run.summary.evidence_complete++ }
        $caseMetricStatus = Get-PropertyValue $caseRecord.semantic 'metric_status'
        if ($null -ne $caseMetricStatus) {
            foreach ($statusProperty in $caseMetricStatus.PSObject.Properties) {
                Add-StatusCount $run.summary.metric_status_counts ([string]$statusProperty.Value)
            }
        }
        $caseNamespaceStatus = Get-PropertyValue $caseRecord.semantic 'metric_namespace_status'
        if ($null -ne $caseNamespaceStatus) {
            foreach ($statusProperty in $caseNamespaceStatus.PSObject.Properties) {
                Add-StatusCount $run.summary.metric_namespace_status_counts ([string]$statusProperty.Value)
            }
        }
        $caseTree = Get-PropertyValue (Get-PropertyValue $caseRecord 'resources') 'process_tree'
        Add-StatusCount $run.summary.process_tree_status_counts (Get-StringValue $caseTree 'status' 'UNKNOWN')
        if ($caseRecord.dynamic.status -ne 'NOT_RUN') { $run.summary.dynamic_attempted += [long]$caseRecord.dynamic.attempted }
        $run.summary.dynamic_unknown += [long]$caseRecord.dynamic.unknown
        if ($caseRecord.execution.status -eq 'COMPLETED' -or $caseRecord.execution.status -eq 'NOT_RUN_PLAN_ONLY') { $run.summary.completed++ } else { $run.summary.failed++ }
        $run.cases.Add([pscustomobject]$caseRecord) | Out-Null
        Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    }
    $run.fingerprint = Get-DeterministicFingerprint $run.manifest.sha256 $run.tool.launcher_sha256 $ruleHash $git.head $git.worktree_digest $launcherRuntimeProfile.java_sha256 @($plans.ToArray())
    $run.state = if ($anyFailure) { 'FAILED' } elseif ($PlanOnly) { 'PLAN_ONLY_COMPLETE' } else { 'COMPLETE' }
    $run.outcome = if ($anyFailure) {
        New-RunOutcome 'FAILED' 'INTERNAL' 'UNKNOWN' 'UNKNOWN' -ReasonCodes @('CASE_FAILURE') -Detail 'one or more cases failed'
    } elseif ($PlanOnly) {
        New-RunOutcome 'NOT_RUN' 'OK' 'NOT_APPLICABLE' 'NOT_REQUESTED' -ReasonCodes @('PLAN_ONLY') -Detail 'plans generated without scanner execution'
    } elseif ($anyPartial) {
        New-RunOutcome 'PARTIAL' 'OK' 'PARTIAL' 'NOT_REQUESTED' -ReasonCodes @('CASE_PARTIAL') -Detail 'one or more scans are semantically partial'
    } else {
        New-RunOutcome 'SUCCESS' 'OK' 'SUPPORTED' 'NOT_REQUESTED' -ReasonCodes @() -Detail 'all selected cases completed'
    }
    $run.finished_at = (Get-Date).ToUniversalTime().ToString('o')
    $run.summary.selected_cases = $selectedIds
    Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    return $run
}

try {
    if ($SelfTest) {
        if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'MANIFEST_REQUIRED_FOR_SELFTEST' }
        $self = Invoke-RunnerSelfTest (Resolve-RegularFile $ManifestPath (Get-Location).Path 'manifest')
        Write-Output ('RUN_REGRESSION_V2_SELF_TEST=PASS')
        Write-Output ('tests=' + (($self.tests) -join ','))
        exit 0
    }
    $result = Invoke-Runner
    $result | ConvertTo-Json -Depth 30
    exit (Get-RunOutcomeExitCode $result.outcome)
} catch {
    [Console]::Error.WriteLine(('RUN_REGRESSION_V2_ERROR: ' + $_.Exception.Message))
    exit 2
}
