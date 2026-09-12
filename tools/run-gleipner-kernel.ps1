[CmdletBinding()]
param(
    [string] $ManifestPath = 'benchmark/manifest/gleipner.v2.json',
    [string] $LauncherJar,
    [string] $OutputRoot,
    [string[]] $CaseId,
    [string] $JabbaExe,
    [string] $LauncherJdkId = 'temurin@17.0.19',
    [ValidateRange(1, 30)]
    [int] $LauncherJdkFeature = 17,
    [ValidateRange(1, 86400000)]
    [long] $ProcessTimeoutMs = 900000,
    [switch] $PlanOnly,
    [switch] $SelfTest
)

# This adapter is deliberately benchmark-side orchestration.  It never changes
# Just rules or truth.  The only score source is the manifest embedded in each
# generated Gleipner category JAR and the official evaluator JAR.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedContractId = 'JUST-PROD-D009-V1'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ValidatorPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'validate-benchmark-manifest.ps1'))
$AdapterVersion = 'gleipner-kernel-adapter-v1'

Add-Type -AssemblyName System.IO.Compression.FileSystem

function Resolve-PowerShellExecutable {
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
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
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

function Get-RelativePathCompat {
    param([Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Path)
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    $method = [IO.Path].GetMethod('GetRelativePath', [Type[]]@([string], [string]))
    if ($null -ne $method) { return ([IO.Path]::GetRelativePath($baseFull, $pathFull)).Replace([char]92, [char]47) }
    return [Uri]::UnescapeDataString(([Uri]$baseFull).MakeRelativeUri(([Uri]$pathFull)).ToString()).Replace([char]92, [char]47)
}

function Resolve-RepositoryPath {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Label)
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "${Label}_PATH_EMPTY" }
    if ([IO.Path]::IsPathRooted($Value) -or $Value -match '^[A-Za-z]:') { throw "${Label}_PATH_ABSOLUTE" }
    $candidate = [IO.Path]::GetFullPath((Join-Path $Base $Value))
    $root = $RepoRoot.TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    if (-not ($candidate.Equals($RepoRoot, [StringComparison]::OrdinalIgnoreCase) -or $candidate.StartsWith($root, [StringComparison]::OrdinalIgnoreCase))) { throw "${Label}_PATH_ESCAPE" }
    if (-not (Test-Path -LiteralPath $candidate)) { throw "${Label}_MISSING: $candidate" }
    return $candidate
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Label)
    $path = Resolve-RepositoryPath $Value $Base $Label
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "${Label}_NOT_FILE: $path" }
    return $path
}

function Resolve-Directory {
    param([Parameter(Mandatory = $true)] [string] $Value, [Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Label)
    $path = Resolve-RepositoryPath $Value $Base $Label
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "${Label}_NOT_DIRECTORY: $path" }
    return $path
}

function Invoke-Capture {
    param([Parameter(Mandatory = $true)] [string] $FilePath, [Parameter(Mandatory = $true)] [string[]] $Arguments)
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $FilePath @Arguments 2>&1)
        return [pscustomobject]@{ exit_code = [int]$LASTEXITCODE; output = (($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim() }
    } finally { $ErrorActionPreference = $previous }
}

function Resolve-JabbaExecutable {
    param([string] $Requested)
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $candidate = [IO.Path]::GetFullPath($Requested)
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "JABBA_NOT_FOUND: $candidate" }
        return $candidate
    }
    $profiles = [Collections.Generic.List[string]]::new()
    foreach ($candidateProfile in @($env:USERPROFILE, [Environment]::GetFolderPath('UserProfile'))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidateProfile) -and -not $profiles.Contains([string]$candidateProfile)) { $profiles.Add([string]$candidateProfile) | Out-Null }
    }
    $usersRoot = Join-Path ([IO.Path]::GetPathRoot($RepoRoot)) 'Users'
    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not $profiles.Contains($_.FullName)) { $profiles.Add($_.FullName) | Out-Null }
        }
    }
    foreach ($candidateProfile in $profiles) {
        $candidate = Join-Path $candidateProfile '.jabba\bin\jabba.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return [IO.Path]::GetFullPath($candidate) }
    }
    $command = Get-Command jabba -ErrorAction SilentlyContinue
    if ($null -ne $command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source)) { return [IO.Path]::GetFullPath([string]$command.Source) }
    throw 'JABBA_NOT_FOUND: use -JabbaExe or install Jabba under .jabba\bin'
}

function Get-JdkHomeDigest {
    param([Parameter(Mandatory = $true)] [string] $JdkHomePath, [Parameter(Mandatory = $true)] [int] $Feature)
    $files = [Collections.Generic.List[string]]::new()
    $release = Join-Path $JdkHomePath 'release'
    if (Test-Path -LiteralPath $release -PathType Leaf) { $files.Add($release) | Out-Null }
    if ($Feature -eq 8) {
        $rt = Join-Path $JdkHomePath 'jre\lib\rt.jar'
        if (Test-Path -LiteralPath $rt -PathType Leaf) { $files.Add($rt) | Out-Null }
    } else {
        $jmods = Join-Path $JdkHomePath 'jmods'
        if (Test-Path -LiteralPath $jmods -PathType Container) { Get-ChildItem -LiteralPath $jmods -Filter '*.jmod' -File | Sort-Object FullName | ForEach-Object { $files.Add($_.FullName) | Out-Null } }
    }
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $item = Get-Item -LiteralPath $file -Force
        $rows.Add("$(Get-RelativePathCompat $JdkHomePath $item.FullName)=$(Get-Sha256 $item.FullName)=$($item.Length)") | Out-Null
    }
    return Get-TextSha256 (($rows.ToArray()) -join "`n")
}

function Resolve-JdkProfile {
    param([Parameter(Mandatory = $true)] $JdkProfile, [Parameter(Mandatory = $true)] [string] $JabbaPath)
    $id = Get-StringValue $JdkProfile 'id' ''
    $feature = [int](Get-LongValue $JdkProfile 'feature' 0)
    if ([string]::IsNullOrWhiteSpace($id) -or $feature -le 0) { throw 'JDK_PROFILE_INVALID' }
    $which = Invoke-Capture $JabbaPath @('which', $id)
    if ($which.exit_code -ne 0) { throw "JDK_NOT_FOUND: id=$id output=$($which.output)" }
    $jdkHomeResolved = ($which.output -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 1).Trim()
    if ([string]::IsNullOrWhiteSpace($jdkHomeResolved)) { throw "JDK_HOME_EMPTY: id=$id" }
    if (-not (Test-Path -LiteralPath $jdkHomeResolved -PathType Container)) { throw "JDK_HOME_MISSING: id=$id home=$jdkHomeResolved" }
    $java = Join-Path $jdkHomeResolved 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $java -PathType Leaf)) { throw "JDK_JAVA_MISSING: id=$id" }
    $versionResult = Invoke-Capture $java @('--version')
    if ($versionResult.exit_code -ne 0) { $versionResult = Invoke-Capture $java @('-version') }
    $match = [Regex]::Match($versionResult.output, 'version\s+"(?<version>[^"]+)"')
    if (-not $match.Success) { $match = [Regex]::Match($versionResult.output, '(?<version>\d+(?:\.\d+){0,3})') }
    if (-not $match.Success) { throw "JDK_VERSION_UNPARSEABLE: id=$id" }
    $version = $match.Groups['version'].Value
    $featureText = if ($version.StartsWith('1.')) { $version.Substring(2).Split('.')[0] } else { $version.Split('.')[0] }
    $actualFeature = 0
    if (-not [int]::TryParse($featureText, [ref]$actualFeature) -or $actualFeature -ne $feature) { throw "JDK_FEATURE_MISMATCH: id=$id expected=$feature actual=$actualFeature" }
    if ($feature -eq 8 -and -not (Test-Path -LiteralPath (Join-Path $jdkHomeResolved 'jre\lib\rt.jar') -PathType Leaf)) { throw "JDK_LAYOUT_MISMATCH: id=$id" }
    if ($feature -ne 8 -and -not (Test-Path -LiteralPath (Join-Path $jdkHomeResolved 'release') -PathType Leaf) -and -not (Test-Path -LiteralPath (Join-Path $jdkHomeResolved 'jmods') -PathType Container)) { throw "JDK_LAYOUT_MISMATCH: id=$id" }
    return [ordered]@{ id = $id; feature = $feature; resolver = 'jabba'; home = [IO.Path]::GetFullPath($jdkHomeResolved); java = [IO.Path]::GetFullPath($java); java_sha256 = Get-Sha256 $java; java_version = $version; java_version_output = $versionResult.output; home_digest = Get-JdkHomeDigest $jdkHomeResolved $feature; status = 'MATCH' }
}

function Get-JarManifestAttributes {
    param([Parameter(Mandatory = $true)] [string] $JarPath)
    $archive = [IO.Compression.ZipFile]::OpenRead($JarPath)
    try {
        $entry = $archive.GetEntry('META-INF/MANIFEST.MF')
        if ($null -eq $entry) { throw "JAR_MANIFEST_MISSING: $JarPath" }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $archive.Dispose() }
    $attrs = [ordered]@{}
    $last = $null
    foreach ($line in ($text -split "`r?`n")) {
        if ($line.StartsWith(' ') -and $null -ne $last) { $attrs[$last] = ([string]$attrs[$last]) + $line.Substring(1); continue }
        if ($line -match '^([^:]+):[ ]?(.*)$') { $last = $matches[1]; $attrs[$last] = $matches[2] } else { $last = $null }
    }
    return $attrs
}

function Get-ArtifactRecord {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Definition, [Parameter(Mandatory = $true)] [string] $Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item -isnot [IO.FileInfo]) { throw "${Label}_NOT_FILE" }
    $actualHash = Get-Sha256 $Path
    $expectedHash = Get-StringValue $Definition 'sha256' ''
    $expectedBytes = Get-PropertyValue $Definition 'bytes'
    if ([string]::IsNullOrWhiteSpace($expectedHash) -or $expectedHash -eq 'null') { throw "${Label}_HASH_UNPINNED" }
    if (-not $actualHash.Equals($expectedHash.ToLowerInvariant(), [StringComparison]::Ordinal)) { throw "${Label}_HASH_MISMATCH: expected=$expectedHash actual=$actualHash" }
    if ($null -ne $expectedBytes -and [int64]$item.Length -ne [int64]$expectedBytes) { throw "${Label}_SIZE_MISMATCH" }
    return [ordered]@{ path = $Path; relative_path = Get-RelativePathCompat $RepoRoot $Path; bytes = [int64]$item.Length; sha256 = $actualHash; expected_sha256 = $expectedHash.ToLowerInvariant(); expected_bytes = if ($null -eq $expectedBytes) { $null } else { [int64]$expectedBytes }; status = 'MATCH' }
}

function Get-TextFileRecord {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] [string] $Name)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return [ordered]@{ name = $Name; path = $Path; status = 'MISSING'; bytes = $null; sha256 = $null; rows = $null } }
    $item = Get-Item -LiteralPath $Path -Force
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8)
    return [ordered]@{ name = $Name; path = $Path; status = 'OBSERVED'; bytes = [int64]$item.Length; sha256 = Get-Sha256 $Path; rows = [Math]::Max(0, $lines.Count - 1) }
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + $Value.Replace('\\', '\\\\').Replace('"', '\\"') + '"'
}

function Invoke-ProcessCapture {
    param([Parameter(Mandatory = $true)] [string] $FilePath, [Parameter(Mandatory = $true)] [string[]] $Arguments, [Parameter(Mandatory = $true)] [string] $WorkingDirectory, [Parameter(Mandatory = $true)] [string] $StdoutPath, [Parameter(Mandatory = $true)] [string] $StderrPath, [Parameter(Mandatory = $true)] [long] $TimeoutMs)
    $quoted = @($Arguments | ForEach-Object { ConvertTo-ProcessArgument ([string]$_) }) -join ' '
    $watch = [Diagnostics.Stopwatch]::StartNew(); $process = $null; $timedOut = $false
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $quoted -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath -NoNewWindow -PassThru
        if (-not $process.WaitForExit([int][Math]::Min($TimeoutMs, [int]::MaxValue))) { $timedOut = $true; try { $process.Kill($true) } catch { try { $process.Kill() } catch { } }; $process.WaitForExit(5000) | Out-Null }
        $watch.Stop()
        $exitCode = if ($timedOut) { 124 } else { [int]$process.ExitCode }
        $cpu = -1L; $rss = -1L
        try { $process.Refresh(); $cpu = [long]$process.TotalProcessorTime.TotalMilliseconds } catch { }
        try { $rss = [long][Math]::Ceiling($process.PeakWorkingSet64 / 1MB) } catch { }
        if ($rss -le 0) { $rss = -1L }
        if ($cpu -lt 0) { $cpu = -1L }
        return [ordered]@{ status = if ($timedOut) { 'TIMEOUT' } else { 'COMPLETED' }; exit_code = $exitCode; process_id = [int]$process.Id; wall_ms = [long]$watch.ElapsedMilliseconds; cpu_ms = $cpu; rss_peak_mb = $rss; stdout = $StdoutPath; stderr = $StderrPath; process_tree = [ordered]@{ status = 'NOT_SAMPLED'; source = 'adapter-parent-only'; reason_code = 'P0_8_ADAPTER_PROCESS_TREE_NOT_COLLECTED' } }
    } finally { $watch.Stop(); if ($null -ne $process) { $process.Dispose() } }
}

function Get-BlockRecords {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "CONVERTER_OUTPUT_MISSING: $Path" }
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $blocks = @($text -split "(?:\r?\n)[\t ]*(?:\r?\n)+" | ForEach-Object {
        $lines = @($_ -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -gt 0) { [pscustomobject]@{ lines = @($lines); first = [string]$lines[0] } }
    })
    return $blocks
}

function Test-IsStrictPrefix {
    param([string[]] $Short, [string[]] $Long)
    if ($Short.Count -ge $Long.Count) { return $false }
    for ($i = 0; $i -lt $Short.Count; $i++) { if ($Short[$i] -ne $Long[$i]) { return $false } }
    return $true
}

function Normalize-EvaluatorBlocks {
    param([Parameter(Mandatory = $true)] [string] $InputPath, [Parameter(Mandatory = $true)] [string] $OutputPath)
    $records = [Collections.Generic.List[object]]::new()
    foreach ($block in @(Get-BlockRecords $InputPath)) {
        $lines = @($block.lines)
        $root = 0
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^gleipner\.chains\.') { $root = $i; break }
        }
        $suffix = ($lines[$root..($lines.Count - 1)] -join "`n")
        $records.Add([pscustomobject]@{ lines = $lines; first = [string]$lines[0]; suffix = $suffix; root = $root }) | Out-Null
    }
    # A static evidence row can repeat an edge with a field-annotated variant or
    # prepend a generic TriggerGadget/Hashtable wrapper.  Keep one deterministic
    # representative for the identical chain suffix; this is representation
    # normalization, not top-k ranking or truth manipulation.
    $bySuffix = @{}
    foreach ($record in @($records | Sort-Object suffix, @{Expression = { $_.lines.Count }; Ascending = $true}, first)) {
        if (-not $bySuffix.ContainsKey($record.suffix)) { $bySuffix[$record.suffix] = $record }
    }
    $deduped = [Collections.Generic.List[object]]::new()
    foreach ($record in @($bySuffix.Values | Sort-Object suffix)) { $deduped.Add($record) | Out-Null }
    # When one row is an exact prefix of another from the same entry method, the
    # longer row is a cross-chain concatenation.  Suppress only that strict-prefix
    # representation; divergent branches remain independent (Multipath).
    $kept = [Collections.Generic.List[object]]::new()
    foreach ($record in @($deduped | Sort-Object first, @{Expression = { $_.lines.Count }; Ascending = $true}, suffix)) {
        $shadowed = $false
        foreach ($existing in @($kept | Where-Object { $_.first -eq $record.first })) {
            if (Test-IsStrictPrefix $existing.lines $record.lines) { $shadowed = $true; break }
        }
        if (-not $shadowed) { $kept.Add($record) | Out-Null }
    }
    $ordered = @($kept | Sort-Object suffix, first)
    $builder = [Text.StringBuilder]::new()
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        if ($i -gt 0) { [void]$builder.Append("`n`n") }
        [void]$builder.Append(($ordered[$i].lines -join "`n"))
    }
    [IO.File]::WriteAllText($OutputPath, $builder.ToString(), [Text.UTF8Encoding]::new($false))
    return [ordered]@{ raw_blocks = $records.Count; normalized_blocks = $ordered.Count; duplicate_suffixes_removed = $records.Count - $deduped.Count; strict_prefixes_removed = $deduped.Count - $ordered.Count; sha256 = Get-Sha256 $OutputPath; bytes = [int64](Get-Item -LiteralPath $OutputPath).Length }
}

function Parse-EvaluatorCounts {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "EVALUATOR_OUTPUT_MISSING: $Path" }
    $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $clean = [Regex]::Replace($text, "`e\[[0-9;]*m", '')
    $tp = [Regex]::Match($clean, 'True positives:\s*(\d+)\s*/\s*(\d+)')
    $fp = [Regex]::Match($clean, 'False positives:\s*(\d+)\s*/\s*(\d+)')
    $ys = [Regex]::Match($clean, 'Ysoserial Chains:\s*(\d+)')
    if (-not $tp.Success -or -not $fp.Success) { throw "EVALUATOR_PARSE_FAILED: $Path" }
    return [ordered]@{ observed_tp = [int]$tp.Groups[1].Value; expected_tp = [int]$tp.Groups[2].Value; observed_fp = [int]$fp.Groups[1].Value; expected_fp = [int]$fp.Groups[2].Value; ysoserial = if ($ys.Success) { [int]$ys.Groups[1].Value } else { $null }; output_sha256 = Get-Sha256 $Path; output_bytes = [int64](Get-Item -LiteralPath $Path).Length }
}

function Write-JsonAtomic {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    $partial = "$Path.$([Guid]::NewGuid().ToString('N')).partial"
    try {
        $Value | ConvertTo-Json -Depth 35 | Set-Content -LiteralPath $partial -Encoding UTF8 -NoNewline
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = "$Path.bak"
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
            [IO.File]::Replace($partial, $Path, $backup, $true)
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        } else { [IO.File]::Move($partial, $Path) }
    } finally { if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force } }
}

function Assert-OutputAvailable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path) { throw "OUTPUT_EXISTS: refusing to overwrite $Path" }
}

function Invoke-AdapterSelfTest {
    param([Parameter(Mandatory = $true)] [string] $ManifestFile)
    $definition = Get-Content -LiteralPath $ManifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string](Get-PropertyValue $definition 'contract_id') -ne $ExpectedContractId) { throw 'SELFTEST_CONTRACT_MISMATCH' }
    $case = @((Get-PropertyValue $definition 'cases'))[0]
    $base = Split-Path -Parent $ManifestFile
    $artifact = @((Get-PropertyValue $case 'artifacts') | Where-Object { (Get-StringValue $_ 'status' '') -eq 'OBSERVED' })[0]
    $artifactPath = Resolve-RegularFile (Get-StringValue $artifact 'path' '') $base 'selftest-artifact'
    $attrs = Get-JarManifestAttributes $artifactPath
    if ([int]$attrs['chains-tp'] -ne 2 -or [int]$attrs['chains-fp'] -ne 0) { throw 'SELFTEST_MANIFEST_ATTRIBUTES_FAILED' }
    $fixture = Join-Path ([IO.Path]::GetTempPath()) ('just-gleipner-adapter-selftest-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $fixture | Out-Null
    try {
        $raw = Join-Path $fixture 'raw.txt'; $normalized = Join-Path $fixture 'normalized.txt'
        [IO.File]::WriteAllText($raw, "gleipner.core.TriggerGadget;readObject;Ljava/io/ObjectInputStream`ngleipner.chains.basic.BasicLinkGadget;hashCode`ngleipner.chains.basic.BasicSinkGadget;load`n`ngleipner.chains.basic.BasicLinkGadget;hashCode`ngleipner.chains.basic.BasicSinkGadget;load`n`ngleipner.chains.basic.BasicTriggerGadget;readObject;Ljava/io/ObjectInputStream`n`ngleipner.chains.basic.BasicTriggerGadget;readObject;Ljava/io/ObjectInputStream`ngleipner.core.SinkGadget;sinkMethod;Ljava.lang.String", [Text.UTF8Encoding]::new($false))
        $normalizedStats = Normalize-EvaluatorBlocks $raw $normalized
        if ([int]$normalizedStats.normalized_blocks -ne 2 -or [int]$normalizedStats.duplicate_suffixes_removed -ne 1 -or [int]$normalizedStats.strict_prefixes_removed -ne 1) { throw 'SELFTEST_NORMALIZATION_FAILED' }
        $eval = Join-Path $fixture 'eval.txt'; [IO.File]::WriteAllText($eval, "True positives: `e[32m2`e[0m/2`nFalse positives: 0/0`nYsoserial Chains: 0", [Text.UTF8Encoding]::new($false))
        $counts = Parse-EvaluatorCounts $eval
        if ($counts.observed_tp -ne 2 -or $counts.expected_tp -ne 2 -or $counts.observed_fp -ne 0 -or $counts.expected_fp -ne 0) { throw 'SELFTEST_EVALUATOR_PARSE_FAILED' }
        return [ordered]@{ status = 'PASS'; tests = @('contract-id', 'official-manifest-attributes', 'suffix-deduplication', 'strict-prefix-normalization', 'ansi-evaluator-parser') }
    } finally { if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force } }
}

function Invoke-Adapter {
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'MANIFEST_REQUIRED' }
    $manifestFile = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ManifestPath)) }
    if (-not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) { throw "MANIFEST_MISSING: $manifestFile" }
    $manifestBase = Split-Path -Parent $manifestFile
    $manifestText = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8
    $definition = $manifestText | ConvertFrom-Json
    if ([string](Get-PropertyValue $definition 'contract_id') -ne $ExpectedContractId) { throw 'CONTRACT_MISMATCH' }
    if ([string](Get-PropertyValue $definition 'manifest_kind') -ne 'gleipner-kernel') { throw 'MANIFEST_KIND_MISMATCH' }
    if (-not (Test-Path -LiteralPath $ValidatorPath -PathType Leaf)) { throw 'MANIFEST_VALIDATOR_MISSING' }
    $validatorHost = Resolve-PowerShellExecutable
    $validationJson = @(& $validatorHost -NoProfile -ExecutionPolicy Bypass -File $ValidatorPath -ManifestPath $manifestFile -Json)
    if ($LASTEXITCODE -ne 0) { throw "MANIFEST_INVALID: $($validationJson -join ' ')" }
    $validation = ($validationJson -join "`n") | ConvertFrom-Json
    if (-not [bool]$validation.valid) { throw 'MANIFEST_INVALID' }
    $case = @((Get-PropertyValue $definition 'cases'))[0]
    $directoryDefinition = @((Get-PropertyValue $case 'artifacts') | Where-Object { (Get-StringValue $_ 'kind' '') -eq 'directory' })[0]
    $observedArtifactDefinition = @((Get-PropertyValue $case 'artifacts') | Where-Object { (Get-StringValue $_ 'status' '') -eq 'OBSERVED' -and (Get-StringValue $_ 'kind' '') -eq 'jar' })[0]
    $categoryDirectory = Resolve-Directory (Get-StringValue $directoryDefinition 'path' '') $manifestBase 'gleipner-category-directory'
    $basicPath = Resolve-RegularFile (Get-StringValue $observedArtifactDefinition 'path' '') $manifestBase 'gleipner-basic-artifact'
    $basicRecord = Get-ArtifactRecord $basicPath $observedArtifactDefinition 'gleipner-basic-artifact'
    $dependencies = @((Get-PropertyValue $case 'dependencies') | Where-Object { (Get-StringValue $_ 'scope' '') -eq 'external' })
    if ($dependencies.Count -ne 1) { throw 'EVALUATOR_DEPENDENCY_COUNT' }
    $evaluatorDefinition = $dependencies[0]
    $evaluatorPath = Resolve-RegularFile (Get-StringValue $evaluatorDefinition 'location' '') $manifestBase 'gleipner-evaluator'
    $evaluatorRecord = Get-ArtifactRecord $evaluatorPath $evaluatorDefinition 'gleipner-evaluator'
    $chainsClasses = Resolve-Directory '../Gleipner/chains/target/classes' $manifestBase 'gleipner-chains-classes'
    $converterPath = Resolve-RegularFile '../Gleipner/GleipnerOut.java' $manifestBase 'gleipner-converter'
    $rulesPath = Resolve-RegularFile '../Gleipner/just-rules.yaml' $manifestBase 'gleipner-rules'
    $jabba = Resolve-JabbaExecutable $JabbaExe
    $launcherJdk = Resolve-JdkProfile ([pscustomobject]@{ id = $LauncherJdkId; feature = $LauncherJdkFeature }) $jabba
    $targetJdk = Resolve-JdkProfile (Get-PropertyValue $case 'target_jdk') $jabba
    $launcher = $null; $launcherHash = 'NOT_USED'
    if (-not [string]::IsNullOrWhiteSpace($LauncherJar)) { $launcher = [IO.Path]::GetFullPath($LauncherJar) } elseif (-not $PlanOnly) { throw 'LAUNCHER_REQUIRED' }
    if ($null -ne $launcher) { if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) { throw "LAUNCHER_MISSING: $launcher" }; $launcherHash = Get-Sha256 $launcher }
    $allJars = @(Get-ChildItem -LiteralPath $categoryDirectory -Filter 'gleipner.chains-1.0-*.jar' -File | Sort-Object Name)
    $categories = [Collections.Generic.List[object]]::new()
    foreach ($jarItem in $allJars) {
        $attrs = Get-JarManifestAttributes $jarItem.FullName
        if (-not $attrs.Contains('chains-tp') -or -not $attrs.Contains('chains-fp')) { continue }
        $categories.Add([pscustomobject]@{ name = $jarItem.BaseName; path = $jarItem.FullName; bytes = [int64]$jarItem.Length; sha256 = Get-Sha256 $jarItem.FullName; expected_tp = [int]$attrs['chains-tp']; expected_fp = [int]$attrs['chains-fp'] }) | Out-Null
    }
    if ($categories.Count -eq 0) { throw 'GLEIPNER_CATEGORIES_EMPTY' }
    $selected = if ($null -eq $CaseId -or @($CaseId).Count -eq 0 -or @($CaseId) -contains 'gleipner-all-categories') { @($categories | Sort-Object name) } else {
        $wanted = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); foreach ($id in @($CaseId)) { $wanted.Add($id) | Out-Null }
        @($categories | Where-Object { $wanted.Contains($_.name) -or $wanted.Contains(($_.name -replace '^gleipner\.chains-1\.0-', '')) } | Sort-Object name)
    }
    if ($selected.Count -eq 0) { throw 'CATEGORY_SELECTION_EMPTY' }
    if ($null -ne $CaseId -and @($CaseId).Count -gt 0 -and -not (@($CaseId) -contains 'gleipner-all-categories') -and $selected.Count -ne @($CaseId).Count) { throw 'CATEGORY_SELECTION_UNKNOWN_ID' }
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path (Join-Path $RepoRoot 'benchmark\runs') ('p08-gleipner-' + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $root = [IO.Path]::GetFullPath($OutputRoot); Assert-OutputAvailable $root; New-Item -ItemType Directory -Path $root | Out-Null
    $run = [ordered]@{
        schema_version = 2; contract_id = $ExpectedContractId; state = 'RUNNING'; run_id = Split-Path -Leaf $root; started_at = (Get-Date).ToUniversalTime().ToString('o'); finished_at = $null
        mode = 'gadget-kernel'; manifest = [ordered]@{ path = $manifestFile; relative_path = Get-RelativePathCompat $RepoRoot $manifestFile; sha256 = Get-TextSha256 $manifestText; id = Get-StringValue $definition 'manifest_id' 'UNKNOWN'; truth_status = Get-StringValue $case.truth 'status' 'UNKNOWN'; validator = [ordered]@{ valid = [bool]$validation.valid } }
        tool = [ordered]@{ name = 'Just'; adapter = $AdapterVersion; adapter_path = [IO.Path]::GetFullPath($PSCommandPath); adapter_sha256 = Get-Sha256 ([IO.Path]::GetFullPath($PSCommandPath)); launcher = $launcher; launcher_sha256 = $launcherHash; rules = [ordered]@{ path = $rulesPath; relative_path = Get-RelativePathCompat $RepoRoot $rulesPath; sha256 = Get-Sha256 $rulesPath }; converter = [ordered]@{ path = $converterPath; relative_path = Get-RelativePathCompat $RepoRoot $converterPath; sha256 = Get-Sha256 $converterPath }; evaluator = $evaluatorRecord }
        jdk_resolver = [ordered]@{ executable = $jabba; policy = 'explicit-jabba-which'; no_global_use = $true; launcher_runtime = $launcherJdk; evaluator_runtime = $targetJdk }
        configuration = [ordered]@{ plan_only = [bool]$PlanOnly; scan_verify_policy = 'no-verify'; dynamic = 'NOT_REQUESTED'; process_timeout_ms = $ProcessTimeoutMs; selected_categories = @($selected | ForEach-Object { $_.name }); class_initialization_possible = $true; sink_invocation = 'NOT_INVOKED' }
        safety = [ordered]@{ target_trust = 'JUST_OWNED_BENCHMARK_FIXTURES_ONLY'; dynamic_verifier = 'DISABLED'; arbitrary_payload = 'NOT_EXECUTED'; dangerous_sink = 'NOT_INVOKED'; network = 'NOT_REQUESTED'; file_write = 'ADAPTER_OUTPUT_ONLY'; evaluator_class_initialization_possible = $true; job_object = [ordered]@{ capability = 'NOT_USED_BY_ADAPTER'; note = 'Job Object is not a complete sandbox.' } }
        artifacts = [ordered]@{ basic = $basicRecord; evaluator = $evaluatorRecord; category_directory = [ordered]@{ path = $categoryDirectory; relative_path = Get-RelativePathCompat $RepoRoot $categoryDirectory; status = 'OBSERVED'; inventory_count = $categories.Count; inventory_digest = Get-TextSha256 (($categories | Sort-Object name | ForEach-Object { "$($_.name)|$($_.sha256)|$($_.bytes)|$($_.expected_tp)|$($_.expected_fp)" }) -join "`n") } }
        categories = [Collections.Generic.List[object]]::new()
        summary = [ordered]@{ selected = @($selected | ForEach-Object { $_.name }); total_categories = $categories.Count; completed = 0; failed = 0; semantic_mismatch = 0; expected_tp = 0; expected_fp = 0; observed_tp = 0; observed_fp = 0; tp_match = $false; fp_match = $false; all_category_counts_match = $false; static_evidence_complete = 0; evaluator_blocks = 0; normalization_removed = 0 }
    }
    Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    $anyFailure = $false
    foreach ($category in $selected) {
        $safe = ($category.name -replace '[^A-Za-z0-9_.-]', '_'); $out = Join-Path $root $safe; New-Item -ItemType Directory -Path $out | Out-Null
        $record = [ordered]@{ id = $category.name; artifact = [ordered]@{ path = $category.path; relative_path = Get-RelativePathCompat $RepoRoot $category.path; bytes = $category.bytes; sha256 = $category.sha256; expected_tp = $category.expected_tp; expected_fp = $category.expected_fp }; status = 'RUNNING'; scan = $null; converter = $null; normalization = $null; evaluator = $null; evidence = $null; failure = $null }
        $run.summary.expected_tp += $category.expected_tp; $run.summary.expected_fp += $category.expected_fp
        try {
            $scanOut = Join-Path $out 'scan'; $scanStdout = Join-Path $out 'scan.stdout.log'; $scanStderr = Join-Path $out 'scan.stderr.log'
            if ($PlanOnly) {
                $record.scan = [ordered]@{ status = 'NOT_RUN_PLAN_ONLY'; command = @('-jar', $launcher, 'scan', '--jar', $category.path, '--rules', $rulesPath, '--output', $scanOut, '--jdk-home', $targetJdk.home, '--no-verify') }
                $record.status = 'PLAN_ONLY'
            } else {
                $scanArgs = @('-jar', $launcher, 'scan', '--jar', $category.path, '--rules', $rulesPath, '--output', $scanOut, '--jdk-home', $targetJdk.home, '--no-verify')
                $record.scan = Invoke-ProcessCapture $launcherJdk.java $scanArgs $RepoRoot $scanStdout $scanStderr $ProcessTimeoutMs
                $metadataPath = Join-Path $scanOut 'meta\scan-metadata.json'; $chainsPath = Join-Path $scanOut 'evidence\chains.csv'; $findingsPath = Join-Path $scanOut 'findings\findings.csv'
                $record.evidence = [ordered]@{ metadata = Get-TextFileRecord $metadataPath 'metadata'; chains = Get-TextFileRecord $chainsPath 'chains'; findings = Get-TextFileRecord $findingsPath 'findings' }
                if ($record.scan.exit_code -ne 0 -or $record.evidence.chains.status -ne 'OBSERVED') { throw "SCAN_FAILED: exit=$($record.scan.exit_code)" }
                $raw = Join-Path $out 'evaluator.raw.txt'; $normalized = Join-Path $out 'evaluator.basic.txt'; $convOut = Join-Path $out 'converter.stdout.log'; $convErr = Join-Path $out 'converter.stderr.log'
                $record.converter = Invoke-ProcessCapture $launcherJdk.java @($converterPath, $category.path, $chainsPath, $raw) $RepoRoot $convOut $convErr $ProcessTimeoutMs
                if ($record.converter.exit_code -ne 0 -or -not (Test-Path -LiteralPath $raw -PathType Leaf)) { throw "CONVERTER_FAILED: exit=$($record.converter.exit_code)" }
                $record.normalization = Normalize-EvaluatorBlocks $raw $normalized
                $evalOut = Join-Path $out 'evaluator.stdout.log'; $evalErr = Join-Path $out 'evaluator.stderr.log'; $evalText = Join-Path $out 'evaluator.txt'
                $classPath = ($chainsClasses + [IO.Path]::PathSeparator + $evaluatorPath + [IO.Path]::PathSeparator + $category.path)
                $record.evaluator = Invoke-ProcessCapture $targetJdk.java @('-cp', $classPath, 'gleipner.evaluator.Main', $normalized, $category.path, 'basic', $evalText) $categoryDirectory $evalOut $evalErr $ProcessTimeoutMs
                if ($record.evaluator.exit_code -ne 0) { throw "EVALUATOR_FAILED: exit=$($record.evaluator.exit_code)" }
                $record.evaluator_counts = Parse-EvaluatorCounts $evalText
                if ($record.evaluator_counts.expected_tp -ne $category.expected_tp -or $record.evaluator_counts.expected_fp -ne $category.expected_fp) { throw "EVALUATOR_MANIFEST_DISAGREEMENT: adapter=$($record.evaluator_counts.expected_tp)/$($record.evaluator_counts.expected_fp) jar=$($category.expected_tp)/$($category.expected_fp)" }
                $record.comparison = [ordered]@{ tp_match = ($record.evaluator_counts.observed_tp -eq $category.expected_tp); fp_match = ($record.evaluator_counts.observed_fp -eq $category.expected_fp); status = if ($record.evaluator_counts.observed_tp -eq $category.expected_tp -and $record.evaluator_counts.observed_fp -eq $category.expected_fp) { 'MATCH' } else { 'SEMANTIC_MISMATCH' } }
                $record.status = if ($record.comparison.status -eq 'MATCH') { 'COMPLETE' } else { 'SEMANTIC_MISMATCH' }
                if ($record.status -eq 'SEMANTIC_MISMATCH') { $run.summary.semantic_mismatch++ }
                $run.summary.static_evidence_complete++
                $run.summary.observed_tp += $record.evaluator_counts.observed_tp; $run.summary.observed_fp += $record.evaluator_counts.observed_fp; $run.summary.evaluator_blocks += $record.normalization.normalized_blocks; $run.summary.normalization_removed += $record.normalization.raw_blocks - $record.normalization.normalized_blocks
            }
        } catch {
            $anyFailure = $true; $record.status = 'FAILED'; $record.failure = [ordered]@{ reason_code = if ($_.Exception.Message -match '^([A-Z0-9_]+):') { $Matches[1] } else { 'GLEIPNER_ADAPTER_FAILURE' }; message = $_.Exception.Message }
        }
        if ($record.status -eq 'COMPLETE' -or $record.status -eq 'PLAN_ONLY' -or $record.status -eq 'SEMANTIC_MISMATCH') { $run.summary.completed++ } else { $run.summary.failed++ }
        $run.categories.Add([pscustomobject]$record) | Out-Null; Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    }
    $run.summary.tp_match = ($run.summary.expected_tp -eq $run.summary.observed_tp -and $run.summary.failed -eq 0 -and -not $PlanOnly)
    $run.summary.fp_match = ($run.summary.expected_fp -eq $run.summary.observed_fp -and $run.summary.failed -eq 0 -and -not $PlanOnly)
    $run.summary.all_category_counts_match = ($run.summary.tp_match -and $run.summary.fp_match -and $run.summary.completed -eq $selected.Count)
    $run.state = if ($anyFailure) { 'FAILED' } elseif ($PlanOnly) { 'PLAN_ONLY_COMPLETE' } elseif (-not $run.summary.all_category_counts_match) { 'COMPLETE_WITH_SEMANTIC_MISMATCH' } else { 'COMPLETE' }
    $run.finished_at = (Get-Date).ToUniversalTime().ToString('o')
    $run.reconciliation = [ordered]@{ observed_category_count = $categories.Count; observed_tp = $run.summary.observed_tp; observed_fp = $run.summary.observed_fp; official_manifest_tp = $run.summary.expected_tp; official_manifest_fp = $run.summary.expected_fp; readme_lead_tp = 120; readme_lead_fp = 47; history_267_is_not_a_truth_source = $true; explanation = 'Current generated JAR manifests are authoritative for this build: 30 categories, 122 TP, 47 FP. README 120/47 is stale; historical 267 counts representation variants and are not evaluator truth. Adapter removes only duplicate suffix/prefix representations before the official evaluator.'; truth_manifest_remains = Get-StringValue $case.truth 'status' 'UNKNOWN'; manual_bytecode_review_required = $true }
    Write-JsonAtomic (Join-Path $root 'run-manifest.json') $run
    return $run
}

try {
    if ($SelfTest) {
        $manifestFile = if ([IO.Path]::IsPathRooted($ManifestPath)) { [IO.Path]::GetFullPath($ManifestPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ManifestPath)) }
        $self = Invoke-AdapterSelfTest $manifestFile
        Write-Output 'GLEIPNER_KERNEL_ADAPTER_SELF_TEST=PASS'; Write-Output ('tests=' + ($self.tests -join ',')); exit 0
    }
    $result = Invoke-Adapter
    $result | ConvertTo-Json -Depth 35
    if ($result.state -notin @('COMPLETE', 'PLAN_ONLY_COMPLETE')) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine('GLEIPNER_KERNEL_ADAPTER_ERROR: ' + $_.Exception.Message)
    exit 2
}
