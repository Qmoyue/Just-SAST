[CmdletBinding()]
param(
    [string] $ProjectRoot = (Split-Path -Parent $PSScriptRoot),

    [string] $OutputRoot,

    [switch] $Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TextSha256 {
    param([AllowNull()] [string] $Text)
    $bytes = [Text.Encoding]::UTF8.GetBytes($(if ($null -eq $Text) { '' } else { $Text }))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RelativePathCompat {
    param([Parameter(Mandatory = $true)] [string] $Base, [Parameter(Mandatory = $true)] [string] $Path)
    $baseFull = [IO.Path]::GetFullPath($Base).TrimEnd([char]92, [char]47) + [IO.Path]::DirectorySeparatorChar
    $pathFull = [IO.Path]::GetFullPath($Path)
    if ($pathFull.TrimEnd([char]92, [char]47).Equals($baseFull.TrimEnd([char]92, [char]47), [StringComparison]::OrdinalIgnoreCase)) { return '.' }
    $method = [IO.Path].GetMethod('GetRelativePath', [Type[]]@([string], [string]))
    if ($null -ne $method) { return ([IO.Path]::GetRelativePath($baseFull, $pathFull)).Replace([char]92, [char]47) }
    return [Uri]::UnescapeDataString(([Uri]$baseFull).MakeRelativeUri(([Uri]$pathFull)).ToString()).Replace([char]92, [char]47)
}

function Write-JsonAtomic {
    param([Parameter(Mandatory = $true)] [string] $Path, [Parameter(Mandatory = $true)] $Value)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    $partial = "$Path.$([Guid]::NewGuid().ToString('N')).partial"
    try {
        $Value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $partial -Encoding UTF8 -NoNewline
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $backup = "$Path.bak"
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
            [IO.File]::Replace($partial, $Path, $backup, $true)
            if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        } else {
            [IO.File]::Move($partial, $Path)
        }
    } finally {
        if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    }
}

function Assert-OutputAvailable {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (Test-Path -LiteralPath $Path) { throw "OUTPUT_EXISTS: refusing to overwrite $Path" }
}

function Get-JarSnapshot {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [ordered]@{ status = 'MISSING'; path = $Path; relative_path = Get-RelativePathCompat $ProjectRoot $Path; bytes = $null; sha256 = $null; entry_count = 0; entry_digest = $null; has_just_main = $false; has_picocli = $false; main_class = $null }
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $item = Get-Item -LiteralPath $Path -Force
    $zip = [IO.Compression.ZipFile]::OpenRead($Path)
    $entryLines = [Collections.Generic.List[string]]::new()
    $names = [Collections.Generic.List[string]]::new()
    $mainClass = $null
    $index = 0
    try {
        foreach ($entry in $zip.Entries) {
            $index++
            $name = [string]$entry.FullName
            $names.Add($name) | Out-Null
            $stamp = $entry.LastWriteTime.UtcDateTime.ToString('o')
            $entryLines.Add("$index|$name|$($entry.Length)|$stamp") | Out-Null
            if ($name -eq 'META-INF/MANIFEST.MF') {
                $reader = New-Object IO.StreamReader($entry.Open(), [Text.Encoding]::UTF8, $true)
                try {
                    $manifestText = $reader.ReadToEnd()
                    $mainMatch = [Regex]::Match($manifestText, '(?im)^Main-Class:\s*(?<class>[^\r\n]+)')
                    if ($mainMatch.Success) { $mainClass = $mainMatch.Groups['class'].Value.Trim() }
                } finally { $reader.Dispose() }
            }
        }
    } finally { $zip.Dispose() }
    return [ordered]@{
        status = 'OBSERVED'
        path = $Path
        relative_path = Get-RelativePathCompat $ProjectRoot $Path
        bytes = [long]$item.Length
        sha256 = Get-Sha256 $Path
        entry_count = $index
        entry_digest = Get-TextSha256 (($entryLines.ToArray()) -join "`n")
        has_just_main = [bool]($names -contains 'io/just/sast/cli/JustMain.class')
        has_picocli = [bool]($names | Where-Object { $_ -like 'picocli/*' })
        main_class = $mainClass
    }
}

function Invoke-MavenPackage {
    param(
        [Parameter(Mandatory = $true)] [string] $Maven,
        [Parameter(Mandatory = $true)] [string[]] $MavenArguments,
        [Parameter(Mandatory = $true)] [string] $LogPath
    )
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Maven @MavenArguments 1> $LogPath 2>&1
        $exitCode = [int]$LASTEXITCODE
    } finally {
        $watch.Stop()
        $ErrorActionPreference = $previous
    }
    return [ordered]@{ exit_code = $exitCode; wall_ms = [long]$watch.ElapsedMilliseconds; log = $LogPath }
}

function Invoke-Idempotence {
    $project = [IO.Path]::GetFullPath($ProjectRoot)
    if (-not (Test-Path -LiteralPath (Join-Path $project 'pom.xml') -PathType Leaf)) { throw "PROJECT_INVALID: pom.xml not found under $project" }
    $mavenCommand = Get-Command mvn -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
        $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) ("just-package-idempotence-" + [Guid]::NewGuid().ToString('N'))
    }
    $root = [IO.Path]::GetFullPath($OutputRoot)
    Assert-OutputAvailable $root
    New-Item -ItemType Directory -Path $root | Out-Null
    $reportPath = Join-Path $root 'package-idempotence.json'
    $artifactNames = @('just-sast-0.2.0.jar', 'just-sast-0.2.0-shaded.jar', 'just-sast-0.2.0-testprobe.jar', 'just-sast-0.2.0-verify8.jar', 'original-just-sast-0.2.0.jar')
    $report = [ordered]@{
        schema_version = 1
        contract_id = 'JUST-PROD-D009-V1'
        state = 'RUNNING'
        project = $project
        project_relative = Get-RelativePathCompat $RepoRoot $project
        maven = $mavenCommand.Source
        offline = [bool]$Offline
        started_at = (Get-Date).ToUniversalTime().ToString('o')
        finished_at = $null
        builds = [Collections.Generic.List[object]]::new()
        snapshots = [Collections.Generic.List[object]]::new()
        checks = [Collections.Generic.List[object]]::new()
        failure = $null
    }
    Write-JsonAtomic $reportPath $report
    try {
        $buildDefinitions = @(
            [pscustomobject]@{ id = 'clean-1'; arguments = @('clean', 'package', '-DskipTests') },
            [pscustomobject]@{ id = 'clean-2'; arguments = @('clean', 'package', '-DskipTests') },
            [pscustomobject]@{ id = 'repeat'; arguments = @('package', '-DskipTests') }
        )
        $buildIndex = 0
        foreach ($build in $buildDefinitions) {
            $buildIndex++
            $runArguments = [Collections.Generic.List[string]]::new()
            $runArguments.Add('-f') | Out-Null
            $runArguments.Add((Join-Path $project 'pom.xml')) | Out-Null
            if ($Offline) { $runArguments.Add('-o') | Out-Null }
            foreach ($argument in @($build.arguments)) { $runArguments.Add($argument) | Out-Null }
            $logPath = Join-Path $root ("build-$($build.id).log")
            $buildResult = Invoke-MavenPackage $mavenCommand.Source $runArguments.ToArray() $logPath
            $buildRecord = [ordered]@{ id = $build.id; index = $buildIndex; arguments = @($runArguments.ToArray()); result = $buildResult; artifacts = [ordered]@{} }
            foreach ($name in $artifactNames) { $buildRecord.artifacts[$name] = Get-JarSnapshot (Join-Path (Join-Path $project 'target') $name) }
            $report.builds.Add([pscustomobject]$buildRecord) | Out-Null
            Write-JsonAtomic $reportPath $report
            if ($buildResult.exit_code -ne 0) { throw "MAVEN_BUILD_FAILED: $($build.id) exit=$($buildResult.exit_code)" }
        }
        $clean1 = $report.builds[0]
        $clean2 = $report.builds[1]
        $repeat = $report.builds[2]
        foreach ($name in $artifactNames) {
            $first = $clean1.artifacts[$name]
            $second = $clean2.artifacts[$name]
            $third = $repeat.artifacts[$name]
            $sameClean = ($first.status -eq $second.status -and $first.sha256 -eq $second.sha256 -and $first.bytes -eq $second.bytes -and $first.entry_digest -eq $second.entry_digest)
            $sameRepeat = ($second.status -eq $third.status -and $second.sha256 -eq $third.sha256 -and $second.bytes -eq $third.bytes -and $second.entry_digest -eq $third.entry_digest)
            $check = [ordered]@{ artifact = $name; clean_equal = [bool]$sameClean; repeat_equal = [bool]$sameRepeat; first_status = $first.status; second_status = $second.status; third_status = $third.status }
            $report.checks.Add([pscustomobject]$check) | Out-Null
            if (-not $sameClean -or -not $sameRepeat) { throw "ARTIFACT_NOT_IDEMPOTENT: $name clean_equal=$sameClean repeat_equal=$sameRepeat" }
        }
        $thin = $repeat.artifacts['just-sast-0.2.0.jar']
        $shaded = $repeat.artifacts['just-sast-0.2.0-shaded.jar']
        $original = $repeat.artifacts['original-just-sast-0.2.0.jar']
        if ($thin.status -ne 'OBSERVED' -or $thin.has_just_main -ne $true -or $thin.has_picocli -ne $false -or $thin.main_class -ne $null) { throw 'THIN_OWNER_CONTRACT_FAILED' }
        if ($shaded.status -ne 'OBSERVED' -or $shaded.has_just_main -ne $true -or $shaded.has_picocli -ne $true -or $shaded.main_class -ne 'io.just.sast.cli.JustMain') { throw 'SHADED_OWNER_CONTRACT_FAILED' }
        if ($original.status -ne 'MISSING') { throw 'SHADE_ORIGINAL_ARTIFACT_MUST_NOT_EXIST' }
        $report.checks.Add([pscustomobject]@{ artifact = 'owner-contract'; thin = 'PASS'; shaded = 'PASS'; original = 'ABSENT' }) | Out-Null
        $report.state = 'PASS'
    } catch {
        $report.state = 'FAIL'
        $report.failure = [ordered]@{ reason_code = if ($_.Exception.Message -match '^([A-Z0-9_]+):') { $Matches[1] } else { 'PACKAGE_IDEMPOTENCE_FAILURE' }; message = $_.Exception.Message }
    }
    $report.finished_at = (Get-Date).ToUniversalTime().ToString('o')
    Write-JsonAtomic $reportPath $report
    return $report
}

try {
    $RepoRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
    $result = Invoke-Idempotence
    $result | ConvertTo-Json -Depth 30
    if ($result.state -ne 'PASS') { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('PACKAGE_IDEMPOTENCE_ERROR: ' + $_.Exception.Message))
    exit 2
}
