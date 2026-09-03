[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LauncherJar,

    [Parameter(Mandatory = $true)]
    [string] $Manifest,

    [string] $OutputRoot,

    [switch] $MeasurePerformance,

    [ValidateSet("hot", "cold")]
    [string] $Mode = "cold",

    [int] $Warmups = 1,

    [int] $Runs = 3,

    [string] $PerformanceProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RegularFile([string] $Path, [string] $Label) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item -isnot [System.IO.FileInfo]) {
        throw "$Label 不是普通文件: $Path"
    }
    return $item.FullName
}

function Resolve-InputPath([string] $Value, [string] $Base, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }
    $candidate = if ([System.IO.Path]::IsPathRooted($Value)) {
        $Value
    } else {
        Join-Path -Path $Base -ChildPath $Value
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if (-not ($item -is [System.IO.FileInfo] -or $item -is [System.IO.DirectoryInfo])) {
        throw "$Label 不是可读文件或目录: $candidate"
    }
    return $item.FullName
}

function Get-Property($Object, [string] $Name) {
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
        return $null
    }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-BooleanProperty($Object, [string] $Name, [bool] $Default) {
    $value = Get-Property $Object $Name
    if ($null -eq $value) {
        return $Default
    }
    return [bool]$value
}

function Get-IntegerProperty($Object, [string] $Name, [int] $Default) {
    $value = Get-Property $Object $Name
    if ($null -eq $value) {
        return $Default
    }
    return [int]$value
}

function Get-StringProperty($Object, [string] $Name, [string] $Default) {
    $value = Get-Property $Object $Name
    if ($null -eq $value) {
        return $Default
    }
    return [string]$value
}

function Get-MetadataValue($Object, [string] $Name, $Default) {
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
        return $Default
    }
    $value = $Object.PSObject.Properties[$Name].Value
    if ($null -eq $value) {
        return $Default
    }
    return $value
}

function Get-CanonicalDigest([string] $OutputDirectory) {
    $findingFile = Join-Path $OutputDirectory "findings\findings.csv"
    $chainFile = Join-Path $OutputDirectory "evidence\chains.csv"
    $findingExists = Test-Path -LiteralPath $findingFile -PathType Leaf
    $chainExists = Test-Path -LiteralPath $chainFile -PathType Leaf
    if (-not $findingExists -or -not $chainExists) {
        return "MISSING"
    }
    $findingHash = (Get-FileHash -LiteralPath $findingFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $chainHash = (Get-FileHash -LiteralPath $chainFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $canonical = "findings=$findingHash" + [Environment]::NewLine
    $canonical += "chains=$chainHash" + [Environment]::NewLine
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($digest.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $digest.Dispose()
    }
}

function Join-DependencyPaths([object[]] $Values) {
    if ($null -eq $Values -or $Values.Count -eq 0) {
        return $null
    }
    return ($Values -join ",")
}

function Invoke-CommandToLog([string] $Java, [string[]] $Arguments,
                             [string] $Stdout, [string] $Stderr) {
    $previousErrorAction = $ErrorActionPreference
    try {
        # Java intentionally writes normal diagnostics to stderr. PowerShell 7 promotes
        # native stderr to an exception under Stop even when the stream is redirected.
        # Capture the stream in the requested log and judge only the process exit code.
        $ErrorActionPreference = "Continue"
        & $Java @Arguments 1> $Stdout 2> $Stderr
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

$launcher = Resolve-RegularFile $LauncherJar "launcher JAR"
$manifestFile = Resolve-RegularFile $Manifest "manifest"
$manifestBase = Split-Path -Parent $manifestFile
$definition = Get-Content -LiteralPath $manifestFile -Raw -Encoding UTF8 | ConvertFrom-Json
$schema = Get-Property $definition "schema_version"
if ($null -ne $schema -and [int]$schema -ne 1) {
    throw "不支持的 manifest schema_version: $schema"
}
$cases = @(Get-Property $definition "cases")
if ($cases.Count -eq 0) {
    throw "manifest.cases 不能为空"
}
if ($Warmups -lt 0 -or $Runs -le 0) {
    throw "Warmups 必须非负，Runs 必须大于 0"
}

$javaCommand = Get-Command java -ErrorAction Stop
$java = $javaCommand.Source
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("just-regression-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
$root = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $root -Force | Out-Null

$profile = $null
if (-not [string]::IsNullOrWhiteSpace($PerformanceProfile)) {
    $profile = Resolve-RegularFile $PerformanceProfile "performance profile"
}

$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$records = [System.Collections.Generic.List[object]]::new()
$anyFailure = $false
$index = 0
foreach ($case in $cases) {
    $index++
    $id = Get-StringProperty $case "id" ("case-" + $index)
    if ($id -notmatch "^[A-Za-z0-9_.-]+$" -or -not $seen.Add($id)) {
        throw "case id 必须唯一且只包含 ASCII 字母、数字、点、下划线或短横线: $id"
    }

    $jarValue = Get-StringProperty $case "jar" ""
    $jar = Resolve-InputPath $jarValue $manifestBase "$id.jar"
    if ($null -eq $jar) {
        throw "$id 缺少 jar"
    }
    $caseOutput = Join-Path $root $id
    if (Test-Path -LiteralPath $caseOutput) {
        throw "输出目录已存在，为避免覆盖请更换 OutputRoot: $caseOutput"
    }
    New-Item -ItemType Directory -Path $caseOutput -Force | Out-Null
    $stdout = Join-Path $caseOutput "scan.stdout.log"
    $stderr = Join-Path $caseOutput "scan.stderr.log"

    $arguments = [System.Collections.Generic.List[string]]::new()
    $null = $arguments.Add("-jar")
    $null = $arguments.Add($launcher)
    $null = $arguments.Add("scan")
    $null = $arguments.Add("--jar")
    $null = $arguments.Add($jar)
    $null = $arguments.Add("--output")
    $null = $arguments.Add($caseOutput)

    $dependencyValues = @()
    $dependencyProperty = Get-Property $case "deps"
    if ($null -ne $dependencyProperty) {
        $dependencyValues = @($dependencyProperty)
    }
    $resolvedDeps = [System.Collections.Generic.List[string]]::new()
    if ($dependencyValues.Count -gt 0) {
        foreach ($dependency in $dependencyValues) {
            $null = $resolvedDeps.Add((Resolve-InputPath ([string]$dependency) $manifestBase "$id dependency"))
        }
        $null = $arguments.Add("--deps")
        $null = $arguments.Add((Join-DependencyPaths $resolvedDeps.ToArray()))
    }

    $rules = Resolve-InputPath (Get-StringProperty $case "rules" "") $manifestBase "$id rules"
    if ($null -ne $rules) {
        $null = $arguments.Add("--rules")
        $null = $arguments.Add($rules)
    }
    $jdkHome = Resolve-InputPath (Get-StringProperty $case "jdk_home" "") $manifestBase "$id jdk_home"
    if ($null -ne $jdkHome) {
        $null = $arguments.Add("--jdk-home")
        $null = $arguments.Add($jdkHome)
    }
    if (Get-BooleanProperty $case "fast" $false) {
        $null = $arguments.Add("--fast")
    }
    if (-not (Get-BooleanProperty $case "verify" $true)) {
        $null = $arguments.Add("--no-verify")
    }
    $budget = Get-IntegerProperty $case "verify_budget" 20
    if ($budget -lt 0) {
        throw "$id verify_budget 不能为负数"
    }
    $null = $arguments.Add("--verify-budget")
    $null = $arguments.Add([string]$budget)

    $exitCode = Invoke-CommandToLog $java $arguments.ToArray() $stdout $stderr
    $metadataPath = Join-Path $caseOutput "meta\scan-metadata.json"
    $metadata = $null
    if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $phase = Get-MetadataValue $metadata "phase_ms" $null
    $metrics = Get-MetadataValue $metadata "metrics" $null
    $rss = Get-MetadataValue $metrics "parent_rss_mb" $null
    if ($null -eq $rss) {
        $rss = Get-MetadataValue $metrics "rss_peak_mb" -1
    }
    $record = [ordered]@{
        id = $id
        exit_code = $exitCode
        output = $caseOutput
        metadata = if ($null -eq $metadata) { "MISSING" } else { $metadataPath }
        chains_found = [int](Get-MetadataValue $metadata "chains_found" 0)
        completeness = [string](Get-MetadataValue $metadata "completeness" "UNKNOWN")
        static_ms = [long](Get-MetadataValue $phase "static" 0)
        verify_ms = [long](Get-MetadataValue $phase "verify" 0)
        rss_peak_mb = [long]$rss
        resource_metrics = if ($null -eq $metrics) { @{} } else { $metrics }
        canonical_digest = Get-CanonicalDigest $caseOutput
    }

    if ($exitCode -ne 0 -or $record.canonical_digest -eq "MISSING") {
        $anyFailure = $true
    }

    if ($MeasurePerformance) {
        $perfReport = Join-Path $caseOutput "performance.json"
        $perfOut = Join-Path $caseOutput "perf.stdout.log"
        $perfErr = Join-Path $caseOutput "perf.stderr.log"
        $perfArguments = [System.Collections.Generic.List[string]]::new()
        $null = $perfArguments.Add("-jar")
        $null = $perfArguments.Add($launcher)
        $null = $perfArguments.Add("perf")
        $null = $perfArguments.Add("--jar")
        $null = $perfArguments.Add($jar)
        $null = $perfArguments.Add("--mode")
        $null = $perfArguments.Add($Mode)
        $null = $perfArguments.Add("--warmups")
        $null = $perfArguments.Add([string]$Warmups)
        $null = $perfArguments.Add("--runs")
        $null = $perfArguments.Add([string]$Runs)
        $null = $perfArguments.Add("--report")
        $null = $perfArguments.Add($perfReport)
        $null = $perfArguments.Add("--launcher-jar")
        $null = $perfArguments.Add($launcher)
        $null = $perfArguments.Add("--work-dir")
        $null = $perfArguments.Add($caseOutput)
        if ($resolvedDeps.Count -gt 0) {
            $null = $perfArguments.Add("--deps")
            $null = $perfArguments.Add((Join-DependencyPaths $resolvedDeps.ToArray()))
        }
        if ($null -ne $rules) {
            $null = $perfArguments.Add("--rules")
            $null = $perfArguments.Add($rules)
        }
        if ($null -ne $jdkHome) {
            $null = $perfArguments.Add("--jdk-home")
            $null = $perfArguments.Add($jdkHome)
        }
        if (Get-BooleanProperty $case "fast" $false) {
            $null = $perfArguments.Add("--fast")
        }
        if (-not (Get-BooleanProperty $case "verify" $true)) {
            $null = $perfArguments.Add("--no-verify")
        }
        $null = $perfArguments.Add("--verify-budget")
        $null = $perfArguments.Add([string]$budget)
        if ($null -ne $profile) {
            $null = $perfArguments.Add("--limits-file")
            $null = $perfArguments.Add($profile)
        }
        $perfExit = Invoke-CommandToLog $java $perfArguments.ToArray() $perfOut $perfErr
        $record["performance_exit_code"] = $perfExit
        $performancePath = "MISSING"
        if (Test-Path -LiteralPath $perfReport -PathType Leaf) {
            $performancePath = $perfReport
        }
        $record["performance_report"] = $performancePath
        if ($perfExit -ne 0 -or $record.performance_report -eq "MISSING") {
            $anyFailure = $true
        }
    }
    $null = $records.Add([pscustomobject]$record)
}

$report = [ordered]@{
    schema_version = 1
    launcher = $launcher
    manifest = $manifestFile
    output_root = $root
    mode = $Mode
    warmups = $Warmups
    runs = $Runs
    measured = [bool]$MeasurePerformance
    cases = $records
    passed = -not $anyFailure
}
$reportPath = Join-Path $root "regression-report.json"
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Output ($report | ConvertTo-Json -Depth 12)
if ($anyFailure) {
    exit 1
}
