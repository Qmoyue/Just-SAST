Set-StrictMode -Version Latest

$script:JdkDiscoverySchemaVersion = 1
$script:JdkDiscoveryContractId = 'JUST-PROD-D009-V1'

function Get-PropertyValueV1 {
    param(
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    if ($null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-Sha256V1 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TextSha256V1 {
    param([AllowNull()] [string] $Text)
    $value = if ($null -eq $Text) { '' } else { $Text }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Resolve-RegularFileV1 {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $BasePath,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "${Label}_PATH_EMPTY" }
    $candidate = if ([IO.Path]::IsPathRooted($Value)) { [IO.Path]::GetFullPath($Value) } else { [IO.Path]::GetFullPath((Join-Path $BasePath $Value)) }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "${Label}_MISSING: $candidate" }
    return (Get-Item -LiteralPath $candidate -Force).FullName
}

function Resolve-DirectoryV1 {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $BasePath,
        [Parameter(Mandatory = $true)] [string] $Label
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { throw "${Label}_PATH_EMPTY" }
    $candidate = if ([IO.Path]::IsPathRooted($Value)) { [IO.Path]::GetFullPath($Value) } else { [IO.Path]::GetFullPath((Join-Path $BasePath $Value)) }
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { throw "${Label}_MISSING: $candidate" }
    return (Get-Item -LiteralPath $candidate -Force).FullName
}

function Invoke-CaptureV1 {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [string] $WorkingDirectory
    )
    $previous = $ErrorActionPreference
    $pushed = $false
    try {
        if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
            Push-Location -LiteralPath $WorkingDirectory
            $pushed = $true
        }
        $ErrorActionPreference = 'Continue'
        $lines = @(& $FilePath @Arguments 2>&1)
        $code = [int]$LASTEXITCODE
        return [pscustomobject]@{
            exit_code = $code
            output = (($lines | ForEach-Object { [string]$_ }) -join [Environment]::NewLine).Trim()
        }
    } finally {
        if ($pushed) { Pop-Location }
        $ErrorActionPreference = $previous
    }
}

function Resolve-JabbaExecutableV1 {
    param(
        [string] $Requested,
        [string] $BasePath = (Get-Location).Path,
        [string] $RepoRoot = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        return Resolve-RegularFileV1 $Requested $BasePath 'JABBA_EXE'
    }
    $profiles = [Collections.Generic.List[string]]::new()
    foreach ($candidate in @($env:USERPROFILE, [Environment]::GetFolderPath('UserProfile'))) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate) -and -not $profiles.Contains([string]$candidate)) { $profiles.Add([string]$candidate) | Out-Null }
    }
    if (-not [string]::IsNullOrWhiteSpace($RepoRoot)) {
        $usersRoot = Join-Path ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($RepoRoot))) 'Users'
        if (Test-Path -LiteralPath $usersRoot -PathType Container) {
            Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if (-not $profiles.Contains($_.FullName)) { $profiles.Add($_.FullName) | Out-Null }
            }
        }
    }
    foreach ($profile in $profiles) {
        $candidate = Join-Path $profile '.jabba\bin\jabba.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Get-Item -LiteralPath $candidate -Force).FullName }
    }
    $command = Get-Command jabba -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        $path = if (-not [string]::IsNullOrWhiteSpace([string]$command.Source)) { [string]$command.Source } else { [string]$command.Path }
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path -PathType Leaf)) { return (Get-Item -LiteralPath $path -Force).FullName }
    }
    throw 'JABBA_NOT_FOUND: set -JabbaExe or install Jabba under %USERPROFILE%\\.jabba\\bin'
}

function Parse-JabbaIdsV1 {
    param([AllowNull()] [string] $Text)
    $ids = [Collections.Generic.List[string]]::new()
    if ($null -eq $Text) { return @() }
    foreach ($line in ($Text -split "`r?`n")) {
        $value = $line.Trim()
        if ($value -match '^[A-Za-z0-9_.+:-]+@[A-Za-z0-9_.+:-]+$' -and -not $ids.Contains($value)) { $ids.Add($value) | Out-Null }
    }
    return @($ids.ToArray() | Sort-Object)
}

function Get-JabbaInstalledIdsV1 {
    param([Parameter(Mandatory = $true)] [string] $JabbaPath)
    $result = Invoke-CaptureV1 $JabbaPath @('ls')
    if ($result.exit_code -ne 0) { throw "JABBA_LIST_FAILED: exit=$($result.exit_code) output=$($result.output)" }
    return [ordered]@{
        status = 'MATCH'
        ids = @(Parse-JabbaIdsV1 $result.output)
        command = 'jabba ls'
        exit_code = $result.exit_code
        output_sha256 = Get-TextSha256V1 $result.output
    }
}

function Assert-JdkProfileIdentityV1 {
    param(
        [Parameter(Mandatory = $true)] [string] $Id,
        [Parameter(Mandatory = $true)] [int] $ExpectedFeature,
        [Parameter(Mandatory = $true)] [string] $Version
    )
    $featureText = if ($Version.StartsWith('1.')) { $Version.Substring(2).Split('.')[0] } else { $Version.Split('.')[0] }
    $actualFeature = 0
    if (-not [int]::TryParse($featureText, [ref]$actualFeature)) { throw "JDK_FEATURE_UNPARSEABLE: id=$Id version=$Version" }
    if ($actualFeature -ne $ExpectedFeature) { throw "JDK_FEATURE_MISMATCH: id=$Id expected=$ExpectedFeature actual=$actualFeature version=$Version" }
    return [ordered]@{ id = $Id; expected_feature = $ExpectedFeature; actual_feature = $actualFeature; version = $Version; status = 'MATCH' }
}

function Get-JdkHomeDigestV1 {
    param(
        [Parameter(Mandatory = $true)] [string] $JdkHomePath,
        [Parameter(Mandatory = $true)] [int] $Feature
    )
    $files = [Collections.Generic.List[string]]::new()
    $release = Join-Path $JdkHomePath 'release'
    if (Test-Path -LiteralPath $release -PathType Leaf) { $files.Add($release) | Out-Null }
    if ($Feature -le 8) {
        $rt = Join-Path $JdkHomePath 'jre\lib\rt.jar'
        if (Test-Path -LiteralPath $rt -PathType Leaf) { $files.Add($rt) | Out-Null }
    } else {
        $jmods = Join-Path $JdkHomePath 'jmods'
        if (Test-Path -LiteralPath $jmods -PathType Container) {
            Get-ChildItem -LiteralPath $jmods -File -Filter '*.jmod' -Force | Sort-Object FullName | ForEach-Object { $files.Add($_.FullName) | Out-Null }
        }
    }
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $item = Get-Item -LiteralPath $file -Force
        $rows.Add("$([IO.Path]::GetFileName($item.FullName))=$(Get-Sha256V1 $item.FullName)=$($item.Length)") | Out-Null
    }
    return Get-TextSha256V1 (($rows.ToArray()) -join "`n")
}

function Resolve-JdkProfileV1 {
    param(
        [Parameter(Mandatory = $true)] $JdkProfile,
        [Parameter(Mandatory = $true)] [string] $JabbaPath,
        [string] $BasePath = (Get-Location).Path
    )
    $id = [string](Get-PropertyValueV1 $JdkProfile 'id')
    $expectedFeature = [int](Get-PropertyValueV1 $JdkProfile 'feature')
    if ([string]::IsNullOrWhiteSpace($id) -or $expectedFeature -le 0) { throw 'JDK_PROFILE_INVALID: id and positive feature are required' }
    $which = Invoke-CaptureV1 $JabbaPath @('which', $id)
    if ($which.exit_code -ne 0 -or [string]::IsNullOrWhiteSpace($which.output)) { throw "JDK_NOT_FOUND: id=$id exit=$($which.exit_code) output=$($which.output)" }
    $homeLine = @($which.output -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) | Select-Object -Last 1
    if ($null -eq $homeLine -or [string]::IsNullOrWhiteSpace([string]$homeLine)) { throw "JDK_HOME_EMPTY: id=$id" }
    $home = Resolve-DirectoryV1 ([string]$homeLine) $BasePath "JDK_HOME_$id"
    $java = Join-Path $home 'bin\java.exe'
    if (-not (Test-Path -LiteralPath $java -PathType Leaf)) { throw "JDK_JAVA_MISSING: id=$id home=$home" }
    $versionResult = Invoke-CaptureV1 $java @('--version')
    if ($versionResult.exit_code -ne 0) { $versionResult = Invoke-CaptureV1 $java @('-version') }
    if ($versionResult.exit_code -ne 0) { throw "JDK_VERSION_FAILED: id=$id exit=$($versionResult.exit_code)" }
    $match = [Regex]::Match($versionResult.output, 'version\s+"(?<version>[^"]+)"')
    if (-not $match.Success) { $match = [Regex]::Match($versionResult.output, '(?<version>\d+(?:\.\d+){0,3})') }
    if (-not $match.Success) { throw "JDK_VERSION_UNPARSEABLE: id=$id output=$($versionResult.output)" }
    $version = $match.Groups['version'].Value
    $identity = Assert-JdkProfileIdentityV1 $id $expectedFeature $version
    $rtJar = Join-Path $home 'jre\lib\rt.jar'
    $release = Join-Path $home 'release'
    $jmods = Join-Path $home 'jmods'
    if ($expectedFeature -le 8) {
        if (-not (Test-Path -LiteralPath $rtJar -PathType Leaf)) { throw "JDK_LAYOUT_MISMATCH: id=$id expected=rt.jar home=$home" }
    } elseif (-not (Test-Path -LiteralPath $release -PathType Leaf) -and -not (Test-Path -LiteralPath $jmods -PathType Container)) {
        throw "JDK_LAYOUT_MISMATCH: id=$id expected=release-or-jmods home=$home"
    }
    $javaFull = (Get-Item -LiteralPath $java -Force).FullName
    return [ordered]@{
        id = $id
        feature = $expectedFeature
        resolver = 'jabba'
        home = $home
        canonical_home = [IO.Path]::GetFullPath($home)
        java = $javaFull
        java_sha256 = Get-Sha256V1 $javaFull
        java_version = $version
        java_version_output = $versionResult.output
        home_digest = Get-JdkHomeDigestV1 $home $expectedFeature
        status = $identity.status
    }
}

function Get-RequiredJdkProfilesV1 {
    return @(
        [pscustomobject]@{ key = 'jdk7'; id = 'system@1.7.0-21'; feature = 7; required = $true },
        [pscustomobject]@{ key = 'jdk8'; id = 'temurin@8.0.482'; feature = 8; required = $true },
        [pscustomobject]@{ key = 'jdk11'; id = 'temurin@11.0.31'; feature = 11; required = $true },
        [pscustomobject]@{ key = 'jdk17'; id = 'temurin@17.0.19'; feature = 17; required = $true },
        [pscustomobject]@{ key = 'jdk21'; id = 'temurin@21.0.11'; feature = 21; required = $true },
        [pscustomobject]@{ key = 'jdk24'; id = 'temurin@24.0.2'; feature = 24; required = $true },
        [pscustomobject]@{ key = 'jdk25'; id = 'openjdk@25.0.2'; feature = 25; required = $true }
    )
}

Export-ModuleMember -Function Resolve-JabbaExecutableV1,Parse-JabbaIdsV1,Get-JabbaInstalledIdsV1,Assert-JdkProfileIdentityV1,Get-JdkHomeDigestV1,Resolve-JdkProfileV1,Get-RequiredJdkProfilesV1,Get-Sha256V1,Get-TextSha256V1
