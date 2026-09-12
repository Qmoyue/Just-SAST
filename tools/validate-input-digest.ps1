[CmdletBinding()]
param(
    [string] $InputDigestPath,
    [string] $SchemaPath,
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$SchemaVersion = 1
$SchemaPath = if ([string]::IsNullOrWhiteSpace($SchemaPath)) {
    Join-Path $PSScriptRoot '..\docs\schemas\input-digest-v1.schema.json'
} else { [IO.Path]::GetFullPath($SchemaPath) }

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-JsonIfPresent {
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
}

function Get-PropertyNames {
    param([AllowNull()] $Object)
    if ($null -eq $Object) { return @() }
    return @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
}

function Test-ExactProperties {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string[]] $Expected)
    $actual = @(Get-PropertyNames $Object | Sort-Object -Unique)
    $wanted = @($Expected | Sort-Object -Unique)
    return (($actual -join "`n") -eq ($wanted -join "`n"))
}

function Get-StringValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name, [string] $Default = '')
    $value = Get-PropertyValue $Object $Name
    if ($null -eq $value) { return $Default }
    return [string]$value
}

function Test-Digest {
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $false }
    return ([string]$Value -match '^(UNKNOWN|[0-9a-fA-F]{64})$')
}

function Test-InputDigest {
    param([AllowNull()] $Document)
    $issues = [Collections.Generic.List[string]]::new()
    if ($null -eq $Document) {
        $issues.Add('JSON_INVALID_OR_MISSING') | Out-Null
        return [ordered]@{ valid = $false; issues = @($issues.ToArray()); schema_version = $SchemaVersion }
    }
    if (-not (Test-ExactProperties $Document @('schema_version', 'status', 'target', 'dependencies', 'reasons'))) { $issues.Add('ROOT_PROPERTIES') | Out-Null }
    if ([int](Get-PropertyValue $Document 'schema_version') -ne $SchemaVersion) { $issues.Add('SCHEMA_VERSION') | Out-Null }
    $status = Get-StringValue $Document 'status' ''
    if (@('MATCH', 'CHANGED', 'UNAVAILABLE') -notcontains $status) { $issues.Add('STATUS') | Out-Null }
    $target = Get-PropertyValue $Document 'target'
    if (-not (Test-ExactProperties $target @('before', 'after'))) { $issues.Add('TARGET_PROPERTIES') | Out-Null }
    foreach ($name in @('before', 'after')) {
        if (-not (Test-Digest (Get-PropertyValue $target $name))) { $issues.Add('TARGET_' + $name.ToUpperInvariant() + '_DIGEST') | Out-Null }
    }
    $dependencies = @(Get-PropertyValue $Document 'dependencies')
    $expectedIndex = 0
    foreach ($dependency in $dependencies) {
        if (-not (Test-ExactProperties $dependency @('index', 'before', 'after'))) { $issues.Add('DEPENDENCY_PROPERTIES') | Out-Null }
        $indexValue = Get-PropertyValue $dependency 'index'
        if ($null -eq $indexValue -or [int]$indexValue -ne $expectedIndex) { $issues.Add('DEPENDENCY_INDEX_' + $expectedIndex) | Out-Null }
        foreach ($name in @('before', 'after')) {
            if (-not (Test-Digest (Get-PropertyValue $dependency $name))) { $issues.Add('DEPENDENCY_' + $expectedIndex + '_' + $name.ToUpperInvariant() + '_DIGEST') | Out-Null }
        }
        $expectedIndex++
    }
    $reasons = @(Get-PropertyValue $Document 'reasons')
    $reasonSet = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reason in $reasons) {
        if ($null -eq $reason -or [string]::IsNullOrWhiteSpace([string]$reason)) { $issues.Add('REASON_EMPTY') | Out-Null; continue }
        if (-not $reasonSet.Add([string]$reason)) { $issues.Add('REASON_DUPLICATE') | Out-Null }
    }
    # MATCH is a strong statement: every observed digest must be known and equal.
    if ($status -eq 'MATCH') {
        if ((Get-PropertyValue $target 'before') -eq 'UNKNOWN' -or (Get-PropertyValue $target 'after') -eq 'UNKNOWN') { $issues.Add('MATCH_UNKNOWN_TARGET') | Out-Null }
        foreach ($dependency in $dependencies) {
            if ((Get-PropertyValue $dependency 'before') -eq 'UNKNOWN' -or (Get-PropertyValue $dependency 'after') -eq 'UNKNOWN') { $issues.Add('MATCH_UNKNOWN_DEPENDENCY') | Out-Null }
        }
        if ($reasons.Count -ne 0) { $issues.Add('MATCH_HAS_REASONS') | Out-Null }
    }
    return [ordered]@{ valid = ($issues.Count -eq 0); issues = @($issues.ToArray()); schema_version = $SchemaVersion; status = $status; dependency_count = $dependencies.Count }
}

function Invoke-SelfTest {
    $valid = [pscustomobject]@{
        schema_version = 1; status = 'MATCH'
        target = [pscustomobject]@{ before = ('a' * 64); after = ('a' * 64) }
        dependencies = @([pscustomobject]@{ index = 0; before = ('b' * 64); after = ('b' * 64) })
        reasons = @()
    }
    $validResult = Test-InputDigest $valid
    if (-not $validResult.valid) { throw ('SELFTEST_VALID:' + ($validResult.issues -join ',')) }
    $unknown = [pscustomobject]@{
        schema_version = 1; status = 'MATCH'
        target = [pscustomobject]@{ before = 'UNKNOWN'; after = 'UNKNOWN' }
        dependencies = @(); reasons = @()
    }
    $unknownResult = Test-InputDigest $unknown
    if ($unknownResult.valid -or @($unknownResult.issues | Where-Object { $_ -eq 'MATCH_UNKNOWN_TARGET' }).Count -eq 0) { throw 'SELFTEST_UNKNOWN_MATCH' }
    $extra = [pscustomobject]@{
        schema_version = 1; status = 'UNAVAILABLE'
        target = [pscustomobject]@{ before = 'UNKNOWN'; after = 'UNKNOWN'; path = 'secret' }
        dependencies = @(); reasons = @('INPUT_DIGEST_AFTER_UNAVAILABLE')
    }
    $extraResult = Test-InputDigest $extra
    if ($extraResult.valid -or @($extraResult.issues | Where-Object { $_ -eq 'TARGET_PROPERTIES' }).Count -eq 0) { throw 'SELFTEST_EXTRA_PROPERTY' }
    [ordered]@{ status = 'PASS'; tests = @('schema-contract', 'valid-match', 'unknown-match-rejected', 'extra-property-rejected') }
}

try {
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'INPUT_DIGEST_SCHEMA_MISSING' }
    $schema = Get-JsonIfPresent $SchemaPath
    if ($null -eq $schema -or [int](Get-PropertyValue $schema.properties.schema_version 'const') -ne $SchemaVersion) { throw 'INPUT_DIGEST_SCHEMA_INVALID' }
    if ($SelfTest) {
        $result = Invoke-SelfTest
        if ($Json) { $result | ConvertTo-Json -Depth 20 } else { Write-Output ('INPUT_DIGEST_VALIDATOR_SELF_TEST=' + $result.status); Write-Output ('tests=' + ($result.tests -join ',')) }
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($InputDigestPath)) { throw 'INPUT_DIGEST_REQUIRED' }
    $full = if ([IO.Path]::IsPathRooted($InputDigestPath)) { [IO.Path]::GetFullPath($InputDigestPath) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $InputDigestPath)) }
    $result = Test-InputDigest (Get-JsonIfPresent $full)
    if ($Json) { $result | ConvertTo-Json -Depth 20 } else { Write-Output ('INPUT_DIGEST_VALID=' + $result.valid); Write-Output ('issues=' + (@($result.issues) -join ',')) }
    if (-not $result.valid) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('INPUT_DIGEST_VALIDATOR_ERROR: ' + $_.Exception.Message))
    exit 2
}
