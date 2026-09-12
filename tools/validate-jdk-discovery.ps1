[CmdletBinding()]
param(
    [string] $JabbaExe,
    [string] $OutputPath,
    [switch] $SelfTest,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ContractId = 'JUST-PROD-D009-V1'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$ModulePath = Join-Path $PSScriptRoot 'jdk-discovery-v1.psm1'
$SchemaPath = Join-Path $PSScriptRoot 'jdk-discovery-v1.schema.json'

try {
    Import-Module -Name $ModulePath -Force -DisableNameChecking -ErrorAction Stop
} catch {
    $errorObject = [ordered]@{ schema_version = 1; contract_id = $ContractId; status = 'FAIL'; valid = $false; reason_code = 'JDK_DISCOVERY_MODULE_LOAD_FAILED'; message = $_.Exception.Message }
    if ($Json) { $errorObject | ConvertTo-Json -Depth 12 } else { Write-Error $errorObject.message }
    exit 1
}

function Write-Result {
    param(
        [Parameter(Mandatory = $true)] $Result,
        [switch] $AsJson,
        [string] $Path
    )
    foreach ($field in @('schema_version', 'contract_id', 'status', 'valid', 'profiles', 'safety')) {
        $present = if ($Result -is [Collections.IDictionary]) {
            $Result.Contains($field)
        } else {
            $null -ne $Result.PSObject.Properties[$field]
        }
        if (-not $present) { throw "JDK_DISCOVERY_SCHEMA_FIELD_MISSING: $field" }
    }
    if ([int]$Result.schema_version -ne 1 -or [string]$Result.contract_id -ne $ContractId) { throw 'JDK_DISCOVERY_SCHEMA_ID_MISMATCH' }
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw "JDK_DISCOVERY_SCHEMA_MISSING: $SchemaPath" }
    $jsonText = $Result | ConvertTo-Json -Depth 20
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $full = [IO.Path]::GetFullPath($Path)
        if (Test-Path -LiteralPath $full) { throw "OUTPUT_EXISTS: $full" }
        $parent = Split-Path -Parent $full
        if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $tmp = "$full.tmp-$([Guid]::NewGuid().ToString('N'))"
        try {
            [IO.File]::WriteAllText($tmp, $jsonText, (New-Object Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $tmp -Destination $full
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        }
    }
    if ($AsJson) {
        Write-Output $jsonText
    } else {
        Write-Output ("JDK_DISCOVERY status={0} valid={1} jabba={2}" -f $Result.status, $Result.valid, $Result.jabba_executable)
        foreach ($profile in @($Result.profiles)) {
            Write-Output ("  {0} {1} {2}" -f $profile.key, $profile.status, $profile.id)
        }
    }
}

function Invoke-SelfTest {
    $checks = [Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'SELFTEST_SCHEMA_MISSING' }
    $schema = Get-Content -LiteralPath $SchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([int]$schema.properties.schema_version.const -ne 1 -or [string]$schema.properties.schema.const -ne 'jdk-discovery-v1') { throw 'SELFTEST_SCHEMA_CONTRACT_FAILED' }
    $checks.Add('schema-contract') | Out-Null
    $ids = @(Parse-JabbaIdsV1 "warning`nsystem@1.7.0-21`ntemurin@24.0.2`nopenjdk@25.0.2`nsystem@1.7.0-21")
    if ($ids.Count -ne 3 -or $ids[0] -ne 'openjdk@25.0.2' -or $ids[1] -ne 'system@1.7.0-21' -or $ids[2] -ne 'temurin@24.0.2') { throw 'SELFTEST_JABBA_ID_PARSER_FAILED' }
    $checks.Add('jabba-id-parser') | Out-Null
    $identity = Assert-JdkProfileIdentityV1 'temurin@24.0.2' 24 '24.0.2'
    if ($identity.status -ne 'MATCH') { throw 'SELFTEST_FEATURE_MATCH_FAILED' }
    $checks.Add('feature-match') | Out-Null
    $mismatch = $false
    try { Assert-JdkProfileIdentityV1 'openjdk@25.0.2' 24 '25.0.2' | Out-Null } catch { $mismatch = $_.Exception.Message -match '^JDK_FEATURE_MISMATCH:' }
    if (-not $mismatch) { throw 'SELFTEST_25_NOT_A_24_SUBSTITUTE_FAILED' }
    $checks.Add('jdk25-not-a-jdk24-substitute') | Out-Null
    $profiles = @(Get-RequiredJdkProfilesV1)
    if ($profiles.Count -ne 7 -or $profiles[5].id -ne 'temurin@24.0.2' -or $profiles[6].feature -ne 25) { throw 'SELFTEST_REQUIRED_PROFILE_SET_FAILED' }
    $checks.Add('required-profile-set') | Out-Null
    $missing = $false
    try { Resolve-JabbaExecutableV1 -Requested (Join-Path ([IO.Path]::GetTempPath()) ('missing-jabba-' + [Guid]::NewGuid().ToString('N') + '.exe')) -BasePath (Get-Location).Path } catch { $missing = $_.Exception.Message -match '^JABBA_EXE_MISSING:' }
    if (-not $missing) { throw 'SELFTEST_EXPLICIT_PATH_FAIL_CLOSED_FAILED' }
    $checks.Add('explicit-path-fail-closed') | Out-Null
    return [ordered]@{
        schema_version = 1
        schema = 'jdk-discovery-v1'
        contract_id = $ContractId
        status = 'PASS'
        valid = $true
        observed_ids = @()
        jabba_executable = $null
        profiles = @()
        checks = @($checks)
        resolver_policy = 'explicit-jabba-which'
        no_global_use = $true
        path_or_java_home_mutation = $false
        safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED'; global_jabba_use = 'NOT_INVOKED' }
    }
}

if ($SelfTest) {
    try {
        $selfResult = Invoke-SelfTest
        Write-Result $selfResult -AsJson:$Json -Path $OutputPath
        exit 0
    } catch {
        $selfFailure = [ordered]@{ schema_version = 1; contract_id = $ContractId; status = 'FAIL'; valid = $false; reason_code = 'JDK_DISCOVERY_SELFTEST_FAILED'; message = $_.Exception.Message }
        Write-Result $selfFailure -AsJson:$Json
        exit 1
    }
}

$result = $null
try {
    $jabba = Resolve-JabbaExecutableV1 -Requested $JabbaExe -BasePath (Get-Location).Path -RepoRoot $RepoRoot
    $inventory = Get-JabbaInstalledIdsV1 -JabbaPath $jabba
    $records = [Collections.Generic.List[object]]::new()
    $hasFailure = $false
    $hasNotRun = $false
    foreach ($expected in @(Get-RequiredJdkProfilesV1)) {
        if (-not (@($inventory.ids) -contains $expected.id)) {
            $records.Add([ordered]@{ key = $expected.key; id = $expected.id; feature = $expected.feature; status = 'NOT_RUN'; reason_code = 'JDK_NOT_INSTALLED'; home = $null; java = $null; java_sha256 = $null; home_digest = $null }) | Out-Null
            $hasNotRun = $true
            continue
        }
        try {
            $resolved = Resolve-JdkProfileV1 -JdkProfile $expected -JabbaPath $jabba -BasePath (Get-Location).Path
            $resolved['key'] = $expected.key
            $resolved['required'] = [bool]$expected.required
            $records.Add($resolved) | Out-Null
        } catch {
            $message = $_.Exception.Message
            $reason = if ($message -match '^JDK_(NOT_FOUND|HOME_EMPTY|HOME_.*|JAVA_MISSING):') { 'JDK_NOT_RUN' } else { 'JDK_PROFILE_INVALID' }
            $status = if ($reason -eq 'JDK_NOT_RUN') { 'NOT_RUN' } else { 'FAIL' }
            $records.Add([ordered]@{ key = $expected.key; id = $expected.id; feature = $expected.feature; status = $status; reason_code = $reason; message = $message; home = $null; java = $null; java_sha256 = $null; home_digest = $null }) | Out-Null
            if ($status -eq 'FAIL') { $hasFailure = $true } else { $hasNotRun = $true }
        }
    }
    $overall = if ($hasFailure) { 'FAIL' } elseif ($hasNotRun) { 'NOT_RUN' } else { 'PASS' }
    $result = [ordered]@{
        schema_version = 1
        schema = 'jdk-discovery-v1'
        contract_id = $ContractId
        status = $overall
        valid = ($overall -eq 'PASS')
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        jabba_executable = $jabba
        resolver_policy = 'explicit-jabba-which'
        no_global_use = $true
        path_or_java_home_mutation = $false
        observed_ids = @($inventory.ids)
        inventory_output_sha256 = $inventory.output_sha256
        profiles = @($records)
        safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED'; global_jabba_use = 'NOT_INVOKED' }
    }
} catch {
    $message = $_.Exception.Message
    $reason = if ($message -match '^JABBA_NOT_FOUND') { 'JABBA_NOT_FOUND' } elseif ($message -match '^JABBA_LIST_FAILED') { 'JABBA_LIST_FAILED' } else { 'JDK_DISCOVERY_FAILED' }
    $result = [ordered]@{ schema_version = 1; schema = 'jdk-discovery-v1'; contract_id = $ContractId; status = 'NOT_RUN'; valid = $false; reason_code = $reason; message = $message; jabba_executable = $null; resolver_policy = 'explicit-jabba-which'; no_global_use = $true; path_or_java_home_mutation = $false; profiles = @(); safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED'; global_jabba_use = 'NOT_INVOKED' } }
}

Write-Result $result -AsJson:$Json -Path $OutputPath
if (-not [bool]$result.valid) { exit 1 }
exit 0
