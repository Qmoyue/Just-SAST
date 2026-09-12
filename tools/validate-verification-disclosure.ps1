[CmdletBinding()]
param(
    [string] $RunPath,
    [string] $DynamicPath,
    [string] $RunSchemaPath,
    [string] $DynamicSchemaPath,
    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$RunSchemaPath = if ([string]::IsNullOrWhiteSpace($RunSchemaPath)) { Join-Path $Root 'docs/schemas/run-v1.schema.json' } else { [IO.Path]::GetFullPath($RunSchemaPath) }
$DynamicSchemaPath = if ([string]::IsNullOrWhiteSpace($DynamicSchemaPath)) { Join-Path $Root 'docs/schemas/dynamic-verification-v1.schema.json' } else { [IO.Path]::GetFullPath($DynamicSchemaPath) }

function Read-Json([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "MISSING_JSON:$Path" }
    try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { throw "INVALID_JSON:$Path" }
}

function Prop($Object, [string] $Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function Field($Object, [string] $SnakeName) {
    $value = Prop $Object $SnakeName
    if ($null -ne $value) { return $value }
    $camel = switch ($SnakeName) {
        'verification_mode' { 'verificationMode' }
        'target_code_execution_possible' { 'targetCodeExecutionPossible' }
        'target_code_executed' { 'targetCodeExecuted' }
        'resource_containment_only' { 'resourceContainmentOnly' }
        'filesystem_isolation' { 'filesystemIsolation' }
        'network_isolation' { 'networkIsolation' }
        'token_isolation' { 'tokenIsolation' }
        'dangerous_sink_executed' { 'dangerousSinkExecuted' }
        'recommended_for_untrusted_artifacts' { 'recommendedForUntrustedArtifacts' }
        'target_trust' { 'targetTrust' }
        'isolation_backend' { 'isolationBackend' }
        'isolation_status' { 'isolationStatus' }
        'fail_closed_on_isolation_failure' { 'failClosedOnIsolationFailure' }
        default { $null }
    }
    if ($null -eq $camel) { return $null }
    return Prop $Object $camel
}

function Add-Issue([Collections.Generic.List[string]] $Issues, [string] $Code) { $Issues.Add($Code) | Out-Null }

function Test-Safety($Document, [string] $Prefix, [Collections.Generic.List[string]] $Issues) {
    $mode = [string](Field $Document 'verification_mode')
    $possible = [bool](Field $Document 'target_code_execution_possible')
    $executed = [string](Field $Document 'target_code_executed')
    $trust = [string](Field $Document 'target_trust')
    if (@('AUTO', 'STATIC_ONLY') -notcontains $mode) { Add-Issue $Issues ($Prefix + 'MODE') }
    if (@('TRUSTED_LOCAL_TARGET_REQUIRED', 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH') -notcontains $trust) { Add-Issue $Issues ($Prefix + 'TRUST') }
    if ($null -eq (Field $Document 'resource_containment_only') -or -not [bool](Field $Document 'resource_containment_only')) { Add-Issue $Issues ($Prefix + 'CONTAINMENT') }
    if ($null -eq (Field $Document 'filesystem_isolation') -or [bool](Field $Document 'filesystem_isolation')) { Add-Issue $Issues ($Prefix + 'FILESYSTEM_OVERCLAIM') }
    if ($null -eq (Field $Document 'network_isolation') -or [bool](Field $Document 'network_isolation')) { Add-Issue $Issues ($Prefix + 'NETWORK_OVERCLAIM') }
    if ($null -eq (Field $Document 'token_isolation') -or [bool](Field $Document 'token_isolation')) { Add-Issue $Issues ($Prefix + 'TOKEN_OVERCLAIM') }
    if ($null -eq (Field $Document 'dangerous_sink_executed') -or [bool](Field $Document 'dangerous_sink_executed')) { Add-Issue $Issues ($Prefix + 'DANGEROUS_SINK') }
    if ($null -eq (Field $Document 'fail_closed_on_isolation_failure') -or -not [bool](Field $Document 'fail_closed_on_isolation_failure')) { Add-Issue $Issues ($Prefix + 'FAIL_OPEN') }
    if ([string]::IsNullOrWhiteSpace($executed)) { Add-Issue $Issues ($Prefix + 'EXECUTED_EMPTY') }
    if ($mode -eq 'AUTO' -and -not $possible) { Add-Issue $Issues ($Prefix + 'AUTO_POSSIBILITY') }
    if ($mode -eq 'STATIC_ONLY' -and $possible) { Add-Issue $Issues ($Prefix + 'STATIC_POSSIBILITY') }
    if (-not $possible -and $executed -eq 'YES') { Add-Issue $Issues ($Prefix + 'IMPOSSIBLE_EXECUTION') }
}

function Test-Documents($Run, $Dynamic) {
    $issues = [Collections.Generic.List[string]]::new()
    if ([int](Prop $Run 'schema_version') -ne 1) { Add-Issue $issues 'RUN_SCHEMA_VERSION' }
    if (([string](Prop $Run 'kind')) -ne 'just-run') { Add-Issue $issues 'RUN_KIND' }
    Test-Safety $Run 'RUN_SAFETY_' $issues
    if ([int](Prop $Dynamic 'schema_version') -ne 1) { Add-Issue $issues 'DYNAMIC_SCHEMA_VERSION' }
    Test-Safety $Dynamic 'DYNAMIC_SAFETY_' $issues
    if ($null -eq $Dynamic.PSObject.Properties['results']) { Add-Issue $issues 'DYNAMIC_RESULTS' }
    return [ordered]@{ valid = ($issues.Count -eq 0); issues = @($issues.ToArray()) }
}

function Invoke-SelfTest {
    $run = [pscustomobject]@{ schema_version = 1; kind = 'just-run'; verification_mode = 'STATIC_ONLY'; target_code_execution_possible = $false; target_code_executed = 'NO'; resource_containment_only = $true; filesystem_isolation = $false; network_isolation = $false; token_isolation = $false; dangerous_sink_executed = $false; recommended_for_untrusted_artifacts = $true; target_trust = 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH'; fail_closed_on_isolation_failure = $true }
    $dynamic = [pscustomobject]@{ schema_version = 1; verification_mode = 'STATIC_ONLY'; target_code_execution_possible = $false; target_code_executed = 'NO'; resource_containment_only = $true; filesystem_isolation = $false; network_isolation = $false; token_isolation = $false; dangerous_sink_executed = $false; recommended_for_untrusted_artifacts = $true; target_trust = 'STATIC_ONLY_UNTRUSTED_ARTIFACT_PATH'; isolation_backend = 'UNKNOWN'; isolation_status = 'NOT_REQUESTED'; fail_closed_on_isolation_failure = $true; capability_gaps = @(); results = @() }
    $valid = Test-Documents $run $dynamic
    if (-not $valid.valid) { throw ('VALID_DISCLOSURE_REJECTED:' + (@($valid.issues) -join ',')) }
    $dynamic.filesystem_isolation = $true
    $invalid = Test-Documents $run $dynamic
    if ($invalid.valid -or @($invalid.issues | Where-Object { $_ -eq 'DYNAMIC_SAFETY_FILESYSTEM_OVERCLAIM' }).Count -eq 0) { throw 'OVERCLAIM_NOT_REJECTED' }
    return [ordered]@{ status = 'PASS'; tests = @('run-safety', 'dynamic-safety', 'overclaim-rejected') }
}

try {
    if ($SelfTest) {
        $result = Invoke-SelfTest
        if ($Json) { $result | ConvertTo-Json -Depth 10 } else { Write-Output ('VERIFICATION_DISCLOSURE_VALIDATOR_SELF_TEST=' + $result.status) }
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($RunPath) -or [string]::IsNullOrWhiteSpace($DynamicPath)) { throw 'RUN_AND_DYNAMIC_REQUIRED' }
    if (-not (Test-Path -LiteralPath $RunSchemaPath -PathType Leaf)) { throw 'RUN_SCHEMA_MISSING' }
    if (-not (Test-Path -LiteralPath $DynamicSchemaPath -PathType Leaf)) { throw 'DYNAMIC_SCHEMA_MISSING' }
    $run = Read-Json ([IO.Path]::GetFullPath($RunPath))
    $dynamic = Read-Json ([IO.Path]::GetFullPath($DynamicPath))
    $result = Test-Documents $run $dynamic
    $result.run_path = [IO.Path]::GetFullPath($RunPath)
    $result.dynamic_path = [IO.Path]::GetFullPath($DynamicPath)
    if ($Json) { $result | ConvertTo-Json -Depth 10 } else { Write-Output ('VERIFICATION_DISCLOSURE_VALID=' + $result.valid); Write-Output ('issues=' + (@($result.issues) -join ',')) }
    if (-not $result.valid) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine(('VERIFICATION_DISCLOSURE_VALIDATOR_ERROR: ' + $_.Exception.Message))
    exit 2
}
