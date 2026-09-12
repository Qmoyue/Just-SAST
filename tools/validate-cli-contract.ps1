[CmdletBinding()]
param(
    [string] $LauncherJar = 'target/just-sast-0.2.0-shaded.jar',
    [int] $TimeoutMs = 30000,
    [string] $OutputPath,
    [switch] $SelfTest,
    [switch] $Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ContractId = 'JUST-PROD-D009-V1'
$RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$SchemaPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'cli-contract-v1.schema.json'))

function Assert-SchemaContract {
    if (-not (Test-Path -LiteralPath $SchemaPath -PathType Leaf)) { throw 'CLI_CONTRACT_SCHEMA_MISSING' }
    try { $schema = Get-Content -LiteralPath $SchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { throw 'CLI_CONTRACT_SCHEMA_INVALID' }
    if ($schema.schema -ne 'cli-contract-v1' -or $schema.contract_id -ne $ContractId) { throw 'CLI_CONTRACT_SCHEMA_ID_MISMATCH' }
}

function Resolve-RegularFile {
    param([Parameter(Mandatory = $true)] [string] $Value)
    $path = if ([IO.Path]::IsPathRooted($Value)) { [IO.Path]::GetFullPath($Value) } else { [IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Value)) }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "LAUNCHER_MISSING: $path" }
    return (Get-Item -LiteralPath $path -Force).FullName
}

function Resolve-Java {
    $command = Get-Command java.exe -ErrorAction SilentlyContinue
    if ($null -eq $command) { $command = Get-Command java -ErrorAction SilentlyContinue }
    if ($null -eq $command) { throw 'JAVA_NOT_FOUND' }
    $path = if (-not [string]::IsNullOrWhiteSpace([string]$command.Source)) { [string]$command.Source } else { [string]$command.Path }
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'JAVA_NOT_FOUND' }
    return (Get-Item -LiteralPath $path -Force).FullName
}

function Get-TextSha256 {
    param([AllowNull()] [string] $Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($(if ($null -eq $Text) { '' } else { $Text }))
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)] [string] $Value)
    if ($Value -match '^[A-Za-z0-9_./:=+-]+$') { return $Value }
    return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"'
}

function Invoke-Cli {
    param(
        [Parameter(Mandatory = $true)] [string] $JavaPath,
        [Parameter(Mandatory = $true)] [string] $Launcher,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]] $Arguments,
        [Parameter(Mandatory = $true)] [int] $Timeout
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $JavaPath
    $all = @('-jar', $Launcher) + $Arguments
    $psi.Arguments = (($all | ForEach-Object { Quote-ProcessArgument ([string]$_) }) -join ' ')
    $psi.WorkingDirectory = $RepoRoot
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $started = [DateTime]::UtcNow
    if (-not $process.Start()) { throw 'CLI_PROCESS_START_FAILED' }
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Timeout)) {
            try { $process.Kill() } catch { }
            return [ordered]@{ status = 'FAIL'; exit_code = -1; timed_out = $true; stdout = $stdoutTask.Result; stderr = $stderrTask.Result; wall_ms = [long](([DateTime]::UtcNow - $started).TotalMilliseconds) }
        }
        return [ordered]@{ status = 'COMPLETED'; exit_code = [int]$process.ExitCode; timed_out = $false; stdout = $stdoutTask.Result; stderr = $stderrTask.Result; wall_ms = [long](([DateTime]::UtcNow - $started).TotalMilliseconds) }
    } finally {
        $process.Dispose()
    }
}

function New-Case {
    param(
        [string] $Id,
        [string[]] $Arguments,
        [int] $ExpectedExit,
        [string] $StdoutPattern,
        [string] $StderrPattern,
        [string] $Purpose
    )
    return [ordered]@{ id = $Id; arguments = @($Arguments); expected_exit = $ExpectedExit; stdout_pattern = $StdoutPattern; stderr_pattern = $StderrPattern; purpose = $Purpose }
}

function Get-ContractCases {
    param([Parameter(Mandatory = $true)] [string] $MissingTarget)
    $missingConfig = Join-Path $RepoRoot 'target\cli-contract-selftest-missing.yml'
    return @(
        (New-Case 'help' @('--help') 0 '(?s)Commands:.*scan.*diff.*perf' '^$' 'help is stdout-only'),
        (New-Case 'version' @('--version') 0 '^just-sast\s+0\.2\.0' '^$' 'version is stable stdout'),
        (New-Case 'missing-subcommand' @() 2 '^$' '(?i)缺少子命令|Missing required|Usage:' 'usage errors are stderr and exit 2'),
        (New-Case 'unknown-option' @('scan', '--jar', $MissingTarget, '--unknown') 2 '^$' '(?i)Unknown option|Unmatched argument|未知选项' 'unknown options fail fast'),
        (New-Case 'missing-target-static-only' @('scan', '--jar', $MissingTarget, '--no-verify') 2 '^$' '(?i)STATIC_ONLY|目标不存在|does-not-exist' 'static-only missing target never starts dynamic verification'),
        (New-Case 'missing-target-default-auto' @('scan', '--jar', $MissingTarget) 2 '^$' '(?is)verificationMode=AUTO.*targetCodeExecutionPossible=true' 'default mode discloses trusted-target dynamic risk before analysis'),
        (New-Case 'config-unsupported' @('scan', '--jar', $MissingTarget, '--no-verify', '--config', $missingConfig) 2 '^$' '(?i)Unknown option|Unmatched argument|未知选项' 'implicit/config-file control plane is not silently accepted'),
        (New-Case 'duplicate-budget-rejected' @('scan', '--jar', $MissingTarget, '--no-verify', '--verify-budget', '1', '--verify-budget', '2') 2 '^$' '(?is)specified only once|duplicate|Usage:' 'duplicate scalar options are rejected before target analysis'),
        (New-Case 'out-of-range-budget-characterized' @('scan', '--jar', $MissingTarget, '--no-verify', '--verify-budget', '0') 2 '^$' '(?is)verificationMode=STATIC_ONLY.*targetCodeExecutionPossible=false' 'budget range is not rejected during CLI parsing; typed config migration owns fail-fast validation')
    )
}

function Invoke-SelfTest {
    Assert-SchemaContract
    $missing = Join-Path $RepoRoot 'target\cli-contract-selftest-missing.jar'
    $cases = @(Get-ContractCases $missing)
    if ($cases.Count -ne 9 -or $cases[0].id -ne 'help' -or $cases[7].id -ne 'duplicate-budget-rejected' -or $cases[8].id -ne 'out-of-range-budget-characterized') { throw 'SELFTEST_CASE_SET_FAILED' }
    if (-not ($cases[4].arguments -contains '--no-verify')) { throw 'SELFTEST_STATIC_ONLY_CASE_FAILED' }
    if (-not ($cases[5].stdout_pattern -eq '^$' -and $cases[5].stderr_pattern -match 'AUTO')) { throw 'SELFTEST_AUTO_DISCLOSURE_CASE_FAILED' }
    if (-not ($cases[6].arguments -contains '--config')) { throw 'SELFTEST_CONFIG_CASE_FAILED' }
    if (-not ($cases[7].arguments -contains '--verify-budget' -and $cases[8].arguments -contains '0')) { throw 'SELFTEST_OPTION_BOUNDARY_CASE_FAILED' }
    return [ordered]@{ schema_version = 1; schema = 'cli-contract-v1'; contract_id = $ContractId; status = 'PASS'; valid = $true; checks = @('schema-file', 'case-set', 'static-only-explicit', 'exit-code-contract', 'stdout-stderr-contract'); cases = @($cases | ForEach-Object { [ordered]@{ id = $_.id; status = 'CHARACTERIZED'; expected_exit = $_.expected_exit; purpose = $_.purpose } }); safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED' } }
}

function Write-Result {
    param([Parameter(Mandatory = $true)] $Result)
    $jsonText = $Result | ConvertTo-Json -Depth 20
    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $path = [IO.Path]::GetFullPath($OutputPath)
        if (Test-Path -LiteralPath $path) { throw "OUTPUT_EXISTS: $path" }
        $parent = Split-Path -Parent $path
        if (-not [string]::IsNullOrWhiteSpace($parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        $tmp = "$path.tmp-$([Guid]::NewGuid().ToString('N'))"
        try {
            [IO.File]::WriteAllText($tmp, $jsonText, (New-Object Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $tmp -Destination $path
        } finally {
            if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
        }
    }
    if ($Json) { Write-Output $jsonText } else {
        Write-Output ("CLI_CONTRACT status={0} valid={1}" -f $Result.status, $Result.valid)
        foreach ($case in @($Result.cases)) { Write-Output ("  {0} {1}" -f $case.id, $case.status) }
    }
}

if ($SelfTest) {
    try { Write-Result (Invoke-SelfTest); exit 0 } catch { Write-Result ([ordered]@{ schema_version = 1; schema = 'cli-contract-v1'; contract_id = $ContractId; status = 'FAIL'; valid = $false; reason_code = 'CLI_CONTRACT_SELFTEST_FAILED'; message = $_.Exception.Message; cases = @(); safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED' } }); exit 1 }
}

$result = $null
try {
    Assert-SchemaContract
    $java = Resolve-Java
    $launcher = Resolve-RegularFile $LauncherJar
    $missingTarget = Join-Path ([IO.Path]::GetTempPath()) ('just-cli-contract-missing-' + [Guid]::NewGuid().ToString('N') + '.jar')
    $records = [Collections.Generic.List[object]]::new()
    $failed = $false
    foreach ($case in @(Get-ContractCases $missingTarget)) {
        $run = Invoke-Cli $java $launcher $case.arguments $TimeoutMs
        $exitOk = (-not $run.timed_out) -and $run.exit_code -eq $case.expected_exit
        $stdoutOk = $run.stdout -match $case.stdout_pattern
        $stderrOk = $run.stderr -match $case.stderr_pattern
        $status = if ($exitOk -and $stdoutOk -and $stderrOk) { 'PASS' } else { 'FAIL' }
        if ($status -eq 'FAIL') { $failed = $true }
        $records.Add([ordered]@{ id = $case.id; status = $status; expected_exit = $case.expected_exit; actual_exit = $run.exit_code; timed_out = $run.timed_out; stdout_sha256 = Get-TextSha256 $run.stdout; stderr_sha256 = Get-TextSha256 $run.stderr; wall_ms = $run.wall_ms; stdout_contract = $stdoutOk; stderr_contract = $stderrOk; purpose = $case.purpose }) | Out-Null
    }
    $result = [ordered]@{ schema_version = 1; schema = 'cli-contract-v1'; contract_id = $ContractId; status = if ($failed) { 'FAIL' } else { 'PASS' }; valid = -not $failed; generated_at = (Get-Date).ToUniversalTime().ToString('o'); launcher = $launcher; java = $java; cases = @($records); safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED'; no_verify_case = 'STATIC_ONLY' } }
} catch {
    $result = [ordered]@{ schema_version = 1; schema = 'cli-contract-v1'; contract_id = $ContractId; status = 'NOT_RUN'; valid = $false; reason_code = if ($_.Exception.Message -match '^JAVA_NOT_FOUND') { 'JAVA_NOT_FOUND' } elseif ($_.Exception.Message -match '^LAUNCHER_MISSING') { 'LAUNCHER_MISSING' } else { 'CLI_CONTRACT_FAILED' }; message = $_.Exception.Message; cases = @(); safety = [ordered]@{ target_code_executed = 'NO'; network_access = 'NOT_INVOKED'; arbitrary_payload = 'NOT_INVOKED' } }
}
Write-Result $result
if (-not [bool]$result.valid) { exit 1 }
exit 0
