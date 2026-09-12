[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $ManifestPath,

    [switch] $Json,
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# This validator is a harness boundary. It verifies the local manifest and its
# hash-pinned inputs; it never invokes Just, an evaluator, a payload, or target
# code. The product scanner must not consume the truth fields in this file.
$ExpectedContractId = "JUST-PROD-D009-V1"
$KnownKinds = @("wp8", "gleipner-kernel", "apache-heldout")
$ExpectedWpIds = @("demo", "demo2", "n1cat", "babychain", "babygadget", "javamix", "qiao", "jdbc-master")
$AllowedTop = @('$schema', 'schema_version', 'contract_id', 'manifest_id', 'manifest_kind', 'truth_policy', 'generated_at', 'jdk_catalog', 'cases')
$AllowedJdk = @('id', 'feature', 'resolver', 'status', 'java_sha256', 'home_digest', 'notes')
$AllowedArtifact = @('path', 'kind', 'status', 'sha256', 'bytes', 'provenance')
$AllowedProvenance = @('source_kind', 'license_status', 'upstream', 'commit', 'build_command', 'missing_reason')
$AllowedDependency = @('id', 'scope', 'status', 'location', 'sha256', 'bytes', 'coordinate', 'notes')
$AllowedEntry = @('id', 'owner', 'boundary', 'status', 'controllability', 'protocol', 'method', 'location', 'notes')
$AllowedSite = @('id', 'owner', 'role', 'status', 'protocol', 'signature', 'location', 'artifact_scope', 'notes')
$AllowedJoin = @('id', 'status', 'application_entry', 'site', 'dependency_segment', 'required_evidence', 'notes')
$AllowedBridge = @('id', 'kind', 'status', 'source', 'target', 'required', 'protocol_version', 'controlled_value', 'notes')
$AllowedNegative = @('id', 'kind', 'status', 'reason')
$AllowedDynamic = @('allowed_level', 'side_effect_policy', 'max_attempts', 'timeout_ms', 'status', 'notes')
$AllowedTruth = @('status', 'version', 'source_refs', 'reviewers', 'last_verified', 'notes')
$AllowedChain = @('status', 'progress', 'terminal', 'middle_nodes_not_terminal', 'required_joins', 'expected_callbacks', 'notes')
$AllowedCase = @('id', 'category', 'status', 'artifacts', 'target_jdk', 'dependencies', 'dependency_completeness', 'application_entries', 'sites', 'join_evidence', 'bridge_evidence', 'chain_expectation', 'negative_anchors', 'dynamic', 'truth', 'notes')

function Add-Issue {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues,
        [Parameter(Mandatory = $true)] [string] $Code,
        [Parameter(Mandatory = $true)] [string] $Message
    )
    $Issues.Add([pscustomobject]@{ code = $Code; message = $Message }) | Out-Null
}

function Get-PropertyValue {
    param([AllowNull()] $Object, [Parameter(Mandatory = $true)] [string] $Name)
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.PSObject.Properties[$Name].Value
}

function Test-StringValue {
    param([AllowNull()] $Value)
    return ($null -ne $Value -and $Value -is [string] -and -not [string]::IsNullOrWhiteSpace([string]$Value))
}

function Assert-ObjectShape {
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] $Object,
        [Parameter(Mandatory = $true)] [string[]] $Allowed,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues
    )
    if ($null -eq $Object) {
        Add-Issue $Issues "NULL_OBJECT" "$Path is null."
        return
    }
    foreach ($property in @($Object.PSObject.Properties)) {
        if ($Allowed -notcontains $property.Name) {
            Add-Issue $Issues "UNKNOWN_FIELD" "$Path.$($property.Name) is not allowed by manifest schema v2."
        }
    }
}

function Resolve-ManifestInput {
    param(
        [Parameter(Mandatory = $true)] [string] $Value,
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $RepoRoot,
        [Parameter(Mandatory = $true)] [string] $Label,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues
    )
    if (-not (Test-StringValue $Value)) {
        Add-Issue $Issues "PATH_EMPTY" "$Label path is empty."
        return $null
    }
    if ([IO.Path]::IsPathRooted($Value) -or $Value -match '^[A-Za-z]:') {
        Add-Issue $Issues "PATH_ABSOLUTE" "$Label must be repository-relative: $Value"
        return $null
    }
    $candidate = [IO.Path]::GetFullPath((Join-Path -Path $Base -ChildPath $Value))
    $rootWithSlash = $RepoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not ($candidate.Equals($RepoRoot, [StringComparison]::OrdinalIgnoreCase) -or $candidate.StartsWith($rootWithSlash, [StringComparison]::OrdinalIgnoreCase))) {
        Add-Issue $Issues "PATH_ESCAPE" "$Label escapes repository root: $Value"
        return $null
    }
    return $candidate
}

function Get-ExpectedSha256 {
    param([Parameter(Mandatory = $true)] [string] $Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Test-Artifact {
    param(
        [Parameter(Mandatory = $true)] $Artifact,
        [Parameter(Mandatory = $true)] [string] $Label,
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $RepoRoot,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Observed,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Missing
    )
    Assert-ObjectShape $Artifact $AllowedArtifact $Label $Issues
    $pathValue = [string](Get-PropertyValue $Artifact 'path')
    $resolved = Resolve-ManifestInput $pathValue $Base $RepoRoot $Label $Issues
    $status = [string](Get-PropertyValue $Artifact 'status')
    $kind = [string](Get-PropertyValue $Artifact 'kind')
    $sha = Get-PropertyValue $Artifact 'sha256'
    $bytes = Get-PropertyValue $Artifact 'bytes'
    if ($status -notin @('OBSERVED', 'MISSING', 'UNVERIFIED')) {
        Add-Issue $Issues "ARTIFACT_STATUS" "$Label has unsupported status '$status'."
    }
    if ($kind -notin @('jar', 'war', 'zip', 'tar-gz', 'directory', 'source-tree', 'evaluator')) {
        Add-Issue $Issues "ARTIFACT_KIND" "$Label has unsupported kind '$kind'."
    }
    if ($null -ne $sha -and ([string]$sha -notmatch '^[a-f0-9]{64}$')) {
        Add-Issue $Issues "ARTIFACT_SHA_FORMAT" "$Label sha256 is not lowercase hexadecimal SHA-256."
    }
    if ($null -ne $bytes -and (([int64]$bytes) -lt 0)) {
        Add-Issue $Issues "ARTIFACT_SIZE" "$Label bytes cannot be negative."
    }
    if ($status -eq 'OBSERVED') {
        if ($null -eq $resolved -or -not (Test-Path -LiteralPath $resolved)) {
            Add-Issue $Issues "INPUT_MISSING" "$Label is OBSERVED but does not exist."
        } elseif ($kind -in @('jar', 'war', 'zip', 'tar-gz', 'evaluator')) {
            $item = Get-Item -LiteralPath $resolved -Force
            if ($item -isnot [IO.FileInfo]) {
                Add-Issue $Issues "INPUT_NOT_FILE" "$Label is OBSERVED but is not a regular file."
            } else {
                $actualSha = Get-ExpectedSha256 $resolved
                $actualBytes = [int64]$item.Length
                if ([string]$sha -ne $actualSha) { Add-Issue $Issues "INPUT_MISMATCH" "$Label SHA-256 mismatch: expected '$sha', observed '$actualSha'." }
                if ([int64]$bytes -ne $actualBytes) { Add-Issue $Issues "INPUT_SIZE_MISMATCH" "$Label size mismatch: expected $bytes, observed $actualBytes." }
                $Observed.Add([pscustomobject]@{ label = $Label; path = $resolved; sha256 = $actualSha; bytes = $actualBytes }) | Out-Null
            }
        } else {
            $Observed.Add([pscustomobject]@{ label = $Label; path = $resolved; sha256 = $null; bytes = $null }) | Out-Null
        }
    } elseif ($status -eq 'MISSING') {
        if ($null -ne $resolved -and (Test-Path -LiteralPath $resolved)) {
            Add-Issue $Issues "MISSING_BUT_PRESENT" "$Label is marked MISSING but exists."
        }
        $Missing.Add($Label) | Out-Null
    }
    return $resolved
}

function Test-Dependency {
    param(
        [Parameter(Mandatory = $true)] $Dependency,
        [Parameter(Mandatory = $true)] [string] $Label,
        [Parameter(Mandatory = $true)] [string] $Base,
        [Parameter(Mandatory = $true)] [string] $RepoRoot,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues
    )
    Assert-ObjectShape $Dependency $AllowedDependency $Label $Issues
    $scope = [string](Get-PropertyValue $Dependency 'scope')
    $status = [string](Get-PropertyValue $Dependency 'status')
    if ($status -ne 'UNVERIFIED') { Add-Issue $Issues "DEPENDENCY_STATUS" "$Label status must remain UNVERIFIED in P0.1 skeleton." }
    if ($scope -notin @('embedded', 'external', 'jdk', 'protocol-helper')) { Add-Issue $Issues "DEPENDENCY_SCOPE" "$Label has unsupported scope '$scope'." }
    $location = [string](Get-PropertyValue $Dependency 'location')
    $path = Resolve-ManifestInput $location $Base $RepoRoot $Label $Issues
    $sha = Get-PropertyValue $Dependency 'sha256'
    $bytes = Get-PropertyValue $Dependency 'bytes'
    if ($null -ne $sha -and $sha -notmatch '^[a-f0-9]{64}$') { Add-Issue $Issues "DEPENDENCY_SHA_FORMAT" "$Label sha256 is invalid." }
    if ($scope -eq 'external' -and $null -ne $path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        $item = Get-Item -LiteralPath $path -Force
        $actualSha = Get-ExpectedSha256 $path
        if ($null -ne $sha -and [string]$sha -ne $actualSha) { Add-Issue $Issues "DEPENDENCY_INPUT_MISMATCH" "$Label SHA-256 mismatch: expected '$sha', observed '$actualSha'." }
        if ($null -ne $bytes -and [int64]$bytes -ne [int64]$item.Length) { Add-Issue $Issues "DEPENDENCY_SIZE_MISMATCH" "$Label size mismatch." }
    } elseif ($scope -eq 'external') {
        Add-Issue $Issues "DEPENDENCY_MISSING" "$Label external dependency is missing: $location"
    }
}

function Assert-UnverifiedStatus {
    param(
        [Parameter(Mandatory = $true)] $Object,
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Property,
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Issues
    )
    $value = Get-PropertyValue $Object $Property
    if ([string]$value -ne 'UNVERIFIED') { Add-Issue $Issues "TRUTH_STATUS" "$Path.$Property must be UNVERIFIED in this skeleton (got '$value')." }
}

function Invoke-ManifestValidation {
    param([Parameter(Mandatory = $true)] [string] $Text, [Parameter(Mandatory = $true)] [string] $DisplayPath)

    $issues = [System.Collections.Generic.List[object]]::new()
    try { $definition = $Text | ConvertFrom-Json } catch { Add-Issue $issues "JSON_PARSE" "Manifest JSON parse failed: $($_.Exception.Message)"; return [pscustomobject]@{ valid = $false; manifest_path = $DisplayPath; manifest_id = $null; manifest_kind = $null; case_count = 0; observed_artifact_count = 0; missing_artifact_count = 0; issues = @($issues.ToArray()) } }
    Assert-ObjectShape $definition $AllowedTop '<root>' $issues
    $schema = Get-PropertyValue $definition 'schema_version'
    if ([int]$schema -ne 2) { Add-Issue $issues "SCHEMA_VERSION" "schema_version must be 2." }
    $contract = [string](Get-PropertyValue $definition 'contract_id')
    if ($contract -ne $ExpectedContractId) { Add-Issue $issues "CONTRACT_ID" "contract_id must be $ExpectedContractId." }
    $kind = [string](Get-PropertyValue $definition 'manifest_kind')
    if ($kind -notin $KnownKinds) { Add-Issue $issues "MANIFEST_KIND" "manifest_kind '$kind' is unsupported." }
    if ([string](Get-PropertyValue $definition 'truth_policy') -ne 'UNVERIFIED_UNTIL_MANUAL_BYTECODE_AND_EVALUATOR_REVIEW') { Add-Issue $issues "TRUTH_POLICY" "truth_policy is not the required unverified policy." }
    $base = Split-Path -Parent ([IO.Path]::GetFullPath($DisplayPath))
    $repoRoot = [IO.Path]::GetFullPath((Join-Path $base '..\..'))
    $observed = [System.Collections.Generic.List[object]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()

    foreach ($jdk in @((Get-PropertyValue $definition 'jdk_catalog'))) {
        Assert-ObjectShape $jdk $AllowedJdk "jdk_catalog" $issues
        if ([string](Get-PropertyValue $jdk 'resolver') -ne 'jabba') { Add-Issue $issues "JDK_RESOLVER" "jdk profile must resolve through Jabba." }
        if ([string](Get-PropertyValue $jdk 'status') -notin @('OBSERVED', 'UNVERIFIED', 'NOT_RUN')) { Add-Issue $issues "JDK_STATUS" "unsupported JDK status." }
    }

    $cases = @((Get-PropertyValue $definition 'cases'))
    if ($cases.Count -eq 0) { Add-Issue $issues "CASES_EMPTY" "manifest.cases must not be empty." }
    $seenCases = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($case in $cases) {
        $caseId = [string](Get-PropertyValue $case 'id')
        $casePath = "cases[$caseId]"
        Assert-ObjectShape $case $AllowedCase $casePath $issues
        if (-not $seenCases.Add($caseId)) { Add-Issue $issues "CASE_DUPLICATE" "case id '$caseId' is duplicated." }
        if ([string](Get-PropertyValue $case 'status') -ne 'UNVERIFIED') { Add-Issue $issues "CASE_STATUS" "$casePath.status must be UNVERIFIED in the skeleton." }
        if ([string](Get-PropertyValue $case 'category') -notin @('wp', 'gadget-kernel', 'apache')) { Add-Issue $issues "CASE_CATEGORY" "$casePath.category is unsupported." }
        Assert-UnverifiedStatus $case $casePath 'status' $issues
        foreach ($artifact in @((Get-PropertyValue $case 'artifacts'))) {
            Test-Artifact $artifact "$casePath.artifact" $base $repoRoot $issues $observed $missing | Out-Null
            Assert-ObjectShape (Get-PropertyValue $artifact 'provenance') $AllowedProvenance "$casePath.artifact.provenance" $issues
        }
        $jdk = Get-PropertyValue $case 'target_jdk'
        Assert-ObjectShape $jdk $AllowedJdk "$casePath.target_jdk" $issues
        if ([string](Get-PropertyValue $jdk 'resolver') -ne 'jabba') { Add-Issue $issues "JDK_RESOLVER" "$casePath.target_jdk must use Jabba." }
        if ([string](Get-PropertyValue $jdk 'status') -ne 'UNVERIFIED') { Add-Issue $issues "TARGET_JDK_STATUS" "$casePath.target_jdk.status must be UNVERIFIED." }
        $dependencyIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($dependency in @((Get-PropertyValue $case 'dependencies'))) {
            $dependencyId = [string](Get-PropertyValue $dependency 'id')
            if (-not $dependencyIds.Add($dependencyId)) { Add-Issue $issues "DEPENDENCY_DUPLICATE" "$casePath dependency '$dependencyId' is duplicated." }
            Test-Dependency $dependency "$casePath.dependency[$dependencyId]" $base $repoRoot $issues
        }
        foreach ($entry in @((Get-PropertyValue $case 'application_entries'))) { Assert-ObjectShape $entry $AllowedEntry "$casePath.application_entry" $issues; Assert-UnverifiedStatus $entry "$casePath.application_entry" 'status' $issues }
        foreach ($site in @((Get-PropertyValue $case 'sites'))) { Assert-ObjectShape $site $AllowedSite "$casePath.site" $issues; Assert-UnverifiedStatus $site "$casePath.site" 'status' $issues }
        foreach ($join in @((Get-PropertyValue $case 'join_evidence'))) { Assert-ObjectShape $join $AllowedJoin "$casePath.join" $issues; Assert-UnverifiedStatus $join "$casePath.join" 'status' $issues }
        foreach ($bridge in @((Get-PropertyValue $case 'bridge_evidence'))) { Assert-ObjectShape $bridge $AllowedBridge "$casePath.bridge" $issues; Assert-UnverifiedStatus $bridge "$casePath.bridge" 'status' $issues }
        $chain = Get-PropertyValue $case 'chain_expectation'; Assert-ObjectShape $chain $AllowedChain "$casePath.chain_expectation" $issues; Assert-UnverifiedStatus $chain "$casePath.chain_expectation" 'status' $issues
        $negatives = @((Get-PropertyValue $case 'negative_anchors'))
        if ($negatives.Count -lt 2) { Add-Issue $issues "NEGATIVE_ANCHORS" "$casePath must have at least two negative anchors." }
        foreach ($negative in $negatives) { Assert-ObjectShape $negative $AllowedNegative "$casePath.negative" $issues; Assert-UnverifiedStatus $negative "$casePath.negative" 'status' $issues }
        $dynamic = Get-PropertyValue $case 'dynamic'; Assert-ObjectShape $dynamic $AllowedDynamic "$casePath.dynamic" $issues; Assert-UnverifiedStatus $dynamic "$casePath.dynamic" 'status' $issues
        if ([string](Get-PropertyValue $dynamic 'side_effect_policy') -ne 'NO_DANGEROUS_SINK_NO_NETWORK_NO_FILE_WRITE_NO_ARBITRARY_BYTECODE') { Add-Issue $issues "DYNAMIC_POLICY" "$casePath.dynamic has an unsafe side-effect policy." }
        $truth = Get-PropertyValue $case 'truth'; Assert-ObjectShape $truth $AllowedTruth "$casePath.truth" $issues; Assert-UnverifiedStatus $truth "$casePath.truth" 'status' $issues
        if ([string](Get-PropertyValue $case 'category') -eq 'gadget-kernel' -and @((Get-PropertyValue $case 'application_entries')).Count -ne 0) { Add-Issue $issues "KERNEL_ENTRY" "$casePath gadget-kernel case must not declare an application entry." }
    }
    if ($kind -eq 'wp8') {
        $actualIds = @($seenCases | Sort-Object)
        $expectedSorted = @($ExpectedWpIds | Sort-Object)
        if (($actualIds -join ',') -ne ($expectedSorted -join ',')) { Add-Issue $issues "WP_CASE_SET" "wp8 case set must be exactly: $($ExpectedWpIds -join ',')." }
    }
    return [pscustomobject]@{
        valid = ($issues.Count -eq 0)
        manifest_path = $DisplayPath
        manifest_id = [string](Get-PropertyValue $definition 'manifest_id')
        manifest_kind = $kind
        case_count = $cases.Count
        observed_artifact_count = $observed.Count
        missing_artifact_count = $missing.Count
        observed_artifacts = @($observed.ToArray())
        missing_artifacts = @($missing.ToArray())
        issues = @($issues.ToArray())
    }
}

function Assert-SelfTestCase {
    param([Parameter(Mandatory = $true)] [string] $Name, [Parameter(Mandatory = $true)] [string] $Text, [Parameter(Mandatory = $true)] [bool] $ExpectedValid, [Parameter(Mandatory = $true)] [string] $BaseManifestPath)
    $result = Invoke-ManifestValidation $Text $BaseManifestPath
    if ([bool]$result.valid -ne $ExpectedValid) {
        throw "Self-test '$Name' expected valid=$ExpectedValid, got valid=$($result.valid): $((@($result.issues) | ForEach-Object { $_.code }) -join ',')"
    }
    return [pscustomobject]@{ name = $Name; valid = $result.valid }
}

function Invoke-ManifestSelfTest {
    param([Parameter(Mandatory = $true)] [string] $Text, [Parameter(Mandatory = $true)] [string] $BaseManifestPath)
    $base = Assert-SelfTestCase 'current-manifest' $Text $true $BaseManifestPath
    $mutations = [ordered]@{
        'bad-contract' = ($Text -replace 'JUST-PROD-D009-V1', 'WRONG-CONTRACT')
        'duplicate-case' = ($Text -replace '"id": "demo2",', '"id": "demo",')
        'absolute-artifact-path' = ($Text -replace '"path": "\.\./demo/demo\.jar"', '"path": "C:\\outside\\demo.jar"')
        'hash-mismatch' = ($Text -replace '125a6620d61c8c19cdcd4313fdaa1dd08913314f7cd16daf37119f3043bf65ed', ('0' * 64))
        'verified-truth' = ($Text -replace '"truth": \{ "status": "UNVERIFIED"', '"truth": { "status": "VERIFIED"')
        'missing-negative' = ($Text -replace '(?s)"negative_anchors": \[.*?\]', '"negative_anchors": []')
        'unknown-field' = ($Text -replace '"manifest_id": "', '"unknown_field": true,\n  "manifest_id": "')
    }
    $cases = [System.Collections.Generic.List[object]]::new(); $cases.Add($base) | Out-Null
    foreach ($name in $mutations.Keys) { $cases.Add((Assert-SelfTestCase $name ([string]$mutations[$name]) $false $BaseManifestPath)) | Out-Null }
    return [pscustomobject]@{ status = 'PASS'; test_count = $cases.Count; cases = @($cases.ToArray()) }
}

try {
    if ($SelfTest) {
        $source = Get-Content -LiteralPath ([IO.Path]::GetFullPath($ManifestPath)) -Raw -Encoding UTF8
        $self = Invoke-ManifestSelfTest $source ([IO.Path]::GetFullPath($ManifestPath))
        if ($Json) { $self | ConvertTo-Json -Depth 8 } else { "MANIFEST_VALIDATOR_SELF_TEST=PASS"; "cases=$($self.test_count)"; foreach ($case in @($self.cases)) { "case=$($case.name)" } }
        exit 0
    }
    $resolved = [IO.Path]::GetFullPath($ManifestPath)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Manifest file not found: $resolved" }
    $text = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8
    $result = Invoke-ManifestValidation $text $resolved
    if ($Json) { $result | ConvertTo-Json -Depth 12 } else {
        "MANIFEST_VALID=$($result.valid)"; "manifest_id=$($result.manifest_id)"; "manifest_kind=$($result.manifest_kind)"; "case_count=$($result.case_count)"; "observed_artifact_count=$($result.observed_artifact_count)"; "missing_artifact_count=$($result.missing_artifact_count)"; foreach ($issue in @($result.issues)) { "ISSUE[$($issue.code)] $($issue.message)" }
    }
    if (-not $result.valid) { exit 1 }
    exit 0
} catch {
    [Console]::Error.WriteLine("MANIFEST_VALIDATOR_ERROR: $($_.Exception.Message)")
    exit 2
}
