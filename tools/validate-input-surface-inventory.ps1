[CmdletBinding()]
param(
    [string]$InventoryPath,
    [switch]$SelfTest,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $repoRoot
if ([string]::IsNullOrWhiteSpace($InventoryPath)) {
    $InventoryPath = Join-Path (Join-Path $repoRoot 'tools') 'input-surface-inventory-v1.json'
}

function New-Result {
    param([bool]$Valid, [string[]]$Issues, [string[]]$Checks)
    [pscustomobject]@{
        schema_version = 1
        valid = $Valid
        contract_id = 'JUST-PROD-D009-V1'
        inventory = 'input-surface-inventory-v1'
        checks = @($Checks)
        issues = @($Issues)
    }
}

$requiredIds = @(
    'frontend.jar-reader', 'verify.nested-classpath', 'report.dependency-inventory',
    'util.artifact-fingerprint', 'report.scan-cache', 'config.yaml-rule-loader',
    'report.atomic-files', 'report.multi-format', 'report.csv', 'report.sarif',
    'report.baseline-suppression', 'report.path-and-identity', 'verify.dynamic-temp',
    'verify.parallel', 'cli.scan-pipeline', 'cli.performance', 'cli.diff', 'verify.safe-sink-adapter',
    'perf.profile', 'report.scan-identity', 'util.io'
)
$requiredArchivePaths = @(
    'src/main/java/io/just/sast/frontend/asm/JarReader.java',
    'src/main/java/io/just/sast/verify/NestedClasspath.java',
    'src/main/java/io/just/sast/report/DependencyInventoryWriter.java',
    'src/main/java/io/just/sast/util/ArtifactFingerprint.java',
    'src/main/java/io/just/sast/report/ScanCache.java',
    'src/main/java/io/just/sast/config/YamlRuleLoader.java',
    'src/main/java/io/just/sast/report/AtomicFiles.java',
    'src/main/java/io/just/sast/cli/DiffCommand.java'
)
$p29RequiredIds = @(
    'frontend.jar-reader', 'frontend.bytecode-frontend', 'verify.nested-classpath',
    'report.dependency-inventory', 'util.artifact-fingerprint', 'report.scan-cache',
    'config.yaml-rule-loader', 'report.atomic-files', 'report.path-and-identity',
    'knowledge.chain-composer', 'frontend.classfile-limits', 'frontend.jrt-class-source',
    'frontend.target-jdk-source', 'util.io'
)
$p29RequiredCoverage = @{
    'frontend.jar-reader' = @('caller-total-budget', 'randomized-central-directory-fuzz', 'randomized-whole-archive-fuzz', 'typed-provider-atomic-status', 'pre-read-request-clamp', 'tracker-atomic-read-accounting')
    'frontend.bytecode-frontend' = @('caller-tracker-loadStreaming', 'class-parse-time-accounting', 'caller-context-status-typed')
    'verify.nested-classpath' = @('parse-time-budget', 'zero-progress-guard', 'source-TOCTOU-snapshot', 'output-parent-replacement-race', 'typed-provider-atomic-status')
    'report.dependency-inventory' = @('parse-time-budget', 'caller-total-budget', 'typed-provider-atomic-status', 'pre-read-request-clamp', 'tracker-atomic-read-accounting')
    'util.artifact-fingerprint' = @('global-budget', 'TOCTOU-snapshot', 'directory-component-identity-contract', 'pre-read-request-clamp', 'tracker-atomic-read-accounting')
    'report.scan-cache' = @('typed-input-budget', 'bounded-tree-copy', 'source-directory-chain-identity', 'restore-parent-identity-before-commit', 'pre-read-request-clamp', 'tracker-atomic-read-accounting')
    'config.yaml-rule-loader' = @('aggregate-node-accounting', 'aggregate-collection-accounting', 'aggregate-scalar-accounting', 'deterministic-randomized-malformed-fuzz')
    'report.atomic-files' = @('run-level-staging-commit', 'failed-state-recovery-marker', 'recovery-reconciliation-read-only', 'output-target-identity-before-move')
    'report.path-and-identity' = @('run-state-machine', 'recovery-reconciliation-read-only', 'typed-recovery-action-policy')
    'knowledge.chain-composer' = @('bounded-archive-enumeration', 'parse-time-budget', 'entry-identity-before-after', 'typed-provider-atomic-status')
    'frontend.classfile-limits' = @('bounded-preflight', 'caller-parser-time-hook', 'deterministic-randomized-malformed-fuzz')
    'frontend.jrt-class-source' = @('caller-total-budget', 'index-structure-budget', 'index-path-bound', 'index-entry-budget', 'class-entry-identity-before-after', 'typed-provider-atomic-status')
    'frontend.target-jdk-source' = @('caller-total-budget', 'class-entry-identity-before-after', 'class-entry-crc', 'class-entry-content-digest-consistency', 'typed-provider-atomic-status')
    'util.io' = @('single-stream-byte-limit', 'zero-progress-guard', 'time-budget', 'caller-total-budget', 'typed-provider-atomic-status', 'pre-read-request-clamp', 'tracker-atomic-read-accounting')
}

function Test-Inventory {
    param($data, [string]$root)
    $issues = [System.Collections.Generic.List[string]]::new()
    $checks = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $data) {
        $issues.Add('INVENTORY_EMPTY')
        return New-Result $false $issues $checks
    }
    if ($data.schemaVersion -ne 'input-surface-inventory-v1') { $issues.Add('SCHEMA_VERSION') }
    if ($data.contractId -ne 'JUST-PROD-D009-V1') { $issues.Add('CONTRACT_ID') }
    if ($data.statusVocabulary -join ',' -ne 'SUPPORTED,PARTIAL,UNSUPPORTED') { $issues.Add('STATUS_VOCABULARY') }
    if ($null -eq $data.sharedOwners.archiveBudget -or $null -eq $data.sharedOwners.ruleLoader -or $null -eq $data.sharedOwners.singleFileCommit) {
        $issues.Add('SHARED_OWNERS_MISSING')
    }
    $consumers = @($data.consumers)
    if ($consumers.Count -eq 0) { $issues.Add('CONSUMERS_EMPTY') }
    $seen = @{}
    foreach ($consumer in $consumers) {
        if ([string]::IsNullOrWhiteSpace([string]$consumer.id)) { $issues.Add('CONSUMER_ID_MISSING'); continue }
        if ($seen.ContainsKey([string]$consumer.id)) { $issues.Add("CONSUMER_ID_DUPLICATE:$($consumer.id)") }
        $seen[[string]$consumer.id] = $true
        if ($consumer.status -notin @('SUPPORTED','PARTIAL','UNSUPPORTED')) { $issues.Add("STATUS_INVALID:$($consumer.id)") }
        if ([string]$consumer.status -ne 'SUPPORTED' -and @($consumer.gaps).Count -eq 0) { $issues.Add("GAPS_MISSING:$($consumer.id)") }
        # A provider-atomic gap is a deliberate capability boundary, not an untyped TODO.
        # Require a closed status, stable reason code, single owner and reproducible evidence
        # so consumers can fail closed without inferring semantics from prose.
        foreach ($gap in @($consumer.gaps)) {
            if ([string]$gap -notlike 'provider-atomic*') { continue }
            $detail = @($consumer.gapDetails | Where-Object { [string]$_.id -eq [string]$gap })
            if ($detail.Count -ne 1) {
                $issues.Add("PROVIDER_GAP_DETAIL_MISSING:$($consumer.id):$gap")
                continue
            }
            $record = $detail[0]
            if ([string]$record.status -notin @('SUPPORTED','PARTIAL','UNSUPPORTED')) {
                $issues.Add("PROVIDER_GAP_STATUS_INVALID:$($consumer.id):$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.reasonCode)) {
                $issues.Add("PROVIDER_GAP_REASON_MISSING:$($consumer.id):$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.owner)) {
                $issues.Add("PROVIDER_GAP_OWNER_MISSING:$($consumer.id):$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.evidence)) {
                $issues.Add("PROVIDER_GAP_EVIDENCE_MISSING:$($consumer.id):$gap")
            }
        }
        $relative = [string]$consumer.path
        if ([string]::IsNullOrWhiteSpace($relative) -or -not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) {
            $issues.Add("PATH_MISSING:$($consumer.id)")
        }
        if (@($consumer.coverage).Count -eq 0) { $issues.Add("COVERAGE_MISSING:$($consumer.id)") }
    }
    foreach ($id in $requiredIds) {
        if (-not $seen.ContainsKey($id)) { $issues.Add("REQUIRED_CONSUMER_MISSING:$id") }
    }
    $consumerById = @{}
    foreach ($consumer in $consumers) {
        if (-not [string]::IsNullOrWhiteSpace([string]$consumer.id) -and -not $consumerById.ContainsKey([string]$consumer.id)) {
            $consumerById[[string]$consumer.id] = $consumer
        }
    }
    foreach ($id in $p29RequiredIds) {
        if (-not $consumerById.ContainsKey($id)) {
            $issues.Add("P29_CONSUMER_MISSING:$id")
            continue
        }
        $consumer = $consumerById[$id]
        $coverage = @($consumer.coverage | ForEach-Object { [string]$_ })
        foreach ($token in @($p29RequiredCoverage[$id])) {
            if ($coverage -notcontains $token) { $issues.Add("P29_COVERAGE_MISSING:${id}:$token") }
        }
        $gaps = @($consumer.gaps | ForEach-Object { [string]$_ })
        if ([string]$consumer.status -eq 'SUPPORTED' -and $gaps.Count -gt 0) {
            $issues.Add("P29_SUPPORTED_WITH_GAPS:$id")
        }
        $details = @($consumer.gapDetails | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.id) })
        foreach ($gap in $gaps) {
            $detail = @($details | Where-Object { [string]$_.id -eq $gap })
            if ($detail.Count -ne 1) {
                $issues.Add("P29_GAP_DETAIL_MISSING:${id}:$gap")
                continue
            }
            $record = $detail[0]
            if ([string]$record.status -notin @('SUPPORTED','UNSUPPORTED','NOT_RUN')) {
                $issues.Add("P29_GAP_STATUS_INVALID:${id}:$gap")
            }
            if ([string]$record.status -eq 'PARTIAL') {
                $issues.Add("P29_GAP_STATUS_OPEN:${id}:$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.reasonCode) -or [string]$record.reasonCode -notmatch '^[A-Z][A-Z0-9_]*$') {
                $issues.Add("P29_GAP_REASON_INVALID:${id}:$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.owner)) {
                $issues.Add("P29_GAP_OWNER_MISSING:${id}:$gap")
            }
            if ([string]::IsNullOrWhiteSpace([string]$record.evidence)) {
                $issues.Add("P29_GAP_EVIDENCE_MISSING:${id}:$gap")
            }
        }
        foreach ($detail in $details) {
            if ($gaps -notcontains [string]$detail.id) {
                $issues.Add("P29_GAP_DETAIL_ORPHAN:${id}:$([string]$detail.id)")
            }
        }
    }
    foreach ($relative in $requiredArchivePaths) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $relative) -PathType Leaf)) { $issues.Add("REQUIRED_PATH_MISSING:$relative") }
    }
    if ($issues.Count -eq 0) {
        $checks.Add('schema-and-contract')
        $checks.Add('unique-consumer-ids')
        $checks.Add('all-required-consumers')
        $checks.Add('source-paths-exist')
        $checks.Add('partial-statuses-have-gaps')
        $checks.Add('provider-atomic-gaps-have-typed-reason-owner-evidence')
        $checks.Add('p29-input-consumers-have-required-coverage')
        $checks.Add('p29-gaps-have-closed-typed-reason-owner-evidence')
    }
    return New-Result ($issues.Count -eq 0) $issues $checks
}

if ($SelfTest) {
    $sample = [pscustomobject]@{
        schemaVersion = 'input-surface-inventory-v1'
        contractId = 'JUST-PROD-D009-V1'
        statusVocabulary = @('SUPPORTED','PARTIAL','UNSUPPORTED')
        sharedOwners = [pscustomobject]@{ archiveBudget = 'a'; ruleLoader = 'b'; singleFileCommit = 'c' }
        consumers = @([pscustomobject]@{ id = 'sample'; path = 'tools/validate-input-surface-inventory.ps1'; status = 'PARTIAL'; coverage = @('x'); gaps = @('provider-atomic-open'); gapDetails = @() })
    }
    $self = Test-Inventory $sample $repoRoot
    $missingRequired = @($self.issues | Where-Object { $_ -like 'REQUIRED_CONSUMER_MISSING:*' }).Count -gt 0
    $missingProviderDetail = @($self.issues | Where-Object { $_ -like 'PROVIDER_GAP_DETAIL_MISSING:*' }).Count -eq 1
    $p29GenericGapSample = [pscustomobject]@{
        schemaVersion = 'input-surface-inventory-v1'
        contractId = 'JUST-PROD-D009-V1'
        statusVocabulary = @('SUPPORTED','PARTIAL','UNSUPPORTED')
        sharedOwners = [pscustomobject]@{ archiveBudget = 'a'; ruleLoader = 'b'; singleFileCommit = 'c' }
        consumers = @([pscustomobject]@{
            id = 'report.path-and-identity'
            path = 'tools/validate-input-surface-inventory.ps1'
            status = 'PARTIAL'
            coverage = @('path-containment')
            gaps = @('provider-atomic-directory-move', 'recovery-mutation-publish')
            gapDetails = @([pscustomobject]@{
                id = 'provider-atomic-directory-move'
                status = 'UNSUPPORTED'
                reasonCode = 'PROVIDER_PATH_ONLY_SNAPSHOT'
                owner = 'sample'
                evidence = 'sample'
            })
        })
    }
    $p29GenericGap = Test-Inventory $p29GenericGapSample $repoRoot
    $missingP29GenericDetail = @($p29GenericGap.issues | Where-Object { $_ -like 'P29_GAP_DETAIL_MISSING:report.path-and-identity:recovery-mutation-publish' }).Count -eq 1
    # The sample deliberately lacks required consumers; a validator must fail closed.
    $selfResult = [pscustomobject]@{
        schema_version = 1
        valid = ($self.valid -eq $false -and $missingRequired -and $missingProviderDetail -and $missingP29GenericDetail)
        checks = @('missing-required-consumer-rejected', 'untyped-provider-gap-rejected', 'untyped-p29-gap-rejected')
        issues = @()
    }
    if ($Json) { $selfResult | ConvertTo-Json -Depth 8 } else { if ($selfResult.valid) { 'PASS missing-required-consumer-rejected' } else { 'FAIL missing-required-consumer-rejected' } }
    if (-not $selfResult.valid) { exit 1 }
    exit 0
}

if (-not (Test-Path -LiteralPath $InventoryPath -PathType Leaf)) {
    $result = New-Result $false @("INVENTORY_NOT_FOUND:$InventoryPath") @()
} else {
    try {
        $data = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json
    $result = Test-Inventory $data $repoRoot
    } catch {
        $result = New-Result $false @("INVENTORY_PARSE_FAILED:$($_.Exception.GetType().Name)") @()
    }
}
if ($Json) { $result | ConvertTo-Json -Depth 8 } else {
    if ($result.valid) { 'PASS input-surface-inventory' } else { 'FAIL ' + ($result.issues -join ',') }
}
if (-not $result.valid) { exit 1 }
exit 0
