[CmdletBinding()]
param(
    [string] $PlanPath = (Join-Path (Get-Location) 'docs\refactor-todo.md'),
    [switch] $Json,
    [switch] $SelfTest,
    [switch] $RecoveryRehearsal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Read-only structural guard. Product evaluation belongs to acceptance runners.
$ExpectedContractId = 'JUST-PROD-D009-V1'
$MaximumPlanLines = 500
$MaximumPlanBytes = 120KB
$ExpectedGateIds = @(
    'PLAN_INTEGRITY', 'BUILD_REPRODUCIBLE', 'FAST_TESTS', 'ARCHITECTURE',
    'ENTRY_ANCHOR_POLICY', 'GLEIPNER_KERNEL', 'WP8_STATIC', 'WP8_DYNAMIC',
    'DYNAMIC_TRIAGE', 'APACHE_APPLICATION_CHAIN', 'WINDOWS_CONTAINMENT',
    'JDK_MATRIX', 'PERFORMANCE', 'DETERMINISM', 'HOSTILE_INPUT_SAFETY',
    'CLI_OFFLINE_CONTRACT', 'OUTPUT_AND_BASELINE', 'ROBUSTNESS_SOAK',
    'USABILITY', 'RELEASE_SUPPLY_CHAIN', 'DOCS_RELEASE'
)
$ExpectedItemIds = @(
    foreach ($n in 0..14) { "P0.$n" }
    foreach ($phase in 1..2) { foreach ($n in 1..9) { "P$phase.$n" } }
    foreach ($n in 1..10) { "P3.$n" }
    foreach ($n in 1..8) { "P4.$n" }
    foreach ($phase in 5..6) { foreach ($n in 1..11) { "P$phase.$n" } }
    foreach ($n in 1..8) { "P7.$n" }
    foreach ($n in 0..6) { "P8.$n" }
    foreach ($phase in 9..10) { foreach ($n in 1..10) { "P$phase.$n" } }
    foreach ($n in 1..14) { "P11.$n" }
)

function Add-PlanIssue {
    param(
        [System.Collections.Generic.List[object]] $Bag,
        [string] $Code,
        [string] $Message,
        [int] $Line = 0
    )
    $Bag.Add([pscustomobject]@{ code = $Code; message = $Message; line = $Line }) | Out-Null
}

function Read-PlanCursor {
    param([string] $Text, [System.Collections.Generic.List[object]] $Issues)

    $blocks = [regex]::Matches($Text, '(?ms)^```yaml[ \t]*\r?\n(?<body>.*?)^```[ \t]*(?:\r?\n|$)')
    if ($blocks.Count -ne 1) {
        Add-PlanIssue $Issues 'CURSOR_BLOCK_COUNT' "Expected one yaml cursor block; found $($blocks.Count)."
        return @{}
    }

    $cursor = @{}
    $activeList = $null
    $lineNumber = 0
    foreach ($line in [regex]::Split($blocks[0].Groups['body'].Value, '\r?\n')) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^(?<key>[a-z][a-z0-9_]*):\s*(?<value>.*)$') {
            $key = $Matches.key
            if ($cursor.ContainsKey($key)) {
                Add-PlanIssue $Issues 'CURSOR_DUPLICATE_KEY' "Duplicate cursor key '$key'." $lineNumber
                continue
            }
            if ([string]::IsNullOrWhiteSpace($Matches.value)) {
                $cursor[$key] = [System.Collections.Generic.List[string]]::new()
                $activeList = $key
            }
            else {
                $cursor[$key] = $Matches.value.Trim().Trim('"').Trim("'")
                $activeList = $null
            }
        }
        elseif ($null -ne $activeList -and $line -match '^\s+-\s+(?<value>.+)$') {
            $cursor[$activeList].Add($Matches.value.Trim().Trim('"').Trim("'"))
        }
        else {
            Add-PlanIssue $Issues 'CURSOR_SYNTAX' 'Unsupported cursor syntax.' $lineNumber
        }
    }
    return $cursor
}

function Test-EvidencePath {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '^(?:[A-Za-z]:[\\/]|\\\\|/)' -or $Value -match '(^|[\\/])\.\.([\\/]|$)') { return $false }
    return $Value.Replace('\', '/').StartsWith('benchmark/runs', [StringComparison]::Ordinal)
}

function Test-RefactorPlanText {
    param([AllowEmptyString()][string] $Text, [string] $Source = '<memory>')

    $issues = [System.Collections.Generic.List[object]]::new()
    $lines = [regex]::Split($Text, '\r?\n')
    $bytes = [Text.Encoding]::UTF8.GetByteCount($Text)
    if ($lines.Count -gt $MaximumPlanLines) { Add-PlanIssue $issues 'PLAN_TOO_LONG' "Plan has $($lines.Count) lines; limit is $MaximumPlanLines." }
    if ($bytes -gt $MaximumPlanBytes) { Add-PlanIssue $issues 'PLAN_TOO_LARGE' "Plan has $bytes UTF-8 bytes; limit is $MaximumPlanBytes." }
    if ($Text -match '(?m)^##\s+.*Append-only work log\s*$') { Add-PlanIssue $issues 'APPEND_ONLY_LOG_FORBIDDEN' 'Move long logs to benchmark/runs.' }
    if ($Text -match '(?m)^(observed_)?dirty_paths\s*:') { Add-PlanIssue $issues 'DIRTY_PATH_INVENTORY_FORBIDDEN' 'Do not copy git status into the cursor.' }
    if ((@($lines | Where-Object { $_ -match '^```' }).Count % 2) -ne 0) { Add-PlanIssue $issues 'UNBALANCED_FENCES' 'Markdown code fences are unbalanced.' }

    $cursor = Read-PlanCursor $Text $issues
    $requiredKeys = @(
        'plan_schema', 'contract_id', 'state', 'current_phase', 'next_item',
        'active_slice', 'slice_id', 'last_closed_item', 'last_green_gate',
        'last_failed_gate', 'release_acceptance', 'verification_tier',
        'evidence_root', 'last_checkpoint', 'working_tree_policy',
        'next_action', 'pending_checks'
    )
    foreach ($key in $requiredKeys) {
        if (-not $cursor.ContainsKey($key)) { Add-PlanIssue $issues 'CURSOR_REQUIRED_KEY' "Missing cursor key '$key'." }
    }
    if ($cursor.ContainsKey('plan_schema') -and $cursor.plan_schema -ne '3') { Add-PlanIssue $issues 'PLAN_SCHEMA' 'plan_schema must be 3.' }
    if ($cursor.ContainsKey('contract_id') -and $cursor.contract_id -ne $ExpectedContractId) { Add-PlanIssue $issues 'CONTRACT_ID' "contract_id must remain $ExpectedContractId." }
    if ($cursor.ContainsKey('state') -and $cursor.state -notin @('ACTIVE', 'BLOCKED', 'COMPLETE')) { Add-PlanIssue $issues 'CURSOR_STATE' 'Invalid cursor state.' }
    if ($cursor.ContainsKey('verification_tier') -and $cursor.verification_tier -notin @('SLICE', 'BATCH', 'PHASE', 'RELEASE')) { Add-PlanIssue $issues 'VERIFICATION_TIER' 'Invalid verification tier.' }
    $batchKeys = @('batch_id', 'batch_scope', 'batch_task_limit', 'batch_file_limit', 'batch_elapsed_minutes', 'batch_completed_tasks', 'batch_flush')
    if ($cursor.ContainsKey('verification_tier') -and $cursor.verification_tier -eq 'BATCH') {
        foreach ($key in $batchKeys) {
            if (-not $cursor.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$cursor[$key])) { Add-PlanIssue $issues 'BATCH_REQUIRED_KEY' "BATCH cursor requires '$key'." }
        }
        $taskLimit = 0
        $fileLimit = 0
        $elapsedLimit = 0
        $completedTasks = 0
        if ($cursor.ContainsKey('batch_task_limit') -and (-not [int]::TryParse([string]$cursor.batch_task_limit, [ref]$taskLimit) -or $taskLimit -lt 2 -or $taskLimit -gt 5)) { Add-PlanIssue $issues 'BATCH_TASK_LIMIT' 'batch_task_limit must be an integer from 2 through 5.' }
        if ($cursor.ContainsKey('batch_file_limit') -and (-not [int]::TryParse([string]$cursor.batch_file_limit, [ref]$fileLimit) -or $fileLimit -lt 1 -or $fileLimit -gt 5)) { Add-PlanIssue $issues 'BATCH_FILE_LIMIT' 'batch_file_limit must be an integer from 1 through 5.' }
        if ($cursor.ContainsKey('batch_elapsed_minutes') -and (-not [int]::TryParse([string]$cursor.batch_elapsed_minutes, [ref]$elapsedLimit) -or $elapsedLimit -lt 15 -or $elapsedLimit -gt 120)) { Add-PlanIssue $issues 'BATCH_ELAPSED_LIMIT' 'batch_elapsed_minutes must be an integer from 15 through 120.' }
        if ($cursor.ContainsKey('batch_completed_tasks') -and (-not [int]::TryParse([string]$cursor.batch_completed_tasks, [ref]$completedTasks) -or $completedTasks -lt 0 -or ($taskLimit -gt 0 -and $completedTasks -gt $taskLimit))) { Add-PlanIssue $issues 'BATCH_COMPLETED_TASKS' 'batch_completed_tasks must be between zero and batch_task_limit.' }
        if ($cursor.ContainsKey('batch_id') -and $cursor.batch_id -notmatch '^[a-z0-9][a-z0-9-]*$') { Add-PlanIssue $issues 'BATCH_ID' 'batch_id must be a stable lowercase slug.' }
    }
    elseif (@($batchKeys | Where-Object { $cursor.ContainsKey($_) }).Count -gt 0) {
        Add-PlanIssue $issues 'BATCH_FIELDS_UNEXPECTED' 'Remove batch fields when verification_tier is not BATCH.'
    }
    if ($cursor.ContainsKey('release_acceptance') -and $cursor.release_acceptance -notin @('PASS', 'FAIL', 'NOT_RUN', 'INCOMPARABLE')) { Add-PlanIssue $issues 'RELEASE_ACCEPTANCE' 'Invalid release acceptance state.' }
    if ($cursor.ContainsKey('working_tree_policy') -and $cursor.working_tree_policy -ne 'PRESERVE_EXISTING_CHANGES') { Add-PlanIssue $issues 'WORKTREE_POLICY' 'Existing changes must be preserved.' }
    foreach ($key in @('evidence_root', 'last_checkpoint')) {
        if ($cursor.ContainsKey($key) -and -not (Test-EvidencePath $cursor[$key])) { Add-PlanIssue $issues 'EVIDENCE_PATH' "$key must be a relative benchmark/runs path." }
    }
    if ($cursor.ContainsKey('state') -and $cursor.state -eq 'ACTIVE') {
        if ($cursor.ContainsKey('active_slice') -and $cursor.ContainsKey('next_item') -and $cursor.active_slice -ne $cursor.next_item) { Add-PlanIssue $issues 'ACTIVE_SLICE' 'active_slice must equal next_item while ACTIVE.' }
        if ($cursor.ContainsKey('pending_checks')) {
            $count = @($cursor.pending_checks).Count
            if ($count -lt 1 -or $count -gt 5) { Add-PlanIssue $issues 'PENDING_CHECK_COUNT' "ACTIVE cursor must have 1-5 immediate checks; found $count." }
        }
    }
    if ($cursor.ContainsKey('state') -and $cursor.state -eq 'BLOCKED' -and (-not $cursor.ContainsKey('unblock_condition') -or [string]::IsNullOrWhiteSpace([string]$cursor.unblock_condition))) {
        Add-PlanIssue $issues 'UNBLOCK_CONDITION' 'BLOCKED state requires unblock_condition.'
    }

    $matches = [regex]::Matches($Text, '(?m)^- \[(?<mark>[ xX])\] (?<id>P\d+\.\d+)\b')
    $items = @($matches | ForEach-Object { [pscustomobject]@{ id = $_.Groups['id'].Value; checked = ($_.Groups['mark'].Value -match '[xX]') } })
    if ($items.Count -ne $ExpectedItemIds.Count) { Add-PlanIssue $issues 'ITEM_COUNT' "Expected $($ExpectedItemIds.Count) P-items; found $($items.Count)." }
    for ($i = 0; $i -lt [Math]::Min($items.Count, $ExpectedItemIds.Count); $i++) {
        if ($items[$i].id -ne $ExpectedItemIds[$i]) { Add-PlanIssue $issues 'ITEM_SEQUENCE' "Expected $($ExpectedItemIds[$i]); found $($items[$i].id)."; break }
    }
    $duplicates = @($items | Group-Object id | Where-Object Count -gt 1)
    if ($duplicates.Count -gt 0) { Add-PlanIssue $issues 'ITEM_DUPLICATE' "Duplicate P-items: $(@($duplicates.Name) -join ', ')." }
    $firstOpenIndex = -1
    for ($i = 0; $i -lt $items.Count; $i++) { if (-not $items[$i].checked) { $firstOpenIndex = $i; break } }
    $firstOpen = if ($firstOpenIndex -ge 0) { $items[$firstOpenIndex].id } else { 'NONE' }
    if ($cursor.ContainsKey('next_item') -and $cursor.next_item -ne $firstOpen) { Add-PlanIssue $issues 'CURSOR_NEXT_ITEM' "next_item '$($cursor.next_item)' must be '$firstOpen'." }
    if ($firstOpen -match '^P(?<phase>\d+)\.' -and $cursor.ContainsKey('current_phase') -and $cursor.current_phase -ne "Phase $($Matches.phase)") { Add-PlanIssue $issues 'CURSOR_PHASE' 'current_phase does not match the first open item.' }
    if ($firstOpenIndex -gt 0 -and $cursor.ContainsKey('last_closed_item') -and $cursor.last_closed_item -ne $items[$firstOpenIndex - 1].id) { Add-PlanIssue $issues 'LAST_CLOSED_ITEM' 'last_closed_item does not precede next_item.' }
    if ($firstOpenIndex -ge 0 -and @($items[$firstOpenIndex..($items.Count - 1)] | Where-Object checked).Count -gt 0) { Add-PlanIssue $issues 'ITEM_GAP' 'Checked P-item appears after the first open item.' }
    if ($cursor.ContainsKey('state') -and $cursor.state -eq 'COMPLETE' -and ($firstOpen -ne 'NONE' -or $cursor.release_acceptance -ne 'PASS')) { Add-PlanIssue $issues 'COMPLETE_STATE' 'COMPLETE requires no open P-items and release_acceptance PASS.' }

    $gateSection = [regex]::Match($Text, '(?ms)^## 7\. 固定发布门禁\s*\r?\n(?<body>.*?)(?=^##\s|\z)')
    $gateIds = if ($gateSection.Success) { @([regex]::Matches($gateSection.Groups['body'].Value, '(?m)^\| `(?<id>[A-Z][A-Z0-9_]+)` \|') | ForEach-Object { $_.Groups['id'].Value }) } else { @() }
    if (-not $gateSection.Success) { Add-PlanIssue $issues 'GATE_SECTION' 'Missing fixed release gate section.' }
    if ($gateIds.Count -ne $ExpectedGateIds.Count) { Add-PlanIssue $issues 'GATE_COUNT' "Expected $($ExpectedGateIds.Count) gates; found $($gateIds.Count)." }
    for ($i = 0; $i -lt [Math]::Min($gateIds.Count, $ExpectedGateIds.Count); $i++) {
        if ($gateIds[$i] -ne $ExpectedGateIds[$i]) { Add-PlanIssue $issues 'GATE_SEQUENCE' "Expected $($ExpectedGateIds[$i]); found $($gateIds[$i])."; break }
    }

    $requiredText = [ordered]@{
        D005_SUPERSESSION = 'D-005（SUPERSEDED_BY_D-007）'
        D006_SUPERSESSION = 'D-006（SUPERSEDED_IN_PART_BY_D-010）'
        D009_CONTRACT = 'D-009（2026-09-08）'
        D010_POLICY = 'D-010（2026-09-11）'
        D011_BATCH_POLICY = 'D-011（2026-09-11）'
        APPLICATION_CHAIN_CONTRACT = 'ApplicationAnchoredChain'
        ENTRY_JOIN_CONTRACT = 'EntryChainJoinEvidence'
        BRIDGE_CONTRACT = 'BridgeEvidence'
        VERIFY_AUTO_CONTRACT = 'verify=auto'
        NO_VERIFY_CONTRACT = '--no-verify'
        JOB_OBJECT_CONTRACT = 'Job Object'
        KERNEL_CONTRACT = 'gadget-kernel'
    }
    foreach ($entry in $requiredText.GetEnumerator()) {
        if (-not $Text.Contains([string]$entry.Value)) { Add-PlanIssue $issues ([string]$entry.Key) "Missing required text '$($entry.Value)'." }
    }
    $checkpointCount = [regex]::Matches($Text, '(?m)^### checkpoint\s+').Count
    if ($checkpointCount -ne 2) { Add-PlanIssue $issues 'CHECKPOINT_COUNT' "Expected two compact checkpoints; found $checkpointCount." }

    $checkedCount = @($items | Where-Object checked).Count
    $openCount = $items.Count - $checkedCount
    return [pscustomobject]@{
        schema_version = 3; valid = ($issues.Count -eq 0); source = $Source
        contract_id = if ($cursor.ContainsKey('contract_id')) { $cursor.contract_id } else { $null }
        state = if ($cursor.ContainsKey('state')) { $cursor.state } else { $null }
        current_phase = if ($cursor.ContainsKey('current_phase')) { $cursor.current_phase } else { $null }
        next_item = if ($cursor.ContainsKey('next_item')) { $cursor.next_item } else { $null }
        verification_tier = if ($cursor.ContainsKey('verification_tier')) { $cursor.verification_tier } else { $null }
        batch_id = if ($cursor.ContainsKey('batch_id')) { $cursor.batch_id } else { $null }
        batch_completed_tasks = if ($cursor.ContainsKey('batch_completed_tasks')) { $cursor.batch_completed_tasks } else { $null }
        line_count = $lines.Count; utf8_bytes = $bytes
        item_count = $items.Count; checked_item_count = $checkedCount; unchecked_item_count = $openCount
        # Compatibility aliases used by run-acceptance.ps1.
        phase_item_count = $items.Count; checked_phase_items = $checkedCount; unchecked_phase_items = $openCount
        fixed_gate_count = $gateIds.Count; checkpoint_count = $checkpointCount; issues = @($issues)
    }
}

function Replace-First {
    param([string] $Text, [string] $Pattern, [AllowEmptyString()][string] $Replacement)
    return ([regex]::new($Pattern, [Text.RegularExpressions.RegexOptions]::Multiline)).Replace($Text, $Replacement, 1)
}

function Invoke-PlanSelfTest {
    param([string] $Text)
    $cases = [System.Collections.Generic.List[object]]::new()
    $current = Test-RefactorPlanText $Text 'selftest/current'
    $cases.Add([pscustomobject]@{ name = 'current-plan'; passed = $current.valid; expected = 'valid'; observed = if ($current.valid) { 'valid' } else { @($current.issues.code) -join ',' } })
    $mutations = @(
        @{ name = 'bad-schema'; text = (Replace-First $Text '^plan_schema: 3$' 'plan_schema: 2'); code = 'PLAN_SCHEMA' },
        @{ name = 'bad-contract'; text = (Replace-First $Text '^contract_id: JUST-PROD-D009-V1$' 'contract_id: BROKEN'); code = 'CONTRACT_ID' },
        @{ name = 'cursor-drift'; text = (Replace-First $Text '^next_item: P3\.1$' 'next_item: P3.2'); code = 'CURSOR_NEXT_ITEM' },
        @{ name = 'missing-gate'; text = (Replace-First $Text '^\| `PLAN_INTEGRITY` \|.*\r?\n' ''); code = 'GATE_COUNT' },
        @{ name = 'missing-d010'; text = $Text.Replace('D-010', 'D-01X'); code = 'D010_POLICY' },
        @{ name = 'missing-d011'; text = $Text.Replace('D-011', 'D-01Y'); code = 'D011_BATCH_POLICY' },
        @{ name = 'bad-batch-limit'; text = (Replace-First $Text '^batch_task_limit: 3$' 'batch_task_limit: 6'); code = 'BATCH_TASK_LIMIT' },
        @{ name = 'missing-batch-field'; text = (Replace-First $Text '^batch_scope:.*\r?\n' ''); code = 'BATCH_REQUIRED_KEY' },
        @{ name = 'stale-batch-fields'; text = (Replace-First $Text '^verification_tier: BATCH$' 'verification_tier: SLICE'); code = 'BATCH_FIELDS_UNEXPECTED' },
        @{ name = 'third-checkpoint'; text = $Text + "`n### checkpoint extra — self-test`n"; code = 'CHECKPOINT_COUNT' },
        @{ name = 'append-only-log'; text = $Text + "`n## 17. Append-only work log`n"; code = 'APPEND_ONLY_LOG_FORBIDDEN' },
        @{ name = 'oversized-plan'; text = $Text + (("`n<!-- self-test padding -->") * 160); code = 'PLAN_TOO_LONG' }
    )
    foreach ($mutation in $mutations) {
        $result = Test-RefactorPlanText $mutation.text ("selftest/" + $mutation.name)
        $codes = @($result.issues.code)
        $passed = (-not $result.valid) -and ($codes -contains $mutation.code)
        $cases.Add([pscustomobject]@{ name = $mutation.name; passed = $passed; expected = $mutation.code; observed = $codes -join ',' })
    }
    $failed = @($cases | Where-Object { -not $_.passed })
    return [pscustomobject]@{ schema_version = 3; mode = 'self-test'; valid = ($failed.Count -eq 0); case_count = $cases.Count; failed_count = $failed.Count; cases = @($cases) }
}

function Invoke-RecoveryRehearsal {
    param([string] $Text, [string] $ResolvedPath, [string] $HashBefore)
    $first = Test-RefactorPlanText $Text $ResolvedPath
    $second = Test-RefactorPlanText ([IO.File]::ReadAllText($ResolvedPath)) $ResolvedPath
    $hashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $ResolvedPath).Hash
    $valid = $first.valid -and $second.valid -and $first.contract_id -eq $second.contract_id -and $first.current_phase -eq $second.current_phase -and $first.next_item -eq $second.next_item -and $HashBefore -eq $hashAfter
    return [pscustomobject]@{
        schema_version = 3; mode = 'recovery-rehearsal'; valid = $valid; read_only = ($HashBefore -eq $hashAfter)
        contract_id = $second.contract_id; recovered_phase = $second.current_phase; recovered_next_item = $second.next_item
        recovered_verification_tier = $second.verification_tier; recovered_batch_id = $second.batch_id
        hash_before = $HashBefore; hash_after = $hashAfter; issues = @($second.issues)
    }
}

if (-not (Test-Path -LiteralPath $PlanPath -PathType Leaf)) { throw "Plan file not found: $PlanPath" }
$resolvedPath = (Resolve-Path -LiteralPath $PlanPath).Path
$hashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedPath).Hash
$content = [IO.File]::ReadAllText($resolvedPath)
$result = if ($SelfTest) {
    Invoke-PlanSelfTest $content
}
elseif ($RecoveryRehearsal) {
    Invoke-RecoveryRehearsal $content $resolvedPath $hashBefore
}
else {
    Test-RefactorPlanText $content $resolvedPath
}

if ($Json) { $result | ConvertTo-Json -Depth 8 }
else {
    Write-Output ($(if ($result.valid) { 'PASS: refactor plan contract is valid.' } else { 'FAIL: refactor plan contract is invalid.' }))
    $result | Format-List *
}
if (-not $result.valid) { exit 1 }
