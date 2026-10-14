#Requires -Version 7.0

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Load the actual planner without Azure reads or template generation
$migrationPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'New-WafMigrationTemplate.ps1'
$text = Get-Content -LiteralPath $migrationPath -Raw
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($migrationPath, [ref] $tokens, [ref] $errors)
if ($errors.Count) { throw ($errors.Message -join "`n") }
foreach ($definition in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true)) {
    Invoke-Expression $definition.Extent.Text
}
foreach ($name in 'apiVersion', 'resourceType', 'drsPath', 'supersededRuleIds',
    'actionType', 'stateType', 'wafShapes') {
    $assignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq $name
    }, $true)
    if ($null -eq $assignment) { throw "Missing runtime configuration $name." }
    Invoke-Expression $assignment.Extent.Text
}
$start = $text.IndexOf('#region Execution - baseline validation and decision planning', [StringComparison]::Ordinal)
$end = $text.IndexOf('# Choices annotate the report first;', [StringComparison]::Ordinal)
if ($start -lt 0 -or $end -le $start) { throw 'Cannot locate decision planner.' }
$planner = $text.Substring($start, $end - $start)
$drsDocumentation = Get-DrsDocumentation
$drsCatalog = Get-EmbeddedDrsCatalog
$catalogIndexes = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
#endregion

#region Regression fixtures and assertions
function Assert-Equal {
    <#
    .SYNOPSIS
    Requires exact scalar equality.
    .DESCRIPTION
    Throws a named regression failure when actual and expected values differ.
    #>
    param($Actual, $Expected, [string] $Message)
    if ($Actual -cne $Expected) { throw "$Message`: expected [$Expected], got [$Actual]." }
}

function New-ReportPolicy {
    <#
    .SYNOPSIS
    Creates an isolated Bot Manager policy fixture.
    .DESCRIPTION
    Uses native version defaults without overrides, custom rules or DRS.
    #>
    param([string] $Version)
    @{
        type = $resourceType; name = 'ReportFixture'; location = 'Global'
        sku = @{ name = 'Premium_AzureFrontDoor' }
        tags = @{}
        properties = @{
            policySettings = @{ enabledState = 'Enabled'; mode = 'Prevention' }
            customRules = @{ rules = @() }
            managedRules = @{
                managedRuleSets = @(@{
                    ruleSetType = 'Microsoft_BotManagerRuleSet'
                    ruleSetVersion = $Version; ruleGroupOverrides = @()
                })
            }
        }
    }
}

foreach ($versions in @(@('1.1', '1.0'), @('1.0', '1.1'))) {
    $sourceOriginalDrsVersion = $null
    $sourcePolicyName = 'ReportFixture'
    $hasMasterPolicy = $true
    $ReportOnly = $true
    $keepSourceRanges = ConvertTo-DecisionRanges @() 'KeepSource'
    $keepTargetRanges = ConvertTo-DecisionRanges @() 'KeepTarget'
    $source = ConvertTo-PolicyConfiguration (New-ReportPolicy $versions[0]) 'Source' -AllowMissingDefaultRuleSet
    $target = ConvertTo-PolicyConfiguration (New-ReportPolicy $versions[1]) 'Master' -AllowMissingDefaultRuleSet
    $source.tags = @{ Deployed_by = 'private-source-value'; Source = 'private-origin-value' }
    $target.tags = @{ Deployed_by = 'private-target-value' }
    $decisions = [System.Collections.Generic.List[object]]::new()
    $explicitSourceCustomRuleNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    Invoke-Expression $planner

    $tag = @($decisions | Where-Object Path -eq 'tags.Deployed_by')[0]
    $overview = Get-DecisionOverview $tag
    Assert-Equal $overview.Item 'Tag: Deployed_by' 'Tag key is explicitly labeled and preserved'
    Assert-Equal $overview.Source 'Existing value' 'Present source tag uses value terminology'
    Assert-Equal $overview.Target 'Existing value' 'Present target tag uses value terminology'
    $tag = @($decisions | Where-Object Path -eq 'tags.Source')[0]
    Assert-Equal (Get-DecisionOverview $tag).Target '---' 'Absent target tag uses the absence marker'
    # Target-only tags retain existing inheritance; exercise the formatter independently.
    $tag.SourcePresent = $false
    $tag.TargetPresent = $true
    Assert-Equal (Get-DecisionOverview $tag).Source '---' 'Absent source tag uses the absence marker'
    Assert-Equal (Get-DecisionOverview $tag).Target 'Existing value' 'Present target-only tag uses value terminology'

    $botItems = @($decisions | Where-Object RuleSetType -eq 'Microsoft_BotManagerRuleSet')
    foreach ($item in $botItems) { $item.CompatibilityIssues = Get-CandidateCompatibilityIssues $item }
    Assert-Equal $botItems.Count 7 'Both migration directions review six memberships and one definition change'
    foreach ($id in 'Bot100300', 'Bot200300', 'Bot200400', 'Bot200500', 'Bot200600', 'Bot200700') {
        $item = @($botItems | Where-Object RuleId -eq $id)[0]
        $group = if ($id -eq 'Bot100300') { 'BadBots' } else { 'GoodBots' }
        $description = (Get-CatalogIndex 'Microsoft_BotManagerRuleSet/1.1').Rules[$group][$id]['description']
        $absentSide = if ($versions[0] -eq '1.1') { 'target' } else { 'source' }
        Assert-Equal $item.RuleDescription "$description (absent from $absentSide v1.0)" 'Native bot description identifies version absence'
        $overview = Get-DecisionOverview $item
        Assert-Equal $overview.Name $item.RuleDescription 'Console name retains version-absence explanation'
        Assert-Equal $overview.$absentSide '---' 'Version-absent bot rule has no effective action'
        if ($absentSide -eq 'target') {
            Assert-Equal ($item.SourceValue.Count -gt 0) $false 'Downgrade cannot invent a source-copy operation'
            $issues = Get-CandidateCompatibilityIssues $item
            Assert-Equal $issues.Count 1 'Downgrade remains explicitly blocked'
            Assert-Equal ($issues[0].Contains('but not in target v1.0')) $true 'Warning identifies version incompatibility rather than missing metadata'
        }
    }
    $item = @($botItems | Where-Object RuleId -eq 'Bot200200')[0]
    $sourceDescription = (Get-CatalogIndex "Microsoft_BotManagerRuleSet/$($versions[0])").Rules['GoodBots']['Bot200200']['description']
    $targetDescription = (Get-CatalogIndex "Microsoft_BotManagerRuleSet/$($versions[1])").Rules['GoodBots']['Bot200200']['description']
    Assert-Equal $item.RuleDescription "$sourceDescription (source v$($versions[0])) -> $targetDescription (target v$($versions[1]))" 'Changed same-ID bot definition shows both native meanings'
    Assert-Equal (Get-DecisionOverview $item).Name $item.RuleDescription 'Console name retains both version-specific definitions'
    $report = @(Write-DecisionSummary $decisions 'Policy settings and tags' 180 3>&1 6>&1) -join "`n"
    Assert-Equal ($report.Contains('private-')) $false 'Report does not expose tag contents'

    if ($versions[0] -eq '1.1') {
        foreach ($width in 40, 90, 180) {
            $records = @(Write-DecisionSummary $botItems 'Bot protection' $width 3>&1 6>&1)
            $warningIndexes = @(
                for ($index = 0; $index -lt $records.Count; $index++) {
                    if ($records[$index] -is [System.Management.Automation.WarningRecord]) { $index }
                }
            )
            Assert-Equal $warningIndexes.Count 6 "Each removed bot rule has exactly one inline warning at width $width"
            foreach ($index in $warningIndexes) {
                Assert-Equal ($records[$index - 1] -is [System.Management.Automation.InformationRecord]) $true 'Warning immediately follows its rendered row'
                $match = [regex]::Match($records[$index].Message, '^Row (?<id>\d+):')
                $warningItem = @($botItems | Where-Object Id -eq ([int] $match.Groups['id'].Value))[0]
                $priorText = [string] $records[$index - 1]
                $rowIdPattern = "(?m)^\s*(?:Id\s*:\s*)?$($warningItem.Id)\s"
                Assert-Equal ($priorText -match $rowIdPattern) $true 'Immediately preceding row has the matching warning row ID'
            }
        }
        $custom = [pscustomobject]@{
            Id = 100; Path = 'properties.customRules.rules[PriorityFixture]'
            Scope = "Custom rule 'PriorityFixture'"; RuleSetType = ''; RuleDescription = ''
            IdentityValue = 'PriorityFixture'; DecisionKind = 'SourceCandidate'; Key = 'rules'
            SourcePresent = $true; TargetPresent = $true
            SourceValue = @{ priority = 1; ruleType = 'MatchRule'; action = 'Block' }
            TargetValue = @{ priority = 2; ruleType = 'MatchRule'; action = 'Log' }
            Choice = 'Pending'; CompatibilityIssues = @('Test compatibility failure')
            PriorityConflicts = @('OccupiedFixture'); SourcePriority = 1
        }
        foreach ($choice in 'Pending', 'KeepSource', 'KeepTarget') {
            $custom.Choice = $choice
            $overview = Get-DecisionOverview $custom
            Assert-Equal $overview.SourcePriority '1' 'Source priority is shown without a misleading transition arrow'
            Assert-Equal $overview.TargetPriority '2' 'Master priority is a separate input value'
            Assert-Equal $overview.SelectedPriority ($(switch ($choice) { KeepSource { '1' }; KeepTarget { '2' }; default { 'Pending' } })) 'Selected priority follows the actual choice'
            foreach ($width in 40, 90, 180) {
                $records = @(Write-DecisionSummary @($custom) 'Custom rules' $width 3>&1 6>&1)
                $warnings = @($records | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
                Assert-Equal $warnings.Count ($(if ($choice -eq 'KeepTarget') { 1 } else { 2 })) 'Priority warnings retain choice-based visibility across responsive layouts'
            }
        }
        $custom.SourceValue = @{}
        $custom.TargetValue = @{}
        $overview = Get-DecisionOverview $custom
        Assert-Equal $overview.SourcePriority '---' 'Unspecified source custom priority uses the common marker'
        Assert-Equal $overview.TargetPriority '---' 'Unspecified master custom priority uses the common marker'
        Assert-Equal $overview.Type '---' 'Unspecified custom rule type uses the common marker'
        Assert-Equal $overview.Source 'Enabled / ---' 'Unspecified source custom action uses the common marker'
        Assert-Equal $overview.Target 'Enabled / ---' 'Unspecified target custom action uses the common marker'
        $records = @(Write-DecisionTable $botItems 3>&1 6>&1)
        Assert-Equal @($records | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count 6 'Full report does not repeat inline warnings at the end'
    }
}

#region Custom priority planning and resolution
$target = ConvertTo-PolicyConfiguration (New-ReportPolicy '1.1') 'Priority master' -AllowMissingDefaultRuleSet
$masterShared = @{ name = 'ZShared'; priority = 20; ruleType = 'MatchRule'; action = 'Log' }
$sourceShared = @{ name = 'ZShared'; priority = 100; ruleType = 'MatchRule'; action = 'Block' }
$incoming = @{ name = 'EarlyIncoming'; priority = 20; ruleType = 'MatchRule'; action = 'Block' }
$retained = @{ name = 'Retained'; priority = 30; ruleType = 'MatchRule'; action = 'Block' }
$target.properties.customRules.rules = @($masterShared, $retained)
$decisions = [System.Collections.Generic.List[object]]::new()
Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[EarlyIncoming]' `
    $false $null $true $incoming 'name' 'EarlyIncoming'
$incomingDecision = $decisions[0]
$incomingDecision.Choice = 'KeepSource'
Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[ZShared]' `
    $true $masterShared $true $sourceShared 'name' 'ZShared'
$sharedDecision = $decisions[1]
$sharedDecision.Choice = 'KeepSource'
Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[Retained]' `
    $true $retained $false $null 'name' 'Retained' 'TargetCustomRule'
$retainedDecision = $decisions[2]
$retainedDecision.Choice = 'KeepTarget'

# Known source choices free master slots and reserve priorities even before mutation.
Assert-Equal (Get-CustomPriorityConflicts $incoming).Count 0 'A future source replacement frees its old master priority'
Assert-Equal ((Get-CustomPriorityConflicts @{ name = 'Probe'; priority = 100 }) -join ',') 'ZShared' 'A future source priority is reserved'
Assert-Equal ((Get-CustomPriorityConflicts @{ name = 'Probe'; priority = 30 }) -join ',') 'Retained' 'Retained master-only rules still conflict'
$sharedDecision.Choice = 'Pending'
Assert-Equal ((Get-CustomPriorityConflicts $incoming) -join ',') 'ZShared' 'Pending choices do not prematurely free master slots'
$sharedDecision.Choice = 'KeepTarget'
Assert-Equal ((Get-CustomPriorityConflicts $incoming) -join ',') 'ZShared' 'An explicit master choice keeps its priority occupied'
$sharedDecision.Choice = 'KeepSource'
$retainedDecision.Choice = 'KeepSource'
Assert-Equal (Get-CustomPriorityConflicts @{ name = 'Probe'; priority = 30 }).Count 0 'A removed target-only rule releases its priority'
$retainedDecision.Choice = 'KeepTarget'

$script:priorityAnswers = [System.Collections.Generic.Queue[string]]::new()
function Read-Host {
    <#
    .SYNOPSIS
    Supplies bounded answers for custom-priority regressions.
    .DESCRIPTION
    Throws if priority resolution prompts when no test answer was scheduled.
    #>
    param([string] $Prompt)
    if (-not $script:priorityAnswers.Count) { throw "Unexpected priority prompt: $Prompt" }
    $script:priorityAnswers.Dequeue()
}
try {
    Resolve-CustomPriority $incomingDecision
    Assert-Equal $incomingDecision.ResolvedPriority $null 'Freed master slots require neither a prompt nor a fictitious priority resolution'
    Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[Conflicting]' `
        $false $null $true @{ name = 'Conflicting'; priority = 30; ruleType = 'MatchRule'; action = 'Block' } 'name' 'Conflicting'
    $conflictingDecision = $decisions[3]
    $conflictingDecision.Choice = 'KeepSource'
    $script:priorityAnswers.Enqueue('100')
    $script:priorityAnswers.Enqueue('21')
    Resolve-CustomPriority $conflictingDecision 3>$null 6>$null
    Assert-Equal $script:priorityAnswers.Count 0 'Resolution rejects a priority reserved by a future source choice'
    Assert-Equal $conflictingDecision.SourcePriority 30 'Resolution retains the original source priority for comparison'
    Assert-Equal $conflictingDecision.ResolvedPriority 21 'Only the conflicting source rule receives the approved new priority'
    $overview = Get-DecisionOverview $conflictingDecision
    Assert-Equal $overview.SourcePriority '30' 'Post-resolution display retains the original input priority'
    Assert-Equal $overview.SelectedPriority '21' 'Post-resolution display shows the actual chosen priority'
    foreach ($decision in @($incomingDecision, $conflictingDecision, $sharedDecision)) {
        Set-SourceDecision $decision
    }
    Assert-Equal @($target.properties.customRules.rules.priority | Sort-Object -Unique).Count 4 'The selected custom-rule union has unique priorities'
    Assert-Equal $retained.priority 30 'Priority resolution never renumbers retained master rules'

    # Accepting a suggestion produces a resolution panel, not a second warning about the same row.
    Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[Suggested]' `
        $false $null $true @{ name = 'Suggested'; priority = 30; ruleType = 'MatchRule'; action = 'Block' } 'name' 'Suggested'
    $suggestedDecision = $decisions[4]
    $suggestedDecision.Choice = 'KeepSource'
    $script:priorityAnswers.Enqueue('')
    $resolutionRecords = @(Resolve-CustomPriority $suggestedDecision 3>&1 6>&1)
    Assert-Equal @($resolutionRecords | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count 0 'A valid priority fix does not repeat the comparison warning'
    Assert-Equal $suggestedDecision.ResolvedPriority 31 'Enter explicitly accepts the next available priority after the source'
    $resolutionText = ($resolutionRecords | ForEach-Object { [string] $_ }) -join "`n"
    Assert-Equal ($resolutionText -match 'Source priority 30 is occupied by: Retained') $true 'The panel identifies the exact priority owner'
    Assert-Equal ($resolutionText -match 'Suggested priority: 31') $true 'The panel explains its proposed new priority'
    $confirmation = @(Write-DecisionSelection $suggestedDecision 6>&1) -join "`n"
    Assert-Equal ($confirmation -match "'Suggested' priority 31 \(source was 30\)") $true 'Confirmation distinguishes the changed priority from the original input'
    Set-SourceDecision $suggestedDecision

    # Invalid answers distinguish bad numbers from occupied priorities, and Q preserves the candidate.
    Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[Cancelled]' `
        $false $null $true @{ name = 'Cancelled'; priority = 30; ruleType = 'MatchRule'; action = 'Block' } 'name' 'Cancelled'
    $cancelledDecision = $decisions[5]
    $cancelledDecision.Choice = 'KeepSource'
    foreach ($answer in 'invalid', '0', '1001', '100', 'Q') { $script:priorityAnswers.Enqueue($answer) }
    $cancelRecords = [System.Collections.Generic.List[object]]::new()
    $cancelled = $false
    try {
        Resolve-CustomPriority $cancelledDecision 3>&1 6>&1 | ForEach-Object { $cancelRecords.Add($_) }
    } catch {
        if ($_.Exception.Message -cne 'Migration cancelled. No ARM file was written.') { throw }
        $cancelled = $true
    }
    Assert-Equal $cancelled $true 'Q explicitly cancels a priority fix'
    Assert-Equal $cancelledDecision.SourceValue.priority 30 'Rejected answers and cancellation never mutate the candidate'
    Assert-Equal $cancelledDecision.ResolvedPriority $null 'Cancelled priority changes are not recorded as accepted'
    $answerWarnings = @($cancelRecords | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
    Assert-Equal $answerWarnings.Count 4 'Each rejected input emits exactly one distinct warning'
    Assert-Equal @($answerWarnings | Where-Object Message -Like '*not an integer from 1-1000*').Count 3 'Syntax and out-of-range answers have specific diagnostics'
    Assert-Equal ($answerWarnings[3].Message -match 'Priority 100 is occupied by ZShared') $true 'Occupied input identifies the reserved rule'
    $cancelledDecision.Choice = 'KeepTarget'

    # Suggestions wrap at the service limit and skip slots reserved by retained rules.
    $limitRule = @{ name = 'AtLimit'; priority = 1000; ruleType = 'MatchRule'; action = 'Block' }
    $firstRule = @{ name = 'AtFirst'; priority = 1; ruleType = 'MatchRule'; action = 'Block' }
    $target.properties.customRules.rules += @($limitRule, $firstRule)
    Add-Decision $target.properties.customRules 'rules' 'properties.customRules.rules[Wrapped]' `
        $false $null $true @{ name = 'Wrapped'; priority = 1000; ruleType = 'MatchRule'; action = 'Block' } 'name' 'Wrapped'
    $wrappedDecision = $decisions[6]
    $wrappedDecision.Choice = 'KeepSource'
    $script:priorityAnswers.Enqueue('')
    Resolve-CustomPriority $wrappedDecision 3>$null 6>$null
    Assert-Equal $wrappedDecision.ResolvedPriority 2 'Suggestion wraps from 1000 and skips occupied priority 1'
    Assert-Equal $script:priorityAnswers.Count 0 'Every scheduled priority answer was consumed'

    # Exhausted slots must fail explicitly before prompting or mutating a candidate.
    $savedRules = $target.properties.customRules.rules
    try {
        $target.properties.customRules.rules = @(
            foreach ($priority in 1..1000) { @{ name = "Reserved_$priority"; priority = $priority } }
        )
        $exhausted = $false
        try {
            Resolve-CustomPriority $wrappedDecision
        } catch {
            if ($_.Exception.Message -notlike 'No unused priority from 1-1000 is available*') { throw }
            $exhausted = $true
        }
        Assert-Equal $exhausted $true 'No available priority is an explicit error, not an impossible prompt'
        Assert-Equal $wrappedDecision.SourceValue.priority 2 'An exhausted range does not change the candidate'
    } finally {
        $target.properties.customRules.rules = $savedRules
    }
} finally {
    Remove-Item -LiteralPath Function:\Read-Host
}
Write-Host 'PASS: distinct input/selected priorities, choice-aware collisions, freed slots and future-priority reservations'
#endregion

$unspecifiedPolicy = New-ReportPolicy '1.1'
$null = $unspecifiedPolicy.properties.Remove('policySettings')
$configuration = ConvertTo-PolicyConfiguration $unspecifiedPolicy 'Unspecified fixture' -AllowMissingDefaultRuleSet
$rule = (Get-DrsEffectiveRules $configuration '1.1' 'Microsoft_BotManagerRuleSet')['Bot100100']
Assert-Equal $rule.PolicyState '---' 'Unspecified policy state uses the common marker'
Assert-Equal $rule.PolicyMode '---' 'Unspecified policy mode uses the common marker'
Assert-Equal $rule.RuleSetAction '---' 'Unspecified Bot Manager scope action uses the common marker'
Assert-Equal $rule.State 'Enabled' 'Unspecified policy metadata does not disable native rules'
Write-Host 'PASS: tag labels/privacy/absence, bidirectional bot metadata, and inline warnings across responsive layouts'
#endregion

#region Front Door exclusion selector semantics
foreach ($variable in 'RequestHeaderNames', 'RequestCookieNames', 'QueryStringArgNames',
    'RequestBodyPostArgNames', 'RequestBodyJsonArgNames') {
    foreach ($operator in 'Equals', 'Contains', 'StartsWith', 'EndsWith') {
        $left = @{ matchVariable = $variable; selectorMatchOperator = $operator; selector = 'MixedCase' }
        $right = Copy-JsonValue $left
        $right.selector = 'mixedcase'
        $caseInsensitive = $variable -cin 'RequestHeaderNames', 'RequestCookieNames'
        Assert-Equal (Test-JsonEqual $left $right 'exclusion') $caseInsensitive "$variable/$operator uses native selector case semantics"
        Assert-Equal (Test-JsonEqual @($left) @($right) 'exclusions') $caseInsensitive "$variable/$operator uses the same semantics for exclusion arrays"
        Assert-Equal (Test-JsonEqual @{ exclusions = @($left) } @{ exclusions = @($right) }) $caseInsensitive "$variable/$operator uses the same semantics in nested configuration"
        Assert-Equal $left.selector 'MixedCase' 'Comparison preserves the source selector spelling'
        Assert-Equal $right.selector 'mixedcase' 'Comparison preserves the target selector spelling'
        Assert-Equal (Test-JsonEqual @($left, $left) @($right) 'exclusions') $false 'Selector canonicalization does not collapse duplicate occurrences'
    }
}

foreach ($scope in 'Rule set', 'Rule group', 'Individual rule') {
    $sourceOriginalDrsVersion = '2.2'
    $sourcePolicy = New-ReportPolicy '1.1'
    $sourceSet = @{
        ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'; ruleSetAction = 'Block'
        ruleGroupOverrides = @()
    }
    $exclusion = @{ matchVariable = 'RequestHeaderNames'; selectorMatchOperator = 'Equals'; selector = 'X-Token' }
    switch ($scope) {
        'Rule set' { $sourceSet.exclusions = @($exclusion) }
        'Rule group' { $sourceSet.ruleGroupOverrides = @(@{ ruleGroupName = 'SQLI'; exclusions = @($exclusion); rules = @() }) }
        'Individual rule' {
            $sourceSet.ruleGroupOverrides = @(@{
                ruleGroupName = 'SQLI'; rules = @(@{ ruleId = '942100'; exclusions = @($exclusion) })
            })
        }
    }
    $sourcePolicy.properties.managedRules.managedRuleSets = @($sourceSet)
    $source = ConvertTo-PolicyConfiguration $sourcePolicy 'Source' -AllowMissingDefaultRuleSet
    $target = Copy-JsonValue $source
    $targetEntries = Get-DrsExclusionEntries $target
    $targetEntries[0].Exclusion.selector = 'x-token'
    $decisions = [System.Collections.Generic.List[object]]::new()
    Invoke-Expression $planner
    Assert-Equal $decisions.Count 0 "$scope case-equivalent exclusions produce no decisions or rule risks"
    $sourceEntries = Get-DrsExclusionEntries $drsSourceSnapshot
    Assert-Equal $sourceEntries[0].Exclusion.selector 'X-Token' "$scope planning preserves source selector spelling"
    Assert-Equal $targetEntries[0].Exclusion.selector 'x-token' "$scope planning preserves target selector spelling"
}
Write-Host 'PASS: native exclusion selector case semantics, scoped planning, duplicates and input preservation'
#endregion
