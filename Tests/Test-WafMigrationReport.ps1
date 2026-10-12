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
foreach ($name in 'apiVersion', 'resourceType', 'drsPath', 'supersededRuleIds', 'retiredRuleIds',
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
$start = $text.IndexOf('#region Execution - supersession scan and decision planning', [StringComparison]::Ordinal)
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
    $UseRecommendedTarget = @()
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
            $records = @(Write-DecisionSummary @($custom) 'Custom rules' 180 3>&1 6>&1)
            $warnings = @($records | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
            Assert-Equal $warnings.Count ($(if ($choice -eq 'KeepTarget') { 1 } else { 2 })) 'Priority warnings retain choice-based visibility and compatibility warnings remain visible'
        }
        $custom.SourceValue = @{}
        $custom.TargetValue = @{}
        $overview = Get-DecisionOverview $custom
        Assert-Equal $overview.Priority '---' 'Unspecified custom priority uses the common marker'
        Assert-Equal $overview.Type '---' 'Unspecified custom rule type uses the common marker'
        Assert-Equal $overview.Source 'Enabled / ---' 'Unspecified source custom action uses the common marker'
        Assert-Equal $overview.Target 'Enabled / ---' 'Unspecified target custom action uses the common marker'
        $records = @(Write-DecisionTable $botItems 3>&1 6>&1)
        Assert-Equal @($records | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count 6 'Full report does not repeat inline warnings at the end'
    }
}
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
