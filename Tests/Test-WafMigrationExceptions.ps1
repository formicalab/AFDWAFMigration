#Requires -Version 7.0
#Requires -Modules Az.Accounts

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Load actual validation helpers and isolated fixtures
$migrationPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'New-WafMigrationTemplate.ps1'
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
$drsCatalog = Get-EmbeddedDrsCatalog
$catalogIndexes = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)

function Assert-True {
    <#
    .SYNOPSIS
    Requires a regression condition.
    .DESCRIPTION
    Throws a named failure without printing private fixture values.
    #>
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) { throw $Message }
}

function New-ExceptionPolicy {
    <#
    .SYNOPSIS
    Creates a Premium next-generation policy containing all supported families.
    .DESCRIPTION
    Uses matching native defaults so exception membership is the only difference.
    #>
    param([object[]] $Exceptions = @(), [string] $DrsVersion = '2.2', [string] $BotVersion = '1.1')
    @{
        name = 'ExceptionFixture'; type = $resourceType; location = 'Global'
        sku = @{ name = 'Premium_AzureFrontDoor' }; tags = @{}
        properties = @{
            policySettings = @{ enabledState = 'Enabled'; mode = 'Prevention' }
            customRules = @{ rules = @() }
            managedRules = @{
                managedRuleSets = @(
                    @{ ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = $DrsVersion; ruleSetAction = 'Block'; ruleGroupOverrides = @() }
                    @{ ruleSetType = 'Microsoft_BotManagerRuleSet'; ruleSetVersion = $BotVersion; ruleGroupOverrides = @() }
                    @{ ruleSetType = 'Microsoft_HTTPDDoSRuleSet'; ruleSetVersion = '1.0'; ruleGroupOverrides = @() }
                )
                exceptionsList = @{ exceptions = $Exceptions }
            }
        }
    }
}

function Write-ExceptionFixture {
    <#
    .SYNOPSIS
    Writes one JSON fixture in the test's isolated directory.
    .DESCRIPTION
    Uses the same serialization depth as generated templates.
    #>
    param([string] $Name, [System.Collections.IDictionary] $Resource)
    $path = Join-Path $testDirectory $Name
    ConvertTo-Json -InputObject $Resource -Depth 100 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

function Invoke-ExceptionMigration {
    <#
    .SYNOPSIS
    Executes the actual script and captures its report plus host output.
    .DESCRIPTION
    Keeps information/warning records separate from the single structured result.
    #>
    param([hashtable] $Arguments)
    $records = @(& $migrationPath @Arguments 3>&1 6>&1)
    $summaries = @($records | Where-Object { $null -ne $_.PSObject.Properties['Decisions'] })
    Assert-True ($summaries.Count -eq 1) 'Migration must produce exactly one structured result.'
    [pscustomobject]@{ Report = $summaries[0]; Text = $records -join "`n" }
}

$setScope = @{ ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2' }
$ruleScope = @{
    ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'
    ruleGroupScopes = @(@{ ruleGroupName = 'SQLI'; ruleScopes = @(@{ ruleId = '942100' }) })
}
$common = @{
    matchVariable = 'RequestUri'; valueMatchOperator = 'Equals'
    matchValues = @('/shared-one', '/shared-two'); scopes = @($ruleScope)
}
$header = @{
    matchVariable = 'RequestHeaderNames'; selectorMatchOperator = 'Equals'; selector = 'X-Trusted'
    valueMatchOperator = 'Equals'; matchValues = @('private-header-credential')
    scopes = @(
        @{ ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'; ruleGroupScopes = @(@{ ruleGroupName = 'SQLI' }) }
        @{
            ruleSetType = 'Microsoft_BotManagerRuleSet'; ruleSetVersion = '1.1'
            ruleGroupScopes = @(@{ ruleGroupName = 'GoodBots'; ruleScopes = @(@{ ruleId = 'Bot200200' }) })
        }
        @{ ruleSetType = 'Microsoft_HTTPDDoSRuleSet'; ruleSetVersion = '1.0' }
    )
}
$ip = @{
    matchVariable = 'SocketAddr'; valueMatchOperator = 'IPMatch'
    matchValues = @('192.0.2.0/24', '2001:db8::/32'); scopes = @($setScope)
}
$targetOnly = @{
    matchVariable = 'RequestUri'; valueMatchOperator = 'StartsWith'
    matchValues = @('/private-target'); scopes = @($ruleScope)
}
#endregion

#region Predicate, scope and limit validation
$valid = ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($common, $header, $ip)) 'Master'
Assert-True (@(Get-CatalogIssues $valid).Count -eq 0) 'All attributes and DRS/Bot/HTTP scopes must be supported.'
foreach ($operator in 'Equals', 'Contains', 'StartsWith', 'EndsWith', 'EqualsAny') {
    $entry = Copy-JsonValue $common
    $entry.valueMatchOperator = $operator
    if ($operator -eq 'EqualsAny') { $entry.matchValues = @() }
    Assert-True (@(Get-CatalogIssues (ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($entry)) 'Master')).Count -eq 0) "URI operator $operator must be preserved."
}
foreach ($case in @(
    @{ Variable = 'SocketAddr'; Count = 600; Entry = $ip }
    @{ Variable = 'RequestUri'; Count = 10; Entry = $common }
    @{ Variable = 'RequestHeaderNames'; Count = 10; Entry = $header }
)) {
    $entry = Copy-JsonValue $case.Entry
    $entry.matchValues = @((1..$case.Count) | ForEach-Object { $case.Entry.matchValues[0] })
    $managed = (New-ExceptionPolicy @($entry)).properties.managedRules
    Assert-True (@(Get-ExceptionValidationIssues $managed).Count -eq 0) "$($case.Variable) must accept the exact value limit."
    $entry.matchValues += $case.Entry.matchValues[0]
    Assert-True (@(Get-ExceptionValidationIssues $managed).Count -gt 0) "$($case.Variable) must reject one value above the limit."
}
$managed = (New-ExceptionPolicy @((1..60) | ForEach-Object { Copy-JsonValue $common })).properties.managedRules
Assert-True (@(Get-ExceptionValidationIssues $managed).Count -eq 0) 'Exactly 60 exceptions must be accepted.'
$managed.exceptionsList.exceptions += Copy-JsonValue $common
Assert-True (@(Get-ExceptionValidationIssues $managed).Count -gt 0) '61 exceptions must be rejected.'

foreach ($mutation in @(
    { param($entry) $entry.scopes = @() }
    { param($entry) $entry.matchValues = @() }
    { param($entry) $entry.matchValues = @('') }
    { param($entry) $entry.selector = 'not a header'; $entry.selectorMatchOperator = 'Equals' }
    { param($entry) $entry.valueMatchOperator = 'IPMatch' }
)) {
    $entry = Copy-JsonValue $common
    & $mutation $entry
    $failed = $false
    try { $null = ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($entry)) 'Source' }
    catch {
        if ($_.Exception.Message -notlike '*invalid request exceptions*') { throw }
        $failed = $true
    }
    Assert-True $failed 'Invalid source predicates must fail explicitly before planning.'
}
foreach ($address in '192.0.2.1/33', '2001:db8::/129', '192.0.2.1/-1', '999.0.0.1', 'example.com', '127.1') {
    $entry = Copy-JsonValue $ip
    $entry.matchValues = @($address)
    Assert-True (@(Get-ExceptionValidationIssues (New-ExceptionPolicy @($entry)).properties.managedRules).Count -gt 0) 'Invalid address/CIDR must be rejected.'
}
$badHeader = Copy-JsonValue $header
$null = $badHeader.Remove('selectorMatchOperator')
Assert-True (@(Get-ExceptionValidationIssues (New-ExceptionPolicy @($badHeader)).properties.managedRules).Count -gt 0) 'Header selector operator is required.'
$legacy = ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($header) -DrsVersion '1.1') 'Source'
Assert-True (@(Get-CatalogIssues $legacy | Where-Object { $_ -like '*next-generation*' }).Count -eq 1) 'Bot/HTTP exceptions still require a configured modern DRS engine.'
$badScope = Copy-JsonValue $valid
$badScope.properties.managedRules.exceptionsList.exceptions[0].scopes[0].ruleGroupScopes[0].ruleScopes[0].ruleId = 'missing-rule'
Assert-True (@(Get-CatalogIssues $badScope | Where-Object { $_ -like 'Exception rule*' }).Count -eq 1) 'Unknown exception rule IDs must not broaden to a group.'
Write-Host 'PASS: exception attributes, operators, scopes, engine requirement, exact limits and invalid predicates'
#endregion

#region Actual reports and generated ARM templates
$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "waf-exceptions-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $testDirectory
try {
    $sourceFile = Write-ExceptionFixture 'source.json' (New-ExceptionPolicy @($common, $header, $ip))
    $reorderedCommon = Copy-JsonValue $common
    $reorderedCommon.matchValues = @('/shared-two', '/shared-one')
    $masterFile = Write-ExceptionFixture 'master.json' (New-ExceptionPolicy @($reorderedCommon, $targetOnly))
    $arguments = @{ SourcePolicy = $sourceFile; MasterPolicy = $masterFile; TargetPolicyName = 'ExceptionTest'; ReportOnly = $true }
    $run = Invoke-ExceptionMigration $arguments
    $reviews = @($run.Report.Decisions | Where-Object DecisionKind -eq 'ManagedException')
    Assert-True ($reviews.Count -eq 3 -and $run.Report.DecisionCount -eq 3) 'Only three unmatched exception occurrences need choices.'
    Assert-True ($run.Text.Contains('Request exceptions (Preview)') -and $run.Text.Contains('Value count')) 'Exceptions need a dedicated visible review section.'
    Assert-True (-not $run.Text.Contains('private-header-credential') -and -not $run.Text.Contains('/private-target')) 'Console output must never print exception match values.'
    $reportJson = $run.Report | ConvertTo-Json -Depth 100
    Assert-True (-not $reportJson.Contains('private-header-credential') -and -not $reportJson.Contains('/private-target')) 'ReportOnly metadata must not expose request match values.'
    Assert-True (@($reviews | Where-Object { $_.CompatibilityIssues.Count }).Count -eq 0) 'Valid mixed-family exceptions must remain actionable.'
    $headerReview = @($reviews | Where-Object { $_.ExceptionContext.MatchVariable -eq 'RequestHeaderNames' })[0]
    Assert-True ($headerReview.ExceptionContext.Scopes.Count -eq 3) 'A mixed exception must stay one atomic three-scope choice.'
    foreach ($width in 50, 120, 220) {
        $source = ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($common, $header, $ip)) 'Source'
        $target = ConvertTo-PolicyConfiguration (New-ExceptionPolicy @($common, $targetOnly)) 'Master'
        $decisions = [System.Collections.Generic.List[object]]::new()
        Add-ManagedExceptionDecisions $source
        foreach ($decision in $decisions) { $decision.CompatibilityIssues = Get-CandidateCompatibilityIssues $decision }
        $display = @(Write-DecisionSummary $decisions.ToArray() 'Request exceptions' $width 6>&1) -join "`n"
        Assert-True (-not $display.Contains('private-header-credential')) "Exception values must stay private at width $width."
    }

    foreach ($mode in 'Source', 'Target', 'Mixed') {
        $outputPath = Join-Path $testDirectory "$mode.arm.json"
        $generation = @{ SourcePolicy = $sourceFile; MasterPolicy = $masterFile; TargetPolicyName = 'ExceptionTest'; OutputPath = $outputPath }
        if ($mode -eq 'Source') { $generation.KeepSource = '1-3' }
        elseif ($mode -eq 'Target') { $generation.KeepTarget = '1-3' }
        else {
            $generation.KeepSource = [string] $headerReview.Id
            $generation.KeepTarget = @($reviews | Where-Object Id -ne $headerReview.Id | ForEach-Object { [string] $_.Id })
        }
        $result = Invoke-ExceptionMigration $generation
        Assert-True ($result.Report.PendingDecisionCount -eq 0 -and (Test-Path -LiteralPath $outputPath)) 'All choices must persist in an ARM file.'
        $template = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        $actual = $template.resources[0].properties.managedRules.exceptionsList.exceptions
        $expected = switch ($mode) {
            'Source' { ,@($common, $header, $ip) }
            'Target' { ,@($common, $targetOnly) }
            'Mixed' { ,@($common, $targetOnly, $header) }
        }
        Assert-True (Test-JsonEqual $actual $expected) "$mode choices must preserve exactly the selected exception predicates and complete scopes."
    }

    $emptyFile = Write-ExceptionFixture 'empty.json' (New-ExceptionPolicy)
    $onlyTargetFile = Write-ExceptionFixture 'only-target.json' (New-ExceptionPolicy @($targetOnly))
    $emptyOutput = Join-Path $testDirectory 'removed.arm.json'
    $null = Invoke-ExceptionMigration @{
        SourcePolicy = $emptyFile; MasterPolicy = $onlyTargetFile; TargetPolicyName = 'RemoveTest'
        OutputPath = $emptyOutput; KeepSource = '1'
    }
    $removedTemplate = Get-Content -LiteralPath $emptyOutput -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    Assert-True (-not $removedTemplate.resources[0].properties.managedRules.ContainsKey('exceptionsList')) 'Removing the last target-only exception must omit the optional container.'

    $promptState = @{ Answers = [System.Collections.Generic.Queue[string]]::new(); Count = 0 }
    foreach ($answer in 'S', 'T', 'S') { $promptState.Answers.Enqueue($answer) }
    function Read-Host {
        <#
        .SYNOPSIS
        Supplies deterministic answers to the real interactive review.
        .DESCRIPTION
        Counts prompts and fails if the script asks an unexpected additional question.
        #>
        param([string] $Prompt)
        $promptState.Count++
        return $promptState.Answers.Dequeue()
    }
    try {
        $interactiveOutput = Join-Path $testDirectory 'interactive.arm.json'
        $interactive = Invoke-ExceptionMigration @{
            SourcePolicy = $sourceFile; MasterPolicy = $masterFile; TargetPolicyName = 'InteractiveTest'; OutputPath = $interactiveOutput
        }
        Assert-True ($promptState.Count -eq 3 -and $interactive.Report.PendingDecisionCount -eq 0) 'Interactive exception choices must resolve exactly the displayed rows.'
        $interactiveTemplate = Get-Content -LiteralPath $interactiveOutput -Raw | ConvertFrom-Json -AsHashtable -Depth 100
        Assert-True (Test-JsonEqual $interactiveTemplate.resources[0].properties.managedRules.exceptionsList.exceptions @($common, $header)) 'Interactive source/target/absent-source choices must produce exact membership.'
    } finally { Remove-Item -LiteralPath Function:\Read-Host }

    # Each input is individually within quota; their selected union must also be checked.
    $quotaSource = Write-ExceptionFixture 'quota-source.json' (New-ExceptionPolicy @(
        foreach ($index in 1..31) {
            $entry = Copy-JsonValue $common
            $entry.matchValues = @("/source-$index")
            $entry
        }
    ))
    $quotaMaster = Write-ExceptionFixture 'quota-master.json' (New-ExceptionPolicy @(
        foreach ($index in 1..30) {
            $entry = Copy-JsonValue $common
            $entry.matchValues = @("/target-$index")
            $entry
        }
    ))
    $quotaReport = (Invoke-ExceptionMigration @{
        SourcePolicy = $quotaSource; MasterPolicy = $quotaMaster; TargetPolicyName = 'QuotaTest'; ReportOnly = $true
    }).Report
    $additions = @($quotaReport.Decisions | Where-Object SourcePresent | ForEach-Object { [string] $_.Id })
    $retentions = @($quotaReport.Decisions | Where-Object { -not $_.SourcePresent } | ForEach-Object { [string] $_.Id })
    $protectedOutput = Join-Path $testDirectory 'Source.arm.json'
    $hash = (Get-FileHash -LiteralPath $protectedOutput).Hash
    $failed = $false
    try {
        $null = Invoke-ExceptionMigration @{
            SourcePolicy = $quotaSource; MasterPolicy = $quotaMaster; TargetPolicyName = 'QuotaTest'
            OutputPath = $protectedOutput; Force = $true; KeepSource = $additions; KeepTarget = $retentions
        }
    } catch {
        if ($_.Exception.Message -notlike '*exceeds the policy limit of 60 exceptions*') { throw }
        $failed = $true
    }
    Assert-True $failed 'A selected union of 61 exceptions must fail before output.'
    Assert-True ((Get-FileHash -LiteralPath $protectedOutput).Hash -ceq $hash) 'Combined validation must preserve existing output even with Force.'

    $duplicates = Write-ExceptionFixture 'duplicates.json' (New-ExceptionPolicy @($common, $common))
    $single = Write-ExceptionFixture 'single.json' (New-ExceptionPolicy @($common))
    $duplicateReport = (Invoke-ExceptionMigration @{ SourcePolicy = $duplicates; MasterPolicy = $single; TargetPolicyName = 'DuplicateTest'; ReportOnly = $true }).Report
    Assert-True ($duplicateReport.DecisionCount -eq 1 -and $duplicateReport.Decisions[0].SourcePresent) 'An extra identical occurrence is one independent source membership review.'

    $source21 = New-ExceptionPolicy @((Copy-JsonValue $common)) -DrsVersion '2.1'
    $source21.properties.managedRules.exceptionsList.exceptions[0].scopes[0].ruleSetVersion = '2.1'
    $versionSource = Write-ExceptionFixture 'source21.json' $source21
    $versionReport = (Invoke-ExceptionMigration @{ SourcePolicy = $versionSource; MasterPolicy = $single; TargetPolicyName = 'VersionTest'; ReportOnly = $true }).Report
    Assert-True (@($versionReport.Decisions | Where-Object DecisionKind -eq 'ManagedException').Count -eq 0) 'Matching scopes must align DRS versions without unnecessary exception choices.'

    $missingBot = Copy-JsonValue $header
    $missingBot.scopes[1].ruleGroupScopes[0].ruleScopes[0].ruleId = 'Bot200300'
    $botSource = Write-ExceptionFixture 'bot-source.json' (New-ExceptionPolicy @($missingBot))
    $botMaster = Write-ExceptionFixture 'bot-master.json' (New-ExceptionPolicy -BotVersion '1.0')
    $botRun = Invoke-ExceptionMigration @{ SourcePolicy = $botSource; MasterPolicy = $botMaster; TargetPolicyName = 'BotTest'; ReportOnly = $true }
    $botReview = @($botRun.Report.Decisions | Where-Object DecisionKind -eq 'ManagedException')[0]
    Assert-True (@($botReview.CompatibilityIssues | Where-Object { $_ -like '*Bot200300*' }).Count -eq 1) 'Removed Bot rule scopes must prevent KeepSource with an inline compatibility warning.'
    Assert-True ($botRun.Text.Contains("Row $($botReview.Id): KeepSource cannot be used")) 'Exception compatibility warnings must be visible beside the review.'

    $masterless = Invoke-ExceptionMigration @{ SourcePolicy = $sourceFile; TargetPolicyName = 'DefaultsTest'; ReportOnly = $true }
    Assert-True (@($masterless.Report.Decisions | Where-Object DecisionKind -eq 'ManagedException').Count -eq 3) 'Masterless tuning must review all source exception entries, including Bot/HTTP scopes.'
    $outputPath = Join-Path $testDirectory 'masterless.arm.json'
    $null = Invoke-ExceptionMigration @{ SourcePolicy = $sourceFile; TargetPolicyName = 'DefaultsTest'; OutputPath = $outputPath; KeepSource = "1-$($masterless.Report.DecisionCount)" }
    $template = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    Assert-True (Test-JsonEqual $template.resources[0].properties.managedRules.exceptionsList.exceptions @($common, $header, $ip)) 'Masterless source choices must restore full mixed-family scopes without implicit splitting.'
    Write-Host 'PASS: independent exception reports, privacy, duplicate pairing, version compatibility and exact ARM persistence'
} finally {
    Remove-Item -LiteralPath $testDirectory -Recurse -Force
}
#endregion
