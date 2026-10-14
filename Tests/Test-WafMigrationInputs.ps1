#Requires -Version 7.0
#Requires -Modules Az.Accounts

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Fixtures and read-only Azure mocks
$migrationPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'New-WafMigrationTemplate.ps1'
$subscriptionId = '00000000-0000-0000-0000-000000000001'
$sourceId = "/subscriptions/$subscriptionId/resourceGroups/Test/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/LiveSource"
$masterId = "/subscriptions/$subscriptionId/resourceGroups/Test/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/LiveMaster"
$mockState = @{
    ReadPaths = [System.Collections.Generic.List[string]]::new()
    ContextCalls = 0; AllowContext = $true; ContextAvailable = $true
}
$startupProgress = [System.Collections.Generic.List[object]]::new()
$mockState.Context = [pscustomobject]@{
    Account = [pscustomobject]@{ Id = 'LocalRegression' }
    Subscription = [pscustomobject]@{ Id = $subscriptionId }
}
$sourceFixture = @{
    type = 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies'
    name = 'SourceSnapshot'; location = 'Global'; sku = @{ name = 'Premium_AzureFrontDoor' }
    id = $sourceId
    tags = @{ origin = '[literal-origin]' }
    properties = @{
        policySettings = @{ enabledState = 'Enabled'; mode = 'Prevention' }
        managedRules = @{
            managedRuleSets = @(@{
                ruleSetType = 'Microsoft_BotManagerRuleSet'; ruleSetVersion = '1.1'
                ruleSetAction = 'Block'; ruleGroupOverrides = @()
            })
        }
    }
}
$masterFixture = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
$masterFixture['name'] = 'MasterSnapshot'
$masterFixture['id'] = $masterId
$null = $masterFixture.properties.managedRules.managedRuleSets[0].Remove('ruleSetAction')

function Get-AzContext {
    <#
    .SYNOPSIS
    Provides an isolated context for input regressions.
    .DESCRIPTION
    Rejects all context access during file-only cases and never reads a real account.
    #>
    [CmdletBinding()]
    param()
    $mockState.ContextCalls++
    if (-not $mockState.AllowContext) { throw 'Offline execution unexpectedly requested an Azure context.' }
    if ($mockState.ContextAvailable) { return $mockState.Context }
    return $null
}

function Invoke-AzRestMethod {
    <#
    .SYNOPSIS
    Serves only fixture policy GETs.
    .DESCRIPTION
    Rejects writes, unvalidated contexts and unexpected paths without contacting Azure.
    #>
    [CmdletBinding()]
    param([string] $Path, [string] $Method, [object] $DefaultProfile)
    if ($Method -cne 'GET') { throw 'Input loading must be read-only.' }
    if ($DefaultProfile.Subscription.Id -cne $subscriptionId) { throw 'Input GET used the wrong context.' }
    $fixture = if ($Path -ceq "${sourceId}?api-version=2026-04-01") { $sourceFixture }
        elseif ($Path -ceq "${masterId}?api-version=2026-04-01") { $masterFixture }
        else { throw "Unexpected ARM read: $Path" }
    $mockState.ReadPaths.Add($Path)
    [pscustomobject]@{ StatusCode = 200; Content = ConvertTo-Json $fixture -Depth 100 }
}

function Write-Progress {
    <#
    .SYNOPSIS
    Captures compatibility progress without relying on a terminal renderer.
    .DESCRIPTION
    Records updates and completion so startup feedback can be tested independently
    of the host's progress preferences.
    #>
    param([int] $Id, [string] $Activity, [string] $Status, [int] $PercentComplete, [switch] $Completed)
    $startupProgress.Add([pscustomobject]@{
        Id = $Id; Activity = $Activity; Status = $Status
        PercentComplete = $PercentComplete; Completed = [bool] $Completed
    })
}

function Assert-Equal {
    <#
    .SYNOPSIS
    Requires exact scalar equality.
    .DESCRIPTION
    Throws a named regression failure rather than continuing with an invalid result.
    #>
    param($Actual, $Expected, [string] $Message)
    if ($Actual -cne $Expected) { throw "$Message`: expected [$Expected], got [$Actual]." }
}

function Assert-InputFailure {
    <#
    .SYNOPSIS
    Requires a specific input-validation failure.
    .DESCRIPTION
    Runs the actual migration script and rejects unexpected successes or diagnostics.
    #>
    param([hashtable] $Arguments, [string] $Pattern)
    $failed = $false
    try { $null = & $migrationPath @Arguments 3>$null 6>$null }
    catch {
        if ($_.Exception.Message -notlike $Pattern) { throw }
        $failed = $true
    }
    Assert-Equal $failed $true "Expected input failure matching $Pattern"
}

function Write-InputFixture {
    <#
    .SYNOPSIS
    Writes JSON fixture data into the unique test directory.
    .DESCRIPTION
    Preserves JSON array roots so malformed-input tests exercise the actual parser.
    #>
    param([string] $Name, [AllowNull()] $Document)
    $path = Join-Path $testDirectory $Name
    ConvertTo-Json -InputObject $Document -Depth 100 |
        Set-Content -LiteralPath $path -Encoding utf8
    return $path
}
#endregion

#region Actual script input combinations and validation
$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "waf-inputs-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Path $testDirectory
try {
    $sourceFile = Write-InputFixture 'source.json' $sourceFixture
    $masterFile = Write-InputFixture 'master.json' $masterFixture
    $sourceTemplate = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $sourceTemplate.tags.origin = '[[literal-origin]'
    $sourceTemplateFile = Write-InputFixture 'source-template.json' @{ resources = @($sourceTemplate) }
    $masterTemplate = $masterFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $masterTemplate.tags.origin = '[[literal-origin]'
    $masterTemplateFile = Write-InputFixture 'master-template.json' @{ resources = @($masterTemplate) }
    $sourceHash = (Get-FileHash -LiteralPath $sourceFile).Hash
    $masterHash = (Get-FileHash -LiteralPath $masterFile).Hash

    foreach ($case in @(
        @{ Source = $sourceFile; Master = $masterFile; Reads = 0; Name = 'SourceSnapshot' }
        @{ Source = $sourceTemplateFile; Master = $masterTemplateFile; Reads = 0; Name = 'SourceSnapshot' }
        @{ Source = $sourceId; Master = $masterFile; Reads = 1; Name = 'LiveSource' }
        @{ Source = $sourceFile; Master = $masterId; Reads = 1; Name = 'SourceSnapshot' }
        @{ Source = $sourceId; Master = $masterId; Reads = 2; Name = 'LiveSource' }
    )) {
        $mockState.ReadPaths.Clear()
        $mockState.ContextCalls = 0
        $mockState.AllowContext = $case.Reads -gt 0
        $report = & $migrationPath -SourcePolicy $case.Source -MasterPolicy $case.Master `
            -TargetPolicyName InputTest -ReportOnly 3>$null 6>$null
        Assert-Equal $mockState.ReadPaths.Count $case.Reads 'Only resource-ID inputs perform Azure GETs'
        Assert-Equal $mockState.ContextCalls ([int] ($case.Reads -gt 0)) 'File-only runs do not request a context'
        Assert-Equal $report.SourcePolicyName $case.Name 'Source name comes from the chosen input'
        Assert-Equal $report.OutputPath $null 'ReportOnly never generates an ARM file'
        Assert-Equal $report.DecisionCount 1 'Equivalent inputs yield the same action review'
        $scopeRow = @($report.ManagedRuleRiskAnalysis | Where-Object ScopeKind -eq 'RuleSetAction')[0]
        Assert-Equal $scopeRow.SourceEffectiveAction 'Block' 'Configured source scope action is retained'
        Assert-Equal $scopeRow.TargetEffectiveAction '---' 'Omitted target scope action uses the common marker'
        Assert-Equal $scopeRow.TargetDefaultAction '---' 'Structured defaults use the common marker too'
    }
    Write-Host 'PASS: file/file, template/template, live/file, file/live and live/live policy inputs'

    $mockState.AllowContext = $false
    $mockState.ReadPaths.Clear()
    $parameters = (Get-Command $migrationPath).Parameters
    foreach ($name in 'SourcePolicy', 'MasterPolicy') {
        Assert-Equal $parameters.ContainsKey($name) $true "$name is a canonical parameter"
        Assert-Equal $parameters[$name].Aliases.Count 0 "$name has no legacy aliases"
    }
    foreach ($name in 'SourcePolicyResourceId', 'SourcePolicyPath', 'MasterPolicyPath', 'MasterPolicyResourceId',
        'UseRecommendedTarget') {
        Assert-Equal $parameters.ContainsKey($name) $false "$name is not an exposed option"
        Assert-InputFailure @{
            SourcePolicy = $sourceFile; TargetPolicyName = 'RemovedOptionTest'; ReportOnly = $true; $name = '1'
        } "*parameter cannot be found*'$name'*"
    }
    $explicitContext = [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]::new()
    $explicitContext.Account = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureAccount]::new()
    $explicitContext.Account.Id = 'LocalRegression'
    $explicitContext.Subscription = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureSubscription]::new()
    $explicitContext.Subscription.Id = $subscriptionId
    $mockState.ContextCalls = 0
    $report = & $migrationPath -SourcePolicy $sourceId -MasterPolicy $masterFile -DefaultProfile $explicitContext `
        -TargetPolicyName ExplicitContextTest -ReportOnly 3>$null 6>$null
    Assert-Equal $report.DecisionCount 1 'Explicit profiles support live inputs'
    Assert-Equal $mockState.ContextCalls 0 'Explicit profiles bypass ambient context access'
    Assert-Equal $mockState.ReadPaths.Count 1 'Explicit profiles perform only the requested source GET'
    $mockState.ReadPaths.Clear()
    $report = & $migrationPath -SourcePolicy $sourceFile -TargetPolicyName DefaultsTest -ReportOnly 3>$null 6>$null
    Assert-Equal $report.TargetBotManagerRuleSetVersion '1.1' 'File sources support the masterless native baseline'

    $outputFile = Join-Path $testDirectory 'generated.arm.json'
    $result = & $migrationPath -SourcePolicy $sourceFile -MasterPolicy $masterTemplateFile `
        -TargetPolicyName GeneratedInputTest -KeepTarget 1 -OutputPath $outputFile 3>$null 6>$null
    Assert-Equal $result.OutputPath $outputFile 'File inputs generate a persistent ARM template'
    $outputText = Get-Content -LiteralPath $outputFile -Raw
    $output = $outputText | ConvertFrom-Json -AsHashtable
    Assert-Equal $output.resources[0].tags.origin '[[literal-origin]' 'Template literal decoding and output escaping round-trip'
    Assert-Equal $output.resources[0].properties.managedRules.managedRuleSets[0].Contains('ruleSetAction') $false 'Absent scope action remains omitted, not an ARM marker'
    Assert-Equal ($outputText.Contains('---')) $false 'Report markers are not written as configuration values'

    $autoSource = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $autoMaster = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $autoSource.name = 'AutoSource'
    $autoMaster.name = 'AutoMaster'
    $autoSource.tags.origin = 'source-auto'
    $autoMaster.tags.origin = 'target-auto'
    $autoMaster.properties.policySettings.mode = 'Detection'
    $autoSource.properties.customRules = @{ rules = @(
        @{
            name = 'SharedRule'; enabledState = 'Enabled'; priority = 10
            ruleType = 'MatchRule'; action = 'Block'
            matchConditions = @(@{ matchVariable = 'RequestUri'; operator = 'Contains'; matchValue = @('/source-shared') })
        },
        @{
            name = 'SourceOnlyRule'; enabledState = 'Enabled'; priority = 20
            ruleType = 'MatchRule'; action = 'Log'
            matchConditions = @(@{ matchVariable = 'RequestUri'; operator = 'Contains'; matchValue = @('/source-only') })
        }
    ) }
    $autoMaster.properties.customRules = @{ rules = @(
        @{
            name = 'SharedRule'; enabledState = 'Enabled'; priority = 20
            ruleType = 'MatchRule'; action = 'Log'
            matchConditions = @(@{ matchVariable = 'RequestUri'; operator = 'Contains'; matchValue = @('/target-shared') })
        },
        @{
            name = 'TargetOnlyRule'; enabledState = 'Enabled'; priority = 12
            ruleType = 'MatchRule'; action = 'Block'
            matchConditions = @(@{ matchVariable = 'RequestUri'; operator = 'Contains'; matchValue = @('/target-only') })
        }
    ) }
    $sourceExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'source-global' }
    $sourceGroupExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'source-group' }
    $sourceRuleExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'source-rule' }
    $targetExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'target-global' }
    $targetGroupExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'target-group' }
    $targetRuleExclusion = @{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'target-rule' }
    $autoSource.properties.managedRules.managedRuleSets = @(
        @{
            ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'; ruleSetAction = 'Block'
            exclusions = @($sourceExclusion)
            ruleGroupOverrides = @(@{
                ruleGroupName = 'SQLI'; exclusions = @($sourceGroupExclusion)
                rules = @(@{ ruleId = '942450'; enabledState = 'Enabled'; action = 'AnomalyScoring'; exclusions = @($sourceRuleExclusion) })
            })
        },
        $autoSource.properties.managedRules.managedRuleSets[0]
    )
    $autoMaster.properties.managedRules.managedRuleSets = @(
        @{
            ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'; ruleSetAction = 'Log'
            exclusions = @($targetExclusion)
            ruleGroupOverrides = @(@{
                ruleGroupName = 'SQLI'; exclusions = @($targetGroupExclusion)
                rules = @(@{ ruleId = '942450'; enabledState = 'Disabled'; action = 'Log'; exclusions = @($targetRuleExclusion) })
            })
        },
        $autoMaster.properties.managedRules.managedRuleSets[0]
    )
    $autoSourceFile = Write-InputFixture 'auto-source.json' $autoSource
    $autoMasterFile = Write-InputFixture 'auto-master.json' $autoMaster
    $startupProgress.Clear()
    $autoRecords = @(& $migrationPath -SourcePolicy $autoSourceFile -MasterPolicy $autoMasterFile `
        -TargetPolicyName AutoReportTest -Auto -ReportOnly 3>$null 6>&1)
    $autoSummaries = @($autoRecords | Where-Object { $_ -isnot [System.Management.Automation.InformationRecord] })
    Assert-Equal $autoSummaries.Count 1 'Startup feedback does not contaminate the success-stream summary'
    $autoReport = $autoSummaries[0]
    $startupMessages = @($autoRecords | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } |
        ForEach-Object { [string] $_.MessageData })
    Assert-Equal $startupMessages[0] 'Preparing WAF migration. Azure resources will not be changed.' 'The first executable startup phase announces read-only preparation'
    Assert-Equal ($startupMessages -contains 'Loading and validating policy inputs...') $true 'Input loading is announced'
    Assert-Equal ($startupMessages -contains 'Loading embedded managed-rule catalogs and resolving native defaults...') $true 'Catalog loading is announced'
    Assert-Equal ($startupMessages -contains 'Comparing managed-rule behavior, exclusions, and request exceptions...') $true 'Managed-rule comparison is announced'
    Assert-Equal ($startupMessages -contains 'Analysis complete. Displaying policy comparisons.') $true 'Analysis completion precedes the comparison report'

    # Progress measures completed work against the actual count and is cleared before display.
    $activeProgress = @($startupProgress | Where-Object { -not $_.Completed })
    Assert-Equal $activeProgress.Count $autoReport.DecisionCount 'Every compatibility decision has a progress update'
    for ($index = 0; $index -lt $activeProgress.Count; $index++) {
        Assert-Equal $activeProgress[$index].Status "Checking decision $($index + 1) of $($autoReport.DecisionCount)" 'Progress uses exact decision counts'
        Assert-Equal $activeProgress[$index].PercentComplete ([int] (100 * $index / $autoReport.DecisionCount)) 'Progress percentage reflects completed checks'
    }
    Assert-Equal @($startupProgress | Where-Object Completed).Count 1 'The compatibility progress bar is completed once'
    Assert-Equal $startupProgress[$startupProgress.Count - 1].Completed $true 'Progress is cleared after all checks'
    Assert-Equal $autoReport.OutputPath $null 'Automatic report-only mode writes no output'
    Assert-Equal $autoReport.PendingDecisionCount 0 'Automatic mode resolves every displayed decision'
    Assert-Equal @($autoReport.Decisions | Where-Object {
        $_.DecisionKind -eq 'TargetCustomRule' -and $_.Choice -ne 'KeepTarget'
    }).Count 0 'Automatic mode retains every target-only custom rule'
    Assert-Equal @($autoReport.Decisions | Where-Object {
        $_.DecisionKind -ne 'TargetCustomRule' -and $_.Choice -ne 'KeepSource'
    }).Count 0 'Automatic mode selects source for every other decision'
    Assert-Equal @($autoReport.Decisions | Where-Object { $_.PriorityConflicts.Count }).Count 0 'Automatic preview does not warn about the shared master priority freed by source selection'

    $autoOutputFile = Join-Path $testDirectory 'auto-generated.arm.json'
    $autoResult = & $migrationPath -SourcePolicy $autoSourceFile -MasterPolicy $autoMasterFile `
        -TargetPolicyName AutoGeneratedTest -Auto -OutputPath $autoOutputFile 3>$null 6>$null
    Assert-Equal $autoResult.PendingDecisionCount 0 'Automatic generation leaves no pending decisions'
    $autoOutput = Get-Content -LiteralPath $autoOutputFile -Raw | ConvertFrom-Json -AsHashtable -Depth 100
    $autoResource = $autoOutput.resources[0]
    Assert-Equal $autoResource.tags.origin 'source-auto' 'Automatic mode selects source general settings'
    Assert-Equal $autoResource.properties.policySettings.mode 'Prevention' 'Automatic mode selects source policy settings'
    $generatedCustomRules = @{}
    foreach ($rule in $autoResource.properties.customRules.rules) { $generatedCustomRules[$rule.name] = $rule }
    Assert-Equal $generatedCustomRules.Count 3 'Automatic mode emits the custom-rule union by name'
    Assert-Equal $generatedCustomRules.SharedRule.action 'Block' 'Automatic mode selects source for a shared custom rule'
    Assert-Equal $generatedCustomRules.SharedRule.priority 10 'Shared custom rule keeps the source priority'
    Assert-Equal $generatedCustomRules.SourceOnlyRule.action 'Log' 'Automatic mode retains a source-only custom rule'
    Assert-Equal $generatedCustomRules.SourceOnlyRule.priority 20 'A source-only rule keeps the priority freed by a shared source choice'
    Assert-Equal $generatedCustomRules.TargetOnlyRule.action 'Block' 'Automatic mode retains a target-only custom rule'
    $generatedDrs = @($autoResource.properties.managedRules.managedRuleSets |
        Where-Object ruleSetType -EQ 'Microsoft_DefaultRuleSet')[0]
    Assert-Equal $generatedDrs.ruleSetAction 'Block' 'Automatic mode selects the source DRS global action'
    Assert-Equal $generatedDrs.exclusions[0].selector 'source-global' 'Automatic mode selects source global exclusions'
    Assert-Equal $generatedDrs.ruleGroupOverrides[0].exclusions[0].selector 'source-group' 'Automatic mode selects source group exclusions'
    Assert-Equal $generatedDrs.ruleGroupOverrides[0].rules[0].exclusions[0].selector 'source-rule' 'Automatic mode selects source rule exclusions'

    foreach ($manualParameter in 'KeepSource', 'KeepTarget') {
        Assert-InputFailure (@{
            SourcePolicy = $autoSourceFile; MasterPolicy = $autoMasterFile
            TargetPolicyName = 'AutoConflictTest'; Auto = $true; $manualParameter = @('1')
        }) '*-Auto cannot be used with -KeepSource or -KeepTarget*'
    }
    Write-Host 'PASS: automatic report, generation, custom-rule union, source exclusions and manual-selection rejection'

    $compatibleSource = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $compatibleSource.properties.managedRules.managedRuleSets = @(
        @{
            ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.2'; ruleSetAction = 'Block'
            ruleGroupOverrides = @()
        }
        @{
            ruleSetType = 'Microsoft_BotManagerRuleSet'; ruleSetVersion = '1.1'
            ruleGroupOverrides = @(@{
                ruleGroupName = 'BadBots'
                rules = @(
                    @{ ruleId = 'Bot100100'; action = 'Log' }
                    @{ ruleId = 'Bot100300'; action = 'Log' }
                )
            })
        }
    )
    $compatibleSource.properties.managedRules.exceptionsList = @{ exceptions = @(@{
        matchVariable = 'RequestUri'; valueMatchOperator = 'Equals'; matchValues = @('/trusted')
        scopes = @(@{
            ruleSetType = 'Microsoft_BotManagerRuleSet'; ruleSetVersion = '1.1'
            ruleGroupScopes = @(@{ ruleGroupName = 'BadBots'; ruleScopes = @(@{ ruleId = 'Bot100300' }) })
        })
    }) }
    $compatibleMaster = $compatibleSource | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
    $compatibleMaster.properties.managedRules.managedRuleSets[1].ruleSetVersion = '1.0'
    $compatibleMaster.properties.managedRules.managedRuleSets[1].ruleGroupOverrides = @()
    $null = $compatibleMaster.properties.managedRules.Remove('exceptionsList')
    $compatibleSourceFile = Write-InputFixture 'compatibility-source.json' $compatibleSource
    $compatibleMasterFile = Write-InputFixture 'compatibility-master.json' $compatibleMaster
    $compatibleOutput = Join-Path $testDirectory 'compatibility.arm.json'
    $records = @(& $migrationPath -SourcePolicy $compatibleSourceFile -MasterPolicy $compatibleMasterFile `
        -TargetPolicyName CompatibilityTest -Auto -OutputPath $compatibleOutput 3>&1 6>&1)
    $compatibleReport = @($records | Where-Object { $null -ne $_.PSObject.Properties['Decisions'] })[0]
    $unsupported = @($compatibleReport.Decisions | Where-Object { $_.CompatibilityIssues.Count })
    Assert-Equal ($unsupported.Count -gt 0) $true 'The downgrade has explicitly unsupported source choices'
    Assert-Equal @($unsupported | Where-Object Choice -ne 'KeepTarget').Count 0 'Automatic mode retains target for unsupported managed carryover'
    Assert-Equal (($records -join "`n").Contains('KeepSource cannot be used')) $true 'Unsupported automatic carryover has visible compatibility diagnostics'
    $compatibleTemplate = Get-Content -LiteralPath $compatibleOutput -Raw | ConvertFrom-Json -AsHashtable
    $compatibleManaged = $compatibleTemplate.resources[0].properties.managedRules
    $compatibleBot = @($compatibleManaged.managedRuleSets | Where-Object ruleSetType -EQ 'Microsoft_BotManagerRuleSet')[0]
    Assert-Equal $compatibleBot.ruleSetVersion '1.0' 'Automatic mode retains the configured target version'
    $compatibleRules = @($compatibleBot.ruleGroupOverrides.rules)
    Assert-Equal @($compatibleRules | Where-Object ruleId -EQ 'Bot100300').Count 0 'Unsupported source IDs are not copied or remapped'
    Assert-Equal @($compatibleRules | Where-Object ruleId -EQ 'Bot100100')[0].action 'Log' 'Supported source tuning survives alongside unsupported settings'
    Assert-Equal $compatibleManaged.ContainsKey('exceptionsList') $false 'An unsupported source exception is not imported'
    Assert-Equal $compatibleReport.PendingDecisionCount 0 'Unsupported carryover does not leave automatic decisions pending'
    Write-Host 'PASS: automatic compatibility filtering retains supported source tuning without remapping unsupported scopes'

    # Load the pinned definitions to check every common rule's generated effective behavior.
    $catalogTokens = $null
    $catalogErrors = $null
    $catalogAst = [System.Management.Automation.Language.Parser]::ParseFile($migrationPath, [ref] $catalogTokens, [ref] $catalogErrors)
    Assert-Equal $catalogErrors.Count 0 'The embedded catalog script parses'
    foreach ($name in 'Get-EmbeddedDrsCatalog', 'Get-EmbeddedAdditionalManagedCatalog') {
        $definition = $catalogAst.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        Invoke-Expression $definition.Extent.Text
    }
    $catalog = Get-EmbeddedDrsCatalog
    $native20 = $catalog['Microsoft_DefaultRuleSet/2.0'].ruleGroups
    Assert-Equal $native20.Count 17 'DRS 2.0 has exactly 17 native groups'
    Assert-Equal @($native20.rules).Count 170 'DRS 2.0 has exactly 170 native rules'
    Assert-Equal @($native20.rules | Where-Object defaultState -EQ 'Disabled').Count 8 'DRS 2.0 keeps its eight native disabled defaults'
    Assert-Equal @($native20.rules | Where-Object { $_.paranoiaLevel -eq 2 -and $_.defaultState -eq 'Enabled' }).Count 49 'DRS 2.0 has 49 enabled PL2 rules, independent of the 2.2 baseline'

    $savedSourceFixture = $sourceFixture
    try {
        $sourceFixture = $savedSourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
        $sourceFixture.properties.managedRules.managedRuleSets = @(@{
            ruleSetType = 'Microsoft_DefaultRuleSet'; ruleSetVersion = '2.0'; ruleSetAction = 'Log'
            exclusions = @(@{ matchVariable = 'RequestHeaderNames'; selectorMatchOperator = 'Equals'; selector = 'X-Source' })
            ruleGroupOverrides = @(@{
                ruleGroupName = 'SQLI'
                exclusions = @(@{ matchVariable = 'QueryStringArgNames'; selectorMatchOperator = 'Equals'; selector = 'MixedArg' })
                rules = @(
                    @{ ruleId = '942100'; action = 'Log' }
                    @{
                        ruleId = '942200'; enabledState = 'Disabled'; action = 'Log'
                        exclusions = @(@{ matchVariable = 'RequestCookieNames'; selectorMatchOperator = 'Equals'; selector = 'SourceCookie' })
                    }
                )
            }, @{
                ruleGroupName = 'MS-ThreatIntel-WebShells'
                rules = @(@{ ruleId = '99005006'; enabledState = 'Disabled'; action = 'Log' })
            })
        })
        $source20File = Write-InputFixture 'source20.json' $sourceFixture
        # Exercise both target baselines with the same native 2.0 defaults and tuning.
        foreach ($targetVersion in '2.1', '2.2') {
            $master20 = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
            $master20.properties.managedRules.managedRuleSets[0].ruleSetVersion = $targetVersion
            $master20.properties.managedRules.managedRuleSets[0].ruleSetAction = 'Block'
            $master20.properties.managedRules.managedRuleSets[0].ruleGroupOverrides = @()
            $master20File = Write-InputFixture "master-$targetVersion.json" $master20
            # Live reads are mocked; generated ARM must be identical in effective behavior.
            foreach ($inputKind in 'JSON', 'ResourceId') {
                $mockState.AllowContext = $inputKind -eq 'ResourceId'
                $mockState.ReadPaths.Clear()
                $output20 = Join-Path $testDirectory "source20-$targetVersion-$inputKind.arm.json"
                $arguments = @{
                    SourcePolicy = if ($inputKind -eq 'ResourceId') { $sourceId } else { $source20File }
                    MasterPolicy = $master20File; TargetPolicyName = 'Source20Test'; Auto = $true; OutputPath = $output20
                }
                $report20 = & $migrationPath @arguments 3>$null 6>$null
                Assert-Equal $mockState.ReadPaths.Count ([int] ($inputKind -eq 'ResourceId')) 'DRS 2.0 reads Azure only for a resource-ID input'
                Assert-Equal $report20.SourceRuleSetVersion '2.0' 'The original 2.0 source version is retained in reports'
                Assert-Equal $report20.TargetRuleSetVersion $targetVersion 'A master preserves its declared target version'
                Assert-Equal @($report20.DrsRuleInventory | Where-Object RuleSetVersion -EQ '2.0').Count 170 'The structured inventory includes every native 2.0 rule'
                Assert-Equal $report20.PendingDecisionCount 0 'Automatic DRS 2.0 migration resolves every decision'
                $generated20 = Get-Content -LiteralPath $output20 -Raw | ConvertFrom-Json -AsHashtable
                $set20 = $generated20.resources[0].properties.managedRules.managedRuleSets[0]
                Assert-Equal $set20.ruleSetAction 'Log' 'Automatic migration preserves the source ruleset action'
                Assert-Equal $set20.exclusions[0].selector 'X-Source' 'Source ruleset exclusions are preserved'
                $groups20 = @{}
                foreach ($group in $set20.ruleGroupOverrides) { $groups20[$group.ruleGroupName] = $group }
                Assert-Equal $groups20.SQLI.exclusions[0].selector 'MixedArg' 'Source group exclusions preserve argument case'
                $generatedRule200 = @($groups20.SQLI.rules | Where-Object ruleId -EQ '942200')[0]
                Assert-Equal $generatedRule200.exclusions[0].selector 'SourceCookie' 'Source rule exclusions are preserved'
                # Compare native defaults plus explicit tuning, never just the emitted override count.
                foreach ($group in $native20) {
                    $defaults = @($catalog["Microsoft_DefaultRuleSet/$targetVersion"].ruleGroups |
                        Where-Object ruleGroupName -CEQ $group.ruleGroupName)[0]
                    foreach ($rule in $group.rules) {
                        # Resolve sparse overrides against target defaults before checking source fidelity.
                        $targetRules = @($defaults.rules | Where-Object ruleId -CEQ $rule.ruleId)
                        $override = @(
                            if ($groups20.ContainsKey($group.ruleGroupName)) {
                                $groups20[$group.ruleGroupName].rules | Where-Object ruleId -CEQ $rule.ruleId
                            }
                        )
                        if (-not $targetRules.Count) {
                            Assert-Equal $override.Count 0 "Removed source rule $($rule.ruleId) is not emitted in target $targetVersion"
                            continue
                        }
                        $targetRule = $targetRules[0]
                        $state = if ($override.Count -and $override[0].ContainsKey('enabledState')) {
                            $override[0].enabledState
                        } else { $targetRule.defaultState }
                        $action = if ($override.Count -and $override[0].ContainsKey('action')) {
                            $override[0].action
                        } else { $targetRule.defaultAction }
                        $expectedState = if ($rule.ruleId -eq '942200') { 'Disabled' } else { $rule.defaultState }
                        $expectedAction = if ($rule.ruleId -in '942100', '942200', '99005006') { 'Log' } else { $rule.defaultAction }
                        Assert-Equal $state $expectedState "$inputKind target $targetVersion preserves source state for $($rule.ruleId)"
                        Assert-Equal $action $expectedAction "$inputKind target $targetVersion preserves source action for $($rule.ruleId)"
                    }
                }
            }
        }
        # Without a master, source 2.0 still uses the 2.2 baseline; 1.2 must fail explicitly.
        $mockState.AllowContext = $false
        $mockState.ReadPaths.Clear()
        $default20Output = Join-Path $testDirectory 'source20-default.arm.json'
        $default20 = & $migrationPath -SourcePolicy $source20File -TargetPolicyName Default20Test `
            -Auto -OutputPath $default20Output 3>$null 6>$null
        Assert-Equal $default20.TargetRuleSetVersion '2.2' 'Masterless DRS 2.0 migration uses 2.2'
        $default20Template = Get-Content -LiteralPath $default20Output -Raw | ConvertFrom-Json -AsHashtable
        $default20Rules = @($default20Template.resources[0].properties.managedRules.managedRuleSets[0].ruleGroupOverrides.rules)
        Assert-Equal @($default20Rules | Where-Object ruleId -EQ '99005002')[0].enabledState 'Enabled' 'Masterless automatic migration restores native source PL2 coverage'
        $unsupported12 = $sourceFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
        $unsupported12.properties.managedRules.managedRuleSets[0].ruleSetVersion = '1.2'
        $unsupported12File = Write-InputFixture 'unsupported12.json' $unsupported12
        Assert-InputFailure @{ SourcePolicy = $unsupported12File; TargetPolicyName = 'Unsupported12Test'; ReportOnly = $true } '*does not support managed rule set Microsoft_DefaultRuleSet/1.2*'
    } finally {
        $sourceFixture = $savedSourceFixture
        $mockState.AllowContext = $false
        $mockState.ReadPaths.Clear()
    }
    Write-Host 'PASS: native DRS 2.0 inventory and automatic state/action/exclusion preservation for JSON and live-ID inputs'

    foreach ($protectedFile in $sourceFile, $masterFile, $migrationPath) {
        Assert-InputFailure @{
            SourcePolicy = $sourceFile; MasterPolicy = $masterFile
            TargetPolicyName = 'ProtectedTest'; OutputPath = $protectedFile; Force = $true
        } '*OutputPath must not overwrite the source, master or script*'
    }
    Assert-Equal (Get-FileHash -LiteralPath $sourceFile).Hash $sourceHash 'Source file is unchanged'
    Assert-Equal (Get-FileHash -LiteralPath $masterFile).Hash $masterHash 'Master file is unchanged'
    Assert-Equal $mockState.ReadPaths.Count 0 'File inputs with embedded IDs never fetch Azure values'
    Write-Host 'PASS: canonical parameters, masterless files, ARM generation, escaped literals and input/output protection'

    foreach ($invalid in @(
        @{ Name = 'array.json'; Document = @($sourceFixture); Pattern = '*JSON must be a resource object or an ARM template object*' }
        @{ Name = 'null.json'; Document = $null; Pattern = '*JSON must be a resource object or an ARM template object*' }
        @{ Name = 'empty-template.json'; Document = @{ resources = @() }; Pattern = '*exactly one Front Door WAF resource*' }
        @{ Name = 'multiple-template.json'; Document = @{ resources = @($sourceFixture, $sourceFixture) }; Pattern = '*exactly one Front Door WAF resource*' }
        @{ Name = 'bad-resources.json'; Document = @{ resources = $sourceFixture }; Pattern = '*resources must be a JSON array*' }
        @{ Name = 'wrong-type.json'; Document = @{ type = 'Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies'; properties = @{} }; Pattern = '*Front Door WAF resource with policy properties*' }
        @{ Name = 'missing-name.json'; Document = @{ type = $sourceFixture.type; properties = $sourceFixture.properties }; Pattern = '*nonempty policy name*' }
        @{ Name = 'expression.json'; Document = @{ resources = @(@{ type = $sourceFixture.type; name = "[parameters('name')]"; properties = $sourceFixture.properties }) }; Pattern = '*ARM expression*' }
    )) {
        $invalidFile = Write-InputFixture $invalid.Name $invalid.Document
        Assert-InputFailure @{ SourcePolicy = $invalidFile; TargetPolicyName = 'InvalidTest'; ReportOnly = $true } $invalid.Pattern
    }
    Assert-InputFailure @{ SourcePolicy = $testDirectory; TargetPolicyName = 'DirectoryTest'; ReportOnly = $true } '*filesystem JSON file*'
    Assert-InputFailure @{ SourcePolicy = '/subscriptions/not-a-guid/resourceGroups/Test/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/Test'; TargetPolicyName = 'IdTest'; ReportOnly = $true } '*complete Front Door WAF policy resource ID*'
    Assert-InputFailure @{ SourcePolicy = $sourceFile; MasterPolicy = $sourceFile.Replace('source.json', 'missing.json'); TargetPolicyName = 'MissingTest'; ReportOnly = $true } '*does not exist*'
    $malformedFile = Join-Path $testDirectory 'malformed.json'
    '{' | Set-Content -LiteralPath $malformedFile
    Assert-InputFailure @{ SourcePolicy = $malformedFile; TargetPolicyName = 'MalformedTest'; ReportOnly = $true } '*Conversion from JSON failed*'
    foreach ($invalidMaster in @(
        @{ Field = 'sku'; Value = @{ name = 'Standard_AzureFrontDoor' }; Pattern = '*Master must use Premium_AzureFrontDoor*' }
        @{ Field = 'location'; Value = 'westus'; Pattern = '*Master Front Door WAF location must be Global*' }
    )) {
        $fixture = $masterFixture | ConvertTo-Json -Depth 100 | ConvertFrom-Json -AsHashtable
        $fixture[$invalidMaster.Field] = $invalidMaster.Value
        $invalidFile = Write-InputFixture "invalid-master-$($invalidMaster.Field).json" $fixture
        Assert-InputFailure @{ SourcePolicy = $sourceFile; MasterPolicy = $invalidFile; TargetPolicyName = 'MasterTest'; ReportOnly = $true } $invalidMaster.Pattern
    }

    $mockState.AllowContext = $true
    $mockState.ContextAvailable = $false
    Assert-InputFailure @{ SourcePolicy = $sourceId; TargetPolicyName = 'ContextTest'; ReportOnly = $true } '*No authenticated Az context*'
    $mockState.ContextAvailable = $true
    $otherSubscription = $masterId.Replace($subscriptionId, '00000000-0000-0000-0000-000000000002')
    foreach ($arguments in @(
        @{ SourcePolicy = $otherSubscription }
        @{ SourcePolicy = $sourceId; MasterPolicy = $otherSubscription }
    )) {
        Assert-InputFailure ($arguments + @{ TargetPolicyName = 'SubscriptionTest'; ReportOnly = $true }) '*does not match policy subscription*'
    }
    Assert-Equal $mockState.ReadPaths.Count 0 'Invalid contexts and mismatched subscriptions fail before all Azure GETs'
    Write-Host 'PASS: malformed JSON shapes, resource identities, missing files and live-context failures'

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($migrationPath, [ref] $tokens, [ref] $errors)
    Assert-Equal $errors.Count 0 'Migration script parses successfully'
    foreach ($definition in $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)) {
        $help = $definition.Body.GetHelpContent()
        Assert-Equal ([string]::IsNullOrWhiteSpace($help.Synopsis)) $false "$($definition.Name) has a synopsis"
        Assert-Equal ([string]::IsNullOrWhiteSpace($help.Description)) $false "$($definition.Name) has a description"
    }
    Assert-Equal ((Get-Content -LiteralPath $migrationPath -Raw) -match '(?i)not specified') $false 'All unspecified report situations use ---'
    Write-Host 'PASS: complete function help and no remaining Not specified markers'
}
finally {
    # Delete only generated files within this test's unique directory, never a broad tree.
    foreach ($file in (Get-ChildItem -LiteralPath $testDirectory -File)) { Remove-Item -LiteralPath $file.FullName }
    Remove-Item -LiteralPath $testDirectory
}
#endregion
