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
    foreach ($arguments in @(
        @{ SourcePolicyResourceId = $sourceFile; MasterPolicyPath = $masterFile }
        @{ SourcePolicyPath = $sourceFile; MasterPolicyResourceId = $masterFile }
    )) {
        $report = & $migrationPath @arguments -TargetPolicyName AliasTest -ReportOnly 3>$null 6>$null
        Assert-Equal $report.DecisionCount 1 'Legacy parameter names and new aliases accept either input format'
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
            name = 'SourceOnlyRule'; enabledState = 'Enabled'; priority = 11
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
    $autoReport = & $migrationPath -SourcePolicy $autoSourceFile -MasterPolicy $autoMasterFile `
        -TargetPolicyName AutoReportTest -Auto -ReportOnly 3>$null 6>$null
    Assert-Equal $autoReport.OutputPath $null 'Automatic report-only mode writes no output'
    Assert-Equal $autoReport.PendingDecisionCount 0 'Automatic mode resolves every displayed decision'
    Assert-Equal @($autoReport.Decisions | Where-Object {
        $_.DecisionKind -eq 'TargetCustomRule' -and $_.Choice -ne 'KeepTarget'
    }).Count 0 'Automatic mode retains every target-only custom rule'
    Assert-Equal @($autoReport.Decisions | Where-Object {
        $_.DecisionKind -ne 'TargetCustomRule' -and $_.Choice -ne 'KeepSource'
    }).Count 0 'Automatic mode selects source for every other decision'

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

    foreach ($protectedFile in $sourceFile, $masterFile, $migrationPath) {
        Assert-InputFailure @{
            SourcePolicy = $sourceFile; MasterPolicy = $masterFile
            TargetPolicyName = 'ProtectedTest'; OutputPath = $protectedFile; Force = $true
        } '*OutputPath must not overwrite the source, master or script*'
    }
    Assert-Equal (Get-FileHash -LiteralPath $sourceFile).Hash $sourceHash 'Source file is unchanged'
    Assert-Equal (Get-FileHash -LiteralPath $masterFile).Hash $masterHash 'Master file is unchanged'
    Assert-Equal $mockState.ReadPaths.Count 0 'File inputs with embedded IDs never fetch Azure values'
    Write-Host 'PASS: aliases, masterless files, ARM generation, escaped literals and input/output protection'

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
