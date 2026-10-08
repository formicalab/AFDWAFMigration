# Front Door WAF policy migration

[`New-WafMigrationTemplate.ps1`](New-WafMigrationTemplate.ps1) reads an existing
Front Door WAF policy, compares it with a destination configuration, and asks which
settings to keep. It then writes an ARM template for a new Premium WAF policy.
**It does not deploy or change Azure policies or Front Door associations.**

- [Part 1 - How it works](#part-1---how-it-works)
- [Part 2 - Syntax and examples](#part-2---syntax-and-examples)

## Part 1 - How it works

### Catalogs and supported versions

A **catalog** lists a managed ruleset's groups, rules, and default states/actions.
If a policy has no override for a rule, that rule uses its version's defaults.
It does not mean the rule is disabled.

The catalogs are stored in the script:

| Ruleset | Included versions |
|---|---|
| Microsoft_DefaultRuleSet | 1.0, 1.1, 2.1, 2.2 |
| Microsoft_BotManagerRuleSet | 1.0, 1.1 |
| Microsoft_HTTPDDoSRuleSet | 1.0 |

Microsoft_DefaultRuleSet supports **source versions 1.0, 1.1, 2.1, and 2.2** and
**destination versions 2.1 and 2.2**. The catalogs contain the rule membership
and state/action defaults for all four versions; the snapshot was verified on
2026-10-08.

Comparison and validation use these local catalogs. Azure is queried only to
read the source policy, not to download catalog definitions. Unsupported versions
require a catalog update in the script. Missing paranoia-level metadata is shown
as `Not documented`.

See Microsoft's [managed rules documentation](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs)
for background. Rule descriptions come from Microsoft documentation under CC BY 4.0.

### Effective source and destination

The script compares the resulting rule settings, not just the JSON overrides:

```text
Effective source      = original source-version defaults + source policy overrides
Effective destination = destination-version defaults     + destination overrides
```

It also considers policy state/mode, HTTP DDoS sensitivity, DRS exclusions, and
request exceptions.

For example, `RFI/931130` defaults to Enabled in Microsoft_DefaultRuleSet 1.1 but
Disabled in 2.2. The policies differ even when neither has an override.
Each side uses its own version's defaults throughout the comparison.

A family that is not configured in a policy provides no inspection on that side.
This differs from a configured family whose rules simply have no overrides.

### The optional master

The **master** is a local JSON file used as the initial destination configuration.

- **With a master:** use its managed versions, overrides, exclusions, exceptions,
  custom rules, policy settings, and tags.
- **Without a master:** start source-configured managed families from the latest
  included defaults: Microsoft_DefaultRuleSet 2.2, Microsoft_BotManagerRuleSet 1.1,
  and Microsoft_HTTPDDoSRuleSet 1.0. Preserve source custom rules, policy settings,
  and tags. Source managed tuning remains available as review choices.

A family absent from both sides stays absent. Custom-only policies are supported.
Keeping a source setting does not change the destination's ruleset version.

The master must be a Premium Front Door WAF resource export or an ARM template
with one literal WAF resource. Unresolved ARM expressions are rejected.
If it includes Microsoft_DefaultRuleSet, that version must be 2.1 or 2.2.
`DefaultRuleSet` is accepted as an alias for `Microsoft_DefaultRuleSet`.

[Templates/mastertemplate.json](Templates/mastertemplate.json) is a sanitized example. It retains the original
managed versions and rule state/action overrides, but removes customer identifiers,
custom rules, exclusions, exceptions, log-scrubbing selectors, and custom responses.
Adapt it to your needs; it is not equivalent to the original policy.
Other files in `Templates`, test contents, and reports are ignored by Git.

### Checks and comparisons

The script reviews:

- **Policy settings and tags:** configured differences and optional policy settings.
- **Custom rules:** matched by name; differences in priority, state, action,
  conditions, rule type, and rate-limit settings.
- **Managed rules:** matched by group/rule ID; differences in effective state,
  action, sensitivity, and protection caused by version or override changes.
- **DRS exclusions and exceptions:** criteria and scopes, including exclusions
  for the entire ruleset, a group, or a specific rule.

It validates supported fields, catalog identities, scopes, and custom priorities
before writing the selected configuration.

Comparison rules:

- Equal effective settings need no choice, even if one side writes an explicit
  override and the other uses the same default.
- For DRS only, `Block` and `AnomalyScoring` are equivalent. Source blocking
  choices use `AnomalyScoring` in DRS 2.x. Other actions remain distinct.
- Original and replacement rule IDs have separate choices. Settings and exclusions
  are not transferred between them.
- New DRS rules without a source tuning/protection conflict keep destination
  defaults. Mapped replacements and Bot/HTTP presence differences can require choices.
- Exclusion rows compare membership only. Identical entries at the same scope
  are omitted from the report and preserved in the output.

### Choosing settings

Run with `-ReportOnly` first. It shows numbered comparisons and warnings without
prompts, changes to the destination configuration, or output files.

| Choice | Effect on the selected row |
|---|---|
| `KeepSource` | Apply the compatible source setting |
| `KeepTarget` | Keep the destination setting |
| Quit | Cancel without writing a template |

Choosing an absent side can remove an optional item or disable a newly introduced
managed rule. If source settings cannot be copied, KeepSource is unavailable.
If a source custom priority is occupied, you must select an unused priority.

Run without `-ReportOnly` to choose interactively:

```text
[12] Choose Keep[S]ource, Keep[T]arget, or [Q]uit
```

Or pass row numbers/ranges through `-KeepSource` and `-KeepTarget`.
Unlisted rows prompt during generation. Report-only presets only preview choices.
The same row cannot be selected by both parameters.

In the report, `---` means absence, `*` marks a setting that differs from its
documented defaults, and green highlights identify selected rows and values.
Exclusions use `Present`/`---`, without default markers.

**Use fresh row numbers after changing either input.** Choices apply to their own
scope, not the whole policy. Once resolved, the script validates the result and
writes the template; source and master inputs remain unchanged.

This compares configuration, not request-matching equivalence between versions.
Deployment validation, deployment, association changes, and traffic/log testing
are separate steps.

## Part 2 - Syntax and examples

### Requirements and syntax

- PowerShell **7** and **Az.Accounts**.
- An authenticated context matching the source subscription, with read permission
  on the source policy. Application Gateway WAF is not supported.
- An existing output directory. Target names start with a letter and contain
  only letters/digits, up to 128 characters.

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicyResourceId <string> `
    -TargetPolicyName <string> `
    [-MasterPolicyPath <string>] `
    [-ReportOnly] `
    [-KeepSource <string[]>] `
    [-KeepTarget <string[]>] `
    [-OutputPath <string>] `
    [-Force] `
    [-DefaultProfile <PSAzureContext>]
```

| Parameter | Purpose |
|---|---|
| `SourcePolicyResourceId` | Required full source-policy resource ID |
| `TargetPolicyName` | Required new Premium policy name |
| `MasterPolicyPath` | Optional destination baseline file |
| `ReportOnly` | Compare without prompts or output |
| `KeepSource`, `KeepTarget` | Report IDs/ranges, such as `1,2,'4-19'` |
| `OutputPath` | Defaults to `<TargetPolicyName>.arm.json` in the current directory |
| `Force` | Allow replacing an output file, never an input |
| `DefaultProfile` | Optional explicit Az context |

`UseRecommendedTarget` is obsolete; use KeepSource/KeepTarget instead.

### 1. Sign in and identify the source

```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId '<subscription-id>'

$sourceId = '/subscriptions/<subscription-id>/resourceGroups/<source-rg>/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/<source-policy>'
```

The script uses the selected context; it does not switch subscriptions.

### 2. Preview without or with a master

```powershell
# Latest included defaults for source-configured managed families.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicyResourceId $sourceId `
    -TargetPolicyName newPolicy `
    -ReportOnly

# Versions and settings from a master.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicyResourceId $sourceId `
    -TargetPolicyName newPolicy `
    -MasterPolicyPath .\Templates\mastertemplate.json `
    -ReportOnly
```

For a 2.1 destination, use a master declaring Microsoft_DefaultRuleSet 2.1.
There is no separate target-version parameter.

### 3. Choose and generate

Omit `-ReportOnly` to choose interactively and generate the template:

```powershell
$result = .\New-WafMigrationTemplate.ps1 `
    -SourcePolicyResourceId $sourceId `
    -TargetPolicyName newPolicy `
    -MasterPolicyPath .\Templates\mastertemplate.json `
    -OutputPath .\newPolicy.arm.json
```

To preselect choices, use IDs from your current report. These numbers are examples:

```powershell
$migration = @{
    SourcePolicyResourceId = $sourceId
    TargetPolicyName       = 'newPolicy'
    MasterPolicyPath       = '.\Templates\mastertemplate.json'
    KeepSource             = @('1', '2', '4-19', '23')
    KeepTarget             = @('3', '20-22')
}

.\New-WafMigrationTemplate.ps1 @migration -ReportOnly
$result = .\New-WafMigrationTemplate.ps1 @migration -OutputPath .\newPolicy.arm.json
```

Unlisted rows and priority conflicts still prompt. Omit `MasterPolicyPath` to
generate without a master. Use `-Force` to replace an existing output file.

### 4. Inspect results and export the catalog

```powershell
$report = .\New-WafMigrationTemplate.ps1 `
    -SourcePolicyResourceId $sourceId -TargetPolicyName newPolicy -ReportOnly

$report.Decisions |
    Select-Object Id, Scope, RuleSetType, RuleId, Choice, CompatibilityIssues
$report.ManagedRuleRiskAnalysis
$report.CustomRuleBehaviorAssessments

$report.DrsRuleInventory | Export-Csv .\DrsRuleInventory.csv -NoTypeInformation
```

The result contains versions, decision counts, diagnostics, and rule inventories.
Report-only decisions omit candidate values. After generation, the template path
is in `$result.OutputPath`.

### 5. Validate and deploy separately

These commands require **Az.Resources**, deployment permissions, and an existing
destination resource group. Review what-if before deploying.

```powershell
$deployment = @{
    ResourceGroupName = '<destination-rg>'
    TemplateFile      = '.\newPolicy.arm.json'
}

Test-AzResourceGroupDeployment @deployment
New-AzResourceGroupDeployment @deployment -WhatIf
New-AzResourceGroupDeployment @deployment -Name 'wafMigration'
```

Then configure Front Door associations and verify traffic, logs, and rollback.
