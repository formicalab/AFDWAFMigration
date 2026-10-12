# Front Door WAF policy migration

[`New-WafMigrationTemplate.ps1`](New-WafMigrationTemplate.ps1) reads a
Front Door WAF policy from Azure or a JSON file, compares it with a destination configuration, and asks which
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
and state/action defaults for all four versions.

Comparison and validation use these local catalogs. Azure is queried only for
inputs supplied as resource IDs, not to download catalog definitions. Unsupported versions
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

The **master** is an optional policy used as the initial destination configuration.
Like the source, it can be a resource ID (read live from Azure) or a local JSON file.

- **With a master:** use its managed versions, overrides, exclusions, exceptions,
  custom rules, policy settings, and tags.
- **Without a master:** start source-configured managed families from the latest
  included defaults: Microsoft_DefaultRuleSet 2.2, Microsoft_BotManagerRuleSet 1.1,
  and Microsoft_HTTPDDoSRuleSet 1.0. Preserve source custom rules, policy settings,
  and tags. Source managed tuning remains available as review choices.

A family absent from both sides stays absent. Custom-only policies are supported.
Keeping a source setting does not change the destination's ruleset version.

The master must use the Premium Front Door SKU and Global location.
For either input, a JSON file must contain a resource object or an ARM template
with exactly one literal Front Door WAF resource. Unresolved ARM expressions
are rejected; ARM-escaped literals are decoded. Files are used as snapshots;
an `id` field inside a JSON file does not trigger an Azure read.
Source files must include a nonempty policy name.
If the master includes Microsoft_DefaultRuleSet, that version must be 2.1 or 2.2.
`DefaultRuleSet` is accepted as an alias for `Microsoft_DefaultRuleSet`.

[Templates/mastertemplate.json](Templates/mastertemplate.json) is a sanitized example
containing managed versions and rule state/action overrides, without customer
identifiers, custom rules, exclusions, exceptions, log-scrubbing selectors, or
custom responses. Adapt it to your needs.

### Checks and comparisons

The script reviews:

- **Policy settings and tags:** configured differences and optional policy settings.
- **Custom rules:** matched by name; differences in priority, state, action,
  conditions, rule type, and rate-limit settings.
- **Managed rules:** matched by group/rule ID; differences in effective state,
  action, sensitivity, and protection caused by version or override changes.
- **DRS exclusions:** field selectors at ruleset, group, or individual-rule scope.
- **Request exceptions (Preview):** complete request predicates and their scopes,
  independently reviewed for DRS, Bot Manager, and HTTP DDoS.

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
- Exception rows also compare membership. Each complete exception is one choice,
  including all its scopes; a changed predicate or scope yields separate source-only
  and target-only rows. Identical occurrences are paired one-to-one and preserved.

### Front Door request exceptions (Preview)

[Request exceptions](https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/front-door-exceptions)
are **not exclusions**. An exclusion omits selected field values from inspection.
An exception bypasses inspection of the **matching request**, but only for its
listed managed rules, groups, or entire rulesets. Other scopes still inspect it.

The script reads and writes `properties.managedRules.exceptionsList.exceptions`
from either live policy IDs or JSON inputs. It supports:

- `RequestUri`, with exact, partial, or API-supported `EqualsAny` matching.
- `SocketAddr`, with `IPMatch` and literal IPv4/IPv6 addresses or CIDR ranges.
- `RequestHeaderNames`, with an exact header-name `selector`,
  `selectorMatchOperator: Equals`, and separate value matching.
- Multiple scopes within one exception, including entire rulesets, rule groups,
  and specific rule IDs in DRS, Bot Manager, and HTTP DDoS.

The next-generation engine is required: the selected policy must configure
DRS 2.1 or 2.2, including when an exception targets Bot Manager or HTTP DDoS.
Only the embedded families/versions listed above are supported.
Application Gateway and CRS migration are not supported.

The dedicated **Request exceptions (Preview)** report section shows scope,
match variable, header name where applicable, operator, match-value count,
and `Present`/`---`. **Match values are not printed or included in report-only
decision metadata**, because header values can contain credentials. Review
the input JSON or Azure policy to inspect the actual values.

`KeepSource` adds a source-only exception or removes a target-only exception.
`KeepTarget` retains the destination's membership. No exception is split into
independent scope choices, broadened, or transferred to a replacement rule.
Source scope versions follow the destination versions without changing the
destination's versions or rule identities. An unavailable rule/group makes
KeepSource unavailable, with a warning beside the exception row.
If an exception needs a family introduced by another choice, final validation
requires that family to actually be present before writing the template.

Without a master, exceptions for supported managed families start absent and
are offered as source review choices, like other managed tuning. The selected
entries are applied after rule/group choices and validated together.

Local validation enforces 60 exceptions per policy, up to 600 IP match values
or 10 URI/header match values per exception, valid predicates, and configured
catalog scopes. The aggregate limit of 60 across policies associated with one
Front Door cannot be checked from these policy inputs alone; verify associations,
preview availability, and service acceptance using Azure deployment validation
and what-if before deployment.

### Choosing settings

Run with `-ReportOnly` first. It shows numbered comparisons and warnings without
prompts, changes to the destination configuration, or output files.
Compatibility and unresolved custom-priority warnings appear immediately below
their comparison rows, including wrapped tables and narrow-console list layouts.

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

In the report, `---` means an absent or unspecified value, `*` marks a setting that differs from its
documented defaults, and green highlights identify selected rows and values.
Exclusions and request exceptions use `Present`/`---`, without default markers.

Tags are labeled `Tag: <exact tag key>`. Their cells use `Existing value` when
present and `---` when absent; tag contents are not printed. Target-only tags
retain the master's values without requiring a choice.

Bot/HTTP rule names come from each version's native catalog. A rule labeled
`absent from target v1.0` exists in the source version but not in target version
1.0; it does **not** mean the embedded catalog is missing its definition.
For example, moving Bot Manager 1.1 to 1.0 removes `Bot100300` and
`Bot200300` through `Bot200700`. Their target cells show `---`, and KeepSource
cannot copy them into 1.0. Select a 1.1 master if you need to retain those rules;
the script never changes the master's version automatically.
`Bot200200` also changes meaning: 1.1 uses **Verified misc bots / Allow**, while
1.0 uses **Unverified search engine crawlers / Log**. Both descriptions and their
versions are shown when definitions differ; copying an action does not copy
the source version's bot classification.

For Bot/HTTP, a rule-set action of `---` means that field is omitted,
not that inspection is disabled. Read the individual rule rows for their
effective actions.

**Use fresh row numbers after changing either input.** Choices apply to their own
scope, not the whole policy. Once resolved, the script validates the result and
writes the template; source and master inputs remain unchanged.

This compares configuration, not request-matching equivalence between versions.
Deployment validation, deployment, association changes, and traffic/log testing
are separate steps.

## Part 2 - Syntax and examples

### Requirements and syntax

- PowerShell **7** and **Az.Accounts**.
- The migration script is **self-contained**. No companion files are required.
  Local JSON inputs are needed only
  when you explicitly supply them instead of resource IDs.
- For resource-ID inputs, an authenticated Az context with read permission on each
  live policy. Every live ID must match the selected subscription; the script does
  not switch subscriptions. Use a JSON export to compare policies from different
  subscriptions.
- File-only runs require no Azure sign-in or context. Az.Accounts must still be
  installed because the script declares it as a dependency.
- Application Gateway WAF is not supported.
- An existing output directory. Target names start with a letter and contain
  only letters/digits, up to 128 characters.

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy <resource-id-or-json-path> `
    -TargetPolicyName <string> `
    [-MasterPolicy <resource-id-or-json-path>] `
    [-ReportOnly] `
    [-KeepSource <string[]>] `
    [-KeepTarget <string[]>] `
    [-OutputPath <string>] `
    [-Force] `
    [-DefaultProfile <PSAzureContext>]
```

| Parameter | Purpose |
|---|---|
| `SourcePolicy` | Required source resource ID or JSON file path; alias for `SourcePolicyResourceId`. `SourcePolicyPath` is also accepted. |
| `TargetPolicyName` | Required new Premium policy name |
| `MasterPolicy` | Optional master resource ID or JSON file path; alias for `MasterPolicyPath`. `MasterPolicyResourceId` is also accepted. |
| `ReportOnly` | Compare without prompts or output |
| `KeepSource`, `KeepTarget` | Report IDs/ranges, such as `1,2,'4-19'` |
| `OutputPath` | Defaults to `<TargetPolicyName>.arm.json` in the current directory |
| `Force` | Allow replacing an output file, never an input |
| `DefaultProfile` | Optional explicit Az context for live reads; ignored in file-only runs |

### 1. Choose source and master inputs

Sign in only when at least one input is a resource ID:
```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId '<subscription-id>'

$sourceId = '/subscriptions/<subscription-id>/resourceGroups/<source-rg>/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/<source-policy>'
$masterId = '/subscriptions/<subscription-id>/resourceGroups/<master-rg>/providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/<master-policy>'
```

The script uses the selected context; it does not switch subscriptions. Resource
IDs are fetched with GET requests on every run. A path always uses the file's
contents, even if the JSON includes a resource ID.

### 2. Preview without or with a master

```powershell
# Latest included defaults for source-configured managed families.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy $sourceId `
    -TargetPolicyName newPolicy `
    -ReportOnly

# Versions and settings from a master.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy $sourceId `
    -TargetPolicyName newPolicy `
    -MasterPolicy .\Templates\mastertemplate.json `
    -ReportOnly

# Both policies read live from Azure.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy $sourceId `
    -MasterPolicy $masterId `
    -TargetPolicyName newPolicy `
    -ReportOnly

# Entirely offline, using JSON exports or literal ARM templates.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source-policy.json `
    -MasterPolicy .\Templates\mastertemplate.json `
    -TargetPolicyName newPolicy `
    -ReportOnly

# A file source with a live master is also supported.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source-policy.json `
    -MasterPolicy $masterId `
    -TargetPolicyName newPolicy `
    -ReportOnly
```

For a 2.1 destination, use a master declaring Microsoft_DefaultRuleSet 2.1.
There is no separate target-version parameter.

### 3. Choose and generate

Omit `-ReportOnly` to choose interactively and generate the template:

```powershell
$result = .\New-WafMigrationTemplate.ps1 `
    -SourcePolicy $sourceId `
    -TargetPolicyName newPolicy `
    -MasterPolicy .\Templates\mastertemplate.json `
    -OutputPath .\newPolicy.arm.json
```

To preselect choices, use IDs from your current report. These numbers are examples:

```powershell
$migration = @{
    SourcePolicy           = $sourceId
    TargetPolicyName       = 'newPolicy'
    MasterPolicy           = '.\Templates\mastertemplate.json'
    KeepSource             = @('1', '2', '4-19', '23')
    KeepTarget             = @('3', '20-22')
}

.\New-WafMigrationTemplate.ps1 @migration -ReportOnly
$result = .\New-WafMigrationTemplate.ps1 @migration -OutputPath .\newPolicy.arm.json
```

Unlisted rows and priority conflicts still prompt. Omit `MasterPolicy` to
generate without a master. Use `-Force` to replace an existing output file.

### 4. Inspect results and export the catalog

```powershell
$report = .\New-WafMigrationTemplate.ps1 `
    -SourcePolicy $sourceId -TargetPolicyName newPolicy -ReportOnly

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
