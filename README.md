# Azure Front Door WAF migration

[`New-WafMigrationTemplate.ps1`](New-WafMigrationTemplate.ps1) compares an
existing Azure Front Door WAF policy with an optional master policy and creates
an ARM template for a new Premium policy.

The script reads Azure only when an input is a resource ID. It does not deploy,
update policies, change Front Door associations, or change the active Azure
context.
Startup messages identify input loading, catalog initialization, baseline
validation, and comparison planning. Compatibility checks show progress by
review-decision count. These messages use the host/information stream and do
not alter the structured migration summary returned by the script.

## Requirements

- PowerShell 7
- `Az.Accounts`
- An authenticated Azure context only for resource-ID inputs

Both source and master inputs can be:

- A Front Door WAF resource ID.
- A JSON resource export.
- An ARM template containing exactly one literal Front Door WAF resource.

The master must use `Premium_AzureFrontDoor` and `Global`. ARM expressions in
input policy fields are rejected.

Use the same parameter names for either input format:

```powershell
# JSON inputs; no authenticated Azure context is required.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source.json `
    -MasterPolicy .\Templates\mastertemplate.json `
    -TargetPolicyName newPolicy `
    -Auto `
    -ReportOnly

# Live policy inputs; authenticate and select their subscription first.
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy '/subscriptions/<subscription-id>/resourceGroups/<source-group>/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/<source-policy>' `
    -MasterPolicy '/subscriptions/<subscription-id>/resourceGroups/<master-group>/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies/<master-policy>' `
    -TargetPolicyName newPolicy `
    -Auto `
    -ReportOnly
```

JSON and resource-ID inputs can also be mixed. Both live inputs must belong to
the subscription in the selected Az context or supplied `DefaultProfile`.
`MasterPolicy` is optional.

## Supported managed rules

| Ruleset | Versions |
|---|---|
| `Microsoft_DefaultRuleSet` | 1.0, 1.1, 2.0, 2.1, 2.2 |
| `Microsoft_BotManagerRuleSet` | 1.0, 1.1 |
| `Microsoft_HTTPDDoSRuleSet` | 1.0 |

Managed-rule catalogs are embedded in the script. No documentation or catalog
download occurs at runtime.
DRS 1.0, 1.1, and 2.0 are supported as source versions; generated DRS targets
use 2.1 or 2.2. DRS 1.2 is not supported because a verified native catalog is
not available.

When a master is supplied, its managed-rule versions are preserved. Without a
master, source-configured families use DRS 2.2, Bot Manager 1.1, and HTTP DDoS
1.0. A family absent from both policies remains absent.

## Selection modes

### Report only

Use `-ReportOnly` to inspect differences without prompts or output:

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source.json `
    -MasterPolicy .\Templates\mastertemplate.json `
    -TargetPolicyName newPolicy `
    -ReportOnly
```

### Automatic

Use `-Auto` to resolve decisions as follows:

- Policy settings, tags, managed-rule settings, exclusions, and exceptions:
  select source whenever compatible with the target version.
- Unsupported managed-rule carryover: retain the target choice and report
  the incompatibility. Removed rule settings and scopes are not remapped to
  replacement IDs.
- Custom rule only in source: select source.
- Custom rule in both policies with the same name: select source.
- Custom rule only in target: retain target.

`-Auto` can be combined with `-ReportOnly`. It cannot be combined with
`-KeepSource` or `-KeepTarget`.

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source.json `
    -MasterPolicy .\Templates\mastertemplate.json `
    -TargetPolicyName newPolicy `
    -Auto `
    -ReportOnly
```

Without `-ReportOnly`, automatic mode writes the ARM template. If retained
custom rules have duplicate priorities, the script asks for an unused priority.
The custom-rule table shows source, master, and selected priorities separately;
these are not automatic renumbering instructions. Warnings use the selected
merged rules, so a master priority freed by a same-name source selection is not
reported as occupied. When all custom choices are known, priority resolution
also reserves the priorities of source rules that will be applied later.
Retained master rules are never silently removed or renumbered.
Invalid source baselines and invalid combinations of selected settings still
stop generation; automatic mode does not hide validation errors.

### Manual

Without `-Auto`, unresolved decisions prompt during generation. Decisions can
also be supplied by report row ID:

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source.json `
    -MasterPolicy .\Templates\mastertemplate.json `
    -TargetPolicyName newPolicy `
    -KeepSource 1,2,'4-19' `
    -KeepTarget 3 `
    -OutputPath .\newPolicy.arm.json
```

The same row cannot appear in both selections. Unselected rows prompt.

## Parameters

| Parameter | Purpose |
|---|---|
| `SourcePolicy` | Source resource ID or JSON file |
| `MasterPolicy` | Optional master resource ID or JSON file |
| `TargetPolicyName` | Name of the generated WAF policy |
| `ReportOnly` | Show comparisons without writing a file |
| `Auto` | Select compatible source; retain target-only custom rules |
| `KeepSource` | Source decision IDs or ranges |
| `KeepTarget` | Target decision IDs or ranges |
| `OutputPath` | ARM template path |
| `Force` | Replace an existing output file |
| `DefaultProfile` | Explicit Az context for resource-ID inputs |

Use `SourcePolicy` and `MasterPolicy` for either resource IDs or JSON files.

## Compared configuration

The script compares:

- Policy settings and tags.
- Custom rules by case-sensitive name.
- Effective managed-rule state and action.
- DRS ruleset, group, and individual-rule exclusions.
- Managed request exceptions and their scopes.
- Bot Manager and HTTP DDoS family membership and settings.

Equal effective settings produce no decision. Original and replacement DRS
rule IDs remain independent; settings are never transferred automatically.
Sensitive exception match values are not printed in report output.
Exclusion comparisons ignore header and cookie selector case, but preserve
case for query-string, POST, and JSON argument selectors. Original selector
spelling is retained in the selected configuration.

## Output and deployment

Generation writes a resource-group ARM template. Validate and deploy it
separately:

```powershell
Test-AzResourceGroupDeployment `
    -ResourceGroupName '<resource-group>' `
    -TemplateFile .\newPolicy.arm.json

New-AzResourceGroupDeployment `
    -ResourceGroupName '<resource-group>' `
    -TemplateFile .\newPolicy.arm.json `
    -WhatIf
```

Remove `-WhatIf` only after reviewing the deployment.

## Templates

- [`Templates/mastertemplate.json`](Templates/mastertemplate.json) is a
  sanitized example and the only tracked file in `Templates`.
- Other files in `Templates` and all JSON files in `Tests` remain local and
  are ignored by Git.

## Tests

Run the maintained PowerShell test scripts:

```powershell
pwsh -NoProfile -File .\Tests\Test-WafMigrationFormatting.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationReport.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationInputs.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationExceptions.ps1
```

The suites cover JSON and mocked live inputs, DRS 2.0 migrations to 2.1/2.2,
native defaults and source tuning, custom-rule merging, exclusion case
semantics, scoped exceptions, formatting, report-only behavior, and validation
failures. They do not modify Azure resources.
