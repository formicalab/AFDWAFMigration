# Azure Front Door WAF migration

[`New-WafMigrationTemplate.ps1`](New-WafMigrationTemplate.ps1) compares an
existing Azure Front Door WAF policy with an optional master policy and creates
an ARM template for a new Premium policy.

The script reads Azure only when an input is a resource ID. It does not deploy,
update policies, change Front Door associations, or change the active Azure
context.

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

## Supported managed rules

| Ruleset | Versions |
|---|---|
| `Microsoft_DefaultRuleSet` | 1.0, 1.1, 2.1, 2.2 |
| `Microsoft_BotManagerRuleSet` | 1.0, 1.1 |
| `Microsoft_HTTPDDoSRuleSet` | 1.0 |

Managed-rule catalogs are embedded in the script. No documentation or catalog
download occurs at runtime.

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
  select source.
- Custom rule only in source: select source.
- Custom rule in both policies with the same name: select source.
- Custom rule only in target: retain target.

`-Auto` can be combined with `-ReportOnly`. It cannot be combined with
`-KeepSource` or `-KeepTarget`.

```powershell
.\New-WafMigrationTemplate.ps1 `
    -SourcePolicy .\source.json `
    -MasterPolicy .\Templates\masterfdwafpremium01.json `
    -TargetPolicyName newPolicy `
    -Auto `
    -ReportOnly
```

Without `-ReportOnly`, automatic mode writes the ARM template. If retained
custom rules have duplicate priorities, the script asks for an unused priority.

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
| `Auto` | Select source except for target-only custom rules |
| `KeepSource` | Source decision IDs or ranges |
| `KeepTarget` | Target decision IDs or ranges |
| `OutputPath` | ARM template path |
| `Force` | Replace an existing output file |
| `DefaultProfile` | Explicit Az context for resource-ID inputs |

`SourcePolicyResourceId`, `SourcePolicyPath`, `MasterPolicyPath`, and
`MasterPolicyResourceId` remain accepted parameter names.

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
  sanitized example.
- [`Templates/masterfdwafpremium-drs22.json`](Templates/masterfdwafpremium-drs22.json)
  is the DRS 2.2 master created from the supplied Terraform configuration.

## Tests

Run the maintained PowerShell test scripts:

```powershell
pwsh -NoProfile -File .\Tests\Test-WafMigrationFormatting.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationReport.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationInputs.ps1
pwsh -NoProfile -File .\Tests\Test-WafMigrationExceptions.ps1
```

The input suite includes automatic-mode coverage for general settings, custom
rule merging, DRS exclusions, report-only behavior, and incompatible manual
selection parameters.
