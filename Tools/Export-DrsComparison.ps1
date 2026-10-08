#Requires -Version 7.0
#Requires -Modules ImportExcel

<#
.SYNOPSIS
Exports the Front Door DRS 1.0/1.1 versus 2.2 comparison to Excel.
.DESCRIPTION
Downloads the live Microsoft Learn rule catalogs and compares DRS 1.0 and 1.1
with DRS 2.2. Reads overrides and exclusions from a local DRS 2.1 policy JSON.
Extracts group and rule tables directly from the official HTML page.

Uses Export-Excel from ImportExcel to create one Rules worksheet. Group header
rows have blank rule IDs and contain group-scoped exclusions. Individual rule
rows show documented defaults and same-ID master overrides. Source attribution
and interpretation notes are embedded in column-header comments.

Requires an HTTPS connection to Microsoft Learn. Does not require Azure
authentication, query Azure resources, or modify the reference policy.
.PARAMETER MasterPolicyPath
Path to an Azure Front Door WAF policy JSON containing exactly one
Microsoft_DefaultRuleSet 2.1 configuration. Defaults to
Templates\masterfdwafpremium01.json in the repository.
.PARAMETER OutputPath
Destination .xlsx file. Its directory must exist. Defaults to DrsComparison.xlsx
in the script directory.
.PARAMETER Force
Allows replacement of an existing output workbook.
.OUTPUTS
System.Management.Automation.PSCustomObject
Output path and counts for documented rules, group headers, matched/unmatched
master overrides, exclusions, and Enabled overrides against Disabled defaults.
.NOTES
Requires PowerShell 7 and the ImportExcel module. Microsoft Excel is not required.
Descriptions are attributed to Microsoft under CC BY 4.0.
.LINK
https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs?tabs=drs22#drs-22
.EXAMPLE
.\Tools\Export-DrsComparison.ps1
.EXAMPLE
.\Tools\Export-DrsComparison.ps1 -OutputPath .\Comparison.xlsx -Force
#>
[CmdletBinding()]
param(
    [string] $MasterPolicyPath = (Join-Path (Split-Path $PSScriptRoot -Parent) 'Templates\masterfdwafpremium01.json'),
    [string] $OutputPath = (Join-Path $PSScriptRoot 'DrsComparison.xlsx'),
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-HtmlText {
    param([string] $Html)
    # Strip HTML tags before decoding entities so literal examples such as <script> survive.
    $text = $Html -replace '(?i)<br\s*/?>', "`n"
    $text = $text -replace '<[^>]+>', ''
    [System.Net.WebUtility]::HtmlDecode($text).Trim()
}

function Get-HtmlCells {
    param([string] $Row)
    foreach ($cell in [regex]::Matches($Row, '(?is)<td\b[^>]*>(?<body>.*?)</td>')) {
        [pscustomobject]@{
            Html = $cell.Groups['body'].Value
            Text = ConvertFrom-HtmlText $cell.Groups['body'].Value
        }
    }
}

function Get-NormalizedDescription {
    param([string] $Text)
    # Only case and whitespace are ignored; wording differences remain significant.
    ($Text -replace '\s+', ' ').Trim().ToLowerInvariant()
}

function Get-GroupDefinitions {
    param([string] $Version)
    $id = 'drs-' + $Version.Replace('.', '')
    $pattern = '(?is)<h3\b[^>]*\bid="' + $id + '"[^>]*>.*?</h3>(?<body>.*?)(?=<h3\b|\z)'
    $section = [regex]::Match($documentation, $pattern)
    if (-not $section.Success) { throw "Missing DRS $Version group summary in the documentation." }
    $table = [regex]::Match($section.Groups['body'].Value, '(?is)<table\b[^>]*>.*?</table>')
    if (-not $table.Success) { throw "Missing DRS $Version group-summary table." }
    # API group names are matching keys; full documented labels are display values.
    $count = 0
    foreach ($row in [regex]::Matches($table.Value, '(?is)<tr\b[^>]*>.*?</tr>')) {
        $cells = @(Get-HtmlCells $row.Value)
        if ($cells.Count -eq 0) { continue }
        $anchor = [regex]::Match($cells[0].Html, 'href="[^"]*#(?<id>[^"]+)"')
        if ($cells.Count -ne 3 -or -not $anchor.Success) { throw "Unrecognized DRS $Version group-summary row." }
        $count++
        [pscustomobject]@{
            Name = $cells[1].Text
            Label = $cells[0].Text
            Description = $cells[2].Text
            HeadingId = $anchor.Groups['id'].Value
        }
    }
    if ($count -eq 0) { throw "Empty DRS $Version group-summary table." }
}

function Get-RuleCatalog {
    param([string] $Version)
    $tab = $Version.Replace('.', '')
    $pattern = '(?is)<section\b[^>]*\bdata-tab="drs' + $tab + '"[^>]*>(?<body>.*?)</section>'
    $section = [regex]::Match($documentation, $pattern)
    if (-not $section.Success) { throw "Missing DRS $Version rule catalog in the documentation." }
    # Composite keys distinguish rules across groups; legacy catalogs omit score/PL metadata.
    $result = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $group = $null
    $blocks = [regex]::Matches($section.Groups['body'].Value,
        '(?is)<h3\b[^>]*\bid="(?<heading>[^"]+)"[^>]*>.*?</h3>|<tr\b[^>]*>.*?</tr>')
    foreach ($block in $blocks) {
        if ($block.Groups['heading'].Success) {
            $heading = $block.Groups['heading'].Value -replace '-\d+$', ''
            if (-not $headingGroups.ContainsKey($heading)) { throw "Unrecognized DRS $Version group heading: $heading" }
            $group = $headingGroups[$heading]
            continue
        }
        $cells = @(Get-HtmlCells $block.Value)
        if ($cells.Count -eq 0 -or $cells[0].Text -notmatch '^\d+$') { continue }
        $parts = @($cells | ForEach-Object Text)
        $hasMetadata = $Version -in '2.1', '2.2'
        $expectedColumns = if ($hasMetadata) { 4 } else { 2 }
        if (-not $group -or $parts.Count -ne $expectedColumns) { throw "Unrecognized DRS $Version rule row: $($parts[0])" }
        $key = "$group/$($parts[0])"
        if ($result.ContainsKey($key)) { throw "Duplicate DRS $Version rule: $key" }
        if ($hasMetadata -and $parts[2] -notin '1', '2') { throw "Unsupported paranoia level in $key`: $($parts[2])" }
        $result.Add($key, [pscustomobject]@{
            Group = $group
            Id = $parts[0]
            Description = $parts[-1]
            Severity = if ($hasMetadata) { $parts[1] } else { 'N/A' }
            Paranoia = if ($hasMetadata) { $parts[2] } else { 'N/A' }
        })
    }
    if ($result.Count -eq 0) { throw "Empty DRS $Version rule catalog." }
    $result
}

function Format-Exclusions {
    param([object[]] $Exclusions)
    # Selectors share a display line only when their match variable and operator agree.
    $sets = [ordered]@{}
    foreach ($exclusion in $Exclusions) {
        foreach ($key in $exclusion.Keys) {
            if ($key -notin 'matchVariable', 'selectorMatchOperator', 'selector') { throw "Unsupported exclusion property: $key" }
        }
        foreach ($key in 'matchVariable', 'selectorMatchOperator', 'selector') {
            if (-not $exclusion.Contains($key) -or $null -eq $exclusion[$key]) { throw "Missing exclusion property: $key" }
        }
        $key = "$($exclusion.matchVariable)/$($exclusion.selectorMatchOperator)"
        if (-not $sets.Contains($key)) { $sets[$key] = [System.Collections.Generic.List[string]]::new() }
        $sets[$key].Add([string] $exclusion.selector)
    }
    ($sets.GetEnumerator() | ForEach-Object { "$($_.Key.Replace('/', ' ')): $($_.Value -join ', ')" }) -join "`n"
}

function Get-RowHeight {
    param([string[]] $Values, [double[]] $Widths)
    # Estimate wrapped-text height at the default font and bound it to Excel's row limit.
    $maxLines = 1
    for ($index = 0; $index -lt $Values.Count; $index++) {
        $lineCount = 0
        foreach ($line in $Values[$index].Split("`n")) {
            $lineCount += [Math]::Max(1, [Math]::Ceiling($line.Length / ($Widths[$index] - 2)))
        }
        $maxLines = [Math]::Max($maxLines, $lineCount)
    }
    [Math]::Min(409, [Math]::Max(27, $lineHeight * $maxLines + 8))
}

function Set-TableAppearance {
    param($Sheet, [double[]] $Widths)
    # Direct fills and disabled table stripes keep rule rows uniformly colored.
    $table = $Sheet.Tables[0]
    $table.ShowFilter = $true
    $table.ShowRowStripes = $false
    $table.ShowColumnStripes = $false
    $table.ShowFirstColumn = $false
    $table.ShowLastColumn = $false
    $range = $Sheet.Cells[$Sheet.Dimension.Address]
    $range.Style.WrapText = $true
    $range.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Top
    $range.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $range.Style.Fill.BackgroundColor.SetColor([Drawing.ColorTranslator]::FromHtml('#eaf2f8'))
    $header = $Sheet.Cells[1, 1, 1, $Widths.Count]
    $header.Style.Fill.BackgroundColor.SetColor([Drawing.ColorTranslator]::FromHtml('#1f4e78'))
    $header.Style.Font.Color.SetColor([Drawing.Color]::White)
    $header.Style.Font.Bold = $true
    $header.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $Sheet.Row(1).Height = 40
    for ($index = 0; $index -lt $Widths.Count; $index++) { $Sheet.Column($index + 1).Width = $Widths[$index] }
    for ($row = 2; $row -le $Sheet.Dimension.End.Row; $row++) {
        $values = @(1..$Widths.Count | ForEach-Object { [string] $Sheet.Cells[$row, $_].Value })
        $Sheet.Row($row).Height = Get-RowHeight -Values $values -Widths $Widths
    }
    $Sheet.View.FreezePanes(2, 1)
}

# Validate destinations before any download; replacement requires explicit permission.
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$MasterPolicyPath = [IO.Path]::GetFullPath($MasterPolicyPath)
if ([IO.Path]::GetExtension($OutputPath) -ne '.xlsx') { throw 'OutputPath must have the .xlsx extension.' }
if (-not (Test-Path -LiteralPath $MasterPolicyPath -PathType Leaf)) { throw "Reference policy not found: $MasterPolicyPath" }
if (-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($OutputPath)) -PathType Container)) {
    throw "Output directory does not exist: $([IO.Path]::GetDirectoryName($OutputPath))"
}
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Output already exists; use -Force to replace it: $OutputPath" }

# The live article is the only rule-inventory source; download failures stop the export.
$sourceUri = 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs?tabs=drs22#drs-22'
$downloadUri = 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs?tabs=drs22'
$response = Invoke-WebRequest -Uri $downloadUri -Headers @{
    Accept = 'text/html'
    'Cache-Control' = 'no-cache'
    Pragma = 'no-cache'
}
if ($response.Headers['Content-Type'] -notlike 'text/html*') { throw 'Microsoft Learn did not return an HTML page.' }
$documentation = if ($response.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($response.Content) } else { $response.Content }
$documentation = $documentation.Replace("`r`n", "`n").TrimStart([char] 0xFEFF)
# Default-state derivation is valid only while the article confirms these baselines.
$articleText = Get-NormalizedDescription (ConvertFrom-HtmlText $documentation)
if ($articleText -notmatch 'By default, DRS versions 2\.0 and above use anomaly scoring' -or
    $articleText -notmatch 'By default, DRS 2\.2 is configured at Paranoia Level 1 \(PL1\), and all PL2 rules are disabled') {
    throw 'The documented default-action or PL2-disabled guidance has changed; review the exporter before proceeding.'
}

$groups = [System.Collections.Generic.List[object]]::new()
$groupDefinitions = @{}
foreach ($group in @(Get-GroupDefinitions '2.2')) {
    if ($groupDefinitions.ContainsKey($group.Name)) { throw "Duplicate target group: $($group.Name)" }
    $groups.Add($group)
    $groupDefinitions[$group.Name] = $group
}
foreach ($group in @(Get-GroupDefinitions '2.1')) {
    if (-not $groupDefinitions.ContainsKey($group.Name)) { $groupDefinitions[$group.Name] = $group }
}
# Summary-table links supply heading IDs; version suffixes differ between tabs.
$headingGroups = @{}
foreach ($group in $groupDefinitions.Values) {
    $heading = $group.HeadingId -replace '-\d+$', ''
    if ($headingGroups.ContainsKey($heading) -and $headingGroups[$heading] -ne $group.Name) {
        throw "Conflicting rule group for HTML heading: $heading"
    }
    $headingGroups[$heading] = $group.Name
}
$catalogs = @{}
foreach ($version in '1.0', '1.1', '2.1', '2.2') { $catalogs[$version] = Get-RuleCatalog $version }
# The 1.1 PowerShell entry uses an RFI ID; require a matching 2.1 RCE description before correcting it.
$correctedLegacyId = $false
if ($catalogs['1.1'].ContainsKey('RCE/931120')) {
    $misprinted = $catalogs['1.1']['RCE/931120']
    if ($catalogs['1.1'].ContainsKey('RCE/932120') -or -not $catalogs['2.1'].ContainsKey('RCE/932120') -or
        -not $catalogs['2.1'].ContainsKey('RFI/931120') -or
        (Get-NormalizedDescription $misprinted.Description) -ne (Get-NormalizedDescription $catalogs['2.1']['RCE/932120'].Description)) {
        throw 'The DRS 1.1 PowerShell rule ID discrepancy cannot be corrected unambiguously.'
    }
    $null = $catalogs['1.1'].Remove('RCE/931120')
    $misprinted.Id = '932120'
    $catalogs['1.1'].Add('RCE/932120', $misprinted)
    $correctedLegacyId = $true
}

# Replacement relationships require explicit annotations, not similar descriptions.
$target = $catalogs['2.2']
$targetById = @{}
$replacements = @{}
foreach ($rule in $target.Values) {
    if ($targetById.ContainsKey($rule.Id)) { throw "Duplicate target rule ID: $($rule.Id)" }
    $targetById[$rule.Id] = $rule
    $oldId = $null
    $newId = $null
    if ($rule.Description -match 'replaced by rule #(\d+)') { $oldId = $rule.Id; $newId = $Matches[1] }
    elseif ($rule.Description -match 'replacing rule #(\d+)') { $oldId = $Matches[1]; $newId = $rule.Id }
    if ($oldId) {
        if ($replacements.ContainsKey($oldId) -and $replacements[$oldId] -ne $newId) { throw "Conflicting replacement for $oldId" }
        $replacements[$oldId] = $newId
    }
}
foreach ($newId in $replacements.Values) {
    if (-not $targetById.ContainsKey($newId)) { throw "Documented replacement $newId is missing from the target rule list." }
}
# The comparison includes legacy and target rules; 2.1 supplies reference metadata only.
$union = @{}
foreach ($version in '1.0', '1.1', '2.2') {
    foreach ($entry in $catalogs[$version].GetEnumerator()) { $union[$entry.Key] = $entry.Value }
}

# Read the reference configuration without changing its ruleset or writing the JSON.
$policy = Get-Content -LiteralPath $MasterPolicyPath -Raw | ConvertFrom-Json -AsHashtable
$rulesets = @($policy.properties.managedRules.managedRuleSets | Where-Object {
    $_.ruleSetType -eq 'Microsoft_DefaultRuleSet' -and $_.ruleSetVersion -eq '2.1'
})
if ($rulesets.Count -ne 1) { throw 'The reference policy must contain exactly one Microsoft_DefaultRuleSet 2.1.' }
$master = $rulesets[0]
# Match rule overrides by ID, but keep group-scoped exclusions attached to their source group.
$groupOverrides = @{}
$matchedOverrides = @{}
$unmatchedOverrides = @{}
$unmatchedGroups = [System.Collections.Generic.List[string]]::new()
$overrideCount = 0
$groupExclusionCount = 0
$ruleExclusionCount = 0
foreach ($group in $master['ruleGroupOverrides']) {
    foreach ($key in $group.Keys) {
        if ($key -notin 'ruleGroupName', 'rules', 'exclusions') { throw "Unsupported master group property: $key" }
    }
    $name = [string] $group['ruleGroupName']
    if (-not $name -or $groupOverrides.ContainsKey($name)) { throw "Missing or duplicate master group name: $name" }
    $groupOverrides[$name] = $group
    $groupExclusions = @($group['exclusions'] | Where-Object { $null -ne $_ })
    $groupExclusionCount += $groupExclusions.Count
    if (-not ($target.Values | Where-Object Group -EQ $name) -and $groupExclusions.Count) { $unmatchedGroups.Add($name) }
    foreach ($rule in $group['rules']) {
        foreach ($key in $rule.Keys) {
            if ($key -notin 'ruleId', 'enabledState', 'action', 'exclusions') { throw "Unsupported master rule property: $key" }
        }
        $id = [string] $rule['ruleId']
        if ($id -notmatch '^\d+$') { throw "Invalid master rule ID in $name`: $id" }
        if ($rule['enabledState'] -and $rule['enabledState'] -notin 'Enabled', 'Disabled') { throw "Invalid state for master rule $id" }
        $ruleExclusionCount += @($rule['exclusions'] | Where-Object { $null -ne $_ }).Count
        $overrideCount++
        if ($targetById.ContainsKey($id)) {
            $key = "$($targetById[$id].Group)/$id"
            if ($matchedOverrides.ContainsKey($key)) { throw "Duplicate master override for target rule $id" }
            $matchedOverrides[$key] = @{ Rule = $rule; SourceGroup = $name }
        } else {
            # Retain unsupported source overrides as explicit rows instead of discarding them.
            $key = "$name/$id"
            if ($unmatchedOverrides.ContainsKey($key)) { throw "Duplicate unmatched master override: $key" }
            $unmatchedOverrides[$key] = $rule
            if (-not $union.ContainsKey($key)) {
                $union[$key] = if ($catalogs['2.1'].ContainsKey($key)) { $catalogs['2.1'][$key] } else {
                    [pscustomobject]@{ Group = $name; Id = $id; Description = 'Master override; description not documented in DRS 2.1 or 2.2.' }
                }
            }
        }
    }
}
# Groups with unmatched exclusions need a header row even when they contain no documented target rules.
foreach ($name in @(@($union.Values.Group) + @($unmatchedGroups) | Select-Object -Unique)) {
    if (-not ($groups | Where-Object Name -EQ $name)) {
        $definition = if ($groupDefinitions.ContainsKey($name)) { $groupDefinitions[$name] } else {
            [pscustomobject]@{ Name = $name; Label = "$name (not documented)"; Description = 'Master group not present in the official DRS 2.2 rule list.' }
        }
        $groups.Add($definition)
    }
}

$headers = @(
    'DRS 1.0', 'DRS 1.1', 'Rule ID', 'Description (legacy first; Microsoft Learn)',
    'Anomaly score severity (2.2)', 'Paranoia level (2.2)', 'DRS 2.2',
    '2.2 default action', '2.2 default status', '2.1 master overrides (for 2.2)'
)
$columnWidths = @(38, 14, 14, 13, 70, 24, 22, 75, 25, 20, 85)
$enabledDeviations = [System.Collections.Generic.List[string]]::new()
$comparisonRows = [System.Collections.Generic.List[object]]::new()
foreach ($group in $groups) {
    $sourceGroup = if ($groupOverrides.ContainsKey($group.Name)) { $groupOverrides[$group.Name] } else { $null }
    $groupStatus = if ($unmatchedGroups.Contains($group.Name)) { 'Master group exclusions: no matching group in official DRS 2.2 rule list' }
        elseif ($target.Values | Where-Object Group -EQ $group.Name) {
            if (($catalogs['1.0'].Values | Where-Object Group -EQ $group.Name) -or
                ($catalogs['1.1'].Values | Where-Object Group -EQ $group.Name)) { 'same' } else { 'new group' }
        } else { 'N/A' }
    $groupValues = @(
        $(if ($catalogs['1.0'].Values | Where-Object Group -EQ $group.Name) { 'exists' } else { 'N/A' }),
        $(if ($catalogs['1.1'].Values | Where-Object Group -EQ $group.Name) { 'exists' } else { 'N/A' }),
        '', $group.Description, '-', '-', $groupStatus, '-', '-',
        $(if ($sourceGroup -and $sourceGroup['exclusions']) {
            "Group exclusions:`n$(Format-Exclusions $sourceGroup['exclusions'])"
        } else { '-' })
    )
    # A blank rule ID identifies a group header and keeps its exclusions separate from rule exclusions.
    $groupRecord = [ordered]@{ Group = $group.Label }
    for ($index = 0; $index -lt $headers.Count; $index++) { $groupRecord[$headers[$index]] = [string] $groupValues[$index] }
    $comparisonRows.Add([pscustomobject] $groupRecord)
    foreach ($rule in @($union.Values | Where-Object Group -EQ $group.Name | Sort-Object { [long] $_.Id })) {
        $key = "$($group.Name)/$($rule.Id)"
        $old10 = if ($catalogs['1.0'].ContainsKey($key)) { $catalogs['1.0'][$key] } else { $null }
        $old11 = if ($catalogs['1.1'].ContainsKey($key)) { $catalogs['1.1'][$key] } else { $null }
        $current = if ($target.ContainsKey($key)) { $target[$key] } else { $null }
        $baseline = if ($old10) { $old10 } elseif ($old11) { $old11 } elseif ($current) { $current } else { $rule }
        $description = $baseline.Description
        # Show legacy wording first; include target wording only when it differs meaningfully.
        $legacyDifferent = $old10 -and $old11 -and
            (Get-NormalizedDescription $old10.Description) -ne (Get-NormalizedDescription $old11.Description)
        if ($legacyDifferent) { $description = "1.0: $($old10.Description)`n1.1: $($old11.Description)" }
        $status = if ($current) { if ($old10 -or $old11) { 'same' } else { 'new' } } else { 'N/A' }
        $defaultStatus = 'N/A'
        if ($current) {
            # Product defaults come from documented PL/replacement behavior, not the master.
            $defaultStatus = if ($current.Paranoia -eq '2' -or $replacements.ContainsKey($rule.Id)) { 'Disabled' } else { 'Enabled' }
            if ($replacements.ContainsKey($rule.Id)) {
                $status = "superseded by $($replacements[$rule.Id]) (original still listed; disabled by default)"
            } elseif ($defaultStatus -eq 'Disabled') { $status += ' (disabled by default)' }
            if ($old10 -or $old11) {
                $matches10 = $old10 -and (Get-NormalizedDescription $old10.Description) -eq (Get-NormalizedDescription $current.Description)
                $matches11 = $old11 -and (Get-NormalizedDescription $old11.Description) -eq (Get-NormalizedDescription $current.Description)
                if (-not $matches10 -and -not $matches11) { $status += "`n2.2 description: $($current.Description)" }
                elseif ($legacyDifferent) { $status += "`nDescription matches DRS $(if ($matches10) { '1.0' } else { '1.1' })." }
            }
        }
        $overrideText = [System.Collections.Generic.List[string]]::new()
        $explicit = $null
        if ($unmatchedOverrides.ContainsKey($key)) {
            $explicit = $unmatchedOverrides[$key]
            $status = 'Master override: no matching rule in official DRS 2.2 rule list'
            $settings = @(
                if ($explicit['enabledState']) { "Status: $($explicit['enabledState'])" }
                if ($explicit['action']) { "Action: $($explicit['action'])" }
            )
            $overrideText.Add($(if ($settings.Count) { "2.1 source settings: $($settings -join '; ')" } else {
                '2.1 source settings: no explicit action or status'
            }))
        } elseif ($matchedOverrides.ContainsKey($key)) {
            $explicit = $matchedOverrides[$key].Rule
            # Omit no-op action/state settings; exclusions are still displayed at their own scope.
            if ($explicit['enabledState'] -and $explicit['enabledState'] -ne $defaultStatus) {
                $overrideText.Add("Status: $($explicit['enabledState']) (default: $defaultStatus)")
                if ($explicit['enabledState'] -eq 'Enabled' -and $defaultStatus -eq 'Disabled') { $enabledDeviations.Add($rule.Id) }
            }
            if ($explicit['action'] -and $explicit['action'] -ne 'AnomalyScoring') { $overrideText.Add("Action: $($explicit['action']) (default: AnomalyScoring)") }
            if ($matchedOverrides[$key].SourceGroup -ne $group.Name) {
                $sourceName = $matchedOverrides[$key].SourceGroup
                $sourceLabel = if ($groupDefinitions.ContainsKey($sourceName)) { $groupDefinitions[$sourceName].Label } else { "$sourceName (not documented)" }
                $overrideText.Add("2.1 source group: $sourceLabel")
            }
        }
        if ($explicit -and $explicit['exclusions']) { $overrideText.Add("Rule exclusions: $(Format-Exclusions $explicit['exclusions'])") }
        $values = @(
            $(if ($old10) { 'exists' } else { 'N/A' }), $(if ($old11) { 'exists' } else { 'N/A' }), $rule.Id,
            $description, $(if ($current) { $current.Severity } else { 'N/A' }),
            $(if ($current) { $current.Paranoia } else { 'N/A' }), $status,
            $(if ($current) { 'AnomalyScoring' } else { 'N/A' }), $defaultStatus,
            $(if ($overrideText.Count) { $overrideText -join "`n" } else { '-' })
        )
        $record = [ordered]@{ Group = $group.Label }
        for ($index = 0; $index -lt $headers.Count; $index++) { $record[$headers[$index]] = [string] $values[$index] }
        $comparisonRows.Add([pscustomobject] $record)
    }
}
if ($matchedOverrides.Count + $unmatchedOverrides.Count -ne $overrideCount) { throw 'Not all master overrides were accounted for.' }

# Source attribution, scope, and interpretation travel with the workbook as header comments.
$notes = @(
    [pscustomobject]@{ Topic = 'Rule documentation'; Details = $sourceUri }
    [pscustomobject]@{ Topic = 'Description license'; Details = 'Microsoft, CC BY 4.0: https://creativecommons.org/licenses/by/4.0/' }
    [pscustomobject]@{ Topic = 'Generated (UTC)'; Details = [DateTime]::UtcNow.ToString('o') }
    [pscustomobject]@{ Topic = 'Documentation input'; Details = "$downloadUri (live download on every export; no local documentation or cached fallback)" }
    [pscustomobject]@{ Topic = 'Reference policy'; Details = "$MasterPolicyPath (DRS 2.1; ruleset action: $(if ($master['ruleSetAction']) { $master['ruleSetAction'] } else { 'not explicitly set' }))" }
    [pscustomobject]@{ Topic = 'Rule inventory'; Details = "DRS 1.0: $($catalogs['1.0'].Count); 1.1: $($catalogs['1.1'].Count); 2.2: $($target.Count). Official article inventory, not an Azure resource inventory." }
    [pscustomobject]@{ Topic = 'Master matching'; Details = "$($matchedOverrides.Count) of $overrideCount rule overrides match the official 2.2 list by ID; unmatched: $($unmatchedOverrides.Count)." }
    [pscustomobject]@{ Topic = 'Exclusion counts'; Details = "Group: $groupExclusionCount; rule: $ruleExclusionCount; ruleset: $(@($master['exclusions'] | Where-Object { $null -ne $_ }).Count)." }
    [pscustomobject]@{ Topic = 'Group exclusion scopes without a match'; Details = $(if ($unmatchedGroups.Count) { $unmatchedGroups -join ', ' } else { 'None' }) }
    [pscustomobject]@{ Topic = 'Defaults'; Details = '2.2 defaults come from the article: AnomalyScoring; all PL2 and superseded original rules Disabled; other rules Enabled. They do not come from the master.' }
    [pscustomobject]@{ Topic = 'Enabled against Disabled defaults'; Details = $(if ($enabledDeviations.Count) { ($enabledDeviations | Sort-Object { [long] $_ }) -join ', ' } else { 'None' }) }
    [pscustomobject]@{ Topic = 'Same'; Details = 'Same group and rule ID, not identical signatures or behavior. Exclusions are not transferred to replacement IDs.' }
    [pscustomobject]@{ Topic = 'Descriptions'; Details = 'Legacy wording first; new rules use 2.2 wording. Differences only in case/whitespace are ignored. Severity and paranoia level refer to 2.2 only; not published for DRS 1.x.' }
    [pscustomobject]@{ Topic = 'Override cells'; Details = 'Only deviations from 2.2 defaults and exclusions. A dash means no deviation or exclusion at that scope, not Disabled or exempt from group exclusions.' }
    [pscustomobject]@{ Topic = 'Excel layout'; Details = 'A single Rules sheet and table, labels/filters in frozen row 1, repeated group names. Bold group header rows have blank rule IDs, a darker blue background, and group descriptions/exclusions. All header rows are vertically middle-aligned. Rule rows are not bold. Source and interpretation notes are in column-header comments. Columns B/C/D and anomaly severity/paranoia level are centered. No merges, outlines, alternating row bands, or font name/size overrides.' }
    [pscustomobject]@{ Topic = 'Threshold event'; Details = '949110 (Inbound Anomaly Score Exceeded) is a log event, not another catalog rule. AnomalyScoring contributes to the score; the ruleset action applies at the threshold.' }
    [pscustomobject]@{ Topic = 'Scope'; Details = 'Read-only comparison. No policies, associations, or reference JSON are changed. Bot Manager, DDoS rules, and other policy settings are outside this table.' }
)
if ($correctedLegacyId) {
    $notes += [pscustomobject]@{ Topic = 'DRS 1.1 documentation error'; Details = 'RCE incorrectly lists 931120 for PowerShell; corrected to 932120, verified against the 2.1 description. RFI 931120 is a separate rule.' }
}
if ($master['exclusions']) { $notes += [pscustomobject]@{ Topic = 'Ruleset-wide exclusions'; Details = Format-Exclusions $master['exclusions'] } }

$package = [OfficeOpenXml.ExcelPackage]::new()
try {
    $lineHeight = [double] $package.Workbook.Styles.Fonts[0].Size * 1.4
    $package = $comparisonRows | Export-Excel -ExcelPackage $package -WorksheetName 'Rules' -TableName DrsComparison `
        -TableStyle Medium2 -NoNumberConversion '*' -NoHyperLinkConversion '*' -PassThru
    $sheet = $package.Workbook.Worksheets['Rules']
    Set-TableAppearance -Sheet $sheet -Widths $columnWidths
    $sheet.Cells[1, 2, $sheet.Dimension.End.Row, 4].Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $sheet.Cells[1, 2, $sheet.Dimension.End.Row, 4].Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $sheet.Cells[1, 6, $sheet.Dimension.End.Row, 7].Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $sheet.Cells[1, 6, $sheet.Dimension.End.Row, 7].Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    for ($row = 2; $row -le $sheet.Dimension.End.Row; $row++) {
        # Group emphasis depends on the blank-ID marker, not row position or alternating bands.
        $rowRange = $sheet.Cells[$row, 1, $row, 11]
        $isGroupHeader = [string]::IsNullOrEmpty($sheet.Cells[$row, 4].Text)
        $rowRange.Style.Font.Bold = $isGroupHeader
        if ($isGroupHeader) {
            $rowRange.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
            $rowRange.Style.Fill.BackgroundColor.SetColor([Drawing.ColorTranslator]::FromHtml('#bdd7ee'))
        }
    }
    # Route topic-specific notes to their relevant headers; general notes belong to Group.
    $noteColumns = @{
        'Master matching' = 11
        'Exclusion counts' = 11
        'Group exclusion scopes without a match' = 11
        'Defaults' = 9
        'Enabled against Disabled defaults' = 10
        'Same' = 8
        'Descriptions' = 5
        'Override cells' = 11
        'Threshold event' = 6
        'DRS 1.1 documentation error' = 4
        'Ruleset-wide exclusions' = 11
    }
    $headerNotes = @{}
    foreach ($note in $notes) {
        $column = if ($noteColumns.ContainsKey($note.Topic)) { $noteColumns[$note.Topic] } else { 1 }
        if (-not $headerNotes.ContainsKey($column)) { $headerNotes[$column] = [System.Collections.Generic.List[string]]::new() }
        $headerNotes[$column].Add("$($note.Topic):`n$($note.Details)")
    }
    foreach ($entry in $headerNotes.GetEnumerator()) {
        $comment = $sheet.Cells[1, [int] $entry.Key].AddComment(($entry.Value -join "`n`n"), 'DRS comparison')
        $comment.AutoFit = $true
        $comment.Visible = $false
    }
    # Recheck after the download and rendering in case another process created the destination.
    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw "Output already exists; use -Force to replace it: $OutputPath" }
    $package.SaveAs([IO.FileInfo]::new($OutputPath))
} finally {
    $package.Dispose()
}

[pscustomobject]@{
    Path = $OutputPath
    TargetRules = $target.Count
    ComparisonRules = $union.Count
    RuleTables = 1
    Groups = $groups.Count
    TableRows = $comparisonRows.Count
    MatchedMasterOverrides = $matchedOverrides.Count
    UnmatchedMasterOverrides = $unmatchedOverrides.Count
    GroupExclusions = $groupExclusionCount
    RuleExclusions = $ruleExclusionCount
    EnabledAgainstDisabledDefaults = @($enabledDeviations)
}
