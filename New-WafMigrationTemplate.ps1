#Requires -Version 7.0
#Requires -Modules Az.Accounts

<#
.SYNOPSIS
Creates an Azure Front Door Premium WAF ARM template from a source policy.
.DESCRIPTION
Compares a source policy with an optional master policy, resolves policy settings,
custom rules, managed rules, exclusions, and request exceptions, then writes a
resource-group ARM template. Inputs can be Azure resource IDs or local policy/ARM
JSON files. Azure is read only for resource-ID inputs. The script never deploys or
modifies Azure resources.

Embedded catalogs support DRS 1.0, 1.1, 2.0, 2.1, and 2.2; Bot Manager 1.0 and 1.1;
and HTTP DDoS 1.0. A master keeps its declared managed-rule versions. Without a
master, source-configured families use the latest embedded versions.
.PARAMETER SourcePolicy
Source Front Door WAF resource ID or JSON file.
.PARAMETER MasterPolicy
Optional master Front Door WAF resource ID or JSON file.
.PARAMETER TargetPolicyName
Name of the new Premium Front Door WAF policy.
.PARAMETER ReportOnly
Shows comparisons and selected choices without prompting or writing a file.
.PARAMETER Auto
Selects compatible source decisions, retaining target when managed source carryover
is unsupported. Target-only custom rules are retained.
Can be combined with ReportOnly, but not KeepSource or KeepTarget. Priority conflicts
still prompt during generation.
.PARAMETER OutputPath
Output ARM file. Defaults to <TargetPolicyName>.arm.json.
.PARAMETER Force
Replaces an existing output file. Inputs and the script cannot be overwritten.
.PARAMETER KeepSource
Decision IDs or ranges that select source, for example 1,2,4-19.
.PARAMETER KeepTarget
Decision IDs or ranges that select target. Cannot overlap KeepSource.
.PARAMETER DefaultProfile
Optional Az context for resource-ID inputs.
.OUTPUTS
PSCustomObject containing the migration summary, decisions, managed-rule analysis,
and output path.
.EXAMPLE
.\New-WafMigrationTemplate.ps1 -SourcePolicy .\source.json -MasterPolicy .\Templates\mastertemplate.json -TargetPolicyName newPolicy -ReportOnly
.EXAMPLE
.\New-WafMigrationTemplate.ps1 -SourcePolicy .\source.json -MasterPolicy .\Templates\mastertemplate.json -TargetPolicyName newPolicy -Auto -OutputPath .\newPolicy.arm.json
.EXAMPLE
.\New-WafMigrationTemplate.ps1 -SourcePolicy $sourceId -TargetPolicyName newPolicy -KeepSource 1,2,'4-19' -KeepTarget 3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $SourcePolicy,

    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string] $MasterPolicy,

    [Parameter(Mandatory, Position = 2)]
    [ValidatePattern('^[A-Za-z][A-Za-z0-9]{0,127}$')]
    [string] $TargetPolicyName,

    [switch] $ReportOnly,
    [switch] $Auto,
    [string] $OutputPath,
    [switch] $Force,
    [ValidateNotNullOrEmpty()]
    [string[]] $KeepSource = @(),
    [ValidateNotNullOrEmpty()]
    [string[]] $KeepTarget = @(),
    [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext] $DefaultProfile
)

#region Decision selection parsing
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Write-Host 'Preparing WAF migration. Azure resources will not be changed.' -ForegroundColor Cyan

function ConvertTo-DecisionRanges {
    <#
    .SYNOPSIS
    Validates numeric review selections without expanding ranges before planning.
    .DESCRIPTION
    Accepts string arrays or comma-separated strings, with inclusive ascending
    ranges. Syntax and positive Int32 endpoints are checked before Azure reads.
    .PARAMETER Selections
    Review IDs and ranges; an empty array means no preset choices.
    .PARAMETER ParameterName
    Caller parameter name used in validation errors.
    .OUTPUTS
    One array of Start/End interval objects.
    #>
    param([string[]] $Selections, [string] $ParameterName)
    return ,@(
        foreach ($selection in $Selections) {
            foreach ($part in $selection.Split(',')) {
                # Validate bounded endpoints before materializing any selected row IDs.
                if ($part -notmatch '^\s*([0-9]+)(?:\s*-\s*([0-9]+))?\s*$') {
                    throw "Invalid -$ParameterName selection '$part'; use a positive row ID or ascending range such as 4-19."
                }
                $first = 0
                if (-not [int]::TryParse($Matches[1], [ref] $first) -or $first -lt 1) {
                    throw "Invalid -$ParameterName row ID '$($Matches[1])'; IDs must be between 1 and 2147483647."
                }
                $last = $first
                if ($Matches.ContainsKey(2) -and
                    (-not [int]::TryParse($Matches[2], [ref] $last) -or $last -lt 1)) {
                    throw "Invalid -$ParameterName row ID '$($Matches[2])'; IDs must be between 1 and 2147483647."
                }
                if ($last -lt $first) { throw "Invalid -$ParameterName range '$part'; the end must be greater than or equal to the start." }
                [pscustomobject]@{ Start = $first; End = $last }
            }
        }
    )
}

function Resolve-DecisionRanges {
    <#
    .SYNOPSIS
    Expands validated selections once final review numbering and count are known.
    .DESCRIPTION
    Checks every endpoint before expansion, bounding work by the current report.
    Repeated or overlapping selections within one parameter select each row once.
    .PARAMETER Ranges
    Validated intervals returned by ConvertTo-DecisionRanges.
    .PARAMETER ParameterName
    Caller parameter name used in unknown-row errors.
    .PARAMETER DecisionCount
    Number of consecutively numbered reviews in the current plan.
    .OUTPUTS
    One HashSet of selected integer review IDs.
    #>
    param([object[]] $Ranges, [string] $ParameterName, [int] $DecisionCount)
    foreach ($range in $Ranges) {
        if ($range.End -gt $DecisionCount) {
            throw "Unknown decision row ID $($range.End) in -$ParameterName; this run has $DecisionCount displayed rows."
        }
    }
    $ids = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($range in $Ranges) {
        for ([long] $rowId = $range.Start; $rowId -le $range.End; $rowId++) { $null = $ids.Add([int] $rowId) }
    }
    return ,$ids
}

#endregion

#region Runtime configuration and writable API shapes
$keepSourceRanges = ConvertTo-DecisionRanges $KeepSource 'KeepSource'
$keepTargetRanges = ConvertTo-DecisionRanges $KeepTarget 'KeepTarget'
if ($Auto -and ($KeepSource.Count -or $KeepTarget.Count)) {
    throw '-Auto cannot be used with -KeepSource or -KeepTarget; automatic mode selects every decision.'
}
foreach ($sourceRange in $keepSourceRanges) {
    foreach ($targetRange in $keepTargetRanges) {
        if ($sourceRange.Start -le $targetRange.End -and $targetRange.Start -le $sourceRange.End) {
            $rowId = [Math]::Max($sourceRange.Start, $targetRange.Start)
            throw "Row $rowId cannot be both -KeepSource and -KeepTarget."
        }
    }
}
# Latest stable version advertised by Microsoft.Network, verified 2026-10-05.
$apiVersion = '2026-04-01'
$resourceType = 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies'
$drsPath = 'properties.managedRules.managedRuleSets[Microsoft_DefaultRuleSet]'
$decisions = [System.Collections.Generic.List[object]]::new()
# Front Door DRS 2.2 replacement annotations, verified against Microsoft Learn.
$supersededRuleIds = @{
    '942110' = '99031001'; '942440' = '99031002'; '942150' = '99031003'
    '942260' = '99031004'; '942430' = '99031005'; '942340' = '99031006'
    '941120' = '99032001'; '931130' = '99032002'
}
$actionType = 'string:Allow,Block,Log,Redirect,AnomalyScoring,JSChallenge,CAPTCHA'
$stateType = 'string:Enabled,Disabled'
# Deliberate writable allowlist: future API fields must be reviewed, never silently discarded.
$wafShapes = @{
    Policy = @{ policySettings = 'Settings'; customRules = 'CustomRules'; managedRules = 'ManagedRules!' }
    Settings = @{
        enabledState = $stateType; mode = 'string:Prevention,Detection'; redirectUrl = 'string'
        customBlockResponseStatusCode = 'integer'; customBlockResponseBody = 'string'
        requestBodyCheck = $stateType; javascriptChallengeExpirationInMinutes = 'integer'
        captchaExpirationInMinutes = 'integer'; logScrubbing = 'LogScrubbing'
    }
    CustomRules = @{ rules = 'array:CustomRule' }
    CustomRule = @{
        name = 'string!'; enabledState = $stateType; priority = 'integer!'; ruleType = 'string:MatchRule,RateLimitRule!'
        rateLimitDurationInMinutes = 'integer'; rateLimitThreshold = 'integer'
        matchConditions = 'array:Condition!'; action = "$actionType!"; groupBy = 'array:GroupBy'
    }
    Condition = @{
        matchVariable = 'string:RemoteAddr,RequestMethod,QueryString,PostArgs,RequestUri,RequestHeader,RequestBody,Cookies,SocketAddr,JA4!'
        selector = 'string'
        operator = 'string:Any,IPMatch,GeoMatch,Equal,Contains,LessThan,GreaterThan,LessThanOrEqual,GreaterThanOrEqual,BeginsWith,EndsWith,RegEx,ServiceTagMatch,AsnMatch,ClientFingerprint!'
        negateCondition = 'boolean'; matchValue = 'array:string!'
        transforms = 'array:string:Lowercase,RemoveNulls,Trim,Uppercase,UrlDecode,UrlEncode'
    }
    GroupBy = @{ variableName = 'string:SocketAddr,GeoLocation,None,Asn,Ja4!' }
    ManagedRules = @{ managedRuleSets = 'array:RuleSet!'; exceptionsList = 'Exceptions' }
    RuleSet = @{
        ruleSetType = 'string!'; ruleSetVersion = 'string!'; ruleSetAction = 'string:Block,Log,Redirect'
        ruleGroupOverrides = 'array:RuleGroup'; exclusions = 'array:Exclusion'
    }
    RuleGroup = @{ ruleGroupName = 'string!'; rules = 'array:Override'; exclusions = 'array:Exclusion' }
    Override = @{
        ruleId = 'string!'; enabledState = $stateType; action = $actionType
        sensitivity = 'string:Low,Medium,High'; exclusions = 'array:Exclusion'
    }
    Exclusion = @{
        matchVariable = 'string:RequestHeaderNames,RequestCookieNames,QueryStringArgNames,RequestBodyPostArgNames,RequestBodyJsonArgNames!'
        selectorMatchOperator = 'string:Equals,Contains,StartsWith,EndsWith,EqualsAny!'; selector = 'string!'
    }
    Exceptions = @{ exceptions = 'array:Exception' }
    Exception = @{
        matchVariable = 'string:RequestUri,SocketAddr,RequestHeaderNames!'
        valueMatchOperator = 'string:Equals,Contains,StartsWith,EndsWith,EqualsAny,IPMatch!'
        matchValues = 'array:string!'; scopes = 'array:SetScope!'; selector = 'string'
        selectorMatchOperator = 'string:Equals'
    }
    SetScope = @{ ruleSetType = 'string!'; ruleSetVersion = 'string!'; ruleGroupScopes = 'array:GroupScope' }
    GroupScope = @{ ruleGroupName = 'string!'; ruleScopes = 'array:RuleScope' }
    RuleScope = @{ ruleId = 'string!' }
    LogScrubbing = @{ state = $stateType; scrubbingRules = 'array:ScrubbingRule' }
    ScrubbingRule = @{
        matchVariable = 'string:RequestIPAddress,RequestUri,QueryStringArgNames,RequestHeaderNames,RequestCookieNames,RequestBodyPostArgNames,RequestBodyJsonArgNames!'
        selectorMatchOperator = 'string:EqualsAny,Equals!'; selector = 'string'; state = $stateType
    }
}

#endregion

#region JSON validation, normalization and collection helpers
function Assert-PolicyShape {
    <#
    .SYNOPSIS
    Validates writable policy fields against the supported ARM API shapes.
    .DESCRIPTION
    Recursively checks required fields, JSON types, and case-sensitive enum values.
    Unknown fields terminate processing rather than being discarded.
    .PARAMETER Value
    JSON value to validate.
    .PARAMETER Kind
    Shape name or primitive/array descriptor from wafShapes; ! marks a required field.
    .PARAMETER Path
    Diagnostic property path included in validation errors.
    .OUTPUTS
    None. Throws on invalid input.
    #>
    param([AllowNull()] $Value, [string] $Kind, [string] $Path)
    # Requiredness belongs to the parent field; recursion validates the underlying type.
    $Kind = $Kind.TrimEnd('!')
    if ($Kind.StartsWith('array:')) {
        if ($Value -isnot [System.Collections.IList]) { throw "$Path must be a JSON array." }
        $index = 0
        foreach ($item in $Value) {
            Assert-PolicyShape $item $Kind.Substring(6) "$Path[$index]"
            $index++
        }
        return
    }
    if ($Kind.StartsWith('string')) {
        if ($Value -isnot [string]) { throw "$Path must be a string." }
        if ($Kind.StartsWith('string:') -and $Value -cnotin $Kind.Substring(7).Split(',')) {
            throw "Unsupported value '$Value' at $Path."
        }
        return
    }
    if ($Kind -eq 'integer') {
        if ($Value -isnot [int] -and $Value -isnot [long]) { throw "$Path must be an integer." }
        return
    }
    if ($Kind -eq 'boolean') {
        if ($Value -isnot [bool]) { throw "$Path must be a boolean." }
        return
    }
    if ($Value -isnot [System.Collections.IDictionary]) { throw "$Path must be a JSON object." }
    $shape = $wafShapes[$Kind]
    # Check missing requirements separately from unknown fields to avoid silently dropping data.
    foreach ($field in $shape.Keys) {
        if ($shape[$field].EndsWith('!') -and -not $Value.Contains($field)) { throw "$Path is missing required field '$field'." }
    }
    foreach ($field in $Value.Keys) {
        if (-not $shape.ContainsKey($field)) { throw "Unsupported field '$Path.$field' for API $apiVersion." }
        Assert-PolicyShape $Value[$field] $shape[$field] "$Path.$field"
    }
}

function Copy-JsonValue {
    <#
    .SYNOPSIS
    Deep-copies JSON-compatible configuration without sharing mutable children.
    .DESCRIPTION
    Uses PowerShell 7 hashtable conversion and NoEnumerate to preserve array shape.
    .PARAMETER Value
    JSON-compatible value, including null or an empty/single-item array.
    .OUTPUTS
    A detached value emitted as one pipeline object.
    #>
    param([AllowNull()] $Value)
    # Both NoEnumerate and the unary comma prevent empty/single-item arrays from collapsing.
    return ,(ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $Value -Depth 100 -Compress) -AsHashtable -Depth 100 -NoEnumerate)
}

function Remove-NullProperties {
    <#
    .SYNOPSIS
    Removes null dictionary properties in place.
    .DESCRIPTION
    Recurses through objects and arrays; null optional fields count as absent for migration.
    Array elements are not removed or reordered.
    .PARAMETER Value
    Mutable JSON tree to normalize.
    .OUTPUTS
    None. Mutates the supplied tree.
    #>
    param([AllowNull()] $Value)
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in @($Value.Keys)) {
            if ($null -eq $Value[$key]) { $Value.Remove($key) }
            else { Remove-NullProperties $Value[$key] }
        }
    }
    elseif ($Value -is [System.Collections.IList]) {
        foreach ($item in $Value) { Remove-NullProperties $item }
    }
}

function ConvertFrom-ArmResource {
    <#
    .SYNOPSIS
    Decodes ARM-escaped literal strings in a policy template resource.
    .DESCRIPTION
    Builds a new JSON tree and rejects unresolved ARM expressions; no expressions are evaluated.
    .PARAMETER Value
    Template resource or nested JSON value.
    .OUTPUTS
    Decoded JSON value, preserving collection shape.
    #>
    param([AllowNull()] $Value)
    if ($Value -is [string]) {
        # Decode escaped literals first; evaluating expressions would require deployment context.
        if ($Value.StartsWith('[[')) { return $Value.Substring(1) }
        if ($Value.StartsWith('[') -and $Value.EndsWith(']')) {
            throw "Policy template contains an ARM expression '$Value'. Supply a concrete resource export."
        }
        return $Value
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $Value.Keys) { $result[$key] = ConvertFrom-ArmResource $Value[$key] }
        return $result
    }
    if ($Value -is [System.Collections.IList]) {
        return ,@(foreach ($item in $Value) { ConvertFrom-ArmResource $item })
    }
    return $Value
}

function Get-CanonicalValue {
    <#
    .SYNOPSIS
    Produces a deterministic JSON value for comparison.
    .DESCRIPTION
    Sorts object keys and unordered array contents while preserving ordinary string case.
    Transform arrays retain their order because transform composition is order-dependent.
    Exclusion comparisons ignore header/cookie selector case without modifying input.
    .PARAMETER Value
    JSON value to canonicalize without mutating it.
    .PARAMETER Property
    Containing property name, used to recognize order-sensitive transforms.
    .OUTPUTS
    Canonical JSON-compatible value.
    #>
    param([AllowNull()] $Value, [string] $Property = '')
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object -CaseSensitive)) {
            if ($Property -ceq 'exclusion' -and $key -ceq 'selector' -and
                $Value['matchVariable'] -cin 'RequestHeaderNames', 'RequestCookieNames') {
                $result[$key] = $Value[$key].ToUpperInvariant()
            } else { $result[$key] = Get-CanonicalValue $Value[$key] $key }
        }
        return $result
    }
    if ($Value -is [System.Collections.IList]) {
        $items = @(
            foreach ($item in $Value) {
                Get-CanonicalValue $item $(if ($Property -ceq 'exclusions') { 'exclusion' } else { '' })
            }
        )
        # Serialized sort keys compare nested objects consistently without reordering transform chains.
        if ($Property -ne 'transforms') {
            $items = @($items | Sort-Object -CaseSensitive -Property {
                ConvertTo-Json -InputObject $_ -Depth 100 -Compress
            })
        }
        return ,$items
    }
    return $Value
}

function Test-JsonEqual {
    <#
    .SYNOPSIS
    Compares JSON values using migration-specific canonicalization.
    .DESCRIPTION
    Ignores property and unordered-array ordering, preserving wording and transform order.
    Case is preserved except header/cookie selectors in exclusion comparisons.
    .PARAMETER Left
    First JSON value.
    .PARAMETER Right
    Second JSON value.
    .PARAMETER Property
    Containing property name passed to canonicalization.
    .OUTPUTS
    System.Boolean.
    #>
    param([AllowNull()] $Left, [AllowNull()] $Right, [string] $Property = '')
    $leftJson = ConvertTo-Json -InputObject (Get-CanonicalValue $Left $Property) -Depth 100 -Compress
    $rightJson = ConvertTo-Json -InputObject (Get-CanonicalValue $Right $Property) -Depth 100 -Compress
    [string]::Equals($leftJson, $rightJson, [StringComparison]::Ordinal)
}

function Get-Collection {
    <#
    .SYNOPSIS
    Reads a JSON array without collapsing empty or single-item collections.
    .DESCRIPTION
    Missing properties return an empty array; present non-array values are errors.
    .PARAMETER Object
    Dictionary containing the property.
    .PARAMETER Key
    Array property name.
    .OUTPUTS
    One System.Object[] pipeline object.
    #>
    param([System.Collections.IDictionary] $Object, [string] $Key)
    if (-not $Object.Contains($Key)) { return ,@() }
    if ($Object[$Key] -isnot [System.Collections.IList]) { throw "'$Key' must be a JSON array." }
    return ,@($Object[$Key])
}

function Get-CustomRuleBehaviorAssessments {
    <#
    .SYNOPSIS
    Describes source custom-rule mechanics without disclosing ordinary match values.
    .DESCRIPTION
    Returns one assessment per explicit source custom rule. Conditions retain the
    variable, selector, operator, negation, transforms, and match-value count.
    GeoMatch country codes are retained because the presence of ZZ/Unknown is
    behaviorally significant; IP ranges and all other match values are omitted.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary] $Configuration)

    if (-not $Configuration['properties'].Contains('customRules')) { return }
    $assessments = foreach ($rule in (Get-Collection $Configuration['properties']['customRules'] 'rules')) {
        $flags = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        if ($rule['ruleType'] -ceq 'RateLimitRule') { $null = $flags.Add('DistributedFixedWindowRateLimit') }
        switch -CaseSensitive ($rule['action']) {
            'Allow' { $null = $flags.Add('TerminalAllow') }
            'Block' { $null = $flags.Add('TerminalBlock') }
            'Redirect' { $null = $flags.Add('TerminalRedirect') }
            'Log' { $null = $flags.Add('NonTerminalLog') }
            'AnomalyScoring' { $null = $flags.Add('NonTerminalAnomalyScoring') }
            'JSChallenge' { $null = $flags.Add('JSChallenge') }
            'CAPTCHA' { $null = $flags.Add('CAPTCHA') }
        }
        $conditionIndex = 0
        $conditions = @(
            foreach ($condition in (Get-Collection $rule 'matchConditions')) {
                # Expose behavior-relevant condition metadata without leaking private match values.
                $conditionIndex++
                if ($condition['matchVariable'] -ceq 'RemoteAddr') { $null = $flags.Add('OriginalClientIp') }
                if ($condition['matchVariable'] -ceq 'SocketAddr') { $null = $flags.Add('SocketPeerIp') }
                $geoValues = @()
                if ($condition['operator'] -ceq 'GeoMatch') {
                    $null = $flags.Add('GeoMatch')
                    $geoValues = @(Get-Collection $condition 'matchValue')
                    if (-not @($geoValues | Where-Object { $_ -iin 'ZZ', 'Unknown' }).Count) {
                        $null = $flags.Add('GeoMatchMissingUnknown')
                    }
                }
                [pscustomobject]@{
                    Index = $conditionIndex
                    MatchVariable = $condition['matchVariable']
                    Selector = if ($condition.Contains('selector')) { $condition['selector'] } else { $null }
                    Operator = $condition['operator']
                    NegateCondition = if ($condition.Contains('negateCondition')) { $condition['negateCondition'] } else { $false }
                    Transforms = Get-Collection $condition 'transforms'
                    MatchValueCount = @(Get-Collection $condition 'matchValue').Count
                    GeoMatchValues = $geoValues
                }
            }
        )
        # Keep policy-level behavior flags separate from each condition's diagnostics.
        [pscustomobject]@{
            Name = $rule['name']
            EnabledState = $rule['enabledState'] ?? 'Enabled'
            Priority = $rule['priority']
            RuleType = $rule['ruleType']
            Action = $rule['action']
            RateLimitThreshold = if ($rule.Contains('rateLimitThreshold')) { $rule['rateLimitThreshold'] } else { $null }
            RateLimitDurationInMinutes = if ($rule.Contains('rateLimitDurationInMinutes')) { $rule['rateLimitDurationInMinutes'] } else { $null }
            GroupBy = @((Get-Collection $rule 'groupBy') | ForEach-Object { $_['variableName'] })
            BehaviorFlags = @($flags | Sort-Object)
            Conditions = $conditions
        }
    }
    return $assessments
}

function Get-IdentityMap {
    <#
    .SYNOPSIS
    Indexes a collection by its case-sensitive identity.
    .DESCRIPTION
    Rejects missing, blank, and duplicate identities instead of silently overwriting entries.
    .PARAMETER Items
    Dictionary items to index.
    .PARAMETER Identity
    Identity field such as name, ruleSetType, ruleGroupName, or ruleId.
    .PARAMETER Path
    Collection path used in error messages.
    .OUTPUTS
    An ordinal Dictionary[string,object].
    #>
    param([object[]] $Items, [string] $Identity, [string] $Path)
    $map = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($item in $Items) {
        if ($item -isnot [System.Collections.IDictionary] -or
            -not $item.Contains($Identity) -or [string]::IsNullOrWhiteSpace([string] $item[$Identity])) {
            throw "Missing '$Identity' in $Path."
        }
        $id = [string] $item[$Identity]
        if ($map.ContainsKey($id)) { throw "Duplicate '$id' in $Path." }
        $map.Add($id, $item)
    }
    return ,$map
}

function Get-CollectionIdentity {
    <#
    .SYNOPSIS
    Selects the matching key for a migration collection.
    .DESCRIPTION
    Shares identity selection between inheritance and comparison. Other arrays remain atomic lists.
    .PARAMETER Key
    Collection property name.
    .PARAMETER Path
    Parent path distinguishing custom-rule and managed-rule arrays.
    .OUTPUTS
    Identity field name, or no output for a non-keyed collection.
    #>
    param([string] $Key, [string] $Path)
    switch ($Key) {
        'managedRuleSets' { 'ruleSetType' }
        'ruleGroupOverrides' { 'ruleGroupName' }
        'rules' {
            if ($Path -eq 'properties.customRules') { 'name' }
            elseif ($Path -match '\.ruleGroupOverrides\[') { 'ruleId' }
        }
    }
}

#endregion

#region Embedded catalog and policy validation helpers
function Get-CatalogIndex {
    <#
    .SYNOPSIS
    Returns cached group and rule indexes for an embedded managed rule set.
    .DESCRIPTION
    Lazily indexes each type/version once per run, validating duplicate catalog identities.
    .PARAMETER Key
    Managed rule set type/version, for example Microsoft_DefaultRuleSet/2.2.
    .OUTPUTS
    Object with Groups and Rules dictionaries; Rules is keyed by group name.
    #>
    param([string] $Key)
    if ($script:catalogIndexes.ContainsKey($Key)) { return $script:catalogIndexes[$Key] }
    if (-not $drsCatalog.ContainsKey($Key)) {
        throw "Embedded catalog does not support managed rule set $Key. Update the embedded catalog before using this version."
    }
    $groups = Get-IdentityMap (Get-Collection $drsCatalog[$Key] 'ruleGroups') 'ruleGroupName' $Key
    $rules = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($groupName in $groups.Keys) {
        $rules.Add($groupName, (Get-IdentityMap (Get-Collection $groups[$groupName] 'rules') 'ruleId' "$Key/$groupName"))
    }
    $index = [pscustomobject]@{ Groups = $groups; Rules = $rules }
    $script:catalogIndexes.Add($Key, $index)
    return $index
}

function Get-DrsRuleInventory {
    <#
    .SYNOPSIS
    Inventories embedded DRS versions, native defaults, target PL, and documented 2.2 relationships.
    .DESCRIPTION
    Returns native rule metadata for each supported version without Azure catalog queries.
    #>
    param([string] $TargetVersion = '2.2')
    $targetIndex = Get-CatalogIndex 'Microsoft_DefaultRuleSet/2.2'
    $targetRows = @(
        foreach ($groupName in $targetIndex.Rules.Keys) {
            foreach ($ruleId in $targetIndex.Rules[$groupName].Keys) {
                @{ ruleId = $ruleId; ruleGroupName = $groupName; paranoiaLevel = $targetIndex.Rules[$groupName][$ruleId]['paranoiaLevel'] }
            }
        }
    )
    $targetRules = Get-IdentityMap $targetRows 'ruleId' 'DRS 2.2 rule inventory'
    $selectedIndex = if ($TargetVersion) { Get-CatalogIndex "Microsoft_DefaultRuleSet/$TargetVersion" }
        else { @{ Rules = @{} } }
    $selectedRows = @(
        foreach ($groupName in $selectedIndex.Rules.Keys) {
            foreach ($ruleId in $selectedIndex.Rules[$groupName].Keys) {
                @{ ruleId = $ruleId; paranoiaLevel = $selectedIndex.Rules[$groupName][$ruleId]['paranoiaLevel'] }
            }
        }
    )
    $selectedRules = Get-IdentityMap $selectedRows 'ruleId' "DRS $TargetVersion target inventory"
    $supersedes = @{}
    foreach ($ruleId in $supersededRuleIds.Keys) {
        $replacementId = $supersededRuleIds[$ruleId]
        if (-not $targetRules.ContainsKey($replacementId)) {
            throw "Documented replacement $replacementId is missing from the DRS 2.2 inventory."
        }
        if ($supersedes.ContainsKey($replacementId)) { throw "Ambiguous supersession metadata for $replacementId." }
        $supersedes[$replacementId] = $ruleId
    }
    return ,@(
        foreach ($version in '1.0', '1.1', '2.0', '2.1', '2.2') {
            $index = Get-CatalogIndex "Microsoft_DefaultRuleSet/$version"
            foreach ($groupName in @($index.Rules.Keys | Sort-Object -CaseSensitive)) {
                foreach ($ruleId in @($index.Rules[$groupName].Keys | Sort-Object -CaseSensitive)) {
                    $rule = $index.Rules[$groupName][$ruleId]
                    if (-not $rule.Contains('defaultState') -or $rule['defaultState'] -notin 'Enabled', 'Disabled') {
                        throw "Embedded catalog does not provide a usable defaultState for DRS $version/$groupName/$ruleId."
                    }
                    $replacementId = if ($supersededRuleIds.ContainsKey($ruleId)) { $supersededRuleIds[$ruleId] } else { $null }
                    [pscustomobject]@{
                        # Native defaults and replacement annotations are independent metadata.
                        RuleSetVersion = $version
                        RuleGroupName = $groupName
                        RuleId = $ruleId
                        Description = if ($rule.Contains('description') -and
                            -not [string]::IsNullOrWhiteSpace([string] $rule['description'])) {
                            [string] $rule['description']
                        } else { 'Embedded catalog does not provide a description for this rule.' }
                        DefaultState = [string] $rule['defaultState']
                        DefaultAction = if ($rule.Contains('defaultAction')) { [string] $rule['defaultAction'] } else { $null }
                        ParanoiaLevel = $rule['paranoiaLevel']
                        TargetRuleSetVersion = $TargetVersion
                        TargetParanoiaLevel = if ($selectedRules.ContainsKey($ruleId)) { $selectedRules[$ruleId]['paranoiaLevel'] } else { $null }
                        AvailableInTargetDrs = $selectedRules.ContainsKey($ruleId)
                        AvailableInDrs22 = $targetRules.ContainsKey($ruleId)
                        SupersededByRuleId = $replacementId
                        SupersededByRuleGroupName = if ($null -ne $replacementId) { $targetRules[$replacementId]['ruleGroupName'] } else { $null }
                        SupersedesRuleId = if ($version -in '2.0', '2.1', '2.2' -and $supersedes.ContainsKey($ruleId)) { $supersedes[$ruleId] } else { $null }
                    }
                }
            }
        }
    )
}

function ConvertTo-PolicyConfiguration {
    <#
    .SYNOPSIS
    Extracts and normalizes a Front Door WAF resource for migration.
    .DESCRIPTION
    Copies writable properties/tags, removes read-only fields and null properties,
    normalizes default rule-set aliases, optionally aligns source carryover to the
    target DRS version, and supplies missing
    keyed arrays. Does not change the input resource or infer service defaults.
    .PARAMETER Resource
    Concrete Front Door WAF resource dictionary.
    .PARAMETER Label
    Input label, normally Master or Source, for diagnostics.
    .PARAMETER AllowMissingDefaultRuleSet
    Allows custom-only policies and policies containing only optional managed families.
    Source, master and final target may omit the default rule set.
    .PARAMETER TargetDrsVersion
    Aligns source carryover and its default-rule-set exception scopes to this target
    version. Omit for a master to preserve its declared set and scope versions.
    .OUTPUTS
    Ordered dictionary containing tags and properties.
    #>
    param([System.Collections.IDictionary] $Resource, [string] $Label, [switch] $AllowMissingDefaultRuleSet,
        [string] $TargetDrsVersion)
    if (-not $Resource.Contains('type') -or $Resource['type'] -ine $resourceType) {
        throw "$Label is not a Front Door WAF resource."
    }
    if (-not $Resource.Contains('properties') -or $Resource['properties'] -isnot [System.Collections.IDictionary]) {
        throw "$Label has no policy properties."
    }
    $properties = Copy-JsonValue $Resource['properties']
    # Association/status fields describe the source resource, not writable target configuration.
    foreach ($key in 'frontendEndpointLinks', 'routingRuleLinks', 'securityPolicyLinks', 'resourceState', 'provisioningState') {
        $properties.Remove($key)
    }
    foreach ($key in $properties.Keys) {
        if ($key -notin 'policySettings', 'customRules', 'managedRules') {
            throw "Unsupported writable property '$key' in $Label; refusing to discard it."
        }
    }
    Remove-NullProperties $properties
    if ($AllowMissingDefaultRuleSet) {
        # A custom-only source contributes no managed baseline.
        if (-not $properties.Contains('managedRules')) {
            $properties['managedRules'] = [ordered]@{ managedRuleSets = @() }
        }
        elseif ($properties['managedRules'] -is [System.Collections.IDictionary] -and
            -not $properties['managedRules'].Contains('managedRuleSets')) {
            $properties['managedRules']['managedRuleSets'] = @()
        }
    }
    Assert-PolicyShape $properties 'Policy' $Label
    $exceptionIssues = @(Get-ExceptionValidationIssues $properties['managedRules'])
    if ($exceptionIssues.Count) { throw "$Label has invalid request exceptions:`n$($exceptionIssues -join "`n")" }
    $sets = Get-Collection $properties['managedRules'] 'managedRuleSets'
    if (-not $properties.Contains('customRules')) { $properties['customRules'] = [ordered]@{ rules = @() } }
    elseif (-not $properties['customRules'].Contains('rules')) { $properties['customRules']['rules'] = @() }
    foreach ($set in $sets) {
        # Normalize omitted collections without altering configured rule values.
        if (-not $set.Contains('ruleGroupOverrides')) { $set['ruleGroupOverrides'] = @() }
        foreach ($group in $set['ruleGroupOverrides']) {
            if (-not $group.Contains('rules')) { $group['rules'] = @() }
        }
    }
    $defaultSets = @($sets | Where-Object { $_['ruleSetType'] -in 'DefaultRuleSet', 'Microsoft_DefaultRuleSet' })
    if ($defaultSets.Count -gt 1 -or ($defaultSets.Count -eq 0 -and -not $AllowMissingDefaultRuleSet)) {
        $requirement = $AllowMissingDefaultRuleSet ? 'at most one' : 'exactly one'
        throw "$Label must contain $requirement default rule set."
    }
    if ($defaultSets.Count -eq 1) {
        # Normalize identity/version only; existing overrides retain their group names and rule IDs.
        $defaultSets[0]['ruleSetType'] = 'Microsoft_DefaultRuleSet'
        if ($TargetDrsVersion) { $defaultSets[0]['ruleSetVersion'] = $TargetDrsVersion }
    }
    if ($properties['managedRules'].Contains('exceptionsList')) {
        foreach ($exception in (Get-Collection $properties['managedRules']['exceptionsList'] 'exceptions')) {
            foreach ($scope in (Get-Collection $exception 'scopes')) {
                if ($scope['ruleSetType'] -in 'DefaultRuleSet', 'Microsoft_DefaultRuleSet') {
                    $scope['ruleSetType'] = 'Microsoft_DefaultRuleSet'
                    if ($TargetDrsVersion) { $scope['ruleSetVersion'] = $TargetDrsVersion }
                }
            }
        }
    }
    $tags = if ($Resource.Contains('tags') -and $null -ne $Resource['tags']) { Copy-JsonValue $Resource['tags'] } else { [ordered]@{} }
    if ($tags -isnot [System.Collections.IDictionary]) { throw "$Label tags must be an object." }
    return [ordered]@{ tags = $tags; properties = $properties }
}

function New-DefaultDrsTargetConfiguration {
    <#
    .SYNOPSIS
    Creates latest native targets only for source-configured families, preserving other settings.
    .DESCRIPTION
    Clears managed tuning and request exceptions for supported families while
    preserving custom rules, policy settings and tags.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration)
    $configuration = Copy-JsonValue $SourceConfiguration
    $managed = $configuration['properties']['managedRules']
    $sets = Get-Collection $managed 'managedRuleSets'
    $types = Get-ManagedRuleSetTypes
    $otherSets = @($sets | Where-Object { $_['ruleSetType'] -cnotin $types })
    $managed['managedRuleSets'] = @($otherSets) + @(
        foreach ($type in $types) {
            if ($null -eq (Get-DrsSet $SourceConfiguration $type)) { continue }
            $set = [ordered]@{
                ruleSetType = $type; ruleSetVersion = Get-LatestManagedRuleSetVersion $type
                ruleGroupOverrides = @()
            }
            if ($type -ceq 'Microsoft_DefaultRuleSet') { $set['ruleSetAction'] = 'Block' }
            $set
        }
    )
    if ($managed.Contains('exceptionsList')) {
        $exceptions = @(
            # Discard defaulted-family scopes without widening any remaining exception.
            foreach ($exception in (Get-Collection $managed['exceptionsList'] 'exceptions')) {
                $scopes = Get-Collection $exception 'scopes'
                $otherScopes = @($scopes | Where-Object { $_['ruleSetType'] -cnotin $types })
                if ($otherScopes.Count) {
                    $exception['scopes'] = $otherScopes
                    $exception
                }
            }
        )
        $managed['exceptionsList']['exceptions'] = $exceptions
    }
    return $configuration
}

function Invoke-ArmRead {
    <#
    .SYNOPSIS
    Reads ARM JSON through Az.Accounts in the validated current context.
    .DESCRIPTION
    Performs GET only, requires HTTP 200, and propagates authentication/transport/JSON errors.
    .PARAMETER Path
    ARM path including its API-version query.
    .OUTPUTS
    JSON dictionaries parsed using PowerShell 7 ConvertFrom-Json -AsHashtable.
    #>
    param([string] $Path)
    $response = Invoke-AzRestMethod -Path $Path -Method GET -DefaultProfile $context -ErrorAction Stop
    if ($response.StatusCode -ne 200) {
        throw "ARM GET '$Path' returned HTTP $($response.StatusCode): $($response.Content)"
    }
    $document = ConvertFrom-Json -InputObject $response.Content -AsHashtable -Depth 100 -NoEnumerate
    if ($document -isnot [System.Collections.IDictionary]) { throw "ARM GET '$Path' did not return a JSON object." }
    return $document
}

function Resolve-PolicyInput {
    <#
    .SYNOPSIS
    Resolves a policy resource ID or validates a local policy JSON file.
    .DESCRIPTION
    Extracts exactly one concrete WAF resource from a file without Azure access.
    Resource-ID descriptors retain their subscription for context checks before GETs.
    .PARAMETER Value
    Complete Front Door WAF resource ID or a filesystem JSON path.
    .PARAMETER Label
    Source or Master input label used in diagnostics.
    .OUTPUTS
    Descriptor with ResourceId, SubscriptionId, FilePath and a local Resource if present.
    #>
    param([string] $Value, [string] $Label)
    $resourceId = $null
    $subscription = $null
    $filePath = $null
    $resource = $null
    if ($Value.StartsWith('/')) {
        $pattern = '^/subscriptions/(?<subscription>[0-9a-fA-F-]{36})/resourceGroups/[^/]+/providers/Microsoft\.Network/frontdoorWebApplicationFirewallPolicies/[^/]+$'
        $idMatch = [regex]::Match($Value, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $subscriptionGuid = [guid]::Empty
        if (-not $idMatch.Success -or -not [guid]::TryParse($idMatch.Groups['subscription'].Value, [ref] $subscriptionGuid)) {
            throw "$Label must be a complete Front Door WAF policy resource ID or a JSON file path."
        }
        $resourceId = $Value
        $subscription = $subscriptionGuid.ToString()
    } else {
        $file = Get-Item -LiteralPath $Value -ErrorAction Stop
        if ($file -isnot [System.IO.FileInfo]) { throw "$Label must be a filesystem JSON file, not a directory or another provider item." }
        $filePath = $file.FullName
        # NoEnumerate prevents a single-resource JSON array from being mistaken for an object.
        $resource = ConvertFrom-Json -InputObject (Get-Content -LiteralPath $filePath -Raw) -AsHashtable -Depth 100 -NoEnumerate
        if ($resource -isnot [System.Collections.IDictionary]) {
            throw "$Label JSON must be a resource object or an ARM template object."
        }
        if ($resource.Contains('resources')) {
            if ($resource['resources'] -isnot [System.Collections.IList]) { throw "$Label template resources must be a JSON array." }
            $resources = @($resource['resources'] | Where-Object {
                $_ -is [System.Collections.IDictionary] -and $_['type'] -ieq $resourceType
            })
            if ($resources.Count -ne 1) { throw "$Label template must contain exactly one Front Door WAF resource." }
            $resource = ConvertFrom-ArmResource $resources[0]
        }
        if ($resource['type'] -ine $resourceType -or $resource['properties'] -isnot [System.Collections.IDictionary]) {
            throw "$Label JSON must contain a Front Door WAF resource with policy properties."
        }
        if ($Label -eq 'Source' -and ($resource['name'] -isnot [string] -or
            [string]::IsNullOrWhiteSpace($resource['name']))) {
            throw 'Source JSON must contain a nonempty policy name.'
        }
    }
    [pscustomobject]@{
        ResourceId = $resourceId; SubscriptionId = $subscription
        FilePath = $filePath; Resource = $resource
    }
}

function Read-PolicyInput {
    <#
    .SYNOPSIS
    Reads live policy values or returns a previously validated local resource.
    .DESCRIPTION
    Uses GET only for resource-ID inputs; JSON descriptors never access Azure.
    The caller must validate the selected context before any live read.
    .PARAMETER InputPolicy
    Descriptor returned by Resolve-PolicyInput.
    .OUTPUTS
    Front Door WAF resource dictionary.
    #>
    param([pscustomobject] $InputPolicy)
    if ($InputPolicy.ResourceId) { return Invoke-ArmRead "$($InputPolicy.ResourceId)?api-version=$apiVersion" }
    return $InputPolicy.Resource
}

function Get-ExceptionValidationIssues {
    <#
    .SYNOPSIS
    Reports invalid request-exception predicates and policy-local preview limits.
    .DESCRIPTION
    Checks header selectors, variable/operator combinations, IP/CIDR syntax and
    nonempty scopes without printing potentially sensitive match values.
    EqualsAny is retained as an API-supported wildcard, including an empty value list.
    The associated Front Door's aggregate limit requires deployment-time validation.
    #>
    param([System.Collections.IDictionary] $ManagedRules)
    if (-not $ManagedRules.Contains('exceptionsList')) { return }
    $exceptions = Get-Collection $ManagedRules['exceptionsList'] 'exceptions'
    if ($exceptions.Count -gt 60) { 'Exception list exceeds the policy limit of 60 exceptions.' }
    for ($index = 0; $index -lt $exceptions.Count; $index++) {
        $exception = $exceptions[$index]
        $label = "Exception $($index + 1)"
        $variable = $exception['matchVariable']
        $operator = $exception['valueMatchOperator']
        $values = Get-Collection $exception 'matchValues'
        $limit = if ($variable -ceq 'SocketAddr') { 600 } else { 10 }
        if ($values.Count -gt $limit) { "$label exceeds the $limit match-value limit for $variable." }
        if ($operator -cne 'EqualsAny' -and -not $values.Count) { "$label needs at least one match value." }
        if (@($values | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) {
            "$label contains an empty match value."
        }
        if ($variable -ceq 'RequestHeaderNames') {
            if (-not $exception.Contains('selector') -or [string]::IsNullOrWhiteSpace($exception['selector']) -or
                $exception['selector'] -cnotmatch "^[!#$%&'*+.^_``|~0-9A-Za-z-]+$" -or
                -not $exception.Contains('selectorMatchOperator') -or $exception['selectorMatchOperator'] -cne 'Equals') {
                "$label requires a valid header-name selector and selectorMatchOperator Equals."
            }
        } elseif ($exception.Contains('selector') -or $exception.Contains('selectorMatchOperator')) {
            "$label uses header-selector fields with $variable; selectors apply only to RequestHeaderNames."
        }
        if ($variable -ceq 'SocketAddr') {
            if ($operator -cne 'IPMatch') { "$label must use IPMatch for SocketAddr." }
            # Parse literal addresses locally; never resolve names or expose address values in errors.
            foreach ($value in $values) {
                $parts = $value.Split('/')
                $address = $null
                $valid = $parts.Count -le 2 -and
                    ($parts[0].Contains(':') -or $parts[0] -cmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') -and
                    [System.Net.IPAddress]::TryParse($parts[0], [ref] $address)
                if ($valid -and $parts.Count -eq 2) {
                    $prefix = 0
                    $bits = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
                    $valid = $parts[1] -cmatch '^[0-9]+$' -and
                        [int]::TryParse($parts[1], [ref] $prefix) -and $prefix -le $bits
                }
                if (-not $valid) { "$label contains an invalid IP address or CIDR prefix."; break }
            }
        } elseif ($operator -ceq 'IPMatch') { "$label cannot use IPMatch for $variable." }
        $scopes = Get-Collection $exception 'scopes'
        if (-not $scopes.Count) { "$label needs at least one explicit managed-rule scope." }
    }
}

function Get-CatalogIssues {
    <#
    .SYNOPSIS
    Reports managed-rule and exception identities incompatible with the embedded catalog.
    .DESCRIPTION
    Checks type/version, group, rule, and configured exception scopes using cached indexes.
    Duplicate configured identities are errors, not review warnings.
    .PARAMETER Configuration
    Normalized configuration or a managed-rules fragment.
    .OUTPUTS
    Zero or more diagnostic strings.
    #>
    param([System.Collections.IDictionary] $Configuration)
    $sets = Get-Collection $Configuration['properties']['managedRules'] 'managedRuleSets'
    # Duplicate configured identities are invalid even when catalog checks would otherwise pass.
    $setMap = Get-IdentityMap $sets 'ruleSetType' 'managedRuleSets'
    foreach ($set in $sets) {
        $type = [string] $set['ruleSetType']
        $version = [string] $set['ruleSetVersion']
        $catalogKey = "$type/$version"
        if (-not $drsCatalog.ContainsKey($catalogKey)) {
            "Managed rule set $catalogKey is not in the embedded catalog."
            continue
        }
        $index = Get-CatalogIndex $catalogKey
        $groups = $index.Groups
        $additionalFamily = $type -in 'Microsoft_BotManagerRuleSet', 'Microsoft_HTTPDDoSRuleSet'
        if ($additionalFamily -and (Get-Collection $set 'exclusions').Count) {
            "Exclusions are supported only for DRS, not $catalogKey."
        }
        $overrides = Get-Collection $set 'ruleGroupOverrides'
        $null = Get-IdentityMap $overrides 'ruleGroupName' "$catalogKey/ruleGroupOverrides"
        foreach ($group in $overrides) {
            $groupName = [string] $group['ruleGroupName']
            if ($additionalFamily -and (Get-Collection $group 'exclusions').Count) {
                "Exclusions are supported only for DRS, not $catalogKey/$groupName."
            }
            if (-not $groups.ContainsKey($groupName)) {
                "Group $catalogKey/$groupName is not in the embedded catalog."
                continue
            }
            $rules = $index.Rules[$groupName]
            $ruleOverrides = Get-Collection $group 'rules'
            $null = Get-IdentityMap $ruleOverrides 'ruleId' "$catalogKey/$groupName/rules"
            foreach ($rule in $ruleOverrides) {
                # A shared ARM schema does not imply every managed family supports every field.
                if ($additionalFamily -and (Get-Collection $rule 'exclusions').Count) {
                    "Exclusions are supported only for DRS, not $catalogKey/$groupName/$($rule['ruleId'])."
                }
                if ($additionalFamily -and $rule.Contains('action') -and
                    $rule['action'] -cnotin 'Allow', 'Log', 'Redirect', 'Block', 'JSChallenge', 'CAPTCHA') {
                    "Action $($rule['action']) is not supported by $catalogKey/$groupName/$($rule['ruleId']); anomaly scoring is DRS-only."
                }
                if (-not $rules.ContainsKey([string] $rule['ruleId'])) {
                    "Override $catalogKey/$groupName/$($rule['ruleId']) is not in the embedded catalog."
                }
            }
        }
    }
    $managed = $Configuration['properties']['managedRules']
    Get-ExceptionValidationIssues $managed
    if ($managed.Contains('exceptionsList')) {
        if ((Get-Collection $managed['exceptionsList'] 'exceptions').Count -and
            (-not $setMap.ContainsKey('Microsoft_DefaultRuleSet') -or
                $setMap['Microsoft_DefaultRuleSet']['ruleSetVersion'] -cnotin '2.1', '2.2')) {
            'Exception lists require the next-generation WAF engine with a configured DRS 2.1 or later.'
        }
        foreach ($exception in (Get-Collection $managed['exceptionsList'] 'exceptions')) {
            foreach ($scope in (Get-Collection $exception 'scopes')) {
                $type = [string] $scope['ruleSetType']
                $key = "$type/$($scope['ruleSetVersion'])"
                if ($type -ceq 'Microsoft_DefaultRuleSet' -and $scope['ruleSetVersion'] -cnotin '2.1', '2.2') {
                    "Exception scope $key is unsupported. Request exceptions are supported only for DRS 2.1 or later."
                }
                # An available catalog version is insufficient: the policy must actually configure it.
                if (-not $setMap.ContainsKey($type) -or $setMap[$type]['ruleSetVersion'] -cne $scope['ruleSetVersion']) {
                    "Exception scope $key does not match a configured managed rule set."
                }
                if (-not $drsCatalog.ContainsKey($key)) {
                    "Exception scope $key is not in the embedded catalog."
                    continue
                }
                $index = Get-CatalogIndex $key
                $groups = $index.Groups
                foreach ($group in (Get-Collection $scope 'ruleGroupScopes')) {
                    # Reject unknown scope membership rather than widening an exception.
                    $name = [string] $group['ruleGroupName']
                    if (-not $groups.ContainsKey($name)) {
                        "Exception group $key/$name is not in the embedded catalog."
                        continue
                    }
                    $rules = $index.Rules[$name]
                    foreach ($rule in (Get-Collection $group 'ruleScopes')) {
                        if (-not $rules.ContainsKey([string] $rule['ruleId'])) {
                            "Exception rule $key/$name/$($rule['ruleId']) is not in the embedded catalog."
                        }
                    }
                }
            }
        }
    }
}

function Assert-TargetConfiguration {
    <#
    .SYNOPSIS
    Validates the baseline or selected target before template generation.
    .DESCRIPTION
    Combines writable-shape validation with catalog checks, supported target DRS versions,
    supported settings ranges, custom-rule identities/priorities, and rate-limit constraints.
    Does not replace Azure resource-group deployment validation.
    .PARAMETER Configuration
    Target dictionary containing properties and tags.
    .OUTPUTS
    None. Throws on an invalid target.
    #>
    param([System.Collections.IDictionary] $Configuration)
    Assert-PolicyShape $Configuration['properties'] 'Policy' 'Target'
    foreach ($tag in $Configuration['tags'].Keys) {
        Assert-PolicyShape $Configuration['tags'][$tag] 'string' "Target.tags.$tag"
    }
    if ($Configuration['properties'].Contains('policySettings')) {
        # Validate challenge timeouts against the service limits before writing a template.
        $settings = $Configuration['properties']['policySettings']
        foreach ($key in 'javascriptChallengeExpirationInMinutes', 'captchaExpirationInMinutes') {
            if ($settings.Contains($key) -and ($settings[$key] -lt 5 -or $settings[$key] -gt 1440)) {
                throw "$key must be between 5 and 1440."
            }
        }
        if ($settings.Contains('customBlockResponseBody') -and
            $settings['customBlockResponseBody'] -cnotmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$') {
            throw 'customBlockResponseBody must be base64 encoded.'
        }
    }
    $issues = @(Get-CatalogIssues $Configuration)
    # Validate the combined target, not just each candidate; separate choices can be incompatible together.
    if ($issues.Count -gt 0) { throw "Invalid target configuration:`n$($issues -join "`n")" }
    $sets = Get-Collection $Configuration['properties']['managedRules'] 'managedRuleSets'
    $drs = @($sets | Where-Object { $_['ruleSetType'] -ceq 'Microsoft_DefaultRuleSet' })
    if ($drs.Count -gt 1) { throw 'Target must contain at most one Microsoft_DefaultRuleSet.' }
    if ($drs.Count -eq 1 -and $drs[0]['ruleSetVersion'] -notin '2.1', '2.2') {
        throw "Unsupported target DRS version '$($drs[0]['ruleSetVersion'])'; supported targets are 2.1 and 2.2."
    }
    foreach ($type in 'Microsoft_BotManagerRuleSet', 'Microsoft_HTTPDDoSRuleSet') {
        if ($null -ne (Get-DrsSet $Configuration $type)) { $null = Get-DrsTargetVersion $Configuration $type }
    }
    if ($Configuration['properties'].Contains('customRules')) {
        $rules = Get-Collection $Configuration['properties']['customRules'] 'rules'
        $null = Get-IdentityMap $rules 'name' 'customRules.rules'
        # Priority uniqueness is policy-wide; never repair evaluation order by automatic renumbering.
        $priorities = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($rule in $rules) {
            if ($rule['name'] -cnotmatch '^[A-Za-z][A-Za-z0-9]{0,127}$') { throw "Invalid custom rule name '$($rule['name'])'." }
            if ($rule['priority'] -lt 1 -or $rule['priority'] -gt 1000) { throw "Priority of '$($rule['name'])' must be between 1 and 1000." }
            if (-not $priorities.Add([int] $rule['priority'])) { throw "Duplicate custom-rule priority $($rule['priority']); resolve the source/template choices rather than silently renumbering." }
            if ((Get-Collection $rule 'matchConditions').Count -eq 0) { throw "Custom rule '$($rule['name'])' has no match conditions." }
            if ($rule['ruleType'] -ceq 'RateLimitRule') {
                if (-not $rule.Contains('rateLimitThreshold') -or $rule['rateLimitThreshold'] -le 0) { throw "RateLimitRule '$($rule['name'])' needs a positive rateLimitThreshold." }
                if ($rule.Contains('rateLimitDurationInMinutes') -and $rule['rateLimitDurationInMinutes'] -notin 1, 5) { throw "RateLimitRule '$($rule['name'])' duration must be 1 or 5 minutes." }
            }
        }
    }
}

#endregion

#region Embedded official DRS documentation
function Get-EmbeddedDrsCatalog {
    <#
    .SYNOPSIS
    Loads pinned DRS 1.0, 1.1, 2.0, 2.1, and 2.2 membership, groups, and defaults.
    .DESCRIPTION
    Uses version-native rule identities, descriptions, defaults and paranoia levels
    from the Azure 2026-04-01 managed-rule catalog. Microsoft Learn supplies the
    companion display descriptions. This data is embedded; loading it makes no
    network requests.
    #>
    # https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs
    $groupRows = @'
"RuleSetVersion","RuleGroupName","Description"
"1.0","FIX","Protect against session-fixation attacks"
"1.0","JAVA","Protect against JAVA attacks"
"1.0","LFI","Protect against file and path attacks"
"1.0","MS-ThreatIntel-CVEs","Protect against CVE attacks"
"1.0","MS-ThreatIntel-WebShells","Protect against Web shell attacks"
"1.0","PHP","Protect against PHP-injection attacks"
"1.0","PROTOCOL-ATTACK","Protect against header injection, request smuggling, and response splitting"
"1.0","RCE","Protect against remote command execution"
"1.0","RFI","Protect against remote file inclusion attacks"
"1.0","SQLI","Protect against SQL-injection attacks"
"1.0","XSS","Protect against cross-site scripting attacks"
"1.1","FIX","Protect against session-fixation attacks"
"1.1","JAVA","Protect against JAVA attacks"
"1.1","LFI","Protect against file and path attacks"
"1.1","MS-ThreatIntel-AppSec","Protect against AppSec attacks"
"1.1","MS-ThreatIntel-CVEs","Protect against CVE attacks"
"1.1","MS-ThreatIntel-SQLI","Protect against SQLI attacks"
"1.1","MS-ThreatIntel-WebShells","Protect against Web shell attacks"
"1.1","PHP","Protect against PHP-injection attacks"
"1.1","PROTOCOL-ATTACK","Protect against header injection, request smuggling, and response splitting"
"1.1","RCE","Protect against remote command execution"
"1.1","RFI","Protect against remote file inclusion attacks"
"1.1","SQLI","Protect against SQL-injection attacks"
"1.1","XSS","Protect against cross-site scripting attacks"
"2.0","FIX","Session Fixation attacks"
"2.0","General","Method Enforcement"
"2.0","JAVA","Java attacks"
"2.0","LFI","Local file inclusion"
"2.0","METHOD-ENFORCEMENT","Method Enforcement"
"2.0","MS-ThreatIntel-AppSec","Path traversal evasion"
"2.0","MS-ThreatIntel-CVEs","Rest API exploitation"
"2.0","MS-ThreatIntel-SQLI","SQL injection"
"2.0","MS-ThreatIntel-WebShells","Web shell attacks"
"2.0","NODEJS","Node JS Attacks"
"2.0","PHP","PHP attacks"
"2.0","PROTOCOL-ATTACK","Protocol attack"
"2.0","PROTOCOL-ENFORCEMENT","Protocol Enforcement"
"2.0","RCE","Remote Command Execution attacks"
"2.0","RFI","Remote file inclusion"
"2.0","SQLI","SQL injection"
"2.0","XSS","Cross-site scripting"
"2.1","FIX","Session Fixation attacks"
"2.1","General","Method Enforcement"
"2.1","JAVA","Java attacks"
"2.1","LFI","Local file inclusion"
"2.1","METHOD-ENFORCEMENT","Method Enforcement"
"2.1","MS-ThreatIntel-AppSec","Path traversal evasion"
"2.1","MS-ThreatIntel-CVEs","Rest API exploitation"
"2.1","MS-ThreatIntel-SQLI","SQL injection"
"2.1","MS-ThreatIntel-WebShells","Web shell attacks"
"2.1","NODEJS","Node JS Attacks"
"2.1","PHP","PHP attacks"
"2.1","PROTOCOL-ATTACK","Protocol attack"
"2.1","PROTOCOL-ENFORCEMENT","Protocol Enforcement"
"2.1","RCE","Remote Command Execution attacks"
"2.1","RFI","Remote file inclusion"
"2.1","SQLI","SQL injection"
"2.1","XSS","Cross-site scripting"
"2.2","FIX","Protect against session-fixation attacks"
"2.2","General","General group"
"2.2","JAVA","Protect against JAVA attacks"
"2.2","LFI","Protect against file and path attacks"
"2.2","METHOD-ENFORCEMENT","Lock-down methods (PUT, PATCH)"
"2.2","MS-ThreatIntel-AppSec","Protect against AppSec attacks"
"2.2","MS-ThreatIntel-CVEs","Protect against CVE attacks"
"2.2","MS-ThreatIntel-SQLI","Protect against SQLI attacks"
"2.2","MS-ThreatIntel-WebShells","Protect against Web shell attacks"
"2.2","MS-ThreatIntel-XSS","Protect against XSS attacks"
"2.2","NODEJS","Protect against Node JS attacks"
"2.2","PHP","Protect against PHP-injection attacks"
"2.2","PROTOCOL-ATTACK","Protect against header injection, request smuggling, and response splitting"
"2.2","PROTOCOL-ENFORCEMENT","Protect against protocol and encoding issues"
"2.2","RCE","Protect again remote code execution attacks"
"2.2","RFI","Protect against remote file inclusion (RFI) attacks"
"2.2","SQLI","Protect against SQL-injection attacks"
"2.2","XSS","Protect against cross-site scripting attacks"
'@ | ConvertFrom-Csv
    # PL snapshot 2026-10-06 from the same official article: DRS 1.x and two native
    # 2.2 rules have no documented PL. Blank values are unknown, not inferred from state.
    $ruleRows = @'
"RuleSetVersion","RuleGroupName","RuleId","DefaultState","DefaultAction","Description","ParanoiaLevel"
"1.0","FIX","943100","Enabled","Block","Possible Session Fixation Attack: Setting Cookie Values in HTML",""
"1.0","FIX","943110","Enabled","Block","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referrer",""
"1.0","FIX","943120","Enabled","Block","Possible Session Fixation Attack: SessionID Parameter Name with No Referrer",""
"1.0","JAVA","944100","Enabled","Block","Remote Command Execution: Apache Struts, Oracle WebLogic",""
"1.0","JAVA","944110","Enabled","Block","Detects potential payload execution",""
"1.0","JAVA","944120","Enabled","Block","Possible payload execution and remote command execution",""
"1.0","JAVA","944130","Enabled","Block","Suspicious Java classes",""
"1.0","JAVA","944200","Enabled","Block","Exploitation of Java deserialization Apache Commons",""
"1.0","JAVA","944210","Enabled","Block","Possible use of Java serialization",""
"1.0","JAVA","944240","Enabled","Block","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)",""
"1.0","JAVA","944250","Enabled","Block","Remote Command Execution: Suspicious Java method detected",""
"1.0","LFI","930100","Enabled","Block","Path Traversal Attack (/../)",""
"1.0","LFI","930110","Enabled","Block","Path Traversal Attack (/../)",""
"1.0","LFI","930120","Enabled","Block","OS File Access Attempt",""
"1.0","LFI","930130","Enabled","Block","Restricted File Access Attempt",""
"1.0","MS-ThreatIntel-CVEs","99001014","Disabled","Block","Attempted Spring Cloud routing-expression injection CVE-2022-22963",""
"1.0","MS-ThreatIntel-CVEs","99001015","Disabled","Block","Attempted Spring Framework unsafe class object exploitation CVE-2022-22965",""
"1.0","MS-ThreatIntel-CVEs","99001016","Disabled","Block","Attempted Spring Cloud Gateway Actuator injection CVE-2022-22947",""
"1.0","MS-ThreatIntel-CVEs","99001017","Disabled","Block","Attempted Apache Struts file upload exploitation CVE-2023-50164",""
"1.0","MS-ThreatIntel-WebShells","99005006","Disabled","Block","Spring4Shell Interaction Attempt",""
"1.0","PHP","933100","Enabled","Block","PHP Injection Attack: Opening/Closing Tag Found",""
"1.0","PHP","933110","Enabled","Block","PHP Injection Attack: PHP Script File Upload Found",""
"1.0","PHP","933120","Enabled","Block","PHP Injection Attack: Configuration Directive Found",""
"1.0","PHP","933130","Enabled","Block","PHP Injection Attack: Variables Found",""
"1.0","PHP","933140","Enabled","Block","PHP Injection Attack: I/O Stream Found",""
"1.0","PHP","933150","Enabled","Block","PHP Injection Attack: High-Risk PHP Function Name Found",""
"1.0","PHP","933151","Enabled","Block","PHP Injection Attack: Medium-Risk PHP Function Name Found",""
"1.0","PHP","933160","Enabled","Block","PHP Injection Attack: High-Risk PHP Function Call Found",""
"1.0","PHP","933170","Enabled","Block","PHP Injection Attack: Serialized Object Injection",""
"1.0","PHP","933180","Enabled","Block","PHP Injection Attack: Variable Function Call Found",""
"1.0","PROTOCOL-ATTACK","921110","Enabled","Block","HTTP Request Smuggling Attack",""
"1.0","PROTOCOL-ATTACK","921120","Enabled","Block","HTTP Response Splitting Attack",""
"1.0","PROTOCOL-ATTACK","921130","Enabled","Block","HTTP Response Splitting Attack",""
"1.0","PROTOCOL-ATTACK","921140","Enabled","Block","HTTP Header Injection Attack via headers",""
"1.0","PROTOCOL-ATTACK","921150","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF detected)",""
"1.0","PROTOCOL-ATTACK","921151","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF detected)",""
"1.0","PROTOCOL-ATTACK","921160","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF and header-name detected)",""
"1.0","RCE","932100","Enabled","Block","Remote Command Execution: Unix Command Injection",""
"1.0","RCE","932105","Enabled","Block","Remote Command Execution: Unix Command Injection",""
"1.0","RCE","932110","Enabled","Block","Remote Command Execution: Windows Command Injection",""
"1.0","RCE","932115","Enabled","Block","Remote Command Execution: Windows Command Injection",""
"1.0","RCE","932120","Enabled","Block","Remote Command Execution: Windows PowerShell Command Found",""
"1.0","RCE","932130","Enabled","Block","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) or Text4Shell (CVE-2022-42889) Found",""
"1.0","RCE","932140","Enabled","Block","Remote Command Execution: Windows FOR/IF Command Found",""
"1.0","RCE","932150","Enabled","Block","Remote Command Execution: Direct Unix Command Execution",""
"1.0","RCE","932160","Enabled","Block","Remote Command Execution: Unix Shell Code Found",""
"1.0","RCE","932170","Enabled","Block","Remote Command Execution: Shellshock (CVE-2014-6271)",""
"1.0","RCE","932171","Enabled","Block","Remote Command Execution: Shellshock (CVE-2014-6271)",""
"1.0","RCE","932180","Enabled","Block","Restricted File Upload Attempt",""
"1.0","RFI","931100","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address",""
"1.0","RFI","931110","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload",""
"1.0","RFI","931120","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)",""
"1.0","RFI","931130","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link",""
"1.0","SQLI","942100","Enabled","Block","SQL Injection Attack Detected via libinjection",""
"1.0","SQLI","942110","Enabled","Block","SQL Injection Attack: Common Injection Testing Detected",""
"1.0","SQLI","942120","Enabled","Block","SQL Injection Attack: SQL Operator Detected",""
"1.0","SQLI","942140","Enabled","Block","SQL Injection Attack: Common DB Names Detected",""
"1.0","SQLI","942150","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942160","Enabled","Block","Detects blind SQLI tests using sleep() or benchmark()",""
"1.0","SQLI","942170","Enabled","Block","Detects SQL benchmark and sleep injection attempts including conditional queries",""
"1.0","SQLI","942180","Enabled","Block","Detects basic SQL authentication bypass attempts 1/3",""
"1.0","SQLI","942190","Enabled","Block","Detects MSSQL code execution and information gathering attempts",""
"1.0","SQLI","942200","Enabled","Block","Detects MySQL comment-/space-obfuscated injections and backtick termination",""
"1.0","SQLI","942210","Enabled","Block","Detects chained SQL injection attempts 1/2",""
"1.0","SQLI","942220","Enabled","Block","Looking for integer overflow attacks, these rules come from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash",""
"1.0","SQLI","942230","Enabled","Block","Detects conditional SQL injection attempts",""
"1.0","SQLI","942240","Enabled","Block","Detects MySQL charset switch and MSSQL DoS attempts",""
"1.0","SQLI","942250","Enabled","Block","Detects MATCH AGAINST, MERGE, and EXECUTE IMMEDIATE injections",""
"1.0","SQLI","942260","Enabled","Block","Detects basic SQL authentication bypass attempts 2/3",""
"1.0","SQLI","942270","Enabled","Block","Looking for basic SQL injection. Common attack string for MySQL, Oracle, and others",""
"1.0","SQLI","942280","Enabled","Block","Detects Postgres pg\_sleep injection, wait for delay attacks and database shutdown attempts",""
"1.0","SQLI","942290","Enabled","Block","Finds basic MongoDB SQL injection attempts",""
"1.0","SQLI","942300","Enabled","Block","Detects MySQL comments, conditions, and ch(a)r injections",""
"1.0","SQLI","942310","Enabled","Block","Detects chained SQL injection attempts 2/2",""
"1.0","SQLI","942320","Enabled","Block","Detects MySQL and PostgreSQL stored procedure/function injections",""
"1.0","SQLI","942330","Enabled","Block","Detects classic SQL injection probings 1/2",""
"1.0","SQLI","942340","Enabled","Block","Detects basic SQL authentication bypass attempts 3/3",""
"1.0","SQLI","942350","Enabled","Block","Detects MySQL UDF injection and other data/structure manipulation attempts",""
"1.0","SQLI","942360","Enabled","Block","Detects concatenated basic SQL injection and SQLLFI attempts",""
"1.0","SQLI","942361","Enabled","Block","Detects basic SQL injection based on keyword alter or union",""
"1.0","SQLI","942370","Enabled","Block","Detects classic SQL injection probings 2/2",""
"1.0","SQLI","942380","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942390","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942400","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942410","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942430","Enabled","Block","Restricted SQL Character Anomaly Detection (args): number of special characters exceeded (12)",""
"1.0","SQLI","942440","Enabled","Block","SQL Comment Sequence Detected",""
"1.0","SQLI","942450","Enabled","Block","SQL Hex Encoding Identified",""
"1.0","SQLI","942470","Enabled","Block","SQL Injection Attack",""
"1.0","SQLI","942480","Enabled","Block","SQL Injection Attack",""
"1.0","XSS","941100","Enabled","Block","XSS Attack Detected via libinjection",""
"1.0","XSS","941101","Enabled","Block","XSS Attack Detected via libinjection.This rule detects requests with a `Referer` header",""
"1.0","XSS","941110","Enabled","Block","XSS Filter - Category 1: Script Tag Vector",""
"1.0","XSS","941120","Enabled","Block","XSS Filter - Category 2: Event Handler Vector",""
"1.0","XSS","941130","Enabled","Block","XSS Filter - Category 3: Attribute Vector",""
"1.0","XSS","941140","Enabled","Block","XSS Filter - Category 4: JavaScript URI Vector",""
"1.0","XSS","941150","Enabled","Block","XSS Filter - Category 5: Disallowed HTML Attributes",""
"1.0","XSS","941160","Enabled","Block","NoScript XSS InjectionChecker: HTML Injection",""
"1.0","XSS","941170","Enabled","Block","NoScript XSS InjectionChecker: Attribute Injection",""
"1.0","XSS","941180","Enabled","Block","Node-Validator Blocklist Keywords",""
"1.0","XSS","941190","Enabled","Block","XSS Using style sheets",""
"1.0","XSS","941200","Enabled","Block","XSS using VML frames",""
"1.0","XSS","941210","Enabled","Block","IE XSS Filters - Attack Detected or Text4Shell (CVE-2022-42889)",""
"1.0","XSS","941220","Enabled","Block","XSS using obfuscated VB Script",""
"1.0","XSS","941230","Enabled","Block","XSS using `embed` tag",""
"1.0","XSS","941240","Enabled","Block","XSS using `import` or `implementation` attribute",""
"1.0","XSS","941250","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.0","XSS","941260","Enabled","Block","XSS using `meta` tag",""
"1.0","XSS","941270","Enabled","Block","XSS using `link` href",""
"1.0","XSS","941280","Enabled","Block","XSS using `base` tag",""
"1.0","XSS","941290","Enabled","Block","XSS using `applet` tag",""
"1.0","XSS","941300","Enabled","Block","XSS using `object` tag",""
"1.0","XSS","941310","Enabled","Block","US-ASCII Malformed Encoding XSS Filter - Attack Detected",""
"1.0","XSS","941320","Enabled","Block","Possible XSS Attack Detected - HTML Tag Handler",""
"1.0","XSS","941330","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.0","XSS","941340","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.0","XSS","941350","Enabled","Block","UTF-7 Encoding IE XSS - Attack Detected",""
"1.1","FIX","943100","Enabled","Block","Possible Session Fixation Attack: Setting Cookie Values in HTML",""
"1.1","FIX","943110","Enabled","Block","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referrer",""
"1.1","FIX","943120","Enabled","Block","Possible Session Fixation Attack: SessionID Parameter Name with No Referrer",""
"1.1","JAVA","944100","Enabled","Block","Remote Command Execution: Suspicious Java class detected",""
"1.1","JAVA","944110","Enabled","Block","Possible Session Fixation Attack: Setting Cookie Values in HTML",""
"1.1","JAVA","944120","Enabled","Block","Remote Command Execution: Java serialization (CVE-2015-5842)",""
"1.1","JAVA","944130","Enabled","Block","Suspicious Java class detected",""
"1.1","JAVA","944200","Enabled","Block","Magic bytes detected, probable Java serialization in use",""
"1.1","JAVA","944210","Enabled","Block","Magic bytes detected Base64 encoded, probable Java serialization in use",""
"1.1","JAVA","944240","Enabled","Block","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)",""
"1.1","JAVA","944250","Enabled","Block","Remote Command Execution: Suspicious Java method detected",""
"1.1","LFI","930100","Enabled","Block","Path Traversal Attack (/../)",""
"1.1","LFI","930110","Enabled","Block","Path Traversal Attack (/../)",""
"1.1","LFI","930120","Enabled","Block","OS File Access Attempt",""
"1.1","LFI","930130","Enabled","Block","Restricted File Access Attempt",""
"1.1","MS-ThreatIntel-AppSec","99030001","Enabled","Block","Path Traversal Evasion in Headers (/.././../)",""
"1.1","MS-ThreatIntel-AppSec","99030002","Enabled","Block","Path Traversal Evasion in Request Body (/.././../)",""
"1.1","MS-ThreatIntel-CVEs","99001001","Enabled","Block","Attempted F5 tmui (CVE-2020-5902) REST API Exploitation with known credentials",""
"1.1","MS-ThreatIntel-CVEs","99001014","Disabled","Block","Attempted Spring Cloud routing-expression injection CVE-2022-22963",""
"1.1","MS-ThreatIntel-CVEs","99001015","Disabled","Block","Attempted Spring Framework unsafe class object exploitation CVE-2022-22965",""
"1.1","MS-ThreatIntel-CVEs","99001016","Disabled","Block","Attempted Spring Cloud Gateway Actuator injection CVE-2022-22947",""
"1.1","MS-ThreatIntel-CVEs","99001017","Disabled","Block","Attempted Apache Struts file upload exploitation CVE-2023-50164",""
"1.1","MS-ThreatIntel-CVEs","99001018","Enabled","Block","Attempted React2Shell remote code execution exploitation (CVE-2025-55182)",""
"1.1","MS-ThreatIntel-SQLI","99031001","Enabled","Block","SQL Injection Attack: Common Injection Testing Detected",""
"1.1","MS-ThreatIntel-SQLI","99031002","Enabled","Block","SQL Comment Sequence Detected",""
"1.1","MS-ThreatIntel-WebShells","99005002","Enabled","Block","Web Shell Interaction Attempt (POST)",""
"1.1","MS-ThreatIntel-WebShells","99005003","Enabled","Block","Web Shell Upload Attempt (POST) - CHOPPER PHP",""
"1.1","MS-ThreatIntel-WebShells","99005004","Enabled","Block","Web Shell Upload Attempt (POST) - CHOPPER ASPX",""
"1.1","MS-ThreatIntel-WebShells","99005006","Disabled","Block","Spring4Shell Interaction Attempt",""
"1.1","PHP","933100","Enabled","Block","PHP Injection Attack: PHP Open Tag Found",""
"1.1","PHP","933110","Enabled","Block","PHP Injection Attack: PHP Script File Upload Found",""
"1.1","PHP","933120","Enabled","Block","PHP Injection Attack: Configuration Directive Found",""
"1.1","PHP","933130","Enabled","Block","PHP Injection Attack: Variables Found",""
"1.1","PHP","933140","Enabled","Block","PHP Injection Attack: I/O Stream Found",""
"1.1","PHP","933150","Enabled","Block","PHP Injection Attack: High-Risk PHP Function Name Found",""
"1.1","PHP","933151","Enabled","Block","PHP Injection Attack: Medium-Risk PHP Function Name Found",""
"1.1","PHP","933160","Enabled","Block","PHP Injection Attack: High-Risk PHP Function Call Found",""
"1.1","PHP","933170","Enabled","Block","PHP Injection Attack: Serialized Object Injection",""
"1.1","PHP","933180","Enabled","Block","PHP Injection Attack: Variable Function Call Found",""
"1.1","PROTOCOL-ATTACK","921110","Enabled","Block","HTTP Request Smuggling Attack",""
"1.1","PROTOCOL-ATTACK","921120","Enabled","Block","HTTP Response Splitting Attack",""
"1.1","PROTOCOL-ATTACK","921130","Enabled","Block","HTTP Response Splitting Attack",""
"1.1","PROTOCOL-ATTACK","921140","Enabled","Block","HTTP Header Injection Attack via headers",""
"1.1","PROTOCOL-ATTACK","921150","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF detected)",""
"1.1","PROTOCOL-ATTACK","921151","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF detected)",""
"1.1","PROTOCOL-ATTACK","921160","Enabled","Block","HTTP Header Injection Attack via payload (CR/LF and header-name detected)",""
"1.1","RCE","932100","Enabled","Block","Remote Command Execution: Unix Command Injection",""
"1.1","RCE","932105","Enabled","Block","Remote Command Execution: Unix Command Injection",""
"1.1","RCE","932110","Enabled","Block","Remote Command Execution: Windows Command Injection",""
"1.1","RCE","932115","Enabled","Block","Remote Command Execution: Windows Command Injection",""
"1.1","RCE","932120","Enabled","Block","Remote Command Execution: Windows PowerShell Command Found",""
"1.1","RCE","932130","Enabled","Block","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) or Text4Shell (CVE-2022-42889) Found",""
"1.1","RCE","932140","Enabled","Block","Remote Command Execution: Windows FOR/IF Command Found",""
"1.1","RCE","932150","Enabled","Block","Remote Command Execution: Direct Unix Command Execution",""
"1.1","RCE","932160","Enabled","Block","Remote Command Execution: Shellshock (CVE-2014-6271)",""
"1.1","RCE","932170","Enabled","Block","Remote Command Execution: Shellshock (CVE-2014-6271)",""
"1.1","RCE","932171","Enabled","Block","Remote Command Execution: Shellshock (CVE-2014-6271)",""
"1.1","RCE","932180","Enabled","Block","Restricted File Upload Attempt",""
"1.1","RFI","931100","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address",""
"1.1","RFI","931110","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload",""
"1.1","RFI","931120","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)",""
"1.1","RFI","931130","Enabled","Block","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link",""
"1.1","SQLI","942100","Enabled","Block","SQL Injection Attack Detected via libinjection",""
"1.1","SQLI","942110","Disabled","Block","SQL Injection Attack: Common Injection Testing Detected",""
"1.1","SQLI","942120","Enabled","Block","SQL Injection Attack: SQL Operator Detected",""
"1.1","SQLI","942140","Enabled","Block","SQL Injection Attack: Common DB Names Detected",""
"1.1","SQLI","942150","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942160","Enabled","Block","Detects blind SQLI tests using sleep() or benchmark()",""
"1.1","SQLI","942170","Enabled","Block","Detects SQL benchmark and sleep injection attempts including conditional queries",""
"1.1","SQLI","942180","Enabled","Block","Detects basic SQL authentication bypass attempts 1/3",""
"1.1","SQLI","942190","Enabled","Block","Detects MSSQL code execution and information gathering attempts",""
"1.1","SQLI","942200","Enabled","Block","Detects MySQL comment-/space-obfuscated injections and backtick termination",""
"1.1","SQLI","942210","Enabled","Block","Detects chained SQL injection attempts 1/2",""
"1.1","SQLI","942220","Enabled","Block","Looking for integer overflow attacks, these rules come from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash",""
"1.1","SQLI","942230","Enabled","Block","Detects conditional SQL injection attempts",""
"1.1","SQLI","942240","Enabled","Block","Detects MySQL charset switch and MSSQL DoS attempts",""
"1.1","SQLI","942250","Enabled","Block","Detects MATCH AGAINST, MERGE, and EXECUTE IMMEDIATE injections",""
"1.1","SQLI","942260","Enabled","Block","Detects basic SQL authentication bypass attempts 2/3",""
"1.1","SQLI","942270","Enabled","Block","Looking for basic SQL injection. Common attack string for MySQL, Oracle, and others",""
"1.1","SQLI","942280","Enabled","Block","Detects Postgres pg\_sleep injection, wait for delay attacks and database shutdown attempts",""
"1.1","SQLI","942290","Enabled","Block","Finds basic MongoDB SQL injection attempts",""
"1.1","SQLI","942300","Enabled","Block","Detects MySQL comments, conditions, and ch(a)r injections",""
"1.1","SQLI","942310","Enabled","Block","Detects chained SQL injection attempts 2/2",""
"1.1","SQLI","942320","Enabled","Block","Detects MySQL and PostgreSQL stored procedure/function injections",""
"1.1","SQLI","942330","Enabled","Block","Detects classic SQL injection probings 1/3",""
"1.1","SQLI","942340","Enabled","Block","Detects basic SQL authentication bypass attempts 3/3",""
"1.1","SQLI","942350","Enabled","Block","Detects MySQL UDF injection and other data/structure manipulation attempts",""
"1.1","SQLI","942360","Enabled","Block","Detects concatenated basic SQL injection and SQLLFI attempts",""
"1.1","SQLI","942361","Enabled","Block","Detects basic SQL injection based on keyword alter or union",""
"1.1","SQLI","942370","Enabled","Block","Detects classic SQL injection probings 2/3",""
"1.1","SQLI","942380","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942390","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942400","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942410","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942430","Disabled","Block","Restricted SQL Character Anomaly Detection (args): number of special characters exceeded (12)",""
"1.1","SQLI","942440","Disabled","Block","SQL Comment Sequence Detected",""
"1.1","SQLI","942450","Enabled","Block","SQL Hex Encoding Identified",""
"1.1","SQLI","942470","Enabled","Block","SQL Injection Attack",""
"1.1","SQLI","942480","Enabled","Block","SQL Injection Attack",""
"1.1","XSS","941100","Enabled","Block","XSS Attack Detected via libinjection",""
"1.1","XSS","941101","Enabled","Block","XSS Attack Detected via libinjection.This rule detects requests with a `Referer` header",""
"1.1","XSS","941110","Enabled","Block","XSS Filter - Category 1: Script Tag Vector",""
"1.1","XSS","941120","Enabled","Block","XSS Filter - Category 2: Event Handler Vector",""
"1.1","XSS","941130","Enabled","Block","XSS Filter - Category 3: Attribute Vector",""
"1.1","XSS","941140","Enabled","Block","XSS Filter - Category 4: JavaScript URI Vector",""
"1.1","XSS","941150","Enabled","Block","XSS Filter - Category 5: Disallowed HTML Attributes",""
"1.1","XSS","941160","Enabled","Block","NoScript XSS InjectionChecker: HTML Injection",""
"1.1","XSS","941170","Enabled","Block","NoScript XSS InjectionChecker: Attribute Injection",""
"1.1","XSS","941180","Enabled","Block","Node-Validator Blocklist Keywords",""
"1.1","XSS","941190","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941200","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941210","Enabled","Block","IE XSS Filters - Attack Detected or Text4Shell (CVE-2022-42889) found",""
"1.1","XSS","941220","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941230","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941240","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941250","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941260","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941270","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941280","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941290","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941300","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941310","Enabled","Block","US-ASCII Malformed Encoding XSS Filter - Attack Detected",""
"1.1","XSS","941320","Enabled","Block","Possible XSS Attack Detected - HTML Tag Handler",""
"1.1","XSS","941330","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941340","Enabled","Block","IE XSS Filters - Attack Detected",""
"1.1","XSS","941350","Enabled","Block","UTF-7 Encoding IE XSS - Attack Detected",""
"2.0","FIX","943100","Enabled","AnomalyScoring","Possible Session Fixation Attack: Setting Cookie Values in HTML","1"
"2.0","FIX","943110","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer","1"
"2.0","FIX","943120","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with No Referer","1"
"2.0","General","200002","Enabled","AnomalyScoring","Failed to parse request body.","1"
"2.0","General","200003","Enabled","AnomalyScoring","Multipart request body failed strict validation","1"
"2.0","JAVA","944100","Enabled","AnomalyScoring","Remote Command Execution: Suspicious Java class detected","1"
"2.0","JAVA","944110","Enabled","AnomalyScoring","Remote Command Execution: Java process spawn (CVE-2017-9805)","1"
"2.0","JAVA","944120","Enabled","AnomalyScoring","Remote Command Execution: Java serialization (CVE-2015-5842)","1"
"2.0","JAVA","944130","Enabled","AnomalyScoring","Suspicious Java class detected","1"
"2.0","JAVA","944200","Enabled","AnomalyScoring","Magic bytes Detected, probable java serialization in use","2"
"2.0","JAVA","944210","Enabled","AnomalyScoring","Magic bytes Detected Base64 Encoded, probable java serialization in use","2"
"2.0","JAVA","944240","Enabled","AnomalyScoring","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)","2"
"2.0","JAVA","944250","Enabled","AnomalyScoring","Remote Command Execution: Suspicious Java method detected","2"
"2.0","LFI","930100","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.0","LFI","930110","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.0","LFI","930120","Enabled","AnomalyScoring","OS File Access Attempt","1"
"2.0","LFI","930130","Enabled","AnomalyScoring","Restricted File Access Attempt","1"
"2.0","METHOD-ENFORCEMENT","911100","Enabled","AnomalyScoring","Method is not allowed by policy","1"
"2.0","MS-ThreatIntel-AppSec","99030001","Enabled","AnomalyScoring","Path Traversal Evasion in Headers (/.././../)","2"
"2.0","MS-ThreatIntel-AppSec","99030002","Enabled","AnomalyScoring","Path Traversal Evasion in Request Body (/.././../)","2"
"2.0","MS-ThreatIntel-CVEs","99001001","Enabled","AnomalyScoring","Attempted F5 tmui (CVE-2020-5902) REST API Exploitation with known credentials","2"
"2.0","MS-ThreatIntel-CVEs","99001014","Disabled","AnomalyScoring","Attempted Spring Cloud routing-expression injection (CVE-2022-22963)","2"
"2.0","MS-ThreatIntel-CVEs","99001015","Disabled","AnomalyScoring","Attempted Spring Framework unsafe class object exploitation (CVE-2022-22965)","2"
"2.0","MS-ThreatIntel-CVEs","99001016","Disabled","AnomalyScoring","Attempted Spring Cloud Gateway Actuator injection (CVE-2022-22947)","2"
"2.0","MS-ThreatIntel-CVEs","99001017","Disabled","AnomalyScoring","Attempted Apache Struts file upload exploitation (CVE-2023-50164)","2"
"2.0","MS-ThreatIntel-CVEs","99001018","Enabled","AnomalyScoring","Attempted React2Shell remote code execution exploitation (CVE-2025-55182)","1"
"2.0","MS-ThreatIntel-SQLI","99031001","Enabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected","2"
"2.0","MS-ThreatIntel-SQLI","99031002","Enabled","AnomalyScoring","SQL Comment Sequence Detected.","2"
"2.0","MS-ThreatIntel-WebShells","99005002","Enabled","AnomalyScoring","Web Shell Interaction Attempt (POST)","2"
"2.0","MS-ThreatIntel-WebShells","99005003","Enabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER PHP","2"
"2.0","MS-ThreatIntel-WebShells","99005004","Enabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER ASPX","2"
"2.0","MS-ThreatIntel-WebShells","99005006","Disabled","AnomalyScoring","Spring4Shell Interaction Attempt","2"
"2.0","NODEJS","934100","Enabled","AnomalyScoring","Node.js Injection Attack","1"
"2.0","PHP","933100","Enabled","AnomalyScoring","PHP Injection Attack: PHP Open Tag Found","1"
"2.0","PHP","933110","Enabled","AnomalyScoring","PHP Injection Attack: PHP Script File Upload Found","1"
"2.0","PHP","933120","Enabled","AnomalyScoring","PHP Injection Attack: Configuration Directive Found","1"
"2.0","PHP","933130","Enabled","AnomalyScoring","PHP Injection Attack: Variables Found","1"
"2.0","PHP","933140","Enabled","AnomalyScoring","PHP Injection Attack: I/O Stream Found","1"
"2.0","PHP","933150","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Name Found","1"
"2.0","PHP","933151","Enabled","AnomalyScoring","PHP Injection Attack: Medium-Risk PHP Function Name Found","2"
"2.0","PHP","933160","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Call Found","1"
"2.0","PHP","933170","Enabled","AnomalyScoring","PHP Injection Attack: Serialized Object Injection","1"
"2.0","PHP","933180","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.0","PHP","933200","Enabled","AnomalyScoring","PHP Injection Attack: Wrapper scheme detected","1"
"2.0","PHP","933210","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.0","PROTOCOL-ATTACK","921110","Enabled","AnomalyScoring","HTTP Request Smuggling Attack","1"
"2.0","PROTOCOL-ATTACK","921120","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.0","PROTOCOL-ATTACK","921130","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.0","PROTOCOL-ATTACK","921140","Enabled","AnomalyScoring","HTTP Header Injection Attack via headers","1"
"2.0","PROTOCOL-ATTACK","921150","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","1"
"2.0","PROTOCOL-ATTACK","921151","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","2"
"2.0","PROTOCOL-ATTACK","921160","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF and header-name detected)","1"
"2.0","PROTOCOL-ENFORCEMENT","920100","Enabled","AnomalyScoring","Invalid HTTP Request Line","1"
"2.0","PROTOCOL-ENFORCEMENT","920120","Enabled","AnomalyScoring","Attempted multipart/form-data bypass","1"
"2.0","PROTOCOL-ENFORCEMENT","920121","Enabled","AnomalyScoring","Attempted multipart/form-data bypass","2"
"2.0","PROTOCOL-ENFORCEMENT","920160","Enabled","AnomalyScoring","Content-Length HTTP header is not numeric.","1"
"2.0","PROTOCOL-ENFORCEMENT","920170","Enabled","AnomalyScoring","GET or HEAD Request with Body Content.","1"
"2.0","PROTOCOL-ENFORCEMENT","920171","Enabled","AnomalyScoring","GET or HEAD Request with Transfer-Encoding.","1"
"2.0","PROTOCOL-ENFORCEMENT","920180","Enabled","AnomalyScoring","POST without Content-Length or Transfer-Encoding headers.","1"
"2.0","PROTOCOL-ENFORCEMENT","920190","Enabled","AnomalyScoring","Range: Invalid Last Byte Value.","1"
"2.0","PROTOCOL-ENFORCEMENT","920200","Enabled","AnomalyScoring","Range: Too many fields (6 or more)","2"
"2.0","PROTOCOL-ENFORCEMENT","920201","Enabled","AnomalyScoring","Range: Too many fields for pdf request (63 or more)","2"
"2.0","PROTOCOL-ENFORCEMENT","920210","Enabled","AnomalyScoring","Multiple/Conflicting Connection Header Data Found.","1"
"2.0","PROTOCOL-ENFORCEMENT","920220","Enabled","AnomalyScoring","URL Encoding Abuse Attack Attempt","1"
"2.0","PROTOCOL-ENFORCEMENT","920230","Enabled","AnomalyScoring","Multiple URL Encoding Detected","2"
"2.0","PROTOCOL-ENFORCEMENT","920240","Enabled","AnomalyScoring","URL Encoding Abuse Attack Attempt","1"
"2.0","PROTOCOL-ENFORCEMENT","920260","Enabled","AnomalyScoring","Unicode Full/Half Width Abuse Attack Attempt","1"
"2.0","PROTOCOL-ENFORCEMENT","920270","Enabled","AnomalyScoring","Invalid character in request (null character)","1"
"2.0","PROTOCOL-ENFORCEMENT","920271","Enabled","AnomalyScoring","Invalid character in request (non printable characters)","2"
"2.0","PROTOCOL-ENFORCEMENT","920280","Enabled","AnomalyScoring","Request Missing a Host Header","1"
"2.0","PROTOCOL-ENFORCEMENT","920290","Enabled","AnomalyScoring","Empty Host Header","1"
"2.0","PROTOCOL-ENFORCEMENT","920300","Enabled","AnomalyScoring","Request Missing an Accept Header","2"
"2.0","PROTOCOL-ENFORCEMENT","920310","Enabled","AnomalyScoring","Request Has an Empty Accept Header","1"
"2.0","PROTOCOL-ENFORCEMENT","920311","Enabled","AnomalyScoring","Request Has an Empty Accept Header","1"
"2.0","PROTOCOL-ENFORCEMENT","920320","Enabled","AnomalyScoring","Missing User Agent Header","2"
"2.0","PROTOCOL-ENFORCEMENT","920330","Enabled","AnomalyScoring","Empty User Agent Header","1"
"2.0","PROTOCOL-ENFORCEMENT","920340","Enabled","AnomalyScoring","Request Containing Content, but Missing Content-Type header","1"
"2.0","PROTOCOL-ENFORCEMENT","920341","Enabled","AnomalyScoring","Request Containing Content Requires Content-Type header","2"
"2.0","PROTOCOL-ENFORCEMENT","920350","Enabled","AnomalyScoring","Host header is a numeric IP address","1"
"2.0","PROTOCOL-ENFORCEMENT","920420","Enabled","AnomalyScoring","Request content type is not allowed by policy","1"
"2.0","PROTOCOL-ENFORCEMENT","920430","Enabled","AnomalyScoring","HTTP protocol version is not allowed by policy","1"
"2.0","PROTOCOL-ENFORCEMENT","920440","Enabled","AnomalyScoring","URL file extension is restricted by policy","1"
"2.0","PROTOCOL-ENFORCEMENT","920450","Enabled","AnomalyScoring","HTTP header is restricted by policy","1"
"2.0","PROTOCOL-ENFORCEMENT","920470","Enabled","AnomalyScoring","Illegal Content-Type header","1"
"2.0","PROTOCOL-ENFORCEMENT","920480","Enabled","AnomalyScoring","Request content type charset is not allowed by policy","1"
"2.0","RCE","932100","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.0","RCE","932105","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.0","RCE","932110","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.0","RCE","932115","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.0","RCE","932120","Enabled","AnomalyScoring","Remote Command Execution: Windows PowerShell Command Found","1"
"2.0","RCE","932130","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found","1"
"2.0","RCE","932140","Enabled","AnomalyScoring","Remote Command Execution: Windows FOR/IF Command Found","1"
"2.0","RCE","932150","Enabled","AnomalyScoring","Remote Command Execution: Direct Unix Command Execution","1"
"2.0","RCE","932160","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Code Found","1"
"2.0","RCE","932170","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.0","RCE","932171","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.0","RCE","932180","Enabled","AnomalyScoring","Restricted File Upload Attempt","1"
"2.0","RFI","931100","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address","1"
"2.0","RFI","931110","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload","1"
"2.0","RFI","931120","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)","1"
"2.0","RFI","931130","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link","2"
"2.0","SQLI","942100","Enabled","AnomalyScoring","SQL Injection Attack Detected via libinjection","1"
"2.0","SQLI","942110","Disabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected","2"
"2.0","SQLI","942120","Enabled","AnomalyScoring","SQL Injection Attack: SQL Operator Detected","2"
"2.0","SQLI","942140","Enabled","AnomalyScoring","SQL Injection Attack: Common DB Names Detected","1"
"2.0","SQLI","942150","Enabled","AnomalyScoring","SQL Injection Attack (replaced by rule #99031003)","2"
"2.0","SQLI","942160","Enabled","AnomalyScoring","Detects blind sqli tests using sleep() or benchmark().","1"
"2.0","SQLI","942170","Enabled","AnomalyScoring","Detects SQL benchmark and sleep injection attempts including conditional queries","1"
"2.0","SQLI","942180","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 1/3","2"
"2.0","SQLI","942190","Enabled","AnomalyScoring","Detects MSSQL code execution and information gathering attempts","1"
"2.0","SQLI","942200","Enabled","AnomalyScoring","Detects MySQL comment-/space-obfuscated injections and backtick termination","2"
"2.0","SQLI","942210","Enabled","AnomalyScoring","Detects chained SQL injection attempts 1/2","2"
"2.0","SQLI","942220","Enabled","AnomalyScoring","Looking for integer overflow attacks, these are taken from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash","1"
"2.0","SQLI","942230","Enabled","AnomalyScoring","Detects conditional SQL injection attempts","1"
"2.0","SQLI","942240","Enabled","AnomalyScoring","Detects MySQL charset switch and MSSQL DoS attempts","1"
"2.0","SQLI","942250","Enabled","AnomalyScoring","Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections","1"
"2.0","SQLI","942260","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 2/3 (replaced by rule #99031004)","2"
"2.0","SQLI","942270","Enabled","AnomalyScoring","Looking for basic sql injection. Common attack string for mysql, oracle and others.","1"
"2.0","SQLI","942280","Enabled","AnomalyScoring","Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts","1"
"2.0","SQLI","942290","Enabled","AnomalyScoring","Finds basic MongoDB SQL injection attempts","1"
"2.0","SQLI","942300","Enabled","AnomalyScoring","Detects MySQL comments, conditions and ch(a)r injections","2"
"2.0","SQLI","942310","Enabled","AnomalyScoring","Detects chained SQL injection attempts 2/2","2"
"2.0","SQLI","942320","Enabled","AnomalyScoring","Detects MySQL and PostgreSQL stored procedure/function injections","1"
"2.0","SQLI","942330","Enabled","AnomalyScoring","Detects classic SQL injection probings 1/3","2"
"2.0","SQLI","942340","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 3/3 (replaced by rule #99031006)","2"
"2.0","SQLI","942350","Enabled","AnomalyScoring","Detects MySQL UDF injection and other data/structure manipulation attempts","1"
"2.0","SQLI","942360","Enabled","AnomalyScoring","Detects concatenated basic SQL injection and SQLLFI attempts","1"
"2.0","SQLI","942361","Enabled","AnomalyScoring","Detects basic SQL injection based on keyword alter or union","2"
"2.0","SQLI","942370","Enabled","AnomalyScoring","Detects classic SQL injection probings 2/3","2"
"2.0","SQLI","942380","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942390","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942400","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942410","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942430","Disabled","AnomalyScoring","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replaced by rule #99031005)","2"
"2.0","SQLI","942440","Disabled","AnomalyScoring","SQL Comment Sequence Detected (replaced by rule #99031002).","2"
"2.0","SQLI","942450","Enabled","AnomalyScoring","SQL Hex Encoding Identified","2"
"2.0","SQLI","942470","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942480","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.0","SQLI","942500","Enabled","AnomalyScoring","MySQL in-line comment detected.","1"
"2.0","SQLI","942510","Enabled","AnomalyScoring","SQLi bypass attempt by ticks or backticks detected.","2"
"2.0","XSS","941100","Enabled","AnomalyScoring","XSS Attack Detected via libinjection","1"
"2.0","XSS","941101","Enabled","AnomalyScoring","XSS Attack Detected via libinjection","2"
"2.0","XSS","941110","Enabled","AnomalyScoring","XSS Filter - Category 1: Script Tag Vector","1"
"2.0","XSS","941120","Enabled","AnomalyScoring","XSS Filter - Category 2: Event Handler Vector","1"
"2.0","XSS","941130","Enabled","AnomalyScoring","XSS Filter - Category 3: Attribute Vector","1"
"2.0","XSS","941140","Enabled","AnomalyScoring","XSS Filter - Category 4: Javascript URI Vector","1"
"2.0","XSS","941150","Enabled","AnomalyScoring","XSS Filter - Category 5: Disallowed HTML Attributes","2"
"2.0","XSS","941160","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: HTML Injection","1"
"2.0","XSS","941170","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: Attribute Injection","1"
"2.0","XSS","941180","Enabled","AnomalyScoring","Node-Validator Blacklist Keywords","1"
"2.0","XSS","941190","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941200","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941210","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941220","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941230","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941240","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941250","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941260","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941270","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941280","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941290","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941300","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.0","XSS","941310","Enabled","AnomalyScoring","US-ASCII Malformed Encoding XSS Filter - Attack Detected.","1"
"2.0","XSS","941320","Enabled","AnomalyScoring","Possible XSS Attack Detected - HTML Tag Handler","2"
"2.0","XSS","941330","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.0","XSS","941340","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.0","XSS","941350","Enabled","AnomalyScoring","UTF-7 Encoding IE XSS - Attack Detected.","1"
"2.0","XSS","941360","Enabled","AnomalyScoring","JSFuck / Hieroglyphy obfuscation detected","1"
"2.0","XSS","941370","Enabled","AnomalyScoring","JavaScript global variable found","1"
"2.0","XSS","941380","Enabled","AnomalyScoring","AngularJS client side template injection detected","2"
"2.1","FIX","943100","Enabled","AnomalyScoring","Possible Session Fixation Attack: Setting Cookie Values in HTML","1"
"2.1","FIX","943110","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer","1"
"2.1","FIX","943120","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with No Referer","1"
"2.1","General","200002","Enabled","AnomalyScoring","Failed to parse request body.","1"
"2.1","General","200003","Enabled","AnomalyScoring","Multipart request body failed strict validation","1"
"2.1","JAVA","944100","Enabled","AnomalyScoring","Remote Command Execution: Suspicious Java class detected","1"
"2.1","JAVA","944110","Enabled","AnomalyScoring","Remote Command Execution: Java process spawn (CVE-2017-9805)","1"
"2.1","JAVA","944120","Enabled","AnomalyScoring","Remote Command Execution: Java serialization (CVE-2015-5842)","1"
"2.1","JAVA","944130","Enabled","AnomalyScoring","Suspicious Java class detected","1"
"2.1","JAVA","944200","Enabled","AnomalyScoring","Magic bytes Detected, probable java serialization in use","2"
"2.1","JAVA","944210","Enabled","AnomalyScoring","Magic bytes Detected Base64 Encoded, probable java serialization in use","2"
"2.1","JAVA","944240","Enabled","AnomalyScoring","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)","2"
"2.1","JAVA","944250","Enabled","AnomalyScoring","Remote Command Execution: Suspicious Java method detected","2"
"2.1","LFI","930100","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.1","LFI","930110","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.1","LFI","930120","Enabled","AnomalyScoring","OS File Access Attempt","1"
"2.1","LFI","930130","Enabled","AnomalyScoring","Restricted File Access Attempt","1"
"2.1","METHOD-ENFORCEMENT","911100","Enabled","AnomalyScoring","Method is not allowed by policy","1"
"2.1","MS-ThreatIntel-AppSec","99030001","Enabled","AnomalyScoring","Path Traversal Evasion in Headers (/.././../)","2"
"2.1","MS-ThreatIntel-AppSec","99030002","Enabled","AnomalyScoring","Path Traversal Evasion in Request Body (/.././../)","2"
"2.1","MS-ThreatIntel-CVEs","99001001","Enabled","AnomalyScoring","Attempted F5 tmui (CVE-2020-5902) REST API Exploitation with known credentials","2"
"2.1","MS-ThreatIntel-CVEs","99001002","Enabled","AnomalyScoring","Attempted Citrix NSC_USER directory traversal (CVE-2019-19781)","2"
"2.1","MS-ThreatIntel-CVEs","99001003","Enabled","AnomalyScoring","Attempted Atlassian Confluence Widget Connector exploitation (CVE-2019-3396)","2"
"2.1","MS-ThreatIntel-CVEs","99001004","Enabled","AnomalyScoring","Attempted Pulse Secure custom template exploitation (CVE-2020-8243)","2"
"2.1","MS-ThreatIntel-CVEs","99001005","Enabled","AnomalyScoring","Attempted SharePoint type converter exploitation (CVE-2020-0932)","2"
"2.1","MS-ThreatIntel-CVEs","99001006","Enabled","AnomalyScoring","Attempted Pulse Connect directory traversal (CVE-2019-11510)","2"
"2.1","MS-ThreatIntel-CVEs","99001007","Enabled","AnomalyScoring","Attempted Junos OS J-Web local file inclusion (CVE-2020-1631)","2"
"2.1","MS-ThreatIntel-CVEs","99001008","Enabled","AnomalyScoring","Attempted Fortinet path traversal (CVE-2018-13379)","2"
"2.1","MS-ThreatIntel-CVEs","99001009","Enabled","AnomalyScoring","Attempted Apache struts ognl injection (CVE-2017-5638)","2"
"2.1","MS-ThreatIntel-CVEs","99001010","Enabled","AnomalyScoring","Attempted Apache struts ognl injection (CVE-2017-12611)","2"
"2.1","MS-ThreatIntel-CVEs","99001011","Enabled","AnomalyScoring","Attempted Oracle WebLogic path traversal (CVE-2020-14882)","2"
"2.1","MS-ThreatIntel-CVEs","99001012","Enabled","AnomalyScoring","Attempted Telerik WebUI insecure deserialization exploitation (CVE-2019-18935)","2"
"2.1","MS-ThreatIntel-CVEs","99001013","Enabled","AnomalyScoring","Attempted SharePoint insecure XML deserialization (CVE-2019-0604)","2"
"2.1","MS-ThreatIntel-CVEs","99001014","Disabled","AnomalyScoring","Attempted Spring Cloud routing-expression injection (CVE-2022-22963)","2"
"2.1","MS-ThreatIntel-CVEs","99001015","Disabled","AnomalyScoring","Attempted Spring Framework unsafe class object exploitation (CVE-2022-22965)","2"
"2.1","MS-ThreatIntel-CVEs","99001016","Disabled","AnomalyScoring","Attempted Spring Cloud Gateway Actuator injection (CVE-2022-22947)","2"
"2.1","MS-ThreatIntel-CVEs","99001017","Disabled","AnomalyScoring","Attempted Apache Struts file upload exploitation (CVE-2023-50164)","2"
"2.1","MS-ThreatIntel-CVEs","99001018","Enabled","AnomalyScoring","Attempted React2Shell remote code execution exploitation (CVE-2025-55182)","1"
"2.1","MS-ThreatIntel-CVEs","99001019","Disabled","AnomalyScoring","Attempted WP2Shell remote code execution exploitation (CVE-2026-63030)","2"
"2.1","MS-ThreatIntel-SQLI","99031001","Enabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected (replacing rule #942110)","2"
"2.1","MS-ThreatIntel-SQLI","99031002","Enabled","AnomalyScoring","SQL Comment Sequence Detected (replacing rule #942440).","2"
"2.1","MS-ThreatIntel-SQLI","99031003","Enabled","AnomalyScoring","SQL Injection Attack (replacing rule #942150)","2"
"2.1","MS-ThreatIntel-SQLI","99031004","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 2/3 (replacing rule #942260)","2"
"2.1","MS-ThreatIntel-WebShells","99005002","Enabled","AnomalyScoring","Web Shell Interaction Attempt (POST)","2"
"2.1","MS-ThreatIntel-WebShells","99005003","Enabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER PHP","2"
"2.1","MS-ThreatIntel-WebShells","99005004","Enabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER ASPX","2"
"2.1","MS-ThreatIntel-WebShells","99005005","Enabled","AnomalyScoring","Web Shell Interaction Attempt","2"
"2.1","MS-ThreatIntel-WebShells","99005006","Disabled","AnomalyScoring","Spring4Shell Interaction Attempt","2"
"2.1","NODEJS","934100","Enabled","AnomalyScoring","Node.js Injection Attack","1"
"2.1","PHP","933100","Enabled","AnomalyScoring","PHP Injection Attack: PHP Open Tag Found","1"
"2.1","PHP","933110","Enabled","AnomalyScoring","PHP Injection Attack: PHP Script File Upload Found","1"
"2.1","PHP","933120","Enabled","AnomalyScoring","PHP Injection Attack: Configuration Directive Found","1"
"2.1","PHP","933130","Enabled","AnomalyScoring","PHP Injection Attack: Variables Found","1"
"2.1","PHP","933140","Enabled","AnomalyScoring","PHP Injection Attack: I/O Stream Found","1"
"2.1","PHP","933150","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Name Found","1"
"2.1","PHP","933151","Enabled","AnomalyScoring","PHP Injection Attack: Medium-Risk PHP Function Name Found","2"
"2.1","PHP","933160","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Call Found","1"
"2.1","PHP","933170","Enabled","AnomalyScoring","PHP Injection Attack: Serialized Object Injection","1"
"2.1","PHP","933180","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.1","PHP","933200","Enabled","AnomalyScoring","PHP Injection Attack: Wrapper scheme detected","1"
"2.1","PHP","933210","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.1","PROTOCOL-ATTACK","921110","Enabled","AnomalyScoring","HTTP Request Smuggling Attack","1"
"2.1","PROTOCOL-ATTACK","921120","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.1","PROTOCOL-ATTACK","921130","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.1","PROTOCOL-ATTACK","921140","Enabled","AnomalyScoring","HTTP Header Injection Attack via headers","1"
"2.1","PROTOCOL-ATTACK","921150","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","1"
"2.1","PROTOCOL-ATTACK","921151","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","2"
"2.1","PROTOCOL-ATTACK","921160","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF and header-name detected)","1"
"2.1","PROTOCOL-ATTACK","921190","Enabled","AnomalyScoring","HTTP Splitting (CR/LF in request filename detected)","1"
"2.1","PROTOCOL-ATTACK","921200","Enabled","AnomalyScoring","LDAP Injection Attack","1"
"2.1","PROTOCOL-ENFORCEMENT","920100","Enabled","AnomalyScoring","Invalid HTTP Request Line","1"
"2.1","PROTOCOL-ENFORCEMENT","920120","Enabled","AnomalyScoring","Attempted multipart/form-data bypass","1"
"2.1","PROTOCOL-ENFORCEMENT","920121","Enabled","AnomalyScoring","Attempted multipart/form-data bypass","2"
"2.1","PROTOCOL-ENFORCEMENT","920160","Enabled","AnomalyScoring","Content-Length HTTP header is not numeric.","1"
"2.1","PROTOCOL-ENFORCEMENT","920170","Enabled","AnomalyScoring","GET or HEAD Request with Body Content.","1"
"2.1","PROTOCOL-ENFORCEMENT","920171","Enabled","AnomalyScoring","GET or HEAD Request with Transfer-Encoding.","1"
"2.1","PROTOCOL-ENFORCEMENT","920180","Enabled","AnomalyScoring","POST without Content-Length or Transfer-Encoding headers.","1"
"2.1","PROTOCOL-ENFORCEMENT","920181","Enabled","AnomalyScoring","Content-Length and Transfer-Encoding headers present","1"
"2.1","PROTOCOL-ENFORCEMENT","920190","Enabled","AnomalyScoring","Range: Invalid Last Byte Value.","1"
"2.1","PROTOCOL-ENFORCEMENT","920200","Enabled","AnomalyScoring","Range: Too many fields (6 or more)","2"
"2.1","PROTOCOL-ENFORCEMENT","920201","Enabled","AnomalyScoring","Range: Too many fields for pdf request (63 or more)","2"
"2.1","PROTOCOL-ENFORCEMENT","920210","Enabled","AnomalyScoring","Multiple/Conflicting Connection Header Data Found.","1"
"2.1","PROTOCOL-ENFORCEMENT","920220","Enabled","AnomalyScoring","URL Encoding Abuse Attack Attempt","1"
"2.1","PROTOCOL-ENFORCEMENT","920230","Enabled","AnomalyScoring","Multiple URL Encoding Detected","2"
"2.1","PROTOCOL-ENFORCEMENT","920240","Enabled","AnomalyScoring","URL Encoding Abuse Attack Attempt","1"
"2.1","PROTOCOL-ENFORCEMENT","920260","Enabled","AnomalyScoring","Unicode Full/Half Width Abuse Attack Attempt","1"
"2.1","PROTOCOL-ENFORCEMENT","920270","Enabled","AnomalyScoring","Invalid character in request (null character)","1"
"2.1","PROTOCOL-ENFORCEMENT","920271","Enabled","AnomalyScoring","Invalid character in request (non printable characters)","2"
"2.1","PROTOCOL-ENFORCEMENT","920280","Enabled","AnomalyScoring","Request Missing a Host Header","1"
"2.1","PROTOCOL-ENFORCEMENT","920290","Enabled","AnomalyScoring","Empty Host Header","1"
"2.1","PROTOCOL-ENFORCEMENT","920300","Enabled","AnomalyScoring","Request Missing an Accept Header","2"
"2.1","PROTOCOL-ENFORCEMENT","920310","Enabled","AnomalyScoring","Request Has an Empty Accept Header","1"
"2.1","PROTOCOL-ENFORCEMENT","920311","Enabled","AnomalyScoring","Request Has an Empty Accept Header","1"
"2.1","PROTOCOL-ENFORCEMENT","920320","Enabled","AnomalyScoring","Missing User Agent Header","2"
"2.1","PROTOCOL-ENFORCEMENT","920330","Enabled","AnomalyScoring","Empty User Agent Header","1"
"2.1","PROTOCOL-ENFORCEMENT","920340","Enabled","AnomalyScoring","Request Containing Content, but Missing Content-Type header","1"
"2.1","PROTOCOL-ENFORCEMENT","920341","Enabled","AnomalyScoring","Request Containing Content Requires Content-Type header","2"
"2.1","PROTOCOL-ENFORCEMENT","920350","Enabled","AnomalyScoring","Host header is a numeric IP address","1"
"2.1","PROTOCOL-ENFORCEMENT","920420","Enabled","AnomalyScoring","Request content type is not allowed by policy","1"
"2.1","PROTOCOL-ENFORCEMENT","920430","Enabled","AnomalyScoring","HTTP protocol version is not allowed by policy","1"
"2.1","PROTOCOL-ENFORCEMENT","920440","Enabled","AnomalyScoring","URL file extension is restricted by policy","1"
"2.1","PROTOCOL-ENFORCEMENT","920450","Enabled","AnomalyScoring","HTTP header is restricted by policy","1"
"2.1","PROTOCOL-ENFORCEMENT","920470","Enabled","AnomalyScoring","Illegal Content-Type header","1"
"2.1","PROTOCOL-ENFORCEMENT","920480","Enabled","AnomalyScoring","Request content type charset is not allowed by policy","1"
"2.1","PROTOCOL-ENFORCEMENT","920500","Enabled","AnomalyScoring","Attempt to access a backup or working file","1"
"2.1","RCE","932100","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.1","RCE","932105","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.1","RCE","932110","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.1","RCE","932115","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.1","RCE","932120","Enabled","AnomalyScoring","Remote Command Execution: Windows PowerShell Command Found","1"
"2.1","RCE","932130","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found","1"
"2.1","RCE","932140","Enabled","AnomalyScoring","Remote Command Execution: Windows FOR/IF Command Found","1"
"2.1","RCE","932150","Enabled","AnomalyScoring","Remote Command Execution: Direct Unix Command Execution","1"
"2.1","RCE","932160","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Code Found","1"
"2.1","RCE","932170","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.1","RCE","932171","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.1","RCE","932180","Enabled","AnomalyScoring","Restricted File Upload Attempt","1"
"2.1","RFI","931100","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address","1"
"2.1","RFI","931110","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload","1"
"2.1","RFI","931120","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)","1"
"2.1","RFI","931130","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link","2"
"2.1","SQLI","942100","Enabled","AnomalyScoring","SQL Injection Attack Detected via libinjection","1"
"2.1","SQLI","942110","Disabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected","2"
"2.1","SQLI","942120","Enabled","AnomalyScoring","SQL Injection Attack: SQL Operator Detected","2"
"2.1","SQLI","942140","Enabled","AnomalyScoring","SQL Injection Attack: Common DB Names Detected","1"
"2.1","SQLI","942150","Disabled","AnomalyScoring","SQL Injection Attack (replaced by rule #99031003)","2"
"2.1","SQLI","942160","Enabled","AnomalyScoring","Detects blind sqli tests using sleep() or benchmark().","1"
"2.1","SQLI","942170","Enabled","AnomalyScoring","Detects SQL benchmark and sleep injection attempts including conditional queries","1"
"2.1","SQLI","942180","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 1/3","2"
"2.1","SQLI","942190","Enabled","AnomalyScoring","Detects MSSQL code execution and information gathering attempts","1"
"2.1","SQLI","942200","Enabled","AnomalyScoring","Detects MySQL comment-/space-obfuscated injections and backtick termination","2"
"2.1","SQLI","942210","Enabled","AnomalyScoring","Detects chained SQL injection attempts 1/2","2"
"2.1","SQLI","942220","Enabled","AnomalyScoring","Looking for integer overflow attacks, these are taken from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash","1"
"2.1","SQLI","942230","Enabled","AnomalyScoring","Detects conditional SQL injection attempts","1"
"2.1","SQLI","942240","Enabled","AnomalyScoring","Detects MySQL charset switch and MSSQL DoS attempts","1"
"2.1","SQLI","942250","Enabled","AnomalyScoring","Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections","1"
"2.1","SQLI","942260","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 2/3 (replaced by rule #99031004)","2"
"2.1","SQLI","942270","Enabled","AnomalyScoring","Looking for basic sql injection. Common attack string for mysql, oracle and others.","1"
"2.1","SQLI","942280","Enabled","AnomalyScoring","Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts","1"
"2.1","SQLI","942290","Enabled","AnomalyScoring","Finds basic MongoDB SQL injection attempts","1"
"2.1","SQLI","942300","Enabled","AnomalyScoring","Detects MySQL comments, conditions and ch(a)r injections","2"
"2.1","SQLI","942310","Enabled","AnomalyScoring","Detects chained SQL injection attempts 2/2","2"
"2.1","SQLI","942320","Enabled","AnomalyScoring","Detects MySQL and PostgreSQL stored procedure/function injections","1"
"2.1","SQLI","942330","Enabled","AnomalyScoring","Detects classic SQL injection probings 1/3","2"
"2.1","SQLI","942340","Enabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 3/3 (replaced by rule #99031006)","2"
"2.1","SQLI","942350","Enabled","AnomalyScoring","Detects MySQL UDF injection and other data/structure manipulation attempts","1"
"2.1","SQLI","942360","Enabled","AnomalyScoring","Detects concatenated basic SQL injection and SQLLFI attempts","1"
"2.1","SQLI","942361","Enabled","AnomalyScoring","Detects basic SQL injection based on keyword alter or union","2"
"2.1","SQLI","942370","Enabled","AnomalyScoring","Detects classic SQL injection probings 2/3","2"
"2.1","SQLI","942380","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942390","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942400","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942410","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942430","Disabled","AnomalyScoring","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replaced by rule #99031005)","2"
"2.1","SQLI","942440","Disabled","AnomalyScoring","SQL Comment Sequence Detected (replaced by rule #99031002).","2"
"2.1","SQLI","942450","Enabled","AnomalyScoring","SQL Hex Encoding Identified","2"
"2.1","SQLI","942470","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942480","Enabled","AnomalyScoring","SQL Injection Attack","2"
"2.1","SQLI","942500","Enabled","AnomalyScoring","MySQL in-line comment detected.","1"
"2.1","SQLI","942510","Enabled","AnomalyScoring","SQLi bypass attempt by ticks or backticks detected.","2"
"2.1","XSS","941100","Enabled","AnomalyScoring","XSS Attack Detected via libinjection","1"
"2.1","XSS","941101","Enabled","AnomalyScoring","XSS Attack Detected via libinjection","2"
"2.1","XSS","941110","Enabled","AnomalyScoring","XSS Filter - Category 1: Script Tag Vector","1"
"2.1","XSS","941120","Enabled","AnomalyScoring","XSS Filter - Category 2: Event Handler Vector","1"
"2.1","XSS","941130","Enabled","AnomalyScoring","XSS Filter - Category 3: Attribute Vector","1"
"2.1","XSS","941140","Enabled","AnomalyScoring","XSS Filter - Category 4: Javascript URI Vector","1"
"2.1","XSS","941150","Enabled","AnomalyScoring","XSS Filter - Category 5: Disallowed HTML Attributes","2"
"2.1","XSS","941160","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: HTML Injection","1"
"2.1","XSS","941170","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: Attribute Injection","1"
"2.1","XSS","941180","Enabled","AnomalyScoring","Node-Validator Blacklist Keywords","1"
"2.1","XSS","941190","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941200","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941210","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941220","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941230","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941240","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941250","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941260","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941270","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941280","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941290","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941300","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.1","XSS","941310","Enabled","AnomalyScoring","US-ASCII Malformed Encoding XSS Filter - Attack Detected.","1"
"2.1","XSS","941320","Enabled","AnomalyScoring","Possible XSS Attack Detected - HTML Tag Handler","2"
"2.1","XSS","941330","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.1","XSS","941340","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.1","XSS","941350","Enabled","AnomalyScoring","UTF-7 Encoding IE XSS - Attack Detected.","1"
"2.1","XSS","941360","Enabled","AnomalyScoring","JSFuck / Hieroglyphy obfuscation detected","1"
"2.1","XSS","941370","Enabled","AnomalyScoring","JavaScript global variable found","1"
"2.1","XSS","941380","Enabled","AnomalyScoring","AngularJS client side template injection detected","2"
"2.2","FIX","943100","Enabled","AnomalyScoring","Possible Session Fixation Attack: Setting Cookie Values in HTML","1"
"2.2","FIX","943110","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer","1"
"2.2","FIX","943120","Enabled","AnomalyScoring","Possible Session Fixation Attack: SessionID Parameter Name with No Referer","1"
"2.2","General","200002","Enabled","AnomalyScoring","Failed to parse request body.","1"
"2.2","General","200003","Enabled","AnomalyScoring","Multipart request body failed strict validation","1"
"2.2","JAVA","944100","Enabled","AnomalyScoring","Remote Command Execution: Suspicious Java class detected","1"
"2.2","JAVA","944110","Enabled","AnomalyScoring","Remote Command Execution: Java process spawn (CVE-2017-9805)","1"
"2.2","JAVA","944120","Enabled","AnomalyScoring","Remote Command Execution: Java serialization (CVE-2015-5842)","1"
"2.2","JAVA","944130","Enabled","AnomalyScoring","Suspicious Java class detected","1"
"2.2","JAVA","944200","Disabled","AnomalyScoring","Magic bytes detected, probable Java serialization in use","2"
"2.2","JAVA","944210","Disabled","AnomalyScoring","Magic bytes detected Base64 encoded, probable Java serialization in use","2"
"2.2","JAVA","944240","Disabled","AnomalyScoring","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)","2"
"2.2","JAVA","944250","Disabled","AnomalyScoring","Remote Command Execution: Suspicious Java method detected","2"
"2.2","LFI","930100","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.2","LFI","930110","Enabled","AnomalyScoring","Path Traversal Attack (/../)","1"
"2.2","LFI","930120","Enabled","AnomalyScoring","OS File Access Attempt","1"
"2.2","LFI","930130","Enabled","AnomalyScoring","Restricted File Access Attempt","1"
"2.2","METHOD-ENFORCEMENT","911100","Enabled","AnomalyScoring","Method isn't allowed by policy","1"
"2.2","MS-ThreatIntel-AppSec","99030001","Disabled","AnomalyScoring","Path Traversal Evasion in Headers (/.././../)","2"
"2.2","MS-ThreatIntel-AppSec","99030002","Disabled","AnomalyScoring","Path Traversal Evasion in Request Body (/.././../)","2"
"2.2","MS-ThreatIntel-AppSec","99030003","Disabled","AnomalyScoring","URL encoded file path","2"
"2.2","MS-ThreatIntel-AppSec","99030004","Disabled","AnomalyScoring","Missing brotli encoding from supporting browser with https referer","2"
"2.2","MS-ThreatIntel-AppSec","99030005","Disabled","AnomalyScoring","Missing brotli encoding from supporting browser over HTTP/2","2"
"2.2","MS-ThreatIntel-AppSec","99030006","Disabled","AnomalyScoring","Illegal character in requested filename","2"
"2.2","MS-ThreatIntel-CVEs","99001001","Disabled","AnomalyScoring","Attempted F5 tmui (CVE-2020-5902) REST API exploitation with known credentials","2"
"2.2","MS-ThreatIntel-CVEs","99001002","Disabled","AnomalyScoring","Attempted Citrix NSC\_USER directory traversal CVE-2019-19781","2"
"2.2","MS-ThreatIntel-CVEs","99001003","Disabled","AnomalyScoring","Attempted Atlassian Confluence Widget Connector exploitation CVE-2019-3396","2"
"2.2","MS-ThreatIntel-CVEs","99001004","Disabled","AnomalyScoring","Attempted Pulse Secure custom template exploitation CVE-2020-8243","2"
"2.2","MS-ThreatIntel-CVEs","99001005","Disabled","AnomalyScoring","Attempted SharePoint type converter exploitation CVE-2020-0932","2"
"2.2","MS-ThreatIntel-CVEs","99001006","Disabled","AnomalyScoring","Attempted Pulse Connect directory traversal CVE-2019-11510","2"
"2.2","MS-ThreatIntel-CVEs","99001007","Disabled","AnomalyScoring","Attempted Junos OS J-Web local file inclusion CVE-2020-1631","2"
"2.2","MS-ThreatIntel-CVEs","99001008","Disabled","AnomalyScoring","Attempted Fortinet path traversal CVE-2018-13379","2"
"2.2","MS-ThreatIntel-CVEs","99001009","Disabled","AnomalyScoring","Attempted Apache struts ognl injection CVE-2017-5638","2"
"2.2","MS-ThreatIntel-CVEs","99001010","Disabled","AnomalyScoring","Attempted Apache struts ognl injection CVE-2017-12611","2"
"2.2","MS-ThreatIntel-CVEs","99001011","Disabled","AnomalyScoring","Attempted Oracle WebLogic path traversal CVE-2020-14882","2"
"2.2","MS-ThreatIntel-CVEs","99001012","Disabled","AnomalyScoring","Attempted Telerik WebUI insecure deserialization exploitation CVE-2019-18935","2"
"2.2","MS-ThreatIntel-CVEs","99001013","Disabled","AnomalyScoring","Attempted SharePoint insecure XML deserialization CVE-2019-0604","2"
"2.2","MS-ThreatIntel-CVEs","99001014","Disabled","AnomalyScoring","Attempted Spring Cloud routing-expression injection CVE-2022-22963","2"
"2.2","MS-ThreatIntel-CVEs","99001015","Disabled","AnomalyScoring","Attempted Spring Framework unsafe class object exploitation CVE-2022-22965","2"
"2.2","MS-ThreatIntel-CVEs","99001016","Disabled","AnomalyScoring","Attempted Spring Cloud Gateway Actuator injection CVE-2022-22947","2"
"2.2","MS-ThreatIntel-CVEs","99001017","Disabled","AnomalyScoring","Attempted Apache Struts file upload exploitation CVE-2023-50164","2"
"2.2","MS-ThreatIntel-CVEs","99001018","Enabled","AnomalyScoring","Attempted React2Shell remote code execution exploitation (CVE-2025-55182)",""
"2.2","MS-ThreatIntel-CVEs","99001019","Disabled","AnomalyScoring","Attempted WP2Shell remote code execution exploitation CVE-2026-63030","2"
"2.2","MS-ThreatIntel-SQLI","99031001","Disabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected (replacing rule #942110)","2"
"2.2","MS-ThreatIntel-SQLI","99031002","Disabled","AnomalyScoring","SQL Comment Sequence Detected (replacing rule #942440).","2"
"2.2","MS-ThreatIntel-SQLI","99031003","Disabled","AnomalyScoring","SQL Injection Attack (replacing rule #942150)","2"
"2.2","MS-ThreatIntel-SQLI","99031004","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 2/3 (replacing rule #942260)","2"
"2.2","MS-ThreatIntel-SQLI","99031005","Disabled","AnomalyScoring","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replacing rule #942430)","2"
"2.2","MS-ThreatIntel-SQLI","99031006","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 3/3 (replacing rule #942340)","2"
"2.2","MS-ThreatIntel-WebShells","99005002","Disabled","AnomalyScoring","Web Shell Interaction Attempt (POST)","2"
"2.2","MS-ThreatIntel-WebShells","99005003","Disabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER PHP","2"
"2.2","MS-ThreatIntel-WebShells","99005004","Disabled","AnomalyScoring","Web Shell Upload Attempt (POST) - CHOPPER ASPX","2"
"2.2","MS-ThreatIntel-WebShells","99005005","Disabled","AnomalyScoring","Web Shell Interaction Attempt","2"
"2.2","MS-ThreatIntel-WebShells","99005006","Disabled","AnomalyScoring","Spring4Shell Interaction Attempt","2"
"2.2","MS-ThreatIntel-XSS","99032001","Enabled","AnomalyScoring","XSS Filter - Category 2: Event Handler Vector (replacing rule #941120)","1"
"2.2","MS-ThreatIntel-XSS","99032002","Disabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link (replacing rule #931130)","2"
"2.2","NODEJS","934100","Enabled","AnomalyScoring","Node.js Injection Attack","1"
"2.2","PHP","933100","Enabled","AnomalyScoring","PHP Injection Attack: PHP Open Tag Found","1"
"2.2","PHP","933110","Enabled","AnomalyScoring","PHP Injection Attack: PHP Script File Upload Found","1"
"2.2","PHP","933120","Enabled","AnomalyScoring","PHP Injection Attack: Configuration Directive Found","1"
"2.2","PHP","933130","Enabled","AnomalyScoring","PHP Injection Attack: Variables Found","1"
"2.2","PHP","933140","Enabled","AnomalyScoring","PHP Injection Attack: I/O Stream Found","1"
"2.2","PHP","933150","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Name Found","1"
"2.2","PHP","933151","Disabled","AnomalyScoring","PHP Injection Attack: Medium-Risk PHP Function Name Found","2"
"2.2","PHP","933160","Enabled","AnomalyScoring","PHP Injection Attack: High-Risk PHP Function Call Found","1"
"2.2","PHP","933170","Enabled","AnomalyScoring","PHP Injection Attack: Serialized Object Injection","1"
"2.2","PHP","933180","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.2","PHP","933200","Enabled","AnomalyScoring","PHP Injection Attack: Wrapper scheme detected","1"
"2.2","PHP","933210","Enabled","AnomalyScoring","PHP Injection Attack: Variable Function Call Found","1"
"2.2","PROTOCOL-ATTACK","921110","Enabled","AnomalyScoring","HTTP Request Smuggling Attack","1"
"2.2","PROTOCOL-ATTACK","921120","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.2","PROTOCOL-ATTACK","921130","Enabled","AnomalyScoring","HTTP Response Splitting Attack","1"
"2.2","PROTOCOL-ATTACK","921140","Enabled","AnomalyScoring","HTTP Header Injection Attack via headers","1"
"2.2","PROTOCOL-ATTACK","921150","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","1"
"2.2","PROTOCOL-ATTACK","921151","Disabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF detected)","2"
"2.2","PROTOCOL-ATTACK","921160","Enabled","AnomalyScoring","HTTP Header Injection Attack via payload (CR/LF and header-name detected)","1"
"2.2","PROTOCOL-ATTACK","921190","Enabled","AnomalyScoring","HTTP Splitting (CR/LF in request filename detected)","1"
"2.2","PROTOCOL-ATTACK","921200","Enabled","AnomalyScoring","LDAP Injection Attack","1"
"2.2","PROTOCOL-ATTACK","921421","Enabled","AnomalyScoring","Content-Type header: Dangerous content type outside the mime type declaration",""
"2.2","PROTOCOL-ATTACK","921422","Disabled","AnomalyScoring","Detect content types in the Content-Type header outside of the actual content type declaration","2"
"2.2","PROTOCOL-ENFORCEMENT","920100","Enabled","AnomalyScoring","Invalid HTTP request line","1"
"2.2","PROTOCOL-ENFORCEMENT","920120","Enabled","AnomalyScoring","Attempted multipart/form-data bypass","1"
"2.2","PROTOCOL-ENFORCEMENT","920121","Disabled","AnomalyScoring","Attempted multipart/form-data bypass","2"
"2.2","PROTOCOL-ENFORCEMENT","920160","Enabled","AnomalyScoring","Content-Length HTTP header isn't numeric.","1"
"2.2","PROTOCOL-ENFORCEMENT","920170","Enabled","AnomalyScoring","GET or HEAD Request with Body Content.","1"
"2.2","PROTOCOL-ENFORCEMENT","920171","Enabled","AnomalyScoring","GET or HEAD Request with Transfer-Encoding.","1"
"2.2","PROTOCOL-ENFORCEMENT","920180","Enabled","AnomalyScoring","POST without Content-Length or Transfer-Encoding headers.","1"
"2.2","PROTOCOL-ENFORCEMENT","920181","Enabled","AnomalyScoring","Content-Length and Transfer-Encoding headers present","1"
"2.2","PROTOCOL-ENFORCEMENT","920190","Enabled","AnomalyScoring","Range: Invalid Last Byte Value.","1"
"2.2","PROTOCOL-ENFORCEMENT","920200","Disabled","AnomalyScoring","Range: Too many fields (6 or more)","2"
"2.2","PROTOCOL-ENFORCEMENT","920201","Disabled","AnomalyScoring","Range: Too many fields for pdf request (63 or more)","2"
"2.2","PROTOCOL-ENFORCEMENT","920210","Enabled","AnomalyScoring","Multiple/Conflicting Connection Header Data Found.","1"
"2.2","PROTOCOL-ENFORCEMENT","920220","Enabled","AnomalyScoring","URL encoding abuse attack attempt","1"
"2.2","PROTOCOL-ENFORCEMENT","920230","Disabled","AnomalyScoring","Multiple URL encoding detected","2"
"2.2","PROTOCOL-ENFORCEMENT","920240","Enabled","AnomalyScoring","URL encoding abuse attack attempt","1"
"2.2","PROTOCOL-ENFORCEMENT","920260","Enabled","AnomalyScoring","Unicode full-width or half-width abuse attack attempt","1"
"2.2","PROTOCOL-ENFORCEMENT","920270","Enabled","AnomalyScoring","Invalid character in request (null character)","1"
"2.2","PROTOCOL-ENFORCEMENT","920271","Disabled","AnomalyScoring","Invalid character in request (non printable characters)","2"
"2.2","PROTOCOL-ENFORCEMENT","920280","Enabled","AnomalyScoring","Request missing a Host header","1"
"2.2","PROTOCOL-ENFORCEMENT","920290","Enabled","AnomalyScoring","Empty Host header","1"
"2.2","PROTOCOL-ENFORCEMENT","920300","Disabled","AnomalyScoring","Request missing an Accept header","2"
"2.2","PROTOCOL-ENFORCEMENT","920310","Enabled","AnomalyScoring","Request has an empty Accept header","1"
"2.2","PROTOCOL-ENFORCEMENT","920311","Enabled","AnomalyScoring","Request has an empty Accept header","1"
"2.2","PROTOCOL-ENFORCEMENT","920320","Disabled","AnomalyScoring","Missing User-Agent header","2"
"2.2","PROTOCOL-ENFORCEMENT","920330","Enabled","AnomalyScoring","Empty User-Agent header","1"
"2.2","PROTOCOL-ENFORCEMENT","920340","Enabled","AnomalyScoring","Request containing content but missing Content-Type header","1"
"2.2","PROTOCOL-ENFORCEMENT","920341","Disabled","AnomalyScoring","Request Containing Content Requires Content-Type header","2"
"2.2","PROTOCOL-ENFORCEMENT","920350","Enabled","AnomalyScoring","Host header is a numeric IP address","1"
"2.2","PROTOCOL-ENFORCEMENT","920420","Disabled","AnomalyScoring","Request content type is not allowed by policy","2"
"2.2","PROTOCOL-ENFORCEMENT","920430","Enabled","AnomalyScoring","HTTP protocol version is not allowed by policy","1"
"2.2","PROTOCOL-ENFORCEMENT","920440","Enabled","AnomalyScoring","URL file extension is restricted by policy","1"
"2.2","PROTOCOL-ENFORCEMENT","920450","Enabled","AnomalyScoring","HTTP header is restricted by policy","1"
"2.2","PROTOCOL-ENFORCEMENT","920470","Enabled","AnomalyScoring","Illegal Content-Type header","1"
"2.2","PROTOCOL-ENFORCEMENT","920480","Enabled","AnomalyScoring","Request content type charset is not allowed by policy","1"
"2.2","PROTOCOL-ENFORCEMENT","920500","Enabled","AnomalyScoring","Attempt to access a backup or working file","1"
"2.2","PROTOCOL-ENFORCEMENT","920530","Enabled","AnomalyScoring","Restrict charset parameter inside content type header to occur max once","1"
"2.2","PROTOCOL-ENFORCEMENT","920620","Enabled","AnomalyScoring","Multiple Content-Type Request Headers","1"
"2.2","RCE","932100","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.2","RCE","932105","Enabled","AnomalyScoring","Remote Command Execution: Unix Command Injection","1"
"2.2","RCE","932110","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.2","RCE","932115","Enabled","AnomalyScoring","Remote Command Execution: Windows Command Injection","1"
"2.2","RCE","932120","Enabled","AnomalyScoring","Remote Command Execution: Windows PowerShell Command Found","1"
"2.2","RCE","932130","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found","1"
"2.2","RCE","932140","Enabled","AnomalyScoring","Remote Command Execution: Windows FOR/IF Command Found","1"
"2.2","RCE","932150","Enabled","AnomalyScoring","Remote Command Execution: Direct Unix Command Execution","1"
"2.2","RCE","932160","Enabled","AnomalyScoring","Remote Command Execution: Unix Shell Code Found","1"
"2.2","RCE","932170","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.2","RCE","932171","Enabled","AnomalyScoring","Remote Command Execution: Shellshock (CVE-2014-6271)","1"
"2.2","RCE","932180","Enabled","AnomalyScoring","Restricted File Upload Attempt","1"
"2.2","RFI","931100","Disabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address","2"
"2.2","RFI","931110","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload","1"
"2.2","RFI","931120","Enabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)","1"
"2.2","RFI","931130","Disabled","AnomalyScoring","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link","2"
"2.2","SQLI","942100","Enabled","AnomalyScoring","SQL Injection Attack Detected via libinjection","1"
"2.2","SQLI","942110","Disabled","AnomalyScoring","SQL Injection Attack: Common Injection Testing Detected","2"
"2.2","SQLI","942120","Disabled","AnomalyScoring","SQL Injection Attack: SQL Operator Detected","2"
"2.2","SQLI","942140","Enabled","AnomalyScoring","SQL Injection Attack: Common DB Names Detected","1"
"2.2","SQLI","942150","Disabled","AnomalyScoring","SQL Injection Attack (replaced by rule #99031003)","2"
"2.2","SQLI","942160","Enabled","AnomalyScoring","Detects blind sqli tests using sleep() or benchmark().","1"
"2.2","SQLI","942170","Enabled","AnomalyScoring","Detects SQL benchmark and sleep injection attempts including conditional queries","1"
"2.2","SQLI","942180","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 1/3","2"
"2.2","SQLI","942190","Enabled","AnomalyScoring","Detects MSSQL code execution and information gathering attempts","1"
"2.2","SQLI","942200","Disabled","AnomalyScoring","Detects MySQL comment-/space-obfuscated injections and backtick termination","2"
"2.2","SQLI","942210","Disabled","AnomalyScoring","Detects chained SQL injection attempts 1/2","2"
"2.2","SQLI","942220","Enabled","AnomalyScoring","Looking for integer overflow attacks, these rules come from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash","1"
"2.2","SQLI","942230","Enabled","AnomalyScoring","Detects conditional SQL injection attempts","1"
"2.2","SQLI","942240","Enabled","AnomalyScoring","Detects MySQL charset switch and MSSQL DoS attempts","1"
"2.2","SQLI","942250","Enabled","AnomalyScoring","Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections","1"
"2.2","SQLI","942260","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 2/3 (replaced by rule #99031004)","2"
"2.2","SQLI","942270","Enabled","AnomalyScoring","Looking for basic sql injection. Common attack string for mysql, oracle and others.","1"
"2.2","SQLI","942280","Enabled","AnomalyScoring","Detects Postgres pg\_sleep injection, waitfor delay attacks and database shutdown attempts","1"
"2.2","SQLI","942290","Enabled","AnomalyScoring","Finds basic MongoDB SQL injection attempts","1"
"2.2","SQLI","942300","Disabled","AnomalyScoring","Detects MySQL comments, conditions and ch(a)r injections","2"
"2.2","SQLI","942310","Disabled","AnomalyScoring","Detects chained SQL injection attempts 2/2","2"
"2.2","SQLI","942320","Enabled","AnomalyScoring","Detects MySQL and PostgreSQL stored procedure/function injections","1"
"2.2","SQLI","942330","Disabled","AnomalyScoring","Detects classic SQL injection probings 1/3","2"
"2.2","SQLI","942340","Disabled","AnomalyScoring","Detects basic SQL authentication bypass attempts 3/3 (replaced by rule #99031006)","2"
"2.2","SQLI","942350","Enabled","AnomalyScoring","Detects MySQL UDF injection and other data/structure manipulation attempts","1"
"2.2","SQLI","942360","Enabled","AnomalyScoring","Detects concatenated basic SQL injection and SQLLFI attempts","1"
"2.2","SQLI","942361","Disabled","AnomalyScoring","Detects basic SQL injection based on keyword alter or union","2"
"2.2","SQLI","942370","Disabled","AnomalyScoring","Detects classic SQL injection probings 2/3","2"
"2.2","SQLI","942380","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942390","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942400","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942410","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942430","Disabled","AnomalyScoring","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replaced by rule #99031005)","2"
"2.2","SQLI","942440","Disabled","AnomalyScoring","SQL Comment Sequence Detected (replaced by rule #99031002).","2"
"2.2","SQLI","942450","Disabled","AnomalyScoring","SQL Hex Encoding Identified","2"
"2.2","SQLI","942470","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942480","Disabled","AnomalyScoring","SQL Injection Attack","2"
"2.2","SQLI","942500","Enabled","AnomalyScoring","MySQL in-line comment detected.","1"
"2.2","SQLI","942510","Disabled","AnomalyScoring","SQLi bypass attempt by ticks or backticks detected.","2"
"2.2","XSS","941100","Enabled","AnomalyScoring","XSS Attack Detected via libinjection","1"
"2.2","XSS","941101","Disabled","AnomalyScoring","XSS Attack Detected via libinjection","2"
"2.2","XSS","941110","Enabled","AnomalyScoring","XSS Filter - Category 1: Script Tag Vector","1"
"2.2","XSS","941120","Disabled","AnomalyScoring","XSS Filter - Category 2: Event Handler Vector","2"
"2.2","XSS","941130","Enabled","AnomalyScoring","XSS Filter - Category 3: Attribute Vector","1"
"2.2","XSS","941140","Enabled","AnomalyScoring","XSS Filter - Category 4: Javascript URI Vector","1"
"2.2","XSS","941150","Disabled","AnomalyScoring","XSS Filter - Category 5: Disallowed HTML Attributes","2"
"2.2","XSS","941160","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: HTML Injection","1"
"2.2","XSS","941170","Enabled","AnomalyScoring","NoScript XSS InjectionChecker: Attribute Injection","1"
"2.2","XSS","941180","Enabled","AnomalyScoring","Node-Validator Blacklist Keywords","1"
"2.2","XSS","941190","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941200","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941210","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941220","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941230","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941240","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941250","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941260","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941270","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941280","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941290","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941300","Enabled","AnomalyScoring","IE XSS Filters - Attack Detected.","1"
"2.2","XSS","941310","Enabled","AnomalyScoring","US-ASCII Malformed Encoding XSS Filter - Attack Detected.","1"
"2.2","XSS","941320","Disabled","AnomalyScoring","Possible XSS Attack Detected - HTML Tag Handler","2"
"2.2","XSS","941330","Disabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.2","XSS","941340","Disabled","AnomalyScoring","IE XSS Filters - Attack Detected.","2"
"2.2","XSS","941350","Enabled","AnomalyScoring","UTF-7 Encoding IE XSS - Attack Detected.","1"
"2.2","XSS","941360","Enabled","AnomalyScoring","JSFuck / Hieroglyphy obfuscation detected","1"
"2.2","XSS","941370","Enabled","AnomalyScoring","JavaScript global variable found","1"
"2.2","XSS","941380","Disabled","AnomalyScoring","AngularJS client side template injection detected","2"
'@ | ConvertFrom-Csv
    $definitions = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($version in '1.0', '1.1', '2.0', '2.1', '2.2') {
        $groups = @(
            foreach ($group in ($groupRows | Where-Object RuleSetVersion -ceq $version)) {
                @{
                    ruleGroupName = $group.RuleGroupName
                    description = $group.Description
                    rules = @(
                        foreach ($rule in ($ruleRows | Where-Object {
                            $_.RuleSetVersion -ceq $version -and $_.RuleGroupName -ceq $group.RuleGroupName
                        })) {
                            # Each source version must carry its own verified defaults and PL metadata.
                            if ($rule.DefaultState -cnotin 'Enabled', 'Disabled' -or
                                $rule.DefaultAction -cnotin 'Block', 'AnomalyScoring') {
                                throw "Invalid embedded defaults for DRS $version/$($group.RuleGroupName)/$($rule.RuleId)."
                            }
                            if ($rule.ParanoiaLevel -cnotin '', '1', '2') {
                                throw "Invalid embedded PL for DRS $version/$($group.RuleGroupName)/$($rule.RuleId)."
                            }
                            @{
                                ruleId = $rule.RuleId
                                description = $rule.Description
                                defaultState = $rule.DefaultState
                                defaultAction = $rule.DefaultAction
                                paranoiaLevel = if ($rule.ParanoiaLevel -ne '') { [int] $rule.ParanoiaLevel } else { $null }
                            }
                        }
                    )
                }
            }
        )
        if (-not $groups.Count) { throw "Embedded DRS $version groups are missing." }
        $definitions.Add("Microsoft_DefaultRuleSet/$version", @{ ruleGroups = $groups })
    }
    $additional = Get-EmbeddedAdditionalManagedCatalog
    foreach ($key in $additional.Keys) { $definitions.Add($key, $additional[$key]) }
    return ,$definitions
}

function Get-EmbeddedAdditionalManagedCatalog {
    <#
    .SYNOPSIS
    Returns version-native Front Door Bot Manager and HTTP DDoS catalog snapshots.
    .DESCRIPTION
    Groups, identities and defaults were verified against the read-only Azure catalog
    on 2026-10-07. Microsoft Learn documents bot category actions and HTTP DDoS rules
    and sensitivity; it does not publish a complete versioned bot-ID table.
    #>
    $rows = @'
Type,Version,Group,Id,Action,Description,Sensitivity
Microsoft_BotManagerRuleSet,1.0,BadBots,Bot100100,Block,Malicious bots detected by threat intelligence,
Microsoft_BotManagerRuleSet,1.0,BadBots,Bot100200,Block,Malicious bots that have falsified their identity,
Microsoft_BotManagerRuleSet,1.0,GoodBots,Bot200100,Allow,Search engine crawlers,
Microsoft_BotManagerRuleSet,1.0,GoodBots,Bot200200,Log,Unverified search engine crawlers,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300100,Log,Unspecified identity,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300200,Log,Tools and frameworks for web crawling and attacks,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300300,Log,General purpose HTTP clients and SDKs,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300400,Log,Service agents,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300500,Log,Site health monitoring services,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300600,Log,Unknown bots detected by threat intelligence,
Microsoft_BotManagerRuleSet,1.0,UnknownBots,Bot300700,Log,Other bots,
Microsoft_BotManagerRuleSet,1.1,BadBots,Bot100100,Block,Malicious bots detected by threat intelligence,
Microsoft_BotManagerRuleSet,1.1,BadBots,Bot100200,Block,Malicious bots that have falsified their identity,
Microsoft_BotManagerRuleSet,1.1,BadBots,Bot100300,Block,High risk bots detected by threat intelligence,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200100,Allow,Search engine crawlers,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200200,Allow,Verified misc bots,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200300,Allow,Verified link checker bots,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200400,Allow,Verified social media bots,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200500,Allow,Verified content fetchers,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200600,Allow,Verified feed fetchers,
Microsoft_BotManagerRuleSet,1.1,GoodBots,Bot200700,Allow,Verified Advertising bots,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300100,Log,Unspecified identity,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300200,Log,Tools and frameworks for web crawling and attacks,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300300,Log,General purpose HTTP clients and SDKs,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300400,Log,Service agents,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300500,Log,Site health monitoring services,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300600,Log,Unknown bots detected by threat intelligence,
Microsoft_BotManagerRuleSet,1.1,UnknownBots,Bot300700,Log,Other bots,
Microsoft_HTTPDDoSRuleSet,1.0,ExcessiveRequests,500100,Log,Anomaly detected on high rate of client requests,Medium
Microsoft_HTTPDDoSRuleSet,1.0,ExcessiveRequests,500110,Log,Suspected bots sending high rate of requests,Medium
'@ | ConvertFrom-Csv
    $definitions = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    foreach ($version in ($rows | Group-Object Type,Version)) {
        $first = $version.Group[0]
        $groups = @(
            foreach ($group in ($version.Group | Group-Object Group)) {
                @{
                    # Bot/HTTP families have independent native actions and optional sensitivity.
                    ruleGroupName = $group.Name
                    description = switch ($group.Name) {
                        BadBots { 'Bad bots' }; GoodBots { 'Good bots' }
                        UnknownBots { 'Unknown bots' }; ExcessiveRequests { 'Excessive Requests' }
                        default { throw "Unknown embedded managed group '$($group.Name)'." }
                    }
                    rules = @(
                        foreach ($row in $group.Group) {
                            $definition = @{
                                ruleId = $row.Id; description = $row.Description
                                defaultState = 'Enabled'; defaultAction = $row.Action
                            }
                            if ($row.Sensitivity) { $definition.defaultSensitivity = $row.Sensitivity }
                            $definition
                        }
                    )
                }
            }
        )
        $definitions.Add("$($first.Type)/$($first.Version)", @{ ruleGroups = $groups })
    }
    return ,$definitions
}

function Get-ManagedRuleSetTypes {
    <#
    .SYNOPSIS
    Lists the three managed families using native-default migration reviews.
    .DESCRIPTION
    Provides the shared supported-family identities for validation and planning.
    #>
    'Microsoft_DefaultRuleSet', 'Microsoft_BotManagerRuleSet', 'Microsoft_HTTPDDoSRuleSet'
}

function Get-ManagedSourceVersion {
    <#
    .SYNOPSIS
    Returns a family's original source version without borrowing target defaults.
    .DESCRIPTION
    Uses the saved original DRS version because its carryover version may be aligned.
    #>
    param([System.Collections.IDictionary] $Configuration, [string] $RuleSetType)
    $set = Get-DrsSet $Configuration $RuleSetType
    if ($null -eq $set) { return }
    if ($RuleSetType -eq 'Microsoft_DefaultRuleSet') { return $sourceOriginalDrsVersion }
    [string] $set['ruleSetVersion']
}

function Get-LatestManagedRuleSetVersion {
    <#
    .SYNOPSIS
    Selects a family's newest supported version from the pinned native catalog.
    .DESCRIPTION
    Sorts embedded versions numerically and fails when no baseline is available.
    #>
    param([string] $RuleSetType)
    $versions = @($drsCatalog.Keys | Where-Object { $_.StartsWith("$RuleSetType/", [StringComparison]::Ordinal) } |
        ForEach-Object { ($_ -split '/', 2)[1] } | Sort-Object { [version] $_ } -Descending)
    if (-not $versions.Count) { throw "No pinned versions for managed family $RuleSetType." }
    $versions[0]
}

function Get-ManagedComparisonVersion {
    <#
    .SYNOPSIS
    Chooses the declared target version or the source version for an absent target family.
    .DESCRIPTION
    Keeps optional-family absence comparisons native to the source catalog.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration, [string] $RuleSetType)
    if ($null -ne (Get-DrsSet $target $RuleSetType)) { return Get-DrsTargetVersion $target $RuleSetType }
    if ($RuleSetType -ceq 'Microsoft_DefaultRuleSet') { return Get-LatestManagedRuleSetVersion $RuleSetType }
    $version = Get-ManagedSourceVersion $SourceConfiguration $RuleSetType
    if (-not $version -or -not $drsCatalog.ContainsKey("$RuleSetType/$version")) {
        throw "No pinned target comparison baseline for $RuleSetType/$version."
    }
    $version
}

function New-DisabledManagedRuleSet {
    <#
    .SYNOPSIS
    Creates a family with every live native rule disabled before selected copies.
    .DESCRIPTION
    Prevents selecting one source rule from implicitly enabling all catalog siblings.
    This is an in-memory generation baseline, never an Azure mutation.
    #>
    param([string] $RuleSetType, [string] $Version)
    if ($RuleSetType -notin (Get-ManagedRuleSetTypes) -or
        -not $drsCatalog.ContainsKey("$RuleSetType/$Version")) {
        throw "Cannot create an unreviewed managed baseline for $RuleSetType/$Version."
    }
    $index = Get-CatalogIndex "$RuleSetType/$Version"
    if ($RuleSetType -ceq 'Microsoft_DefaultRuleSet' -and $Version -notin '2.1','2.2') {
        throw "Cannot create unsupported target DRS $Version."
    }
    $set = @{
        ruleSetType = $RuleSetType; ruleSetVersion = $Version
        # Materialize every native rule as disabled when the family is absent from the target.
        ruleGroupOverrides = @(
            foreach ($groupName in ($index.Rules.Keys | Sort-Object -CaseSensitive)) {
                @{
                    ruleGroupName = $groupName
                    rules = @(
                        foreach ($id in ($index.Rules[$groupName].Keys | Sort-Object -CaseSensitive)) {
                            @{ ruleId = $id; enabledState = 'Disabled' }
                        }
                    )
                }
            }
        )
    }
    if ($RuleSetType -ceq 'Microsoft_DefaultRuleSet') { $set['ruleSetAction'] = 'Block' }
    $set
}

function Sync-ManagedSourceVersions {
    <#
    .SYNOPSIS
    Aligns carryover versions and exception scopes to configured target families.
    .DESCRIPTION
    Call after saving the original source snapshot used for native-default analysis.
    Missing target families keep their source versions for independent rule reviews.
    #>
    param([System.Collections.IDictionary] $Configuration, [System.Collections.IDictionary] $TargetConfiguration)
    foreach ($type in (Get-ManagedRuleSetTypes)) {
        $left = Get-DrsSet $Configuration $type
        $right = Get-DrsSet $TargetConfiguration $type
        # Align carryover scopes only for families actually configured in both policies.
        if ($null -eq $left -or $null -eq $right) { continue }
        $left['ruleSetVersion'] = $right['ruleSetVersion']
        $managed = $Configuration['properties']['managedRules']
        if ($managed.Contains('exceptionsList')) {
            foreach ($exception in (Get-Collection $managed['exceptionsList'] 'exceptions')) {
                foreach ($scope in (Get-Collection $exception 'scopes')) {
                    if ($scope['ruleSetType'] -ceq $type) { $scope['ruleSetVersion'] = $right['ruleSetVersion'] }
                }
            }
        }
    }
}

function Get-ManagedCatalogInventory {
    <#
    .SYNOPSIS
    Exposes versioned native catalog identities, descriptions and defaults for all families.
    .DESCRIPTION
    Exports group, rule and default metadata from the embedded managed-family catalogs.
    #>
    foreach ($key in ($drsCatalog.Keys | Sort-Object -CaseSensitive)) {
        $parts = $key -split '/', 2
        foreach ($group in $drsCatalog[$key]['ruleGroups']) {
            # Export version-native data rather than the separately maintained display snapshot.
            foreach ($rule in $group['rules']) {
                [pscustomobject]@{
                    RuleSetType = $parts[0]; RuleSetVersion = $parts[1]
                    RuleGroupName = $group['ruleGroupName']; RuleGroupDescription = $group['description']
                    RuleId = $rule['ruleId']; RuleDescription = $rule['description']
                    DefaultState = $rule['defaultState']; DefaultAction = $rule['defaultAction']
                    DefaultSensitivity = $rule['defaultSensitivity']
                    ParanoiaLevel = $rule['paranoiaLevel']
                }
            }
        }
    }
}

function Get-DrsDocumentation {
    <#
    .SYNOPSIS
    Loads the embedded official Front Door DRS display metadata.
    .DESCRIPTION
    Parses the preconfigured group and rule tables once per script execution.
    DRS 2.2 wording takes precedence; DRS 2.1-only entries provide native display coverage.
    No website is accessed, and display labels never replace API identities.
    .OUTPUTS
    Object with Groups and Rules dictionaries keyed by API group and group/rule ID.
    #>
    # https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-drs?tabs=drs22
    # Snapshot 2026-10-05; DRS 2.2 takes precedence over DRS 2.1.
    $groupRows = @'
"RuleGroup","RuleGroupName","Description"
"APPLICATION-ATTACK-SESSION-FIXATION","FIX","Protect against session-fixation attacks"
"General","General","General group"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","Protect against JAVA attacks"
"APPLICATION-ATTACK-LFI","LFI","Protect against file and path attacks"
"METHOD-ENFORCEMENT","METHOD-ENFORCEMENT","Lock-down methods (PUT, PATCH)"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","Protect against AppSec attacks"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","Protect against CVE attacks"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","Protect against SQLI attacks"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","Protect against Web shell attacks"
"MS-ThreatIntel-XSS","MS-ThreatIntel-XSS","Protect against XSS attacks"
"APPLICATION-ATTACK-NodeJS","NODEJS","Protect against Node JS attacks"
"APPLICATION-ATTACK-PHP","PHP","Protect against PHP-injection attacks"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","Protect against header injection, request smuggling, and response splitting"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","Protect against protocol and encoding issues"
"APPLICATION-ATTACK-RCE","RCE","Protect again remote code execution attacks"
"APPLICATION-ATTACK-RFI","RFI","Protect against remote file inclusion (RFI) attacks"
"APPLICATION-ATTACK-SQLI","SQLI","Protect against SQL-injection attacks"
"APPLICATION-ATTACK-XSS","XSS","Protect against cross-site scripting attacks"
'@ | ConvertFrom-Csv
    $ruleRows = @'
"RuleGroup","RuleGroupName","RuleId","Description"
"APPLICATION-ATTACK-SESSION-FIXATION","FIX","943100","Possible Session Fixation Attack: Setting Cookie Values in HTML"
"APPLICATION-ATTACK-SESSION-FIXATION","FIX","943110","Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer"
"APPLICATION-ATTACK-SESSION-FIXATION","FIX","943120","Possible Session Fixation Attack: SessionID Parameter Name with No Referer"
"General","General","200002","Failed to parse request body."
"General","General","200003","Multipart request body failed strict validation"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944100","Remote Command Execution: Suspicious Java class detected"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944110","Remote Command Execution: Java process spawn (CVE-2017-9805)"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944120","Remote Command Execution: Java serialization (CVE-2015-5842)"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944130","Suspicious Java class detected"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944200","Magic bytes detected, probable Java serialization in use"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944210","Magic bytes detected Base64 encoded, probable Java serialization in use"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944240","Remote Command Execution: Java serialization and Log4j vulnerability (CVE-2021-44228, CVE-2021-45046)"
"APPLICATION-ATTACK-SESSION-JAVA","JAVA","944250","Remote Command Execution: Suspicious Java method detected"
"APPLICATION-ATTACK-LFI","LFI","930100","Path Traversal Attack (/../)"
"APPLICATION-ATTACK-LFI","LFI","930110","Path Traversal Attack (/../)"
"APPLICATION-ATTACK-LFI","LFI","930120","OS File Access Attempt"
"APPLICATION-ATTACK-LFI","LFI","930130","Restricted File Access Attempt"
"METHOD-ENFORCEMENT","METHOD-ENFORCEMENT","911100","Method isn't allowed by policy"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030001","Path Traversal Evasion in Headers (/.././../)"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030002","Path Traversal Evasion in Request Body (/.././../)"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030003","URL encoded file path"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030004","Missing brotli encoding from supporting browser with https referer"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030005","Missing brotli encoding from supporting browser over HTTP/2"
"MS-ThreatIntel-AppSec","MS-ThreatIntel-AppSec","99030006","Illegal character in requested filename"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001001","Attempted F5 tmui (CVE-2020-5902) REST API exploitation with known credentials"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001002","Attempted Citrix NSC_USER directory traversal CVE-2019-19781"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001003","Attempted Atlassian Confluence Widget Connector exploitation CVE-2019-3396"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001004","Attempted Pulse Secure custom template exploitation CVE-2020-8243"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001005","Attempted SharePoint type converter exploitation CVE-2020-0932"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001006","Attempted Pulse Connect directory traversal CVE-2019-11510"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001007","Attempted Junos OS J-Web local file inclusion CVE-2020-1631"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001008","Attempted Fortinet path traversal CVE-2018-13379"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001009","Attempted Apache struts ognl injection CVE-2017-5638"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001010","Attempted Apache struts ognl injection CVE-2017-12611"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001011","Attempted Oracle WebLogic path traversal CVE-2020-14882"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001012","Attempted Telerik WebUI insecure deserialization exploitation CVE-2019-18935"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001013","Attempted SharePoint insecure XML deserialization CVE-2019-0604"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001014","Attempted Spring Cloud routing-expression injection CVE-2022-22963"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001015","Attempted Spring Framework unsafe class object exploitation CVE-2022-22965"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001016","Attempted Spring Cloud Gateway Actuator injection CVE-2022-22947"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001017","Attempted Apache Struts file upload exploitation CVE-2023-50164"
"MS-ThreatIntel-CVEs","MS-ThreatIntel-CVEs","99001019","Attempted WP2Shell remote code execution exploitation CVE-2026-63030"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031001","SQL Injection Attack: Common Injection Testing Detected (replacing rule #942110)"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031002","SQL Comment Sequence Detected (replacing rule #942440)."
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031003","SQL Injection Attack (replacing rule #942150)"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031004","Detects basic SQL authentication bypass attempts 2/3 (replacing rule #942260)"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031005","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replacing rule #942430)"
"MS-ThreatIntel-SQLI","MS-ThreatIntel-SQLI","99031006","Detects basic SQL authentication bypass attempts 3/3 (replacing rule #942340)"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","99005002","Web Shell Interaction Attempt (POST)"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","99005003","Web Shell Upload Attempt (POST) - CHOPPER PHP"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","99005004","Web Shell Upload Attempt (POST) - CHOPPER ASPX"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","99005005","Web Shell Interaction Attempt"
"MS-ThreatIntel-WebShells","MS-ThreatIntel-WebShells","99005006","Spring4Shell Interaction Attempt"
"MS-ThreatIntel-XSS","MS-ThreatIntel-XSS","99032001","XSS Filter - Category 2: Event Handler Vector (replacing rule #941120)"
"MS-ThreatIntel-XSS","MS-ThreatIntel-XSS","99032002","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link (replacing rule #931130)"
"APPLICATION-ATTACK-NodeJS","NODEJS","934100","Node.js Injection Attack"
"APPLICATION-ATTACK-PHP","PHP","933100","PHP Injection Attack: PHP Open Tag Found"
"APPLICATION-ATTACK-PHP","PHP","933110","PHP Injection Attack: PHP Script File Upload Found"
"APPLICATION-ATTACK-PHP","PHP","933120","PHP Injection Attack: Configuration Directive Found"
"APPLICATION-ATTACK-PHP","PHP","933130","PHP Injection Attack: Variables Found"
"APPLICATION-ATTACK-PHP","PHP","933140","PHP Injection Attack: I/O Stream Found"
"APPLICATION-ATTACK-PHP","PHP","933150","PHP Injection Attack: High-Risk PHP Function Name Found"
"APPLICATION-ATTACK-PHP","PHP","933151","PHP Injection Attack: Medium-Risk PHP Function Name Found"
"APPLICATION-ATTACK-PHP","PHP","933160","PHP Injection Attack: High-Risk PHP Function Call Found"
"APPLICATION-ATTACK-PHP","PHP","933170","PHP Injection Attack: Serialized Object Injection"
"APPLICATION-ATTACK-PHP","PHP","933180","PHP Injection Attack: Variable Function Call Found"
"APPLICATION-ATTACK-PHP","PHP","933200","PHP Injection Attack: Wrapper scheme detected"
"APPLICATION-ATTACK-PHP","PHP","933210","PHP Injection Attack: Variable Function Call Found"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921110","HTTP Request Smuggling Attack"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921120","HTTP Response Splitting Attack"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921130","HTTP Response Splitting Attack"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921140","HTTP Header Injection Attack via headers"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921150","HTTP Header Injection Attack via payload (CR/LF detected)"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921151","HTTP Header Injection Attack via payload (CR/LF detected)"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921160","HTTP Header Injection Attack via payload (CR/LF and header-name detected)"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921190","HTTP Splitting (CR/LF in request filename detected)"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921200","LDAP Injection Attack"
"PROTOCOL-ATTACK","PROTOCOL-ATTACK","921422","Detect content types in the Content-Type header outside of the actual content type declaration"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920100","Invalid HTTP request line"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920120","Attempted multipart/form-data bypass"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920121","Attempted multipart/form-data bypass"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920160","Content-Length HTTP header isn't numeric."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920170","GET or HEAD Request with Body Content."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920171","GET or HEAD Request with Transfer-Encoding."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920180","POST without Content-Length or Transfer-Encoding headers."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920181","Content-Length and Transfer-Encoding headers present"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920190","Range: Invalid Last Byte Value."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920200","Range: Too many fields (6 or more)"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920201","Range: Too many fields for pdf request (63 or more)"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920210","Multiple/Conflicting Connection Header Data Found."
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920220","URL encoding abuse attack attempt"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920230","Multiple URL encoding detected"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920240","URL encoding abuse attack attempt"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920260","Unicode full-width or half-width abuse attack attempt"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920270","Invalid character in request (null character)"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920271","Invalid character in request (non printable characters)"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920280","Request missing a Host header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920290","Empty Host header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920300","Request missing an Accept header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920310","Request has an empty Accept header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920311","Request has an empty Accept header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920320","Missing User-Agent header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920330","Empty User-Agent header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920340","Request containing content but missing Content-Type header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920341","Request Containing Content Requires Content-Type header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920350","Host header is a numeric IP address"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920420","Request content type is not allowed by policy"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920430","HTTP protocol version is not allowed by policy"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920440","URL file extension is restricted by policy"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920450","HTTP header is restricted by policy"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920470","Illegal Content-Type header"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920480","Request content type charset is not allowed by policy"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920500","Attempt to access a backup or working file"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920530","Restrict charset parameter inside content type header to occur max once"
"PROTOCOL-ENFORCEMENT","PROTOCOL-ENFORCEMENT","920620","Multiple Content-Type Request Headers"
"APPLICATION-ATTACK-RCE","RCE","932100","Remote Command Execution: Unix Command Injection"
"APPLICATION-ATTACK-RCE","RCE","932105","Remote Command Execution: Unix Command Injection"
"APPLICATION-ATTACK-RCE","RCE","932110","Remote Command Execution: Windows Command Injection"
"APPLICATION-ATTACK-RCE","RCE","932115","Remote Command Execution: Windows Command Injection"
"APPLICATION-ATTACK-RCE","RCE","932120","Remote Command Execution: Windows PowerShell Command Found"
"APPLICATION-ATTACK-RCE","RCE","932130","Remote Command Execution: Unix Shell Expression or Confluence Vulnerability (CVE-2022-26134) Found"
"APPLICATION-ATTACK-RCE","RCE","932140","Remote Command Execution: Windows FOR/IF Command Found"
"APPLICATION-ATTACK-RCE","RCE","932150","Remote Command Execution: Direct Unix Command Execution"
"APPLICATION-ATTACK-RCE","RCE","932160","Remote Command Execution: Unix Shell Code Found"
"APPLICATION-ATTACK-RCE","RCE","932170","Remote Command Execution: Shellshock (CVE-2014-6271)"
"APPLICATION-ATTACK-RCE","RCE","932171","Remote Command Execution: Shellshock (CVE-2014-6271)"
"APPLICATION-ATTACK-RCE","RCE","932180","Restricted File Upload Attempt"
"APPLICATION-ATTACK-RFI","RFI","931100","Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address"
"APPLICATION-ATTACK-RFI","RFI","931110","Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload"
"APPLICATION-ATTACK-RFI","RFI","931120","Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)"
"APPLICATION-ATTACK-RFI","RFI","931130","Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link"
"APPLICATION-ATTACK-SQLI","SQLI","942100","SQL Injection Attack Detected via libinjection"
"APPLICATION-ATTACK-SQLI","SQLI","942110","SQL Injection Attack: Common Injection Testing Detected"
"APPLICATION-ATTACK-SQLI","SQLI","942120","SQL Injection Attack: SQL Operator Detected"
"APPLICATION-ATTACK-SQLI","SQLI","942140","SQL Injection Attack: Common DB Names Detected"
"APPLICATION-ATTACK-SQLI","SQLI","942150","SQL Injection Attack (replaced by rule #99031003)"
"APPLICATION-ATTACK-SQLI","SQLI","942160","Detects blind sqli tests using sleep() or benchmark()."
"APPLICATION-ATTACK-SQLI","SQLI","942170","Detects SQL benchmark and sleep injection attempts including conditional queries"
"APPLICATION-ATTACK-SQLI","SQLI","942180","Detects basic SQL authentication bypass attempts 1/3"
"APPLICATION-ATTACK-SQLI","SQLI","942190","Detects MSSQL code execution and information gathering attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942200","Detects MySQL comment-/space-obfuscated injections and backtick termination"
"APPLICATION-ATTACK-SQLI","SQLI","942210","Detects chained SQL injection attempts 1/2"
"APPLICATION-ATTACK-SQLI","SQLI","942220","Looking for integer overflow attacks, these rules come from skipfish, except 3.0.00738585072007e-308 is the ""magic number"" crash"
"APPLICATION-ATTACK-SQLI","SQLI","942230","Detects conditional SQL injection attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942240","Detects MySQL charset switch and MSSQL DoS attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942250","Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections"
"APPLICATION-ATTACK-SQLI","SQLI","942260","Detects basic SQL authentication bypass attempts 2/3 (replaced by rule #99031004)"
"APPLICATION-ATTACK-SQLI","SQLI","942270","Looking for basic sql injection. Common attack string for mysql, oracle and others."
"APPLICATION-ATTACK-SQLI","SQLI","942280","Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942290","Finds basic MongoDB SQL injection attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942300","Detects MySQL comments, conditions and ch(a)r injections"
"APPLICATION-ATTACK-SQLI","SQLI","942310","Detects chained SQL injection attempts 2/2"
"APPLICATION-ATTACK-SQLI","SQLI","942320","Detects MySQL and PostgreSQL stored procedure/function injections"
"APPLICATION-ATTACK-SQLI","SQLI","942330","Detects classic SQL injection probings 1/3"
"APPLICATION-ATTACK-SQLI","SQLI","942340","Detects basic SQL authentication bypass attempts 3/3 (replaced by rule #99031006)"
"APPLICATION-ATTACK-SQLI","SQLI","942350","Detects MySQL UDF injection and other data/structure manipulation attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942360","Detects concatenated basic SQL injection and SQLLFI attempts"
"APPLICATION-ATTACK-SQLI","SQLI","942361","Detects basic SQL injection based on keyword alter or union"
"APPLICATION-ATTACK-SQLI","SQLI","942370","Detects classic SQL injection probings 2/3"
"APPLICATION-ATTACK-SQLI","SQLI","942380","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942390","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942400","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942410","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942430","Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12) (replaced by rule #99031005)"
"APPLICATION-ATTACK-SQLI","SQLI","942440","SQL Comment Sequence Detected (replaced by rule #99031002)."
"APPLICATION-ATTACK-SQLI","SQLI","942450","SQL Hex Encoding Identified"
"APPLICATION-ATTACK-SQLI","SQLI","942470","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942480","SQL Injection Attack"
"APPLICATION-ATTACK-SQLI","SQLI","942500","MySQL in-line comment detected."
"APPLICATION-ATTACK-SQLI","SQLI","942510","SQLi bypass attempt by ticks or backticks detected."
"APPLICATION-ATTACK-XSS","XSS","941100","XSS Attack Detected via libinjection"
"APPLICATION-ATTACK-XSS","XSS","941101","XSS Attack Detected via libinjection"
"APPLICATION-ATTACK-XSS","XSS","941110","XSS Filter - Category 1: Script Tag Vector"
"APPLICATION-ATTACK-XSS","XSS","941120","XSS Filter - Category 2: Event Handler Vector"
"APPLICATION-ATTACK-XSS","XSS","941130","XSS Filter - Category 3: Attribute Vector"
"APPLICATION-ATTACK-XSS","XSS","941140","XSS Filter - Category 4: Javascript URI Vector"
"APPLICATION-ATTACK-XSS","XSS","941150","XSS Filter - Category 5: Disallowed HTML Attributes"
"APPLICATION-ATTACK-XSS","XSS","941160","NoScript XSS InjectionChecker: HTML Injection"
"APPLICATION-ATTACK-XSS","XSS","941170","NoScript XSS InjectionChecker: Attribute Injection"
"APPLICATION-ATTACK-XSS","XSS","941180","Node-Validator Blacklist Keywords"
"APPLICATION-ATTACK-XSS","XSS","941190","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941200","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941210","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941220","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941230","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941240","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941250","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941260","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941270","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941280","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941290","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941300","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941310","US-ASCII Malformed Encoding XSS Filter - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941320","Possible XSS Attack Detected - HTML Tag Handler"
"APPLICATION-ATTACK-XSS","XSS","941330","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941340","IE XSS Filters - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941350","UTF-7 Encoding IE XSS - Attack Detected."
"APPLICATION-ATTACK-XSS","XSS","941360","JSFuck / Hieroglyphy obfuscation detected"
"APPLICATION-ATTACK-XSS","XSS","941370","JavaScript global variable found"
"APPLICATION-ATTACK-XSS","XSS","941380","AngularJS client side template injection detected"
'@ | ConvertFrom-Csv
    $groups = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $rules = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::Ordinal)
    foreach ($row in $groupRows) {
        $groups.Add($row.RuleGroupName, [pscustomobject]@{ Label = $row.RuleGroup; Description = $row.Description })
    }
    foreach ($row in $ruleRows) {
        $rules.Add("$($row.RuleGroupName)/$($row.RuleId)", $row.Description)
    }
    [pscustomobject]@{ Groups = $groups; Rules = $rules }
}


#endregion

#region Console summaries and responsive tables
function Get-DisplayRuleGroup {
    <#
    .SYNOPSIS
    Resolves an API group identity to its official DRS display label.
    .DESCRIPTION
    Leaves non-DRS or unknown groups unchanged; missing DRS metadata is explained separately.
    .PARAMETER RuleSetType
    Managed rule set type.
    .PARAMETER GroupName
    Original API ruleGroupName.
    .OUTPUTS
    Display label string.
    #>
    param([string] $RuleSetType, [string] $GroupName)
    if ($RuleSetType -eq 'Microsoft_DefaultRuleSet' -and $drsDocumentation.Groups.ContainsKey($GroupName)) {
        $drsDocumentation.Groups[$GroupName].Label
    }
    else { $GroupName }
}

function Get-DecisionDisplay {
    <#
    .SYNOPSIS
    Resolves a comparison path into display metadata without mutating identities.
    .DESCRIPTION
    Uses the configured source/target versions and embedded catalog descriptions.
    Native risk rows supply original version metadata after carryover alignment.
    Missing descriptions are explicitly identified.
    .PARAMETER Path
    Internal comparison path identifying the selected scope.
    .OUTPUTS
    Object containing Scope, RuleSetType, RuleGroupName, RuleId, and RuleDescription.
    #>
    param([string] $Path)
    $display = [ordered]@{
        Scope = ''
        RuleSetType = ''
        RuleGroupName = ''
        RuleId = ''
        RuleDescription = ''
        TargetParanoiaLevel = $null
    }
    $match = [regex]::Match($Path, '^properties\.managedRules\.managedRuleSets\[(?<set>[^\]]+)\](?:\.ruleGroupOverrides\[(?<group>[^\]]+)\])?(?:\.rules\[(?<rule>[^\]]+)\])?(?<setting>.*)$')
    if ($match.Success) {
        $type = $match.Groups['set'].Value
        $groupName = $match.Groups['group'].Value
        $ruleId = $match.Groups['rule'].Value
        $display.RuleSetType = $type
        $display.RuleGroupName = if ($groupName) { $groupName } else { '(rule-set scope)' }
        $display.RuleId = if ($ruleId) { $ruleId } elseif ($groupName) { '(group scope)' } else { '(rule-set scope)' }
        # Use the proposed source version for review metadata, falling back for master-only lookups.
        $set = @($script:source['properties']['managedRules']['managedRuleSets'] | Where-Object { $_['ruleSetType'] -ceq $type })
        if ($set.Count -eq 0) {
            $set = @($script:target['properties']['managedRules']['managedRuleSets'] | Where-Object { $_['ruleSetType'] -ceq $type })
        }
        $version = if ($set.Count) { [string] $set[0]['ruleSetVersion'] } else { '' }
        $catalogKey = "$type/$version"
        $description = "Rule set $catalogKey"
        if (-not $drsCatalog.ContainsKey($catalogKey)) {
            $description = "Not available in the embedded catalog: $catalogKey"
        }
        elseif ($groupName) {
            # Display unresolved native scopes explicitly instead of borrowing a different rule.
            $index = Get-CatalogIndex $catalogKey
            $groups = $index.Groups
            if (-not $groups.ContainsKey($groupName)) {
                $description = "Group not available in the embedded catalog: $groupName"
            }
            else {
                $definition = $groups[$groupName]
                # Group descriptions are usable only until an individual rule is requested.
                if ($ruleId) {
                    $rules = $index.Rules[$groupName]
                    $definition = if ($rules.ContainsKey($ruleId)) { $rules[$ruleId] } else { $null }
                }
                $description = if ($null -eq $definition) {
                    "Rule not available in the embedded catalog: $ruleId"
                }
                elseif ($definition.Contains('description') -and -not [string]::IsNullOrWhiteSpace([string] $definition['description'])) {
                    [string] $definition['description']
                }
                else { 'Embedded catalog does not provide a description for this scope.' }
            }
        }
        # Use the official display snapshot, with native descriptions for a 2.1 target.
        if ($type -eq 'Microsoft_DefaultRuleSet' -and $groupName) {
            if ($ruleId) {
                # Prefer native target metadata when the display snapshot describes a newer version.
                $targetVersion = (Get-DrsTargetVersion) ?? (Get-LatestManagedRuleSetVersion $type)
                $targetIndex = Get-CatalogIndex "Microsoft_DefaultRuleSet/$targetVersion"
                if ($targetIndex.Rules.ContainsKey($groupName) -and $targetIndex.Rules[$groupName].ContainsKey($ruleId)) {
                    $display.TargetParanoiaLevel = $targetIndex.Rules[$groupName][$ruleId]['paranoiaLevel']
                }
                $key = "$groupName/$ruleId"
                $description = if ($drsDocumentation.Rules.ContainsKey($key)) {
                    $drsDocumentation.Rules[$key]
                }
                else { "Rule not in the embedded DRS display catalog: $key" }
                if ($targetVersion -eq '2.1' -and $targetIndex.Rules.ContainsKey($groupName) -and
                    $targetIndex.Rules[$groupName].ContainsKey($ruleId)) {
                    $description = $targetIndex.Rules[$groupName][$ruleId]['description']
                }
            }
            else {
                $description = if ($drsDocumentation.Groups.ContainsKey($groupName)) {
                    $drsDocumentation.Groups[$groupName].Description
                }
                else { "Group not in the embedded DRS display catalog: $groupName" }
            }
        }
        $display.RuleDescription = $description
        $setting = $match.Groups['setting'].Value.TrimStart('.')
        $display.Scope = if ($setting) { $setting } elseif ($ruleId) { 'Rule override' } elseif ($groupName) { 'Group override' } else { 'Managed rule set' }
    }
    elseif ($Path -match '^properties\.customRules\.rules\[(?<name>[^\]]+)\]$') {
        $display.Scope = "Custom rule '$($Matches['name'])'"
    }
    else {
        $display.Scope = ($Path -replace '^properties\.', '') -replace '\.', ' / '
    }
    [pscustomobject] $display
}

function Get-DecisionLabel {
    <#
    .SYNOPSIS
    Resolves a decision's display label without exposing configuration values.
    .DESCRIPTION
    Keeps official managed-rule descriptions and humanizes policy/tag setting names.
    .PARAMETER Item
    Decision object produced by Add-Decision.
    .OUTPUTS
    Display label string.
    #>
    param($Item)
    if ($Item.RuleSetType -and $Item.RuleDescription) { return $Item.RuleDescription }
    if ($Item.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)) { return $Item.IdentityValue }
    $parts = $Item.Scope -split ' / ', 2
    $scope = if ($parts.Count -gt 1) { $parts[1] } else { $parts[0] }
    if ($scope -in 'exceptionsList / exceptions','exceptionsList') { return 'Managed-rule exceptions' }
    $label = $scope -creplace '([a-z0-9])([A-Z])', '$1 $2'
    $label.Substring(0, 1).ToUpperInvariant() + $label.Substring(1)
}

function Get-ConsoleWidth {
    <#
    .SYNOPSIS
    Reads the visible console window width.
    .DESCRIPTION
    Unsupported or unavailable host dimensions use a documented 120-column fallback
    with verbose diagnostics; unrelated host failures still terminate processing.
    .OUTPUTS
    Positive System.Int32 column count.
    #>
    $width = 0
    if ($null -ne $Host.UI.RawUI) {
        try {
            $windowSize = $Host.UI.RawUI.WindowSize
            if ($null -ne $windowSize) { $width = $windowSize.Width }
        }
        catch [System.Management.Automation.PSNotImplementedException], [System.NotImplementedException] {
            Write-Verbose 'This host does not implement console dimensions.'
        }
    }
    if ($width -gt 0) { return $width }
    Write-Verbose 'No console width is available; using 120 columns for redirected/non-console output.'
    120
}

function Write-HighlightedReviewRow {
    <#
    .SYNOPSIS
    Highlights a review number and its selected comparison value in formatted rows.
    .DESCRIPTION
    Keeps labels, unselected fields and indentation in the table color.
    Supports wrapped table cells and narrow-console list field continuations.
    #>
    param([string] $Text, [Nullable[ConsoleColor]] $Color,
        [System.Collections.IDictionary] $HostParameters, [string[]] $Properties,
        [int[]] $Widths, [int] $ColumnSpacing, [string] $SelectedProperty, [switch] $ListLayout)
    if ($null -eq $Color) { Write-Host $Text @HostParameters; return }
    if ($SelectedProperty -and $SelectedProperty -notin $Properties) {
        throw "Unknown selected table property '$SelectedProperty'."
    }
    $fieldNames = ($Properties | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $currentProperty = ''
    foreach ($line in ($Text -split '\r?\n')) {
        $segments = [System.Collections.Generic.List[object]]::new()
        if ($ListLayout) {
            # Track the active field so wrapped list values retain the correct highlight.
            $field = [regex]::Match($line, '^((' + $fieldNames + ')[ \t]*:[ \t]*)(.*)$')
            $start = 0
            if ($field.Success) {
                $currentProperty = $field.Groups[2].Value
                $start = $field.Groups[3].Index
            }
            if ($currentProperty -eq $Properties[0] -or $currentProperty -eq $SelectedProperty) {
                $value = [regex]::Match($line.Substring($start), '\S(?:.*\S)?')
                if ($value.Success) { $segments.Add(@{ Start = $start + $value.Index; Length = $value.Length }) }
            }
        } else {
            # Recover table cell offsets from visible widths, not ANSI-encoded output.
            $start = 0
            for ($index = 0; $index -lt $Properties.Count; $index++) {
                if (($index -eq 0 -or $Properties[$index] -eq $SelectedProperty) -and $start -lt $line.Length) {
                    $cellWidth = $Widths[$index]
                    if ($index -lt $Properties.Count - 1) { $cellWidth += $ColumnSpacing - 1 }
                    $length = [Math]::Min($cellWidth, $line.Length - $start)
                    $value = [regex]::Match($line.Substring($start, $length), '\S(?:.*\S)?')
                    if ($value.Success) { $segments.Add(@{ Start = $start + $value.Index; Length = $value.Length }) }
                }
                $start += $Widths[$index] + $ColumnSpacing
            }
        }
        # Color only unstyled cell offsets; ANSI bytes must not affect column widths.
        $position = 0
        foreach ($segment in $segments) {
            if ($segment.Start -gt $position) {
                Write-Host ($line.Substring($position, $segment.Start - $position)) -NoNewline @HostParameters
            }
            Write-Host ($line.Substring($segment.Start, $segment.Length)) -NoNewline -ForegroundColor $Color
            $position = $segment.Start + $segment.Length
        }
        Write-Host ($line.Substring($position)) @HostParameters
    }
}

function Write-ResponsiveTable {
    <#
    .SYNOPSIS
    Renders wrapped columns within the available console width.
    .DESCRIPTION
    Sizes compact fields to content, assigns remaining space to the flexible column,
    and shrinks compact fields to their header minima when needed. Very narrow hosts
    use a list layout. Headerless continuations do not add leading blank lines.
    .PARAMETER Rows
    Objects to render.
    .PARAMETER Properties
    Ordered property names.
    .PARAMETER Labels
    Corresponding column headers.
    .PARAMETER FlexibleProperty
    Property that receives spare width.
    .PARAMETER PaddingProperty
    Optional property that receives spare width after the flexible content fits.
    .PARAMETER ColumnSpacing
    Number of spaces between columns.
    .PARAMETER Width
    Available console columns.
    .PARAMETER HideTableHeaders
    Suppresses headers for continuation rows.
    .PARAMETER ForegroundColor
    Optional host color; omitted values retain the host default.
    .PARAMETER RowColorProperty
    Optional row property containing a ConsoleColor override for the first column's
    value and the selected comparison column. Other fields retain the table color.
    .PARAMETER SelectedColumnProperty
    Optional row property naming the selected comparison field, such as Source or Target.
    .PARAMETER RowWarningProperty
    Optional row property containing warning messages printed immediately after that row.
    .OUTPUTS
    Host information and optional warning records; no success-stream objects.
    #>
    param(
        [object[]] $Rows,
        [string[]] $Properties,
        [string[]] $Labels,
        [string] $FlexibleProperty,
        [string] $PaddingProperty,
        [ValidateRange(1, 10)]
        [int] $ColumnSpacing = 1,
        [int] $Width,
        [switch] $HideTableHeaders,
        [Nullable[ConsoleColor]] $ForegroundColor,
        [string] $RowColorProperty,
        [string] $SelectedColumnProperty,
        [string] $RowWarningProperty
    )
    if ($Rows.Count -eq 0) { return }
    $hostParameters = @{}
    if ($null -ne $ForegroundColor) { $hostParameters['ForegroundColor'] = $ForegroundColor }
    $minimum = @($Labels | ForEach-Object { $_.Length })
    $separatorWidth = ($Properties.Count - 1) * $ColumnSpacing
    [int] $minimumWidth = ($minimum | Measure-Object -Sum).Sum + $separatorWidth
    # When even headers cannot fit, a list preserves all content instead of truncating columns.
    if ($Width -lt $minimumWidth) {
        if ($RowColorProperty -or $RowWarningProperty) {
            # Narrow layouts still show row-specific choices and compatibility warnings.
            foreach ($row in $Rows) {
                $text = ($row | Format-List -Property $Properties | Out-String -Width ([Math]::Max(20, $Width))).TrimEnd()
                $selected = if ($SelectedColumnProperty) { [string] $row.$SelectedColumnProperty } else { '' }
                $color = if ($RowColorProperty) { $row.$RowColorProperty } else { $null }
                Write-HighlightedReviewRow $text $color $hostParameters -Properties $Properties -SelectedProperty $selected -ListLayout
                if ($RowWarningProperty) {
                    foreach ($warning in $row.$RowWarningProperty) { Write-Warning $warning }
                }
            }
        } else {
            Write-Host (($Rows | Format-List -Property $Properties | Out-String -Width ([Math]::Max(20, $Width))).TrimEnd()) @hostParameters
        }
        return
    }
    $flexibleIndex = [array]::IndexOf($Properties, $FlexibleProperty)
    if ($flexibleIndex -lt 0) { throw "Unknown flexible table property '$FlexibleProperty'." }
    $paddingIndex = if ($PaddingProperty) { [array]::IndexOf($Properties, $PaddingProperty) } else { $flexibleIndex }
    if ($paddingIndex -lt 0) { throw "Unknown padding table property '$PaddingProperty'." }
    $preferredFlexibleWidth = 0
    $widths = @(
        for ($index = 0; $index -lt $Properties.Count; $index++) {
            # Compact columns keep their content widths; the flexible column absorbs wrapping.
            $length = $minimum[$index]
            foreach ($row in $Rows) {
                foreach ($line in ([string] $row.($Properties[$index]) -split '\r?\n')) {
                    $length = [Math]::Max($length, $line.Length)
                }
            }
            if ($index -eq $flexibleIndex) {
                $preferredFlexibleWidth = $length
                $initialWidth = [Math]::Min(24, $Width - $minimumWidth + $minimum[$index])
                if ($PaddingProperty) { [Math]::Min($length, $initialWidth) } else { $initialWidth }
            }
            else { $length }
        }
    )
    # Shrink the compact column with the most spare width, keeping every header readable.
    [int] $totalWidth = ($widths | Measure-Object -Sum).Sum + $separatorWidth
    while ($totalWidth -gt $Width) {
        # Redistribute spare width without shrinking any column below its header.
        $shrinkIndex = -1
        $slack = 0
        for ($index = 0; $index -lt $Properties.Count; $index++) {
            if ($index -ne $flexibleIndex -and $widths[$index] - $minimum[$index] -gt $slack) {
                $shrinkIndex = $index
                $slack = $widths[$index] - $minimum[$index]
            }
        }
        if ($shrinkIndex -lt 0) { throw 'Cannot fit the table into the available console width.' }
        $widths[$shrinkIndex]--
        $totalWidth--
    }
    $extraWidth = $Width - $totalWidth
    $contentGrowth = if ($PaddingProperty) {
        [Math]::Min($extraWidth, [Math]::Max(0, $preferredFlexibleWidth - $widths[$flexibleIndex]))
    } else { $extraWidth }
    $widths[$flexibleIndex] += $contentGrowth
    $widths[$paddingIndex] += $extraWidth - $contentGrowth
    $columns = @(
        for ($index = 0; $index -lt $Properties.Count; $index++) {
            $columnWidth = $widths[$index]
            if ($index -lt $Properties.Count - 1) { $columnWidth += $ColumnSpacing - 1 }
            $column = @{ Label = $Labels[$index]; Expression = $Properties[$index]; Width = $columnWidth }
            if ($ColumnSpacing -gt 1) { $column['Alignment'] = 'Left' }
            $column
        }
    )
    if ($RowColorProperty -or $RowWarningProperty) {
        # Render rows individually so selected cells and warnings stay associated with their ID.
        if (-not $HideTableHeaders) {
            $headerRow = [ordered]@{}
            foreach ($property in $Properties) { $headerRow[$property] = $null }
            $header = ([pscustomobject] $headerRow | Format-Table -Property $columns -Wrap | Out-String -Width $Width).TrimEnd()
            Write-Host $header @hostParameters
        }
        foreach ($row in $Rows) {
            $text = ($row | Format-Table -Property $columns -Wrap -HideTableHeaders | Out-String -Width $Width).TrimEnd()
            $selected = if ($SelectedColumnProperty) { [string] $row.$SelectedColumnProperty } else { '' }
            $color = if ($RowColorProperty) { $row.$RowColorProperty } else { $null }
            Write-HighlightedReviewRow ($text.TrimStart([char[]] "`r`n")) $color $hostParameters `
                -Properties $Properties -Widths $widths -ColumnSpacing $ColumnSpacing -SelectedProperty $selected
            if ($RowWarningProperty) {
                foreach ($warning in $row.$RowWarningProperty) { Write-Warning $warning }
            }
        }
        return
    }
    $text = ($Rows | Format-Table -Property $columns -Wrap -HideTableHeaders:$HideTableHeaders | Out-String -Width $Width).TrimEnd()
    # Remove formatter padding only; indentation aligns the colored continuation under its note.
    if ($HideTableHeaders) { $text = $text.TrimStart([char[]] "`r`n") }
    Write-Host $text @hostParameters
}

function Write-DecisionSelection {
    <#
    .SYNOPSIS
    Confirms an interactive choice without repeating its comparison or explanation.
    .DESCRIPTION
    Includes a resolved priority only when selecting the source required a new priority.
    .PARAMETER Item
    Resolved decision, optionally containing a resolved custom-rule priority.
    .OUTPUTS
    Host information records only.
    #>
    param($Item)
    if ($Item.Choice -notin 'KeepSource','KeepTarget') {
        throw "Cannot display an unresolved decision for row $($Item.Id)."
    }
    $text = "[$($Item.Id)] $($Item.Choice)"
    if ($null -ne $Item.ResolvedPriority) { $text += " (priority $($Item.ResolvedPriority))" }
    $color = ($Item.Choice -eq 'KeepSource') ? 'Green' : 'Yellow'
    Write-Host $text -ForegroundColor $color
}

function Test-PolicySettingOverridesDefaults {
    <#
    .SYNOPSIS
    Identifies explicit policy settings that differ from documented WAF defaults.
    .DESCRIPTION
    Detection is the documented policy-creation mode. Custom redirect URLs,
    response bodies and log-scrubbing rules override unconfigured settings.
    Request-body inspection has no published default and is not classified.
    #>
    param([bool] $Present, [AllowNull()] $Value, [string] $Key)
    if (-not $Present -or $null -eq $Value) { return $false }
    if ($Key -eq 'policySettings' -and $Value -is [System.Collections.IDictionary]) {
        foreach ($field in $Value.Keys) {
            if (Test-PolicySettingOverridesDefaults $true $Value[$field] $field) { return $true }
        }
        return $false
    }
    if ($Key -eq 'logScrubbing' -and $Value -is [System.Collections.IDictionary]) {
        foreach ($field in 'state','scrubbingRules') {
            if ($Value.Contains($field) -and (Test-PolicySettingOverridesDefaults $true $Value[$field] $field)) {
                return $true
            }
        }
        return $false
    }
    if ($Key -eq 'scrubbingRules' -and $Value -is [System.Collections.IList]) { return $Value.Count -gt 0 }
    $defaults = @{
        enabledState = 'Enabled'; mode = 'Detection'; state = 'Enabled'
        redirectUrl = ''; customBlockResponseBody = ''; customBlockResponseStatusCode = 403
        javascriptChallengeExpirationInMinutes = 30; captchaExpirationInMinutes = 30
    }
    if (-not $defaults.ContainsKey($Key)) { return $false }
    return -not (Test-JsonEqual $Value $defaults[$Key] $Key)
}

function Format-PolicySettingValue {
    <#
    .SYNOPSIS
    Formats policy-setting summaries with default markers and body redaction.
    .DESCRIPTION
    Uses --- for omitted settings and summarizes complex values without exposing bodies.
    #>
    param([bool] $Present, [AllowNull()] $Value, [string] $Key)
    if (-not $Present) { return '---' }
    $display = if ($Key -eq 'customBlockResponseBody') { 'Custom body' }
        elseif ($Value -is [System.Collections.IDictionary]) { 'Configured' }
        elseif ($Value -is [System.Collections.IList]) { "$($Value.Count) entries" }
        else { [string] $Value }
    if (Test-PolicySettingOverridesDefaults $Present $Value $Key) { $display += ' *' }
    $display
}

function Get-DrsComparableAction {
    <#
    .SYNOPSIS
    Normalizes equivalent managed blocking actions without changing custom actions.
    .DESCRIPTION
    Treats Block and AnomalyScoring as equivalent only in the default-rule-set family.
    #>
    param([string] $Action, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    if ($RuleSetType -cne 'Microsoft_DefaultRuleSet') { return $Action }
    if ($Action -cin 'Block', 'AnomalyScoring', 'Block on Anomaly') { return 'AnomalyScoring' }
    $Action
}

function Test-DrsActionEqual {
    <#
    .SYNOPSIS
    Compares managed actions using their equivalent blocking behavior.
    .DESCRIPTION
    Keeps Bot/HTTP actions distinct while comparing canonical DRS blocking actions.
    #>
    param([string] $Left, [string] $Right, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    (Get-DrsComparableAction $Left $RuleSetType) -ceq (Get-DrsComparableAction $Right $RuleSetType)
}

function Format-DrsStatusAction {
    <#
    .SYNOPSIS
    Formats a managed rule's status/action and optional sensitivity, or its absence marker.
    .DESCRIPTION
    Omits activity for absent rules instead of presenting their prospective defaults.
    #>
    param([string] $State, [string] $Action, [string] $Sensitivity)
    if ($State -eq 'Not present') { return '---' }
    $text = "$State / $($Action -replace 'AnomalyScoring', 'Anomaly scoring')"
    if ($Sensitivity) { $text += " / $Sensitivity" }
    $text
}

function Get-DecisionOverview {
    <#
    .SYNOPSIS
    Builds display-only scope and comparison cells for a decision summary.
    .DESCRIPTION
    Uses each policy's own defaults for override markers without changing candidates.
    Tag labels preserve exact keys and summarize values without exposing their contents.
    Exclusion rows compare membership only, independently of rule settings.
    #>
    param($Item)
    if ($Item.DecisionKind -eq 'ManagedException') {
        # Exception summaries show scope and value counts, never the sensitive predicates.
        $context = $Item.ExceptionContext
        return [pscustomobject]@{
            Id = $Item.Id; Item = 'Request exception'; Name = 'Request exception'
            ReviewScope = $context.Scopes -join '; '
            MatchVariable = $context.MatchVariable; Selector = $context.Selector
            ValueOperator = $context.Operator; MatchValueCount = $context.MatchValueCount
            Source = if ($Item.SourcePresent) { 'Present' } else { '---' }
            Target = if ($Item.TargetPresent) { 'Present' } else { '---' }
        }
    }
    if ($Item.DecisionKind -eq 'DrsExclusion') {
        # Exclusion membership is reviewed independently from rule state and action.
        $context = $Item.ExclusionContext
        $exclusion = $Item.SourceValue ?? $Item.TargetValue
        $scope = switch ($context.ScopeKind) {
            'Rule set' { 'Rule set' }
            'Rule group' { "Rule group: $($context.GroupName)" }
            'Individual rule' { "Rule: $($context.GroupName)/$($context.RuleId)" }
            default { throw "Unsupported exclusion scope '$($context.ScopeKind)'." }
        }
        $selector = if ($exclusion['selector'] -ceq '') { '(empty selector)' } else { $exclusion['selector'] }
        $name = switch ($context.ScopeKind) {
            'Rule set' { $Item.RuleSetType }
            'Rule group' { Get-DisplayRuleGroup $Item.RuleSetType $context.GroupName }
            'Individual rule' { $Item.RuleDescription }
        }
        return [pscustomobject]@{
            Id = $Item.Id; Item = "Exclusion: $selector"; ExclusionScope = $scope
            Name = $name; Review = 'Exclusion'; ReviewScope = $scope; ScopeKind = $context.ScopeKind
            MatchVariable = $exclusion['matchVariable']; SelectorOperator = $exclusion['selectorMatchOperator']; Selector = $selector
            Source = if ($Item.SourcePresent) { 'Present' } else { '---' }
            Target = if ($Item.TargetPresent) { 'Present' } else { '---' }
        }
    }
    $label = Get-DecisionLabel $Item
    $sourceText = 'Existing settings'
    $targetText = 'Different settings'
    if ($Item.DecisionKind -eq 'TargetCustomRule') {
        $sourceText = 'Not used'; $targetText = 'Included'
    }
    elseif ($Item.DecisionKind -eq 'DrsRisk') {
        # Represent native same-ID behavior changes without suggesting a cross-ID copy.
        $row = $Item.RiskContext[0]
        $group = switch ($Item.RuleGroupName) {
            '(rule-set scope)' { 'All managed rules' }
            'LFI' { 'File/path attacks (LFI)' }
            'SQLI' { 'SQL injection (SQLI)' }
            default { $Item.RuleGroupName }
        }
        if ($Item.RiskContext.Count -gt 1) {
            $label = "$($Item.RiskContext.Count) active rules"
            $sourceText = 'Enabled'; $targetText = 'Disabled'
        }
        elseif ($row.ScopeKind -eq 'Exclusions') {
            $label = "$group exclusions"
            $sourceText = $row.SourceEffectiveState; $targetText = $row.TargetEffectiveState
        }
        elseif ($row.ScopeKind -eq 'RuleSetAction') {
            $label = 'Managed-rule action'
            $sourceText = $row.SourceEffectiveAction; $targetText = $row.TargetEffectiveAction
        }
        elseif ($row.BaselineOnly -or ($row.RiskKinds.Count -eq 1 -and $row.RiskKinds[0] -eq 'SourceDisableChanged')) {
            $label = "Rule $($row.RuleId): $($Item.RuleDescription)"
            if ($Item.RuleSetType -eq 'Microsoft_DefaultRuleSet') { $label += " (target $(Format-DrsParanoiaLevel $row.TargetParanoiaLevel))" }
            $sourceText = $row.SourceEffectiveState; $targetText = $row.TargetEffectiveState
        }
        elseif ($row.RuleId -ne 'All') {
            $label = "Rule $($row.RuleId): $($Item.RuleDescription)"
            if ($Item.RuleSetType -eq 'Microsoft_DefaultRuleSet') { $label += " (target $(Format-DrsParanoiaLevel $row.TargetParanoiaLevel))" }
            if (@($row.RiskKinds | Where-Object { $_ -in 'ProtectionLoss','SourceDisableChanged','ActionTuningChanged','EnforcementReduced' }).Count) {
                $sourceText = "$($row.SourceEffectiveState) / $($row.SourceEffectiveAction)"
                $targetText = "$($row.TargetEffectiveState) / $($row.TargetEffectiveAction)"
            }
        }
        else { $label = 'Source carryover needs review' }
    }
    else {
        if ($Item.Path -eq 'properties.policySettings' -or
            $Item.Path.StartsWith('properties.policySettings.', [StringComparison]::Ordinal)) {
            if ($Item.Path -eq 'properties.policySettings') { $label = 'Policy settings' }
            elseif ($Item.Path -eq "properties.policySettings.$($Item.Key)") {
                $label = switch ($Item.Key) {
                    # Match portal terminology while retaining the underlying API field keys.
                    'requestBodyCheck' { 'Enable request body inspection' }
                    'customBlockResponseBody' { 'Block response body' }
                    'customBlockResponseStatusCode' { 'Block response status code' }
                    'captchaExpirationInMinutes' { 'CAPTCHA expiration (minutes)' }
                    'javascriptChallengeExpirationInMinutes' { 'JavaScript challenge expiration (minutes)' }
                    'redirectUrl' { 'Redirect URL' }
                    'logScrubbing' { 'Log scrubbing' }
                    default { $label }
                }
            }
            $sourceText = Format-PolicySettingValue $Item.SourcePresent $Item.SourceValue $Item.Key
            $targetText = Format-PolicySettingValue $Item.TargetPresent $Item.TargetValue $Item.Key
        }
        elseif ($Item.Path -eq 'tags' -or $Item.Path.StartsWith('tags.', [StringComparison]::Ordinal)) {
            $label = if ($Item.Path -eq 'tags') { 'Tags' } else { "Tag: $($Item.Key)" }
            $sourceText = if ($Item.SourcePresent) { 'Existing value' } else { '---' }
            $targetText = if ($Item.TargetPresent) { 'Existing value' } else { '---' }
        }
        elseif ($Item.Key -eq 'ruleSetVersion') {
            $sourceText = [string] $Item.SourceValue; $targetText = [string] $Item.TargetValue
        }
        elseif (-not $Item.TargetPresent) {
            $targetText = 'Not included'
        }
    }
    $customDetails = @{ SourcePriority = '---'; TargetPriority = '---'; SelectedPriority = '---'; Selection = '---'; Type = '---' }
    if ($Item.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)) {
        # Preserve independent source/target priority and action details for the existing merge.
        $sourceText = if (-not $Item.SourcePresent) { '---' }
            elseif ($Item.SourceValue.Contains('enabledState')) { [string] $Item.SourceValue['enabledState'] }
            else { 'Enabled' }
        $targetText = if (-not $Item.TargetPresent) { '---' }
            elseif ($Item.TargetValue.Contains('enabledState')) { [string] $Item.TargetValue['enabledState'] }
            else { 'Enabled' }
        foreach ($column in 'Priority', 'Type') {
            # Input priorities are separate values, not a source-to-master renumbering.
            $key = if ($column -eq 'Priority') { 'priority' } else { 'ruleType' }
            $sourceValue = if ($Item.SourcePresent -and $Item.SourceValue.Contains($key)) { [string] $Item.SourceValue[$key] } else { '---' }
            $targetValue = if ($Item.TargetPresent -and $Item.TargetValue.Contains($key)) { [string] $Item.TargetValue[$key] } else { '---' }
            if ($column -eq 'Type') {
                $sourceValue = switch ($sourceValue) { 'MatchRule' { 'Match' }; 'RateLimitRule' { 'Rate limit' }; default { $sourceValue } }
                $targetValue = switch ($targetValue) { 'MatchRule' { 'Match' }; 'RateLimitRule' { 'Rate limit' }; default { $targetValue } }
            }
            if ($column -eq 'Priority') {
                $customDetails.SourcePriority = if ($Item.SourcePresent -and $Item.SourceValue.Contains('priority')) {
                    [string] $Item.SourcePriority
                } else { '---' }
                $customDetails.TargetPriority = $targetValue
            } else {
                $customDetails.Type = if (-not $Item.SourcePresent) { $targetValue }
                    elseif (-not $Item.TargetPresent -or $sourceValue -eq $targetValue) { $sourceValue }
                    else { "$sourceValue -> $targetValue" }
            }
        }
        # Selected priorities are proposals until conflicting copies have been resolved.
        switch ($Item.Choice) {
            'KeepSource' {
                $customDetails.Selection = if ($Item.SourcePresent) { 'Source' } else { 'Remove' }
                $customDetails.SelectedPriority = if ($Item.SourcePresent -and $Item.SourceValue.Contains('priority')) {
                    [string] $Item.SourceValue['priority']
                } else { '---' }
            }
            'KeepTarget' {
                $customDetails.Selection = if ($Item.TargetPresent) { 'Master' } else { 'Omit' }
                $customDetails.SelectedPriority = $customDetails.TargetPriority
            }
            default {
                $customDetails.Selection = 'Pending'
                $customDetails.SelectedPriority = 'Pending'
            }
        }
        if ($Item.SourcePresent) {
            $sourceAction = if ($Item.SourceValue.Contains('action')) { [string] $Item.SourceValue['action'] } else { '---' }
            $sourceText = "$sourceText / $sourceAction"
        }
        if ($Item.TargetPresent) {
            $targetAction = if ($Item.TargetValue.Contains('action')) { [string] $Item.TargetValue['action'] } else { '---' }
            $targetText = "$targetText / $targetAction"
        }
    }
    $sourceText = $sourceText -replace '^1 exclusions$', '1 exclusion' -replace 'AnomalyScoring', 'Anomaly scoring'
    $targetText = $targetText -replace '^1 exclusions$', '1 exclusion' -replace 'AnomalyScoring', 'Anomaly scoring'
    $paranoiaLevel = '---'
    if ($Item.DecisionKind -eq 'DrsRisk' -and $Item.RiskContext.Count -eq 1) {
        # Show PL from the rule's native side, including rules absent from the target.
        $activityRow = $Item.RiskContext[0]
        if ($activityRow.RuleId -ne 'All') {
            $sourceSensitivity = if ($Item.RuleSetType -ceq 'Microsoft_HTTPDDoSRuleSet') { $activityRow.SourceSensitivity } else { $null }
            $targetSensitivity = if ($Item.RuleSetType -ceq 'Microsoft_HTTPDDoSRuleSet') { $activityRow.TargetSensitivity } else { $null }
            $sourceText = Format-DrsStatusAction $activityRow.SourceEffectiveState $activityRow.SourceEffectiveAction $sourceSensitivity
            $targetText = Format-DrsStatusAction $activityRow.TargetEffectiveState $activityRow.TargetEffectiveAction $targetSensitivity
        }
        $hasTargetRule = $activityRow.RuleId -ne 'All' -and $activityRow.TargetEffectiveState -ne 'Not present'
        if ($hasTargetRule) {
            $paranoiaLevel = Format-DrsParanoiaLevel $activityRow.TargetParanoiaLevel
        } elseif ($activityRow.RuleId -ne 'All') {
            $paranoiaLevel = Format-DrsParanoiaLevel $activityRow.SourceParanoiaLevel
        }
        if ($activityRow.SourceOverridesDefaults) { $sourceText += ' *' }
        if ($activityRow.TargetOverridesDefaults) { $targetText += ' *' }
    }
    [pscustomobject]@{
        Id = $Item.Id; Item = $label; Source = $sourceText; Target = $targetText
        # Grouped coverage decisions and individual settings use distinct review scopes.
        ReviewScope = if ($Item.DecisionKind -eq 'DrsRisk') {
            if ($Item.RiskContext.Count -gt 1) { 'Individual rules' }
            elseif ($Item.RuleGroupName -eq '(rule-set scope)') { 'Rule set' }
            elseif ($Item.RuleId -eq 'All') { "Rule group: $($Item.RuleGroupName)" }
            else { "Rule: $($Item.RuleGroupName)/$($Item.RuleId)" }
        } else { '---' }
        ParanoiaLevel = $paranoiaLevel
        Name = if ($Item.DecisionKind -eq 'DrsRisk') {
            $label -replace '^Rule [^:]+: ', '' -replace ' \(target (?:PL[12]|Not documented)\)$', ''
        } else { $Item.IdentityValue }
        SourcePriority = $customDetails.SourcePriority; TargetPriority = $customDetails.TargetPriority
        SelectedPriority = $customDetails.SelectedPriority; Selection = $customDetails.Selection; Type = $customDetails.Type
    }
}

function Format-ManagedRuleSetHeader {
    <#
    .SYNOPSIS
    Formats an official family name with original source and configured target versions.
    .DESCRIPTION
    Shows --- for an unused family rather than implying a configured baseline.
    #>
    param([string] $RuleSetType)
    $sourceVersion = Get-ManagedSourceVersion $drsSourceSnapshot $RuleSetType
    $targetSet = Get-DrsSet $target $RuleSetType
    $targetVersion = if ($null -ne $targetSet) { [string] $targetSet['ruleSetVersion'] } else { '---' }
    if (-not $sourceVersion) { $sourceVersion = '---' }
    "$RuleSetType (v. $sourceVersion to $targetVersion)"
}

function Write-DefaultOverrideLegend {
    <#
    .SYNOPSIS
    Prints the source/target default-override key in italics where supported.
    .DESCRIPTION
    Uses plain text for hosts without virtual-terminal support or plain-text output.
    #>
    param([switch] $PolicySettings)
    $legend = if ($PolicySettings) {
        '* =  WAF policy defaults overridden by the source policy (Source) or master template (Target).'
    } else { '* =  Catalog defaults overridden by the source policy (Source) or master template (Target).' }
    if ($Host.UI.SupportsVirtualTerminal -and $PSStyle.OutputRendering -ne 'PlainText') {
        Write-Host "$($PSStyle.Italic)$legend$($PSStyle.Reset)"
    } else { Write-Host $legend }
}

function Write-DecisionSummary {
    <#
    .SYNOPSIS
    Prints scope-specific exclusion, managed-rule, custom-rule or policy tables.
    .DESCRIPTION
    Both selected choices highlight their review number and selected Source/Target value.
    Pending numbers and unselected columns keep the default color.
    Green indicates review selection, not compatibility or deployment validation.
    Compatibility and unresolved priority warnings immediately follow their complete row.
    #>
    param([object[]] $Items, [string] $Title, [int] $Width)
    $exclusionsOnly = $Items.Count -gt 0 -and -not @($Items | Where-Object DecisionKind -ne 'DrsExclusion').Count
    $exceptionsOnly = $Items.Count -gt 0 -and -not @($Items | Where-Object DecisionKind -ne 'ManagedException').Count
    if (-not $exclusionsOnly) { Write-Host "`n$Title" -ForegroundColor Cyan }
    if (-not $Items.Count) {
        Write-Host 'No changes to review.'
        return
    }
    $hasPolicyOverrides = $false
    $hasCatalogOverrides = $false
    $rows = @(foreach ($item in $Items) {
        $summaryRows = @(Get-DecisionOverview $item)
        foreach ($row in $summaryRows) {
            # Attach choices and actionable warnings to the same rows the user reviews.
            if ($row.Source.EndsWith(' *', [StringComparison]::Ordinal) -or
                $row.Target.EndsWith(' *', [StringComparison]::Ordinal)) {
                if ($item.Path -eq 'properties.policySettings' -or
                    $item.Path.StartsWith('properties.policySettings.', [StringComparison]::Ordinal)) {
                    $hasPolicyOverrides = $true
                } elseif ($item.DecisionKind -eq 'DrsRisk') { $hasCatalogOverrides = $true }
            }
            $selected = switch ($item.Choice) { 'KeepSource' { 'Source' }; 'KeepTarget' { 'Target' }; default { '' } }
            $row | Add-Member -NotePropertyName ReviewSelectedColumn -NotePropertyValue $selected
            $warnings = @(
                foreach ($issue in $item.CompatibilityIssues) {
                    "Row $($item.Id): KeepSource cannot be used: $issue"
                }
                if ($item.PriorityConflicts.Count -and $item.Choice -in 'Pending','KeepSource') {
                    $certainty = if ($item.Choice -eq 'Pending') { 'may conflict with' } else { 'conflicts with' }
                    "Row $($item.Id): selected source priority $($item.SourcePriority) $certainty $($item.PriorityConflicts -join ', '); KeepSource requires an unused priority if these rules are retained."
                }
            )
            $row | Add-Member -NotePropertyName ReviewWarnings -NotePropertyValue $warnings
            $row | Add-Member -NotePropertyName ReviewColor -NotePropertyValue $(if ($item.Choice -in 'KeepSource','KeepTarget') { [ConsoleColor]::Green }) -PassThru
        }
    })
    if ($hasPolicyOverrides) { Write-DefaultOverrideLegend -PolicySettings }
    if (-not $exclusionsOnly -and $hasCatalogOverrides) { Write-DefaultOverrideLegend }
    if ($exceptionsOnly) {
        Write-ResponsiveTable -Rows $rows -Properties Id,ReviewScope,MatchVariable,Selector,ValueOperator,MatchValueCount,Source,Target `
            -Labels '#',Scope,'Match variable','Header name',Operator,'Value count',Source,Target -FlexibleProperty ReviewScope -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
    } elseif ($exclusionsOnly) {
        foreach ($scopeKind in 'Rule set', 'Rule group', 'Individual rule') {
            # Keep broad bypasses visibly separate from narrowly scoped exclusions.
            $scopeRows = @($rows | Where-Object ScopeKind -ceq $scopeKind)
            if (-not $scopeRows.Count) { continue }
            $scopeTitle = switch ($scopeKind) {
                'Rule set' { 'Exclusions for the entire rule set' }
                'Rule group' { 'Exclusions for rule groups' }
                'Individual rule' { 'Exclusions for specific rules' }
            }
            Write-Host "`n$(Format-ManagedRuleSetHeader 'Microsoft_DefaultRuleSet') - $scopeTitle" -ForegroundColor Cyan
            if ($scopeKind -eq 'Rule set') {
                Write-ResponsiveTable -Rows $scopeRows -Properties Id,Name,MatchVariable,SelectorOperator,Selector,Source,Target `
                    -Labels '#',Name,'Match variable',Operator,Selector,Source,Target -FlexibleProperty Name -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
            } else {
                Write-ResponsiveTable -Rows $scopeRows -Properties Id,ReviewScope,Name,MatchVariable,SelectorOperator,Selector,Source,Target `
                    -Labels '#',Scope,Name,'Match variable',Operator,Selector,Source,Target -FlexibleProperty Name -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
            }
        }
    } elseif (-not @($Items | Where-Object { -not $_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal) }).Count) {
        Write-Host 'Source/Master priorities are input values. Selected is the proposed priority; lower numbers run first.'
        Write-Host 'Conflicts require a new source priority; retained master rules are not renumbered automatically.'
        Write-ResponsiveTable -Rows $rows -Properties Id,Name,Type,SourcePriority,TargetPriority,SelectedPriority,Selection,Source,Target `
            -Labels '#',Name,'Rule type','Source pri.','Master pri.','Selected pri.',Selection,Source,Master -FlexibleProperty Name -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
    } elseif (-not @($Items | Where-Object RuleSetType -ne 'Microsoft_DefaultRuleSet').Count) {
        Write-ResponsiveTable -Rows $rows -Properties Id,ReviewScope,Name,ParanoiaLevel,Source,Target `
            -Labels '#',Scope,Name,PL,Source,Target -FlexibleProperty Name -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
    } elseif (-not @($Items | Where-Object { $_.RuleSetType -notin (Get-ManagedRuleSetTypes) }).Count) {
        Write-ResponsiveTable -Rows $rows -Properties Id,ReviewScope,Name,Source,Target `
            -Labels '#',Scope,Name,Source,Target -FlexibleProperty Name -ColumnSpacing 3 -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
    } else {
        Write-ResponsiveTable -Rows $rows -Properties Id,Item,Source,Target `
            -Labels '#','What to review',Source,Target -FlexibleProperty Item -Width $Width -RowColorProperty ReviewColor -SelectedColumnProperty ReviewSelectedColumn -RowWarningProperty ReviewWarnings
    }
}

function Write-DecisionTable {
    <#
    .SYNOPSIS
    Prints comparison tables and actionable compatibility or priority warnings.
    .DESCRIPTION
    Selected IDs and comparison values are highlighted within the tables.
    Warnings appear directly beneath their rows, not in a detached final block.
    An empty plan is silent; detailed narrative reviews and private values are not printed.
    .PARAMETER Items
    Complete decision objects to display.
    .OUTPUTS
    Host information records only.
    #>
    param([object[]] $Items)
    if ($Items.Count -eq 0) { return }
    $width = Get-ConsoleWidth
    $customItems = @($Items | Where-Object { $_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal) })
    $policyItems = @($Items | Where-Object {
        -not $_.RuleSetType -and $_.DecisionKind -ne 'ManagedException' -and
            -not $_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)
    })
    Write-DecisionSummary $policyItems 'Policy settings and tags' $width
    $managedItems = @($Items | Where-Object RuleSetType)
    foreach ($section in ($managedItems | Group-Object RuleSetType)) {
        # Separate DRS exclusions from effective-rule changes; other families use their own tables.
        $familyHeader = Format-ManagedRuleSetHeader $section.Name
        if ($section.Name -eq 'Microsoft_DefaultRuleSet') {
            $exclusionItems = @($section.Group | Where-Object DecisionKind -eq 'DrsExclusion')
            $otherItems = @($section.Group | Where-Object DecisionKind -ne 'DrsExclusion')
            if ($exclusionItems.Count) {
                Write-DecisionSummary $exclusionItems $familyHeader $width
            }
            Write-DecisionSummary $otherItems "$familyHeader - changed defaults and settings" $width
        } else {
            Write-DecisionSummary $section.Group $familyHeader $width
        }
    }
    $exceptionItems = @($Items | Where-Object DecisionKind -eq 'ManagedException')
    if ($exceptionItems.Count) {
        Write-DecisionSummary $exceptionItems 'Request exceptions (Preview) - bypass inspection only at the listed scopes' $width
    }
    Write-DecisionSummary $customItems 'Custom rules' $width
}

#endregion

#region DRS diagnostics and custom-rule priority resolution
function Get-DrsBlockingIssues {
    <#
    .SYNOPSIS
    Finds unresolved original-version source baselines that prevent safe comparison.
    .DESCRIPTION
    Checks original source identities against their own catalogs across all managed families.
    #>
    param([System.Collections.IDictionary] $Configuration = $target)
    $null = Get-DrsTargetVersion $Configuration
    return ,@(
        foreach ($type in (Get-ManagedRuleSetTypes)) {
            # Validate the unmodified source against its own version before considering carryover.
            $version = Get-ManagedSourceVersion $drsSourceSnapshot $type
            if (-not $version) { continue }
            $sourceRules = Get-DrsEffectiveRules $drsSourceSnapshot $version $type
            foreach ($issue in (Get-DrsSourceBaselineIssues $drsSourceSnapshot $sourceRules $type)) {
                [pscustomobject]@{
                    RuleSetType = $type; RuleGroupName = $issue.Group; RuleId = $issue.RuleId
                    SourceEnabledState = $issue.State
                    Message = $issue.Message
                }
            }
        }
    )
}

function Write-MigrationBlockingIssues {
    <#
    .SYNOPSIS
    Prints explicit configuration or baseline errors that prevent template generation.
    .DESCRIPTION
    Renders blocking diagnostics in a responsive error table without applying settings.
    #>
    param([object[]] $Issues)
    if (-not $Issues.Count) { return }
    Write-Host "`nERROR: migration configuration/baseline must be corrected; generation is blocked" -ForegroundColor Red
    $rows = @($Issues | ForEach-Object {
        [pscustomobject]@{
            Rule = $_.RuleId
            Note = "Source state: $($_.SourceEnabledState). $($_.Message)"
        }
    })
    Write-ResponsiveTable -Rows $rows -Properties Rule,Note -Labels Rule,Error `
        -FlexibleProperty Note -Width (Get-ConsoleWidth) -ForegroundColor Red
}

function Get-CustomPriorityConflicts {
    <#
    .SYNOPSIS
    Finds differently named custom rules occupying a candidate priority.
    .DESCRIPTION
    Planning overlays preset choices on the target and considers both alternatives
    for pending source decisions. Execution can restrict checks to the current target.
    .PARAMETER Rule
    Candidate custom-rule dictionary.
    .PARAMETER CurrentTargetOnly
    Restricts checking to the effective target at execution time.
    .OUTPUTS
    One sorted array of conflicting custom-rule names.
    #>
    param([System.Collections.IDictionary] $Rule, [switch] $CurrentTargetOnly)
    $rules = Get-Collection $script:target['properties']['customRules'] 'rules'
    if (-not $CurrentTargetOnly) {
        # A selected source replaces its namesake; its old master priority is no longer occupied.
        foreach ($decision in ($decisions | Where-Object Identity -eq 'name')) {
            if ($decision.Choice -eq 'KeepSource') {
                $rules = @($rules | Where-Object { $_['name'] -cne $decision.IdentityValue })
            }
            if ($decision.SourcePresent -and $decision.Choice -in 'KeepSource', 'Pending') {
                $rules += @($decision.SourceValue)
            }
        }
    }
    return ,@($rules | Where-Object {
        $_['name'] -cne $Rule['name'] -and $_['priority'] -eq $Rule['priority']
    } | ForEach-Object { [string] $_['name'] } | Sort-Object -Unique -CaseSensitive)
}

function Resolve-CustomPriority {
    <#
    .SYNOPSIS
    Resolves an occupied custom-rule priority before applying KeepSource.
    .DESCRIPTION
    Uses the chosen merged rules when all custom choices are known; otherwise checks
    the current target. Prompts for a conflicting copy and validates 1-1000 and vacancy.
    Mutates the candidate and records its resolved priority without renumbering master rules.
    .PARAMETER Decision
    KeepSource custom-rule decision; non-custom decisions are unchanged.
    .OUTPUTS
    None. May prompt, warn, mutate the candidate, or throw on cancellation.
    #>
    param($Decision)
    if ($Decision.Identity -ne 'name') { return }
    # Known future source selections free old master slots and reserve their new priorities.
    $currentTargetOnly = @($decisions | Where-Object { $_.Identity -eq 'name' -and $_.Choice -eq 'Pending' }).Count -gt 0
    $conflicts = Get-CustomPriorityConflicts $Decision.SourceValue -CurrentTargetOnly:$currentTargetOnly
    if ($conflicts.Count -eq 0) { return }
    Write-Warning "Row $($Decision.Id): '$($Decision.IdentityValue)' needs priority $($Decision.SourceValue['priority']), already used by $($conflicts -join ', '). Retained master rules will not be removed or renumbered."
    do {
        $answer = (Read-Host "Choose an unused priority (1-1000) for '$($Decision.SourceValue['name'])', or Q to quit").Trim()
        if ($answer.ToUpperInvariant() -in 'Q', 'QUIT') { throw 'Migration cancelled. No ARM file was written.' }
        $priority = 0
        $valid = [int]::TryParse($answer, [ref] $priority) -and $priority -ge 1 -and $priority -le 1000
        if ($valid) {
            # Probe a copy so rejected priorities never alter the source candidate.
            $candidate = Copy-JsonValue $Decision.SourceValue
            $candidate['priority'] = $priority
            $valid = (Get-CustomPriorityConflicts $candidate -CurrentTargetOnly:$currentTargetOnly).Count -eq 0
        }
        if (-not $valid) { Write-Warning 'Enter an unused integer priority between 1 and 1000.' }
    } until ($valid)
    $Decision.SourceValue['priority'] = $priority
    $Decision.ResolvedPriority = $priority
}

#endregion

#region Candidate validation, inheritance, comparison and application
function Get-DrsExclusionEntries {
    <#
    .SYNOPSIS
    Enumerates configured exclusions with exact rule-set, group or individual scope.
    .DESCRIPTION
    Preserves scope identities and configured criteria without expanding inherited exclusions.
    #>
    param([System.Collections.IDictionary] $Configuration)
    $set = Get-DrsSet $Configuration
    if ($null -eq $set) { return ,@() }
    $groups = Get-Collection $set 'ruleGroupOverrides'
    return ,@(
        foreach ($exclusion in (Get-Collection $set 'exclusions')) {
            [pscustomobject]@{ ScopeKind = 'Rule set'; GroupName = ''; RuleId = ''; Exclusion = $exclusion }
        }
        foreach ($group in $groups) {
            foreach ($exclusion in (Get-Collection $group 'exclusions')) {
                [pscustomobject]@{ ScopeKind = 'Rule group'; GroupName = $group['ruleGroupName']; RuleId = ''; Exclusion = $exclusion }
            }
        }
        foreach ($group in $groups) {
            foreach ($rule in (Get-Collection $group 'rules')) {
                # Preserve individual scope identities rather than expanding inherited exclusions.
                foreach ($exclusion in (Get-Collection $rule 'exclusions')) {
                    [pscustomobject]@{
                        ScopeKind = 'Individual rule'; GroupName = $group['ruleGroupName']
                        RuleId = $rule['ruleId']; Exclusion = $exclusion
                    }
                }
            }
        }
    )
}

function Add-DrsExclusionDecisions {
    <#
    .SYNOPSIS
    Pairs exact-scope exclusions and independently reviews only unmatched entries.
    .DESCRIPTION
    Matches duplicate occurrences one-to-one and preserves shared entries for generation.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration)
    $sourceEntries = Get-DrsExclusionEntries $SourceConfiguration
    $targetEntries = Get-DrsExclusionEntries $target
    # Match duplicates one-to-one so an extra occurrence remains a real difference.
    $pairedTargetIndexes = [System.Collections.Generic.HashSet[int]]::new()
    $pairs = @(
        foreach ($entry in $sourceEntries) {
            $targetEntry = $null
            # Pair equivalent selector spellings only within the exact same scope.
            for ($index = 0; $index -lt $targetEntries.Count; $index++) {
                $candidate = $targetEntries[$index]
                if (-not $pairedTargetIndexes.Contains($index) -and
                    $entry.GroupName -ceq $candidate.GroupName -and $entry.RuleId -ceq $candidate.RuleId -and
                    (Test-JsonEqual $entry.Exclusion $candidate.Exclusion 'exclusion')) {
                    $null = $pairedTargetIndexes.Add($index)
                    $targetEntry = $candidate
                    break
                }
            }
            [pscustomobject]@{ Entry = $entry; SourcePresent = $true; TargetEntry = $targetEntry }
        }
        for ($index = 0; $index -lt $targetEntries.Count; $index++) {
            if (-not $pairedTargetIndexes.Contains($index)) {
                [pscustomobject]@{ Entry = $targetEntries[$index]; SourcePresent = $false; TargetEntry = $targetEntries[$index] }
            }
        }
    )
    foreach ($pair in $pairs) {
        if ($pair.SourcePresent -and $null -ne $pair.TargetEntry) { continue }
        $entry = $pair.Entry
        $path = $drsPath
        if ($entry.GroupName) { $path += ".ruleGroupOverrides[$($entry.GroupName)]" }
        if ($entry.RuleId) { $path += ".rules[$($entry.RuleId)]" }
        $targetValue = if ($null -ne $pair.TargetEntry) { $pair.TargetEntry.Exclusion } else { $null }
        $sourceValue = if ($pair.SourcePresent) { $entry.Exclusion } else { $null }
        Add-Decision $target['properties']['managedRules'] 'exclusions' "$path.exclusions" `
            ($null -ne $pair.TargetEntry) $targetValue $pair.SourcePresent $sourceValue -DecisionKind DrsExclusion
        $decision = $decisions[$decisions.Count - 1]
        $decision.ExclusionContext = [pscustomobject]@{
            # Shared occurrences remain in the target even when another occurrence is reviewed.
            ScopeKind = $entry.ScopeKind; GroupName = $entry.GroupName; RuleId = $entry.RuleId
            MatchVariable = $entry.Exclusion['matchVariable']; Operator = $entry.Exclusion['selectorMatchOperator']
            Selector = $entry.Exclusion['selector']
            UnchangedExclusions = @(
                foreach ($shared in $pairs) {
                    if ($shared.SourcePresent -and $null -ne $shared.TargetEntry -and
                        $shared.Entry.GroupName -ceq $entry.GroupName -and $shared.Entry.RuleId -ceq $entry.RuleId) {
                        Copy-JsonValue $shared.TargetEntry.Exclusion
                    }
                }
            )
        }
        $decision.Scope = 'Individual exclusion'
        $decision.Operation = 'Review'
    }
}

function Set-DrsExclusionChoices {
    <#
    .SYNOPSIS
    Applies independently selected exclusion membership while preserving rule settings.
    .DESCRIPTION
    Rebuilds only reviewed scopes, retaining shared entries and enforcing source compatibility.
    #>
    param([System.Collections.IDictionary] $Configuration, [object[]] $Items)
    $entries = Get-DrsExclusionEntries $Configuration
    foreach ($scope in ($Items | Where-Object DecisionKind -eq 'DrsExclusion' | Group-Object -CaseSensitive -Property {
        ConvertTo-Json -InputObject @($_.ExclusionContext.GroupName, $_.ExclusionContext.RuleId) -Compress
    })) {
        $context = $scope.Group[0].ExclusionContext
        # Unreviewed shared entries must survive rebuilding a scope's selected list.
        $selected = @(
            foreach ($exclusion in $context.UnchangedExclusions) { Copy-JsonValue $exclusion }
            foreach ($item in $scope.Group) {
                if ($item.Choice -eq 'KeepSource') {
                    Assert-KeepSourceCompatibility $item
                    if ($item.SourcePresent) { Copy-JsonValue $item.SourceValue }
                } elseif ($item.Choice -eq 'KeepTarget') {
                    if ($item.TargetPresent) { Copy-JsonValue $item.TargetValue }
                } else { throw "Exclusion review $($item.Id) is unresolved." }
            }
        )
        $current = @($entries | Where-Object {
            $_.GroupName -ceq $context.GroupName -and $_.RuleId -ceq $context.RuleId
        } | ForEach-Object Exclusion)
        if (Test-JsonEqual $current $selected 'exclusions') { continue }
        $operation = switch ($context.ScopeKind) {
            'Rule set' { @{ Kind = 'RuleSet'; Key = 'exclusions'; Value = $selected } }
            'Rule group' { @{ Kind = 'Group'; GroupName = $context.GroupName; Key = 'exclusions'; Value = $selected } }
            'Individual rule' {
                @{ Kind = 'Rule'; GroupName = $context.GroupName; RuleId = $context.RuleId
                    Value = @{ ruleId = $context.RuleId; exclusions = $selected } }
            }
            default { throw "Unsupported exclusion scope '$($context.ScopeKind)'." }
        }
        $operation['RuleSetVersion'] = (Get-DrsTargetVersion $Configuration) ??
            (Get-LatestManagedRuleSetVersion 'Microsoft_DefaultRuleSet')
        Set-DrsRiskConfiguration $Configuration @($operation)
    }
}

function Get-DrsSet {
    <#
    .SYNOPSIS
    Returns the requested managed rule set and rejects ambiguous duplicates.
    .DESCRIPTION
    Finds at most one configured managed family and rejects duplicate family identities.
    #>
    param([System.Collections.IDictionary] $Configuration, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $sets = Get-Collection $Configuration['properties']['managedRules'] 'managedRuleSets'
    $drsSets = @($sets | Where-Object { $_['ruleSetType'] -ceq $RuleSetType })
    if ($drsSets.Count -gt 1) { throw "Multiple $RuleSetType rule sets cannot be evaluated." }
    if ($drsSets.Count) { return $drsSets[0] }
}

function Get-DrsTargetVersion {
    <#
    .SYNOPSIS
    Returns a configured family's target version, or no version for an absent family.
    .DESCRIPTION
    Reads the selected family's declared version without creating an absent family.
    #>
    param([System.Collections.IDictionary] $Configuration = $target,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $set = Get-DrsSet $Configuration $RuleSetType
    if ($null -eq $set) { return }
    $version = [string] $set['ruleSetVersion']
    if ($RuleSetType -eq 'Microsoft_DefaultRuleSet' -and $version -notin '2.1', '2.2') {
        throw "Unsupported target DRS version '$version'; supported targets are 2.1 and 2.2."
    }
    if ($RuleSetType -ne 'Microsoft_DefaultRuleSet' -and -not $drsCatalog.ContainsKey("$RuleSetType/$version")) {
        throw "No pinned native defaults for target $RuleSetType/$version. Update the embedded catalog before migration."
    }
    $version
}

function Add-ManagedExceptionDecisions {
    <#
    .SYNOPSIS
    Independently reviews unmatched request exceptions, preserving each complete scope list.
    .DESCRIPTION
    Aligns versions to the selected target without remapping rule identities.
    Matches identical occurrences one-to-one; changing criteria or scope creates
    separate source-only and target-only choices rather than silently broadening a bypass.
    Report metadata contains counts and scope identities, never match values.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration)
    $proposal = Copy-JsonValue $SourceConfiguration
    Sync-ManagedSourceVersions $proposal $target
    $managed = $proposal['properties']['managedRules']
    $sourceEntries = if ($managed.Contains('exceptionsList')) {
        Get-Collection $managed['exceptionsList'] 'exceptions'
    } else { ,@() }
    $targetManaged = $target['properties']['managedRules']
    $targetEntries = if ($targetManaged.Contains('exceptionsList')) {
        Get-Collection $targetManaged['exceptionsList'] 'exceptions'
    } else { ,@() }
    $matched = [System.Collections.Generic.HashSet[int]]::new()
    $unmatched = @(
        foreach ($entry in $sourceEntries) {
            $found = $false
            # Match complete predicates one-to-one so duplicate exception counts remain significant.
            for ($index = 0; $index -lt $targetEntries.Count; $index++) {
                if (-not $matched.Contains($index) -and (Test-JsonEqual $entry $targetEntries[$index])) {
                    $null = $matched.Add($index)
                    $found = $true
                    break
                }
            }
            if (-not $found) { [pscustomobject]@{ Entry = $entry; SourcePresent = $true; TargetIndex = -1 } }
        }
        for ($index = 0; $index -lt $targetEntries.Count; $index++) {
            if (-not $matched.Contains($index)) {
                [pscustomobject]@{ Entry = $targetEntries[$index]; SourcePresent = $false; TargetIndex = $index }
            }
        }
    )
    foreach ($pair in $unmatched) {
        $entry = $pair.Entry
        $sourceValue = if ($pair.SourcePresent) { $entry } else { $null }
        $targetValue = if (-not $pair.SourcePresent) { $entry } else { $null }
        Add-Decision $targetManaged 'exceptionsList' "properties.managedRules.exceptionsList.exceptions[$($decisions.Count + 1)]" `
            (-not $pair.SourcePresent) $targetValue $pair.SourcePresent $sourceValue -DecisionKind ManagedException
        $decision = $decisions[$decisions.Count - 1]
        $decision.Scope = 'Request exception'
        $decision.Operation = 'Review'
        $decision.ExceptionContext = [pscustomobject]@{
            # Retain the original target index for precise removal without exposing match values.
            TargetIndex = $pair.TargetIndex
            MatchVariable = $entry['matchVariable']; Operator = $entry['valueMatchOperator']
            Selector = if ($entry.Contains('selector')) { $entry['selector'] } else { '---' }
            MatchValueCount = (Get-Collection $entry 'matchValues').Count
            Scopes = @(
                foreach ($scope in (Get-Collection $entry 'scopes')) {
                    $setLabel = "$($scope['ruleSetType']) v$($scope['ruleSetVersion'])"
                    $groups = Get-Collection $scope 'ruleGroupScopes'
                    if (-not $groups.Count) { "$setLabel / Entire rule set" }
                    foreach ($group in $groups) {
                        $rules = Get-Collection $group 'ruleScopes'
                        if (-not $rules.Count) { "$setLabel / Rule group: $($group['ruleGroupName'])" }
                        foreach ($rule in $rules) { "$setLabel / Rule: $($group['ruleGroupName'])/$($rule['ruleId'])" }
                    }
                }
            )
        }
    }
}

function Set-ManagedExceptionChoices {
    <#
    .SYNOPSIS
    Applies all request-exception membership choices after managed-rule tuning.
    .DESCRIPTION
    Retains unchanged and selected target entries in their original order, then
    appends selected source entries atomically, including every scope and predicate.
    Does not create families, split scopes, widen requests or remap rule IDs.
    #>
    param([System.Collections.IDictionary] $Configuration, [object[]] $Items)
    $reviews = @($Items | Where-Object DecisionKind -eq 'ManagedException')
    if (-not $reviews.Count) { return }
    foreach ($review in $reviews) {
        if ($review.Choice -notin 'KeepSource', 'KeepTarget') { throw "Request exception row $($review.Id) is unresolved." }
        if ($review.Choice -eq 'KeepSource') { Assert-KeepSourceCompatibility $review }
    }
    $managed = $Configuration['properties']['managedRules']
    $original = if ($managed.Contains('exceptionsList')) { Get-Collection $managed['exceptionsList'] 'exceptions' } else { ,@() }
    $removed = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($review in $reviews) {
        if ($review.TargetPresent -and $review.Choice -eq 'KeepSource') {
            $null = $removed.Add([int] $review.ExceptionContext.TargetIndex)
        }
    }
    $selected = @(
        for ($index = 0; $index -lt $original.Count; $index++) {
            if (-not $removed.Contains($index)) { Copy-JsonValue $original[$index] }
        }
        foreach ($review in $reviews) {
            if ($review.SourcePresent -and $review.Choice -eq 'KeepSource') { Copy-JsonValue $review.SourceValue }
        }
    )
    if ($selected.Count) { $managed['exceptionsList'] = [ordered]@{ exceptions = $selected } }
    elseif ($managed.Contains('exceptionsList')) { $managed.Remove('exceptionsList') }
}

function Get-DrsApplicableExceptions {
    <#
    .SYNOPSIS
    Collects request exceptions whose managed scopes include the specified native rule.
    .DESCRIPTION
    Returns predicates whose configured scopes match the requested family, group and rule.
    #>
    param([System.Collections.IDictionary] $Configuration, [string] $GroupName, [string] $RuleId,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $managed = $Configuration['properties']['managedRules']
    $result = @(
        if ($managed.Contains('exceptionsList')) {
            foreach ($exception in (Get-Collection $managed['exceptionsList'] 'exceptions')) {
                $applies = $false
                foreach ($scope in (Get-Collection $exception 'scopes')) {
                    # Empty group/rule scopes inherit the entire containing managed scope.
                    if ($scope['ruleSetType'] -cne $RuleSetType) { continue }
                    $groups = Get-Collection $scope 'ruleGroupScopes'
                    if (-not $groups.Count) { $applies = $true }
                    foreach ($group in $groups) {
                        if ($group['ruleGroupName'] -cne $GroupName) { continue }
                        $rules = Get-Collection $group 'ruleScopes'
                        if (-not $rules.Count -or @($rules | Where-Object { $_['ruleId'] -ceq $RuleId }).Count) {
                            $applies = $true
                        }
                    }
                }
                if ($applies) {
                    $predicate = Copy-JsonValue $exception
                    $null = $predicate.Remove('scopes')
                    $predicate
                }
            }
        }
    )
    return ,$result
}

function Get-DrsEffectiveRules {
    <#
    .SYNOPSIS
    Resolves version-native rule defaults, explicit overrides and applicable scopes.
    .DESCRIPTION
    Requires documented state/action defaults and never borrows another version's baseline.
    #>
    param([System.Collections.IDictionary] $Configuration, [string] $Version,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet', [switch] $IncludeAbsent)
    $result = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $set = Get-DrsSet $Configuration $RuleSetType
    $absent = $null -eq $set
    if ($absent) {
        if (-not $IncludeAbsent) { return ,$result }
        $set = @{ ruleSetType = $RuleSetType; ruleSetVersion = $Version; ruleGroupOverrides = @() }
    }
    $settings = if ($Configuration['properties'].Contains('policySettings')) { $Configuration['properties']['policySettings'] } else { @{} }
    $policyState = $settings['enabledState'] ?? '---'
    $policyMode = $settings['mode'] ?? '---'
    $setAction = $set['ruleSetAction'] ?? $(if ($RuleSetType -eq 'Microsoft_DefaultRuleSet') { 'Block' } else { '---' })
    $key = "$RuleSetType/$Version"
    $index = Get-CatalogIndex $key
    $groups = Get-IdentityMap (Get-Collection $set 'ruleGroupOverrides') 'ruleGroupName' "$key/overrides"
    foreach ($groupName in $index.Groups.Keys) {
        $group = if ($groups.ContainsKey($groupName)) { $groups[$groupName] } else { $null }
        $overrides = if ($null -ne $group) { Get-Collection $group 'rules' } else { ,@() }
        $ruleMap = Get-IdentityMap $overrides 'ruleId' "$key/$groupName/overrides"
        foreach ($id in $index.Rules[$groupName].Keys) {
            if ($result.ContainsKey($id)) { throw "Ambiguous native DRS identity $key/$id." }
            $definition = $index.Rules[$groupName][$id]
            if (-not $definition.Contains('defaultState') -or $definition['defaultState'] -cnotin 'Enabled', 'Disabled' -or
                -not $definition.Contains('defaultAction') -or [string]::IsNullOrWhiteSpace($definition['defaultAction'])) {
                throw "No usable state/action defaults for $key/$groupName/$id."
            }
            $rule = if ($ruleMap.ContainsKey($id)) { $ruleMap[$id] } else { $null }
            $state = if ($absent) { 'Not present' }
                elseif ($null -ne $rule -and $rule.Contains('enabledState')) { [string] $rule['enabledState'] }
                else { [string] $definition['defaultState'] }
            $action = if ($null -ne $rule -and $rule.Contains('action')) { [string] $rule['action'] }
                else { [string] $definition['defaultAction'] }
            $exclusions = Get-Collection $set 'exclusions'
            if ($null -ne $group) { $exclusions += (Get-Collection $group 'exclusions') }
            $ruleExclusions = if ($null -ne $rule) { Get-Collection $rule 'exclusions' } else { ,@() }
            $exclusions += $ruleExclusions
            $exceptions = Get-DrsApplicableExceptions $Configuration $groupName $id $RuleSetType
            $sensitivity = if ($null -ne $rule -and $rule.Contains('sensitivity')) { $rule['sensitivity'] }
                else { $definition['defaultSensitivity'] }
            $result.Add($id, [pscustomobject]@{
                # Retain native defaults alongside effective tuning for version-aware comparison.
                RuleId = $id; RuleGroupName = $groupName; RuleSetType = $RuleSetType; RuleSetVersion = $Version
                RuleDescription = $definition['description']
                DefaultState = [string] $definition['defaultState']
                DefaultAction = [string] $definition['defaultAction']
                DefaultSensitivity = $definition['defaultSensitivity']
                ParanoiaLevel = if ($definition.Contains('paranoiaLevel')) { $definition['paranoiaLevel'] } else { $null }
                State = $state; Action = $action; Override = $rule
                PolicyState = $policyState; PolicyMode = $policyMode; RuleSetAction = $setAction
                Inspecting = $state -ceq 'Enabled' -and $policyState -cne 'Disabled'
                StateTuned = -not $absent -and $state -cne $definition['defaultState']
                ActionTuned = -not $absent -and -not (Test-DrsActionEqual $action $definition['defaultAction'] $RuleSetType)
                SensitivityTuned = -not $absent -and $definition.Contains('defaultSensitivity') -and $sensitivity -cne $definition['defaultSensitivity']
                RuleExclusions = $ruleExclusions; Exclusions = $exclusions; Exceptions = $exceptions
                ExplicitState = if ($null -ne $rule -and $rule.Contains('enabledState')) { [string] $rule['enabledState'] }
                    elseif ($null -ne $rule) { 'Override; state omitted' } else { 'Absent' }
                ExplicitAction = if ($null -ne $rule -and $rule.Contains('action')) { [string] $rule['action'] } else { 'Absent' }
                Sensitivity = $sensitivity
            })
        }
    }
    return ,$result
}

function New-DrsRiskRow {
    <#
    .SYNOPSIS
    Creates family-native, same-ID baseline and tuning review metadata.
    .DESCRIPTION
    Keeps original source and target definitions separate, including explicit absence states.
    #>
    param([string] $RuleId, [AllowNull()] $SourceRule, [AllowNull()] $TargetRule,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet',
        [string] $SourceVersion = $sourceOriginalDrsVersion, [string] $TargetVersion = (Get-DrsTargetVersion))
    [pscustomobject]@{
        RuleSetType = $RuleSetType
        # Absence is explicit; another version's defaults must never fill a missing source rule.
        SourceRuleDescription = if ($null -ne $SourceRule) { $SourceRule.RuleDescription } else { '' }
        TargetRuleDescription = if ($null -ne $TargetRule) { $TargetRule.RuleDescription } else { '' }
        RuleId = $RuleId
        RuleGroupName = if ($null -ne $TargetRule) { $TargetRule.RuleGroupName }
            elseif ($null -ne $SourceRule) { $SourceRule.RuleGroupName } else { '(rule-set scope)' }
        SupersededByRuleId = if ($RuleSetType -eq 'Microsoft_DefaultRuleSet' -and $supersededRuleIds.ContainsKey($RuleId)) { $supersededRuleIds[$RuleId] } else { $null }
        SupersedesRuleId = if ($RuleSetType -eq 'Microsoft_DefaultRuleSet') {
            @($supersededRuleIds.Keys | Where-Object { $supersededRuleIds[$_] -ceq $RuleId }) | Select-Object -First 1
        } else { $null }
        TargetOverridesDefaults = $hasMasterPolicy -and $null -ne $TargetRule -and ($TargetRule.StateTuned -or $TargetRule.ActionTuned -or
            ($TargetRule.PSObject.Properties['SensitivityTuned'] -and $TargetRule.SensitivityTuned))
        SourceOverridesDefaults = $null -ne $SourceRule -and ($SourceRule.StateTuned -or $SourceRule.ActionTuned -or
            ($SourceRule.PSObject.Properties['SensitivityTuned'] -and $SourceRule.SensitivityTuned))
        SourceRuleSetVersion = $SourceVersion
        TargetRuleSetVersion = $TargetVersion
        SourceParanoiaLevel = if ($null -ne $SourceRule) { $SourceRule.ParanoiaLevel } else { $null }
        TargetParanoiaLevel = if ($null -ne $TargetRule) { $TargetRule.ParanoiaLevel } else { $null }
        SourceDefaultState = if ($null -ne $SourceRule) { $SourceRule.DefaultState } else { 'Not present' }
        SourceDefaultAction = if ($null -ne $SourceRule) { $SourceRule.DefaultAction } else { 'Not present' }
        SourceDefaultSensitivity = if ($null -ne $SourceRule) { $SourceRule.DefaultSensitivity } else { $null }
        SourceSensitivity = if ($null -ne $SourceRule) { $SourceRule.Sensitivity } else { $null }
        TargetDefaultSensitivity = if ($null -ne $TargetRule) { $TargetRule.DefaultSensitivity } else { $null }
        SourceExplicitState = if ($null -ne $SourceRule) { $SourceRule.ExplicitState } else { 'Absent' }
        SourceEffectiveState = if ($null -ne $SourceRule) { $SourceRule.State } else { 'Not present' }
        SourceEffectiveAction = if ($null -ne $SourceRule) { $SourceRule.Action } else { 'Not present' }
        SourcePolicyState = if ($null -ne $SourceRule) { $SourceRule.PolicyState } else { 'Not present' }
        SourcePolicyMode = if ($null -ne $SourceRule) { $SourceRule.PolicyMode } else { 'Not present' }
        SourceRuleSetAction = if ($null -ne $SourceRule) { $SourceRule.RuleSetAction } else { 'Not present' }
        SourceStateTuned = $null -ne $SourceRule -and $SourceRule.StateTuned
        SourceActionTuned = $null -ne $SourceRule -and $SourceRule.ActionTuned
        SourceExclusionCount = if ($null -ne $SourceRule) { $SourceRule.Exclusions.Count } else { 0 }
        SourceExceptionCount = if ($null -ne $SourceRule) { $SourceRule.Exceptions.Count } else { 0 }
        ExclusionScopes = @(
            if (($null -ne $SourceRule -and $SourceRule.RuleExclusions.Count) -or
                ($null -ne $TargetRule -and $TargetRule.RuleExclusions.Count)) {
                $groupName = if ($null -ne $SourceRule) { $SourceRule.RuleGroupName } else { $TargetRule.RuleGroupName }
                "Individual rule: $groupName/$RuleId"
            }
        )
        TargetDefaultState = if ($null -ne $TargetRule) { $TargetRule.DefaultState } else { 'Not present' }
        TargetDefaultAction = if ($null -ne $TargetRule) { $TargetRule.DefaultAction } else { 'Not present' }
        TargetExplicitState = if ($null -ne $TargetRule) { $TargetRule.ExplicitState } else { 'Absent' }
        TargetEffectiveState = if ($null -ne $TargetRule) { $TargetRule.State } else { 'Not present' }
        TargetEffectiveAction = if ($null -ne $TargetRule) { $TargetRule.Action } else { 'Not present' }
        TargetSensitivity = if ($null -ne $TargetRule) { $TargetRule.Sensitivity } else { $null }
        TargetPolicyState = if ($null -ne $TargetRule) { $TargetRule.PolicyState } else { 'Not present' }
        TargetPolicyMode = if ($null -ne $TargetRule) { $TargetRule.PolicyMode } else { 'Not present' }
        TargetRuleSetAction = if ($null -ne $TargetRule) { $TargetRule.RuleSetAction } else { 'Not present' }
        RiskKinds = @(); Reason = ''; Treatment = 'Silent'; BaselineOnly = $false
        CandidateOperations = @()
        ScopeKind = ''
    }
}

function Get-DrsRiskSummary {
    <#
    .SYNOPSIS
    Copies review metadata without retaining candidate operations or private scope values.
    .DESCRIPTION
    Exposes native defaults and effective behavior for structured report consumers.
    #>
    param([object[]] $Rows)
    return ,@($Rows | Select-Object RuleSetType, SourceRuleDescription, TargetRuleDescription, RuleId, RuleGroupName, SupersededByRuleId, SupersedesRuleId, TargetOverridesDefaults, SourceOverridesDefaults, SourceRuleSetVersion, TargetRuleSetVersion,
        SourceParanoiaLevel, TargetParanoiaLevel,
        SourceDefaultState, SourceDefaultAction, SourceDefaultSensitivity, SourceSensitivity, TargetDefaultSensitivity,
        SourceExplicitState, SourceEffectiveState, SourceEffectiveAction,
        SourcePolicyState, SourcePolicyMode, SourceRuleSetAction,
        SourceStateTuned, SourceActionTuned, SourceExclusionCount, SourceExceptionCount, ExclusionScopes,
        TargetDefaultState, TargetDefaultAction,
        TargetExplicitState, TargetEffectiveState, TargetEffectiveAction, TargetSensitivity,
        TargetPolicyState, TargetPolicyMode, TargetRuleSetAction,
        RiskKinds, Reason, Treatment, BaselineOnly, ScopeKind)
}

function Format-DrsParanoiaLevel {
    <#
    .SYNOPSIS
    Formats documented paranoia levels without guessing missing native metadata.
    .DESCRIPTION
    Labels missing metadata explicitly and rejects unsupported paranoia-level values.
    #>
    param($Level)
    if ($null -eq $Level) { return 'Not documented' }
    if ($Level -notin 1, 2) { throw "Unsupported DRS paranoia level '$Level'." }
    "PL$Level"
}

function New-DrsRuleOperation {
    <#
    .SYNOPSIS
    Builds a native same-ID source operation containing only changed rule settings.
    .DESCRIPTION
    Copies reviewed state, action and sensitivity fields while preserving unrelated tuning.
    #>
    param($SourceRule, $TargetRule, [string[]] $Risks, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $value = @{ ruleId = $TargetRule.RuleId }
    if ($Risks -contains 'ProtectionLoss' -or $Risks -contains 'SourceDisableChanged' -or $Risks -contains 'RuleStateChanged') {
        $value['enabledState'] = $SourceRule.State
    }
    if ($Risks -contains 'ActionTuningChanged') { $value['action'] = Get-DrsComparableAction $SourceRule.Action $RuleSetType }
    elseif ($Risks -contains 'EnforcementReduced') {
        $value['action'] = if ($SourceRule.ActionTuned) { Get-DrsComparableAction $SourceRule.Action $RuleSetType } else { $TargetRule.DefaultAction }
    }
    if ($Risks -contains 'SensitivityChanged') { $value['sensitivity'] = $SourceRule.Sensitivity }
    return @{ Kind = 'Rule'; GroupName = $TargetRule.RuleGroupName; RuleId = $TargetRule.RuleId
        RuleSetVersion = $TargetRule.RuleSetVersion; Value = $value }
}

function Get-DrsRuleRisks {
    <#
    .SYNOPSIS
    Identifies effective state, action, exclusion and sensitivity changes for one rule.
    .DESCRIPTION
    Separates protection loss from intentional source tuning and keeps non-DRS actions distinct.
    #>
    param($SourceRule, $TargetRule, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $risks = [System.Collections.Generic.List[string]]::new()
    if ($SourceRule.Inspecting -and ($TargetRule.State -ceq 'Disabled' -or
        ($RuleSetType -ne 'Microsoft_DefaultRuleSet' -and $TargetRule.State -ceq 'Not present'))) { $risks.Add('ProtectionLoss') }
    if ($SourceRule.StateTuned -and $SourceRule.State -ceq 'Disabled' -and $TargetRule.State -ceq 'Enabled') {
        $risks.Add('SourceDisableChanged')
    }
    if ($SourceRule.State -cne $TargetRule.State -and
        -not @($risks | Where-Object { $_ -in 'ProtectionLoss','SourceDisableChanged' }).Count) {
        $risks.Add('RuleStateChanged')
    }
    if (-not (Test-DrsActionEqual $SourceRule.Action $TargetRule.Action $RuleSetType)) { $risks.Add('ActionTuningChanged') }
    if ($SourceRule.State -ceq 'Enabled' -or $TargetRule.State -ceq 'Enabled') {
        if ($SourceRule.State -ceq 'Enabled' -and $TargetRule.State -ceq 'Enabled' -and
            $SourceRule.Action -in 'Block', 'AnomalyScoring' -and $TargetRule.Action -in 'Log', 'Allow') {
            $risks.Add('EnforcementReduced')
        }
        if ($SourceRule.RuleExclusions.Count -and
            -not (Test-JsonEqual $SourceRule.RuleExclusions $TargetRule.RuleExclusions 'exclusions')) {
            $risks.Add('RuleExclusionsChanged')
        }
    }
    if ($null -ne $SourceRule.Sensitivity -and $SourceRule.Sensitivity -cne $TargetRule.Sensitivity -and
        ($RuleSetType -ne 'Microsoft_DefaultRuleSet' -or $SourceRule.State -ceq 'Enabled' -or $TargetRule.State -ceq 'Enabled')) {
        $risks.Add('SensitivityChanged')
    }
    return ,$risks.ToArray()
}

function Get-DrsSourceBaselineIssues {
    <#
    .SYNOPSIS
    Finds source override and exception identities missing from their original baseline.
    .DESCRIPTION
    Reports unresolved original-version identities instead of substituting target defaults.
    #>
    param([System.Collections.IDictionary] $Configuration, $NativeRules,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $set = Get-DrsSet $Configuration $RuleSetType
    if ($null -eq $set) { return ,@() }
    $key = "$RuleSetType/$(Get-ManagedSourceVersion $Configuration $RuleSetType)"
    $index = Get-CatalogIndex $key
    return ,@(
        foreach ($group in (Get-Collection $set 'ruleGroupOverrides')) {
            # Unknown original identities make source tuning unresolvable, not safely discardable.
            $name = [string] $group['ruleGroupName']
            if (-not $index.Groups.ContainsKey($name)) {
                [pscustomobject]@{ Group = $name; RuleId = 'All'; State = 'Unknown'; Message = "Source group $name has no original-version baseline. Update the embedded catalog before assessing its tuning." }
            }
            foreach ($rule in (Get-Collection $group 'rules')) {
                $id = [string] $rule['ruleId']
                if (-not $NativeRules.ContainsKey($id) -or $NativeRules[$id].RuleGroupName -cne $name) {
                    [pscustomobject]@{
                        Group = $name; RuleId = $id
                        State = if ($rule.Contains('enabledState')) { $rule['enabledState'] } else { 'Unknown' }
                        Message = "Source rule $name/$id has no original-version baseline. Do not substitute target defaults; update the embedded catalog before assessing its tuning."
                    }
                }
            }
        }
        $managed = $Configuration['properties']['managedRules']
        if ($managed.Contains('exceptionsList')) {
            foreach ($exception in (Get-Collection $managed['exceptionsList'] 'exceptions')) {
                foreach ($scope in (Get-Collection $exception 'scopes')) {
                    if ($scope['ruleSetType'] -cne $RuleSetType) { continue }
                    foreach ($group in (Get-Collection $scope 'ruleGroupScopes')) {
                        # Validate exception rule membership against the original source family.
                        $name = [string] $group['ruleGroupName']
                        if (-not $index.Groups.ContainsKey($name)) {
                            [pscustomobject]@{
                                Group = $name; RuleId = 'All'; State = 'Unknown'
                                Message = "Source exception group $name has no original-version baseline. Correct its scope before assessing its tuning."
                            }
                        }
                        foreach ($rule in (Get-Collection $group 'ruleScopes')) {
                            $id = [string] $rule['ruleId']
                            if (-not $NativeRules.ContainsKey($id) -or $NativeRules[$id].RuleGroupName -cne $name) {
                                [pscustomobject]@{
                                    Group = $name; RuleId = $id; State = 'Unknown'
                                    Message = "Source exception rule $name/$id has no original-version baseline. Do not substitute target membership; correct its scope before assessing its tuning."
                                }
                            }
                        }
                    }
                }
            }
        }
    )
}

function Get-DrsRiskPlan {
    <#
    .SYNOPSIS
    Plans version-aware rule and replacement reviews without cross-ID setting copies.
    .DESCRIPTION
    Compares native effective rules and creates only compatible same-ID source operations.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    if ($null -eq (Get-DrsSet $SourceConfiguration $RuleSetType) -and
        $null -eq (Get-DrsSet $target $RuleSetType)) { return ,@() }
    $sourceVersion = Get-ManagedSourceVersion $SourceConfiguration $RuleSetType
    $targetVersion = Get-ManagedComparisonVersion $SourceConfiguration $RuleSetType
    $sourceRules = Get-DrsEffectiveRules $SourceConfiguration $sourceVersion $RuleSetType
    $targetRules = Get-DrsEffectiveRules $target $targetVersion $RuleSetType -IncludeAbsent
    $rows = [System.Collections.Generic.List[object]]::new()
    $ids = @(@($sourceRules.Keys) + @($targetRules.Keys) | Sort-Object -Unique -CaseSensitive)
    foreach ($id in $ids) {
        $left = if ($sourceRules.ContainsKey($id)) { $sourceRules[$id] } else { $null }
        $right = if ($targetRules.ContainsKey($id)) { $targetRules[$id] } else { $null }
        $row = New-DrsRiskRow $id $left $right $RuleSetType $sourceVersion $targetVersion
        $risks = [System.Collections.Generic.List[string]]::new()
        $manual = $false
        if ($null -ne $left) {
            # Removed inspecting signatures need a review, never an invented replacement operation.
            if ($null -eq $right) {
                if ($left.Inspecting -or $left.StateTuned -or $left.Exclusions.Count -or $left.Exceptions.Count) {
                    $risks.Add('RemovedSignature')
                    $manual = $true
                }
            }
            else {
                foreach ($risk in (Get-DrsRuleRisks $left $right $RuleSetType)) { $risks.Add($risk) }
                if ($RuleSetType -ne 'Microsoft_DefaultRuleSet' -and $sourceVersion -cne $targetVersion -and
                    $left.RuleDescription -cne $right.RuleDescription) {
                    $manual = -not @($risks | Where-Object { $_ -in 'ProtectionLoss','SourceDisableChanged','RuleStateChanged','ActionTuningChanged','SensitivityChanged' }).Count
                    $risks.Add('RuleDefinitionChanged')
                }
            }
        }
        elseif ($null -ne $right -and $right.State -ceq 'Not present') {
            # A prospective catalog entry absent from both policies has no behavior to review.
        }
        elseif ($null -ne $right -and $RuleSetType -ne 'Microsoft_DefaultRuleSet') {
            $risks.Add('TargetOnlyRule')
            $row.CandidateOperations = @(@{
                Kind = 'Rule'; GroupName = $right.RuleGroupName; RuleId = $id
                Value = @{ ruleId = $id; enabledState = 'Disabled' }
            })
        }
        elseif ($null -ne $right -and (
            ($row.SupersedesRuleId -and (
                $sourceRules.ContainsKey($row.SupersedesRuleId) -or
                ($targetRules.ContainsKey($row.SupersedesRuleId) -and $hasMasterPolicy -and
                    ($targetRules[$row.SupersedesRuleId].StateTuned -or $targetRules[$row.SupersedesRuleId].ActionTuned)))) -or
            (($row.SupersededByRuleId -or $row.SupersedesRuleId) -and $hasMasterPolicy -and
                ($right.StateTuned -or $right.ActionTuned)))) {
            $risks.Add($(if ($row.SupersedesRuleId) { 'TargetOnlyReplacement' } else { 'TargetOnlyRelatedRule' }))
            $row.CandidateOperations = @(@{
                Kind = 'Rule'; GroupName = $right.RuleGroupName; RuleId = $id
                Value = @{ ruleId = $id; enabledState = 'Disabled' }
            })
        }
        $row.RiskKinds = $risks.ToArray()
        $reviewRisks = @($risks | Where-Object { $_ -ne 'RuleExclusionsChanged' })
        if ($risks.Count -and -not $reviewRisks.Count) { $row.Treatment = 'ExclusionReview' }
        if ($reviewRisks.Count -and $row.Treatment -ne 'BlockingError') {
            # Only same-ID comparisons can produce an automatic source-copy operation.
            $row.Treatment = 'Decision'
            $row.Reason = "Migration risk: $($row.RiskKinds -join ', ')."
            if ($manual) {
                $row.Reason += ' Review the target configuration explicitly; source settings are not remapped across rule IDs.'
            }
            elseif ($null -ne $left -and $null -ne $right) {
                $row.CandidateOperations = @((New-DrsRuleOperation $left $right $row.RiskKinds $RuleSetType))
            }
            $row.BaselineOnly = $row.RiskKinds -contains 'ProtectionLoss' -and
                -not @($row.RiskKinds | Where-Object { $_ -notin 'ProtectionLoss','ActionTuningChanged' }).Count -and
                ($null -eq $left -or (-not $left.StateTuned -and -not $left.ActionTuned -and
                    -not $left.RuleExclusions.Count -and $null -eq $left.Sensitivity))
        }
        $rows.Add($row)
    }
    foreach ($issue in (Get-DrsSourceBaselineIssues $SourceConfiguration $sourceRules $RuleSetType)) {
        $row = New-DrsRiskRow $issue.RuleId $null $null $RuleSetType $sourceVersion $targetVersion
        $row.RuleGroupName = $issue.Group; $row.SourceDefaultState = 'Unknown'
        $row.SourceExplicitState = $issue.State; $row.SourceEffectiveState = $issue.State
        $row.Treatment = 'BlockingError'; $row.RiskKinds = @('SourceBaselineUnavailable'); $row.Reason = $issue.Message
        $rows.Add($row)
    }
    return ,$rows.ToArray()
}

function Add-DrsRiskDecision {
    <#
    .SYNOPSIS
    Records a managed review and its safe same-family operations with readable metadata.
    .DESCRIPTION
    Uses native analysis descriptions for Bot/HTTP rules rather than the carryover
    source configuration, whose versions have already been aligned with the target.
    Identifies version-specific absence and same-ID definition changes explicitly.
    #>
    param([object[]] $Rows, [object[]] $Operations = @(), [string] $Scope = '',
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    if (-not $Rows.Count) { throw 'A DRS risk decision requires analysis rows.' }
    $path = "properties.managedRules.managedRuleSets[$RuleSetType]"
    Add-Decision $target['properties']['managedRules'] 'managedRuleSets' $path `
        $true $null ($Operations.Count -gt 0) $Operations -DecisionKind DrsRisk
    $decision = $decisions[$decisions.Count - 1]
    $decision.RiskContext = Get-DrsRiskSummary $Rows
    $decision.Scope = if ($Scope) { $Scope }
        elseif ($Rows[0].RiskKinds -contains 'SourceDisableChanged') { 'SourceDisableChanged' }
        else { $Rows[0].RiskKinds -join ', ' }
    $decision.RuleId = ($Rows.RuleId -join ', ')
    $decision.RuleGroupName = if ($Rows.Count -eq 1) { $Rows[0].RuleGroupName } else { '(rule-set scope)' }
    $decision.RuleDescription = if ($Rows.Count -eq 1) {
        $displayPath = if ($Rows[0].RuleId -eq 'All') {
            if ($Rows[0].RuleGroupName -eq '(rule-set scope)') { $path }
            else { "$path.ruleGroupOverrides[$($Rows[0].RuleGroupName)]" }
        } else { "$path.ruleGroupOverrides[$($Rows[0].RuleGroupName)].rules[$($Rows[0].RuleId)]" }
        (Get-DecisionDisplay $displayPath).RuleDescription
    } else { "$($Rows.Count) related default-driven protection losses" }
    # Native analysis retains both original definitions even after carryover versions are aligned.
    if ($Rows.Count -eq 1 -and $RuleSetType -ne 'Microsoft_DefaultRuleSet' -and $Rows[0].RuleId -ne 'All') {
        $row = $Rows[0]
        $sourceDescription = $row.SourceRuleDescription
        $targetDescription = $row.TargetRuleDescription
        if ($sourceDescription -and $targetDescription -and $sourceDescription -cne $targetDescription) {
            $decision.RuleDescription = "$sourceDescription (source v$($row.SourceRuleSetVersion)) -> $targetDescription (target v$($row.TargetRuleSetVersion))"
        }
        elseif ($sourceDescription -and -not $targetDescription) {
            $decision.RuleDescription = "$sourceDescription (absent from target v$($row.TargetRuleSetVersion))"
        }
        elseif ($targetDescription -and -not $sourceDescription) {
            $absence = if ($row.SourceRuleSetVersion) { "absent from source v$($row.SourceRuleSetVersion)" }
                else { 'rule set absent from source' }
            $decision.RuleDescription = "$targetDescription ($absence)"
        }
        elseif ($sourceDescription -or $targetDescription) {
            $decision.RuleDescription = $sourceDescription ? $sourceDescription : $targetDescription
        }
    }
    $decision.Operation = 'Review'
}

function Add-DrsScopeDecisions {
    <#
    .SYNOPSIS
    Reviews configured rule-set action changes when either policy has active native rules.
    .DESCRIPTION
    Treats an omitted Bot/HTTP scope action as --- while retaining DRS's blocking default.
    #>
    param([System.Collections.IDictionary] $SourceConfiguration, [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $left = Get-DrsSet $SourceConfiguration $RuleSetType
    $right = Get-DrsSet $target $RuleSetType
    if ($null -eq $left) { return }
    $sourceVersion = Get-ManagedSourceVersion $SourceConfiguration $RuleSetType
    $targetVersion = Get-ManagedComparisonVersion $SourceConfiguration $RuleSetType
    $sourceRules = Get-DrsEffectiveRules $SourceConfiguration $sourceVersion $RuleSetType
    $targetRules = Get-DrsEffectiveRules $target $targetVersion $RuleSetType -IncludeAbsent
    $activeScope = @($sourceRules.Values | Where-Object Inspecting).Count -gt 0 -or
        @($targetRules.Values | Where-Object Inspecting).Count -gt 0
    if (-not $activeScope) { return }
    foreach ($key in 'ruleSetAction') {
        # Ruleset enforcement is distinct from the anomaly-scoring action on an individual DRS rule.
        $defaultAction = if ($RuleSetType -eq 'Microsoft_DefaultRuleSet') { 'Block' } else { '---' }
        $sourceValue = $left[$key] ?? $defaultAction
        $targetValue = if ($null -ne $right) { $right[$key] ?? $defaultAction } else { $defaultAction }
        if (Test-JsonEqual $sourceValue $targetValue $key) { continue }
        $row = New-DrsRiskRow 'All' $null $null $RuleSetType $sourceVersion $targetVersion
        $row.RuleGroupName = '(rule-set scope)'
        $row.Treatment = 'Decision'; $row.RiskKinds = @('RuleSetTuningChanged')
        $row.Reason = "Effective rule-set $key differs from source; review the complete scope."
        $row.ScopeKind = 'RuleSetAction'
        $row.SourceDefaultAction = $defaultAction; $row.TargetDefaultAction = $defaultAction
        $row.SourceEffectiveAction = $sourceValue; $row.TargetEffectiveAction = $targetValue
        $row.TargetOverridesDefaults = $RuleSetType -eq 'Microsoft_DefaultRuleSet' -and
            $hasMasterPolicy -and $targetValue -cne $row.TargetDefaultAction
        $row.SourceOverridesDefaults = $RuleSetType -eq 'Microsoft_DefaultRuleSet' -and $sourceValue -cne $row.SourceDefaultAction
        $value = if ($RuleSetType -eq 'Microsoft_DefaultRuleSet') { $sourceValue } else { $left[$key] }
        Add-DrsRiskDecision @($row) @(@{ Kind = 'RuleSet'; Key = $key; Value = Copy-JsonValue $value
            Remove = $RuleSetType -ne 'Microsoft_DefaultRuleSet' -and -not $left.Contains($key)
            RuleSetVersion = $targetVersion }) "Rule-set $key" $RuleSetType
    }
}

function Set-DrsRiskConfiguration {
    <#
    .SYNOPSIS
    Applies reviewed native-family fields while preserving siblings and other managed sets.
    .DESCRIPTION
    Lazily creates absent families with disabled siblings and changes only selected fields.
    #>
    param([System.Collections.IDictionary] $Configuration, [object[]] $Operations,
        [string] $RuleSetType = 'Microsoft_DefaultRuleSet')
    $set = Get-DrsSet $Configuration $RuleSetType
    if ($null -eq $set) {
        if (-not $Operations.Count -or -not $Operations[0].Contains('RuleSetVersion')) {
            throw "Cannot apply rule operations to absent $RuleSetType without a native version."
        }
        $set = New-DisabledManagedRuleSet $RuleSetType $Operations[0].RuleSetVersion
        $managed = $Configuration['properties']['managedRules']
        $sets = Get-Collection $managed 'managedRuleSets'
        $managed['managedRuleSets'] = @($sets) + @($set)
    }
    foreach ($operation in $Operations) {
        if ($operation.Kind -eq 'RuleSet') {
            if ($operation.Contains('Remove') -and $operation.Remove) { $null = $set.Remove($operation.Key) }
            else { $set[$operation.Key] = Copy-JsonValue $operation.Value }
            continue
        }
        $groups = Get-Collection $set 'ruleGroupOverrides'
        $groupEntries = @($groups | Where-Object { $_['ruleGroupName'] -ceq $operation.GroupName })
        if ($groupEntries.Count -gt 1) { throw "Duplicate target group $($operation.GroupName)." }
        if ($groupEntries.Count) { $group = $groupEntries[0] }
        else {
            $group = @{ ruleGroupName = $operation.GroupName }
            $set['ruleGroupOverrides'] = @($groups) + @($group)
        }
        if ($operation.Kind -eq 'Group') { $group[$operation.Key] = Copy-JsonValue $operation.Value; continue }
        if ($operation.Kind -ne 'Rule') { throw "Unknown DRS risk operation $($operation.Kind)." }
        $rules = Get-Collection $group 'rules'
        # Apply only the reviewed rule fields; earlier selections and sibling rules survive.
        $ruleEntries = @($rules | Where-Object { $_['ruleId'] -ceq $operation.RuleId })
        if ($ruleEntries.Count -gt 1) { throw "Duplicate target rule $($operation.RuleId)." }
        if ($ruleEntries.Count) {
            foreach ($key in $operation.Value.Keys) { $ruleEntries[0][$key] = Copy-JsonValue $operation.Value[$key] }
        }
        else { $group['rules'] = @($rules) + @((Copy-JsonValue $operation.Value)) }
    }
}

function Get-CandidateCompatibilityIssues {
    <#
    .SYNOPSIS
    Checks only the candidate's managed-rule catalog compatibility.
    .DESCRIPTION
    Builds an isolated fragment so unrelated invalid source customizations do not
    contaminate valid rows. Exception scopes use selected target versions, allowing
    absent families to be introduced by separate choices. Their actual selected
    combination is validated at the end.
    Version-removed Bot/HTTP rules identify the incompatible target version explicitly.
    .PARAMETER Decision
    Decision whose source candidate is under review.
    .OUTPUTS
    One array of catalog-compatibility diagnostics.
    #>
    param($Decision)
    if ($Decision.DecisionKind -eq 'ManagedException') {
        if (-not $Decision.SourcePresent) { return ,@() }
        $fragment = Copy-JsonValue $target
        $managed = $fragment['properties']['managedRules']
        # An absent family may be introduced by separate rule choices; validate the
        # prospective scopes here and their actual selected combination before output.
        $sets = Get-Collection $managed 'managedRuleSets'
        $types = @($sets | ForEach-Object { $_['ruleSetType'] })
        $managed['managedRuleSets'] = @($sets) + @(
            foreach ($set in (Get-Collection $source['properties']['managedRules'] 'managedRuleSets')) {
                if ($set['ruleSetType'] -cnotin $types) {
                    @{ ruleSetType = $set['ruleSetType']; ruleSetVersion = $set['ruleSetVersion'] }
                }
            }
        )
        $managed['exceptionsList'] = @{ exceptions = @((Copy-JsonValue $Decision.SourceValue)) }
        return ,@(Get-CatalogIssues $fragment | Where-Object { $_.StartsWith('Exception', [StringComparison]::Ordinal) })
    }
    if ($Decision.DecisionKind -eq 'DrsExclusion') {
        # Exclusion selectors can be retained only when their exact target scope still exists.
        if (-not $Decision.SourcePresent) { return ,@() }
        $context = $Decision.ExclusionContext
        $version = (Get-DrsTargetVersion) ?? (Get-LatestManagedRuleSetVersion 'Microsoft_DefaultRuleSet')
        $index = Get-CatalogIndex "Microsoft_DefaultRuleSet/$version"
        if ($context.GroupName -and -not $index.Groups.ContainsKey($context.GroupName)) {
            return ,@("Exclusion group $($context.GroupName) is not in the target DRS $version catalog.")
        }
        if ($context.RuleId -and -not $index.Rules[$context.GroupName].ContainsKey($context.RuleId)) {
            return ,@("Exclusion rule $($context.GroupName)/$($context.RuleId) is not in the target DRS $version catalog; its exclusion cannot be moved to another rule.")
        }
        return ,@()
    }
    if ($Decision.DecisionKind -eq 'DrsRisk') {
        if (-not $Decision.SourcePresent) {
            if ($Decision.RuleSetType -ne 'Microsoft_DefaultRuleSet' -and $Decision.RiskContext.Count -eq 1) {
                $row = $Decision.RiskContext[0]
                if ($row.SourceRuleDescription -and -not $row.TargetRuleDescription -and $row.RuleId -ne 'All') {
                    return ,@("Rule $($row.RuleGroupName)/$($row.RuleId) exists in $($Decision.RuleSetType) v$($row.SourceRuleSetVersion), but not in target v$($row.TargetRuleSetVersion). KeepSource cannot copy it into that version. Use a master with a version containing this rule and rerun, or accept its absence with KeepTarget.")
                }
            }
            return ,@('No safe source-copy operation exists. Accept the target risk with KeepTarget, or update the template and rerun; settings cannot be remapped across rule IDs.')
        }
        $candidate = Copy-JsonValue $target
        Set-DrsRiskConfiguration $candidate $Decision.SourceValue $Decision.RuleSetType
        # Attribute only newly introduced errors to this candidate, not existing target issues.
        $baselineBlocked = Get-DrsBlockingIssues -Configuration $target
        $baselineIssues = @(Get-CatalogIssues $target) + @($baselineBlocked | ForEach-Object { $_.Message })
        $issues = @(Get-CatalogIssues $candidate)
        $blocked = Get-DrsBlockingIssues -Configuration $candidate
        $issues += @($blocked | ForEach-Object { $_.Message })
        return ,@($issues | Where-Object { $_ -cnotin $baselineIssues })
    }
    if (-not $Decision.SourcePresent) { return ,@() }
    if (-not $Decision.RuleSetType) { return ,@() }
    $sets = @($script:target['properties']['managedRules']['managedRuleSets'] | Where-Object {
        $_['ruleSetType'] -ceq $Decision.RuleSetType
    })
    if ($Decision.Identity -eq 'ruleSetType') {
        $set = Copy-JsonValue $Decision.SourceValue
    }
    elseif ($sets.Count -ne 1) { throw "Expected one master rule set for $($Decision.RuleSetType)." }
    else { $set = Copy-JsonValue $sets[0] }
    # Build just the candidate's set/group/rule scope; unrelated invalid source rules must not block it.
    if ($Decision.Identity -ne 'ruleSetType' -and $Decision.RuleGroupName -eq '(rule-set scope)') {
        $set[$Decision.Key] = Copy-JsonValue $Decision.SourceValue
    }
    elseif ($Decision.Identity -ne 'ruleSetType') {
        # Isolate the proposed group/rule so unrelated source incompatibilities do not block it.
        if ($Decision.Identity -eq 'ruleGroupName') { $group = Copy-JsonValue $Decision.SourceValue }
        else {
            $groups = @($set['ruleGroupOverrides'] | Where-Object { $_['ruleGroupName'] -ceq $Decision.RuleGroupName })
            if ($groups.Count -ne 1) { throw "Expected one master group for $($Decision.RuleGroupName)." }
            $group = Copy-JsonValue $groups[0]
            if ($Decision.Identity -eq 'ruleId') { $group['rules'] = @((Copy-JsonValue $Decision.SourceValue)) }
            else { $group[$Decision.Key] = Copy-JsonValue $Decision.SourceValue }
        }
        $set['ruleGroupOverrides'] = @($group)
    }
    $fragment = [ordered]@{
        properties = [ordered]@{
            managedRules = [ordered]@{ managedRuleSets = @($set) }
        }
    }
    return ,@(Get-CatalogIssues $fragment)
}

function Merge-SourceConfiguration {
    <#
    .SYNOPSIS
    Builds source import candidates while preserving absent master configuration.
    .DESCRIPTION
    Recursively overlays source dictionaries and keyed collections, inheriting missing
    fields and items. Non-keyed arrays stay source lists, except empty DRS exclusions
    retain master lists. Neither input is mutated.
    .PARAMETER Master
    Baseline dictionary.
    .PARAMETER Source
    Explicit source dictionary before inheritance.
    .PARAMETER Path
    Current recursion path controlling keyed matching and DRS exceptions.
    .OUTPUTS
    Detached source candidate dictionary.
    #>
    param(
        [System.Collections.IDictionary] $Master,
        [System.Collections.IDictionary] $Source,
        [string] $Path = ''
    )
    $result = Copy-JsonValue $Source
    $isDrs = @((Get-ManagedRuleSetTypes) | Where-Object {
        $managedPath = "properties.managedRules.managedRuleSets[$_]"
        $Path -eq $managedPath -or $Path.StartsWith("$managedPath.", [StringComparison]::Ordinal)
    }).Count -gt 0
    foreach ($key in $Master.Keys) {
        $itemPath = if ($Path) { "$Path.$key" } else { $key }
        # Absence is inheritance, never a request to delete or a reason to create a decision.
        if (-not $Source.Contains($key)) {
            $result[$key] = Copy-JsonValue $Master[$key]
            continue
        }
        $left = $Master[$key]
        $right = $Source[$key]
        if ($left -is [System.Collections.IDictionary] -and $right -is [System.Collections.IDictionary]) {
            $result[$key] = Merge-SourceConfiguration $left $right $itemPath
            continue
        }
        if ($left -isnot [System.Collections.IList] -or $right -isnot [System.Collections.IList]) { continue }
        # Empty DRS exclusions also mean retention; other unkeyed lists remain complete source lists.
        if ($isDrs -and $key -eq 'exclusions' -and $right.Count -eq 0) {
            $result[$key] = Copy-JsonValue $left
            continue
        }
        $identity = Get-CollectionIdentity $key $Path
        if (-not $identity) { continue }
        $masterMap = Get-IdentityMap $left $identity $itemPath
        $sourceMap = Get-IdentityMap $right $identity $itemPath
        $items = [System.Collections.Generic.List[object]]::new()
        # Merge shared identities recursively while keeping every master-only keyed entry.
        foreach ($item in $left) {
            $id = [string] $item[$identity]
            if ($sourceMap.ContainsKey($id)) {
                $items.Add((Merge-SourceConfiguration $item $sourceMap[$id] "$itemPath[$id]"))
            }
            else { $items.Add((Copy-JsonValue $item)) }
        }
        # Append only new source identities; shared entries were already merged above.
        foreach ($item in $right) {
            if (-not $masterMap.ContainsKey([string] $item[$identity])) { $items.Add((Copy-JsonValue $item)) }
        }
        $result[$key] = $items.ToArray()
    }
    return $result
}

function Set-DecisionOrder {
    <#
    .SYNOPSIS
    Assigns portal-ordered review IDs before preset selection.
    .DESCRIPTION
    Assigns stable review IDs in report order, with custom rules ordered by priority.
    #>
    $policySettingOrder = @(
        'requestBodyCheck', 'redirectUrl', 'customBlockResponseStatusCode', 'customBlockResponseBody'
        'javascriptChallengeExpirationInMinutes', 'captchaExpirationInMinutes'
        'enabledState', 'mode', 'logScrubbing'
    )
    $ordered = @($decisions | Sort-Object @{
        # Stable portal-section ordering makes printed IDs usable for preset selections.
        Expression = {
            if ($_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)) { 3 }
            elseif ($_.DecisionKind -eq 'ManagedException') { 2 }
            elseif ($_.RuleSetType) { 1 }
            else { 0 }
        }
    }, @{ Expression = { if ($_.RuleSetType) { $_.RuleSetType } else { '' } } }, @{
        Expression = {
            if ($_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)) {
                if ($_.TargetPresent) { [int] $_.TargetValue['priority'] } else { [int] $_.SourceValue['priority'] }
            } elseif (-not $_.RuleSetType) {
                # Policy settings follow portal order; custom rules retain priority ordering.
                $settingName = ($_.Path -replace '^properties\.policySettings\.', '' -split '\.')[0]
                $rank = [array]::IndexOf($policySettingOrder, $settingName)
                if ($rank -ge 0) { $rank } else { $policySettingOrder.Count }
            } elseif ($_.DecisionKind -eq 'DrsExclusion') { -1 }
            else { 0 }
        }
    }, @{
        Expression = {
            if ($_.Scope.StartsWith("Custom rule '", [StringComparison]::Ordinal)) { $_.IdentityValue }
            else { $_.Id }
        }
    } -CaseSensitive)
    $idMap = @{}
    for ($index = 0; $index -lt $ordered.Count; $index++) { $idMap[$ordered[$index].Id] = $index + 1 }
    $decisions.Clear()
    foreach ($decision in $ordered) {
        $decision.Id = $idMap[$decision.Id]
        $decisions.Add($decision)
    }
}

function Add-Decision {
    <#
    .SYNOPSIS
    Records one KeepSource/KeepTarget situation.
    .DESCRIPTION
    Captures candidate snapshots, a live target-parent reference for later mutation,
    readable metadata, and native rule context. IDs are finalized in portal section
    order, with custom rules sorted by priority, before choices are applied.
    .PARAMETER Parent
    Target dictionary owning the field or keyed collection.
    .PARAMETER Key
    Field or collection property to update.
    .PARAMETER Path
    Full internal comparison path.
    .PARAMETER TargetPresent
    Whether a master item/value exists.
    .PARAMETER TargetValue
    Master value snapshot.
    .PARAMETER SourcePresent
    Whether a source candidate exists. False also represents target-only custom
    rules and optional policy settings that require explicit confirmation.
    .PARAMETER SourceValue
        Original source policy setting, or source candidate with absent master fields retained.
    .PARAMETER Identity
    Matching key for an atomic keyed item; empty for a whole property.
    .PARAMETER IdentityValue
    Keyed item identity.
    .OUTPUTS
    None. Appends to the script-scoped decision list.
    #>
    param(
        [System.Collections.IDictionary] $Parent, [string] $Key, [string] $Path,
        [bool] $TargetPresent, [AllowNull()] $TargetValue,
        [bool] $SourcePresent, [AllowNull()] $SourceValue,
        [string] $Identity = '', [string] $IdentityValue = '',
        [ValidateSet('SourceCandidate', 'TargetCustomRule', 'TargetPolicySetting', 'DrsRisk', 'DrsExclusion', 'ManagedException')]
        [string] $DecisionKind = 'SourceCandidate'
    )
    if ($DecisionKind -eq 'TargetCustomRule') {
        if (-not $TargetPresent -or $SourcePresent -or $Identity -cne 'name') {
            throw "Invalid target custom-rule decision at $Path."
        }
    }
    elseif ($DecisionKind -eq 'TargetPolicySetting') {
        if (-not $TargetPresent -or $SourcePresent -or $Identity -or
            -not $Path.StartsWith('properties.policySettings.', [StringComparison]::Ordinal)) {
            throw "Invalid target-only policy-setting decision at $Path."
        }
    }
    elseif ($DecisionKind -in 'DrsExclusion', 'ManagedException') {
        if (-not $SourcePresent -and -not $TargetPresent) { throw "A membership review needs a source or target entry at $Path." }
    }
    elseif ($DecisionKind -ne 'DrsRisk' -and -not $SourcePresent) { throw "Cannot create a decision for absent source configuration at $Path." }
    $operation = if ($DecisionKind -in 'TargetCustomRule', 'TargetPolicySetting') { 'Retain' } elseif ($TargetPresent) { 'Replace' } else { 'Add' }
    $display = Get-DecisionDisplay $Path
    $decisions.Add([pscustomobject]@{
        # Candidate snapshots are immutable; Parent/Key identify the later mutation destination.
        Id = $decisions.Count + 1
        Path = $Path
        Operation = $operation
        TargetPresent = $TargetPresent
        TargetValue = Copy-JsonValue $TargetValue
        SourcePresent = $SourcePresent
        SourceValue = Copy-JsonValue $SourceValue
        DecisionKind = $DecisionKind
        Choice = 'Pending'
        Parent = $Parent
        Key = $Key
        Identity = $Identity
        IdentityValue = $IdentityValue
        Scope = $display.Scope
        RuleSetType = $display.RuleSetType
        RuleGroupName = $display.RuleGroupName
        RuleId = $display.RuleId
        RuleDescription = $display.RuleDescription
        SourcePriority = if ($Identity -eq 'name' -and $SourcePresent) { $SourceValue['priority'] } else { $null }
        ResolvedPriority = $null
        PriorityConflicts = @()
        CompatibilityIssues = @()
        RiskContext = @()
        ExclusionContext = $null
        ExceptionContext = $null
    })
}

function Compare-Configuration {
    <#
    .SYNOPSIS
    Recursively identifies displayed KeepSource/KeepTarget candidates.
    .DESCRIPTION
    Suppresses equal values and inherited non-policy source absences. Policy settings
    are compared separately against the original source; DRS uses the risk planner.
    Matches keyed collections by identity, treats custom rules/individual overrides
    atomically, and keeps non-keyed arrays and version changes as whole-scope choices.
    .PARAMETER Target
    Current master-based target dictionary.
    .PARAMETER Source
    Original source policy settings or the inherited source proposal for other paths.
    .PARAMETER Path
    Recursion path used for matching and display metadata.
    .OUTPUTS
    None. Populates decisions without applying candidates.
    #>
    param([System.Collections.IDictionary] $Target, [System.Collections.IDictionary] $Source, [string] $Path = '')
    $isDrs = @((Get-ManagedRuleSetTypes) | Where-Object {
        $managedPath = "properties.managedRules.managedRuleSets[$_]"
        $Path -eq $managedPath -or $Path.StartsWith("$managedPath.", [StringComparison]::Ordinal)
    }).Count -gt 0
    # DRS decisions come from effective behavior and customer tuning, not JSON differences.
    if ($isDrs) { return }
    # Stable key ordering keeps row IDs deterministic for an unchanged source/master comparison.
    $keys = @(@($Target.Keys) + @($Source.Keys) | Sort-Object -Unique -CaseSensitive)
    foreach ($key in $keys) {
        $itemPath = if ($Path) { "$Path.$key" } else { $key }
        if ($itemPath -eq 'properties.policySettings') { continue }
        if ($itemPath -eq 'properties.managedRules.exceptionsList') { continue }
        $targetPresent = $Target.Contains($key)
        $sourcePresent = $Source.Contains($key)
        $targetValue = $null
        $sourceValue = $null
        if ($targetPresent) { $targetValue = $Target[$key] }
        if ($sourcePresent) { $sourceValue = $Source[$key] }
        if ($targetPresent -and -not $sourcePresent) {
            if ($itemPath.StartsWith('properties.policySettings.', [StringComparison]::Ordinal)) {
                Add-Decision $Target $key $itemPath $true $targetValue $false $null '' '' 'TargetPolicySetting'
            }
            continue
        }
        if ($targetPresent -and $sourcePresent -and (Test-JsonEqual $targetValue $sourceValue $key)) { continue }
        if ($targetPresent -and $sourcePresent -and
            $targetValue -is [System.Collections.IDictionary] -and $sourceValue -is [System.Collections.IDictionary]) {
            Compare-Configuration $targetValue $sourceValue $itemPath
            continue
        }
        $identity = Get-CollectionIdentity $key $Path
        if ($identity -and $targetPresent -and $sourcePresent -and
            $targetValue -is [System.Collections.IList] -and $sourceValue -is [System.Collections.IList]) {
            $targetMap = Get-IdentityMap $targetValue $identity $itemPath
            $sourceMap = Get-IdentityMap $sourceValue $identity $itemPath
            foreach ($id in @(@($targetMap.Keys) + @($sourceMap.Keys) | Sort-Object -Unique -CaseSensitive)) {
                if ($identity -eq 'ruleSetType' -and $id -in (Get-ManagedRuleSetTypes)) { continue }
                $hasTarget = $targetMap.ContainsKey($id)
                $hasSource = $sourceMap.ContainsKey($id)
                if ($hasTarget -and -not $hasSource) {
                    continue
                }
                $left = if ($hasTarget) { $targetMap[$id] } else { $null }
                $right = if ($hasSource) { $sourceMap[$id] } else { $null }
                if ($hasTarget -and $hasSource -and (Test-JsonEqual $left $right)) { continue }
                # Custom rules/individual overrides are one choice; version changes replace a whole set.
                $atomic = $identity -in 'name', 'ruleId'
                if ($hasTarget -and $hasSource -and $identity -eq 'ruleSetType') {
                    $atomic = $left['ruleSetVersion'] -cne $right['ruleSetVersion']
                }
                if ($hasTarget -and $hasSource -and -not $atomic) {
                    Compare-Configuration $left $right "$itemPath[$id]"
                }
                else {
                    Add-Decision $Target $key "$itemPath[$id]" $hasTarget $left $hasSource $right $identity $id
                }
            }
        }
        else {
            Add-Decision $Target $key $itemPath $targetPresent $targetValue $sourcePresent $sourceValue
        }
    }
}

function Assert-KeepSourceCompatibility {
    <#
    .SYNOPSIS
    Rejects a selected source value with known catalog incompatibilities.
    .DESCRIPTION
    Applies the same fail-fast guard to preset and interactive KeepSource choices.
    Final target validation still checks semantic constraints and cross-row dependencies.
    .PARAMETER Decision
    Source candidate selected by KeepSource.
    .OUTPUTS
    None. Throws with the row ID and compatibility diagnostics.
    #>
    param($Decision)
    if ($Decision.CompatibilityIssues.Count) {
        throw "Cannot keep source for row $($Decision.Id): $($Decision.CompatibilityIssues -join ' ')"
    }
}

function Set-SourceDecision {
    <#
    .SYNOPSIS
    Applies a KeepSource candidate to its captured target parent.
    .DESCRIPTION
    Replaces an existing keyed item or appends a source-only item; plain fields and
    non-keyed lists are replaced at their entire scope. Candidate values are copied.
    .PARAMETER Decision
    Validated decision whose optional priority resolution has already completed.
    .OUTPUTS
    None. Mutates the in-memory target only, never Azure.
    #>
    param($Decision)
    if ($Decision.DecisionKind -in 'DrsExclusion', 'ManagedException') {
        throw 'Individual exclusion/exception choices must be finalized together after rule/group tuning.'
    }
    if ($Decision.DecisionKind -eq 'DrsRisk') {
        if (-not $Decision.SourcePresent) { throw 'This DRS risk requires template correction or explicit target-risk acceptance, not a source copy.' }
        Set-DrsRiskConfiguration $target $Decision.SourceValue $Decision.RuleSetType
        return
    }
    if ($Decision.DecisionKind -eq 'TargetPolicySetting') {
        if (-not $Decision.Parent.Contains($Decision.Key)) {
            throw "Target-only policy setting $($Decision.Path) is no longer present."
        }
        $Decision.Parent.Remove($Decision.Key)
        return
    }
    if (-not $Decision.SourcePresent) { throw 'Source-absent configuration cannot be applied as KeepSource here.' }
    if ($Decision.Identity) {
        # Replace only the selected identity, preserving its position and all sibling target entries.
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Decision.Parent[$Decision.Key]) {
            if ([string] $item[$Decision.Identity] -cne $Decision.IdentityValue) { $items.Add($item) }
            else { $items.Add((Copy-JsonValue $Decision.SourceValue)) }
        }
        if (-not $Decision.TargetPresent -and $Decision.SourcePresent) { $items.Add((Copy-JsonValue $Decision.SourceValue)) }
        $Decision.Parent[$Decision.Key] = $items.ToArray()
    }
    else { $Decision.Parent[$Decision.Key] = Copy-JsonValue $Decision.SourceValue }
}

function Remove-TargetTemplateRule {
    <#
    .SYNOPSIS
    Omits a target custom rule selected with KeepSource.
    .DESCRIPTION
    Removes exactly one target-only custom rule after an explicit KeepSource choice.
    #>
    param($Decision)
    if ($Decision.DecisionKind -ne 'TargetCustomRule' -or $Decision.Identity -cne 'name' -or
        -not $Decision.TargetPresent -or $Decision.SourcePresent) {
        throw "Row $($Decision.Id) is not a removable target custom-rule decision."
    }
    $items = @($Decision.Parent[$Decision.Key] | Where-Object {
        [string] $_[$Decision.Identity] -cne $Decision.IdentityValue
    })
    if ($items.Count -ne @($Decision.Parent[$Decision.Key]).Count - 1) {
        throw "Expected exactly one target custom rule '$($Decision.IdentityValue)' to remove."
    }
    $Decision.Parent[$Decision.Key] = $items
}

#endregion

#region ARM literal encoding
function ConvertTo-ArmLiteral {
    <#
    .SYNOPSIS
    Escapes literal JSON strings that ARM might interpret as expressions.
    .DESCRIPTION
    Recursively prefixes strings beginning with [ while preserving arrays and objects.
    Used only on literal tags/properties, not the intentional policy-name expression.
    .PARAMETER Value
    Target JSON value to encode for an ARM template.
    .OUTPUTS
    ARM-safe JSON-compatible value.
    #>
    param([AllowNull()] $Value)
    if ($Value -is [string] -and $Value.StartsWith('[')) { return "[$Value" }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in $Value.Keys) { $result[$key] = ConvertTo-ArmLiteral $Value[$key] }
        return $result
    }
    if ($Value -is [System.Collections.IList]) {
        return ,@(foreach ($item in $Value) { ConvertTo-ArmLiteral $item })
    }
    return $Value
}

#endregion

#region Execution - policy inputs and master baseline
# Protect input/output paths before Azure reads or prompts; Force must never overwrite an input.
Write-Host 'Loading and validating policy inputs...'
$sourceInput = Resolve-PolicyInput $SourcePolicy 'Source'
$hasMasterPolicy = $PSBoundParameters.ContainsKey('MasterPolicy')
$masterInput = if ($hasMasterPolicy) { Resolve-PolicyInput $MasterPolicy 'Master' } else { $null }
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).Path "$TargetPolicyName.arm.json" }
$outputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
foreach ($protectedFile in @($sourceInput.FilePath, $(if ($hasMasterPolicy) { $masterInput.FilePath }), $PSCommandPath)) {
    if ($protectedFile -and [string]::Equals($outputFile, $protectedFile, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputPath must not overwrite the source, master or script.'
    }
}
if (-not $ReportOnly) {
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $outputFile) -PathType Container)) { throw 'Output directory does not exist.' }
    if ((Test-Path -LiteralPath $outputFile) -and -not $Force) { throw "Output already exists: $outputFile. Use -Force to replace it." }
    if (Test-Path -LiteralPath $outputFile -PathType Container) { throw 'OutputPath must be a file, not a directory.' }
}

# Both live inputs use the caller's context; file-only runs neither inspect nor change it.
$liveInputs = @($sourceInput, $masterInput | Where-Object { $null -ne $_ -and $_.ResourceId })
$context = $null
if ($liveInputs.Count) {
    # Validate the caller's subscription without switching context or authenticating offline inputs.
    Write-Host 'Checking the Azure context for resource-ID inputs...'
    $context = if ($null -ne $DefaultProfile) { $DefaultProfile } else { Get-AzContext -ErrorAction Stop }
    if ($null -eq $context -or $null -eq $context.Account -or $null -eq $context.Subscription) {
        throw 'No authenticated Az context. Run Connect-AzAccount and Set-AzContext first.'
    }
    foreach ($inputPolicy in $liveInputs) {
        if ($context.Subscription.Id -ine $inputPolicy.SubscriptionId) {
            throw "Current Az subscription does not match policy subscription $($inputPolicy.SubscriptionId). Run Set-AzContext explicitly or supply an exported JSON file."
        }
    }
}

if ($hasMasterPolicy) {
    Write-Host $(if ($masterInput.ResourceId) { 'Reading the master policy from Azure (GET only)...' } else { 'Preparing the master policy from JSON...' })
    $master = Read-PolicyInput $masterInput
    if ($master['sku'] -isnot [System.Collections.IDictionary] -or $master['sku']['name'] -cne 'Premium_AzureFrontDoor') {
        throw 'Master must use Premium_AzureFrontDoor to support the target managed rules.'
    }
    if (-not $master.Contains('location') -or $master['location'] -ine 'global') { throw 'Master Front Door WAF location must be Global.' }
    $target = ConvertTo-PolicyConfiguration $master 'Master' -AllowMissingDefaultRuleSet
}

#endregion

#region Execution - Azure source and embedded managed-rule catalog
Write-Host $(if ($sourceInput.ResourceId) { 'Reading the source policy from Azure (GET only)...' } else { 'Preparing the source policy from JSON...' })
$sourceResource = Read-PolicyInput $sourceInput
$sourcePolicyName = if ($sourceInput.ResourceId) { ($sourceInput.ResourceId -split '/')[-1] } else { [string] $sourceResource['name'] }
$sourceOriginalDrs = @(
    if ($sourceResource['properties'] -is [System.Collections.IDictionary] -and
        $sourceResource['properties']['managedRules'] -is [System.Collections.IDictionary]) {
        $originalSets = Get-Collection $sourceResource['properties']['managedRules'] 'managedRuleSets'
        $originalSets | Where-Object { $_['ruleSetType'] -in 'DefaultRuleSet', 'Microsoft_DefaultRuleSet' }
    }
)
$sourceOriginalDrsVersion = if ($sourceOriginalDrs.Count) { [string] $sourceOriginalDrs[0]['ruleSetVersion'] } else { $null }
Write-Host 'Loading embedded managed-rule catalogs and resolving native defaults...'
$drsCatalog = Get-EmbeddedDrsCatalog
$targetVersion = if ($hasMasterPolicy) { (Get-DrsTargetVersion) ?? '2.2' } else { '2.2' }
$source = ConvertTo-PolicyConfiguration $sourceResource 'Source' -AllowMissingDefaultRuleSet -TargetDrsVersion $targetVersion
if (-not $hasMasterPolicy) { $target = New-DefaultDrsTargetConfiguration $source }
$sourceCustomRuleBehaviorAssessments = @(Get-CustomRuleBehaviorAssessments $source)
$explicitSourceCustomRuleNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($rule in (Get-Collection $source['properties']['customRules'] 'rules')) {
    $null = $explicitSourceCustomRuleNames.Add([string] $rule['name'])
}
$catalogIndexes = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)

$drsDocumentation = Get-DrsDocumentation
$drsRuleInventory = Get-DrsRuleInventory -TargetVersion (Get-DrsTargetVersion)

#endregion

#region Execution - baseline validation and decision planning
Write-Host 'Validating policy baselines and comparing settings and custom rules...'
Assert-TargetConfiguration $target
$drsSourceSnapshot = Copy-JsonValue $source
Sync-ManagedSourceVersions $source $target
$baselineIssues = Get-DrsBlockingIssues
if (-not $ReportOnly -and $baselineIssues.Count) {
    Write-MigrationBlockingIssues $baselineIssues
    throw 'Source baseline must be corrected before reviewing the target. No ARM file was written.'
}
if ($target['properties'].Contains('customRules')) {
    foreach ($rule in @((Get-Collection $target['properties']['customRules'] 'rules') |
        Sort-Object { [string] $_['name'] } -CaseSensitive)) {
        $name = [string] $rule['name']
        if (-not $explicitSourceCustomRuleNames.Contains($name)) {
            Add-Decision $target['properties']['customRules'] 'rules' "properties.customRules.rules[$name]" `
                $true $rule $false $null 'name' $name 'TargetCustomRule'
        }
    }
}
if ($target['properties'].Contains('policySettings')) {
    $originalPolicySettings = if ($source['properties'].Contains('policySettings')) {
        $source['properties']['policySettings']
    } else { [ordered]@{} }
    Compare-Configuration $target['properties']['policySettings'] $originalPolicySettings 'properties.policySettings'
} elseif ($source['properties'].Contains('policySettings')) {
    Add-Decision $target['properties'] 'policySettings' 'properties.policySettings' `
        $false $null $true $source['properties']['policySettings']
}
# Other source candidates retain unrelated template-only fields.
$source = Merge-SourceConfiguration $target $source
$sourceIssues = @(Get-CatalogIssues $source)
foreach ($issue in ($sourceIssues | Where-Object { -not $_.StartsWith('Exception', [StringComparison]::Ordinal) })) {
    Write-Warning "Source carryover compatibility: $issue"
}
Compare-Configuration $target $source
Set-DecisionOrder
Write-Host 'Comparing managed-rule behavior, exclusions, and request exceptions...'
$drsRiskAnalysis = Get-DrsRiskPlan $drsSourceSnapshot
Add-DrsScopeDecisions $drsSourceSnapshot
Add-DrsExclusionDecisions $drsSourceSnapshot
Add-ManagedExceptionDecisions $drsSourceSnapshot
$additionalManagedRiskAnalysis = @(
    foreach ($type in 'Microsoft_BotManagerRuleSet', 'Microsoft_HTTPDDoSRuleSet') {
        $left = Get-DrsSet $drsSourceSnapshot $type
        $right = Get-DrsSet $target $type
        if ($null -ne $left -or $null -ne $right) {
            Get-DrsRiskPlan $drsSourceSnapshot $type | ForEach-Object { $_ }
            Add-DrsScopeDecisions $drsSourceSnapshot $type
        }
    }
)
$allManagedRiskAnalysis = @($drsRiskAnalysis) + @($additionalManagedRiskAnalysis)
$baselineRisks = @($allManagedRiskAnalysis | Where-Object {
    $_.Treatment -eq 'Decision' -and $_.BaselineOnly -and $_.CandidateOperations.Count
})
foreach ($risk in $baselineRisks) {
    Add-DrsRiskDecision @($risk) $risk.CandidateOperations 'Default-driven protection loss' $risk.RuleSetType
}
foreach ($risk in ($allManagedRiskAnalysis | Where-Object {
    $_.Treatment -eq 'Decision' -and (-not $_.BaselineOnly -or -not $_.CandidateOperations.Count)
})) {
    Add-DrsRiskDecision @($risk) $risk.CandidateOperations -RuleSetType $risk.RuleSetType
}
foreach ($issue in ($sourceIssues | Where-Object {
    $_.Contains('Microsoft_DefaultRuleSet') -and -not $_.StartsWith('Exception', [StringComparison]::Ordinal)
})) {
    $risk = New-DrsRiskRow 'All' $null $null
    $risk.Treatment = 'Decision'; $risk.RiskKinds = @('SourceCompatibility')
    $risk.Reason = "$issue Source carryover cannot be applied; accept omission explicitly or correct the template."
    Add-DrsRiskDecision @($risk) @() 'Source carryover compatibility'
}
foreach ($type in 'Microsoft_BotManagerRuleSet', 'Microsoft_HTTPDDoSRuleSet') {
    foreach ($issue in ($sourceIssues | Where-Object {
        $_.Contains($type) -and -not $_.StartsWith('Exception', [StringComparison]::Ordinal)
    })) {
        # Keep unsupported family carryover visible as a review, not a silent omission.
        $risk = New-DrsRiskRow 'All' $null $null $type `
            (Get-ManagedSourceVersion $drsSourceSnapshot $type) (Get-ManagedComparisonVersion $drsSourceSnapshot $type)
        $risk.Treatment = 'Decision'; $risk.RiskKinds = @('SourceCompatibility')
        $risk.Reason = "$issue Source carryover cannot be applied; accept omission explicitly or correct the template."
        Add-DrsRiskDecision @($risk) @() 'Source carryover compatibility' $type
    }
}
Set-DecisionOrder
$blockingIssues = Get-DrsBlockingIssues
$keepSourceIds = Resolve-DecisionRanges $keepSourceRanges 'KeepSource' $decisions.Count
$keepTargetIds = Resolve-DecisionRanges $keepTargetRanges 'KeepTarget' $decisions.Count
# Choices annotate the report first; target mutations happen only in the non-report execution below.
Write-Host "Checking compatibility for $($decisions.Count) review decisions..."
$decisionNumber = 0
try {
    foreach ($decision in $decisions) {
        # Use the actual decision count; compatibility checks can dominate startup time.
        $decisionNumber++
        Write-Progress -Id 1 -Activity 'Preparing WAF migration report' `
            -Status "Checking decision $decisionNumber of $($decisions.Count)" `
            -PercentComplete ([int] (100 * ($decisionNumber - 1) / $decisions.Count))
        $decision.CompatibilityIssues = Get-CandidateCompatibilityIssues $decision
        if ($keepSourceIds.Contains($decision.Id)) { $decision.Choice = 'KeepSource' }
        elseif ($keepTargetIds.Contains($decision.Id)) { $decision.Choice = 'KeepTarget' }
        # Automatic custom-rule union.
        elseif ($Auto) {
            # Preserve supported source behavior; unsupported managed candidates keep target and warn.
            $decision.Choice = if ($decision.DecisionKind -eq 'TargetCustomRule' -or
                ($decision.DecisionKind -in 'DrsRisk', 'DrsExclusion', 'ManagedException' -and
                    $decision.CompatibilityIssues.Count)) { 'KeepTarget' } else { 'KeepSource' }
        }
    }
} finally {
    Write-Progress -Id 1 -Activity 'Preparing WAF migration report' -Completed
}
# Calculate priority occupancy only after every preset choice is known.
foreach ($decision in ($decisions | Where-Object { $_.Identity -eq 'name' -and $_.SourcePresent })) {
    $decision.PriorityConflicts = Get-CustomPriorityConflicts $decision.SourceValue
}
#endregion

#region Execution - report display and KeepSource/KeepTarget decisions
Write-Host 'Analysis complete. Displaying policy comparisons.' -ForegroundColor Cyan
Write-MigrationBlockingIssues $blockingIssues
Write-DecisionTable $decisions.ToArray()
if ($ReportOnly) { Write-Host "`nReport only: no file created and no Azure resources changed." }
if (-not $ReportOnly -and $blockingIssues.Count) {
    throw 'Migration has blocking DRS errors. Correct the reported template/source-baseline issues and rerun; no decisions were applied and no ARM file was written.'
}
# Reject all known-invalid preset source choices before applying any selected changes.
foreach ($decision in $decisions) {
    if (-not $ReportOnly -and $decision.Choice -eq 'KeepSource' -and $decision.DecisionKind -ne 'TargetCustomRule') {
        Assert-KeepSourceCompatibility $decision
    }
}
foreach ($decision in $decisions) {
    # Report-only never mutates the target, resolves priorities, or prompts, even with preset choices.
    if ($ReportOnly) { continue }
    if ($decision.DecisionKind -eq 'TargetCustomRule' -and $decision.Choice -eq 'KeepSource') {
        Remove-TargetTemplateRule $decision
        continue
    }
    if ($decision.Choice -eq 'KeepTarget') { continue }
    if ($decision.Choice -eq 'KeepSource') {
        if ($decision.DecisionKind -in 'DrsExclusion', 'ManagedException') { continue }
        Resolve-CustomPriority $decision
        Set-SourceDecision $decision
        if ($null -ne $decision.ResolvedPriority) { Write-DecisionSelection $decision }
        continue
    }
    $reviewOnly = ($decision.DecisionKind -eq 'DrsRisk' -and -not $decision.SourcePresent) -or
        $decision.CompatibilityIssues.Count -gt 0
    $allowedAnswers = if ($reviewOnly) { @('T', 'TARGET', 'KEEPTARGET', 'Q', 'QUIT') }
        else { @('S', 'SOURCE', 'KEEPSOURCE', 'T', 'TARGET', 'KEEPTARGET', 'Q', 'QUIT') }
    $prompt = if ($reviewOnly) { "[$($decision.Id)] Choose Keep[T]arget, or [Q]uit and fix the configuration" }
        else { "[$($decision.Id)] Choose Keep[S]ource, Keep[T]arget, or [Q]uit" }
    do {
        $answer = (Read-Host $prompt).Trim().ToUpperInvariant()
        if ($answer -notin $allowedAnswers) {
            Write-Warning "Enter a valid choice: $prompt."
        }
    } until ($answer -in $allowedAnswers)
    if ($answer -in 'Q', 'QUIT') { throw 'Migration cancelled. No ARM file was written.' }
    if ($answer -in 'S', 'SOURCE', 'KEEPSOURCE') {
        # Validate each selected copy; scoped bypasses are applied together after all reviews.
        if ($decision.DecisionKind -eq 'TargetCustomRule') { Remove-TargetTemplateRule $decision }
        else {
            Assert-KeepSourceCompatibility $decision
            if ($decision.DecisionKind -notin 'DrsExclusion', 'ManagedException') {
                Resolve-CustomPriority $decision
                Set-SourceDecision $decision
            }
        }
        $decision.Choice = 'KeepSource'
    }
    else {
        $decision.Choice = 'KeepTarget'
    }
    Write-DecisionSelection $decision
}
if (-not $ReportOnly) {
    # Apply membership after rule/group choices so disabling a group cannot erase reviewed exclusions.
    Set-DrsExclusionChoices $target $decisions.ToArray()
    Set-ManagedExceptionChoices $target $decisions.ToArray()
}

#endregion

#region Execution - resource-group ARM template output
if (-not $ReportOnly) {
    # Cross-row validation must succeed before opening output, including when Force replaces a file.
    Assert-TargetConfiguration $target
    $selectedTargetIssues = Get-DrsBlockingIssues
    if ($selectedTargetIssues.Count) {
        Write-MigrationBlockingIssues $selectedTargetIssues
        throw 'Selected configuration has blocking DRS errors. Correct the reported template/source-baseline issues and rerun; no ARM file was written.'
    }
    # Resource-group scope comes from the template schema and the user's deployment command.
    $template = [ordered]@{
        '$schema' = 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
        contentVersion = '1.0.0.0'
        parameters = [ordered]@{ policyName = [ordered]@{ type = 'string'; defaultValue = $TargetPolicyName } }
        resources = @(
            [ordered]@{
                type = $resourceType
                apiVersion = $apiVersion
                name = "[parameters('policyName')]"
                location = 'Global'
                sku = [ordered]@{ name = 'Premium_AzureFrontDoor' }
                # Escape configuration literals, but leave the intentional policyName expression intact.
                tags = ConvertTo-ArmLiteral $target['tags']
                properties = ConvertTo-ArmLiteral $target['properties']
            }
        )
    }
    $json = ConvertTo-Json -InputObject $template -Depth 100
    # CreateNew closes the race between the earlier existence check and writing a new output file.
    $mode = if ($Force) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::CreateNew }
    $stream = [System.IO.File]::Open($outputFile, $mode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
    Write-Host "`nARM template written: $outputFile"
    # Single-quoted PowerShell literals keep spaces, apostrophes and expression characters in paths safe.
    $templateFileLiteral = "'" + $outputFile.Replace("'", "''") + "'"
    $deploymentExample = "New-AzResourceGroupDeployment -ResourceGroupName '<target-resource-group>' -TemplateFile $templateFileLiteral -Mode Incremental"
    Write-Host "`nUser-run commands (require Az.Resources; select the destination subscription and an existing resource group):" -ForegroundColor Cyan
    Write-Host "What-if (preview only):`n$deploymentExample -WhatIf -ErrorAction Stop"
    Write-Host "Deploy for real:`n$deploymentExample -ErrorAction Stop"
}

#endregion

#region Execution - structured result
# Report summaries omit candidate values; normal-mode summaries retain accepted decision details.
$summary = [pscustomobject]@{
    SourcePolicyName = $sourcePolicyName
    SourceRuleSetVersion = Get-ManagedSourceVersion $drsSourceSnapshot 'Microsoft_DefaultRuleSet'
    TargetPolicyName = $TargetPolicyName
    TargetRuleSetVersion = Get-DrsTargetVersion
    SourceBotManagerRuleSetVersion = Get-ManagedSourceVersion $drsSourceSnapshot 'Microsoft_BotManagerRuleSet'
    TargetBotManagerRuleSetVersion = Get-DrsTargetVersion $target 'Microsoft_BotManagerRuleSet'
    SourceHttpDdosRuleSetVersion = Get-ManagedSourceVersion $drsSourceSnapshot 'Microsoft_HTTPDDoSRuleSet'
    TargetHttpDdosRuleSetVersion = Get-DrsTargetVersion $target 'Microsoft_HTTPDDoSRuleSet'
    TargetBaseline = if (-not (Get-DrsTargetVersion)) { 'NoDefaultRuleSet' }
        elseif ($hasMasterPolicy) { "Drs$((Get-DrsTargetVersion).Replace('.', ''))DefaultsWithTemplateOverrides" } else { 'Drs22Defaults' }
    ReportOnly = [bool] $ReportOnly
    OutputPath = if ($ReportOnly) { $null } else { $outputFile }
    DecisionCount = $decisions.Count
    PendingDecisionCount = @($decisions | Where-Object Choice -eq 'Pending').Count
    SourceCompatibilityIssues = $sourceIssues
    DrsRuleInventory = $drsRuleInventory
    ManagedRuleInventory = @(Get-ManagedCatalogInventory)
    TargetManagedRuleSets = @(
        foreach ($set in $target['properties']['managedRules']['managedRuleSets']) {
            [pscustomobject]@{ RuleSetType = $set['ruleSetType']; RuleSetVersion = $set['ruleSetVersion'] }
        }
    )
    ManagedRuleRiskAnalysis = (Get-DrsRiskSummary $allManagedRiskAnalysis) + @(
        $decisions | Where-Object DecisionKind -eq 'DrsRisk' |
            ForEach-Object { $_.RiskContext } | Where-Object RuleId -eq 'All'
    )
    DrsRiskAnalysis = (Get-DrsRiskSummary $drsRiskAnalysis) + @(
        $decisions | Where-Object DecisionKind -eq 'DrsRisk' |
            ForEach-Object { $_.RiskContext } | Where-Object { $_.RuleId -eq 'All' -and $_.RuleSetType -eq 'Microsoft_DefaultRuleSet' }
    )
    BlockingIssueCount = $blockingIssues.Count
    BlockingIssues = $blockingIssues
    CustomRuleBehaviorAssessments = $sourceCustomRuleBehaviorAssessments
    Decisions = @(
        if ($ReportOnly) {
            $decisions | Select-Object Id, Scope, RuleSetType, RuleGroupName, RuleId, RuleDescription, Operation, DecisionKind, SourcePresent, TargetPresent, Choice, SourcePriority, ResolvedPriority, PriorityConflicts, CompatibilityIssues, RiskContext, ExclusionContext, ExceptionContext
        }
        else {
            $decisions | Select-Object Id, Scope, RuleSetType, RuleGroupName, RuleId, RuleDescription, Operation, DecisionKind, TargetPresent, TargetValue, SourcePresent, SourceValue, Choice, SourcePriority, ResolvedPriority, PriorityConflicts, CompatibilityIssues, RiskContext, ExclusionContext, ExceptionContext
        }
    )
}
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'SourcePolicy DRS version' -Value { $this.SourceRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'TargetPolicy DRS version' -Value { $this.TargetRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'SourcePolicy Bot Manager version' -Value { $this.SourceBotManagerRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'TargetPolicy Bot Manager version' -Value { $this.TargetBotManagerRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'SourcePolicy HTTP DDoS version' -Value { $this.SourceHttpDdosRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType ScriptProperty -Name 'TargetPolicy HTTP DDoS version' -Value { $this.TargetHttpDdosRuleSetVersion ?? '---' }
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'SourcePolicy Microsoft_DefaultRuleSet version' -Value 'SourcePolicy DRS version'
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'SourcePolicy Microsoft_BotManagerRuleSet version' -Value 'SourcePolicy Bot Manager version'
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'SourcePolicy Microsoft_HTTPDDoSRuleSet version' -Value 'SourcePolicy HTTP DDoS version'
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'TargetPolicy Microsoft_DefaultRuleSet version' -Value 'TargetPolicy DRS version'
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'TargetPolicy Microsoft_BotManagerRuleSet version' -Value 'TargetPolicy Bot Manager version'
Add-Member -InputObject $summary -MemberType AliasProperty -Name 'TargetPolicy Microsoft_HTTPDDoSRuleSet version' -Value 'TargetPolicy HTTP DDoS version'
$displayProperties = [System.Management.Automation.PSPropertySet]::new(
    'DefaultDisplayPropertySet',
    [string[]]@(
        'SourcePolicyName', 'SourcePolicy Microsoft_DefaultRuleSet version',
        'SourcePolicy Microsoft_BotManagerRuleSet version', 'SourcePolicy Microsoft_HTTPDDoSRuleSet version',
        'TargetPolicyName', 'TargetPolicy Microsoft_DefaultRuleSet version',
        'TargetPolicy Microsoft_BotManagerRuleSet version', 'TargetPolicy Microsoft_HTTPDDoSRuleSet version',
        'ReportOnly', 'OutputPath', 'DecisionCount', 'PendingDecisionCount'
    )
)
Add-Member -InputObject $summary -MemberType MemberSet -Name PSStandardMembers -Value @($displayProperties)
$summary.PSObject.TypeNames.Insert(0, 'WafMigration.PolicySummary')
$summary
#endregion
