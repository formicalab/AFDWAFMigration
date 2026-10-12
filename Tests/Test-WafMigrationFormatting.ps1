#Requires -Version 7.0
#Requires -Modules Az.Accounts

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Same-session formatting and deployment-module regression
$repositoryPath = Split-Path $PSScriptRoot -Parent
$migrationPath = Join-Path $repositoryPath 'New-WafMigrationTemplate.ps1'
$fixturePath = Join-Path $repositoryPath 'Templates\mastertemplate.json'
$testDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "waf-format-test-$([guid]::NewGuid())"
$outputPath = Join-Path $testDirectory 'generated.arm.json'
$copiedScript = Join-Path $testDirectory 'New-WafMigrationTemplate.ps1'
$null = New-Item -ItemType Directory -Path $testDirectory
$formatAccent = $PSStyle.Formatting.FormatAccent
$rendering = $PSStyle.OutputRendering

function Assert-Equal {
    <#
    .SYNOPSIS
    Requires exact scalar equality.
    .DESCRIPTION
    Throws a named formatting regression failure on any unexpected result.
    #>
    param($Actual, $Expected, [string] $Message)
    if ($Actual -cne $Expected) { throw "$Message`: expected [$Expected], got [$Actual]." }
}

try {
    if (Get-Module Az.Resources) { throw 'Run this test in a fresh pwsh -NoProfile session without Az.Resources preloaded.' }
    if (-not (Get-Module -ListAvailable Az.Resources)) { throw 'This regression requires the installed Az.Resources module.' }
    Copy-Item -LiteralPath $migrationPath -Destination $copiedScript
    Assert-Equal @(Get-FormatData -TypeName 'WafMigration.PolicySummary').Count 0 'Fresh session has no external migration format view'
    $result = & $migrationPath -SourcePolicy $fixturePath -MasterPolicy $fixturePath `
        -TargetPolicyName FormatTest -OutputPath $outputPath 6>$null
    Assert-Equal (Test-Path -LiteralPath $outputPath -PathType Leaf) $true 'Generation produced an ARM template'
    Assert-Equal @(Get-FormatData -TypeName 'WafMigration.PolicySummary').Count 0 'Generation does not register format files'

    # Both explicit refreshes and module imports reread registered format paths.
    Update-FormatData -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    $command = Get-Command New-AzResourceGroupDeployment -ErrorAction Stop
    Assert-Equal $command.ModuleName 'Az.Resources' 'Deployment command loads after generation'
    Assert-Equal $command.Parameters.ContainsKey('WhatIf') $true 'Loaded deployment command supports dry runs'
    Update-FormatData -ErrorAction Stop

    $PSStyle.OutputRendering = 'PlainText'
    $summaryText = $result | Out-String
    Assert-Equal ($summaryText -match '(?m)^SourcePolicyName\s+:') $true 'Source summary label survives module loading'
    Assert-Equal ($summaryText -match '(?m)^TargetPolicyName\s+:\s+FormatTest') $true 'Target summary value survives module loading'
    Assert-Equal $PSStyle.Formatting.FormatAccent $formatAccent 'Formatting leaves session-wide label colors unchanged'
    $null = & $migrationPath -SourcePolicy $fixturePath -MasterPolicy $fixturePath `
        -TargetPolicyName RepeatFormatTest -ReportOnly 6>$null
    Update-FormatData -ErrorAction Stop
    Assert-Equal @(Get-FormatData -TypeName 'WafMigration.PolicySummary').Count 0 'Repeated execution still uses native display metadata'
    Write-Host 'PASS: generation, format refreshes, late Az.Resources import, dry-run command availability and repeated execution'

    Remove-Item -LiteralPath $outputPath
    $standaloneResult = & $copiedScript -SourcePolicy $fixturePath -MasterPolicy $fixturePath `
        -TargetPolicyName StandaloneTest -OutputPath $outputPath 6>$null
    Assert-Equal (Test-Path -LiteralPath $outputPath -PathType Leaf) $true 'The copied script generates output without companion files'
    Assert-Equal (Get-ChildItem -LiteralPath $testDirectory -File).Count 2 'Standalone run creates only its requested ARM output'
    Update-FormatData -ErrorAction Stop
    Remove-Module Az.Resources -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    $standaloneText = $standaloneResult | Out-String
    Assert-Equal ($standaloneText -match '(?m)^TargetPolicyName\s+:\s+StandaloneTest') $true 'Standalone summary remains readable after module reimport'
    Assert-Equal $PSStyle.Formatting.FormatAccent $formatAccent 'Standalone formatting preserves the session theme'
    Write-Host 'PASS: standalone script requires no format/catalog/helper files and survives deployment-module reimport'
}
finally {
    $PSStyle.OutputRendering = $rendering
    foreach ($path in $outputPath, $copiedScript) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
    }
    Remove-Item -LiteralPath $testDirectory
}
#endregion
