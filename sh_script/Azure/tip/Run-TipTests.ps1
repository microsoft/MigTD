<#
.SYNOPSIS
  Backward-compatible entrypoint for TiP hardware test suites.

.DESCRIPTION
  Delegates to Invoke-TipHarness.ps1 in Run mode. By default this runs the fast
  PR suite (mock-quote migration + ServTdExt prebind). -IncludeAgentCases maps
  to the deep release suite (agent cases + rebind).
#>
[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$PowerTestPath = "$env:ProgramFiles\WindowsPowerShell\Modules\PowerTest",
    [switch]$InstallDependencies,
    [switch]$ConfigureHost,
    [switch]$IncludeAgentCases,
    [switch]$CaptureSerial = $true,
    [string]$ResultsPath,
    [string]$EvidenceDir,
    [switch]$SkipHashEvidenceValidation,
    [ValidateSet('PrFast', 'ReleaseDeep')]
    [string]$Suite
)

$ErrorActionPreference = 'Stop'
$harness = Join-Path $PSScriptRoot 'Invoke-TipHarness.ps1'
if (-not (Test-Path $harness)) {
    throw "Harness wrapper not found: $harness"
}

if (-not $PSBoundParameters.ContainsKey('Suite')) {
    $Suite = if ($IncludeAgentCases) { 'ReleaseDeep' } else { 'PrFast' }
}

& $harness -Mode Run `
    -PackageDir $PackageDir `
    -Suite $Suite `
    -PowerTestPath $PowerTestPath `
    -InstallDependencies:$InstallDependencies `
    -ConfigureHost:$ConfigureHost `
    -CaptureSerial:$CaptureSerial `
    -ResultsPath $ResultsPath `
    -EvidenceDir $EvidenceDir `
    -SkipHashEvidenceValidation:$SkipHashEvidenceValidation
