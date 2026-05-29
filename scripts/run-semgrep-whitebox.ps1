param(
  [Parameter(Mandatory = $true)]
  [string] $RepoPath,

  [string] $OutputRoot = "",
  [string] $OutputName = "",
  [string] $ScopeTag = "",
  [switch] $DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

$rules = Join-Path $root "integrations\semgrep-rules"
if (-not (Test-Path -LiteralPath $RepoPath)) {
  Write-Host "Repo path not found: $RepoPath" -ForegroundColor Red
  exit 1
}
if (-not (Test-Path -LiteralPath $rules)) {
  Write-Host "Semgrep rules are missing. Run scripts\update-bounty-integrations.ps1 first." -ForegroundColor Red
  exit 1
}
if (-not $DryRun -and -not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
  Write-Host "Semgrep was not found. Install it first, then rerun this script." -ForegroundColor Red
  Write-Host "Recommended: python -m pip install semgrep"
  exit 1
}

$program = if ($ScopeTag) { $ScopeTag } else { Split-Path -Leaf $RepoPath }
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $program -Kind "semgrep"
if (-not $OutputName) {
  $OutputName = "results.json"
}

$output = Join-Path $runDir $OutputName
$manifest = Join-Path $runDir "manifest.json"
$casePath = Join-Path $runDir "case.md"

@(
  "# Scan Case: $program",
  "",
  "- Created: $((Get-Date).ToString('o'))",
  "- Kind: semgrep-whitebox",
  "- Output directory: $runDir",
  "- Repo path: $((Resolve-Path -LiteralPath $RepoPath).Path)",
  "- Finding statuses: lead -> candidate -> verified -> not_reportable -> out_of_scope",
  "",
  "## Notes",
  "",
  "Semgrep findings are leads until a reviewer confirms reachability, exploitability, and impact."
) | Set-Content -Path $casePath -Encoding UTF8

if ($DryRun) {
  Write-Host "Dry run requested; semgrep was not executed." -ForegroundColor Yellow
} else {
  semgrep `
    --config $rules `
    --json `
    --output $output `
    --timeout 20 `
    --exclude node_modules `
    --exclude vendor `
    --exclude dist `
    --exclude build `
    $RepoPath
}

@{
  type = "semgrep"
  createdAt = (Get-Date).ToString("o")
  sourceLabel = "semgrep"
  scopeTag = ConvertTo-SafeName $program
  repoPath = (Resolve-Path -LiteralPath $RepoPath).Path
  targetLabel = ConvertTo-SafeName $program
  resultsPath = Split-Path -Leaf $output
  casePath = Split-Path -Leaf $casePath
  findingStatuses = @("lead", "candidate", "verified", "not_reportable", "out_of_scope")
  outputRoot = (Get-BaiOutputRoot -OutputRoot $OutputRoot)
  dryRun = [bool]$DryRun
} | ConvertTo-Json -Depth 6 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Semgrep artifacts saved under: $runDir" -ForegroundColor Green
