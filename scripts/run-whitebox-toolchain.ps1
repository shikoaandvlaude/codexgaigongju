param(
  [Parameter(Mandatory = $true)]
  [string] $RepoPath,

  [string] $OutputRoot = "",
  [string] $ScopeTag = "",
  [string] $ToolRoot = "",
  [switch] $All,
  [switch] $IncludeSemgrep,
  [switch] $IncludeSecrets,
  [switch] $IncludeDeps,
  [switch] $IncludeIaC,
  [switch] $DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

function Get-ToolBinDir {
  param([string] $Value)
  if ($Value) { return Join-Path $Value "bin" }
  if ($env:BAI_TOOL_ROOT) { return Join-Path $env:BAI_TOOL_ROOT "bin" }
  return Join-Path $env:USERPROFILE "Desktop\codex\tools\bin"
}

function Resolve-Tool {
  param(
    [string] $Name,
    [string] $BinDir
  )
  $binary = if ($env:OS -eq "Windows_NT") { "$Name.exe" } else { $Name }
  $local = Join-Path $BinDir $binary
  if (Test-Path -LiteralPath $local) { return $local }
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return ""
}

function Invoke-Tool {
  param(
    [string] $Exe,
    [string[]] $ExternalArgs,
    [string] $Name,
    [string] $OutFile = "",
    [switch] $Dry
  )
  if (-not $Exe) {
    Write-Host "$Name not found; skipping." -ForegroundColor Yellow
    return [pscustomobject]@{ name = $Name; status = "missing"; output = $OutFile }
  }
  if ($Dry) {
    $suffix = if ($OutFile) { " > $OutFile" } else { "" }
    Write-Host "[dry-run] ${Name}: $Exe $($ExternalArgs -join ' ')$suffix" -ForegroundColor Yellow
    return [pscustomobject]@{ name = $Name; status = "dry_run"; output = $OutFile }
  }
  Write-Host "Running $Name..." -ForegroundColor Cyan
  if ($OutFile) {
    & $Exe @ExternalArgs 2>&1 | Tee-Object -FilePath $OutFile | Out-Null
  } else {
    & $Exe @ExternalArgs
  }
  return [pscustomobject]@{ name = $Name; status = "completed"; output = $OutFile }
}

if (-not (Test-Path -LiteralPath $RepoPath)) {
  throw "Repo path not found: $RepoPath"
}
if (-not ($All -or $IncludeSemgrep -or $IncludeSecrets -or $IncludeDeps -or $IncludeIaC)) {
  $IncludeSemgrep = $true
  $IncludeSecrets = $true
  $IncludeDeps = $true
  $IncludeIaC = $true
}
if ($All) {
  $IncludeSemgrep = $true
  $IncludeSecrets = $true
  $IncludeDeps = $true
  $IncludeIaC = $true
}

$program = if ($ScopeTag) { $ScopeTag } else { Split-Path -Leaf (Resolve-Path -LiteralPath $RepoPath).Path }
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $program -Kind "whitebox-toolchain"
$manifest = Join-Path $runDir "manifest.json"
$casePath = Join-Path $runDir "case.md"
$toolBin = Get-ToolBinDir -Value $ToolRoot

$semgrep = Resolve-Tool -Name "semgrep" -BinDir $toolBin
$gitleaks = Resolve-Tool -Name "gitleaks" -BinDir $toolBin
$trufflehog = Resolve-Tool -Name "trufflehog" -BinDir $toolBin
$trivy = Resolve-Tool -Name "trivy" -BinDir $toolBin
$grype = Resolve-Tool -Name "grype" -BinDir $toolBin
$checkov = Resolve-Tool -Name "checkov" -BinDir $toolBin
$kingfisher = Resolve-Tool -Name "kingfisher" -BinDir $toolBin

$results = @()
$resolvedRepo = (Resolve-Path -LiteralPath $RepoPath).Path

if ($IncludeSemgrep) {
  $rules = Join-Path $root "integrations\semgrep-rules"
  $out = Join-Path $runDir "semgrep.json"
  if (Test-Path -LiteralPath $rules) {
    $results += Invoke-Tool -Exe $semgrep -Name "semgrep" -Dry:$DryRun -ExternalArgs @("--config", $rules, "--json", "--output", $out, "--timeout", "20", "--exclude", "node_modules", "--exclude", "vendor", "--exclude", "dist", "--exclude", "build", $resolvedRepo)
  } else {
    $results += [pscustomobject]@{ name = "semgrep"; status = "missing-rules"; output = $out }
  }
}

if ($IncludeSecrets) {
  $results += Invoke-Tool -Exe $gitleaks -Name "gitleaks" -Dry:$DryRun -ExternalArgs @("detect", "--source", $resolvedRepo, "--report-format", "json", "--report-path", (Join-Path $runDir "gitleaks.json"), "--no-banner")
  $results += Invoke-Tool -Exe $trufflehog -Name "trufflehog" -Dry:$DryRun -OutFile (Join-Path $runDir "trufflehog.jsonl") -ExternalArgs @("filesystem", "--json", "--no-update", $resolvedRepo)
  $results += Invoke-Tool -Exe $kingfisher -Name "kingfisher" -Dry:$DryRun -OutFile (Join-Path $runDir "kingfisher.txt") -ExternalArgs @("scan", $resolvedRepo)
}

if ($IncludeDeps) {
  $results += Invoke-Tool -Exe $trivy -Name "trivy-fs" -Dry:$DryRun -ExternalArgs @("fs", "--format", "json", "--output", (Join-Path $runDir "trivy-fs.json"), "--scanners", "vuln,secret,misconfig", $resolvedRepo)
  $results += Invoke-Tool -Exe $grype -Name "grype-dir" -Dry:$DryRun -ExternalArgs @("dir:$resolvedRepo", "-o", "json", "--file", (Join-Path $runDir "grype.json"))
}

if ($IncludeIaC) {
  $results += Invoke-Tool -Exe $checkov -Name "checkov" -Dry:$DryRun -OutFile (Join-Path $runDir "checkov.json") -ExternalArgs @("-d", $resolvedRepo, "-o", "json", "--quiet")
}

@(
  "# Whitebox Toolchain Case: $program",
  "",
  "- Created: $((Get-Date).ToString('o'))",
  "- Repo path: $resolvedRepo",
  "- Output directory: $runDir",
  "",
  "## Stages",
  "",
  "- Semgrep: source-pattern leads.",
  "- Gitleaks/TruffleHog/Kingfisher: secret exposure leads.",
  "- Trivy/Grype: dependency, container, and filesystem risk leads.",
  "- Checkov: IaC misconfiguration leads.",
  "",
  "Manual review is required before reporting anything from automated output."
) | Set-Content -Path $casePath -Encoding UTF8

[pscustomobject]@{
  type = "whitebox-toolchain"
  createdAt = (Get-Date).ToString("o")
  scopeTag = ConvertTo-SafeName $program
  repoPath = $resolvedRepo
  casePath = Split-Path -Leaf $casePath
  outputRoot = Get-BaiOutputRoot -OutputRoot $OutputRoot
  tools = @{
    semgrep = $semgrep
    gitleaks = $gitleaks
    trufflehog = $trufflehog
    trivy = $trivy
    grype = $grype
    checkov = $checkov
    kingfisher = $kingfisher
  }
  results = $results
  dryRun = [bool]$DryRun
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Whitebox toolchain artifacts saved under: $runDir" -ForegroundColor Green
