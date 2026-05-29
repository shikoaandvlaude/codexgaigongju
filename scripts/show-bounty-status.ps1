param(
  [string] $OutputRoot = "",
  [string] $ToolRoot = "",
  [int] $Recent = 10
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

function Resolve-BountyTool {
  param(
    [string] $Name,
    [string] $BinDir
  )
  $binary = if ($env:OS -eq "Windows_NT") { "$Name.exe" } else { $Name }
  $local = Join-Path $BinDir $binary
  if (Test-Path -LiteralPath $local) { return $local }
  $commands = @(Get-Command $Name -All -ErrorAction SilentlyContinue)
  if ($Name -eq "httpx") {
    $commands = @($commands | Where-Object { $_.Source -notmatch '\\venv\\Scripts\\httpx\.exe$|\\Python\d*\\Scripts\\httpx\.exe$' })
  }
  $preferred = @($commands | Where-Object { $_.Source -match '\\go\\bin\\|\\codex\\tools\\bin\\' } | Select-Object -First 1)
  if ($preferred) { return $preferred.Source }
  if ($commands) { return $commands[0].Source }
  return ""
}

$runsRoot = Get-BaiOutputRoot -OutputRoot $OutputRoot
$toolRootPath = if ($ToolRoot) { $ToolRoot } elseif ($env:BAI_TOOL_ROOT) { $env:BAI_TOOL_ROOT } else { Join-Path $env:USERPROFILE "Desktop\codex\tools" }
$toolBin = Get-ToolBinDir -Value $ToolRoot

$toolNames = @(
  "subfinder", "dnsx", "httpx", "katana", "nuclei",
  "gau", "waybackurls", "arjun", "kiterunner", "interactsh-client",
  "feroxbuster", "dalfox", "xnLinkFinder", "waymore", "uro",
  "ffuf", "naabu", "gitleaks", "trufflehog", "kingfisher",
  "trivy", "grype", "semgrep", "checkov", "cloudfox", "prowler", "scout"
)

$tools = @($toolNames | ForEach-Object {
  $path = Resolve-BountyTool -Name $_ -BinDir $toolBin
  [pscustomobject]@{
    tool = $_
    status = if ($path) { "present" } else { "missing" }
    path = $path
  }
})

$recentRuns = @()
if (Test-Path -LiteralPath $runsRoot) {
  $recentRuns = @(Get-ChildItem -LiteralPath $runsRoot -Recurse -File -Filter "manifest.json" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First $Recent |
    ForEach-Object {
      $manifestPath = $_.FullName
      $manifest = $null
      try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json } catch {}
      [pscustomobject]@{
        createdAt = if ($manifest.createdAt) { $manifest.createdAt } else { $_.LastWriteTime.ToString("o") }
        type = if ($manifest.type) { $manifest.type } else { "unknown" }
        scopeTag = if ($manifest.scopeTag) { $manifest.scopeTag } else { Split-Path -Leaf (Split-Path -Parent $manifestPath) }
        path = Split-Path -Parent $manifestPath
      }
    })
}

Write-Host "Bai bounty status" -ForegroundColor Cyan
Write-Host "Tool repo: $root"
Write-Host "Tool root: $toolRootPath"
Write-Host "Run root:  $runsRoot"
Write-Host ""

Write-Host "Tools" -ForegroundColor Cyan
$tools | Sort-Object status,tool | Format-Table -AutoSize

Write-Host ""
Write-Host "Recent runs" -ForegroundColor Cyan
if ($recentRuns.Count) {
  $recentRuns | Format-Table -AutoSize
} else {
  Write-Host "No run manifests found yet."
}
