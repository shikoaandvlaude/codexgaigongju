param(
  [switch] $SkipNucleiTemplates
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$integrations = Join-Path $root "integrations"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  Write-Host "Git was not found in PATH." -ForegroundColor Red
  exit 1
}

New-Item -ItemType Directory -Path $integrations -Force | Out-Null

function Sync-Repo([string] $Name, [string] $Url) {
  $target = Join-Path $integrations $Name
  if (Test-Path $target) {
    Write-Host "Updating $Name..." -ForegroundColor Cyan
    git -C $target pull --ff-only
  } else {
    Write-Host "Cloning $Name..." -ForegroundColor Cyan
    git clone --depth 1 $Url $target
  }
}

Sync-Repo "semgrep-rules" "https://github.com/semgrep/semgrep-rules.git"

if (-not $SkipNucleiTemplates) {
  Sync-Repo "nuclei-templates" "https://github.com/projectdiscovery/nuclei-templates.git"
}

Write-Host "Bounty integrations are ready." -ForegroundColor Green
