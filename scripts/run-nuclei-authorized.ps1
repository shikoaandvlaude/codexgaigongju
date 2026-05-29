param(
  [Parameter(Mandatory = $true)]
  [string] $TargetsFile,

  [string] $ScopeFile = "",
  [string] $OutputRoot = "",
  [string] $OutputName = "",
  [string] $ScopeTag = "",
  [string] $Severity = "info,low,medium,high,critical",
  [ValidateSet("baseline", "tech", "focused", "full")]
  [string] $TemplateProfile = "baseline",
  [int] $RateLimitPerMinute = 60,
  [switch] $AllowNoScope,
  [switch] $DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

$templates = Join-Path $root "integrations\nuclei-templates"
if (-not (Test-Path -LiteralPath $TargetsFile)) {
  Write-Host "Targets file not found: $TargetsFile" -ForegroundColor Red
  exit 1
}
if (-not (Test-Path -LiteralPath $templates)) {
  Write-Host "Nuclei templates are missing. Run scripts\update-bounty-integrations.ps1 first." -ForegroundColor Red
  exit 1
}
if (-not $DryRun -and -not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
  Write-Host "Nuclei was not found in PATH." -ForegroundColor Red
  exit 1
}

$policy = Read-BaiScopePolicy -ScopeFile $ScopeFile
$program = if ($ScopeTag) { $ScopeTag } elseif ($policy -and $policy.program) { $policy.program } else { [System.IO.Path]::GetFileNameWithoutExtension($TargetsFile) }
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $program -Kind "nuclei-$TemplateProfile"

$preflight = Invoke-BaiScopePreflight `
  -TargetsFile $TargetsFile `
  -Policy $policy `
  -RunDir $runDir `
  -AllowNoScope:$AllowNoScope

if (@($preflight.allowed).Count -eq 0 -and -not ($AllowNoScope -and -not $policy)) {
  New-BaiCaseReport -RunDir $runDir -Program $program -Kind "nuclei-$TemplateProfile" -Policy $policy -Preflight $preflight -Notes "No targets passed scope validation. Nothing was scanned." | Out-Null
  Write-Host "No targets passed scope validation. See $runDir" -ForegroundColor Yellow
  exit 1
}

if (-not $OutputName) {
  $OutputName = "results.jsonl"
}

$output = Join-Path $runDir $OutputName
$manifest = Join-Path $runDir "manifest.json"
$templatePaths = @(Get-NucleiTemplatePaths -TemplateRoot $templates -Profile $TemplateProfile)
if (-not $templatePaths.Count) {
  throw "No templates resolved for profile '$TemplateProfile'."
}

$ua = if ($policy -and $policy.userAgent) { $policy.userAgent } else { "BaiCodeAgent-HackerOne" }
$policyRate = if ($policy -and $policy.maxRequestsPerMinutePerHost) { [int]$policy.maxRequestsPerMinutePerHost } else { $RateLimitPerMinute }
if ($RateLimitPerMinute -gt $policyRate) {
  Write-Host "Lowering requested rate from $RateLimitPerMinute/min to policy limit $policyRate/min." -ForegroundColor Yellow
  $RateLimitPerMinute = $policyRate
}

$excludeTags = @("dos", "fuzz", "bruteforce", "default-login", "credential-stuffing", "intrusive", "xss", "csrf", "open-redirect", "redirect", "takeover")
if ($policy -and $policy.excludeTags) {
  $excludeTags += @($policy.excludeTags)
}
$excludeTags = $excludeTags | Sort-Object -Unique

$casePath = New-BaiCaseReport `
  -RunDir $runDir `
  -Program $program `
  -Kind "nuclei-$TemplateProfile" `
  -Policy $policy `
  -Preflight $preflight `
  -ResultsPath $output `
  -Notes "Profile '$TemplateProfile' uses layered templates. Treat output as leads until impact is manually verified."

Write-Host "Authorized nuclei run prepared." -ForegroundColor Cyan
Write-Host "Run directory: $runDir"
Write-Host "Case report: $casePath"
Write-Host "Validated targets: $($preflight.validatedFile)"
Write-Host "Template profile: $TemplateProfile"
Write-Host "Rate: $RateLimitPerMinute requests/minute"
Write-Host "User-Agent: $ua"

if ($DryRun) {
  Write-Host "Dry run requested; nuclei was not executed." -ForegroundColor Yellow
} else {
  $templateArgs = @()
  foreach ($templatePath in $templatePaths) {
    $templateArgs += @("-t", $templatePath)
  }

  nuclei `
    -l $preflight.validatedFile `
    @templateArgs `
    -severity $Severity `
    -etags ($excludeTags -join ",") `
    -H "User-Agent: $ua" `
    -rl $RateLimitPerMinute `
    -rld "1m" `
    -c 1 `
    -bs 1 `
    -timeout 8 `
    -retries 0 `
    -jsonl `
    -o $output
}

@{
  type = "nuclei"
  createdAt = (Get-Date).ToString("o")
  sourceLabel = "nuclei:$TemplateProfile"
  scopeTag = ConvertTo-SafeName $program
  targetFile = (Resolve-Path -LiteralPath $TargetsFile).Path
  validatedTargetFile = $preflight.validatedFile
  rejectedTargetsPath = Split-Path -Leaf $preflight.rejectedFile
  dnsPreflightPath = Split-Path -Leaf $preflight.dnsFile
  targetLabel = ConvertTo-SafeName $program
  resultsPath = Split-Path -Leaf $output
  casePath = Split-Path -Leaf $casePath
  severity = $Severity
  rateLimitPerMinute = $RateLimitPerMinute
  templateProfile = $TemplateProfile
  templates = $templatePaths
  excludeTags = $excludeTags
  userAgent = $ua
  findingStatuses = @("lead", "candidate", "verified", "not_reportable", "out_of_scope")
  outputRoot = (Get-BaiOutputRoot -OutputRoot $OutputRoot)
  dryRun = [bool]$DryRun
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Nuclei artifacts saved under: $runDir" -ForegroundColor Green
