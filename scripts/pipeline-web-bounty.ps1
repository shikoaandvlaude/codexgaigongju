param(
  [string] $Domain = "",
  [string] $TargetsFile = "",
  [string] $ScopeFile = "",
  [string] $OutputRoot = "",
  [string] $ScopeTag = "",
  [string] $ToolRoot = "",
  [ValidateSet("baseline", "tech", "focused", "full")]
  [string] $TemplateProfile = "baseline",
  [int] $RateLimitPerMinute = 60,
  [int] $CrawlDepth = 2,
  [int] $MaxDiscoveryUrls = 80,
  [int] $MaxStageMinutes = 15,
  [string] $ApiRouteWordlist = "",
  [switch] $IncludePassiveUrls,
  [switch] $IncludeApiDiscovery,
  [switch] $IncludeParamDiscovery,
  [switch] $AnalyzeFrontendAssets,
  [switch] $FrontendSecretScan,
  [switch] $PrepareOast,
  [switch] $SkipSubfinder,
  [switch] $SkipGau,
  [switch] $SkipKatana,
  [switch] $SkipNuclei,
  [switch] $AllowNoScope,
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
  $commands = @(Get-Command $Name -All -ErrorAction SilentlyContinue)
  if ($Name -eq "httpx") {
    $commands = @($commands | Where-Object { $_.Source -notmatch '\\venv\\Scripts\\httpx\.exe$|\\Python\d*\\Scripts\\httpx\.exe$' })
  }
  $cmd = @($commands | Where-Object { $_.Source -match '\\go\\bin\\|\\codex\\tools\\bin\\' } | Select-Object -First 1)
  if (-not $cmd) {
    $cmd = @($commands | Select-Object -First 1)
  }
  if ($cmd) { return $cmd.Source }
  return ""
}

function Invoke-External {
  param(
    [string] $Exe,
    [string[]] $ExternalArgs,
    [string] $Name,
    [int] $TimeoutSeconds = 0,
    [switch] $Dry
  )
  if ($Dry) {
    Write-Host "[dry-run] ${Name}: $Exe $($ExternalArgs -join ' ')" -ForegroundColor Yellow
    return
  }
  Write-Host "Running $Name..." -ForegroundColor Cyan
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo.FileName = $Exe
  $process.StartInfo.Arguments = Join-ProcessArguments -Values $ExternalArgs
  $process.StartInfo.UseShellExecute = $false
  [void]$process.Start()
  if ($TimeoutSeconds -gt 0) {
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      try { $process.Kill($true) } catch { try { $process.Kill() } catch {} }
      $script:stageIssues += "${Name}:timeout-after-${TimeoutSeconds}s"
      Write-Host "$Name timed out after $TimeoutSeconds seconds; continuing with partial artifacts." -ForegroundColor Yellow
      return
    }
  } else {
    $process.WaitForExit()
  }
  if ($process.ExitCode -ne 0) {
    $script:stageIssues += "${Name}:exit-$($process.ExitCode)"
    Write-Host "$Name exited with code $($process.ExitCode); continuing so artifacts can be reviewed." -ForegroundColor Yellow
  }
}

function Join-ProcessArguments {
  param([string[]] $Values)
  return (($Values | ForEach-Object {
    $value = [string]$_
    if ($value -notmatch '[\s"]') {
      $value
    } else {
      '"' + ($value -replace '"', '\"') + '"'
    }
  }) -join " ")
}

function Invoke-ExternalToFile {
  param(
    [string] $Exe,
    [string[]] $ExternalArgs,
    [string] $Name,
    [string] $OutFile,
    [int] $TimeoutSeconds = 0,
    [switch] $Dry
  )
  if ($Dry) {
    Write-Host "[dry-run] ${Name}: $Exe $($ExternalArgs -join ' ') > $OutFile" -ForegroundColor Yellow
    return
  }
  Write-Host "Running $Name..." -ForegroundColor Cyan
  $stderr = "$OutFile.stderr.txt"
  $argLine = Join-ProcessArguments -Values $ExternalArgs
  $process = Start-Process -FilePath $Exe -ArgumentList $argLine -NoNewWindow -PassThru -RedirectStandardOutput $OutFile -RedirectStandardError $stderr
  if ($TimeoutSeconds -gt 0) {
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      try { $process.Kill($true) } catch { try { $process.Kill() } catch {} }
      $script:stageIssues += "${Name}:timeout-after-${TimeoutSeconds}s"
      Write-Host "$Name timed out after $TimeoutSeconds seconds; continuing with partial artifacts." -ForegroundColor Yellow
      return
    }
  } else {
    $process.WaitForExit()
  }
  if ($process.ExitCode -ne 0) {
    $script:stageIssues += "${Name}:exit-$($process.ExitCode)"
    Write-Host "$Name exited with code $($process.ExitCode); continuing so artifacts can be reviewed." -ForegroundColor Yellow
  }
}

function Convert-HttpxJsonToUrls {
  param(
    [string] $JsonlPath,
    [string] $OutPath
  )
  $urls = @()
  if (Test-Path -LiteralPath $JsonlPath) {
    foreach ($line in Get-Content -LiteralPath $JsonlPath) {
      if (-not $line.Trim()) { continue }
      try {
        $row = $line | ConvertFrom-Json
        if ($row.url) { $urls += $row.url }
        elseif ($row.input) { $urls += $row.input }
      } catch {}
    }
  }
  $urls = @($urls | Where-Object { $_ } | Sort-Object -Unique)
  $urls | Set-Content -Path $OutPath -Encoding ASCII
  return $urls
}

function Convert-KatanaJsonToUrls {
  param(
    [string] $JsonlPath,
    [string] $OutPath
  )
  $urls = @()
  if (Test-Path -LiteralPath $JsonlPath) {
    foreach ($line in Get-Content -LiteralPath $JsonlPath) {
      if (-not $line.Trim()) { continue }
      try {
        $row = $line | ConvertFrom-Json
        if ($row.request.endpoint) { $urls += $row.request.endpoint }
        elseif ($row.url) { $urls += $row.url }
      } catch {}
    }
  }
  $urls = @($urls | Where-Object { $_ } | Sort-Object -Unique)
  $urls | Set-Content -Path $OutPath -Encoding ASCII
  return $urls
}

function Select-ScopedUrls {
  param(
    [string[]] $Urls,
    [object] $Policy,
    [switch] $AllowNoScope
  )
  return @($Urls | Where-Object {
    $url = $_
    if (-not $url) {
      $false
    } elseif ($AllowNoScope -and -not $Policy) {
      $true
    } else {
      $scope = Test-BaiTargetScope -Target $url -Policy $Policy
      $scope.allowed
    }
  } | Sort-Object -Unique)
}

function New-DiscoverySubset {
  param(
    [string] $InputFile,
    [string] $OutputFile,
    [int] $MaxItems
  )
  $items = @()
  if (Test-Path -LiteralPath $InputFile) {
    $items = @(Get-Content -LiteralPath $InputFile | Where-Object { $_ } | Select-Object -First $MaxItems)
  }
  $items | Set-Content -Path $OutputFile -Encoding ASCII
  return $items
}

if (-not $Domain -and -not $TargetsFile) {
  throw "Pass -Domain, -TargetsFile, or both."
}
if ($TargetsFile -and -not (Test-Path -LiteralPath $TargetsFile)) {
  throw "Targets file not found: $TargetsFile"
}

$policy = Read-BaiScopePolicy -ScopeFile $ScopeFile
if (-not $policy -and -not $AllowNoScope) {
  throw "Refusing to run without a scope file. Pass -ScopeFile or explicitly use -AllowNoScope for local/lab testing."
}

$program = if ($ScopeTag) { $ScopeTag } elseif ($policy -and $policy.program) { $policy.program } elseif ($Domain) { $Domain } else { [System.IO.Path]::GetFileNameWithoutExtension($TargetsFile) }
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $program -Kind "web-pipeline"
$manifest = Join-Path $runDir "manifest.json"
$rawTargets = Join-Path $runDir "raw-targets.txt"
$subdomains = Join-Path $runDir "subfinder.txt"
$dnsxOut = Join-Path $runDir "dnsx.jsonl"
$httpxOut = Join-Path $runDir "httpx.jsonl"
$liveUrls = Join-Path $runDir "live-urls.txt"
$katanaOut = Join-Path $runDir "katana.jsonl"
$katanaUrls = Join-Path $runDir "katana-urls.txt"
$passiveUrls = Join-Path $runDir "passive-urls.txt"
$urlCandidates = Join-Path $runDir "url-candidates.txt"
$discoveryUrls = Join-Path $runDir "discovery-urls.txt"
$apiDiscoveryOut = Join-Path $runDir "kiterunner-output.txt"
$apiDiscoveryPlan = Join-Path $runDir "api-discovery-plan.md"
$arjunOut = Join-Path $runDir "arjun-params.json"
$oastPlan = Join-Path $runDir "oast-plan.md"
$nucleiOut = Join-Path $runDir "nuclei-results.jsonl"
$frontendOut = Join-Path $runDir "frontend-assets"
$skippedStages = @()
$stageIssues = @()
$stageTimeoutSeconds = [Math]::Max(60, $MaxStageMinutes * 60)

$toolBin = Get-ToolBinDir -Value $ToolRoot
$subfinder = Resolve-Tool -Name "subfinder" -BinDir $toolBin
$dnsx = Resolve-Tool -Name "dnsx" -BinDir $toolBin
$httpx = Resolve-Tool -Name "httpx" -BinDir $toolBin
$katana = Resolve-Tool -Name "katana" -BinDir $toolBin
$nuclei = Resolve-Tool -Name "nuclei" -BinDir $toolBin
$gau = Resolve-Tool -Name "gau" -BinDir $toolBin
$kr = Resolve-Tool -Name "kr" -BinDir $toolBin
if (-not $kr) {
  $kr = Resolve-Tool -Name "kiterunner" -BinDir $toolBin
}
$arjun = Resolve-Tool -Name "arjun" -BinDir $toolBin
$interactsh = Resolve-Tool -Name "interactsh-client" -BinDir $toolBin

$seedTargets = @()
if ($TargetsFile) {
  $seedTargets += Get-Content -LiteralPath $TargetsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
}
if ($Domain) {
  $seedTargets += $Domain
}

$seedTargets = @($seedTargets | Where-Object { $_ } | Sort-Object -Unique)
$seedTargets | Set-Content -Path $rawTargets -Encoding ASCII

$seedPreflight = Invoke-BaiScopePreflight -TargetsFile $rawTargets -Policy $policy -RunDir $runDir -AllowNoScope:$AllowNoScope
if (@($seedPreflight.allowed).Count -eq 0 -and -not ($AllowNoScope -and -not $policy)) {
  New-BaiCaseReport -RunDir $runDir -Program $program -Kind "web-pipeline" -Policy $policy -Preflight $seedPreflight -Notes "No seed targets passed scope validation. Passive discovery was not started." | Out-Null
  throw "No seed targets passed scope validation. See $runDir"
}

if ($Domain -and -not $SkipSubfinder -and $subfinder) {
  Invoke-External -Exe $subfinder -Name "subfinder" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @("-d", $Domain, "-all", "-silent", "-o", $subdomains)
  if ((Test-Path -LiteralPath $subdomains) -and -not $DryRun) {
    $seedTargets += Get-Content -LiteralPath $subdomains | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  }
} elseif ($Domain -and -not $SkipSubfinder) {
  Write-Host "subfinder not found; continuing with seed domain only." -ForegroundColor Yellow
}

if ($Domain -and $IncludePassiveUrls -and -not $SkipGau) {
  if ($gau) {
    Invoke-External -Exe $gau -Name "gau" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @(
      "--subs",
      "--threads", "5",
      "--timeout", "20",
      "--providers", "wayback,commoncrawl,otx,urlscan",
      "--o", $passiveUrls,
      $Domain
    )
  } else {
    Write-Host "gau not found; skipping passive URL collection." -ForegroundColor Yellow
  }
}

$seedTargets = @($seedTargets | Where-Object { $_ } | Sort-Object -Unique)
$seedTargets | Set-Content -Path $rawTargets -Encoding ASCII

$preflight = Invoke-BaiScopePreflight -TargetsFile $rawTargets -Policy $policy -RunDir $runDir -AllowNoScope:$AllowNoScope
if (@($preflight.allowed).Count -eq 0 -and -not ($AllowNoScope -and -not $policy)) {
  New-BaiCaseReport -RunDir $runDir -Program $program -Kind "web-pipeline" -Policy $policy -Preflight $preflight -Notes "No targets passed scope validation. Nothing was scanned." | Out-Null
  throw "No targets passed scope validation. See $runDir"
}

$ua = if ($policy -and $policy.userAgent) { $policy.userAgent } else { "BaiCodeAgent-HackerOne" }
$policyRate = if ($policy -and $policy.maxRequestsPerMinutePerHost) { [int]$policy.maxRequestsPerMinutePerHost } else { $RateLimitPerMinute }
if ($RateLimitPerMinute -gt $policyRate) {
  Write-Host "Lowering requested rate from $RateLimitPerMinute/min to policy limit $policyRate/min." -ForegroundColor Yellow
  $RateLimitPerMinute = $policyRate
}
$perSecond = [Math]::Max(1, [Math]::Floor($RateLimitPerMinute / 60))
$delaySeconds = [Math]::Max(1, [Math]::Ceiling(60 / [double]$RateLimitPerMinute))

if ($dnsx) {
  Invoke-External -Exe $dnsx -Name "dnsx" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @("-l", $preflight.validatedFile, "-a", "-aaaa", "-resp", "-json", "-silent", "-o", $dnsxOut)
} else {
  Write-Host "dnsx not found; DoH preflight from SecurityScanCommon was still written." -ForegroundColor Yellow
}

if (-not $httpx) {
  throw "httpx not found. Run scripts\install-web-bounty-tools.ps1 -Install first."
}
Invoke-External -Exe $httpx -Name "httpx" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @(
  "-l", $preflight.validatedFile,
  "-silent",
  "-json",
  "-status-code",
  "-title",
  "-tech-detect",
  "-follow-host-redirects",
  "-H", "User-Agent: $ua",
  "-rlm", "$RateLimitPerMinute",
  "-threads", "1",
  "-o", $httpxOut
)

if (-not $DryRun) {
  $liveUrlRows = @(Convert-HttpxJsonToUrls -JsonlPath $httpxOut -OutPath $liveUrls)
} else {
  $preflight.allowed | ForEach-Object { $_.target } | Set-Content -Path $liveUrls -Encoding ASCII
  $liveUrlRows = @($preflight.allowed | ForEach-Object { $_.target })
}

if (@($liveUrlRows).Count -eq 0) {
  $skippedStages += "katana:no-live-urls"
  $skippedStages += "arjun:no-live-urls"
  $skippedStages += "kiterunner:no-live-urls"
  $skippedStages += "nuclei:no-live-urls"
}

if (-not $SkipKatana -and @($liveUrlRows).Count -gt 0) {
  if ($katana) {
    Invoke-External -Exe $katana -Name "katana" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @(
      "-list", $liveUrls,
      "-depth", "$CrawlDepth",
      "-field-scope", "fqdn",
      "-known-files", "robotstxt,sitemapxml",
      "-H", "User-Agent: $ua",
      "-rate-limit-minute", "$RateLimitPerMinute",
      "-concurrency", "1",
      "-parallelism", "1",
      "-jsonl",
      "-o", $katanaOut
    )
    if (-not $DryRun) {
      Convert-KatanaJsonToUrls -JsonlPath $katanaOut -OutPath $katanaUrls | Out-Null
    }
  } else {
    Write-Host "katana not found; skipping crawl." -ForegroundColor Yellow
  }
}

$candidateUrls = @()
foreach ($file in @($liveUrls, $katanaUrls, $passiveUrls)) {
  if (Test-Path -LiteralPath $file) {
    $candidateUrls += Get-Content -LiteralPath $file | Where-Object { $_ }
  }
}
$candidateUrls = Select-ScopedUrls -Urls $candidateUrls -Policy $policy -AllowNoScope:$AllowNoScope
$candidateUrls | Set-Content -Path $urlCandidates -Encoding ASCII
$discoveryRows = @(New-DiscoverySubset -InputFile $urlCandidates -OutputFile $discoveryUrls -MaxItems $MaxDiscoveryUrls)

if ($IncludeParamDiscovery) {
  if (@($discoveryRows).Count -eq 0) {
    $skippedStages += "arjun:no-discovery-urls"
    Write-Host "No discovery URLs available; skipping parameter discovery." -ForegroundColor Yellow
  } elseif ($arjun) {
    Invoke-External -Exe $arjun -Name "arjun" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @(
      "-i", $discoveryUrls,
      "-oJ", $arjunOut,
      "-m", "GET",
      "-t", "1",
      "-d", "$delaySeconds",
      "--rate-limit", "1",
      "--stable",
      "--headers", "User-Agent: $ua"
    )
  } else {
    Write-Host "arjun not found; skipping parameter discovery." -ForegroundColor Yellow
  }
}

if ($IncludeApiDiscovery) {
  $planLines = @(
    "# API Discovery Plan",
    "",
    "- Created: $((Get-Date).ToString('o'))",
    "- Input URLs: $discoveryUrls",
    "- Tool: Kiterunner (`kiterunner` or `kr`)",
    "- Wordlist: $(if ($ApiRouteWordlist) { $ApiRouteWordlist } else { 'not provided' })",
    "",
    "Kiterunner can generate many requests. Use it only when the program allows active API discovery, keep concurrency low, and prefer a small `.kite` route wordlist."
  )
  $planLines | Set-Content -Path $apiDiscoveryPlan -Encoding UTF8
  if (@($discoveryRows).Count -eq 0) {
    $skippedStages += "kiterunner:no-discovery-urls"
    Write-Host "No discovery URLs available; Kiterunner plan only." -ForegroundColor Yellow
  } elseif ($kr -and $ApiRouteWordlist -and (Test-Path -LiteralPath $ApiRouteWordlist)) {
    Invoke-ExternalToFile -Exe $kr -Name "kiterunner" -Dry:$DryRun -OutFile $apiDiscoveryOut -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs @(
      "scan",
      $discoveryUrls,
      "-w", $ApiRouteWordlist,
      "-x", "1",
      "-j", "1"
    )
  } else {
    Write-Host "Kiterunner plan written; install kiterunner/kr and pass -ApiRouteWordlist to execute it." -ForegroundColor Yellow
  }
}

if ($PrepareOast) {
  $interactshPathForPlan = if ($interactsh) { $interactsh } else { "not found" }
  @(
    "# OAST Plan",
    "",
    "- Created: $((Get-Date).ToString('o'))",
    "- Tool: interactsh-client",
    "- Resolved path: $interactshPathForPlan",
    "",
    "Use OAST only when the bounty program explicitly allows out-of-band testing. Keep payloads in your own test objects and do not target customer data.",
    "",
    "Suggested command:",
    "",
    '```powershell',
    "interactsh-client -json -o <run-dir>\interactsh-events.jsonl",
    '```'
  ) | Set-Content -Path $oastPlan -Encoding UTF8
}

if ($AnalyzeFrontendAssets) {
  $frontendScript = Join-Path $root "scripts\analyze-frontend-assets.ps1"
  if (@($liveUrlRows).Count -eq 0) {
    $skippedStages += "frontend-assets:no-live-urls"
    Write-Host "No live URLs available; skipping frontend asset analysis." -ForegroundColor Yellow
  } elseif (Test-Path -LiteralPath $frontendScript) {
    $frontendArgs = @{
      Program = $program
      UrlsFile = $liveUrls
      ScopeFile = $ScopeFile
      OutputDirectory = $frontendOut
      RateLimitPerMinute = $RateLimitPerMinute
      MaxPages = $MaxDiscoveryUrls
      MaxAssets = 80
      DryRun = $DryRun
    }
    if ($AllowNoScope) { $frontendArgs.AllowNoScope = $true }
    if ($FrontendSecretScan) { $frontendArgs.SecretScan = $true }
    & $frontendScript @frontendArgs
  } else {
    $skippedStages += "frontend-assets:script-missing"
  }
}

if (-not $SkipNuclei -and @($liveUrlRows).Count -gt 0) {
  if (-not $nuclei) {
    throw "nuclei not found. Run scripts\install-web-bounty-tools.ps1 -Install first."
  }
  $templates = Join-Path $root "integrations\nuclei-templates"
  if (-not (Test-Path -LiteralPath $templates)) {
    throw "Nuclei templates are missing. Run scripts\update-bounty-integrations.ps1 first."
  }
  $templatePaths = @(Get-NucleiTemplatePaths -TemplateRoot $templates -Profile $TemplateProfile)
  $templateArgs = @()
  foreach ($templatePath in $templatePaths) {
    $templateArgs += @("-t", $templatePath)
  }
  $excludeTags = @("dos", "fuzz", "bruteforce", "default-login", "credential-stuffing", "intrusive", "xss", "csrf", "open-redirect", "redirect", "takeover")
  if ($policy -and $policy.excludeTags) { $excludeTags += @($policy.excludeTags) }
  $excludeTags = @($excludeTags | Sort-Object -Unique)
  $nucleiArgs = @("-l", $liveUrls) + $templateArgs + @(
    "-severity", "info,low,medium,high,critical",
    "-etags", ($excludeTags -join ","),
    "-H", "User-Agent: $ua",
    "-rl", "$RateLimitPerMinute",
    "-rld", "1m",
    "-c", "1",
    "-bs", "1",
    "-timeout", "8",
    "-retries", "0",
    "-jsonl",
    "-o", $nucleiOut
  )
  Invoke-External -Exe $nuclei -Name "nuclei" -Dry:$DryRun -TimeoutSeconds $stageTimeoutSeconds -ExternalArgs $nucleiArgs
} elseif (-not $SkipNuclei) {
  Write-Host "No live URLs available; skipping nuclei." -ForegroundColor Yellow
}

$casePath = New-BaiCaseReport `
  -RunDir $runDir `
  -Program $program `
  -Kind "web-pipeline" `
  -Policy $policy `
  -Preflight $preflight `
  -ResultsPath $nucleiOut `
  -Notes "Pipeline stages: subfinder -> optional gau -> scope/DoH preflight -> dnsx -> httpx -> katana -> optional arjun/kiterunner/OAST plan -> nuclei baseline. Automated hits are leads until manual impact is confirmed."

[pscustomobject]@{
  type = "web-pipeline"
  createdAt = (Get-Date).ToString("o")
  scopeTag = ConvertTo-SafeName $program
  domain = $Domain
  targetsFile = $TargetsFile
  rawTargets = Split-Path -Leaf $rawTargets
  validatedTargets = Split-Path -Leaf $preflight.validatedFile
  rejectedTargets = Split-Path -Leaf $preflight.rejectedFile
  dnsPreflight = Split-Path -Leaf $preflight.dnsFile
  subfinder = Split-Path -Leaf $subdomains
  dnsx = Split-Path -Leaf $dnsxOut
  httpx = Split-Path -Leaf $httpxOut
  liveUrls = Split-Path -Leaf $liveUrls
  katana = Split-Path -Leaf $katanaOut
  katanaUrls = Split-Path -Leaf $katanaUrls
  passiveUrls = Split-Path -Leaf $passiveUrls
  urlCandidates = Split-Path -Leaf $urlCandidates
  discoveryUrls = Split-Path -Leaf $discoveryUrls
  apiDiscoveryOutput = Split-Path -Leaf $apiDiscoveryOut
  apiDiscoveryPlan = Split-Path -Leaf $apiDiscoveryPlan
  arjunParams = Split-Path -Leaf $arjunOut
  oastPlan = Split-Path -Leaf $oastPlan
  frontendAssets = Split-Path -Leaf $frontendOut
  nucleiResults = Split-Path -Leaf $nucleiOut
  casePath = Split-Path -Leaf $casePath
  templateProfile = $TemplateProfile
  rateLimitPerMinute = $RateLimitPerMinute
  crawlDepth = $CrawlDepth
  maxDiscoveryUrls = $MaxDiscoveryUrls
  includePassiveUrls = [bool]$IncludePassiveUrls
  includeApiDiscovery = [bool]$IncludeApiDiscovery
  includeParamDiscovery = [bool]$IncludeParamDiscovery
  analyzeFrontendAssets = [bool]$AnalyzeFrontendAssets
  frontendSecretScan = [bool]$FrontendSecretScan
  prepareOast = [bool]$PrepareOast
  skippedStages = $skippedStages
  stageIssues = $stageIssues
  maxStageMinutes = $MaxStageMinutes
  userAgent = $ua
  toolBin = $toolBin
  tools = @{
    subfinder = $subfinder
    dnsx = $dnsx
    httpx = $httpx
    katana = $katana
    nuclei = $nuclei
    gau = $gau
    kr = $kr
    arjun = $arjun
    interactshClient = $interactsh
  }
  dryRun = [bool]$DryRun
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Web bounty pipeline artifacts saved under: $runDir" -ForegroundColor Green
