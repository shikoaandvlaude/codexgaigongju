param(
  [string] $Program = "frontend",
  [string] $UrlsFile = "",
  [string[]] $Urls = @(),
  [string] $ScopeFile = "",
  [string] $OutputRoot = "",
  [string] $OutputDirectory = "",
  [string] $ToolRoot = "",
  [int] $RateLimitPerMinute = 30,
  [int] $MaxPages = 20,
  [int] $MaxAssets = 80,
  [int] $MaxAssetBytes = 7000000,
  [int] $SecretScanTimeoutSeconds = 60,
  [switch] $SecretScan,
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
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return ""
}

function Get-UrlFileName {
  param(
    [string] $Url,
    [string] $Suffix = ""
  )
  try {
    $uri = [uri]$Url
    $path = $uri.AbsolutePath
    if (-not $path -or $path -eq "/") { $path = "index" }
    $name = "$($uri.Host)$($path -replace '/', '_')"
  } catch {
    $name = $Url
  }
  $safe = ConvertTo-SafeName $name
  if ($safe.Length -gt 140) { $safe = $safe.Substring(0, 140) }
  if ($Suffix) { return "$safe.$Suffix" }
  return $safe
}

function Get-HeaderValue {
  param(
    [string] $HeadersFile,
    [string] $Name
  )
  if (-not (Test-Path -LiteralPath $HeadersFile)) { return "" }
  $pattern = "^$([regex]::Escape($Name))\s*:\s*(.+)$"
  $line = Get-Content -LiteralPath $HeadersFile | Where-Object { $_ -match $pattern } | Select-Object -Last 1
  if ($line -and $line -match $pattern) { return $Matches[1].Trim() }
  return ""
}

function Get-StatusCode {
  param([string] $HeadersFile)
  if (-not (Test-Path -LiteralPath $HeadersFile)) { return "" }
  $line = Get-Content -LiteralPath $HeadersFile | Where-Object { $_ -match '^HTTP/' } | Select-Object -Last 1
  if ($line -and $line -match '^HTTP/\S+\s+(\d+)') { return $Matches[1] }
  return ""
}

function Invoke-CurlDownload {
  param(
    [string] $Url,
    [string] $BodyFile,
    [string] $HeadersFile,
    [string] $UserAgent,
    [int] $MaxBytes
  )
  if ($DryRun) {
    Write-Host "[dry-run] curl $Url -> $BodyFile" -ForegroundColor Yellow
    return [pscustomobject]@{ url = $Url; status = "dry-run"; contentType = ""; size = 0; exitCode = 0; bodyFile = $BodyFile; headersFile = $HeadersFile }
  }
  & curl.exe -sS -L --max-time 25 --max-filesize $MaxBytes -A $UserAgent -D $HeadersFile -o $BodyFile $Url 2>$null
  $exit = $LASTEXITCODE
  $size = if (Test-Path -LiteralPath $BodyFile) { (Get-Item -LiteralPath $BodyFile).Length } else { 0 }
  return [pscustomobject]@{
    url = $Url
    status = Get-StatusCode -HeadersFile $HeadersFile
    contentType = Get-HeaderValue -HeadersFile $HeadersFile -Name "content-type"
    size = $size
    exitCode = $exit
    bodyFile = Split-Path -Leaf $BodyFile
    headersFile = Split-Path -Leaf $HeadersFile
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

function Invoke-ToolToFile {
  param(
    [string] $Exe,
    [string[]] $ExternalArgs,
    [string] $StdoutFile = "",
    [string] $StderrFile = "",
    [int] $TimeoutSeconds = 60
  )
  $argLine = Join-ProcessArguments -Values $ExternalArgs
  $startArgs = @{
    FilePath = $Exe
    ArgumentList = $argLine
    NoNewWindow = $true
    PassThru = $true
  }
  if ($StdoutFile) { $startArgs.RedirectStandardOutput = $StdoutFile }
  if ($StderrFile) { $startArgs.RedirectStandardError = $StderrFile }
  $process = Start-Process @startArgs
  if ($TimeoutSeconds -gt 0) {
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
      try { $process.Kill($true) } catch { try { $process.Kill() } catch {} }
      if ($StderrFile) {
        "Timed out after $TimeoutSeconds seconds." | Add-Content -Path $StderrFile -Encoding UTF8
      }
      return -999
    }
  } else {
    $process.WaitForExit()
  }
  try { $process.Refresh() } catch {}
  if ($process.HasExited) {
    return [int]$process.ExitCode
  }
  return -998
}

function Resolve-AssetUrl {
  param(
    [string] $BaseUrl,
    [string] $Asset
  )
  if (-not $Asset) { return "" }
  if ($Asset -match '^(data:|mailto:|tel:|javascript:)') { return "" }
  try {
    $baseUri = [uri]$BaseUrl
    return ([uri]::new($baseUri, $Asset)).AbsoluteUri
  } catch {
    return ""
  }
}

function Select-ScopedItems {
  param([string[]] $Items)
  return @($Items | Where-Object {
    $item = $_
    if (-not $item) {
      $false
    } elseif ($AllowNoScope -and -not $policy) {
      $true
    } else {
      (Test-BaiTargetScope -Target $item -Policy $policy).allowed
    }
  } | Sort-Object -Unique)
}

function Get-TextMatches {
  param(
    [string] $Text,
    [string] $Pattern
  )
  if (-not $Text) { return @() }
  return @([regex]::Matches($Text, $Pattern) | ForEach-Object {
    if ($_.Groups["value"].Success) { $_.Groups["value"].Value } else { $_.Value }
  })
}

function Get-EndpointScore {
  param(
    [string] $Value,
    [string] $FileName = ""
  )
  $v = $Value.ToLowerInvariant()
  $file = $FileName.ToLowerInvariant()
  $score = 0
  $reasons = @()
  if ($v -match '(^|[\/{:_-])(account|accounts|github-account|organization|organizations|orgs|owner|repo|repos|repository|repositories|installation|installations|tenant)([\/}:_-]|$)') { $score += 3; $reasons += "object-scope" }
  if ($v -match '(^|[\/{:_-])(role|roles|permission|permissions|billing|subscription|admin|token|tokens|secret|secrets|key|keys|webhook|webhooks|config|ci|pull|pulls|job|jobs|user|users)([\/}:_-]|$)') { $score += 2; $reasons += "sensitive-action-or-data" }
  if ($v -match '\{|\$\{|:[a-z_]+|/[0-9]+') { $score += 2; $reasons += "variable-object-id" }
  if ($v -match '^https?://[^/]*api\.|/v[0-9]+/') { $score += 1; $reasons += "api-route" }
  if ($v -match 'w3\.org|xmlsoap|static|assets|favicon|\.css|\.png|\.svg|\.jpg|\.jpeg|\.ico|\.woff|\.map|logout') { $score -= 3; $reasons += "likely-static" }
  if ($file -match 'octokit|graphql|highlight|lodash|mui|fortawesome|radix|tanstack|emojilib|showdown' -and $v -notmatch 'mergify|^/front|^/api|/v[0-9]+/ci|/v[0-9]+/repos') {
    $score -= 4
    $reasons += "third-party-library"
  }
  if ($file -match 'octokit' -and $v -match '^/(orgs|repos|users|user|teams|enterprises)/') {
    $score = 0
    $reasons += "github-sdk-route"
  }
  if ($score -lt 0) { $score = 0 }
  return [pscustomobject]@{
    score = $score
    status = if ($score -ge 5) { "candidate" } elseif ($score -ge 2) { "lead" } else { "info" }
    reasons = @($reasons | Sort-Object -Unique)
  }
}

function Get-TokenContexts {
  param(
    [string] $Text,
    [string] $FileName
  )
  $rows = @()
  if (-not $Text) { return $rows }
  $pattern = '(?i)(api[_-]?key|client[_-]?token|token|dsn|sentry|datadog|authorization|bearer|secret|password)'
  foreach ($match in [regex]::Matches($Text, $pattern)) {
    $start = [Math]::Max(0, $match.Index - 120)
    $length = [Math]::Min(260, $Text.Length - $start)
    $context = $Text.Substring($start, $length) -replace '\s+', ' '
    $context = $context -replace '(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+', '$1<redacted>'
    $context = $context -replace '(?i)(cookie\s*[:=]\s*)[^;,"]+', '$1<redacted>'
    $rows += [pscustomobject]@{
      file = $FileName
      keyword = $match.Value
      context = $context
    }
  }
  return @($rows | Select-Object -First 60)
}

$policy = Read-BaiScopePolicy -ScopeFile $ScopeFile
if (-not $policy -and -not $AllowNoScope) {
  throw "Refusing to analyze remote assets without a scope file. Pass -ScopeFile or use -AllowNoScope for local/lab analysis."
}

$ua = if ($policy -and $policy.userAgent) { $policy.userAgent } else { "BaiCodeAgent-HackerOne" }
$policyRate = if ($policy -and $policy.maxRequestsPerMinutePerHost) { [int]$policy.maxRequestsPerMinutePerHost } else { $RateLimitPerMinute }
if ($RateLimitPerMinute -gt $policyRate) { $RateLimitPerMinute = $policyRate }
$delaySeconds = [Math]::Max(1, [Math]::Ceiling(60 / [double]$RateLimitPerMinute))

$runDir = if ($OutputDirectory) {
  New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
  $OutputDirectory
} else {
  New-BaiRunDirectory -OutputRoot $OutputRoot -Program $Program -Kind "frontend-assets"
}

$pagesDir = Join-Path $runDir "pages"
$assetsDir = Join-Path $runDir "assets"
$mapsDir = Join-Path $runDir "maps"
$analysisDir = Join-Path $runDir "analysis"
New-Item -ItemType Directory -Path $pagesDir -Force | Out-Null
New-Item -ItemType Directory -Path $assetsDir -Force | Out-Null
New-Item -ItemType Directory -Path $mapsDir -Force | Out-Null
New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null

$inputUrls = @()
if ($UrlsFile) {
  if (-not (Test-Path -LiteralPath $UrlsFile)) { throw "UrlsFile not found: $UrlsFile" }
  $inputUrls += Get-Content -LiteralPath $UrlsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
}
$inputUrls += @($Urls)
$inputUrls = @($inputUrls | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First $MaxPages)
$inputUrls = Select-ScopedItems -Items $inputUrls
if (@($inputUrls).Count -eq 0) {
  throw "No scoped URLs to analyze."
}

$pageRows = @()
$assetCandidates = @()
foreach ($url in $inputUrls) {
  $base = Get-UrlFileName -Url $url
  $body = Join-Path $pagesDir "$base.html"
  $headers = Join-Path $pagesDir "$base.headers.txt"
  $row = Invoke-CurlDownload -Url $url -BodyFile $body -HeadersFile $headers -UserAgent $ua -MaxBytes $MaxAssetBytes
  $pageRows += $row
  if (-not $DryRun -and (Test-Path -LiteralPath $body)) {
    $html = Get-Content -LiteralPath $body -Raw -ErrorAction SilentlyContinue
    $matches = Get-TextMatches -Text $html -Pattern '(?i)(?:src|href)\s*=\s*["''](?<value>[^"'']+\.(?:js|css)(?:\?[^"'']*)?)["'']'
    foreach ($asset in $matches) {
      $resolved = Resolve-AssetUrl -BaseUrl $url -Asset $asset
      if ($resolved) { $assetCandidates += $resolved }
    }
  }
  if ($delaySeconds -gt 0) { Start-Sleep -Seconds $delaySeconds }
}

$assetCandidates = Select-ScopedItems -Items $assetCandidates | Select-Object -First $MaxAssets
$assetRows = @()
$mapRows = @()
foreach ($assetUrl in $assetCandidates) {
  $name = Get-UrlFileName -Url $assetUrl
  $ext = if ($assetUrl -match '(?i)\.css(?:\?|$)') { "css" } else { "js" }
  $body = Join-Path $assetsDir "$name.$ext"
  $headers = Join-Path $assetsDir "$name.headers.txt"
  $row = Invoke-CurlDownload -Url $assetUrl -BodyFile $body -HeadersFile $headers -UserAgent $ua -MaxBytes $MaxAssetBytes
  $assetRows += $row

  if (-not $DryRun -and $ext -eq "js" -and (Test-Path -LiteralPath $body)) {
    $text = Get-Content -LiteralPath $body -Raw -ErrorAction SilentlyContinue
    $mapRefs = @()
    $mapRefs += Get-TextMatches -Text $text -Pattern 'sourceMappingURL=(?<value>[^\s*]+)'
    if (-not $mapRefs) { $mapRefs += "$assetUrl.map" }
    foreach ($mapRef in @($mapRefs | Select-Object -First 2)) {
      $mapUrl = Resolve-AssetUrl -BaseUrl $assetUrl -Asset $mapRef
      if (-not $mapUrl) { continue }
      $scope = if ($AllowNoScope -and -not $policy) { $true } else { (Test-BaiTargetScope -Target $mapUrl -Policy $policy).allowed }
      if (-not $scope) { continue }
      $mapName = Get-UrlFileName -Url $mapUrl -Suffix "map"
      $mapBody = Join-Path $mapsDir $mapName
      $mapHeaders = Join-Path $mapsDir "$mapName.headers.txt"
      $mapRows += Invoke-CurlDownload -Url $mapUrl -BodyFile $mapBody -HeadersFile $mapHeaders -UserAgent $ua -MaxBytes 5000000
    }
  }
  if ($delaySeconds -gt 0) { Start-Sleep -Seconds $delaySeconds }
}

$endpointRows = @()
$tokenRows = @()
$textFiles = @(Get-ChildItem -LiteralPath $pagesDir -File -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $assetsDir -File -ErrorAction SilentlyContinue)
foreach ($file in $textFiles) {
  if ($file.Name -match '\.headers\.txt$') { continue }
  $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
  if (-not $text) { continue }
  $found = @()
  $found += Get-TextMatches -Text $text -Pattern 'https?://[^\s''"<>`\\),]{8,260}'
  $found += Get-TextMatches -Text $text -Pattern '(?<![A-Za-z0-9])/(?:api|v[0-9]+|front|graphql|auth|oauth|github|repos|repo|ci|organizations|orgs|users|accounts?|billing|subscription|webhooks?|integrations?|installations?)[A-Za-z0-9._~!$&()*;=:@%/?#\[\]{}$\-]{0,240}'
  foreach ($value in @($found | Where-Object { $_ -and $_.Length -le 300 } | Sort-Object -Unique)) {
    $score = Get-EndpointScore -Value $value -FileName $file.Name
    $endpointRows += [pscustomobject]@{
      endpoint = $value
      status = $score.status
      score = $score.score
      reasons = $score.reasons
      file = $file.Name
    }
  }
  $tokenRows += Get-TokenContexts -Text $text -FileName $file.Name
}

$endpointRows = @($endpointRows | Sort-Object @{ Expression = "score"; Descending = $true }, endpoint -Unique)
$authzCandidates = @($endpointRows | Where-Object { $_.score -ge 5 } | Select-Object -First 120)

$urlsOut = Join-Path $analysisDir "urls.txt"
$pathsOut = Join-Path $analysisDir "paths.txt"
$endpointJson = Join-Path $analysisDir "endpoint-inventory.json"
$authzJson = Join-Path $analysisDir "authz-candidates.json"
$tokenJson = Join-Path $analysisDir "token-context.json"
$planPath = Join-Path $runDir "authz-test-plan.md"
$summaryPath = Join-Path $runDir "summary.json"
$manifest = Join-Path $runDir "manifest.json"

@($endpointRows | Where-Object { $_.endpoint -match '^https?://' } | ForEach-Object { $_.endpoint } | Sort-Object -Unique) | Set-Content -Path $urlsOut -Encoding UTF8
@($endpointRows | Where-Object { $_.endpoint -notmatch '^https?://' } | ForEach-Object { $_.endpoint } | Sort-Object -Unique) | Set-Content -Path $pathsOut -Encoding UTF8
$endpointRows | ConvertTo-Json -Depth 8 | Set-Content -Path $endpointJson -Encoding UTF8
$authzCandidates | ConvertTo-Json -Depth 8 | Set-Content -Path $authzJson -Encoding UTF8
$tokenRows | ConvertTo-Json -Depth 6 | Set-Content -Path $tokenJson -Encoding UTF8

@(
  "# Frontend Authz Test Plan: $Program",
  "",
  "- Created: $((Get-Date).ToString('o'))",
  "- Input URLs: $(@($inputUrls).Count)",
  "- Assets downloaded: $(@($assetRows).Count)",
  "- High-priority authorization candidates: $(@($authzCandidates).Count)",
  "",
  "Use these as leads only. Test with owned accounts and owned objects.",
  "",
  "## Candidate Endpoints",
  "",
  "| Score | Status | Endpoint | Reasons |",
  "| --- | --- | --- | --- |"
) | Set-Content -Path $planPath -Encoding UTF8

foreach ($candidate in $authzCandidates) {
  $endpoint = ($candidate.endpoint -replace '\|', '\|' -replace '`', '')
  $reasons = (@($candidate.reasons) -join ", ")
  "| $($candidate.score) | $($candidate.status) | ``$endpoint`` | $reasons |" | Add-Content -Path $planPath -Encoding UTF8
}

$gitleaksOut = ""
$trufflehogOut = ""
$secretScanRows = @()
if ($SecretScan) {
  $toolBin = Get-ToolBinDir -Value $ToolRoot
  $gitleaks = Resolve-Tool -Name "gitleaks" -BinDir $toolBin
  $trufflehog = Resolve-Tool -Name "trufflehog" -BinDir $toolBin
  if ($gitleaks -and -not $DryRun) {
    $gitleaksOut = Join-Path $runDir "gitleaks-frontend.json"
    $gitleaksStdout = Join-Path $runDir "gitleaks-frontend.stdout.txt"
    $gitleaksStderr = Join-Path $runDir "gitleaks-frontend.stderr.txt"
    $exit = Invoke-ToolToFile -Exe $gitleaks -StdoutFile $gitleaksStdout -StderrFile $gitleaksStderr -TimeoutSeconds $SecretScanTimeoutSeconds -ExternalArgs @(
      "detect", "--no-git", "--redact", "--source", $assetsDir, "--report-format", "json", "--report-path", $gitleaksOut
    )
    $secretScanRows += [pscustomobject]@{ tool = "gitleaks"; exitCode = $exit; output = Split-Path -Leaf $gitleaksOut; stderr = Split-Path -Leaf $gitleaksStderr }
  }
  if ($trufflehog -and -not $DryRun) {
    $trufflehogOut = Join-Path $runDir "trufflehog-frontend.jsonl"
    $trufflehogStderr = Join-Path $runDir "trufflehog-frontend.stderr.txt"
    $exit = Invoke-ToolToFile -Exe $trufflehog -StdoutFile $trufflehogOut -StderrFile $trufflehogStderr -TimeoutSeconds $SecretScanTimeoutSeconds -ExternalArgs @(
      "filesystem", "--json", "--no-update", $assetsDir
    )
    $secretScanRows += [pscustomobject]@{ tool = "trufflehog"; exitCode = $exit; output = Split-Path -Leaf $trufflehogOut; stderr = Split-Path -Leaf $trufflehogStderr }
  }
}

$realMapRows = @($mapRows | Where-Object { $_.contentType -match 'json|source-map' -or ($_.size -gt 0 -and $_.contentType -notmatch 'text/html') })

[pscustomobject]@{
  type = "frontend-assets"
  createdAt = (Get-Date).ToString("o")
  program = $Program
  runDir = $runDir
  inputUrls = @($inputUrls)
  pages = @($pageRows)
  assets = @($assetRows)
  maps = @($mapRows)
  possibleRealSourceMaps = @($realMapRows)
  endpointCount = @($endpointRows).Count
  authzCandidateCount = @($authzCandidates).Count
  tokenContextCount = @($tokenRows).Count
  secretScans = @($secretScanRows)
  files = @{
    urls = "analysis\urls.txt"
    paths = "analysis\paths.txt"
    endpointInventory = "analysis\endpoint-inventory.json"
    authzCandidates = "analysis\authz-candidates.json"
    tokenContext = "analysis\token-context.json"
    authzPlan = "authz-test-plan.md"
    gitleaks = if ($gitleaksOut) { Split-Path -Leaf $gitleaksOut } else { "" }
    trufflehog = if ($trufflehogOut) { Split-Path -Leaf $trufflehogOut } else { "" }
  }
} | ConvertTo-Json -Depth 8 | Set-Content -Path $summaryPath -Encoding UTF8

[pscustomobject]@{
  type = "frontend-assets"
  createdAt = (Get-Date).ToString("o")
  program = $Program
  scopeFile = $ScopeFile
  urlsFile = $UrlsFile
  outputDirectory = $runDir
  userAgent = $ua
  rateLimitPerMinute = $RateLimitPerMinute
  maxPages = $MaxPages
  maxAssets = $MaxAssets
  maxAssetBytes = $MaxAssetBytes
  secretScanTimeoutSeconds = $SecretScanTimeoutSeconds
  secretScan = [bool]$SecretScan
  dryRun = [bool]$DryRun
  summary = Split-Path -Leaf $summaryPath
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Frontend asset analysis saved under: $runDir" -ForegroundColor Green
