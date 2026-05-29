param(
  [Parameter(Mandatory = $true)]
  [string] $CasesFile,

  [Parameter(Mandatory = $true)]
  [string] $AccountAHeadersFile,

  [Parameter(Mandatory = $true)]
  [string] $AccountBHeadersFile,

  [string] $Program = "authz",
  [string] $ScopeFile = "",
  [string] $OutputRoot = "",
  [int] $RateLimitPerMinute = 30,
  [switch] $AllowNoScope,
  [switch] $AllowUnsafeMethods,
  [switch] $DryRun
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

function Read-HeaderLines {
  param([string] $Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "Header file not found: $Path" }
  return @(Get-Content -LiteralPath $Path | ForEach-Object { $_.Trim() } | Where-Object {
    $_ -and -not $_.StartsWith("#") -and $_ -match '^[^:]+:\s*.+$'
  })
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

function Get-FileSha256 {
  param([string] $Path)
  if (-not (Test-Path -LiteralPath $Path)) { return "" }
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-AuthzRequest {
  param(
    [string] $Method,
    [string] $Url,
    [string[]] $Headers,
    [string] $BodyFile,
    [string] $OutBody,
    [string] $OutHeaders,
    [string] $UserAgent
  )

  if ($DryRun) {
    Write-Host "[dry-run] $Method $Url -> $OutBody" -ForegroundColor Yellow
    return [pscustomobject]@{ status = "dry-run"; contentType = ""; length = 0; sha256 = ""; bodyFile = Split-Path -Leaf $OutBody; headersFile = Split-Path -Leaf $OutHeaders }
  }

  $args = @("-sS", "-L", "--max-time", "25", "-X", $Method, "-A", $UserAgent, "-D", $OutHeaders, "-o", $OutBody)
  foreach ($header in $Headers) {
    $args += @("-H", $header)
  }
  if ($BodyFile) {
    if (-not (Test-Path -LiteralPath $BodyFile)) { throw "Body file not found: $BodyFile" }
    $args += @("--data-binary", "@$BodyFile")
  }
  $args += $Url
  & curl.exe @args 2>$null
  $size = if (Test-Path -LiteralPath $OutBody) { (Get-Item -LiteralPath $OutBody).Length } else { 0 }
  return [pscustomobject]@{
    status = Get-StatusCode -HeadersFile $OutHeaders
    contentType = Get-HeaderValue -HeadersFile $OutHeaders -Name "content-type"
    length = $size
    sha256 = Get-FileSha256 -Path $OutBody
    bodyFile = Split-Path -Leaf $OutBody
    headersFile = Split-Path -Leaf $OutHeaders
  }
}

function Get-AuthzStatus {
  param(
    [object] $A,
    [object] $B,
    [string] $ExpectB
  )
  $aCode = 0
  $bCode = 0
  [int]::TryParse([string]$A.status, [ref]$aCode) | Out-Null
  [int]::TryParse([string]$B.status, [ref]$bCode) | Out-Null

  if ($ExpectB -eq "allow") {
    if ($bCode -ge 200 -and $bCode -lt 300) { return "as_expected" }
    return "lead"
  }

  if ($aCode -ge 200 -and $aCode -lt 300 -and $bCode -ge 200 -and $bCode -lt 300) {
    if ($A.sha256 -and $A.sha256 -eq $B.sha256) { return "candidate_same_body" }
    return "candidate_b_access"
  }
  if ($bCode -eq 401 -or $bCode -eq 403 -or $bCode -eq 404) { return "denied" }
  if ($bCode -ge 200 -and $bCode -lt 400) { return "lead_b_non_denied" }
  return "lead"
}

if (-not (Test-Path -LiteralPath $CasesFile)) { throw "Cases file not found: $CasesFile" }
$cases = @(Get-Content -LiteralPath $CasesFile -Raw | ConvertFrom-Json)
if (-not $cases) { throw "Cases file is empty: $CasesFile" }

$policy = Read-BaiScopePolicy -ScopeFile $ScopeFile
if (-not $policy -and -not $AllowNoScope) {
  throw "Refusing to run authz diff without a scope file. Pass -ScopeFile or use -AllowNoScope for local/lab analysis."
}

$ua = if ($policy -and $policy.userAgent) { $policy.userAgent } else { "BaiCodeAgent-HackerOne" }
$policyRate = if ($policy -and $policy.maxRequestsPerMinutePerHost) { [int]$policy.maxRequestsPerMinutePerHost } else { $RateLimitPerMinute }
if ($RateLimitPerMinute -gt $policyRate) { $RateLimitPerMinute = $policyRate }
$delaySeconds = [Math]::Max(1, [Math]::Ceiling(60 / [double]$RateLimitPerMinute))

$safeMethods = @("GET", "HEAD", "OPTIONS")
$headersA = Read-HeaderLines -Path $AccountAHeadersFile
$headersB = Read-HeaderLines -Path $AccountBHeadersFile
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $Program -Kind "authz-diff"
$responsesDir = Join-Path $runDir "responses"
New-Item -ItemType Directory -Path $responsesDir -Force | Out-Null

$results = @()
$index = 0
foreach ($case in $cases) {
  $index += 1
  $method = if ($case.method) { ([string]$case.method).ToUpperInvariant() } else { "GET" }
  $url = [string]$case.url
  $name = if ($case.name) { [string]$case.name } else { "case-$index" }
  $expectB = if ($case.expectB) { [string]$case.expectB } else { "deny" }
  $bodyFile = if ($case.bodyFile) { [string]$case.bodyFile } else { "" }

  if (-not $url) { throw "Case $index has no url." }
  if (-not $AllowUnsafeMethods -and $safeMethods -notcontains $method) {
    $results += [pscustomobject]@{
      name = $name
      method = $method
      url = $url
      status = "skipped_unsafe_method"
      accountA = $null
      accountB = $null
      notes = "Pass -AllowUnsafeMethods only for reversible test-only writes."
    }
    continue
  }

  if (-not ($AllowNoScope -and -not $policy)) {
    $scope = Test-BaiTargetScope -Target $url -Policy $policy
    if (-not $scope.allowed) {
      $results += [pscustomobject]@{
        name = $name
        method = $method
        url = $url
        status = "out_of_scope"
        accountA = $null
        accountB = $null
        notes = $scope.reason
      }
      continue
    }
  }

  $safeName = ConvertTo-SafeName "$index-$name"
  $aBody = Join-Path $responsesDir "$safeName.account-a.body"
  $aHeaders = Join-Path $responsesDir "$safeName.account-a.headers.txt"
  $bBody = Join-Path $responsesDir "$safeName.account-b.body"
  $bHeaders = Join-Path $responsesDir "$safeName.account-b.headers.txt"

  $a = Invoke-AuthzRequest -Method $method -Url $url -Headers $headersA -BodyFile $bodyFile -OutBody $aBody -OutHeaders $aHeaders -UserAgent $ua
  if ($delaySeconds -gt 0) { Start-Sleep -Seconds $delaySeconds }
  $b = Invoke-AuthzRequest -Method $method -Url $url -Headers $headersB -BodyFile $bodyFile -OutBody $bBody -OutHeaders $bHeaders -UserAgent $ua
  if ($delaySeconds -gt 0) { Start-Sleep -Seconds $delaySeconds }

  $status = Get-AuthzStatus -A $a -B $b -ExpectB $expectB
  $results += [pscustomobject]@{
    name = $name
    method = $method
    url = $url
    expectB = $expectB
    status = $status
    accountA = $a
    accountB = $b
    notes = if ($status -match '^candidate') { "Manually verify impact and object ownership before reporting." } else { "" }
  }
}

$resultsPath = Join-Path $runDir "results.json"
$summaryPath = Join-Path $runDir "summary.md"
$manifest = Join-Path $runDir "manifest.json"
$results | ConvertTo-Json -Depth 8 | Set-Content -Path $resultsPath -Encoding UTF8

@(
  "# Authz Diff Summary: $Program",
  "",
  "- Created: $((Get-Date).ToString('o'))",
  "- Cases: $(@($results).Count)",
  "- Scope file: $(if ($ScopeFile) { (Resolve-Path -LiteralPath $ScopeFile).Path } else { 'none' })",
  "- Status key: candidates need manual proof; denied/as_expected are not findings.",
  "",
  "| Status | Method | URL | A status | B status |",
  "| --- | --- | --- | --- | --- |"
) | Set-Content -Path $summaryPath -Encoding UTF8

foreach ($row in $results) {
  $aStatus = if ($row.accountA) { $row.accountA.status } else { "" }
  $bStatus = if ($row.accountB) { $row.accountB.status } else { "" }
  $url = [string]$row.url
  "| $($row.status) | $($row.method) | ``$url`` | $aStatus | $bStatus |" | Add-Content -Path $summaryPath -Encoding UTF8
}

[pscustomobject]@{
  type = "authz-diff"
  createdAt = (Get-Date).ToString("o")
  program = $Program
  scopeFile = $ScopeFile
  casesFile = (Resolve-Path -LiteralPath $CasesFile).Path
  outputDirectory = $runDir
  rateLimitPerMinute = $RateLimitPerMinute
  allowUnsafeMethods = [bool]$AllowUnsafeMethods
  dryRun = [bool]$DryRun
  results = Split-Path -Leaf $resultsPath
  summary = Split-Path -Leaf $summaryPath
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

Write-Host "Authz diff artifacts saved under: $runDir" -ForegroundColor Green
