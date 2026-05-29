Set-StrictMode -Version 3.0

function ConvertTo-SafeName {
  param([string] $Value)
  $safe = if ($Value) { $Value } else { "run" }
  $safe = ($safe -replace '[^a-zA-Z0-9_.-]', '-').Trim('-')
  if (-not $safe) { return "run" }
  return $safe
}

function Get-BaiOutputRoot {
  param([string] $OutputRoot = "")
  if ($OutputRoot) {
    return $OutputRoot
  }
  if ($env:BAI_OUTPUT_ROOT) {
    return $env:BAI_OUTPUT_ROOT
  }
  return Join-Path $env:USERPROFILE "Desktop\codex\runs"
}

function New-BaiRunDirectory {
  param(
    [string] $OutputRoot = "",
    [string] $Program = "",
    [string] $Kind = "scan"
  )

  $root = Get-BaiOutputRoot -OutputRoot $OutputRoot
  $programName = ConvertTo-SafeName $(if ($Program) { $Program } else { "unknown-program" })
  $kindName = ConvertTo-SafeName $Kind
  $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
  $dir = Join-Path $root "$programName\$stamp-$kindName"
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  return $dir
}

function Read-BaiScopePolicy {
  param([string] $ScopeFile)
  if (-not $ScopeFile) {
    return $null
  }
  if (-not (Test-Path -LiteralPath $ScopeFile)) {
    throw "Scope file not found: $ScopeFile"
  }

  $policy = Get-Content -LiteralPath $ScopeFile -Raw | ConvertFrom-Json
  if (-not $policy.program) {
    $policy | Add-Member -NotePropertyName program -NotePropertyValue ([System.IO.Path]::GetFileNameWithoutExtension($ScopeFile))
  }
  if (-not $policy.inScope) {
    throw "Scope file must include an inScope array."
  }
  if ($policy.PSObject.Properties.Name -notcontains "__scopeFile") {
    $policy | Add-Member -NotePropertyName __scopeFile -NotePropertyValue (Resolve-Path -LiteralPath $ScopeFile).Path
  }
  return $policy
}

function Get-TargetHost {
  param([string] $Target)
  $value = if ($null -eq $Target) { "" } else { $Target.Trim() }
  if (-not $value) { return "" }
  try {
    if ($value -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
      $value = "https://$value"
    }
    return ([uri]$value).Host.ToLowerInvariant()
  } catch {
    return ($Target -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', '' -replace '/.*$', '').ToLowerInvariant()
  }
}

function Test-HostPattern {
  param(
    [string] $Host,
    [string] $Pattern
  )

  $hostValue = if ($null -eq $Host) { "" } else { $Host.Trim().ToLowerInvariant() }
  $patternValue = if ($null -eq $Pattern) { "" } else { $Pattern.Trim().ToLowerInvariant() }
  if (-not $hostValue -or -not $patternValue) { return $false }

  $patternValue = $patternValue -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', ''
  $patternValue = $patternValue -replace '/.*$', ''

  if ($patternValue.StartsWith("*.")) {
    $suffix = $patternValue.Substring(1)
    return $hostValue.EndsWith($suffix) -and $hostValue.Length -gt $suffix.Length
  }

  return $hostValue -eq $patternValue
}

function Test-BaiTargetScope {
  param(
    [string] $Target,
    [object] $Policy
  )

  $hostValue = Get-TargetHost -Target $Target
  if (-not $Policy) {
    return [pscustomobject]@{
      target = $Target
      host = $hostValue
      allowed = $false
      reason = "missing-scope-policy"
      matchedInScope = ""
      matchedOutOfScope = ""
    }
  }

  $outMatch = @($Policy.outOfScope) | Where-Object { Test-HostPattern -Host $hostValue -Pattern $_ } | Select-Object -First 1
  if ($outMatch) {
    return [pscustomobject]@{
      target = $Target
      host = $hostValue
      allowed = $false
      reason = "matched-out-of-scope"
      matchedInScope = ""
      matchedOutOfScope = $outMatch
    }
  }

  $inMatch = @($Policy.inScope) | Where-Object { Test-HostPattern -Host $hostValue -Pattern $_ } | Select-Object -First 1
  return [pscustomobject]@{
    target = $Target
    host = $hostValue
    allowed = [bool]$inMatch
    reason = if ($inMatch) { "in-scope" } else { "not-in-scope" }
    matchedInScope = if ($inMatch) { $inMatch } else { "" }
    matchedOutOfScope = ""
  }
}

function Invoke-DohQuery {
  param(
    [string] $Name,
    [string] $Type = "A"
  )

  $url = "https://cloudflare-dns.com/dns-query?name=$([uri]::EscapeDataString($Name))&type=$Type"
  try {
    $raw = & curl.exe -sS --max-time 10 -H "accept: application/dns-json" $url 2>$null
    if (-not $raw) {
      return [pscustomobject]@{ name = $Name; type = $Type; status = -1; answers = @(); error = "empty-response" }
    }
    $json = ($raw -join "") | ConvertFrom-Json
    $answers = @()
    if ($json.Answer) {
      $answers = @($json.Answer | ForEach-Object { $_.data })
    }
    return [pscustomobject]@{ name = $Name; type = $Type; status = [int]$json.Status; answers = $answers; error = "" }
  } catch {
    return [pscustomobject]@{ name = $Name; type = $Type; status = -1; answers = @(); error = $_.Exception.Message }
  }
}

function Get-RegisteredDomainGuess {
  param([string] $Host)
  $hostValue = if ($null -eq $Host) { "" } else { $Host }
  $parts = $hostValue.Split(".") | Where-Object { $_ }
  if ($parts.Count -lt 2) { return $Host }
  return ($parts[($parts.Count - 2)..($parts.Count - 1)] -join ".")
}

function Test-DohWildcard {
  param([string] $Host)
  $root = Get-RegisteredDomainGuess -Host $Host
  $random = "bai-wildcard-$([guid]::NewGuid().ToString('N')).$root"
  $query = Invoke-DohQuery -Name $random -Type "A"
  return [pscustomobject]@{
    root = $root
    probe = $random
    wildcard = ($query.status -eq 0 -and @($query.answers).Count -gt 0)
    answers = @($query.answers)
    status = $query.status
  }
}

function Invoke-BaiScopePreflight {
  param(
    [string] $TargetsFile,
    [object] $Policy,
    [string] $RunDir,
    [switch] $AllowNoScope
  )

  if (-not (Test-Path -LiteralPath $TargetsFile)) {
    throw "Targets file not found: $TargetsFile"
  }

  $targets = Get-Content -LiteralPath $TargetsFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
  $scopeRows = @($targets | ForEach-Object { Test-BaiTargetScope -Target $_ -Policy $Policy })
  if (-not $Policy -and -not $AllowNoScope) {
    throw "Refusing to scan without a scope file. Pass -ScopeFile or explicitly use -AllowNoScope for local-only testing."
  }

  $allowed = @($scopeRows | Where-Object { $_.allowed -or ($AllowNoScope -and -not $Policy) })
  $rejected = @($scopeRows | Where-Object { -not ($_.allowed -or ($AllowNoScope -and -not $Policy)) })

  $validatedFile = Join-Path $RunDir "validated-targets.txt"
  $rejectedFile = Join-Path $RunDir "rejected-targets.json"
  $dnsFile = Join-Path $RunDir "dns-preflight.jsonl"

  $allowed | ForEach-Object { $_.target } | Set-Content -Path $validatedFile -Encoding ASCII
  $rejected | ConvertTo-Json -Depth 6 | Set-Content -Path $rejectedFile -Encoding UTF8
  "" | Set-Content -Path $dnsFile -Encoding UTF8

  $wildcardCache = @{}
  foreach ($row in $allowed) {
    $doh = Invoke-DohQuery -Name $row.host -Type "A"
    $root = Get-RegisteredDomainGuess -Host $row.host
    if (-not $wildcardCache.ContainsKey($root)) {
      $wildcardCache[$root] = Test-DohWildcard -Host $row.host
    }
    [pscustomobject]@{
      target = $row.target
      host = $row.host
      inScope = $row.allowed
      matchedInScope = $row.matchedInScope
      dohStatus = $doh.status
      dohAnswers = @($doh.answers)
      wildcardRoot = $wildcardCache[$root].root
      wildcardProbe = $wildcardCache[$root].probe
      wildcardDetected = $wildcardCache[$root].wildcard
      wildcardAnswers = @($wildcardCache[$root].answers)
    } | ConvertTo-Json -Depth 6 -Compress | Add-Content -Path $dnsFile -Encoding UTF8
  }

  return [pscustomobject]@{
    targets = $targets
    allowed = $allowed
    rejected = $rejected
    validatedFile = $validatedFile
    rejectedFile = $rejectedFile
    dnsFile = $dnsFile
  }
}

function Get-NucleiTemplatePaths {
  param(
    [string] $TemplateRoot,
    [string] $Profile = "baseline"
  )

  $httpRoot = Join-Path $TemplateRoot "http"
  switch ($Profile.ToLowerInvariant()) {
    "baseline" {
      return @(
        "exposures\apis\swagger-api.yaml",
        "exposures\apis\openapi.yaml",
        "exposures\apis\redoc-api-docs.yaml",
        "exposures\configs\git-config.yaml",
        "exposures\configs\git-credentials-disclosure.yaml",
        "exposures\configs\laravel-env.yaml",
        "exposures\configs\javascript-env-config.yaml",
        "exposures\configs\nextjs-vite-public-env.yaml",
        "exposures\configs\debug-vars.yaml",
        "exposures\configs\phpinfo-files.yaml",
        "misconfiguration\springboot\springboot-env.yaml",
        "technologies\graphql-detect.yaml",
        "technologies\springboot-actuator.yaml"
      ) | ForEach-Object { Join-Path $httpRoot $_ } | Where-Object { Test-Path -LiteralPath $_ }
    }
    "tech" {
      return @(
        Join-Path $httpRoot "technologies",
        Join-Path $httpRoot "exposed-panels",
        Join-Path $httpRoot "exposures\apis"
      ) | Where-Object { Test-Path -LiteralPath $_ }
    }
    "focused" {
      return @(
        Join-Path $httpRoot "exposures\apis",
        Join-Path $httpRoot "exposures\configs",
        Join-Path $httpRoot "misconfiguration\graphql",
        Join-Path $httpRoot "misconfiguration\springboot",
        Join-Path $httpRoot "misconfiguration\gitlab",
        Join-Path $httpRoot "misconfiguration\jenkins"
      ) | Where-Object { Test-Path -LiteralPath $_ }
    }
    "full" {
      return @($TemplateRoot)
    }
    default {
      throw "Unknown TemplateProfile '$Profile'. Use baseline, tech, focused, or full."
    }
  }
}

function Get-FindingStatus {
  param(
    [string] $Title = "",
    [string] $Severity = "",
    [string] $Evidence = ""
  )

  $haystack = "$Title $Severity $Evidence".ToLowerInvariant()
  if ($haystack -match 'out.of.scope|not.in.scope') { return "out_of_scope" }
  if ($haystack -match 'verified|confirmed|exploitable') { return "verified" }
  if ($haystack -match 'idor|auth bypass|permission|rce|sql injection|ssrf|account takeover|data exposure') { return "candidate" }
  if ($haystack -match 'swagger|openapi|fingerprint|version|banner|missing header|robots|sitemap|technology') { return "lead" }
  return "lead"
}

function New-BaiCaseReport {
  param(
    [string] $RunDir,
    [string] $Program,
    [string] $Kind,
    [object] $Policy,
    [object] $Preflight,
    [string] $ResultsPath = "",
    [string] $Notes = ""
  )

  $casePath = Join-Path $RunDir "case.md"
  $ua = if ($Policy -and $Policy.userAgent) { $Policy.userAgent } else { "BaiCodeAgent-HackerOne" }
  $rate = if ($Policy -and $Policy.maxRequestsPerMinutePerHost) { $Policy.maxRequestsPerMinutePerHost } else { "" }
  $scopeFile = "none"
  if ($Policy -and $Policy.PSObject.Properties.Name -contains "__scopeFile") {
    $scopeFile = $Policy.__scopeFile
  }
  $lines = @(
    "# Scan Case: $Program",
    "",
    "- Created: $((Get-Date).ToString('o'))",
    "- Kind: $Kind",
    "- Output directory: $RunDir",
    "- User-Agent: $ua",
    "- Per-host rate policy: $rate requests/minute",
    "- Finding statuses: lead -> candidate -> verified -> not_reportable -> out_of_scope",
    "",
    "## Scope",
    "",
    "- Scope file: $scopeFile",
    "- Allowed targets: $(@($Preflight.allowed).Count)",
    "- Rejected targets: $(@($Preflight.rejected).Count)",
    "- Validated targets file: $($Preflight.validatedFile)",
    "- DNS preflight file: $($Preflight.dnsFile)",
    "",
    "## Results",
    "",
    "- Results: $(if ($ResultsPath) { $ResultsPath } else { 'not generated yet' })",
    "- Manifest: $(Join-Path $RunDir 'manifest.json')",
    "",
    "## Notes",
    "",
    $(if ($Notes) { $Notes } else { "No confirmed vulnerability yet. Treat automated hits as leads until manual impact is verified." })
  )
  $lines | Set-Content -Path $casePath -Encoding UTF8
  return $casePath
}

Export-ModuleMember -Function *
