param(
  [Parameter(Mandatory = $true)]
  [string] $Program,

  [string[]] $InScope = @(),
  [string[]] $OutOfScope = @(),
  [string[]] $Targets = @(),
  [string] $UserAgent = "BaiCodeAgent-HackerOne",
  [int] $RateLimitPerMinute = 30,
  [string] $OutputRoot = "",
  [switch] $Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

function ConvertTo-JsonArrayLiteral {
  param([string[]] $Values)
  $items = @(Normalize-StringList -Values $Values | ForEach-Object { "    " + ($_ | ConvertTo-Json -Compress) })
  if (-not $items.Count) { return @() }
  for ($i = 0; $i -lt $items.Count; $i++) {
    if ($i -lt ($items.Count - 1)) { $items[$i] = $items[$i] + "," }
  }
  return $items
}

function Normalize-StringList {
  param([string[]] $Values)
  return @($Values | ForEach-Object {
    $raw = $_
    if ($null -eq $raw) { return }
    $raw -split "," | ForEach-Object { $_.Trim() }
  } | Where-Object { $_ } | Sort-Object -Unique)
}

$safeProgram = ConvertTo-SafeName $Program
$baseRoot = if ($OutputRoot) { $OutputRoot } elseif ($env:BAI_OUTPUT_ROOT) { Split-Path -Parent $env:BAI_OUTPUT_ROOT } else { Join-Path $env:USERPROFILE "Desktop\codex" }
$projectRoot = Join-Path $baseRoot "programs\$safeProgram"
$scopeDir = Join-Path $baseRoot "scopes"
$targetDir = Join-Path $baseRoot "targets"
$scopeFile = Join-Path $scopeDir "$safeProgram.json"
$targetFile = Join-Path $targetDir "$safeProgram.txt"
$notesFile = Join-Path $projectRoot "notes.md"
$commandsFile = Join-Path $projectRoot "commands.ps1"

foreach ($dir in @($projectRoot, $scopeDir, $targetDir)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

if ((Test-Path -LiteralPath $scopeFile) -and -not $Force) {
  throw "Scope file already exists: $scopeFile. Pass -Force to overwrite."
}
if ((Test-Path -LiteralPath $targetFile) -and -not $Force) {
  throw "Targets file already exists: $targetFile. Pass -Force to overwrite."
}

$normalizedInScope = @(Normalize-StringList -Values $InScope)
$normalizedOutOfScope = @(Normalize-StringList -Values $OutOfScope)
$normalizedTargets = @(Normalize-StringList -Values $Targets)

$scopeValues = if ($normalizedInScope.Count) { $normalizedInScope } else { $normalizedTargets }
$targetValues = if ($normalizedTargets.Count) { $normalizedTargets } else { $normalizedInScope }

$scopeLines = @(
  "{",
  "  `"program`": `"$safeProgram`",",
  "  `"userAgent`": `"$UserAgent`",",
  "  `"maxRequestsPerMinutePerHost`": $RateLimitPerMinute,",
  "  `"inScope`": ["
) + (ConvertTo-JsonArrayLiteral -Values $scopeValues) + @(
  "  ],",
  "  `"outOfScope`": ["
) + (ConvertTo-JsonArrayLiteral -Values $normalizedOutOfScope) + @(
  "  ],",
  "  `"excludeTags`": [",
  "    `"dos`",",
  "    `"fuzz`",",
  "    `"bruteforce`",",
  "    `"credential-stuffing`",",
  "    `"intrusive`",",
  "    `"takeover`"",
  "  ],",
  "  `"notes`": [",
  "    `"Update this file from the program policy before scanning.`",",
  "    `"Keep out-of-scope third-party assets here.`"",
  "  ]",
  "}"
)
$scopeLines | Set-Content -Path $scopeFile -Encoding UTF8

$targetValues | Set-Content -Path $targetFile -Encoding ASCII

$notesLines = New-Object System.Collections.Generic.List[string]
foreach ($line in @(
  "# $Program"
  ""
  "- Created: $((Get-Date).ToString('o'))"
  "- Scope file: $scopeFile"
  "- Targets file: $targetFile"
  "- Output root: $(Get-BaiOutputRoot)"
  ""
  "## Policy Checklist"
  ""
  "- Confirm all assets are eligible for bounty."
  "- Copy required user-agent text into the scope file."
  "- Copy per-host rate limits into the scope file."
  "- Add out-of-scope assets before running scans."
  "- Use only accounts and data you own or are explicitly allowed to test."
  ""
  "## Findings"
  ""
  "- lead:"
  "- candidate:"
  "- verified:"
)) {
  $notesLines.Add($line) | Out-Null
}
$notesLines | Set-Content -Path $notesFile -Encoding UTF8

$commandLines = New-Object System.Collections.Generic.List[string]
foreach ($line in @(
  ('$repo = "' + $root + '"')
  ('$scope = "' + $scopeFile + '"')
  ('$targets = "' + $targetFile + '"')
  ""
  "Set-Location `$repo"
  ""
  "# Tool check"
  "powershell -ExecutionPolicy Bypass -File .\scripts\install-web-bounty-tools.ps1"
  ""
  "# Conservative web pipeline"
  "powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 -TargetsFile `$targets -ScopeFile `$scope -TemplateProfile baseline"
  ""
  "# SPA/API pipeline with frontend endpoint and authz lead extraction"
  "powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 -TargetsFile `$targets -ScopeFile `$scope -TemplateProfile baseline -AnalyzeFrontendAssets -FrontendSecretScan -MaxStageMinutes 10"
  ""
  "# Optional deeper discovery after reviewing policy"
  "powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 -TargetsFile `$targets -ScopeFile `$scope -TemplateProfile baseline -IncludePassiveUrls -IncludeParamDiscovery -MaxDiscoveryUrls 50"
  ""
  "# Two-account authorization case"
  "powershell -ExecutionPolicy Bypass -File .\scripts\new-authz-test-case.ps1 -Program `"$safeProgram`" -ScopeFile `$scope -Target https://app.example.com -ResourceHint account-id-owner-repo"
)) {
  $commandLines.Add($line) | Out-Null
}
$commandLines | Set-Content -Path $commandsFile -Encoding UTF8

[pscustomobject]@{
  program = $safeProgram
  projectRoot = $projectRoot
  scopeFile = $scopeFile
  targetFile = $targetFile
  notesFile = $notesFile
  commandsFile = $commandsFile
} | ConvertTo-Json -Depth 4
