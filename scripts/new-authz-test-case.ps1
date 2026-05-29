param(
  [Parameter(Mandatory = $true)]
  [string] $Program,

  [string] $OutputRoot = "",
  [string] $ScopeFile = "",
  [string] $Target = "",
  [string] $ResourceHint = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

$policy = Read-BaiScopePolicy -ScopeFile $ScopeFile
$runDir = New-BaiRunDirectory -OutputRoot $OutputRoot -Program $Program -Kind "authz-case"
$casePath = Join-Path $runDir "authz-plan.md"
$accountA = Join-Path $runDir "account-a-requests.http"
$accountB = Join-Path $runDir "account-b-requests.http"
$accountAHeaders = Join-Path $runDir "account-a.headers.txt"
$accountBHeaders = Join-Path $runDir "account-b.headers.txt"
$cases = Join-Path $runDir "cases.json"
$findings = Join-Path $runDir "findings.json"

$ua = if ($policy -and $policy.userAgent) { $policy.userAgent } else { "BaiCodeAgent-HackerOne" }

@(
  "# Authz / IDOR Test Case: $Program",
  "",
  "- Created: $((Get-Date).ToString('o'))",
  "- Target: $Target",
  "- Resource hint: $(if ($ResourceHint) { $ResourceHint } else { 'not set' })",
  "- User-Agent: $ua",
  "- Scope file: $(if ($ScopeFile) { (Resolve-Path -LiteralPath $ScopeFile).Path } else { 'none' })",
  "- Status: lead",
  "",
  "## Rules",
  "",
  "- Use only accounts you own or accounts explicitly authorized by the program.",
  "- Do not access real customer data.",
  "- Prefer GET/read-only comparisons first.",
  "- For writes, use reversible test-only data and stop after one proof.",
  "- Record exact request times and keep traffic within the program rate limit.",
  "",
  "## Account A",
  "",
  "- Email / identifier:",
  "- Test data owned by A:",
  "",
  "## Account B",
  "",
  "- Email / identifier:",
  "- Test data owned by B:",
  "",
  "## Candidate Endpoints",
  "",
  "| Endpoint | Method | Object id owner | A as A | B as A | Result | Status |",
  "| --- | --- | --- | --- | --- | --- | --- |",
  "|  |  |  |  |  |  | lead |",
  "",
  "## Runnable Diff",
  "",
  "1. Put Account A cookies or authorization headers in `account-a.headers.txt`.",
  "2. Put Account B cookies or authorization headers in `account-b.headers.txt`.",
  "3. Edit `cases.json` with owned Account A object URLs.",
  "4. Run `scripts\run-authz-diff.ps1` from the tool repository.",
  "",
  "```powershell",
  "powershell -ExecutionPolicy Bypass -File .\scripts\run-authz-diff.ps1 ``",
  "  -Program `"$Program`" ``",
  "  -ScopeFile `"$ScopeFile`" ``",
  "  -CasesFile `"$cases`" ``",
  "  -AccountAHeadersFile `"$accountAHeaders`" ``",
  "  -AccountBHeadersFile `"$accountBHeaders`" ``",
  "  -OutputRoot `"$runDir`"",
  "```",
  "",
  "## Impact Notes",
  "",
  "- What data or action crossed an authorization boundary?",
  "- Why is the object/action in scope?",
  "- What is the minimum reproduction?"
) | Set-Content -Path $casePath -Encoding UTF8

@(
  "# Paste sanitized Account A requests here.",
  "# Keep cookies/tokens local. Do not commit or share this file.",
  "# Required header:",
  "User-Agent: $ua"
) | Set-Content -Path $accountA -Encoding UTF8

@(
  "# Paste sanitized Account B requests here.",
  "# Keep cookies/tokens local. Do not commit or share this file.",
  "# Required header:",
  "User-Agent: $ua"
) | Set-Content -Path $accountB -Encoding UTF8

@(
  "# Paste Account A request headers here, one per line.",
  "# Example:",
  "# Cookie: session=<account-a-session>",
  "# Authorization: Bearer <account-a-token>"
) | Set-Content -Path $accountAHeaders -Encoding UTF8

@(
  "# Paste Account B request headers here, one per line.",
  "# Example:",
  "# Cookie: session=<account-b-session>",
  "# Authorization: Bearer <account-b-token>"
) | Set-Content -Path $accountBHeaders -Encoding UTF8

@(
  [pscustomobject]@{
    name = $(if ($ResourceHint) { $ResourceHint } else { "owned-object-read" })
    method = "GET"
    url = $(if ($Target) { $Target } else { "https://app.example.com/path/to/account-a-owned-object" })
    expectB = "deny"
    notes = "Replace with an Account A owned object URL. Keep the first pass read-only."
  }
) | ConvertTo-Json -Depth 6 | Set-Content -Path $cases -Encoding UTF8

@{
  type = "authz-case"
  createdAt = (Get-Date).ToString("o")
  program = $Program
  target = $Target
  resourceHint = $ResourceHint
  status = "lead"
  statuses = @("lead", "candidate", "verified", "not_reportable", "out_of_scope")
  files = @{
    plan = Split-Path -Leaf $casePath
    accountA = Split-Path -Leaf $accountA
    accountB = Split-Path -Leaf $accountB
    accountAHeaders = Split-Path -Leaf $accountAHeaders
    accountBHeaders = Split-Path -Leaf $accountBHeaders
    cases = Split-Path -Leaf $cases
  }
} | ConvertTo-Json -Depth 6 | Set-Content -Path $findings -Encoding UTF8

Write-Host "Authz test case created: $runDir" -ForegroundColor Green
