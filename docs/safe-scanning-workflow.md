# Safe Scanning Workflow

Use this workflow for bug-bounty and SRC black-box checks.

## Output Location

Runtime artifacts are written outside the tool tree by default:

`C:\Users\admin\Desktop\codex\runs\<program>\<timestamp>-<kind>`

Override with:

`$env:BAI_OUTPUT_ROOT = "D:\somewhere\else"`

## Scope Policy

Create a JSON scope file before scanning. Start from:

`docs\scope-policy-example.json`

Or scaffold a project workspace outside the tool tree:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-bounty-project.ps1 `
  -Program example-program `
  -InScope example.com,*.example.com `
  -OutOfScope thirdparty.example.com `
  -Targets example.com
```

This writes scope, targets, notes, and reusable commands under `C:\Users\admin\Desktop\codex`.

Keep these fields current:

- `program`: short program name.
- `userAgent`: program-required UA string.
- `maxRequestsPerMinutePerHost`: strict per-host request ceiling.
- `inScope`: exact domains and wildcard domains that are explicitly allowed.
- `outOfScope`: excluded assets and third-party surfaces.
- `excludeTags`: nuclei tags that should never run for this program.

## Black-Box Nuclei

Default profile is deliberately small:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-nuclei-authorized.ps1 `
  -TargetsFile C:\Users\admin\Desktop\codex\targets\example.txt `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -TemplateProfile baseline
```

Profiles:

- `baseline`: low-request checks for API docs, exposed config, git/env files, GraphQL and actuator hints.
- `tech`: technology and panel discovery.
- `focused`: selected exposures and misconfigurations after manual review.
- `full`: all local templates; use only with explicit approval and a very low rate.

The script writes:

- `validated-targets.txt`
- `rejected-targets.json`
- `dns-preflight.jsonl`
- `results.jsonl`
- `manifest.json`
- `case.md`

## Finding Statuses

Treat every automated result as a lead until a human verifies impact.

- `lead`: worth a look, not a report.
- `candidate`: plausible report after manual reproduction.
- `verified`: impact confirmed inside scope.
- `not_reportable`: noise, intended behavior, or policy-excluded.
- `out_of_scope`: do not continue testing.

## Authenticated Business Logic

Create a two-account authorization case after registering test accounts:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-authz-test-case.ps1 `
  -Program example-program `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -Target https://app.example.com
```

The generated directory contains:

- `authz-plan.md`
- `account-a-requests.http`
- `account-b-requests.http`
- `findings.json`

Use it to compare account A and account B requests without mixing real customer data into the tool tree.

## Tool Install

Check which web bounty tools are available:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-bounty-tools.ps1
```

Show tool readiness and recent run artifacts:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\show-bounty-status.ps1
```

Install missing CLI tools into `C:\Users\admin\Desktop\codex\tools\bin`:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-bounty-tools.ps1 -Install
```

The installer currently handles:

- `nuclei`, `subfinder`, `httpx`, `dnsx`, `katana`, `interactsh-client`, `gau`, `naabu`
- `ffuf`, `feroxbuster`, `dalfox`, `gitleaks`, `trufflehog`, `cloudfox`, `trivy`, `grype`, `kingfisher`
- optional Go tools via `-IncludeGoTools`: `kiterunner` and `waybackurls`
- optional URL tools via `-IncludeUrlTools`: `arjun`, `uro`, `xnLinkFinder`, `waymore`
- optional heavier Python tools via `-IncludePythonTools`: `semgrep`, `checkov`, `prowler`, `ScoutSuite`, plus the URL tools above

## Web Bounty Pipeline

Run a conservative black-box pipeline:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 `
  -Domain example.com `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -TemplateProfile baseline
```

Stages:

- `subfinder`: passive subdomain discovery.
- optional `gau`: passive historical URLs from archives.
- scope + DoH preflight: rejects out-of-scope and wildcard-noise targets before probing.
- `dnsx`: DNS evidence.
- `httpx`: live hosts, status, title, tech.
- `katana`: low-rate crawl of discovered live URLs.
- optional `arjun`: hidden parameter discovery against a capped URL subset.
- optional `kr`: Kiterunner API route discovery when a `.kite` wordlist is explicitly supplied.
- optional `interactsh-client`: writes an OAST plan only; it does not start a listener by default.
- `nuclei`: low-rate baseline findings only.

Use `-IncludePassiveUrls`, `-IncludeParamDiscovery`, `-IncludeApiDiscovery`, or `-PrepareOast` to enable the optional layers:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 `
  -Domain example.com `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -IncludePassiveUrls `
  -IncludeParamDiscovery `
  -MaxDiscoveryUrls 50
```

For SPA/API targets, also extract frontend assets and authorization leads:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\pipeline-web-bounty.ps1 `
  -Domain example.com `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -AnalyzeFrontendAssets `
  -FrontendSecretScan `
  -MaxStageMinutes 10
```

The pipeline does not run ffuf, naabu, sqlmap, password checks, or intrusive templates by default.

## Frontend Asset Analysis

Use this when a target is a modern SPA or dashboard and the shallow scanner only finds login-gated APIs:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\analyze-frontend-assets.ps1 `
  -Program example-program `
  -Urls https://dashboard.example.com,https://api.example.com `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -OutputRoot C:\Users\admin\Desktop\codex\runs `
  -SecretScan
```

It downloads scoped HTML/JS/CSS assets, checks source-map exposure, extracts API routes, scores IDOR/authz candidates, captures token-like contexts for manual review, and writes an `authz-test-plan.md`. Public browser telemetry keys such as Sentry DSNs or Datadog RUM client tokens should stay `not_reportable` unless you can prove concrete sensitive access or abuse.

## Authenticated Diff Testing

Create a case:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-authz-test-case.ps1 `
  -Program example-program `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -Target https://app.example.com `
  -ResourceHint account-id-owner-repo
```

After logging in with two owned accounts, fill:

- `account-a.headers.txt`
- `account-b.headers.txt`
- `cases.json`

Then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-authz-diff.ps1 `
  -Program example-program `
  -ScopeFile C:\Users\admin\Desktop\codex\scopes\example-program.json `
  -CasesFile C:\path\to\cases.json `
  -AccountAHeadersFile C:\path\to\account-a.headers.txt `
  -AccountBHeadersFile C:\path\to\account-b.headers.txt
```

By default this only sends `GET`, `HEAD`, and `OPTIONS`. For any write test, use reversible test-only data and pass `-AllowUnsafeMethods` only after a read-only authorization issue is plausible.

## Whitebox Toolchain

For open-source programs and cloned repos, run the local-only whitebox chain:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run-whitebox-toolchain.ps1 `
  -RepoPath C:\path\to\repo `
  -ScopeTag example-program
```

Stages:

- `semgrep`: source-pattern leads.
- `gitleaks`, `trufflehog`, `kingfisher`: secret exposure leads.
- `trivy`, `grype`: dependency and filesystem risk leads.
- `checkov`: IaC misconfiguration leads.

Everything writes to the external output root and requires manual review before reporting.
