# GitHub Tooling Map

This project uses open-source security tools as controlled building blocks for authorized bounty work. Automated output is always a lead until manually verified in scope.

## Integrated

- ProjectDiscovery `nuclei`, `httpx`, `dnsx`, `katana`, `subfinder`, `naabu`, `interactsh`: discovery, probing, crawling, template checks, and OAST planning.
- `lc/gau` and `tomnomnom/waybackurls`: passive URL discovery.
- Assetnote `kiterunner`: optional API route discovery with an explicit small `.kite` wordlist.
- `s0md3v/Arjun`: optional low-rate parameter discovery.
- `ffuf/ffuf` and `epi052/feroxbuster`: installed for manual content discovery, but not run by the default pipeline.
- `hahwul/dalfox`: installed for manual XSS triage only when a program allows XSS testing.
- `gitleaks`, `trufflehog`, `mongodb/kingfisher`: secret scanning for local repos or downloaded frontend assets.
- `aquasecurity/trivy`, `anchore/grype`, `semgrep`, `checkov`: local whitebox/dependency/IaC analysis.
- `xnl-h4ck3r/xnLinkFinder`, `xnl-h4ck3r/waymore`, and `s0md3v/uro`: optional helpers for endpoint extraction, passive URLs, and URL normalization.

Install lightweight URL tools without pulling the heavier Python audit stack:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-web-bounty-tools.ps1 -Install -IncludeUrlTools
```

## Native Additions Inspired by These Tools

- `scripts\analyze-frontend-assets.ps1`: lightweight JS/CSS asset downloader, source-map checker, endpoint extractor, token-context collector, and authz-candidate scorer.
- `scripts\run-authz-diff.ps1`: two-account request comparison for owned objects. It defaults to read-only methods and writes a reviewable result set.
- `scripts\pipeline-web-bounty.ps1 -AnalyzeFrontendAssets`: runs the frontend analyzer as part of the safe pipeline.
- `scripts\pipeline-web-bounty.ps1 -MaxStageMinutes`: kills long-running stages and preserves partial artifacts.

## Deferred By Default

- Content brute forcing, large wordlists, and broad route fuzzing: run manually only when the program allows it and the rate is explicit.
- XSS fuzzing: use only when XSS is in scope and avoid forms/actions that affect other users.
- OAST payloads: prepare a plan by default; run listeners only when the program explicitly allows out-of-band testing.
- Write-method authz tests: gated by `-AllowUnsafeMethods` and should use reversible test-only data.

## References

- ProjectDiscovery: `https://github.com/projectdiscovery`
- Nuclei templates: `https://github.com/projectdiscovery/nuclei-templates`
- Katana: `https://github.com/projectdiscovery/katana`
- Kiterunner: `https://github.com/assetnote/kiterunner`
- Arjun: `https://github.com/s0md3v/Arjun`
- Feroxbuster: `https://github.com/epi052/feroxbuster`
- Dalfox: `https://github.com/hahwul/dalfox`
- xnLinkFinder: `https://github.com/xnl-h4ck3r/xnLinkFinder`
- Waymore: `https://github.com/xnl-h4ck3r/waymore`
