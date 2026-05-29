export const BOUNTY_INTEGRATIONS = [
  {
    id: "semgrep-rules",
    name: "Semgrep Rules",
    role: "whitebox",
    sourceUrl: "https://github.com/semgrep/semgrep-rules",
    localPath: "integrations/semgrep-rules",
    fileGlobs: ["**/*.yaml", "**/*.yml"],
    focus: [
      "source-to-sink injection checks",
      "auth and access-control mistakes",
      "secret exposure",
      "framework-specific insecure defaults"
    ],
    whenToUse: "Use after a repository mirror is ready. Treat hits as triage leads, then verify manually or with LLM review."
  },
  {
    id: "nuclei-templates",
    name: "Nuclei Templates",
    role: "blackbox",
    sourceUrl: "https://github.com/projectdiscovery/nuclei-templates",
    localPath: "integrations/nuclei-templates",
    fileGlobs: ["**/*.yaml", "**/*.yml"],
    focus: [
      "technology fingerprinting",
      "known CVE exposure checks",
      "misconfiguration checks",
      "safe evidence collection for in-scope targets"
    ],
    whenToUse: "Use only against assets covered by a program scope. Prefer severity-filtered runs and save JSONL output for evidence."
  },
  {
    id: "shannon",
    name: "Shannon",
    role: "second-pass-audit",
    sourceUrl: "https://github.com/baianquanzu/shannon/tree/codex/chinese-report-monitor",
    localPath: "integrations/shannon",
    fileGlobs: ["apps/**/*.ts", "scripts/*.ps1"],
    focus: [
      "second-pass audit",
      "Chinese report monitor",
      "final report consolidation"
    ],
    whenToUse: "Use from the generated shannon-handoff markdown after Bai has selected and mirrored interesting targets."
  }
];
