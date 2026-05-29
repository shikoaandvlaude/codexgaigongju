import { promises as fs } from "node:fs";
import path from "node:path";

const SEVERITY_SCORE = {
  critical: 0.96,
  high: 0.84,
  medium: 0.68,
  low: 0.5,
  info: 0.3,
  informational: 0.3
};

const HIGH_SIGNAL_PATTERNS = /(auth|login|admin|upload|query|ssrf|xss|idor|bypass|permission|callback|redirect|file|path|payment|order|coupon|tenant|role|graphql|api)/i;
const BOUNTY_REPORTABLE_PATTERNS = /(idor|auth|login|admin|permission|bypass|tenant|role|sql|nosql|injection|ssrf|callback|webhook|redirect|upload|path|rce|command|deserial|payment|order|coupon|wallet|billing|graphql|api)/i;
const LOW_REPORTABILITY_PATTERNS = /(info leak|information disclosure|secret|token|api key|apikey|env|debug|backup|log|swagger|openapi|health|metrics|fingerprint|version|banner|missing header|security header|x-frame-options|csp|cors)/i;

export async function collectScanArtifacts({ rootDir = process.cwd(), selectedProjects = [] } = {}) {
  const roots = [
    path.join(rootDir, "workspace", "scans"),
    path.join(rootDir, "workspace", "reports"),
    ...getExternalArtifactRoots()
  ];
  const manifests = [];

  for (const root of roots) {
    manifests.push(...(await findManifests(root)));
  }

  const selectedProjectIds = new Set((selectedProjects || []).map((project) => project.id).filter(Boolean));
  const selectedRepoNames = new Set((selectedProjects || []).flatMap((project) => [
    project.name,
    project.repo,
    project.owner ? `${project.owner}/${project.name}` : "",
    project.localPath ? path.basename(project.localPath) : ""
  ].filter(Boolean)));

  const allArtifacts = [];
  const filteredArtifacts = [];
  for (const manifest of manifests.sort((a, b) => b.mtimeMs - a.mtimeMs)) {
    const parsed = await readManifestArtifact(manifest, selectedProjectIds, selectedRepoNames);
    if (parsed) {
      filteredArtifacts.push(parsed);
    } else {
      const fallbackParsed = await readManifestArtifact(manifest, new Set(), new Set());
      if (fallbackParsed) {
        allArtifacts.push(fallbackParsed);
      }
    }
  }

  const artifacts = (filteredArtifacts.length ? filteredArtifacts : allArtifacts).slice(0, 6);

  const findings = dedupeFindings(artifacts.flatMap((artifact) => artifact.findings || []));
  return {
    generatedAt: new Date().toISOString(),
    count: findings.length,
    artifacts,
    findings: prioritizeFindings(findings),
    summary: buildSummary(artifacts)
  };
}

async function findManifests(root) {
  const output = [];
  if (!(await isDirectory(root))) {
    return output;
  }

  await walkForManifests(root, output);
  return output;
}

async function walkForManifests(current, output) {
  let entries = [];
  try {
    entries = await fs.readdir(current, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(current, entry.name);
    if (entry.isDirectory()) {
      await walkForManifests(fullPath, output);
      continue;
    }

    if (entry.isFile() && entry.name === "manifest.json") {
      const stats = await fs.stat(fullPath).catch(() => null);
      output.push({
        path: fullPath,
        dir: path.dirname(fullPath),
        mtimeMs: stats?.mtimeMs || 0
      });
    }
  }
}

async function readManifestArtifact(manifest, selectedProjectIds, selectedRepoNames) {
  try {
    const raw = await fs.readFile(manifest.path, "utf8");
    const data = JSON.parse(raw);
    if (!matchesSelectionData(data, selectedProjectIds, selectedRepoNames)) {
      return null;
    }
    const type = String(data.type || "").toLowerCase();
    if (type === "nuclei") {
      return normalizeNucleiArtifact(manifest, data);
    }
    if (type === "semgrep") {
      return await normalizeSemgrepArtifact(manifest, data);
    }
    if (type === "burp") {
      return await normalizeBurpArtifact(manifest, data);
    }
    if (type === "httpx") {
      return await normalizeHttpxArtifact(manifest, data);
    }
    if (type === "katana") {
      return await normalizeKatanaArtifact(manifest, data);
    }
    return null;
  } catch {
    return null;
  }
}

function normalizeNucleiArtifact(manifest, data) {
  const resultsPath = resolveRelativeArtifactPath(manifest.dir, data.resultsPath);
  const findings = [];
  const lines = safeReadLines(resultsPath);
  for (const line of lines) {
    const entry = tryParseJson(line);
    if (!entry) continue;
    findings.push(normalizeNucleiFinding(entry, data, manifest));
  }

  return {
    type: "nuclei",
    manifestPath: manifest.path,
    resultsPath,
    createdAt: data.createdAt || new Date(manifest.mtimeMs || Date.now()).toISOString(),
    sourceLabel: data.sourceLabel || "nuclei",
    targetLabel: data.targetLabel || data.targetFile || "unknown",
    findings
  };
}

async function normalizeSemgrepArtifact(manifest, data) {
  const resultsPath = resolveRelativeArtifactPath(manifest.dir, data.resultsPath);
  const findings = [];
  const json = await safeReadJson(resultsPath);
  const results = Array.isArray(json?.results) ? json.results : [];

  for (const result of results) {
    findings.push(normalizeSemgrepFinding(result, data, manifest));
  }

  return {
    type: "semgrep",
    manifestPath: manifest.path,
    resultsPath,
    createdAt: data.createdAt || new Date(manifest.mtimeMs || Date.now()).toISOString(),
    sourceLabel: data.sourceLabel || "semgrep",
    targetLabel: data.targetLabel || data.repoPath || "unknown",
    findings
  };
}

async function normalizeBurpArtifact(manifest, data) {
  const resultsPath = resolveRelativeArtifactPath(manifest.dir, data.resultsPath);
  const findings = [];
  const json = await safeReadJson(resultsPath);
  const issues = Array.isArray(json?.issues)
    ? json.issues
    : Array.isArray(json?.results)
      ? json.results
      : Array.isArray(json)
        ? json
        : [];

  for (const issue of issues) {
    findings.push(normalizeBurpFinding(issue, data, manifest));
  }

  return {
    type: "burp",
    manifestPath: manifest.path,
    resultsPath,
    createdAt: data.createdAt || new Date(manifest.mtimeMs || Date.now()).toISOString(),
    sourceLabel: data.sourceLabel || "burp",
    targetLabel: data.targetLabel || data.targetUrl || data.projectName || "unknown",
    findings
  };
}

async function normalizeHttpxArtifact(manifest, data) {
  const resultsPath = resolveRelativeArtifactPath(manifest.dir, data.resultsPath);
  const findings = [];
  const entries = await readJsonlOrJsonArray(resultsPath);

  for (const entry of entries) {
    findings.push(normalizeHttpxFinding(entry, data, manifest));
  }

  return {
    type: "httpx",
    manifestPath: manifest.path,
    resultsPath,
    createdAt: data.createdAt || new Date(manifest.mtimeMs || Date.now()).toISOString(),
    sourceLabel: data.sourceLabel || "httpx",
    targetLabel: data.targetLabel || data.targetUrl || "unknown",
    findings
  };
}

async function normalizeKatanaArtifact(manifest, data) {
  const resultsPath = resolveRelativeArtifactPath(manifest.dir, data.resultsPath);
  const findings = [];
  const entries = await readJsonlOrJsonArray(resultsPath);

  for (const entry of entries) {
    findings.push(normalizeKatanaFinding(entry, data, manifest));
  }

  return {
    type: "katana",
    manifestPath: manifest.path,
    resultsPath,
    createdAt: data.createdAt || new Date(manifest.mtimeMs || Date.now()).toISOString(),
    sourceLabel: data.sourceLabel || "katana",
    targetLabel: data.targetLabel || data.targetUrl || "unknown",
    findings
  };
}

function normalizeNucleiFinding(entry, manifestData, manifest) {
  const severity = normalizeSeverity(entry?.info?.severity);
  const templateId = String(entry["template-id"] || entry.templateID || entry.template_id || "nuclei-template");
  const target = String(entry.host || entry["matched-at"] || entry.url || manifestData.targetLabel || "unknown");
  const evidenceParts = [
    entry["matched-at"] ? `matched-at: ${entry["matched-at"]}` : "",
    entry["curl-command"] ? `curl: ${entry["curl-command"]}` : "",
    entry.extracted_results?.length ? `extractors: ${entry.extracted_results.join(", ")}` : ""
  ].filter(Boolean);

  return {
    source: "nuclei",
    sourceFile: manifest.path,
    skillId: `nuclei:${templateId}`,
    title: entry?.info?.name || templateId,
    severity,
    confidence: estimateSignalScore({
      severity,
      evidence: evidenceParts.join(" | "),
      target,
      title: entry?.info?.name || templateId,
      source: "nuclei"
    }),
    location: target,
    evidence: evidenceParts.join(" | ") || entry["matched-at"] || target,
    impact: entry?.info?.description || entry?.info?.classification?.description || "Nuclei template matched an in-scope target.",
    remediation: entry?.info?.remediation || "Review the template match manually and verify impact before reporting.",
    safeValidation: "Confirm the finding with a second request or manual review inside the allowed scope.",
    templateId,
    matchedAt: entry["matched-at"] || "",
    signalScore: estimateSignalScore({
      severity,
      evidence: evidenceParts.join(" | "),
      target,
      title: entry?.info?.name || templateId,
      source: "nuclei"
    }),
    raw: entry
  };
}

function normalizeSemgrepFinding(result, manifestData, manifest) {
  const severity = normalizeSeverity(result?.extra?.severity || result?.extra?.metadata?.severity || "medium");
  const pathValue = String(result.path || manifestData.targetLabel || "unknown");
  const line = result?.start?.line ? `:${result.start.line}` : "";
  const evidence = [
    result?.extra?.message || "",
    Array.isArray(result?.extra?.lines) ? result.extra.lines.join("\n") : "",
    result?.extra?.metavars ? JSON.stringify(result.extra.metavars) : ""
  ].filter(Boolean).join(" | ");

  return {
    source: "semgrep",
    sourceFile: manifest.path,
    skillId: `semgrep:${result.check_id || "rule"}`,
    title: result?.extra?.message || result.check_id || "Semgrep finding",
    severity,
    confidence: estimateSignalScore({
      severity,
      evidence,
      target: `${pathValue}${line}`,
      title: result?.extra?.message || result.check_id || "Semgrep finding",
      source: "semgrep"
    }),
    location: `${pathValue}${line}`,
    evidence: evidence || result.check_id || pathValue,
    impact: result?.extra?.metadata?.owasp || result?.extra?.metadata?.shortlink || "Semgrep matched a suspicious code pattern.",
    remediation: result?.extra?.metadata?.fix || "Review the match and verify whether the code is actually exploitable.",
    safeValidation: "Open the referenced file and confirm the control flow and guards before submitting.",
    checkId: result.check_id || "",
    signalScore: estimateSignalScore({
      severity,
      evidence,
      target: `${pathValue}${line}`,
      title: result?.extra?.message || result.check_id || "Semgrep finding",
      source: "semgrep"
    }),
    raw: result
  };
}

function normalizeBurpFinding(issue, manifestData, manifest) {
  const severity = normalizeSeverity(issue?.severity || issue?.severityConfidence || issue?.risk || "medium");
  const host = String(issue?.host || issue?.url || manifestData.targetLabel || "unknown");
  const pathValue = String(issue?.path || issue?.url || issue?.issueBackground || host);
  const evidence = [
    issue?.issueName || issue?.name || "",
    issue?.issueDetail || issue?.detail || "",
    issue?.remediation || "",
    issue?.requestResponse || ""
  ].filter(Boolean).join(" | ");

  return {
    source: "burp",
    sourceFile: manifest.path,
    skillId: `burp:${issue?.issueName || issue?.name || "issue"}`,
    title: issue?.issueName || issue?.name || "Burp issue",
    severity,
    confidence: estimateSignalScore({
      severity,
      evidence,
      target: pathValue,
      title: issue?.issueName || issue?.name || "Burp issue",
      source: "burp"
    }),
    location: host,
    evidence: evidence || pathValue,
    impact: issue?.issueBackground || issue?.remediationBackground || "Burp reported a reusable issue signal.",
    remediation: issue?.remediation || "Review the issue manually and verify within scope before reporting.",
    safeValidation: "Use a manual request or browser replay to confirm the issue with minimal traffic.",
    issueName: issue?.issueName || issue?.name || "",
    signalScore: estimateSignalScore({
      severity,
      evidence,
      target: pathValue,
      title: issue?.issueName || issue?.name || "Burp issue",
      source: "burp"
    }),
    raw: issue
  };
}

function normalizeHttpxFinding(entry, manifestData, manifest) {
  const status = Number(entry?.status_code || entry?.status || 0);
  const title = String(entry?.title || entry?.page_title || entry?.url || "HTTPX result");
  const url = String(entry?.url || entry?.input || manifestData.targetLabel || "unknown");
  const tech = Array.isArray(entry?.tech) ? entry.tech.join(", ") : String(entry?.tech || entry?.webserver || "");
  const evidence = [
    status ? `status: ${status}` : "",
    entry?.webserver ? `server: ${entry.webserver}` : "",
    tech ? `tech: ${tech}` : "",
    entry?.content_length ? `length: ${entry.content_length}` : "",
    entry?.location ? `location: ${entry.location}` : ""
  ].filter(Boolean).join(" | ");
  const severity = status >= 500 ? "medium" : "low";

  return {
    source: "httpx",
    sourceFile: manifest.path,
    skillId: `httpx:${status || "surface"}`,
    title: title || "HTTP surface",
    severity,
    confidence: estimateSignalScore({
      severity,
      evidence,
      target: url,
      title,
      source: "httpx"
    }),
    location: url,
    evidence: evidence || url,
    impact: "Interesting live surface discovered for further manual review.",
    remediation: "Use the host, title, and headers as leads for scoped manual testing.",
    safeValidation: "Confirm the page or endpoint manually and capture only non-destructive evidence.",
    statusCode: status,
    signalScore: estimateSignalScore({
      severity,
      evidence,
      target: url,
      title,
      source: "httpx"
    }),
    raw: entry
  };
}

function normalizeKatanaFinding(entry, manifestData, manifest) {
  const url = String(entry?.url || entry?.input || entry?.request || manifestData.targetLabel || "unknown");
  const method = String(entry?.method || entry?.request_method || "").toUpperCase();
  const status = Number(entry?.status_code || entry?.status || 0);
  const sourceType = String(entry?.source_type || entry?.type || "");
  const title = String(entry?.title || entry?.page_title || entry?.path || "Katana endpoint");
  const evidence = [
    method ? `method: ${method}` : "",
    status ? `status: ${status}` : "",
    sourceType ? `source: ${sourceType}` : "",
    Array.isArray(entry?.tags) && entry.tags.length ? `tags: ${entry.tags.join(", ")}` : "",
    Array.isArray(entry?.forms) && entry.forms.length ? `forms: ${entry.forms.length}` : "",
    Array.isArray(entry?.params) && entry.params.length ? `params: ${entry.params.join(", ")}` : ""
  ].filter(Boolean).join(" | ");
  const severity = /(admin|login|upload|api|graphql|callback|redirect|token|debug|backup)/i.test(`${url} ${title} ${evidence}`)
    ? "medium"
    : "low";

  return {
    source: "katana",
    sourceFile: manifest.path,
    skillId: `katana:${sourceType || "surface"}`,
    title: title || "Katana endpoint",
    severity,
    confidence: estimateSignalScore({
      severity,
      evidence,
      target: url,
      title,
      source: "katana"
    }),
    location: url,
    evidence: evidence || url,
    impact: "Endpoint or parameter surface discovered for follow-up review.",
    remediation: "Use the endpoint map to prioritize scoped, non-destructive manual checks.",
    safeValidation: "Replay the request carefully and keep the workflow inside the allowed scope.",
    signalScore: estimateSignalScore({
      severity,
      evidence,
      target: url,
      title,
      source: "katana"
    }),
    raw: entry
  };
}

function buildSummary(artifacts) {
  return artifacts.map((artifact) => ({
    type: artifact.type,
    sourceLabel: artifact.sourceLabel,
    targetLabel: artifact.targetLabel,
    findings: artifact.findings.length,
    resultsPath: artifact.resultsPath
  }));
}

function prioritizeFindings(findings) {
  const seen = new Set();
  const sorted = [...findings]
    .map((finding) => ({
      ...finding,
      signalScore: normalizeScore(finding.signalScore, finding.confidence),
      bountyPriority: estimateBountyPriority(finding),
      reportabilityScore: estimateReportabilityScore(finding),
      status: finding.status || classifyFindingStatus(finding)
    }))
    .filter((finding) => {
      const key = buildDedupeKey(finding);
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .sort((a, b) => {
      const bountyDiff = (b.reportabilityScore || 0) - (a.reportabilityScore || 0);
      if (Math.abs(bountyDiff) > 1e-6) return bountyDiff;
      const scoreDiff = (b.signalScore || 0) - (a.signalScore || 0);
      if (Math.abs(scoreDiff) > 1e-6) return scoreDiff;
      const severityDiff = severityWeight(b.severity) - severityWeight(a.severity);
      if (severityDiff !== 0) return severityDiff;
      return (b.confidence || 0) - (a.confidence || 0);
    });

  return sorted;
}

function getExternalArtifactRoots() {
  const roots = [];
  if (process.env.BAI_OUTPUT_ROOT) {
    roots.push(process.env.BAI_OUTPUT_ROOT);
  }
  if (process.env.USERPROFILE) {
    roots.push(path.join(process.env.USERPROFILE, "Desktop", "codex", "runs"));
  }
  return Array.from(new Set(roots.filter(Boolean)));
}

function estimateBountyPriority(finding) {
  const base = {
    critical: 1,
    high: 0.9,
    medium: 0.7,
    low: 0.45,
    info: 0.2
  }[String(finding?.severity || "").toLowerCase()] ?? 0.5;
  const haystack = [
    finding?.title,
    finding?.location,
    finding?.evidence,
    finding?.impact
  ].filter(Boolean).join(" ").toLowerCase();

  let score = base;
  if (BOUNTY_REPORTABLE_PATTERNS.test(haystack)) score += 0.12;
  if (LOW_REPORTABILITY_PATTERNS.test(haystack)) score -= 0.2;
  if (/(admin|owner|tenant|role|auth|permission|payment|order|coupon|upload|api|graphql|callback|webhook)/i.test(haystack)) score += 0.06;
  return clamp(score, 0.05, 1);
}

function estimateReportabilityScore(finding) {
  const confidence = Number(finding?.confidence || 0);
  return clamp(estimateBountyPriority(finding) + confidence * 0.2 + (Number(finding?.signalScore || 0) * 0.1), 0, 1);
}

function classifyFindingStatus(finding) {
  const score = estimateReportabilityScore(finding);
  const haystack = [
    finding?.title,
    finding?.location,
    finding?.evidence,
    finding?.impact,
    finding?.remediation,
    finding?.safeValidation
  ].filter(Boolean).join(" ").toLowerCase();

  if (/(out.of.scope|not in scope|excluded asset|third.party|do not test)/i.test(haystack)) {
    return "out_of_scope";
  }
  if (/(verified|confirmed|reproduced|exploit succeeded|impact confirmed)/i.test(haystack)) {
    return "verified";
  }
  if (score >= 0.78 && BOUNTY_REPORTABLE_PATTERNS.test(haystack) && !LOW_REPORTABILITY_PATTERNS.test(haystack)) {
    return "candidate";
  }
  if (score < 0.42 || /(missing header|security header|fingerprint|version|banner|robots|sitemap|openapi|swagger only|technology detected)/i.test(haystack)) {
    return "not_reportable";
  }
  return "lead";
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = buildDedupeKey(finding);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function buildDedupeKey(finding) {
  return [
    String(finding.source || ""),
    String(finding.skillId || finding.checkId || finding.templateId || ""),
    String(finding.title || ""),
    String(finding.location || ""),
    String(finding.evidence || "").slice(0, 180)
  ].join("|");
}

function normalizeSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (text.includes("critical")) return "critical";
  if (text.includes("high")) return "high";
  if (text.includes("medium") || text.includes("moderate")) return "medium";
  if (text.includes("low")) return "low";
  if (text.includes("info")) return "info";
  return "medium";
}

function estimateSignalScore({ severity, evidence, target, title, source }) {
  let score = SEVERITY_SCORE[severity] || 0.6;
  const haystack = `${evidence || ""} ${target || ""} ${title || ""}`.toLowerCase();

  if ((evidence || "").length > 30) score += 0.05;
  if ((evidence || "").length > 90) score += 0.05;
  if (HIGH_SIGNAL_PATTERNS.test(haystack)) score += 0.08;
  if (BOUNTY_REPORTABLE_PATTERNS.test(haystack)) score += 0.12;
  if (LOW_REPORTABILITY_PATTERNS.test(haystack)) score -= 0.18;
  if (/(matched-at|curl|request|response|payload|path|line|metavar)/i.test(evidence || "")) score += 0.05;
  if (source === "nuclei" && /(http|https|url|host|ip|domain)/i.test(haystack)) score += 0.04;
  if (source === "semgrep" && /[:/]/.test(target || "")) score += 0.04;

  return clamp(score, 0.1, 0.99);
}

function normalizeScore(signalScore, confidence) {
  const raw = Number.isFinite(Number(signalScore)) ? Number(signalScore) : Number(confidence) || 0;
  return clamp(raw, 0, 1);
}

function severityWeight(value) {
  switch (String(value || "").toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

async function safeReadLines(filePath) {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return content.split(/\r?\n/).filter(Boolean);
  } catch {
    return [];
  }
}

async function safeReadJson(filePath) {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return JSON.parse(content);
  } catch {
    return {};
  }
}

async function readJsonlOrJsonArray(filePath) {
  const lines = await safeReadLines(filePath);
  const lineEntries = lines
    .map((line) => tryParseJson(line))
    .filter(Boolean);
  if (lineEntries.length) {
    return lineEntries;
  }

  const json = await safeReadJson(filePath);
  if (Array.isArray(json)) {
    return json;
  }
  if (Array.isArray(json?.results)) {
    return json.results;
  }
  if (Array.isArray(json?.items)) {
    return json.items;
  }
  return [];
}

function tryParseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function resolveRelativeArtifactPath(baseDir, inputPath) {
  if (!inputPath) return "";
  if (path.isAbsolute(inputPath)) return inputPath;
  return path.join(baseDir, inputPath);
}

async function isDirectory(value) {
  try {
    return (await fs.stat(value)).isDirectory();
  } catch {
    return false;
  }
}

function matchesSelectionData(data, selectedProjectIds, selectedRepoNames) {
  if (!selectedProjectIds.size && !selectedRepoNames.size) {
    return true;
  }

  const blob = [
    data.projectId,
    data.projectName,
    data.repoName,
    data.repoPath,
    data.targetLabel,
    data.targetFile,
    data.sourceLabel,
    data.scopeTag,
    data.targetUrl
  ].filter(Boolean).join(" ").toLowerCase();

  if (!blob) {
    return false;
  }

  return Array.from(selectedProjectIds).some((id) => blob.includes(String(id).toLowerCase()))
    || Array.from(selectedRepoNames).some((name) => blob.includes(String(name).toLowerCase()));
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number.isFinite(Number(value)) ? Number(value) : min));
}
