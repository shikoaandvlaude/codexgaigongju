import { promises as fs } from "node:fs";
import path from "node:path";
import {
  buildProgramSearchQueries,
  getProgramProfileById,
  getProgramQuery,
  isProgramRelevant
} from "../config/programProfiles.js";

const SAMPLE_REPOS = [
  {
    full_name: "strapi/strapi",
    html_url: "https://github.com/strapi/strapi",
    description: "Open-source headless CMS.",
    stargazers_count: 67000,
    forks_count: 8600,
    language: "TypeScript",
    updated_at: "2026-04-05T08:00:00Z",
    pushed_at: "2026-04-08T06:20:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "nodejs"]
  },
  {
    full_name: "directus/directus",
    html_url: "https://github.com/directus/directus",
    description: "Composable data platform and headless CMS.",
    stargazers_count: 31000,
    forks_count: 4200,
    language: "TypeScript",
    updated_at: "2026-04-06T12:00:00Z",
    pushed_at: "2026-04-08T09:10:00Z",
    default_branch: "main",
    topics: ["cms", "headless-cms", "content-api"]
  },
  {
    full_name: "kubernetes/kubernetes",
    html_url: "https://github.com/kubernetes/kubernetes",
    description: "Production-Grade Container Scheduling and Management.",
    stargazers_count: 115000,
    forks_count: 40000,
    language: "Go",
    updated_at: "2026-04-07T10:00:00Z",
    pushed_at: "2026-04-08T18:20:00Z",
    default_branch: "main",
    topics: ["kubernetes", "cloud-native", "container"]
  },
  {
    full_name: "helm/helm",
    html_url: "https://github.com/helm/helm",
    description: "The Kubernetes Package Manager.",
    stargazers_count: 29000,
    forks_count: 7600,
    language: "Go",
    updated_at: "2026-04-07T10:00:00Z",
    pushed_at: "2026-04-08T18:20:00Z",
    default_branch: "main",
    topics: ["kubernetes", "helm", "cloud-native"]
  }
];

const CMS_TYPE_KEYWORDS = {
  all: [],
  headless: ["headless", "api-first", "content api", "content-api"],
  blog: ["blog", "publishing", "editorial", "news"],
  ecommerce: ["ecommerce", "e-commerce", "shop", "storefront", "shopping"],
  enterprise: ["enterprise", "digital experience", "portal", "dxp"],
  education: ["lms", "education", "learning", "course"],
  flatfile: ["flat-file", "flat file", "markdown"]
};

const INDUSTRY_KEYWORDS = {
  all: [],
  education: ["education", "learning", "course", "student", "campus"],
  ecommerce: ["ecommerce", "store", "shop", "product", "catalog"],
  media: ["media", "editorial", "news", "publishing", "magazine"],
  enterprise: ["enterprise", "portal", "workflow", "business"],
  government: ["government", "public sector", "civic", "municipal"],
  community: ["forum", "community", "member", "social"]
};

const REVIEWABLE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".php",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".xml",
  ".graphql",
  ".gql"
]);

const IGNORED_SEGMENTS = [
  "node_modules/",
  "dist/",
  "build/",
  "coverage/",
  ".next/",
  ".nuxt/",
  "vendor/",
  "fixtures/",
  "__snapshots__/",
  "storybook-static/",
  "public/build/"
];

const DISCOVERY_FILE_LIMIT = 16;
const DISCOVERY_MAX_FILE_SIZE = 120_000;
const AUDIT_MIRROR_FILE_LIMIT = 180;
const AUDIT_MIRROR_MAX_FILE_SIZE = 400_000;
const AUDIT_MIRROR_MAX_TOTAL_BYTES = 12_000_000;
const FETCH_RETRY_LIMIT = 3;

const PROGRAM_KEYWORDS = {
  cms: [
    "cms",
    "headless",
    "content management",
    "content platform",
    "blog",
    "admin panel",
    "publishing",
    "editorial"
  ],
  kubernetes: [
    "kubernetes",
    "k8s",
    "cloud native",
    "helm",
    "operator",
    "ingress",
    "crd",
    "admission",
    "webhook",
    "serviceaccount",
    "namespace",
    "cluster",
    "pod",
    "configmap",
    "secret",
    "rbac"
  ],
  "general-oss": [
    "auth",
    "api",
    "service",
    "platform",
    "controller",
    "workflow",
    "dashboard"
  ],
  fintech: [
    "fintech",
    "finance",
    "banking",
    "payment",
    "wallet",
    "transfer",
    "withdraw",
    "deposit",
    "kyc",
    "aml",
    "trading",
    "portfolio",
    "brokerage",
    "invoice",
    "billing",
    "ledger",
    "risk",
    "compliance",
    "2fa",
    "mfa"
  ]
};

export class FrameworkScoutAgent {
  constructor({ downloadsDir, getGithubConfig }) {
    this.downloadsDir = downloadsDir;
    this.getGithubConfig = getGithubConfig || (() => ({}));
  }

  async run({ query, cmsType = "all", industry = "all", minAdoption = 0, programProfile = "general-oss" }) {
    const source = await this.fetchTrendingFrameworks(query, programProfile);
    const projects = [];

    for (const repo of source) {
      const project = await this.materializeProject(repo, programProfile);
      if (!matchesProjectFilters(project, { cmsType, industry, minAdoption })) {
        continue;
      }
      projects.push(project);
    }

    const profile = getProgramProfileById(programProfile);
    return {
      sourceMode: source === SAMPLE_REPOS ? "sample-fallback" : "live-github",
      query: normalizeProgramQuery(query, programProfile),
      cmsType,
      industry,
      programProfile: profile.id,
      discoveredAt: new Date().toISOString(),
      summary: `已发现 ${projects.length} 个候选项目。选择目标后会先下载审计镜像，再执行规则层和 LLM 复核。`,
      projects
    };
  }

  async ensureProjectSample(project) {
    await this.saveSourceSnapshot(project, { mode: "discovery-sample" });
    return project;
  }

  async ensureProjectMirror(project, options = {}) {
    const sourceRoot = await this.saveSourceSnapshot(project, { mode: "audit-mirror", ...options });
    project.localPath = sourceRoot;
    project.auditMirrorReady = true;
    return project;
  }

  async fetchTrendingFrameworks(query, programProfile = "general-oss") {
    try {
      const github = await this.getGithubConfig();
      const collected = new Map();
      let successCount = 0;

      for (const searchQuery of buildProgramSearchQueries(query, github.ownerFilter, programProfile)) {
        const q = encodeURIComponent(searchQuery);
        const response = await this.fetchGithubResource(
          `https://api.github.com/search/repositories?q=${q}&sort=stars&order=desc&per_page=30`,
          github.token
        );

        if (!response.ok) {
          continue;
        }

        successCount += 1;
        const data = await response.json();
        const items = Array.isArray(data.items) ? data.items : [];
        for (const repo of items) {
          if (!isProgramRelevant(repo, programProfile)) {
            continue;
          }
          const current = collected.get(repo.full_name);
          if (!current || scoreRepo(repo, programProfile) > scoreRepo(current, programProfile)) {
            collected.set(repo.full_name, repo);
          }
        }
      }

      if (!successCount) {
        throw new Error("GitHub search failed");
      }

      const filtered = Array.from(collected.values())
        .sort((a, b) => scoreRepo(b, programProfile) - scoreRepo(a, programProfile))
        .slice(0, 60);

      const fallback = SAMPLE_REPOS.filter((repo) => isProgramRelevant(repo, programProfile));
      return filtered.length ? filtered : (fallback.length ? fallback : SAMPLE_REPOS);
    } catch {
      const fallback = SAMPLE_REPOS.filter((repo) => isProgramRelevant(repo, programProfile));
      return fallback.length ? fallback : SAMPLE_REPOS;
    }
  }

  async materializeProject(repo, programProfile = "general-oss") {
    const [owner, name] = repo.full_name.split("/");
    const traits = inferProjectTraits(repo, programProfile);
    const auditSurfaceHints = inferAuditSurfaceHints(repo, traits);
    const recommendedSkillIds = deriveRecommendedSkillIds(repo, traits, auditSurfaceHints);
    const archiveFileName = `${owner}__${name}.json`;

    return {
      id: `${owner}-${name}`,
      sourceType: "github",
      name,
      owner,
      repoUrl: repo.html_url,
      localPath: "",
      description: repo.description,
      language: repo.language || "Unknown",
      defaultBranch: repo.default_branch || "main",
      updatedAt: repo.updated_at,
      pushedAt: repo.pushed_at,
      downloadArtifact: archiveFileName,
      programProfile: traits.programProfile,
      programFamily: traits.programFamily,
      cmsType: traits.cmsType,
      industries: traits.industries,
      tags: traits.tags,
      auditSurfaceHints,
      recommendedSkillIds,
      adoptionSignals: {
        stars: repo.stargazers_count || 0,
        forks: repo.forks_count || 0,
        estimatedLiveUsage: this.estimateLiveUsage(repo, programProfile)
      }
    };
  }

  estimateLiveUsage(repo, programProfile = "general-oss") {
    const stars = repo.stargazers_count || 0;
    const forks = repo.forks_count || 0;
    const topicBoost = isProgramRelevant(repo, programProfile) ? 40 : 0;
    return Math.round(stars * 0.018 + forks * 0.28 + topicBoost);
  }

  async saveSourceSnapshot(project, { mode, onProgress }) {
    const sourceRoot = path.join(this.downloadsDir, project.id);
    await fs.rm(sourceRoot, { recursive: true, force: true });
    await fs.mkdir(sourceRoot, { recursive: true });

    const mirroredFiles =
      mode === "audit-mirror"
        ? await this.downloadAuditMirror(project, sourceRoot, onProgress)
        : await this.downloadSourceSample(project, sourceRoot, onProgress);

    const payload = {
      project: {
        ...project,
        localPath: mode === "audit-mirror" ? sourceRoot : project.localPath
      },
      snapshotAt: new Date().toISOString(),
      sourceRoot,
      mirrorMode: mode,
      mirroredFiles,
      note:
        mode === "audit-mirror"
          ? "This is a defensive audit mirror used for local rule review and LLM review after manual target selection."
          : "This is a defensive discovery sample used to preview candidate repositories before audit."
    };

    const target = path.join(this.downloadsDir, project.downloadArtifact);
    await fs.writeFile(target, JSON.stringify(payload, null, 2), "utf8");
    return sourceRoot;
  }

  async downloadSourceSample(project, sourceRoot, onProgress) {
    try {
      const github = await this.getGithubConfig();
      const tree = await this.fetchProjectTree(project, github.token);
      const candidateFiles = tree
        .filter((entry) => shouldIncludePath(entry.path))
        .filter((entry) => (entry.size || 0) > 0 && (entry.size || 0) <= DISCOVERY_MAX_FILE_SIZE)
        .sort((a, b) => rankPath(b.path) - rankPath(a.path))
        .slice(0, DISCOVERY_FILE_LIMIT);

      const downloaded = await this.downloadEntries(project, candidateFiles, sourceRoot, github.token, {
        maxFiles: DISCOVERY_FILE_LIMIT,
        maxTotalBytes: AUDIT_MIRROR_MAX_TOTAL_BYTES,
        onProgress
      });

      if (!downloaded.length) {
        await this.writeFallbackSourceSample(project, sourceRoot);
        return [{ path: "SAFE_SAMPLE.md", size: 0 }];
      }

      return downloaded;
    } catch {
      await this.writeFallbackSourceSample(project, sourceRoot);
      return [{ path: "SAFE_SAMPLE.md", size: 0 }];
    }
  }

  async downloadAuditMirror(project, sourceRoot, onProgress) {
    try {
      const github = await this.getGithubConfig();
      const tree = await this.fetchProjectTree(project, github.token);
      const candidateFiles = tree
        .filter((entry) => shouldMirrorPath(entry.path))
        .filter((entry) => (entry.size || 0) > 0 && (entry.size || 0) <= AUDIT_MIRROR_MAX_FILE_SIZE)
        .sort((a, b) => rankMirrorPath(b.path) - rankMirrorPath(a.path) || (a.size || 0) - (b.size || 0))
        .slice(0, AUDIT_MIRROR_FILE_LIMIT * 2);

      const downloaded = await this.downloadEntries(project, candidateFiles, sourceRoot, github.token, {
        maxFiles: AUDIT_MIRROR_FILE_LIMIT,
        maxTotalBytes: AUDIT_MIRROR_MAX_TOTAL_BYTES,
        onProgress
      });

      if (!downloaded.length) {
        await this.writeFallbackSourceSample(project, sourceRoot);
        return [{ path: "SAFE_SAMPLE.md", size: 0 }];
      }

      return downloaded;
    } catch {
      await this.writeFallbackSourceSample(project, sourceRoot);
      return [{ path: "SAFE_SAMPLE.md", size: 0 }];
    }
  }

  async fetchProjectTree(project, token) {
    const refs = await this.resolveTreeRefs(project, token);

    for (const ref of refs) {
      const treeUrl = `https://api.github.com/repos/${project.owner}/${project.name}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
      const treeResponse = await this.fetchGithubResource(treeUrl, token);
      if (!treeResponse.ok) {
        continue;
      }

      const treeData = await treeResponse.json();
      project.defaultBranch = ref;
      return (treeData.tree || []).filter((entry) => entry.type === "blob");
    }

    throw new Error("Tree fetch failed");
  }

  async downloadEntries(project, entries, sourceRoot, token, { maxFiles, maxTotalBytes, onProgress }) {
    const downloaded = [];
    let totalBytes = 0;
    const totalCandidates = Math.min(entries.length, maxFiles);
    let processedCandidates = 0;

    for (const entry of entries) {
      if (downloaded.length >= maxFiles) {
        break;
      }

      try {
        const text = await this.fetchRawFile(project, entry.path, token);
        if (!text) {
          processedCandidates += 1;
          onProgress?.({
            type: "mirror-file",
            projectId: project.id,
            downloaded: downloaded.length,
            processed: processedCandidates,
            total: totalCandidates,
            currentPath: entry.path
          });
          continue;
        }

        const byteLength = Buffer.byteLength(text, "utf8");
        if (downloaded.length && totalBytes + byteLength > maxTotalBytes) {
          processedCandidates += 1;
          onProgress?.({
            type: "mirror-file",
            projectId: project.id,
            downloaded: downloaded.length,
            processed: processedCandidates,
            total: totalCandidates,
            currentPath: entry.path
          });
          continue;
        }

        const target = path.join(sourceRoot, ...entry.path.split("/"));
        await fs.mkdir(path.dirname(target), { recursive: true });
        await fs.writeFile(target, text, "utf8");

        downloaded.push({ path: entry.path, size: byteLength });
        totalBytes += byteLength;
        processedCandidates += 1;
        onProgress?.({
          type: "mirror-file",
          projectId: project.id,
          downloaded: downloaded.length,
          processed: processedCandidates,
          total: totalCandidates,
          currentPath: entry.path
        });
      } catch {
        processedCandidates += 1;
        onProgress?.({
          type: "mirror-file",
          projectId: project.id,
          downloaded: downloaded.length,
          processed: processedCandidates,
          total: totalCandidates,
          currentPath: entry.path
        });
      }
    }

    return downloaded;
  }

  async fetchRawFile(project, filePath, token) {
    const contentUrl = `https://raw.githubusercontent.com/${project.owner}/${project.name}/${project.defaultBranch}/${filePath}`;
    try {
      const contentResponse = await this.fetchRawResource(contentUrl, token);
      if (!contentResponse.ok) {
        return "";
      }
      return contentResponse.text();
    } catch {
      return "";
    }
  }

  async resolveTreeRefs(project, token) {
    const refs = [project.defaultBranch, "main", "master", "develop", "next"];

    try {
      const repoResponse = await this.fetchGithubResource(`https://api.github.com/repos/${project.owner}/${project.name}`, token);
      if (repoResponse.ok) {
        const repoData = await repoResponse.json();
        if (repoData.default_branch) {
          refs.unshift(repoData.default_branch);
        }
      }
    } catch {
      // ignore
    }

    return [...new Set(refs.filter(Boolean))];
  }

  async fetchGithubResource(url, token) {
    let lastError = null;
    for (let attempt = 0; attempt < FETCH_RETRY_LIMIT; attempt += 1) {
      try {
        let response = await fetch(url, { headers: this.buildGithubHeaders(token) });
        if (response.status === 401 && token) {
          response = await fetch(url, { headers: this.buildGithubHeaders("") });
        }
        return response;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("GitHub request failed");
  }

  async fetchRawResource(url, token) {
    let lastError = null;
    for (let attempt = 0; attempt < FETCH_RETRY_LIMIT; attempt += 1) {
      try {
        let response = await fetch(url, { headers: this.buildRawHeaders(token) });
        if (!response.ok && token) {
          response = await fetch(url, { headers: this.buildRawHeaders("") });
        }
        return response;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("Raw file request failed");
  }

  buildGithubHeaders(token) {
    const headers = {
      "User-Agent": "safe-framework-audit-agents",
      Accept: "application/vnd.github+json"
    };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return headers;
  }

  buildRawHeaders() {
    return { "User-Agent": "safe-framework-audit-agents" };
  }

  async writeFallbackSourceSample(project, sourceRoot) {
    const fallback = [
      `# ${project.owner}/${project.name}`,
      "",
      "Safe source mirroring was unavailable for this repository in the current environment.",
      "",
      "Use the metadata snapshot for triage, then rerun in an environment with GitHub raw/tree access if you want code-backed review."
    ].join("\n");

    await fs.mkdir(sourceRoot, { recursive: true });
    await fs.writeFile(path.join(sourceRoot, "SAFE_SAMPLE.md"), fallback, "utf8");
  }
}

function normalizeProgramQuery(query, programProfile = "general-oss") {
  const raw = String(query || "").trim();
  if (raw) {
    return raw;
  }
  return getProgramQuery(programProfile);
}

function buildSearchQueries(query, ownerFilter, programProfile = "general-oss") {
  return buildProgramSearchQueries(query, ownerFilter, programProfile);
}

function isProfileKeywordMatch(repo, programProfile = "general-oss") {
  const keywords = PROGRAM_KEYWORDS[programProfile] || PROGRAM_KEYWORDS.cms;
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  return keywords.some((keyword) => text.includes(keyword.toLowerCase()));
}

function isCmsLike(repo) {
  return isProfileKeywordMatch(repo, "cms");
}

function isProgramRelevantProxy(repo, programProfile = "general-oss") {
  return isProgramRelevant(repo, programProfile) || (programProfile === "cms" ? isCmsLike(repo) : isProfileKeywordMatch(repo, programProfile));
}

function scoreRepo(repo, programProfile = "general-oss") {
  const stars = repo.stargazers_count || 0;
  const forks = repo.forks_count || 0;
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  const keywords = PROGRAM_KEYWORDS[programProfile] || PROGRAM_KEYWORDS.cms;
  const keywordBoost = keywords.reduce((sum, keyword) => sum + (text.includes(keyword) ? 1800 : 0), 0);
  const securitySurfaceBoost = [
    "auth",
    "login",
    "permission",
    "role",
    "upload",
    "storage",
    "api",
    "graphql",
    "admin",
    "config",
    "bootstrap",
    "seed",
    "secret",
    "token",
    "kubernetes",
    "helm",
    "operator",
    "rbac",
    "serviceaccount",
    "admission",
    "webhook"
  ].reduce((sum, keyword) => sum + (text.includes(keyword) ? 450 : 0), 0);
  const freshnessBoost = calculateFreshnessBoost(repo.pushed_at || repo.updated_at);
  return stars * 1.05 + forks * 2.15 + keywordBoost + securitySurfaceBoost + freshnessBoost;
}

function inferProjectTraits(repo, programProfile = "general-oss") {
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  const profile = getProgramProfileById(programProfile);
  const programFamily = profile.family || "general";

  let cmsType = "generic";
  let industries = ["general"];
  if (programProfile === "cms") {
    cmsType = Object.entries(CMS_TYPE_KEYWORDS).find(([key, values]) => key !== "all" && values.some((value) => text.includes(value)))?.[0] || "generic";
    industries = Object.entries(INDUSTRY_KEYWORDS)
      .filter(([key, values]) => key !== "all" && values.some((value) => text.includes(value)))
      .map(([key]) => key);
    if (!industries.length) {
      industries = ["general"];
    }
  } else if (programProfile === "kubernetes") {
    industries = ["infrastructure"];
  } else if (programProfile === "fintech") {
    industries = ["fintech"];
  } else {
    industries = ["general"];
  }

  const tags = Array.from(
    new Set([
      ...(repo.topics || []),
      programProfile,
      programFamily,
      cmsType,
      ...(industries.length ? industries : ["general"])
    ])
  );

  return {
    programProfile,
    programFamily,
    cmsType,
    industries,
    tags
  };
}

function inferAuditSurfaceHints(repo, traits) {
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")} ${(traits?.tags || []).join(" ")}`.toLowerCase();
  const hints = [];

  if (/(auth|login|session|permission|policy|role|rbac|access)/.test(text)) {
    hints.push("access-control");
  }
  if (/(upload|storage|asset|media|file|s3|minio|r2)/.test(text)) {
    hints.push("upload-storage", "path-traversal");
  }
  if (/(api|graphql|endpoint|resolver|content-api|rest)/.test(text)) {
    hints.push("query-safety", "ssrf");
  }
  if (/(secret|token|key|config|env|credential|jwt)/.test(text)) {
    hints.push("secret-exposure", "bootstrap-config");
  }
  if (/(payment|order|cart|coupon|withdraw|wallet|billing)/.test(text)) {
    hints.push("access-control", "query-safety");
  }
  if (traits?.programFamily === "fintech" || /(fintech|kyc|aml|trading|portfolio|brokerage|ledger|transfer|deposit|withdraw|wallet|payment|billing|invoice|2fa|mfa|risk|compliance)/.test(text)) {
    hints.push("access-control", "query-safety", "ssrf", "cicd-exposure", "dependency-risk");
  }
  if (/(javascript|typescript|react|vue|next|nuxt|express|koa|nest|node)/.test(text)) {
    hints.push("xss", "query-safety");
  }
  if (/(php|laravel|wordpress|drupal|joomla)/.test(text)) {
    hints.push("bootstrap-config", "secret-exposure");
  }
  if (/(java|spring|python|django|go)/.test(text)) {
    hints.push("deserialization", "command-injection");
  }
  if (traits?.programFamily === "cloud-native" || /(kubernetes|k8s|helm|operator|ingress|admission|webhook|serviceaccount|namespace|pod|cluster|crd)/.test(text)) {
    hints.push("access-control", "secret-exposure", "bootstrap-config", "cloud-misconfig", "cicd-exposure", "debug-backup");
  }

  return Array.from(new Set(hints));
}

function deriveRecommendedSkillIds(repo, traits, auditSurfaceHints) {
  const ids = new Set(auditSurfaceHints);
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")} ${(traits?.tags || []).join(" ")}`.toLowerCase();

  if (/(admin|dashboard|panel|backoffice)/.test(text)) {
    ids.add("access-control");
  }
  if (/(plugin|bootstrap|seed|init|install)/.test(text)) {
    ids.add("bootstrap-config");
  }
  if (/(error|debug|log|trace|stack)/.test(text)) {
    ids.add("secret-exposure");
  }
  if (traits?.programFamily === "cloud-native" || /(kubernetes|k8s|helm|operator|ingress|admission|webhook|serviceaccount|namespace|pod|cluster|crd)/.test(text)) {
    ids.add("secret-exposure");
    ids.add("bootstrap-config");
    ids.add("access-control");
    ids.add("cloud-misconfig");
    ids.add("cicd-exposure");
    ids.add("debug-backup");
  }

  return Array.from(ids);
}

function matchesProjectFilters(project, { cmsType, industry, minAdoption }) {
  if (Number(project.adoptionSignals?.estimatedLiveUsage || 0) < Number(minAdoption || 0)) {
    return false;
  }
  if (cmsType && cmsType !== "all" && project.cmsType !== cmsType) {
    return false;
  }
  if (industry && industry !== "all" && !(project.industries || []).includes(industry)) {
    return false;
  }
  return true;
}

function shouldIncludePath(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(segment))) {
    return false;
  }

  const interestingNames = [
    "auth",
    "login",
    "session",
    "permission",
    "policy",
    "upload",
    "storage",
    "admin",
    "config",
    "controller",
    "route",
    "api",
    "middleware",
    "access",
    "rbac",
    "role",
    "plugin",
    "bootstrap",
    "seed",
    "collection",
    "schema",
    "kube",
    "helm",
    "operator",
    "ingress",
    "cluster",
    "admission",
    "webhook",
    "payment",
    "wallet",
    "billing",
    "invoice",
    "ledger",
    "kyc",
    "aml",
    "trade",
    "trading",
    "portfolio",
    "withdraw",
    "deposit",
    "transfer",
    "risk",
    "compliance"
  ];

  return REVIEWABLE_EXTENSIONS.has(path.extname(lowered)) && interestingNames.some((token) => lowered.includes(token));
}

function shouldMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(segment))) {
    return false;
  }

  const boostedSegments = [
    "auth",
    "login",
    "session",
    "permission",
    "policy",
    "upload",
    "storage",
    "admin",
    "config",
    "controller",
    "route",
    "api",
    "middleware",
    "access",
    "rbac",
    "role",
    "plugin",
    "graphql",
    "bootstrap",
    "seed",
    "schema",
    "security",
    "kube",
    "helm",
    "operator",
    "ingress",
    "cluster",
    "admission",
    "webhook",
    "payment",
    "wallet",
    "billing",
    "invoice",
    "ledger",
    "kyc",
    "aml",
    "trade",
    "trading",
    "portfolio",
    "withdraw",
    "deposit",
    "transfer",
    "risk",
    "compliance"
  ];

  return REVIEWABLE_EXTENSIONS.has(path.extname(lowered)) && boostedSegments.some((token) => lowered.includes(token));
}

function rankPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = 0;
  if (/auth|permission|policy|access|role/.test(lowered)) score += 90;
  if (/upload|storage|asset/.test(lowered)) score += 75;
  if (/admin|route|controller|middleware|graphql|api/.test(lowered)) score += 60;
  if (/config|bootstrap|seed|schema/.test(lowered)) score += 40;
  if (/kube|helm|operator|ingress|cluster|admission|webhook/.test(lowered)) score += 85;
  return score;
}

function rankMirrorPath(filePath) {
  const lowered = filePath.toLowerCase();
  let score = rankPath(filePath);
  if (/test|spec/.test(lowered)) score -= 30;
  if (/users-permissions|authentication|graphql/.test(lowered)) score += 45;
  return score;
}

function calculateFreshnessBoost(dateValue) {
  if (!dateValue) {
    return 0;
  }
  const ageMs = Date.now() - new Date(dateValue).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  if (ageDays <= 14) return 4000;
  if (ageDays <= 45) return 2200;
  if (ageDays <= 90) return 900;
  return 0;
}
