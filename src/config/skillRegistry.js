import { getAuditSkillCatalog, resolveAuditSkills } from "./auditSkills.js";

const SKILL_METADATA = {
  "access-control": {
    version: "1.2.0",
    cacheScope: "project",
    priority: 5,
    surfaces: ["auth", "admin", "rbac", "tenant", "api"],
    dependencies: ["query-safety"],
    signalKeywords: ["permission", "owner", "role", "policy", "guard", "session"],
    evolutionCue: "Track repeated IDOR, role drift, anonymous admin paths, and owner-check omissions."
  },
  "bootstrap-config": {
    version: "1.1.0",
    cacheScope: "project",
    priority: 3,
    surfaces: ["bootstrap", "seed", "config", "env", "setup"],
    dependencies: ["secret-exposure"],
    signalKeywords: ["init", "seed", "bootstrap", "default", "debug", "dev"],
    evolutionCue: "Watch for one-time setup code that can be replayed or left in production mode."
  },
  "upload-storage": {
    version: "1.1.0",
    cacheScope: "project",
    priority: 4,
    surfaces: ["upload", "storage", "file", "asset", "media"],
    dependencies: ["path-traversal", "access-control"],
    signalKeywords: ["upload", "multer", "file", "path", "bucket", "storage"],
    evolutionCue: "Track file lifecycle, extension handling, storage routing, and cleanup gaps."
  },
  "query-safety": {
    version: "1.2.0",
    cacheScope: "file",
    priority: 5,
    surfaces: ["sql", "nosql", "filter", "sort", "graphql", "api"],
    dependencies: ["access-control"],
    signalKeywords: ["query", "filter", "sort", "where", "find", "execute"],
    evolutionCue: "Keep the model focused on user-controlled predicates, sort fields, and raw query builders."
  },
  "secret-exposure": {
    version: "1.1.0",
    cacheScope: "repo",
    priority: 4,
    surfaces: ["config", "env", "secret", "token", "credential"],
    dependencies: [],
    signalKeywords: ["secret", "token", "key", "password", "env", "credential", "jwt"],
    evolutionCue: "Prefer hardcoded secret detection, leaked env values, and public bundle exposure."
  },
  ssrf: {
    version: "1.1.0",
    cacheScope: "project",
    priority: 4,
    surfaces: ["fetch", "proxy", "callback", "webhook", "url"],
    dependencies: ["query-safety"],
    signalKeywords: ["url", "callback", "webhook", "proxy", "fetch", "axios"],
    evolutionCue: "Watch for user-controlled outbound requests, callbacks, webhook routing, and internal host access."
  },
  "command-injection": {
    version: "1.1.0",
    cacheScope: "repo",
    priority: 4,
    surfaces: ["shell", "exec", "spawn", "cli", "automation"],
    dependencies: ["path-traversal"],
    signalKeywords: ["exec", "spawn", "shell", "command", "argv"],
    evolutionCue: "Focus on command construction, shell flags, and argument concatenation paths."
  },
  "path-traversal": {
    version: "1.0.0",
    cacheScope: "repo",
    priority: 4,
    surfaces: ["filesystem", "download", "upload", "read", "write"],
    dependencies: ["upload-storage"],
    signalKeywords: ["path", "file", "download", "read", "write", "archive"],
    evolutionCue: "Watch file path joins, archive extraction, download handlers, and naming controls."
  },
  xss: {
    version: "1.0.0",
    cacheScope: "file",
    priority: 4,
    surfaces: ["render", "template", "ui", "markdown", "html"],
    dependencies: ["access-control"],
    signalKeywords: ["html", "template", "render", "innerhtml", "v-html", "dangerouslysetinnerhtml"],
    evolutionCue: "Track reflected and stored output sinks, escaped templates, and markdown rendering paths."
  },
  deserialization: {
    version: "1.0.0",
    cacheScope: "repo",
    priority: 3,
    surfaces: ["parse", "load", "yaml", "json", "pickle"],
    dependencies: ["secret-exposure"],
    signalKeywords: ["parse", "load", "yaml", "json", "pickle", "deserialize"],
    evolutionCue: "Watch unsafe loaders, dynamic evaluation, and parser input that crosses trust boundaries."
  },
  "exposed-surface": {
    version: "0.1.0",
    cacheScope: "project",
    priority: 2,
    surfaces: ["admin", "swagger", "actuator", "debug", "health", "backup"],
    dependencies: ["secret-exposure", "access-control"],
    signalKeywords: ["swagger", "openapi", "actuator", "admin", "debug", "backup", "health"],
    evolutionCue: "Use as a supplementary HW-style surface review, not as the main bounty path."
  },
  "weak-credential": {
    version: "0.1.0",
    cacheScope: "repo",
    priority: 2,
    surfaces: ["login", "seed", "demo", "default", "credential"],
    dependencies: ["bootstrap-config", "secret-exposure"],
    signalKeywords: ["admin", "password", "default", "demo", "test", "changeme"],
    evolutionCue: "Track only authorized, evidence-backed default credential risks."
  },
  "cloud-misconfig": {
    version: "0.1.0",
    cacheScope: "repo",
    priority: 2,
    surfaces: ["s3", "oss", "cos", "cdn", "bucket", "iam"],
    dependencies: ["secret-exposure"],
    signalKeywords: ["bucket", "s3", "oss", "cos", "acl", "policy", "public-read"],
    evolutionCue: "Focus on public exposure and over-broad cloud policy signals."
  },
  "cicd-exposure": {
    version: "0.1.0",
    cacheScope: "repo",
    priority: 2,
    surfaces: ["ci", "cd", "runner", "artifact", "secret"],
    dependencies: ["secret-exposure", "command-injection"],
    signalKeywords: ["jenkins", "github actions", "gitlab-ci", "runner", "artifact", "deploy"],
    evolutionCue: "Use as a supplementary pipeline and artifact exposure review."
  },
  "debug-backup": {
    version: "0.1.0",
    cacheScope: "project",
    priority: 2,
    surfaces: ["debug", "trace", "log", "backup", "tmp", "archive"],
    dependencies: ["secret-exposure", "exposed-surface"],
    signalKeywords: ["debug", "trace", "log", "bak", "backup", "old", "tmp"],
    evolutionCue: "Look for accessible debug, log, and backup artifacts with concrete sensitive content."
  }
};

export function getSkillRegistry() {
  return getAuditSkillCatalog().map((skill, index) => enrichSkill(skill, index));
}

export function resolveSkillEntries(skillIds = []) {
  const selected = resolveAuditSkills(skillIds);
  return selected.map((skill, index) => enrichSkill(skill, index));
}

export function getSkillById(skillId) {
  return getSkillRegistry().find((skill) => skill.id === skillId) || null;
}

export function suggestSkillIdsForProject(project, baseSkillIds = []) {
  const ids = new Set((baseSkillIds || []).filter(Boolean));
  const haystack = buildProjectHaystack(project);

  if (/(admin|dashboard|panel|backoffice|role|permission|rbac|policy|access)/.test(haystack)) {
    ids.add("access-control");
  }
  if (/(upload|storage|asset|media|file|s3|minio|r2)/.test(haystack)) {
    ids.add("upload-storage");
    ids.add("path-traversal");
  }
  if (/(api|graphql|content-api|rest|endpoint|resolver)/.test(haystack)) {
    ids.add("query-safety");
    ids.add("ssrf");
  }
  if (/(secret|token|key|config|env|credential|jwt)/.test(haystack)) {
    ids.add("secret-exposure");
    ids.add("bootstrap-config");
  }
  if (/(login|auth|session|tenant|invite|sign|signup|mfa)/.test(haystack)) {
    ids.add("access-control");
    ids.add("query-safety");
  }
  if (/(payment|order|cart|coupon|withdraw|wallet|billing)/.test(haystack)) {
    ids.add("access-control");
    ids.add("query-safety");
  }
  if (/(javascript|typescript|react|vue|next|nuxt|express|koa|nest|node)/.test(haystack)) {
    ids.add("xss");
    ids.add("query-safety");
  }
  if (/(php|laravel|wordpress|drupal|joomla)/.test(haystack)) {
    ids.add("bootstrap-config");
    ids.add("secret-exposure");
  }
  if (/(java|spring|python|django|go)/.test(haystack)) {
    ids.add("deserialization");
    ids.add("command-injection");
  }
  if (/(swagger|openapi|actuator|jenkins|grafana|kibana|debug|backup|bucket|oss|s3|cos|runner|ci\/cd|gitlab-ci)/.test(haystack)) {
    for (const skill of getSupplementaryHwSkills()) {
      if ((baseSkillIds || []).includes(skill.id)) {
        ids.add(skill.id);
      }
    }
  }

  for (const skillId of project?.recommendedSkillIds || []) {
    ids.add(skillId);
  }

  return Array.from(ids);
}

export function getSupplementaryHwSkills() {
  return getSkillRegistry().filter((skill) => skill.defaultEnabled === false || skill.category === "hw-supplement");
}

export function buildSkillFocusTags(skillIds = []) {
  return resolveSkillEntries(skillIds).flatMap((skill) => [
    ...(skill.surfaces || []),
    ...(skill.signalKeywords || [])
  ]);
}

function enrichSkill(skill, index = 0) {
  const meta = SKILL_METADATA[skill.id] || {};
  return {
    ...skill,
    version: meta.version || "1.0.0",
    cacheScope: meta.cacheScope || "project",
    priority: meta.priority || 1,
    surfaces: meta.surfaces || [],
    dependencies: meta.dependencies || [],
    signalKeywords: meta.signalKeywords || [],
    evolutionCue: meta.evolutionCue || "",
    registryOrder: index
  };
}

function buildProjectHaystack(project) {
  return [
    project?.name,
    project?.description,
    project?.language,
    project?.cmsType,
    ...(project?.auditSurfaceHints || []),
    ...(project?.recommendedSkillIds || []),
    ...(project?.tags || []),
    ...(project?.industries || [])
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}
