const HUNT_MODES = [
  {
    id: "hackerone",
    name: "HackerOne 赏金优先",
    description: "默认偏向更容易形成可提交赏金报告的漏洞面，信息泄露只作为补充。",
    defaultSkillIds: [
      "access-control",
      "query-safety",
      "ssrf",
      "upload-storage",
      "command-injection",
      "path-traversal",
      "xss",
      "deserialization",
      "dependency-risk"
    ],
    order: [
      "access-control",
      "query-safety",
      "ssrf",
      "upload-storage",
      "command-injection",
      "path-traversal",
      "xss",
      "deserialization",
      "dependency-risk",
      "bootstrap-config",
      "secret-exposure",
      "exposed-surface",
      "weak-credential",
      "cloud-misconfig",
      "cicd-exposure",
      "debug-backup"
    ]
  },
  {
    id: "lead-discovery",
    name: "Lead Discovery / 线索优先",
    description: "探索阶段多保留 API、权限、支付、KYC、Webhook、依赖和配置线索；报告阶段仍需人工验证。",
    defaultSkillIds: [
      "access-control",
      "query-safety",
      "ssrf",
      "upload-storage",
      "path-traversal",
      "dependency-risk",
      "secret-exposure",
      "exposed-surface",
      "cicd-exposure",
      "debug-backup"
    ],
    order: [
      "access-control",
      "query-safety",
      "ssrf",
      "upload-storage",
      "path-traversal",
      "dependency-risk",
      "secret-exposure",
      "exposed-surface",
      "cicd-exposure",
      "debug-backup",
      "command-injection",
      "deserialization",
      "xss",
      "bootstrap-config",
      "weak-credential",
      "cloud-misconfig"
    ]
  },
  {
    id: "hw-support",
    name: "护网补充",
    description: "默认只启用护网常见补充面，作为主线挖洞之外的辅助检查。",
    defaultSkillIds: [
      "exposed-surface",
      "weak-credential",
      "cloud-misconfig",
      "cicd-exposure",
      "debug-backup"
    ],
    order: [
      "exposed-surface",
      "weak-credential",
      "cloud-misconfig",
      "cicd-exposure",
      "debug-backup",
      "access-control",
      "query-safety",
      "ssrf",
      "upload-storage",
      "command-injection",
      "path-traversal",
      "xss",
      "deserialization",
      "bootstrap-config",
      "secret-exposure"
    ]
  }
];

export function getHuntModes() {
  return HUNT_MODES.map((mode) => ({ ...mode, defaultSkillIds: [...mode.defaultSkillIds], order: [...mode.order] }));
}

export function getHuntModeById(modeId) {
  return getHuntModes().find((mode) => mode.id === modeId) || getHuntModes()[0];
}

export function getDefaultSkillIdsForMode(modeId) {
  const mode = getHuntModeById(modeId);
  return [...(mode?.defaultSkillIds || [])];
}

export function orderSkillsForMode(skillCatalog, modeId) {
  const mode = getHuntModeById(modeId);
  const order = new Map((mode?.order || []).map((id, index) => [id, index]));
  return [...skillCatalog].sort((a, b) => {
    const aDefault = a.defaultEnabled === false ? 1 : 0;
    const bDefault = b.defaultEnabled === false ? 1 : 0;
    if (aDefault !== bDefault) return aDefault - bDefault;

    const aRank = order.has(a.id) ? order.get(a.id) : 999;
    const bRank = order.has(b.id) ? order.get(b.id) : 999;
    if (aRank !== bRank) return aRank - bRank;

    return String(a.name || a.id).localeCompare(String(b.name || b.id));
  });
}
