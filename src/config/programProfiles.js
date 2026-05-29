const DEFAULT_PROGRAM_PROFILE_ID = "general-oss";

const PROGRAM_PROFILES = [
  {
    id: "cms",
    name: "CMS / 内容平台",
    description: "面向内容系统、编辑台、站点后台和 Headless CMS 的发现配置。",
    defaultQuery: 'topic:cms OR "headless cms" OR "content management system"',
    keywords: [
      "cms",
      "headless",
      "content management",
      "content platform",
      "blog",
      "admin panel",
      "publishing",
      "editorial"
    ],
    searchProfiles: [
      'topic:cms archived:false',
      '"headless cms" archived:false',
      '"content management system" archived:false',
      'topic:headless-cms archived:false',
      '"content platform" archived:false'
    ],
    family: "content"
  },
  {
    id: "kubernetes",
    name: "Kubernetes / 云原生",
    description: "面向 Kubernetes、Helm、Operator、Ingress、CI/CD 和云原生控制面的发现配置。",
    defaultQuery: 'topic:kubernetes OR kubernetes OR k8s OR "cloud native"',
    keywords: [
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
    searchProfiles: [
      'topic:kubernetes archived:false',
      '"kubernetes" archived:false',
      '"cloud native" archived:false',
      'topic:helm archived:false',
      '"operator" "kubernetes" archived:false'
    ],
    family: "cloud-native"
  },
  {
    id: "general-oss",
    name: "黑白盒通用",
    description: "适合不先限定技术栈的通用黑白盒发现配置，覆盖 Web、API、OSS 和常见业务面。",
    defaultQuery: 'stars:>200 archived:false',
    keywords: [
      "auth",
      "api",
      "service",
      "platform",
      "controller",
      "workflow",
      "dashboard"
    ],
    searchProfiles: [
      'stars:>200 archived:false',
      'language:Go archived:false stars:>100',
      'language:TypeScript archived:false stars:>100',
      'language:Python archived:false stars:>100'
    ],
    family: "general"
  }
];

export function getProgramProfiles() {
  return PROGRAM_PROFILES.map((profile) => ({
    ...profile,
    keywords: [...profile.keywords],
    searchProfiles: [...profile.searchProfiles]
  }));
}

export function getProgramProfileById(profileId) {
  return (
    getProgramProfiles().find((profile) => profile.id === profileId) ||
    getProgramProfiles().find((profile) => profile.id === DEFAULT_PROGRAM_PROFILE_ID) ||
    getProgramProfiles()[0]
  );
}

export function getDefaultProgramProfileId() {
  return DEFAULT_PROGRAM_PROFILE_ID;
}

export function getProgramQuery(profileId) {
  return getProgramProfileById(profileId).defaultQuery;
}

export function buildProgramSearchQueries(query, ownerFilter, profileId) {
  const profile = getProgramProfileById(profileId);
  const ownerQualifier = ownerFilter ? ` user:${ownerFilter}` : "";
  const rawQuery = String(query || "").trim();
  const effectiveQuery = rawQuery || profile.defaultQuery;

  if (rawQuery) {
    return [
      `${effectiveQuery}${ownerQualifier} archived:false`,
      ...profile.searchProfiles.slice(0, 2).map((searchQuery) => `${searchQuery}${ownerQualifier}`)
    ];
  }

  return profile.searchProfiles.map((searchQuery) => `${searchQuery}${ownerQualifier}`);
}

export function isProgramRelevant(repo, profileId) {
  const profile = getProgramProfileById(profileId);
  if (profile.family === "general") {
    return true;
  }
  const text = `${repo.full_name || ""} ${repo.description || ""} ${(repo.topics || []).join(" ")}`.toLowerCase();
  return profile.keywords.some((keyword) => text.includes(keyword.toLowerCase()));
}
