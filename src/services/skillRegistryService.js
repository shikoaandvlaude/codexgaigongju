import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { buildSkillFocusTags, getSkillRegistry, resolveSkillEntries } from "../config/skillRegistry.js";

const SKILL_REGISTRY_IDS = new Set(getSkillRegistry().map((skill) => skill.id));

const DEFAULT_STATE = {
  updatedAt: null,
  recentRuns: [],
  skills: {},
  drafts: []
};

export function createSkillRegistryStore({ filePath, draftsDir }) {
  async function read() {
    try {
      const raw = await fs.readFile(filePath, "utf8");
      return normalizeState(JSON.parse(raw));
    } catch {
      return structuredClone(DEFAULT_STATE);
    }
  }

  async function write(nextState) {
    const normalized = normalizeState(nextState);
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(normalized, null, 2), "utf8");
    return normalized;
  }

  async function getCatalog() {
    const state = await read();
    return getSkillRegistry().map((skill) => ({
      ...skill,
      stats: state.skills[skill.id] || buildEmptySkillStats(skill.id, skill.name)
    }));
  }

  async function recordRun({ task, selectedProjects = [], auditResult, scanArtifacts }) {
    const state = await read();
    const now = new Date().toISOString();
    const skillMap = new Map(resolveSkillEntries(auditResult?.skillsUsed?.map((skill) => skill.id) || []).map((skill) => [skill.id, skill]));
    const auditFindings = collectAuditFindings(auditResult);
    const scanFindings = collectScanFindings(scanArtifacts);
    const projectedSignals = buildProjectSignals(selectedProjects);

    for (const skill of skillMap.values()) {
      const entry = ensureSkillState(state, skill.id, skill.name);
      entry.runs += 1;
      entry.lastUsedAt = now;
      entry.lastTaskId = task?.id || null;
      entry.lastProjects = uniqStrings([...(entry.lastProjects || []), ...selectedProjects.map((project) => project?.name || project?.id)]);
      entry.lastSignals = uniqObjects([...(entry.lastSignals || []), ...projectedSignals.slice(0, 8)], "title").slice(0, 8);
      entry.evolutionCue = skill.evolutionCue || entry.evolutionCue || "";
      entry.surfaces = uniqStrings([...(entry.surfaces || []), ...(skill.surfaces || []), ...projectedSignals.map((signal) => signal.surface)]);
    }

    for (const finding of auditFindings) {
      const skillId = finding.skillId;
      if (!skillId || !SKILL_REGISTRY_IDS.has(skillId)) continue;
      const entry = ensureSkillState(state, skillId, finding.skillName || skillId);
      entry.findings += 1;
      entry.highSignalFindings += isHighSignalFinding(finding) ? 1 : 0;
      entry.lastUsedAt = now;
      entry.lastTaskId = task?.id || null;
      entry.lastFindings = uniqObjects([finding, ...(entry.lastFindings || [])], "title").slice(0, 6);
      entry.topSignals = prioritizeSignals([...(entry.topSignals || []), toSignalCard(finding)]).slice(0, 6);
      entry.surfaces = uniqStrings([...(entry.surfaces || []), ...signalSurfacesFromFinding(finding)]);
    }

    const drafts = await buildSkillDrafts({
      task,
      selectedProjects,
      auditFindings,
      state,
      draftsDir,
      now
    });

    state.recentRuns = [
      {
        taskId: task?.id || "",
        taskLabel: task?.query || task?.sourceType || "",
        selectedProjects: selectedProjects.map((project) => project?.name || project?.id).filter(Boolean),
        selectedSkills: Array.from(skillMap.keys()),
        findingsCount: auditFindings.length,
        scanCount: scanFindings.length,
        draftCount: drafts.length,
        generatedAt: now
      },
      ...state.recentRuns
    ].slice(0, 8);
    state.drafts = uniqDrafts([...drafts, ...(state.drafts || [])]).slice(0, 12);
    state.updatedAt = now;

    await write(state);
    return buildSkillInsights(state);
  }

  async function getInsights() {
    const state = await read();
    return buildSkillInsights(state);
  }

  return {
    read,
    write,
    getCatalog,
    getInsights,
    recordRun
  };
}

function buildSkillInsights(state) {
  const skills = Object.values(state.skills || {});
  const hotSkills = [...skills]
    .map((skill) => ({
      ...skill,
      score: (skill.findings || 0) * 2 + (skill.highSignalFindings || 0) * 3 + (skill.runs || 0)
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 6);

  const drafts = Array.isArray(state.drafts) ? state.drafts : [];
  const topDrafts = [...drafts]
    .sort((a, b) => (b.signalScore || 0) - (a.signalScore || 0))
    .slice(0, 6);

  return {
    generatedAt: state.updatedAt || new Date().toISOString(),
    summary: {
      trackedSkills: skills.length,
      hotSkills: hotSkills.length,
      drafts: drafts.length,
      recentRuns: Array.isArray(state.recentRuns) ? state.recentRuns.length : 0
    },
    hotSkills,
    drafts: topDrafts,
    catalog: getSkillRegistry().map((skill) => ({
      ...skill,
      stats: state.skills[skill.id] || buildEmptySkillStats(skill.id, skill.name)
    })),
    recentRuns: state.recentRuns || []
  };
}

async function buildSkillDrafts({ task, selectedProjects, auditFindings, state, draftsDir, now }) {
  const findings = auditFindings.filter((finding) => SKILL_REGISTRY_IDS.has(finding.skillId));
  if (!findings.length || !draftsDir) {
    return [];
  }

  const drafts = [];
  const grouped = groupFindingsBySkill(findings);
  const focusTags = buildSkillFocusTags(Array.from(grouped.keys()));
  const projectNames = selectedProjects.map((project) => project?.name || project?.id).filter(Boolean);

  await fs.mkdir(draftsDir, { recursive: true });

  for (const [skillId, items] of grouped.entries()) {
    const currentSkill = getSkillRegistry().find((skill) => skill.id === skillId);
    const topItem = prioritizeSignals(items.map(toSignalCard))[0];
    if (!topItem) continue;

    const draft = {
      id: `${task?.id || "task"}-${skillId}-${crypto.randomUUID().slice(0, 8)}`,
      skillId,
      skillName: currentSkill?.name || skillId,
      sourceTaskId: task?.id || "",
      projectNames,
      focusTags: uniqStrings([...(currentSkill?.surfaces || []), ...(currentSkill?.signalKeywords || []), ...focusTags]),
      signalScore: topItem.signalScore,
      title: buildDraftTitle(currentSkill, topItem),
      prompt: buildDraftPrompt(currentSkill, topItem, projectNames),
      evidence: topItem.evidence,
      createdAt: now
    };

    const fileName = `${sanitizeFileSegment(draft.skillId)}-${sanitizeFileSegment(task?.id || "task")}.md`;
    const filePath = path.join(draftsDir, fileName);
    await fs.writeFile(filePath, renderDraftMarkdown(draft), "utf8");
    drafts.push({
      ...draft,
      filePath
    });

    const stateEntry = ensureSkillState(state, skillId, currentSkill?.name || skillId);
    stateEntry.drafts = (stateEntry.drafts || 0) + 1;
    stateEntry.lastDraftAt = now;
    stateEntry.lastDraftPath = filePath;
  }

  return drafts.slice(0, 6);
}

function renderDraftMarkdown(draft) {
  return [
    `# ${draft.title}`,
    "",
    `- skillId: ${draft.skillId}`,
    `- taskId: ${draft.sourceTaskId}`,
    `- projects: ${draft.projectNames.join(", ") || "n/a"}`,
    `- signalScore: ${formatScore(draft.signalScore)}`,
    "",
    "## Focus",
    "",
    draft.focusTags.length ? draft.focusTags.map((tag) => `- ${tag}`).join("\n") : "- n/a",
    "",
    "## Evidence",
    "",
    draft.evidence || "n/a",
    "",
    "## Prompt Sketch",
    "",
    draft.prompt,
    ""
  ].join("\n");
}

function buildDraftTitle(skill, topItem) {
  if (skill?.name) {
    return `${skill.name} Skill Draft`;
  }
  return `${topItem.title || "Skill"} Draft`;
}

function buildDraftPrompt(skill, topItem, projectNames) {
  const promptParts = [
    `The projects ${projectNames.join(", ") || "selected targets"} repeatedly exposed a ${skill?.name || topItem.skillId || "skill"} pattern.`,
    skill?.evolutionCue || "Keep the prompt defensive and evidence-backed.",
    `Prioritize the surface around ${uniqStrings([...(skill?.surfaces || []), topItem.surface]).join(", ") || "the observed surface"}.`,
    "Generate only a reusable local skill draft that helps future triage and code review.",
    `Observed evidence: ${topItem.evidence || "n/a"}`
  ];

  return promptParts.join(" ");
}

function collectAuditFindings(auditResult) {
  return Array.isArray(auditResult?.projects)
    ? auditResult.projects.flatMap((project) => Array.isArray(project.findings) ? project.findings : [])
    : [];
}

function collectScanFindings(scanArtifacts) {
  return Array.isArray(scanArtifacts?.findings) ? scanArtifacts.findings : [];
}

function groupFindingsBySkill(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const skillId = finding.skillId || inferSkillIdFromSource(finding.source);
    if (!skillId) continue;
    if (!groups.has(skillId)) {
      groups.set(skillId, []);
    }
    groups.get(skillId).push(finding);
  }
  return groups;
}

function ensureSkillState(state, skillId, skillName) {
  if (!state.skills[skillId]) {
    state.skills[skillId] = buildEmptySkillStats(skillId, skillName);
  }
  state.skills[skillId].id = skillId;
  state.skills[skillId].name = skillName || state.skills[skillId].name || skillId;
  state.skills[skillId].updatedAt = new Date().toISOString();
  return state.skills[skillId];
}

function buildEmptySkillStats(skillId, skillName) {
  return {
    id: skillId,
    name: skillName || skillId,
    runs: 0,
    findings: 0,
    highSignalFindings: 0,
    drafts: 0,
    lastUsedAt: null,
    lastTaskId: null,
    lastProjects: [],
    lastSignals: [],
    lastFindings: [],
    topSignals: [],
    surfaces: [],
    evolutionCue: "",
    lastDraftAt: null,
    lastDraftPath: null,
    updatedAt: null
  };
}

function normalizeState(state) {
  const next = structuredClone(DEFAULT_STATE);
  next.updatedAt = state?.updatedAt || null;
  next.recentRuns = Array.isArray(state?.recentRuns) ? state.recentRuns.slice(0, 8) : [];
  next.drafts = Array.isArray(state?.drafts) ? uniqDrafts(state.drafts).slice(0, 12) : [];
  next.skills = {};

  for (const [skillId, entry] of Object.entries(state?.skills || {})) {
    next.skills[skillId] = {
      ...buildEmptySkillStats(skillId, entry?.name || skillId),
      ...entry,
      lastProjects: uniqStrings(entry?.lastProjects || []),
      lastSignals: uniqObjects(entry?.lastSignals || [], "title"),
      lastFindings: uniqObjects(entry?.lastFindings || [], "title"),
      topSignals: uniqObjects(entry?.topSignals || [], "title"),
      surfaces: uniqStrings(entry?.surfaces || [])
    };
  }

  return next;
}

function buildProjectSignals(selectedProjects) {
  return selectedProjects.flatMap((project) => {
    const focusTags = uniqStrings([
      ...(project?.auditSurfaceHints || []),
      ...(project?.recommendedSkillIds || []),
      ...(project?.tags || []),
      ...(project?.industries || [])
    ]);
    return focusTags.map((tag) => ({
      title: `${project?.name || project?.id || "target"}:${tag}`,
      surface: tag,
      evidence: project?.description || project?.repoUrl || "",
      signalScore: 0.45
    }));
  });
}

function signalSurfacesFromFinding(finding) {
  return uniqStrings([
    finding?.source,
    finding?.skillId,
    finding?.location,
    finding?.sourceFile
  ]).filter((value) => value && value.length < 60);
}

function toSignalCard(finding) {
  return {
    title: finding?.title || finding?.checkId || finding?.templateId || "Finding",
    evidence: finding?.evidence || finding?.impact || "",
    surface: finding?.source || finding?.skillId || "",
    signalScore: Number(finding?.signalScore || finding?.confidence || 0),
    severity: finding?.severity || "medium",
    location: finding?.location || ""
  };
}

function prioritizeSignals(items) {
  return [...items]
    .map((item) => ({
      ...item,
      signalScore: clamp(Number(item.signalScore || 0), 0, 1)
    }))
    .sort((a, b) => {
      const scoreDiff = (b.signalScore || 0) - (a.signalScore || 0);
      if (scoreDiff !== 0) return scoreDiff;
      return String(a.title || "").localeCompare(String(b.title || ""));
    });
}

function isHighSignalFinding(finding) {
  const severity = String(finding?.severity || "").toLowerCase();
  const score = Number(finding?.signalScore || finding?.confidence || 0);
  return severity === "critical" || severity === "high" || score >= 0.75;
}

function uniqStrings(values) {
  return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
}

function uniqObjects(values, key) {
  const seen = new Set();
  const output = [];
  for (const value of values || []) {
    const dedupeKey = String(value?.[key] || JSON.stringify(value || {}));
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    output.push(value);
  }
  return output;
}

function uniqDrafts(values) {
  return uniqObjects(values, "id");
}

function sanitizeFileSegment(value) {
  return String(value || "draft")
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80) || "draft";
}

function formatScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) {
    return "0.00";
  }
  return score.toFixed(2);
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number.isFinite(Number(value)) ? Number(value) : min));
}
