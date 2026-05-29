import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FrameworkScoutAgent } from "./src/agents/frameworkScoutAgent.js";
import { LocalRepoScoutAgent } from "./src/agents/localRepoScoutAgent.js";
import { AuditAnalystAgent } from "./src/agents/auditAnalystAgent.js";
import { FofaScoutAgent } from "./src/agents/fofaScoutAgent.js";
import { getDefaultSkillIdsForMode, getHuntModeById, getHuntModes } from "./src/config/huntModes.js";
import { getDefaultProgramProfileId, getProgramProfiles, getProgramProfileById, getProgramQuery } from "./src/config/programProfiles.js";
import { getProviderPreset, maskSecret, resolveLlmConfig } from "./src/config/llmProviders.js";
import { createSkillRegistryStore } from "./src/services/skillRegistryService.js";
import { createTargetStateStore } from "./src/services/targetStateService.js";
import { buildEnvironmentReport } from "./src/services/environmentReport.js";
import { buildBountyIntegrationReport } from "./src/services/bountyIntegrationService.js";
import { collectScanArtifacts } from "./src/services/scanArtifactService.js";
import { DefensiveLlmReviewer } from "./src/services/llmReviewService.js";
import { createMemoryStore } from "./src/services/memoryStore.js";
import { createFingerprintService } from "./src/services/fingerprintService.js";
import { writeAuditHtmlReport } from "./src/services/reportWriter.js";
import { writeShannonHandoff } from "./src/services/shannonHandoffWriter.js";
import { createSettingsStore } from "./src/services/settingsStore.js";
import { createTaskStore } from "./src/store/taskStore.js";
import { SrcScoutAgent } from "./src/agents/srcScoutAgent.js";
import { writeSrcReport, writeSrcHtmlReport } from "./src/services/srcReportWriter.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");
const downloadsDir = path.join(__dirname, "workspace", "downloads");
const reportsDir = path.join(__dirname, "workspace", "reports");
const memoryFile = path.join(__dirname, "workspace", "memory", "project-memory.json");
const settingsFile = path.join(__dirname, "workspace", "settings", "app-settings.json");
const srcTargetFile = path.join(__dirname, "workspace", "src-hunt", "targets.json");
const skillStateFile = path.join(__dirname, "workspace", "skills", "skill-state.json");
const skillDraftsDir = path.join(__dirname, "workspace", "skills", "drafts");
const targetStateFile = path.join(__dirname, "workspace", "targets", "target-state.json");

const settingsStore = createSettingsStore({ filePath: settingsFile });
const srcScoutAgent = new SrcScoutAgent({ targetFilePath: srcTargetFile });
const skillRegistryStore = createSkillRegistryStore({ filePath: skillStateFile, draftsDir: skillDraftsDir });
const targetStateStore = createTargetStateStore({ filePath: targetStateFile });
const scoutAgent = new FrameworkScoutAgent({
  downloadsDir,
  getGithubConfig: async () => (await settingsStore.read()).github
});
const fofaScoutAgent = new FofaScoutAgent({
  getFofaConfig: async () => (await settingsStore.read()).fofa
});
const localScoutAgent = new LocalRepoScoutAgent({ downloadsDir });
const llmReviewer = new DefensiveLlmReviewer();
const auditAgent = new AuditAnalystAgent({ llmReviewer });
const tasks = createTaskStore();
const memoryStore = createMemoryStore({ filePath: memoryFile });
const fingerprintService = createFingerprintService({ downloadsDir });

await fs.mkdir(downloadsDir, { recursive: true });
await fs.mkdir(reportsDir, { recursive: true });

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === "GET" && url.pathname === "/api/health") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      return sendJson(res, 200, { status: "ok", now: new Date().toISOString(), safeMode: true, environment });
    }

    if (req.method === "GET" && url.pathname === "/api/environment") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      return sendJson(res, 200, environment);
    }

    if (req.method === "GET" && url.pathname === "/api/bounty/integrations") {
      return sendJson(res, 200, await buildBountyIntegrationReport({ rootDir: __dirname }));
    }

    if (req.method === "GET" && url.pathname === "/api/hunt-modes") {
      return sendJson(res, 200, {
        generatedAt: new Date().toISOString(),
        modes: getHuntModes()
      });
    }

    if (req.method === "GET" && url.pathname === "/api/program-profiles") {
      return sendJson(res, 200, {
        generatedAt: new Date().toISOString(),
        defaultProfileId: getDefaultProgramProfileId(),
        profiles: getProgramProfiles()
      });
    }

    if (req.method === "GET" && url.pathname === "/api/bounty/scans") {
      const taskId = url.searchParams.get("taskId") || "";
      const task = taskId ? tasks.getTask(taskId) : null;
      const selectedProjects = task?.scoutResult?.projects?.filter((project) =>
        Array.isArray(task.selectedProjectIds) ? task.selectedProjectIds.includes(project.id) : false
      ) || [];
      return sendJson(res, 200, await collectScanArtifacts({ rootDir: __dirname, selectedProjects }));
    }

    if (req.method === "GET" && url.pathname === "/api/target-state") {
      const taskId = url.searchParams.get("taskId") || "";
      const projectId = url.searchParams.get("projectId") || "";
      if (projectId) {
        return sendJson(res, 200, await targetStateStore.getTargetState(projectId));
      }
      if (taskId) {
        return sendJson(res, 200, await targetStateStore.getTaskState(taskId));
      }
      return sendJson(res, 200, await targetStateStore.getSnapshot());
    }

    if (req.method === "GET" && url.pathname === "/api/settings") {
      return sendJson(res, 200, sanitizeSettings(await settingsStore.read()));
    }

    if (req.method === "GET" && url.pathname === "/api/audit-skills") {
      return sendJson(res, 200, await skillRegistryStore.getCatalog());
    }

    if (req.method === "GET" && url.pathname === "/api/audit-skills/state") {
      return sendJson(res, 200, await skillRegistryStore.getInsights());
    }

    if (req.method === "POST" && url.pathname === "/api/settings") {
      const body = await readJson(req);
      const current = await settingsStore.read();
      const updated = await settingsStore.write({
        llm: {
          providerId: body?.llm?.providerId || current.llm.providerId,
          baseUrl: body?.llm?.baseUrl ?? current.llm.baseUrl,
          model: body?.llm?.model ?? current.llm.model,
          apiKey: body?.llm?.apiKey ? body.llm.apiKey : current.llm.apiKey
        },
        github: {
          token: body?.github?.token ? body.github.token : current.github.token,
          ownerFilter: body?.github?.ownerFilter ?? current.github.ownerFilter,
          notes: body?.github?.notes ?? current.github.notes
        },
        fofa: {
          email: body?.fofa?.email ?? current.fofa.email,
          apiKey: body?.fofa?.apiKey ? body.fofa.apiKey : current.fofa.apiKey,
          notes: body?.fofa?.notes ?? current.fofa.notes
        }
      });
      return sendJson(res, 200, sanitizeSettings(updated));
    }

    if (req.method === "POST" && url.pathname === "/api/settings/clear-secrets") {
      const body = await readJson(req);
      return sendJson(res, 200, sanitizeSettings(await settingsStore.clearSecrets(Array.isArray(body?.targets) ? body.targets : [])));
    }

    if (req.method === "POST" && url.pathname === "/api/settings/test") {
      return sendJson(res, 200, await testConnections(await settingsStore.read()));
    }

    if (req.method === "GET" && url.pathname === "/api/memory") {
      return sendJson(res, 200, await memoryStore.read());
    }

    if (req.method === "GET" && url.pathname === "/api/fingerprint/projects") {
      return sendJson(res, 200, await fingerprintService.listProjects());
    }

    if (req.method === "POST" && url.pathname === "/api/fingerprint/analyze") {
      const body = await readJson(req);
      return sendJson(res, 200, await fingerprintService.analyzeProject(String(body?.projectId || "")));
    }

    if (req.method === "POST" && url.pathname === "/api/fingerprint/match") {
      const body = await readJson(req);
      return sendJson(res, 200, await fingerprintService.matchAssets({
        projectId: String(body?.projectId || ""),
        assetText: String(body?.assetText || "")
      }));
    }

    if (req.method === "GET" && url.pathname === "/api/fofa/quick") {
      const settings = await settingsStore.read();
      if (!settings.fofa.apiKey) {
        return sendJson(res, 400, { error: "未配置 FOFA API Key" });
      }
      const query = url.searchParams.get("q") || "";
      const result = await fofaScoutAgent.run({ query, size: 10 });
      return sendJson(res, 200, result);
    }

    if (req.method === "POST" && url.pathname === "/api/memory") {
      const body = await readJson(req);
      return sendJson(res, 200, await memoryStore.write({ preferences: body.preferences || {}, rules: Array.isArray(body.rules) ? body.rules : undefined }));
    }

    if (req.method === "POST" && url.pathname === "/api/tasks") {
      const body = await readJson(req);
      const memory = await memoryStore.read();
      const created = tasks.createTask(applyMemoryDefaults(body, memory));
      if (created.useMemory) {
        tasks.updateTask(created.id, { memorySnapshot: buildMemorySnapshot(memory) });
      }
      runScout(created.id).catch((error) => tasks.failTask(created.id, error instanceof Error ? error.message : String(error)));
      return sendJson(res, 202, tasks.getTask(created.id));
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/audit$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const body = await readJson(req);
      const selectedProjectIds = Array.isArray(body?.selectedProjectIds) ? body.selectedProjectIds : [];
      const task = tasks.getTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      if (!task.scoutResult?.projects?.length) {
        return sendJson(res, 400, { error: "Targets are not ready yet" });
      }
      runAudit(taskId, selectedProjectIds).catch((error) => tasks.failTask(taskId, error instanceof Error ? error.message : String(error)));
      return sendJson(res, 202, tasks.getTask(taskId));
    }

    if (req.method === "GET" && url.pathname === "/api/tasks") {
      return sendJson(res, 200, tasks.listTasks());
    }

    if (req.method === "POST" && url.pathname === "/api/tasks/cancel") {
      const body = await readJson(req);
      const taskId = body?.taskId;
      const task = tasks.getTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      tasks.updateTask(taskId, { status: "cancelled", phase: "cancelled", message: "Task cancelled by user." });
      return sendJson(res, 200, tasks.getTask(taskId));
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/tasks/") && url.pathname.endsWith("/stream")) {
      const id = url.pathname.split("/")[3];
      return serveSse(res, id, tasks);
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/tasks/")) {
      const id = url.pathname.split("/")[3];
      const task = tasks.getTask(id);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      return sendJson(res, 200, task);
    }

    if (req.method === "GET" && url.pathname.startsWith("/downloads/")) {
      return serveFileFromRoot(res, downloadsDir, decodeURIComponent(url.pathname.replace("/downloads/", "")));
    }

    if (req.method === "GET" && url.pathname.startsWith("/reports/")) {
      return serveFileFromRoot(res, reportsDir, decodeURIComponent(url.pathname.replace("/reports/", "")));
    }

    // ============ SRC 挖掘 API ============

    if (req.method === "GET" && url.pathname === "/api/src/targets") {
      const targets = await srcScoutAgent.getTargets();
      return sendJson(res, 200, targets);
    }

    if (req.method === "POST" && url.pathname === "/api/src/targets") {
      const body = await readJson(req);
      const result = await srcScoutAgent.addTarget(body);
      return sendJson(res, result.error ? 400 : 201, result);
    }

    if (req.method === "DELETE" && /^\/api\/src\/targets\/[^/]+$/.test(url.pathname)) {
      const targetId = url.pathname.split("/").pop();
      const result = await srcScoutAgent.removeTarget(targetId);
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" && url.pathname === "/api/src/platforms") {
      const platforms = await srcScoutAgent.getPlatforms();
      return sendJson(res, 200, platforms);
    }

    if (req.method === "GET" && url.pathname === "/api/src/recon") {
      const domain = url.searchParams.get("domain") || "";
      if (!domain) return sendJson(res, 400, { error: "Missing domain parameter" });
      const plan = srcScoutAgent.generateReconPlan(domain);
      return sendJson(res, 200, plan);
    }

    if (req.method === "GET" && url.pathname === "/api/src/f5-decode") {
      const cookie = url.searchParams.get("cookie") || "";
      const ip = srcScoutAgent.decodeF5Ltm(cookie);
      return sendJson(res, 200, { cookie, ip });
    }

    if (req.method === "GET" && url.pathname === "/api/src/dorks") {
      const domain = url.searchParams.get("domain") || "example.com";
      return sendJson(res, 200, {
        google: srcScoutAgent.getSearchDorks("google", domain),
        fofa: srcScoutAgent.getSearchDorks("fofa", domain),
        zoomeye: srcScoutAgent.getSearchDorks("zoomeye", domain)
      });
    }

    if (req.method === "GET" && url.pathname === "/api/src/credentials") {
      return sendJson(res, 200, srcScoutAgent.getAllDefaultCredentials());
    }

    if (req.method === "GET" && url.pathname === "/api/src/templates") {
      return sendJson(res, 200, srcScoutAgent.getVulnTemplates());
    }

    if (req.method === "GET" && url.pathname === "/api/src/templates/recommend") {
      const feature = url.searchParams.get("feature") || "";
      return sendJson(res, 200, srcScoutAgent.recommendTemplates(feature));
    }

    if (req.method === "POST" && url.pathname === "/api/src/templates/analyze-params") {
      const body = await readJson(req);
      const params = Array.isArray(body?.params) ? body.params : [];
      return sendJson(res, 200, srcScoutAgent.analyzeParams(params));
    }

    if (req.method === "GET" && url.pathname === "/api/src/templates/categories") {
      return sendJson(res, 200, srcScoutAgent.getVulnCategories());
    }

    if (req.method === "POST" && url.pathname === "/api/src/report") {
      const body = await readJson(req);
      const [mdReport, htmlReport] = await Promise.all([
        writeSrcReport({ reportsDir, finding: body }),
        writeSrcHtmlReport({ reportsDir, finding: body })
      ]);
      return sendJson(res, 200, { ...htmlReport, mdReport });
    }

    if (req.method === "GET" && url.pathname === "/api/src/redlines") {
      return sendJson(res, 200, srcScoutAgent.getAllRedLines());
    }

    if (req.method === "POST" && url.pathname === "/api/src/redlines/check") {
      const body = await readJson(req);
      const result = srcScoutAgent.checkRedLines(body?.action || "");
      return sendJson(res, 200, result);
    }

    if (req.method === "POST" && url.pathname === "/api/src/analyze-function") {
      const body = await readJson(req);
      const result = srcScoutAgent.analyzeFunctionPoint(body?.description || "");
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" && url.pathname === "/api/src/safety-checklist") {
      const target = url.searchParams.get("target") || "";
      return sendJson(res, 200, srcScoutAgent.generateSafetyChecklist(target));
    }

    if (req.method === "GET" && url.pathname === "/api/src/company-assets") {
      const company = url.searchParams.get("company") || "";
      if (!company) return sendJson(res, 400, { error: "Missing company parameter" });
      return sendJson(res, 200, srcScoutAgent.analyzeCompanyAssets(company));
    }

    // ============ End SRC API ============

    if (req.method === "GET") {
      const target = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      return serveFileFromRoot(res, publicDir, target);
    }

    return sendJson(res, 404, { error: "Not found" });
  } catch (error) {
    if (error?.message === "Request body too large") {
      return sendJson(res, 413, { error: "Request body too large" });
    }
    if (error instanceof SyntaxError) {
      return sendJson(res, 400, { error: "Invalid JSON" });
    }
    return sendJson(res, 500, { error: "Internal server error", detail: error instanceof Error ? error.message : String(error) });
  }
});

async function runScout(taskId) {
  tasks.updateTask(taskId, {
    status: "running",
    phase: "framework-scout",
    message: "正在发现候选目标…",
    progress: {
      stage: "framework-scout",
      label: "正在发现候选目标",
      detail: "",
      percent: 12,
      current: 0,
      total: 0
    }
  });
  const task = tasks.getTask(taskId);
  const scoutResult = task.sourceType === "local"
    ? await localScoutAgent.run({ localRepoPaths: task.localRepoPaths })
    : await scoutAgent.run({
      query: task.query,
      cmsType: task.cmsType,
      industry: task.industry,
      minAdoption: task.minAdoption,
      programProfile: task.programProfile
    });
  if (isTaskCancelled(taskId)) {
    return;
  }
  tasks.updateTask(taskId, {
    status: "awaiting_selection",
    phase: "target-selection",
    message: scoutResult.summary || "请选择需要审计的目标。",
    scoutResult,
    progress: {
      stage: "target-selection",
      label: "请选择要审计的目标",
      detail: "",
      percent: 20,
      current: scoutResult.projects?.length || 0,
      total: scoutResult.projects?.length || 0
    }
  });
  await targetStateStore.recordScoutRun({ task: tasks.getTask(taskId), scoutResult });
}

async function runAudit(taskId, selectedProjectIds) {
  const task = tasks.getTask(taskId);
  if (isTaskCancelled(taskId)) {
    return;
  }
  const selectedProjects = (task.scoutResult?.projects || []).filter((project) => selectedProjectIds.includes(project.id));
  if (!selectedProjects.length) {
    throw new Error("No targets selected for audit.");
  }

  tasks.updateTask(taskId, {
    status: "running",
    phase: "audit-analyst",
    message: "正在下载审计镜像并审计你选中的目标…",
    selectedProjectIds,
    progress: {
      stage: "mirror",
      label: "正在准备审计镜像",
      detail: "",
      percent: 24,
      current: 0,
      total: selectedProjects.length
    }
  });
  await targetStateStore.recordAuditStart({ task: tasks.getTask(taskId), selectedProjects });

  for (const [projectIndex, project] of selectedProjects.entries()) {
    if (isTaskCancelled(taskId)) {
      return;
    }
    if (project.sourceType === "local") {
      updateTaskProgress(taskId, {
        stage: "mirror",
        label: `正在生成本地镜像：${project.name}`,
        detail: "",
        percent: calculateMirrorPercent(projectIndex + 1, selectedProjects.length, 1, 1),
        current: projectIndex + 1,
        total: selectedProjects.length,
        projectId: project.id,
        projectName: project.name
      });
      await localScoutAgent.ensureProjectMirror(project);
    } else {
      await scoutAgent.ensureProjectMirror(project, {
        onProgress: (detail) =>
          updateTaskProgress(taskId, {
            stage: "mirror",
            label: `正在下载审计镜像：${project.name}`,
            detail: detail.currentPath || "",
            percent: calculateMirrorPercent(projectIndex + 1, selectedProjects.length, detail.processed || 0, detail.total || 1),
            current: detail.processed || 0,
            total: detail.total || 0,
            projectId: project.id,
            projectName: project.name
          })
      });
    }
    if (isTaskCancelled(taskId)) {
      return;
    }
  }

  if (isTaskCancelled(taskId)) {
    return;
  }
  const settings = await settingsStore.read();
  const llmConfig = resolveLlmConfig(process.env, settings.llm);
  const auditResult = await auditAgent.run({
    projects: selectedProjects,
    selectedSkillIds: task.selectedSkillIds,
    llmConfig,
    onProgress: (detail) => updateTaskProgress(taskId, buildAuditProgress(detail, selectedProjects.length))
  });
  if (isTaskCancelled(taskId)) {
    return;
  }
  const scanArtifacts = await collectScanArtifacts({ rootDir: __dirname, selectedProjects });
  const skillInsights = await skillRegistryStore.recordRun({
    task: tasks.getTask(taskId),
    selectedProjects,
    auditResult,
    scanArtifacts
  });
  updateTaskProgress(taskId, {
    stage: "report",
    label: "正在生成 HTML 报告",
    detail: "",
    percent: 98,
    current: selectedProjects.length,
    total: selectedProjects.length
  });
  const finalTaskSnapshot = {
    ...tasks.getTask(taskId),
    phase: "completed",
    message: "审计完成，可下载 HTML 报告。",
    selectedProjectIds
  };
  const report = await writeAuditHtmlReport({ reportsDir, task: finalTaskSnapshot, selectedProjects, auditResult, scanArtifacts, skillInsights });
  const shannonHandoff = await writeShannonHandoff({
    reportsDir,
    task: finalTaskSnapshot,
    selectedProjects,
    auditResult,
    scanArtifacts,
    skillInsights,
    shannonRepoRoot: path.join(__dirname, "integrations", "shannon")
  });
  const memorySummary = buildMemorySummary(finalTaskSnapshot, { projects: selectedProjects }, auditResult);
  if (task.useMemory) {
    await memoryStore.appendRunSummary(memorySummary);
  }
  await targetStateStore.recordAuditComplete({
    task: finalTaskSnapshot,
    selectedProjects,
    auditResult,
    scanArtifacts,
    report
  });

  tasks.completeTask(taskId, {
    phase: "completed",
    message: "审计完成，可下载 HTML 报告。",
    selectedProjectIds,
    auditResult,
    scanArtifacts,
    skillInsights,
    report,
    shannonHandoff,
    memorySummary,
    progress: {
      stage: "completed",
      label: "审计完成",
      detail: "",
      percent: 100,
      current: selectedProjects.length,
      total: selectedProjects.length
    }
  });
}

function updateTaskProgress(taskId, progress) {
  if (isTaskCancelled(taskId)) {
    return;
  }
  const current = tasks.getTask(taskId);
  tasks.updateTask(taskId, {
    progress: {
      ...(current?.progress || {}),
      ...progress
    }
  });
  void targetStateStore.recordProgress({
    taskId,
    progress,
    projectId: progress?.projectId || null,
    projectName: progress?.projectName || ""
  });
}

function isTaskCancelled(taskId) {
  return tasks.getTask(taskId)?.status === "cancelled";
}

function calculateMirrorPercent(projectIndex, totalProjects, processedFiles, totalFiles) {
  const safeProjects = Math.max(totalProjects || 1, 1);
  const safeTotalFiles = Math.max(totalFiles || 1, 1);
  const projectOffset = (projectIndex - 1) / safeProjects;
  const fileOffset = Math.min(processedFiles / safeTotalFiles, 1) / safeProjects;
  return Math.min(60, Math.max(24, Math.round(24 + (projectOffset + fileOffset) * 36)));
}

function buildAuditProgress(detail, totalProjects) {
  const safeProjects = Math.max(totalProjects || 1, 1);

  if (detail.stage === "heuristic") {
    return {
      stage: "heuristic",
      label: detail.label || `正在分析规则层：${detail.projectName || ""}`,
      detail: "",
      percent: Math.min(68, Math.round(60 + ((detail.projectIndex - 1) / safeProjects) * 8)),
      current: detail.projectIndex || 0,
      total: detail.totalProjects || safeProjects,
      projectId: detail.projectId || "",
      projectName: detail.projectName || ""
    };
  }

  if (detail.stage === "llm-review") {
    const totalBatches = Math.max(detail.totalBatches || 1, 1);
    const batchProgress = detail.currentBatch ? Math.min(detail.currentBatch / totalBatches, 1) : 0;
    const projectOffset = (Math.max((detail.projectIndex || 1) - 1, 0) / safeProjects) * 24;
    return {
      stage: "llm-review",
      label: detail.label || `正在进行 LLM 复核：${detail.projectName || ""}`,
      detail: detail.currentPath || `${detail.reviewedFiles || 0} / ${detail.totalFiles || 0} 个文件`,
      percent: Math.min(95, Math.round(68 + projectOffset + batchProgress * (24 / safeProjects))),
      current: detail.currentBatch || detail.reviewedBatches || 0,
      total: detail.totalBatches || 0,
      projectId: detail.projectId || "",
      projectName: detail.projectName || ""
    };
  }

  if (detail.stage === "project-complete") {
    return {
      stage: "project-complete",
      label: detail.label || `已完成：${detail.projectName || ""}`,
      detail: `规则层 ${detail.heuristicCount || 0} 条，LLM ${detail.llmCount || 0} 条`,
      percent: Math.min(96, Math.round(68 + ((detail.projectIndex || 0) / safeProjects) * 27)),
      current: detail.projectIndex || 0,
      total: detail.totalProjects || safeProjects,
      projectId: detail.projectId || "",
      projectName: detail.projectName || ""
    };
  }

  return {
    stage: detail.stage || "audit",
    label: detail.label || "正在审计",
    detail: detail.detail || "",
    percent: 70,
    current: detail.current || 0,
    total: detail.total || 0,
    projectId: detail.projectId || "",
    projectName: detail.projectName || ""
  };
}

function sanitizeSettings(settings) {
  return {
    llm: {
      providerId: settings.llm.providerId,
      baseUrl: settings.llm.baseUrl,
      model: settings.llm.model,
      apiKeyConfigured: Boolean(settings.llm.apiKey),
      apiKeyMasked: maskSecret(settings.llm.apiKey),
      defaults: providerDefaults(settings.llm.providerId)
    },
    github: {
      tokenConfigured: Boolean(settings.github.token),
      tokenMasked: maskSecret(settings.github.token),
      ownerFilter: settings.github.ownerFilter,
      notes: settings.github.notes
    },
    fofa: {
      email: settings.fofa.email,
      apiKeyConfigured: Boolean(settings.fofa.apiKey),
      apiKeyMasked: maskSecret(settings.fofa.apiKey),
      notes: settings.fofa.notes,
      safeMode: "stored-only"
    },
    updatedAt: settings.updatedAt
  };
}

function providerDefaults(providerId) {
  const preset = getProviderPreset(providerId);
  return { baseUrl: preset.defaultBaseUrl, model: preset.defaultModel, compatibility: preset.compatibility, label: preset.label };
}

async function testConnections(settings) {
  const llm = resolveLlmConfig(process.env, settings.llm);
  const [llmTest, githubTest, fofaTest] = await Promise.all([
    testLlmConnection(llm),
    testGithubConnection(settings.github),
    testFofaConnection(settings.fofa)
  ]);
  const allOk = llmTest.ok && githubTest.ok && fofaTest.ok;
  const someOk = llmTest.ok || githubTest.ok || fofaTest.ok;
  return { testedAt: new Date().toISOString(), llm: llmTest, github: githubTest, fofa: fofaTest, overall: allOk ? "pass" : someOk ? "partial" : "warn" };
}

async function testGithubConnection(github) {
  if (!github.token) return { ok: false, status: "warn", message: "未配置 GitHub Token" };
  try {
    const response = await fetch("https://api.github.com/rate_limit", {
      headers: {
        "User-Agent": "safe-framework-audit-agents",
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${github.token}`
      }
    });

    if (response.ok) {
      return { ok: true, status: "pass", message: "GitHub Token 可用" };
    }

    if (response.status === 401) {
      const fallback = await fetch("https://api.github.com/rate_limit", {
        headers: {
          "User-Agent": "safe-framework-audit-agents",
          "Accept": "application/vnd.github+json"
        }
      });

      if (fallback.ok) {
        return { ok: true, status: "warn", message: "GitHub Token 无效，但公开仓库仍可匿名抓取" };
      }
    }

    return { ok: false, status: "warn", message: `GitHub 返回 ${response.status}` };
  } catch (error) {
    return { ok: false, status: "warn", message: error instanceof Error ? error.message : String(error) };
  }
}

async function testFofaConnection(fofa) {
  if (!fofa.apiKey) return { ok: false, status: "warn", message: "未配置 FOFA API Key" };
  if (!fofa.email) return { ok: false, status: "warn", message: "未配置 FOFA Email" };
  try {
    const encoded = btoa(`${fofa.email}:${fofa.apiKey}`);
    const response = await fetch("https://api.fofa.com/v1/search/all?size=1&qbase64=IiI=", {
      headers: {
        Authorization: `Basic ${encoded}`,
        Accept: "application/json"
      }
    });

    if (response.ok) {
      return { ok: true, status: "pass", message: "FOFA API 可用" };
    }
    return { ok: false, status: "warn", message: `FOFA 返回 ${response.status}` };
  } catch (error) {
    return { ok: false, status: "warn", message: error instanceof Error ? error.message : String(error) };
  }
}

async function testLlmConnection(llm) {
  if (!llm.apiKey) return { ok: false, status: "warn", message: "未配置 LLM API Key" };
  try {
    let url = llm.baseUrl;
    let options = { headers: {} };
    if (llm.compatibility === "openai") {
      url = `${stripTrailingSlash(llm.baseUrl)}/models`;
      options.headers = { Authorization: `Bearer ${llm.apiKey}` };
    } else if (llm.compatibility === "gemini") {
      url = `${stripTrailingSlash(llm.baseUrl)}/v1beta/models?key=${encodeURIComponent(llm.apiKey)}`;
    } else if (llm.compatibility === "anthropic") {
      url = `${stripTrailingSlash(llm.baseUrl)}/v1/models`;
      options.headers = { "x-api-key": llm.apiKey, "anthropic-version": "2023-06-01" };
    }
    const response = await fetch(url, options);
    const ok = response.ok || response.status === 404;
    return { ok, status: ok ? "pass" : "warn", message: ok ? `LLM 端点可达 (${response.status})` : `LLM 返回 ${response.status}` };
  } catch (error) {
    return { ok: false, status: "warn", message: error instanceof Error ? error.message : String(error) };
  }
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function applyMemoryDefaults(body, memory) {
  const useMemory = body.useMemory !== false;
  const sourceType = body.sourceType === "local" ? "local" : "github";
  const huntMode = getHuntModeById(body.huntMode || memory.preferences.preferredHuntMode || "hackerone").id;
  const programProfile = getProgramProfileById(body.programProfile || memory.preferences.preferredProgramProfile || getDefaultProgramProfileId()).id;
  const selectedSkillIds = Array.isArray(body.selectedSkillIds) && body.selectedSkillIds.length
    ? body.selectedSkillIds
    : getDefaultSkillIdsForMode(huntMode);
  const localRepoPaths = Array.isArray(body.localRepoPaths)
    ? body.localRepoPaths
    : String(body.localRepoPaths || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
  if (sourceType === "local") {
    return {
      ...body,
      sourceType,
      huntMode,
      programProfile,
      selectedSkillIds,
      localRepoPaths,
      useMemory,
      query: "local repository import",
      cmsType: "all",
      industry: "all",
      minAdoption: 0
    };
  }

  if (!useMemory) {
    return {
      ...body,
      sourceType,
      huntMode,
      programProfile,
      selectedSkillIds,
      localRepoPaths: [],
      useMemory: false,
      query: body.query || getProgramQuery(programProfile),
      cmsType: body.cmsType || "all",
      industry: body.industry || "all",
      minAdoption: Number(body.minAdoption || 100)
    };
  }
  return {
    ...body,
    sourceType,
    huntMode,
    programProfile,
    selectedSkillIds,
    localRepoPaths: [],
    useMemory,
    query: body.query || memory.preferences.preferredQuery || getProgramQuery(programProfile),
    cmsType: body.cmsType || "all",
    industry: body.industry || "all",
    minAdoption: Number(body.minAdoption || memory.preferences.preferredMinAdoption || 100)
  };
}

function buildMemorySnapshot(memory) {
  return { rules: memory.rules, preferences: memory.preferences, learnedPatterns: memory.learnedPatterns.slice(0, 5) };
}

function buildMemorySummary(task, scoutResult, auditResult) {
  const topProjects = (scoutResult.projects || []).slice(0, 3).map((project) => project.sourceType === "local" ? project.localPath : `${project.owner}/${project.name}`);
  const findingTitles = auditResult.projects.flatMap((project) => project.findings.map((finding) => finding.title));
  return {
    createdAt: new Date().toISOString(),
    query: task.query,
    minAdoption: task.minAdoption,
    huntMode: task.huntMode,
    programProfile: task.programProfile,
    projectsReviewed: auditResult.projects.length,
    topProjects,
    findingsCount: auditResult.findingsCount,
    learnedPatterns: findingTitles.slice(0, 4)
  };
}

async function readJson(req) {
  const chunks = [];
  let totalBytes = 0;
  const maxBytes = 2 * 1024 * 1024;
  for await (const chunk of req) {
    totalBytes += chunk.length;
    if (totalBytes > maxBytes) {
      throw new Error("Request body too large");
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

async function serveFileFromRoot(res, rootDir, relativePath) {
  const root = path.resolve(rootDir);
  const target = path.resolve(root, relativePath || "");
  if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
    return sendJson(res, 403, { error: "Forbidden" });
  }
  return serveFile(res, target);
}

async function serveFile(res, filePath) {
  try {
    const content = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const type = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".md": "text/markdown; charset=utf-8" }[ext] || "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": type,
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      Expires: "0"
    });
    res.end(content);
  } catch {
    sendJson(res, 404, { error: "File not found" });
  }
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    Expires: "0"
  });
  res.end(JSON.stringify(payload, null, 2));
}

function serveSse(res, taskId, taskStore) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    "Connection": "keep-alive"
  });

  const unsubscribe = taskStore.subscribe(taskId, (event) => {
    res.write(`event: ${event.event}\n`);
    res.write(`data: ${JSON.stringify(event.task)}\n\n`);
  });

  res.on("close", () => {
    unsubscribe();
  });
}

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Safe audit agents listening on http://localhost:${port}`));
