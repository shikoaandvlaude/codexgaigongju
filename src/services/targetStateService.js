import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_STATE = {
  updatedAt: null,
  tasks: {},
  targets: {}
};

let pendingWrite = null;
let writeTimer = null;

export function createTargetStateStore({ filePath }) {
  async function read() {
    if (pendingWrite) {
      return normalizeState(pendingWrite);
    }
    try {
      const raw = await fs.readFile(filePath, "utf8");
      return normalizeState(JSON.parse(raw));
    } catch {
      return structuredClone(DEFAULT_STATE);
    }
  }

  async function write(nextState) {
    const normalized = normalizeState(nextState);
    pendingWrite = normalized;
    if (!writeTimer) {
      writeTimer = setTimeout(async () => {
        writeTimer = null;
        if (!pendingWrite) {
          return;
        }
        try {
          await fs.mkdir(path.dirname(filePath), { recursive: true });
          await fs.writeFile(filePath, JSON.stringify(pendingWrite, null, 2), "utf8");
        } catch {
          // ignore write errors
        } finally {
          pendingWrite = null;
        }
      }, 300);
    }
    return normalized;
  }

  async function recordScoutRun({ task, scoutResult }) {
    const state = await read();
    const now = new Date().toISOString();
    const taskEntry = ensureTaskEntry(state, task);
    taskEntry.phase = "target-selection";
    taskEntry.status = task?.status || "awaiting_selection";
      taskEntry.summary = scoutResult?.summary || taskEntry.summary || "";
      taskEntry.programProfile = task?.programProfile || taskEntry.programProfile || "";
      taskEntry.selectedProjectIds = Array.isArray(task?.selectedProjectIds) ? task.selectedProjectIds : [];
      taskEntry.projects = Array.isArray(scoutResult?.projects)
      ? scoutResult.projects.map((project) => ({
          id: project.id,
          name: project.name,
          sourceType: project.sourceType,
          repoUrl: project.repoUrl,
          localPath: project.localPath || "",
          language: project.language || "",
          programProfile: project.programProfile || "",
          programFamily: project.programFamily || "",
          recommendedSkillIds: Array.isArray(project.recommendedSkillIds) ? project.recommendedSkillIds : [],
          auditSurfaceHints: Array.isArray(project.auditSurfaceHints) ? project.auditSurfaceHints : []
        }))
      : [];
    pushTaskSnapshot(taskEntry, {
      at: now,
      type: "scout-complete",
      stage: "target-selection",
      label: "候选目标已发现",
      detail: taskEntry.summary || "",
      percent: 20,
      selectedProjects: taskEntry.projects.map((project) => project.id)
    });

    for (const project of taskEntry.projects) {
      const targetEntry = ensureTargetEntry(state, project, task);
      targetEntry.status = "discovered";
      targetEntry.phase = "target-selection";
      targetEntry.lastTaskId = task?.id || null;
      targetEntry.lastSeenAt = now;
      targetEntry.selectedSkillIds = uniqStrings([...(targetEntry.selectedSkillIds || []), ...(project.recommendedSkillIds || [])]);
      pushTargetSnapshot(targetEntry, {
        at: now,
        type: "discovered",
        stage: "target-selection",
        label: "候选目标已发现",
        detail: project.name || project.id,
        projectId: project.id,
        percent: 20
      });
    }

    state.updatedAt = now;
    await write(state);
    return state;
  }

  async function recordAuditStart({ task, selectedProjects = [] }) {
    const state = await read();
    const now = new Date().toISOString();
    const taskEntry = ensureTaskEntry(state, task);
    taskEntry.phase = "audit-analyst";
    taskEntry.status = "running";
    taskEntry.selectedProjectIds = selectedProjects.map((project) => project.id);
    pushTaskSnapshot(taskEntry, {
      at: now,
      type: "audit-start",
      stage: "audit-analyst",
      label: "开始审计",
      detail: `Selected ${selectedProjects.length} targets`,
      percent: 24,
      selectedProjects: selectedProjects.map((project) => project.id)
    });

    for (const project of selectedProjects) {
      const targetEntry = ensureTargetEntry(state, project, task);
      targetEntry.status = "selected";
      targetEntry.phase = "mirror";
      targetEntry.lastTaskId = task?.id || null;
      targetEntry.lastSeenAt = now;
      pushTargetSnapshot(targetEntry, {
        at: now,
        type: "selected",
        stage: "mirror",
        label: `准备镜像: ${project.name || project.id}`,
        detail: project.repoUrl || project.localPath || "",
        projectId: project.id,
        percent: 24
      });
    }

    state.updatedAt = now;
    await write(state);
    return state;
  }

  async function recordProgress({ taskId, progress, projectId, projectName }) {
    if (!taskId || !progress) {
      return null;
    }

    const state = await read();
    const now = new Date().toISOString();
    const taskEntry = ensureTaskEntry(state, { id: taskId });
    pushTaskSnapshot(taskEntry, {
      at: now,
      type: "progress",
      stage: progress.stage || "progress",
      label: progress.label || "",
      detail: progress.detail || "",
      percent: Number(progress.percent || 0),
      current: Number(progress.current || 0),
      total: Number(progress.total || 0),
      projectId: projectId || null,
      projectName: projectName || "",
      selectedProjects: Array.isArray(taskEntry.selectedProjectIds) ? taskEntry.selectedProjectIds : []
    });

    if (projectId) {
      const targetEntry = ensureTargetEntry(state, {
        id: projectId,
        name: projectName || projectId,
        sourceType: "unknown"
      }, { id: taskId });
      targetEntry.lastTaskId = taskId;
      targetEntry.lastSeenAt = now;
      targetEntry.phase = progress.stage || targetEntry.phase || "progress";
      targetEntry.status = progress.stage === "completed" ? "completed" : (targetEntry.status || "running");
      pushTargetSnapshot(targetEntry, {
        at: now,
        type: "progress",
        stage: progress.stage || "progress",
        label: progress.label || "",
        detail: progress.detail || "",
        percent: Number(progress.percent || 0),
        current: Number(progress.current || 0),
        total: Number(progress.total || 0),
        projectId,
        projectName: projectName || ""
      });
    }

    state.updatedAt = now;
    await write(state);
    return state;
  }

  async function recordAuditComplete({ task, selectedProjects = [], auditResult, scanArtifacts, report }) {
    const state = await read();
    const now = new Date().toISOString();
    const taskEntry = ensureTaskEntry(state, task);
    taskEntry.phase = "completed";
    taskEntry.status = "completed";
    taskEntry.reportPath = report?.filePath || "";
    taskEntry.handoffPath = report?.jsonDownloadPath || "";
    taskEntry.summary = auditResult?.reviewedAt || taskEntry.summary || "";
    pushTaskSnapshot(taskEntry, {
      at: now,
      type: "completed",
      stage: "completed",
      label: "审计完成",
      detail: report?.fileName || "",
      percent: 100,
      selectedProjects: selectedProjects.map((project) => project.id)
    });

    for (const project of selectedProjects) {
      const targetEntry = ensureTargetEntry(state, project, task);
      targetEntry.status = "completed";
      targetEntry.phase = "completed";
      targetEntry.lastTaskId = task?.id || null;
      targetEntry.lastSeenAt = now;
      targetEntry.findingsCount = Number(targetEntry.findingsCount || 0) + countProjectFindings(auditResult, project.id);
      targetEntry.scanHits = Number(targetEntry.scanHits || 0) + countProjectScanHits(scanArtifacts, project);
      targetEntry.selectedSkillIds = uniqStrings([
        ...(targetEntry.selectedSkillIds || []),
        ...(project?.recommendedSkillIds || []),
        ...((project?.projectProfile || []).map((skill) => skill?.id || skill?.name))
      ]);
      pushTargetSnapshot(targetEntry, {
        at: now,
        type: "completed",
        stage: "completed",
        label: `审计完成: ${project.name || project.id}`,
        detail: `findings=${countProjectFindings(auditResult, project.id)}`,
        percent: 100,
        projectId: project.id,
        projectName: project.name || ""
      });
    }

    state.updatedAt = now;
    await write(state);
    return state;
  }

  async function getTaskState(taskId) {
    const state = await read();
    return taskId ? state.tasks[taskId] || null : state.tasks;
  }

  async function getTargetState(projectId) {
    const state = await read();
    return projectId ? state.targets[projectId] || null : state.targets;
  }

  async function getSnapshot() {
    return read();
  }

  return {
    read,
    write,
    recordScoutRun,
    recordAuditStart,
    recordProgress,
    recordAuditComplete,
    getTaskState,
    getTargetState,
    getSnapshot
  };
}

function ensureTaskEntry(state, task) {
  const taskId = task?.id || "";
  if (!taskId) {
    return {
      taskId: "",
      snapshots: [],
      selectedProjectIds: [],
      projects: []
    };
  }

  if (!state.tasks[taskId]) {
    state.tasks[taskId] = {
      taskId,
      createdAt: task?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      sourceType: task?.sourceType || "",
      query: task?.query || "",
      programProfile: task?.programProfile || "",
      phase: task?.phase || "",
      status: task?.status || "",
      selectedSkillIds: Array.isArray(task?.selectedSkillIds) ? [...task.selectedSkillIds] : [],
      selectedProjectIds: Array.isArray(task?.selectedProjectIds) ? [...task.selectedProjectIds] : [],
      summary: "",
      reportPath: "",
      handoffPath: "",
      snapshots: [],
      projects: []
    };
  }

  state.tasks[taskId] = {
    ...state.tasks[taskId],
    taskId,
    updatedAt: new Date().toISOString(),
    sourceType: task?.sourceType ?? state.tasks[taskId].sourceType,
    query: task?.query ?? state.tasks[taskId].query,
    programProfile: task?.programProfile ?? state.tasks[taskId].programProfile,
    phase: task?.phase ?? state.tasks[taskId].phase,
    status: task?.status ?? state.tasks[taskId].status,
    selectedSkillIds: Array.isArray(task?.selectedSkillIds) ? [...task.selectedSkillIds] : state.tasks[taskId].selectedSkillIds || [],
    selectedProjectIds: Array.isArray(task?.selectedProjectIds) ? [...task.selectedProjectIds] : state.tasks[taskId].selectedProjectIds || [],
    projects: Array.isArray(state.tasks[taskId].projects) ? state.tasks[taskId].projects : [],
    snapshots: Array.isArray(state.tasks[taskId].snapshots) ? state.tasks[taskId].snapshots : []
  };

  return state.tasks[taskId];
}

function ensureTargetEntry(state, project, task) {
  const projectId = project?.id || "";
  if (!projectId) {
    return {
      projectId: "",
      snapshots: []
    };
  }

  if (!state.targets[projectId]) {
    state.targets[projectId] = {
      projectId,
      name: project?.name || projectId,
      sourceType: project?.sourceType || "",
      repoUrl: project?.repoUrl || "",
      localPath: project?.localPath || "",
      language: project?.language || "",
      programProfile: project?.programProfile || "",
      programFamily: project?.programFamily || "",
      status: "new",
      phase: "",
      lastTaskId: task?.id || null,
      lastSeenAt: new Date().toISOString(),
      findingsCount: 0,
      scanHits: 0,
      selectedSkillIds: [],
      snapshots: []
    };
  }

  state.targets[projectId] = {
    ...state.targets[projectId],
    projectId,
    name: project?.name || state.targets[projectId].name || projectId,
    sourceType: project?.sourceType ?? state.targets[projectId].sourceType,
    repoUrl: project?.repoUrl ?? state.targets[projectId].repoUrl,
    localPath: project?.localPath ?? state.targets[projectId].localPath,
    language: project?.language ?? state.targets[projectId].language,
    programProfile: project?.programProfile ?? state.targets[projectId].programProfile,
    programFamily: project?.programFamily ?? state.targets[projectId].programFamily,
    lastTaskId: task?.id || state.targets[projectId].lastTaskId || null,
    snapshots: Array.isArray(state.targets[projectId].snapshots) ? state.targets[projectId].snapshots : [],
    selectedSkillIds: Array.isArray(state.targets[projectId].selectedSkillIds) ? state.targets[projectId].selectedSkillIds : []
  };

  return state.targets[projectId];
}

function pushTaskSnapshot(taskEntry, snapshot) {
  if (!taskEntry) return;
  const snapshots = Array.isArray(taskEntry.snapshots) ? taskEntry.snapshots : [];
  if (isSimilarSnapshot(snapshots[snapshots.length - 1], snapshot)) {
    return;
  }
  snapshots.push(snapshot);
  taskEntry.snapshots = snapshots.slice(-24);
}

function pushTargetSnapshot(targetEntry, snapshot) {
  if (!targetEntry) return;
  const snapshots = Array.isArray(targetEntry.snapshots) ? targetEntry.snapshots : [];
  if (isSimilarSnapshot(snapshots[snapshots.length - 1], snapshot)) {
    return;
  }
  snapshots.push(snapshot);
  targetEntry.snapshots = snapshots.slice(-24);
}

function isSimilarSnapshot(previous, next) {
  if (!previous || !next) return false;
  const sameStage = previous.stage === next.stage;
  const sameLabel = previous.label === next.label;
  const sameProject = previous.projectId === next.projectId;
  const prevPercent = Number(previous.percent || 0);
  const nextPercent = Number(next.percent || 0);
  return sameStage && sameLabel && sameProject && Math.abs(nextPercent - prevPercent) < 5;
}

function countProjectFindings(auditResult, projectId) {
  const project = Array.isArray(auditResult?.projects)
    ? auditResult.projects.find((item) => item.projectId === projectId)
    : null;
  return Array.isArray(project?.findings) ? project.findings.length : 0;
}

function countProjectScanHits(scanArtifacts, project) {
  const findings = Array.isArray(scanArtifacts?.findings) ? scanArtifacts.findings : [];
  const tokens = [
    project?.id,
    project?.name,
    project?.repoUrl,
    project?.localPath
  ]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase());

  if (!tokens.length) {
    return 0;
  }

  return findings.filter((finding) => {
    const haystack = [
      finding?.location,
      finding?.evidence,
      finding?.title,
      finding?.sourceFile
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return tokens.some((token) => haystack.includes(token));
  }).length;
}

function normalizeState(state) {
  const next = structuredClone(DEFAULT_STATE);
  next.updatedAt = state?.updatedAt || null;
  next.tasks = state?.tasks && typeof state.tasks === "object" ? state.tasks : {};
  next.targets = state?.targets && typeof state.targets === "object" ? state.targets : {};

  for (const [taskId, entry] of Object.entries(next.tasks)) {
    next.tasks[taskId] = normalizeTaskEntry(taskId, entry);
  }
  for (const [projectId, entry] of Object.entries(next.targets)) {
    next.targets[projectId] = normalizeTargetEntry(projectId, entry);
  }

  return next;
}

function normalizeTaskEntry(taskId, entry) {
  return {
    taskId,
    createdAt: entry?.createdAt || new Date().toISOString(),
    updatedAt: entry?.updatedAt || new Date().toISOString(),
    sourceType: entry?.sourceType || "",
    query: entry?.query || "",
    phase: entry?.phase || "",
    status: entry?.status || "",
    selectedSkillIds: Array.isArray(entry?.selectedSkillIds) ? entry.selectedSkillIds : [],
    selectedProjectIds: Array.isArray(entry?.selectedProjectIds) ? entry.selectedProjectIds : [],
    summary: entry?.summary || "",
    reportPath: entry?.reportPath || "",
    handoffPath: entry?.handoffPath || "",
    snapshots: Array.isArray(entry?.snapshots) ? entry.snapshots.slice(-24) : [],
    projects: Array.isArray(entry?.projects) ? entry.projects : []
  };
}

function normalizeTargetEntry(projectId, entry) {
  return {
    projectId,
    name: entry?.name || projectId,
    sourceType: entry?.sourceType || "",
    repoUrl: entry?.repoUrl || "",
    localPath: entry?.localPath || "",
    language: entry?.language || "",
    status: entry?.status || "new",
    phase: entry?.phase || "",
    lastTaskId: entry?.lastTaskId || null,
    lastSeenAt: entry?.lastSeenAt || null,
    findingsCount: Number(entry?.findingsCount || 0),
    scanHits: Number(entry?.scanHits || 0),
    selectedSkillIds: Array.isArray(entry?.selectedSkillIds) ? entry.selectedSkillIds : [],
    snapshots: Array.isArray(entry?.snapshots) ? entry.snapshots.slice(-24) : []
  };
}

function uniqStrings(values) {
  return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
}
