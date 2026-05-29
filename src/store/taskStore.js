import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getProgramQuery } from "../config/programProfiles.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Use the same workspace root as server.js (project_root/workspace/)
const workspaceDir = path.join(__dirname, "..", "..", "workspace");
const tasksFile = path.join(workspaceDir, "tasks.json");

const taskListeners = new Map();

// 防抖写入（避免频繁 IO）
let writeTimer = null;
let pendingWrite = null;

async function loadFromDisk() {
  try {
    await fs.mkdir(workspaceDir, { recursive: true });
    const raw = await fs.readFile(tasksFile, "utf8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

async function saveToDisk(tasks) {
  pendingWrite = tasks;
  if (writeTimer) return;
  writeTimer = setTimeout(async () => {
    writeTimer = null;
    if (pendingWrite) {
      try {
        await fs.mkdir(workspaceDir, { recursive: true });
        await fs.writeFile(tasksFile, JSON.stringify(pendingWrite, null, 2), "utf8");
      } catch {
        // ignore write errors
      }
      pendingWrite = null;
    }
  }, 500);
}

export function createTaskStore() {
  const memory = new Map();
  let initialized = false;

  // 异步初始化（不阻塞启动）
  loadFromDisk().then((data) => {
    for (const [id, task] of Object.entries(data)) {
      if (task.status === "running") {
        task.status = "queued";
        task.phase = "queued";
        task.message = "Task recovered after server restart.";
      }
      memory.set(id, task);
    }
    initialized = true;
  }).catch(() => { initialized = true; });

  function persist() {
    const obj = {};
    for (const [id, task] of memory) {
      obj[id] = task;
    }
    saveToDisk(obj);
  }

  function notifyListeners(task, event = "update") {
    const listeners = taskListeners.get(task.id) || [];
    for (const listener of listeners) {
      try {
        listener({ event, task: { id: task.id, status: task.status, phase: task.phase, message: task.message, progress: task.progress } });
      } catch {
        // ignore listener errors
      }
    }
  }

  return {
    subscribe(id, callback) {
      if (!taskListeners.has(id)) {
        taskListeners.set(id, []);
      }
      taskListeners.get(id).push(callback);
      return () => {
        const list = taskListeners.get(id);
        if (list) {
          const idx = list.indexOf(callback);
          if (idx >= 0) list.splice(idx, 1);
        }
      };
    },

    createTask(input = {}) {
      const task = {
        id: crypto.randomUUID(),
        status: "queued",
        phase: "queued",
        message: "Task accepted.",
        createdAt: new Date().toISOString(),
        updatedAt: null,
        sourceType: input.sourceType || "github",
        huntMode: input.huntMode || "hackerone",
        programProfile: input.programProfile || "general-oss",
        query: input.query || getProgramQuery(input.programProfile || "general-oss"),
        cmsType: input.cmsType || "all",
        industry: input.industry || "all",
        localRepoPaths: Array.isArray(input.localRepoPaths) ? input.localRepoPaths : [],
        minAdoption: Number(input.minAdoption || 100),
        useMemory: input.useMemory !== false,
        selectedSkillIds: Array.isArray(input.selectedSkillIds) ? input.selectedSkillIds : [],
        scoutResult: null,
        selectedProjectIds: [],
        auditResult: null,
        report: null,
        progress: {
          stage: "queued",
          label: "等待开始",
          detail: "",
          percent: 0,
          current: 0,
          total: 0
        },
        memorySnapshot: null,
        memorySummary: null,
        error: null
      };
      memory.set(task.id, task);
      persist();
      notifyListeners(task, "created");
      return task;
    },

    listTasks() {
      return Array.from(memory.values()).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    getTask(id) {
      return memory.get(id) || null;
    },

    updateTask(id, patch) {
      const task = memory.get(id);
      if (!task) {
        return null;
      }
      // Never overwrite a cancelled task (prevents race with runScout/runAudit)
      if (task.status === "cancelled" && patch.status && patch.status !== "cancelled") {
        return task;
      }
      Object.assign(task, patch, { updatedAt: new Date().toISOString() });
      persist();
      notifyListeners(task, "update");
      return task;
    },

    completeTask(id, patch) {
      const task = memory.get(id);
      if (task?.status === "cancelled") {
        return task;
      }
      return this.updateTask(id, { ...patch, status: "completed" });
    },

    failTask(id, error) {
      const task = memory.get(id);
      if (task?.status === "cancelled") {
        return task;
      }
      return this.updateTask(id, {
        status: "failed",
        phase: "failed",
        message: "Task failed.",
        error
      });
    }
  };
}
