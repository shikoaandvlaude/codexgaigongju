import { promises as fs } from "node:fs";
import path from "node:path";

export async function writeShannonHandoff({ reportsDir, task, selectedProjects, auditResult, scanArtifacts, skillInsights, shannonRepoRoot }) {
  await fs.mkdir(reportsDir, { recursive: true });

  const stamp = task.id || `task-${Date.now()}`;
  const baseName = `shannon-handoff-${stamp}`;
  const mdFileName = `${baseName}.md`;
  const jsonFileName = `${baseName}.json`;
  const mdPath = path.join(reportsDir, mdFileName);
  const jsonPath = path.join(reportsDir, jsonFileName);

  const payload = buildPayload({ task, selectedProjects, auditResult, scanArtifacts, skillInsights, shannonRepoRoot });
  await fs.writeFile(jsonPath, JSON.stringify(payload, null, 2), "utf8");
  await fs.writeFile(mdPath, renderMarkdown(payload), "utf8");

  return {
    fileName: mdFileName,
    filePath: mdPath,
    downloadPath: `/reports/${mdFileName}`,
    jsonDownloadPath: `/reports/${jsonFileName}`,
    generatedAt: payload.generatedAt
  };
}

function buildPayload({ task, selectedProjects, auditResult, scanArtifacts, skillInsights, shannonRepoRoot }) {
  const repoRoot = shannonRepoRoot || path.join(process.cwd(), "integrations", "shannon");
  const workspaceName = sanitizeSegment(task?.id || "audit-task");
  const outputRoot = path.join(process.cwd(), "workspace", "shannon", workspaceName);
  const auditProjectMap = new Map((auditResult?.projects || []).map((item) => [item.projectId, item]));

  return {
    generatedAt: new Date().toISOString(),
    task: {
      id: task?.id || "",
      query: task?.query || "",
      sourceType: task?.sourceType || "",
      huntMode: task?.huntMode || "hackerone",
      programProfile: task?.programProfile || "cms",
      phase: task?.phase || "",
      useMemory: Boolean(task?.useMemory)
    },
    shannon: {
      repoRoot,
      outputRoot,
      workspaceName
    },
    projects: (selectedProjects || []).map((project, index) => {
      const auditProject = auditProjectMap.get(project?.id);
      const focusTags = uniqStrings([
        ...(project?.auditSurfaceHints || []),
        ...(project?.recommendedSkillIds || []),
        ...((auditProject?.projectProfile || project?.projectProfile || []).map((skill) => skill?.id || skill?.name))
      ]);

      return {
        index: index + 1,
        id: project?.id || "",
        name: project?.name || "",
        owner: project?.owner || "",
        repo: project?.repo || "",
        url: project?.url || project?.repoUrl || "",
        sourceType: project?.sourceType || "",
        localPath: project?.localPath || "",
        language: project?.language || "",
        description: project?.description || "",
        programProfile: project?.programProfile || "",
        programFamily: project?.programFamily || "",
        focusTags,
        findingsCount: auditProject?.heuristicFindings?.length || 0,
        llmFindingsCount: auditProject?.llmReview?.findings?.length || 0,
        command: buildShannonCommand({
          repoRoot,
          outputRoot,
          workspaceName,
          project
        })
      };
    }),
    auditSummary: {
      findingsCount: auditResult?.findingsCount || 0,
      heuristicFindingsCount: auditResult?.heuristicFindingsCount || 0,
      llmFindingsCount: auditResult?.llmFindingsCount || 0,
      llmCallCount: auditResult?.llmCallCount || 0,
      llmSkippedCount: auditResult?.llmSkippedCount || 0,
      reviewedAt: auditResult?.reviewedAt || ""
    },
    externalScans: summarizeScans(scanArtifacts),
    skillInsights: summarizeSkillInsights(skillInsights)
  };
}

function buildShannonCommand({ repoRoot, outputRoot, workspaceName, project }) {
  const repoPath = toWslPath(project?.localPath || path.join(process.cwd(), "workspace", "downloads", project?.id || ""));
  const targetUrl = project?.url || project?.repoUrl || "";
  const outputDir = toWslPath(path.join(outputRoot, project?.id || "project"));
  const workspace = `${workspaceName}-${slugify(project?.name || project?.id || "project")}`;
  const scriptPath = toWslPath(path.join(repoRoot, "scripts", "start-shannon-wsl.sh"));
  const args = [
    `--url ${targetUrl}`,
    `--repo ${repoPath}`,
    `--workspace ${workspace}`,
    `--output ${outputDir}`,
    "--monitor"
  ].filter(Boolean);

  return `wsl -d Ubuntu -- bash ${scriptPath} ${args.join(" ")}`;
}

function renderMarkdown(payload) {
  const lines = [];
  lines.push(`# Shannon 交接包`);
  lines.push("");
  lines.push(`- 生成时间: ${payload.generatedAt}`);
  lines.push(`- 任务 ID: ${payload.task.id}`);
  lines.push(`- 目标数: ${payload.projects.length}`);
  lines.push(`- Shannon 仓库: \`${payload.shannon.repoRoot}\``);
  lines.push(`- 输出根目录: \`${payload.shannon.outputRoot}\``);
  lines.push("");
  lines.push("## 使用方式");
  lines.push("");
  lines.push("按项目逐个跑 Shannon。下面的命令已经把主工具产出的镜像路径和目标地址填好了。");
  lines.push("");

  for (const project of payload.projects) {
    lines.push(`### ${project.name || project.id}`);
    lines.push("");
    if (project.description) {
      lines.push(project.description);
      lines.push("");
    }
    lines.push(`- 本地镜像: \`${project.localPath || "n/a"}\``);
    lines.push(`- 目标地址: \`${project.url || "n/a"}\``);
    lines.push(`- 重点标签: ${project.focusTags.length ? project.focusTags.map((tag) => `\`${tag}\``).join(" ") : "n/a"}`);
    lines.push("");
    lines.push("```powershell");
    lines.push(project.command);
    lines.push("```");
    lines.push("");
  }

  lines.push("## 审计摘要");
  lines.push("");
  lines.push(`- 保留结果: ${payload.auditSummary.findingsCount}`);
  lines.push(`- 规则层结果: ${payload.auditSummary.heuristicFindingsCount}`);
  lines.push(`- LLM 复核结果: ${payload.auditSummary.llmFindingsCount}`);
  lines.push("");

  if (payload.externalScans.length) {
    lines.push("## External scans");
    lines.push("");
    for (const scan of payload.externalScans) {
      lines.push(`### ${String(scan.type || "").toUpperCase()} - ${scan.targetLabel || "n/a"}`);
      lines.push("");
      lines.push(`- Results file: \`${scan.resultsPath || "n/a"}\``);
      lines.push(`- Hits: ${scan.findingsCount || 0}`);
      if (Array.isArray(scan.topFindings) && scan.topFindings.length) {
        for (const finding of scan.topFindings.slice(0, 3)) {
          lines.push(`  - ${finding.title} @ ${finding.location || "n/a"} (${finding.severity || "medium"}, ${formatScore(finding.signalScore || finding.confidence)})`);
        }
      }
      lines.push("");
    }
  }
  if (payload.skillInsights?.hotSkills?.length || payload.skillInsights?.drafts?.length) {
    lines.push("## Skill evolution");
    lines.push("");
    lines.push(`- Tracked skills: ${payload.skillInsights.summary?.trackedSkills || 0}`);
    lines.push(`- Hot skills: ${payload.skillInsights.summary?.hotSkills || 0}`);
    lines.push(`- Drafts: ${payload.skillInsights.summary?.drafts || 0}`);
    lines.push("");
    for (const skill of payload.skillInsights.hotSkills || []) {
      lines.push(`### ${skill.name || skill.id}`);
      lines.push("");
      lines.push(`- Runs: ${skill.runs || 0}`);
      lines.push(`- Findings: ${skill.findings || 0}`);
      lines.push(`- High-signal: ${skill.highSignalFindings || 0}`);
      lines.push(`- Surfaces: ${(skill.surfaces || []).join(", ") || "n/a"}`);
      lines.push("");
    }
    for (const draft of payload.skillInsights.drafts || []) {
      lines.push(`### Draft: ${draft.skillName || draft.skillId}`);
      lines.push("");
      lines.push(`- File: \`${draft.filePath || "n/a"}\``);
      lines.push(`- Focus: ${(draft.focusTags || []).map((tag) => `\`${tag}\``).join(" ") || "n/a"}`);
      lines.push(`- Score: ${formatScore(draft.signalScore || 0)}`);
      lines.push("");
    }
  }
  lines.push("Tip: if the Shannon repo cannot be fully checked out on Windows because of filename issues, keep the runnable subset or run this handoff on WSL / Linux / VPS.");
  return `${lines.join("\n")}\n`;
}

function summarizeScans(scanArtifacts) {
  const artifacts = Array.isArray(scanArtifacts?.artifacts) ? scanArtifacts.artifacts : [];
  const findings = Array.isArray(scanArtifacts?.findings) ? scanArtifacts.findings : [];

  return artifacts.map((artifact) => ({
    type: artifact.type,
    targetLabel: artifact.targetLabel,
    resultsPath: artifact.resultsPath,
    findingsCount: artifact.findings.length,
    topFindings: findings.filter((finding) => finding.source === artifact.type).slice(0, 3)
  }));
}

function summarizeSkillInsights(skillInsights) {
  const hotSkills = Array.isArray(skillInsights?.hotSkills) ? skillInsights.hotSkills : [];
  const drafts = Array.isArray(skillInsights?.drafts) ? skillInsights.drafts : [];

  return {
    generatedAt: skillInsights?.generatedAt || "",
    summary: skillInsights?.summary || {},
    hotSkills: hotSkills.slice(0, 6).map((skill) => ({
      id: skill.id,
      name: skill.name,
      runs: skill.runs || 0,
      findings: skill.findings || 0,
      highSignalFindings: skill.highSignalFindings || 0,
      surfaces: Array.isArray(skill.surfaces) ? skill.surfaces : []
    })),
    drafts: drafts.slice(0, 4).map((draft) => ({
      skillId: draft.skillId,
      skillName: draft.skillName,
      filePath: draft.filePath,
      focusTags: Array.isArray(draft.focusTags) ? draft.focusTags : [],
      signalScore: draft.signalScore || 0
    }))
  };
}

function uniqStrings(values) {
  return [...new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))];
}

function sanitizeSegment(value) {
  return String(value || "")
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80) || "task";
}

function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9\u4e00-\u9fa5]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60) || "project";
}

function toWslPath(value) {
  const text = String(value || "").replace(/\\/g, "/");
  const match = text.match(/^([A-Za-z]):\/(.*)$/);
  if (match) {
    return `/mnt/${match[1].toLowerCase()}/${match[2]}`;
  }
  return text.replace(/\/+/g, "/");
}

function formatScore(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) {
    return "0.00";
  }
  return score.toFixed(2);
}
