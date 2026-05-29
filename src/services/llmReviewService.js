import { promises as fs } from "node:fs";
import path from "node:path";

const MAX_BATCHES = 8;
const MAX_FILES_PER_BATCH = 6;
const MAX_CHARS_PER_BATCH = 32_000;

const BOUNTY_SKILL_PRIORITY = {
  "access-control": 1.0,
  "query-safety": 0.94,
  ssrf: 0.92,
  "upload-storage": 0.86,
  "command-injection": 0.84,
  "path-traversal": 0.78,
  xss: 0.68,
  deserialization: 0.66,
  "bootstrap-config": 0.54,
  "secret-exposure": 0.42,
  "exposed-surface": 0.36,
  "weak-credential": 0.34,
  "cloud-misconfig": 0.34,
  "cicd-exposure": 0.32,
  "debug-backup": 0.3
};

const BOUNTY_FILE_PATTERNS = /(auth|login|session|permission|policy|role|rbac|tenant|owner|admin|api|graphql|resolver|controller|route|payment|order|coupon|wallet|billing|checkout|upload|file|proxy|webhook|callback|redirect|query|repository|service)/i;
const LOW_VALUE_FILE_PATTERNS = /(\.env|readme|docs?|example|sample|fixture|test|spec|debug|log|backup|swagger|openapi|health|metrics|version|banner)/i;
const BOUNTY_REPORTABLE_PATTERNS = /(idor|越权|权限|认证|鉴权|auth|permission|owner|role|tenant|admin|bypass|绕过|sql|nosql|注入|injection|ssrf|callback|webhook|redirect|upload|文件上传|path traversal|路径穿越|rce|command|命令|deserialize|反序列化|payment|order|coupon|wallet|billing|business|逻辑)/i;
const LOW_REPORTABILITY_PATTERNS = /(信息泄露|敏感信息|secret|token|api key|apikey|硬编码|env|debug|backup|日志|swagger|openapi|health|metrics|fingerprint|version|banner|missing header|security header)/i;

export class DefensiveLlmReviewer {
  async reviewProject({ project, selectedSkills, heuristicFindings, llmConfig, onProgress }) {
    if (!llmConfig?.apiKey) {
      return {
        status: "skipped",
        called: false,
        skipReason: "missing-api-key",
        summary: "未配置可用的 LLM API Key，本次没有调用大模型进行二次复核。",
        findings: [],
        warnings: []
      };
    }

    const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
    const files = await collectFiles(sourceRoot);
    if (!files.length) {
      return {
        status: "skipped",
        called: false,
        skipReason: "no-local-files",
        summary: "当前目标没有生成可供大模型复核的本地审计镜像，因此没有实际调用大模型。",
        findings: [],
        warnings: []
      };
    }

    const prioritizedFiles = rankFiles(files, heuristicFindings, selectedSkills);
    const batches = buildBatches(prioritizedFiles);
    const findings = [];
    const warnings = [];
    let reviewedFiles = 0;
    let reviewedBatches = 0;

    onProgress?.({
      type: "llm-start",
      totalFiles: prioritizedFiles.length,
      totalBatches: Math.min(batches.length, MAX_BATCHES),
      reviewedFiles: 0,
      reviewedBatches: 0,
      label: `正在准备 LLM 复核：${project.name}`
    });

    for (const [batchIndex, batch] of batches.slice(0, MAX_BATCHES).entries()) {
      onProgress?.({
        type: "llm-batch",
        currentBatch: batchIndex + 1,
        totalBatches: Math.min(batches.length, MAX_BATCHES),
        batchSize: batch.length,
        reviewedFiles,
        reviewedBatches,
        totalFiles: prioritizedFiles.length,
        label: `正在进行 LLM 复核：第 ${batchIndex + 1} / ${Math.min(batches.length, MAX_BATCHES)} 批`
      });

      try {
        const responseText = await requestStructuredReview({
          llmConfig,
          systemPrompt: buildSystemPrompt(selectedSkills),
          userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings, batch })
        });
        const parsed = parseJsonResponse(responseText);
        const normalized = normalizeFindings(parsed?.findings, selectedSkills);
        findings.push(...normalized);
        reviewedFiles += batch.length;
        reviewedBatches += 1;
        onProgress?.({
          type: "llm-batch-complete",
          currentBatch: batchIndex + 1,
          totalBatches: Math.min(batches.length, MAX_BATCHES),
          batchSize: batch.length,
          reviewedFiles,
          reviewedBatches,
          totalFiles: prioritizedFiles.length,
          label: `LLM 已完成第 ${batchIndex + 1} 批复核`
        });
      } catch (error) {
        warnings.push(error instanceof Error ? error.message : String(error));
        onProgress?.({
          type: "llm-batch-error",
          currentBatch: batchIndex + 1,
          totalBatches: Math.min(batches.length, MAX_BATCHES),
          batchSize: batch.length,
          reviewedFiles,
          reviewedBatches,
          totalFiles: prioritizedFiles.length,
          label: `LLM 第 ${batchIndex + 1} 批复核出现错误`
        });
      }
    }

    const dedupedFindings = dedupeFindings(findings).slice(0, 12);
    const truncated = prioritizedFiles.length > batches.slice(0, MAX_BATCHES).flat().length;

    return {
      status: warnings.length && !reviewedBatches ? "failed" : warnings.length ? "partial" : "completed",
      called: true,
      skipReason: "",
      providerId: llmConfig.providerId,
      model: llmConfig.model,
      reviewedFiles,
      totalCandidateFiles: prioritizedFiles.length,
      reviewedBatches,
      skillsUsed: selectedSkills.map((skill) => skill.id),
      summary: buildSummary({ reviewedFiles, reviewedBatches, findings: dedupedFindings, truncated }),
      warnings,
      findings: dedupedFindings.map((finding) => ({ ...finding, source: "llm" }))
    };
  }
}

async function requestStructuredReview({ llmConfig, systemPrompt, userPrompt }) {
  if (llmConfig.compatibility === "anthropic") {
    const response = await fetch(`${stripTrailingSlash(llmConfig.baseUrl)}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": llmConfig.apiKey,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: llmConfig.model,
        max_tokens: 1800,
        temperature: 0.1,
        system: systemPrompt,
        messages: [{ role: "user", content: userPrompt }]
      })
    });

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Anthropic 返回 ${response.status}`);
    }

    const data = await response.json();
    return (data.content || []).map((item) => item.text || "").join("\n");
  }

  if (llmConfig.compatibility === "gemini") {
    const response = await fetch(
      `${stripTrailingSlash(llmConfig.baseUrl)}/v1beta/models/${encodeURIComponent(llmConfig.model)}:generateContent?key=${encodeURIComponent(llmConfig.apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: [{ role: "user", parts: [{ text: userPrompt }] }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1800
          }
        })
      }
    );

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Gemini 返回 ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.map((item) => item.text || "").join("\n") || "";
  }

  const response = await fetch(`${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${llmConfig.apiKey}`
    },
    body: JSON.stringify({
      model: llmConfig.model,
      temperature: 0.1,
      max_tokens: 1800,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ]
    })
  });

  if (!response.ok) {
    throw new Error(`LLM 复核失败：模型端点返回 ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || "";
}

function buildSystemPrompt(selectedSkills) {
  const skills = selectedSkills.map((skill) => `- ${skill.name}: ${skill.reviewPrompt}`).join("\n");
  return [
    "你是一个防御性代码审计助手，专注于识别真实的安全风险。",
    "",
    "## 核心原则",
    "1. 只报告真实存在、可被利用的安全问题，不是误报",
    "2. 如果代码中有防护措施（验证、过滤、转义、白名单），不要报告风险",
    "3. 需要实际证据（漏洞代码模式）才能报告，不能猜测",
    "4. 如果证据不足，降低置信度或不要报告",
    "",
    "## 输出要求",
    "1. 只返回 JSON 对象，不要输出额外说明",
    "2. 严重性等级：critical（可利用/高风险）, high（条件成立时风险）, medium（需要注意）, low（低风险）",
    "3. 置信度必须在 0.65 以上才能报告",
    "4. 优先报告 HackerOne/SRC 更可能接受的问题：越权/IDOR、认证绕过、权限边界、服务端注入、SSRF、上传到可执行或敏感路径、支付/订单/优惠券/多租户业务逻辑。",
    "5. 信息泄露、硬编码密钥、调试页面、版本/banner/header 类问题只有在能证明真实敏感影响或可直接扩大权限时才报告，否则不要占用结果名额。",
    "",
    "## 不报告的示例（误报）",
    "- 有输入验证但报告 XSS：有 escapeHtml/sanitize 的代码",
    "- 有参数化查询但报告 SQL 注入：使用了 prepared statement",
    "- 有权限校验但报告越权：有 authorize/can/checkPermission",
    "- 白名单路径但报告路径穿越：使用 path.join/normalize",
    "",
    "## 需要报告的示例（真阳性）",
    "- 用户输入直接拼接到 SQL 查询中",
    "- eval() 中使用用户输入",
    "- 文件路径直接拼接用户输入",
    "- JWT 密钥硬编码",
    "- 管理员路由无认证",
    "- 普通用户可读取/修改其他用户或租户的数据",
    "- 支付、优惠券、订单状态等业务字段可被客户端绕过服务端校验",
    "",
    "## 审计 Skill：",
    skills
  ].join("\n");
}

function buildUserPrompt({ project, selectedSkills, heuristicFindings, batch }) {
  const heuristicSummary = heuristicFindings.slice(0, 8).map((finding) => `- ${finding.title} @ ${finding.location} (置信度: ${finding.confidence})`).join("\n") || "- 当前规则层未发现明确问题";
  const skills = selectedSkills.map((skill) => `${skill.id}: ${skill.description}`).join("\n");
  const auditSurfaceSummary = [
    ...(project.auditSurfaceHints || []),
    ...(project.recommendedSkillIds || [])
  ]
    .filter(Boolean)
    .slice(0, 12)
    .join(", ") || "none";
  const snippets = batch.map((file) => `FILE: ${file.relativePath}\n\`\`\`${file.language}\n${file.content}\n\`\`\``).join("\n\n");

  return [
    `## 项目信息`,
    `项目名称：${project.name}`,
    `审计路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
    `Audit surface hints: ${auditSurfaceSummary}`,
    "",
    `## 已启用的审计 Skill：`,
    skills,
    "",
    `## 规则层已发现的问题（供参考）：`,
    heuristicSummary,
    "",
    `## 任务`,
    "请仔细审阅以下源码片段，只报告确实存在安全问题的真实漏洞。",
    "本轮按赏金提交优先级工作：先找能形成 HackerOne/SRC 报告的权限、认证、注入、SSRF、上传、业务逻辑问题；不要把普通信息泄露当主结果。",
    "对于每个发现：",
    "1. 给出精确的问题位置（文件:行号）",
    "2. 说明漏洞的具体代码模式",
    "3. 确认没有防护措施才报告（检查代码中是否有 validate/sanitize/escape/authorize 等）",
    "",
    "## 输出格式（严格 JSON）：",
    '{ "findings": [ { "title": "问题标题", "severity": "critical|high|medium|low", "confidence": 0.65-1.0, "location": "文件路径:行号", "skillId": "skill id", "evidence": "具体漏洞代码", "impact": "影响说明", "remediation": "修复建议", "safeValidation": "验证建议" } ] }',
    "",
    `## 源码片段：`,
    snippets
  ].join("\n\n");
}

async function collectFiles(root) {
  try {
    const output = [];
    await walk(root, root, output);
    return output;
  } catch {
    return [];
  }
}

async function walk(root, currentPath, output) {
  const entries = await fs.readdir(currentPath, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      await walk(root, target, output);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const language = inferFenceLanguage(target);
    if (!language) {
      continue;
    }

    const content = await fs.readFile(target, "utf8");
    output.push({
      fullPath: target,
      relativePath: path.relative(root, target).replaceAll("\\", "/"),
      content,
      language
    });
  }
}

function rankFiles(files, heuristicFindings, selectedSkills) {
  const locationHints = new Set(heuristicFindings.map((finding) => finding.location).filter(Boolean));
  const keywordHints = selectedSkills.flatMap((skill) =>
    skill.reviewPrompt.toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter((token) => token.length > 3)
  );

  return [...files]
    .map((file) => {
      const loweredPath = file.relativePath.toLowerCase();
      let score = Math.min(file.content.length / 400, 50);
      if (locationHints.has(file.relativePath)) {
        score += 120;
      }
      if (/(auth|permission|policy|access|role|admin|upload|secret|query|config|service|controller)/.test(loweredPath)) {
        score += 60;
      }
      if (BOUNTY_FILE_PATTERNS.test(loweredPath)) {
        score += 90;
      }
      if (LOW_VALUE_FILE_PATTERNS.test(loweredPath)) {
        score -= 45;
      }
      for (const keyword of keywordHints) {
        if (loweredPath.includes(keyword)) {
          score += 5;
        }
      }
      return { ...file, score };
    })
    .sort((a, b) => b.score - a.score);
}

function buildBatches(files) {
  const batches = [];
  let currentBatch = [];
  let currentChars = 0;

  for (const file of files) {
    const snippetLength = file.content.length + file.relativePath.length;
    if (currentBatch.length && (currentBatch.length >= MAX_FILES_PER_BATCH || currentChars + snippetLength > MAX_CHARS_PER_BATCH)) {
      batches.push(currentBatch);
      currentBatch = [];
      currentChars = 0;
    }

    currentBatch.push(file);
    currentChars += snippetLength;
  }

  if (currentBatch.length) {
    batches.push(currentBatch);
  }

  return batches;
}

function parseJsonResponse(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) {
    return { findings: [] };
  }

  const fenceMatch = trimmed.match(/```json\s*([\s\S]*?)```/i);
  const candidate = fenceMatch?.[1]?.trim() || trimmed;

  try {
    return JSON.parse(candidate);
  } catch {
    const objectMatch = candidate.match(/\{[\s\S]*\}/);
    if (!objectMatch) {
      throw new Error("LLM 返回内容不是可解析的 JSON。");
    }
    return JSON.parse(objectMatch[0]);
  }
}

function normalizeFindings(findings, selectedSkills) {
  const validSkillIds = new Set(selectedSkills.map((skill) => skill.id));
  if (!Array.isArray(findings)) {
    return [];
  }

  return findings
    .map((finding) => ({
      title: safeString(finding.title, "LLM 复核发现"),
      severity: normalizeSeverity(finding.severity),
      confidence: clampConfidence(finding.confidence),
      location: safeString(finding.location, "n/a"),
      skillId: validSkillIds.has(finding.skillId) ? finding.skillId : selectedSkills[0]?.id || "access-control",
      evidence: safeString(finding.evidence, "模型复核认为这里存在值得继续人工确认的实现迹象。"),
      impact: safeString(finding.impact, "该实现如果在真实部署中成立，可能扩大管理面、数据面或配置暴露面。"),
      remediation: safeString(finding.remediation, "建议结合服务端收口、权限校验和默认值治理进行修复。"),
      safeValidation: safeString(finding.safeValidation, "建议在本地或测试环境里补充代码走读与单元测试来确认边界。")
    }))
    .map((finding) => ({
      ...finding,
      bountyPriority: estimateBountyPriority(finding),
      reportabilityScore: estimateReportabilityScore(finding)
    }))
    // 提高置信度阈值到 0.65 以减少误报
    .filter(isReviewFindingWorthKeeping);
}

function isReviewFindingWorthKeeping(finding) {
  if (finding.reportabilityScore < 0.56 && finding.skillId === "secret-exposure") {
    return finding.confidence >= 0.9 && finding.evidence !== "n/a";
  }
  if (finding.reportabilityScore < 0.5) {
    return false;
  }
  if (finding.severity === "critical" || finding.severity === "high") {
    return finding.confidence >= 0.6 && finding.evidence !== "n/a";
  }
  if (finding.severity === "medium") {
    return finding.confidence >= 0.65 && finding.evidence !== "n/a";
  }
  return finding.confidence >= 0.75 && finding.evidence !== "n/a";
}

function dedupeFindings(findings) {
  const seen = new Set();
  const output = [];

  for (const finding of findings) {
    const key = `${finding.title}::${finding.location}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push(finding);
  }

  return output.sort((a, b) => {
    const reportabilityDiff = (b.reportabilityScore || 0) - (a.reportabilityScore || 0);
    if (Math.abs(reportabilityDiff) > 1e-6) return reportabilityDiff;
    return severityScore(b.severity) - severityScore(a.severity) || b.confidence - a.confidence;
  });
}

function estimateBountyPriority(finding) {
  const base = BOUNTY_SKILL_PRIORITY[finding?.skillId] ?? 0.5;
  const haystack = [
    finding?.title,
    finding?.location,
    finding?.evidence,
    finding?.impact,
    finding?.safeValidation
  ].filter(Boolean).join(" ");

  let score = base;
  if (BOUNTY_REPORTABLE_PATTERNS.test(haystack)) score += 0.18;
  if (LOW_REPORTABILITY_PATTERNS.test(haystack)) score -= 0.18;
  if (/(critical|high)/i.test(finding?.severity || "")) score += 0.08;
  if (/(用户|账号|订单|支付|管理|tenant|role|admin|write|delete|upload|callback|database|internal)/i.test(haystack)) score += 0.08;
  if (/(header|version|banner|fingerprint|readme|文档|示例|example|sample)/i.test(haystack)) score -= 0.12;
  return clampConfidence(score);
}

function estimateReportabilityScore(finding) {
  const confidence = Number(finding?.confidence || 0);
  const severityBoost = { critical: 0.18, high: 0.12, medium: 0.05, low: 0 };
  return clampConfidence(
    estimateBountyPriority(finding)
      + confidence * 0.18
      + (severityBoost[String(finding?.severity || "").toLowerCase()] || 0)
  );
}

function buildSummary({ reviewedFiles, reviewedBatches, findings, truncated }) {
  const parts = [`LLM 已对 ${reviewedBatches} 个批次、${reviewedFiles} 个本地源码文件进行了二次复核。`];
  if (findings.length) {
    parts.push(`最终保留 ${findings.length} 条较高置信度的模型复核结果。`);
  } else {
    parts.push("模型没有额外保留到足够高置信度的问题。");
  }
  if (truncated) {
    parts.push("由于镜像较大，本次优先复核了高信号文件，未覆盖全部镜像文件。");
  }
  return parts.join("");
}

function inferFenceLanguage(filePath) {
  const basename = path.basename(filePath).toLowerCase();
  if (basename === ".env" || basename.startsWith(".env.")) {
    return "dotenv";
  }

  return {
    ".ts": "ts",
    ".tsx": "tsx",
    ".js": "js",
    ".jsx": "jsx",
    ".mjs": "js",
    ".cjs": "js",
    ".php": "php",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".xml": "xml"
  }[path.extname(filePath).toLowerCase()] || "";
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function normalizeSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (text === "critical") return "critical";
  if (text === "high") return "high";
  if (text === "medium") return "medium";
  return "low";
}

function clampConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0.65;
  }
  if (numeric < 0) {
    return 0;
  }
  if (numeric > 1) {
    return 1;
  }
  return numeric;
}

function safeString(value, fallback) {
  const text = String(value || "").trim();
  return text || fallback;
}

function severityScore(value) {
  return value === "critical" ? 4 : value === "high" ? 3 : value === "medium" ? 2 : 1;
}

