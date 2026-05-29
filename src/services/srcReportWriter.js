/**
 * SRC 报告生成器
 * 按照标准 SRC 报告格式生成中文漏洞报告
 * 格式：漏洞概述 → 复现步骤 → 危害说明 → 修复建议
 */
import { promises as fs } from "node:fs";
import path from "node:path";

export async function writeSrcReport({ reportsDir, finding }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const fileName = `SRC-Report-${finding.target || "unknown"}-${finding.vulnType || "vuln"}-${timestamp}.md`;
  const filePath = path.join(reportsDir, fileName);

  const markdown = buildSrcMarkdown(finding);
  await fs.writeFile(filePath, markdown, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

export async function writeSrcHtmlReport({ reportsDir, finding }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const fileName = `SRC-Report-${finding.target || "unknown"}-${finding.vulnType || "vuln"}-${timestamp}.html`;
  const filePath = path.join(reportsDir, fileName);

  const html = buildSrcHtml(finding);
  await fs.writeFile(filePath, html, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

function buildSrcMarkdown(finding) {
  const lines = [];

  lines.push(`# ${finding.title || "漏洞报告"}`);
  lines.push("");
  lines.push(`**提交平台**: ${finding.platform || "未指定"}`);
  lines.push(`**目标**: ${finding.target || "未指定"}`);
  lines.push(`**漏洞类型**: ${finding.vulnType || "未指定"}`);
  lines.push(`**严重程度**: ${finding.severity || "中"}`);
  lines.push(`**发现时间**: ${finding.foundAt || new Date().toISOString().slice(0, 10)}`);
  lines.push("");

  // 漏洞概述
  lines.push("## 一、漏洞概述");
  lines.push("");
  lines.push(finding.summary || "通过修改XXX功能的参数，可以实现XXX效果。");
  lines.push("");

  // 复现步骤
  lines.push("## 二、复现步骤");
  lines.push("");
  if (Array.isArray(finding.steps) && finding.steps.length) {
    finding.steps.forEach((step, i) => {
      lines.push(`${i + 1}. ${step}`);
    });
  } else {
    lines.push("1. 打开目标网站/APP");
    lines.push("2. 进入相关功能页面");
    lines.push("3. 使用抓包工具拦截请求");
    lines.push("4. 修改相关参数");
    lines.push("5. 放行数据包");
    lines.push("6. 观察结果");
  }
  lines.push("");

  // 数据包
  if (finding.requestPacket) {
    lines.push("### 数据包");
    lines.push("");
    lines.push("```http");
    lines.push(finding.requestPacket);
    lines.push("```");
    lines.push("");
  }

  // 截图说明
  if (Array.isArray(finding.screenshots) && finding.screenshots.length) {
    lines.push("### 截图");
    lines.push("");
    finding.screenshots.forEach((screenshot, i) => {
      lines.push(`![截图${i + 1}](${screenshot.url || screenshot})`);
      if (screenshot.description) {
        lines.push(`*${screenshot.description}*`);
      }
      lines.push("");
    });
  }

  // 危害
  lines.push("## 三、危害说明");
  lines.push("");
  lines.push(finding.impact || "该漏洞可能导致平台/用户造成经济损失或数据泄露。");
  lines.push("");

  // 修复建议
  lines.push("## 四、修复建议");
  lines.push("");
  if (Array.isArray(finding.fixSuggestions) && finding.fixSuggestions.length) {
    finding.fixSuggestions.forEach((fix) => {
      lines.push(`- ${fix}`);
    });
  } else {
    lines.push(finding.fix || "建议对该接口的参数做严格的服务端校验。");
  }
  lines.push("");

  // 备注
  if (finding.notes) {
    lines.push("## 五、备注");
    lines.push("");
    lines.push(finding.notes);
    lines.push("");
  }

  return lines.join("\n");
}

function buildSrcHtml(finding) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SRC漏洞报告 - ${escapeHtml(finding.title || "未命名")}</title>
  <style>
    body{font-family:"PingFang SC","Microsoft YaHei",sans-serif;margin:0;background:#f8f6f2;color:#1a1a1a;line-height:1.7}
    .container{max-width:860px;margin:0 auto;padding:40px 24px}
    .header{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:32px;border-radius:16px;margin-bottom:24px}
    .header h1{margin:0 0 12px;font-size:1.5rem}
    .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;font-size:0.85rem;opacity:0.85}
    .section{background:#fff;border:1px solid #e8e2d8;border-radius:12px;padding:24px;margin-bottom:16px}
    .section h2{margin:0 0 16px;font-size:1.15rem;color:#2d2d2d;border-bottom:2px solid #e8e2d8;padding-bottom:8px}
    .severity{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
    .severity.critical{background:#fee;color:#c00}
    .severity.high{background:#fff0e0;color:#c55}
    .severity.medium{background:#fff8e0;color:#886}
    .severity.low{background:#e8f8e8;color:#484}
    ol{padding-left:20px}
    ol li{margin-bottom:8px}
    pre{background:#1a1a2e;color:#e0e0e0;padding:16px;border-radius:8px;overflow-x:auto;font-size:0.85rem}
    .fix-list{list-style:none;padding:0}
    .fix-list li{padding:8px 12px;background:#f0f8f0;border-radius:8px;margin-bottom:8px;border-left:3px solid #4a8}
    .note{padding:14px;background:#fffbe6;border-radius:8px;border:1px solid #ede5b0}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>${escapeHtml(finding.title || "漏洞报告")}</h1>
      <div class="meta">
        <span>平台: ${escapeHtml(finding.platform || "未指定")}</span>
        <span>目标: ${escapeHtml(finding.target || "未指定")}</span>
        <span>类型: ${escapeHtml(finding.vulnType || "未指定")}</span>
        <span>严重程度: <span class="severity ${escapeHtml(finding.severity || "medium")}">${escapeHtml(finding.severity || "中")}</span></span>
        <span>发现时间: ${escapeHtml(finding.foundAt || new Date().toISOString().slice(0, 10))}</span>
      </div>
    </div>

    <div class="section">
      <h2>一、漏洞概述</h2>
      <p>${escapeHtml(finding.summary || "通过修改参数可实现未授权操作。")}</p>
    </div>

    <div class="section">
      <h2>二、复现步骤</h2>
      <ol>
        ${(finding.steps || ["打开目标", "抓包", "修改参数", "验证结果"]).map((s) => `<li>${escapeHtml(s)}</li>`).join("\n        ")}
      </ol>
      ${finding.requestPacket ? `<h3>数据包</h3><pre>${escapeHtml(finding.requestPacket)}</pre>` : ""}
    </div>

    <div class="section">
      <h2>三、危害说明</h2>
      <p>${escapeHtml(finding.impact || "该漏洞可能对平台造成经济损失或用户数据泄露。")}</p>
    </div>

    <div class="section">
      <h2>四、修复建议</h2>
      <ul class="fix-list">
        ${(finding.fixSuggestions || [finding.fix || "建议对参数做服务端校验"]).map((f) => `<li>${escapeHtml(f)}</li>`).join("\n        ")}
      </ul>
    </div>

    ${finding.notes ? `<div class="section"><h2>五、备注</h2><div class="note">${escapeHtml(finding.notes)}</div></div>` : ""}
  </div>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
