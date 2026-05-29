/**
 * SRC 漏洞挖掘前端逻辑
 */

// ============ Tab 切换 ============
const tabs = document.querySelectorAll(".src-tab");
const panels = document.querySelectorAll(".src-panel");

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const target = tab.dataset.tab;
    panels.forEach((p) => {
      p.classList.toggle("hidden", p.id !== `tab-${target}`);
    });
  });
});

// ============ 工具函数 ============
function toast(msg, type = "info") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = `toast ${type}`;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 3000);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  return res.json();
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ============ 目标管理 ============
const btnAddTarget = document.getElementById("btn-add-target");
const addForm = document.getElementById("add-target-form");
const btnSave = document.getElementById("btn-save-target");
const btnCancel = document.getElementById("btn-cancel-target");
const targetList = document.getElementById("target-list");

btnAddTarget.addEventListener("click", () => addForm.classList.toggle("hidden"));
btnCancel.addEventListener("click", () => addForm.classList.add("hidden"));

btnSave.addEventListener("click", async () => {
  const authorized = document.getElementById("f-authorized").checked;
  if (!authorized) {
    toast("⚠️ 红线警告：必须先获得授权才能添加目标！", "error");
    return;
  }
  const target = {
    platformId: document.getElementById("f-platform").value,
    company: document.getElementById("f-company").value,
    rootDomain: document.getElementById("f-domain").value,
    scope: document.getElementById("f-scope").value,
    notes: document.getElementById("f-notes").value,
    authorized
  };
  const result = await api("/api/src/targets", { method: "POST", body: target });
  if (result.error || result.redLine) {
    toast(result.error || "添加失败", "error");
  } else {
    toast("目标已添加", "success");
    addForm.classList.add("hidden");
    loadTargets();
  }
});

async function loadTargets() {
  const data = await api("/api/src/targets");
  if (!Array.isArray(data) || !data.length) {
    targetList.innerHTML = '<p class="muted">暂无授权目标，点击"添加目标"开始。</p>';
    return;
  }
  targetList.innerHTML = data.map((t) => `
    <div class="src-target-card">
      <div class="target-head">
        <strong>${escapeHtml(t.company || t.rootDomain)}</strong>
        <span class="badge">${escapeHtml(t.platformId)}</span>
        <span class="badge ${t.authorized ? 'ok' : 'warn'}">${t.authorized ? '已授权' : '未授权'}</span>
      </div>
      <div class="target-meta">
        <span>域名: ${escapeHtml(t.rootDomain || "-")}</span>
        <span>范围: ${escapeHtml(t.scope)}</span>
        <span>添加时间: ${escapeHtml(t.createdAt?.slice(0, 10) || "-")}</span>
      </div>
      ${t.notes ? `<p class="muted">${escapeHtml(t.notes)}</p>` : ""}
      <div class="target-actions">
        <button class="ghost small" onclick="genReconForTarget('${escapeHtml(t.rootDomain)}')">生成搜集计划</button>
        <button class="ghost small danger" onclick="deleteTarget('${t.id}')">删除</button>
      </div>
    </div>
  `).join("");
}

window.deleteTarget = async function(id) {
  await api(`/api/src/targets/${id}`, { method: "DELETE" });
  toast("目标已删除");
  loadTargets();
};

window.genReconForTarget = function(domain) {
  document.getElementById("recon-domain").value = domain;
  tabs.forEach((t) => t.classList.remove("active"));
  document.querySelector('[data-tab="recon"]').classList.add("active");
  panels.forEach((p) => p.classList.toggle("hidden", p.id !== "tab-recon"));
  document.getElementById("btn-gen-recon").click();
};

// ============ 信息搜集 ============
document.getElementById("btn-gen-recon").addEventListener("click", async () => {
  const domain = document.getElementById("recon-domain").value.trim();
  if (!domain) { toast("请输入域名", "error"); return; }
  const result = await api(`/api/src/recon?domain=${encodeURIComponent(domain)}`);
  renderReconPlan(result);
});

document.getElementById("btn-f5-decode").addEventListener("click", () => {
  const cookie = prompt("输入F5 LTM Cookie值（如：487098378.24095.0000）:");
  if (!cookie) return;
  api(`/api/src/f5-decode?cookie=${encodeURIComponent(cookie)}`).then((r) => {
    const el = document.getElementById("recon-result");
    el.innerHTML = `<div class="sub-card"><h4>F5 LTM 解码结果</h4><p><strong>Cookie:</strong> ${escapeHtml(cookie)}</p><p><strong>真实IP:</strong> <code>${escapeHtml(r.ip || "解码失败")}</code></p></div>`;
  });
});

document.getElementById("btn-dorks").addEventListener("click", async () => {
  const domain = document.getElementById("recon-domain").value.trim() || "example.com";
  const result = await api(`/api/src/dorks?domain=${encodeURIComponent(domain)}`);
  const el = document.getElementById("recon-result");
  let html = '<div class="sub-card"><h4>搜索引擎语法</h4>';
  for (const [engine, dorks] of Object.entries(result)) {
    html += `<h5 style="margin-top:12px">${escapeHtml(engine.toUpperCase())}</h5><ul>`;
    dorks.forEach((d) => { html += `<li><strong>${escapeHtml(d.name)}:</strong> <code>${escapeHtml(d.query)}</code></li>`; });
    html += "</ul>";
  }
  html += "</div>";
  el.innerHTML = html;
});

function renderReconPlan(plan) {
  const el = document.getElementById("recon-result");
  if (!plan || !plan.steps) { el.innerHTML = '<p class="muted">无结果</p>'; return; }
  let html = `<h3>信息搜集计划: ${escapeHtml(plan.domain)}</h3>`;
  for (const step of plan.steps) {
    html += `<div class="sub-card"><h4>Step ${step.order}: ${escapeHtml(step.name)}</h4><p class="muted">${escapeHtml(step.description)}</p>`;
    if (step.tasks) {
      html += "<ul>";
      step.tasks.forEach((t) => {
        html += `<li>${escapeHtml(t.task)}${t.url ? ` - <a href="${escapeHtml(t.url)}" target="_blank">链接</a>` : ""}${t.command ? ` - <code>${escapeHtml(t.command)}</code>` : ""}</li>`;
      });
      html += "</ul>";
    }
    if (step.commands) {
      html += "<p><strong>命令:</strong></p><ul>";
      step.commands.forEach((c) => { html += `<li><code>${escapeHtml(c)}</code></li>`; });
      html += "</ul>";
    }
    if (step.methods) {
      html += "<p><strong>方法:</strong></p><ul>";
      step.methods.forEach((m) => { html += `<li><strong>${escapeHtml(m.name)}</strong>: ${escapeHtml(m.description)}</li>`; });
      html += "</ul>";
    }
    if (step.paths) {
      html += `<p><strong>检测路径 (${step.paths.length}条):</strong></p><ul>`;
      step.paths.slice(0, 10).forEach((p) => { html += `<li><code>${escapeHtml(p.fullUrl)}</code> [${escapeHtml(p.risk)}]</li>`; });
      if (step.paths.length > 10) html += `<li class="muted">...还有 ${step.paths.length - 10} 条</li>`;
      html += "</ul>";
    }
    html += "</div>";
  }
  el.innerHTML = html;
}

// ============ 漏洞模板 ============
document.getElementById("btn-recommend").addEventListener("click", async () => {
  const feature = document.getElementById("tpl-feature").value;
  if (!feature) { toast("请选择功能点类型", "error"); return; }
  const result = await api(`/api/src/templates/recommend?feature=${encodeURIComponent(feature)}`);
  renderTemplates(result);
});

document.getElementById("btn-analyze-params").addEventListener("click", async () => {
  const params = document.getElementById("tpl-params").value.trim();
  if (!params) { toast("请输入参数", "error"); return; }
  const result = await api("/api/src/templates/analyze-params", { method: "POST", body: { params: params.split(",").map((p) => p.trim()) } });
  renderParamAnalysis(result);
});

document.getElementById("btn-all-templates").addEventListener("click", async () => {
  const result = await api("/api/src/templates");
  renderTemplates(result);
});

function renderTemplates(templates) {
  const el = document.getElementById("templates-result");
  if (!templates || !templates.length) { el.innerHTML = '<p class="muted">无匹配模板</p>'; return; }
  let html = "";
  templates.forEach((t) => {
    html += `<div class="sub-card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h4>${escapeHtml(t.name)}</h4>
        <span class="badge ${t.severity}">${escapeHtml(t.severity)}</span>
      </div>
      <p class="muted">[${escapeHtml(t.category)}] ${escapeHtml(t.description)}</p>
      <p><strong>测试步骤:</strong></p><ol>${t.testSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      ${t.params.length ? `<p><strong>关键参数:</strong> <code>${t.params.map(escapeHtml).join(", ")}</code></p>` : ""}
      ${t.payloads.length ? `<p><strong>测试Payload:</strong> <code>${t.payloads.map(escapeHtml).join(", ")}</code></p>` : ""}
    </div>`;
  });
  el.innerHTML = html;
}

function renderParamAnalysis(analysis) {
  const el = document.getElementById("templates-result");
  if (!analysis || !analysis.length) { el.innerHTML = '<p class="muted">未识别到可疑参数</p>'; return; }
  let html = '<h3>参数分析结果</h3>';
  analysis.forEach((a) => {
    html += `<div class="sub-card"><p><strong>参数:</strong> <code>${escapeHtml(a.param)}</code></p><p><strong>原因:</strong> ${escapeHtml(a.reason)}</p><p><strong>推荐测试:</strong> ${a.templates.join(", ")}</p></div>`;
  });
  el.innerHTML = html;
}

// ============ 报告生成 ============
document.getElementById("btn-gen-report").addEventListener("click", async () => {
  const finding = {
    title: document.getElementById("rpt-title").value,
    platform: document.getElementById("rpt-platform").value,
    target: document.getElementById("rpt-target").value,
    vulnType: document.getElementById("rpt-type").value,
    severity: document.getElementById("rpt-severity").value,
    summary: document.getElementById("rpt-summary").value,
    steps: document.getElementById("rpt-steps").value.split("\n").filter(Boolean),
    requestPacket: document.getElementById("rpt-packet").value,
    impact: document.getElementById("rpt-impact").value,
    fixSuggestions: document.getElementById("rpt-fix").value.split("\n").filter(Boolean)
  };
  if (!finding.title) { toast("请填写漏洞标题", "error"); return; }
  const result = await api("/api/src/report", { method: "POST", body: finding });
  const el = document.getElementById("report-result");
  if (result.error) {
    el.innerHTML = `<p class="error">${escapeHtml(result.error)}</p>`;
  } else {
    el.innerHTML = `<div class="sub-card"><h4>✅ 报告已生成</h4><p>文件: ${escapeHtml(result.fileName)}</p><p><a href="${escapeHtml(result.downloadPath)}" target="_blank">下载报告</a></p></div>`;
    toast("报告生成成功！", "success");
  }
});

// ============ 红线提醒 ============
async function loadRedLines() {
  const data = await api("/api/src/redlines");
  const el = document.getElementById("redlines-content");
  let html = '<div class="redline-grid">';
  data.forEach((r) => {
    html += `<div class="sub-card redline-${r.level}"><div style="display:flex;justify-content:space-between"><strong>${escapeHtml(r.rule)}</strong><span class="badge ${r.level}">${escapeHtml(r.level)}</span></div><p class="muted">${escapeHtml(r.description)}</p><p><em>建议: ${escapeHtml(r.suggestion)}</em></p></div>`;
  });
  html += "</div>";
  el.innerHTML = html;
}

document.getElementById("btn-check-redline").addEventListener("click", async () => {
  const input = document.getElementById("redline-check-input").value.trim();
  if (!input) { toast("请输入操作描述", "error"); return; }
  const result = await api("/api/src/redlines/check", { method: "POST", body: { action: input } });
  const el = document.getElementById("redline-check-result");
  if (result.safe) {
    el.innerHTML = '<div class="sub-card" style="border-color:#4a8"><p>✅ <strong>安全</strong> — 未触犯红线规则</p></div>';
  } else {
    let html = `<div class="sub-card" style="border-color:#c55"><p>⚠️ <strong>警告！触犯 ${result.violations.length} 条红线规则</strong></p><ul>`;
    result.violations.forEach((v) => {
      html += `<li><span class="badge ${v.level}">${escapeHtml(v.level)}</span> ${escapeHtml(v.rule)}<br/><em>${escapeHtml(v.suggestion)}</em></li>`;
    });
    html += "</ul></div>";
    el.innerHTML = html;
  }
});

// ============ 初始化 ============
loadTargets();
loadRedLines();
