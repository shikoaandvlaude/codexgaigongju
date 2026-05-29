/**
 * CNVD 报告生成器
 * 按照 CNVD 提交格式生成中文漏洞报告
 * 
 * CNVD 报告要求：
 *   - 漏洞名称（简洁明了）
 *   - 漏洞发现时间
 *   - 漏洞类型（对应CNVD分类）
 *   - 漏洞等级（高危/中危/低危）
 *   - 影响产品/版本
 *   - 漏洞描述
 *   - 漏洞复现步骤
 *   - 修复建议
 *   - 发现者信息
 * 
 * 同时支持生成 CVE 兼容格式（一洞两吃：CVE + CNVD）
 */
import { promises as fs } from "node:fs";
import path from "node:path";

// CNVD 漏洞分类对照表
const CNVD_VULN_TYPES = {
  "sql-injection": { code: "CNVD-C-01", name: "SQL注入漏洞" },
  "xss": { code: "CNVD-C-02", name: "跨站脚本漏洞" },
  "command-injection": { code: "CNVD-C-03", name: "命令执行漏洞" },
  "file-upload": { code: "CNVD-C-04", name: "任意文件上传漏洞" },
  "file-include": { code: "CNVD-C-05", name: "文件包含漏洞" },
  "path-traversal": { code: "CNVD-C-06", name: "目录遍历漏洞" },
  "unauthorized": { code: "CNVD-C-07", name: "未授权访问漏洞" },
  "info-leak": { code: "CNVD-C-08", name: "信息泄露漏洞" },
  "weak-password": { code: "CNVD-C-09", name: "弱口令漏洞" },
  "deserialization": { code: "CNVD-C-10", name: "反序列化漏洞" },
  "ssrf": { code: "CNVD-C-11", name: "服务端请求伪造漏洞" },
  "csrf": { code: "CNVD-C-12", name: "跨站请求伪造漏洞" },
  "rce": { code: "CNVD-C-13", name: "远程代码执行漏洞" },
  "auth-bypass": { code: "CNVD-C-14", name: "认证绕过漏洞" },
  "idor": { code: "CNVD-C-15", name: "越权访问漏洞" },
  "logic": { code: "CNVD-C-16", name: "业务逻辑漏洞" },
  "dos": { code: "CNVD-C-17", name: "拒绝服务漏洞" },
  "hardcoded-secret": { code: "CNVD-C-18", name: "硬编码凭证漏洞" },
  "other": { code: "CNVD-C-99", name: "其他漏洞" }
};

// CNVD 严重等级
const CNVD_SEVERITY = {
  "critical": "高危",
  "high": "高危",
  "medium": "中危",
  "low": "低危"
};

/**
 * 生成 CNVD 格式的 Markdown 报告
 */
export async function writeCnvdReport({ reportsDir, finding }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeName = (finding.productName || "unknown").replace(/[^a-zA-Z0-9\u4e00-\u9fa5_-]/g, "_");
  const fileName = `CNVD-Report-${safeName}-${finding.vulnTypeId || "vuln"}-${timestamp}.md`;
  const filePath = path.join(reportsDir, fileName);

  const markdown = buildCnvdMarkdown(finding);
  await fs.writeFile(filePath, markdown, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

/**
 * 生成 CVE + CNVD 双格式报告（一洞两吃）
 */
export async function writeDualReport({ reportsDir, finding }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const safeName = (finding.productName || "unknown").replace(/[^a-zA-Z0-9\u4e00-\u9fa5_-]/g, "_");

  // CNVD 中文报告
  const cnvdFileName = `CNVD-Report-${safeName}-${timestamp}.md`;
  const cnvdFilePath = path.join(reportsDir, cnvdFileName);
  await fs.writeFile(cnvdFilePath, buildCnvdMarkdown(finding), "utf8");

  // CVE 英文报告
  const cveFileName = `CVE-Report-${safeName}-${timestamp}.md`;
  const cveFilePath = path.join(reportsDir, cveFileName);
  await fs.writeFile(cveFilePath, buildCveMarkdown(finding), "utf8");

  return {
    cnvd: {
      fileName: cnvdFileName,
      filePath: cnvdFilePath,
      downloadPath: `/reports/${cnvdFileName}`
    },
    cve: {
      fileName: cveFileName,
      filePath: cveFilePath,
      downloadPath: `/reports/${cveFileName}`
    },
    generatedAt: new Date().toISOString()
  };
}

/**
 * 获取 CNVD 漏洞分类列表
 */
export function getCnvdVulnTypes() {
  return Object.entries(CNVD_VULN_TYPES).map(([id, info]) => ({
    id,
    ...info
  }));
}

// ────────────────────────────────────────────────────────────────────────────
// 内部函数
// ────────────────────────────────────────────────────────────────────────────

function buildCnvdMarkdown(finding) {
  const vulnType = CNVD_VULN_TYPES[finding.vulnTypeId] || CNVD_VULN_TYPES["other"];
  const severity = CNVD_SEVERITY[finding.severity] || "中危";
  const now = new Date().toISOString().slice(0, 10);

  const lines = [];

  // 标题
  lines.push(`# ${finding.productName || "未知产品"} ${vulnType.name}`);
  lines.push("");

  // 基本信息表
  lines.push("## 基本信息");
  lines.push("");
  lines.push("| 字段 | 内容 |");
  lines.push("|------|------|");
  lines.push(`| 漏洞名称 | ${finding.productName || "未知产品"} ${vulnType.name} |`);
  lines.push(`| 漏洞类型 | ${vulnType.name} (${vulnType.code}) |`);
  lines.push(`| 漏洞等级 | ${severity} |`);
  lines.push(`| 影响产品 | ${finding.productName || "未指定"} |`);
  lines.push(`| 影响版本 | ${finding.affectedVersion || "全版本"} |`);
  lines.push(`| 厂商 | ${finding.vendor || "未指定"} |`);
  lines.push(`| 发现时间 | ${finding.foundAt || now} |`);
  lines.push(`| 发现者 | ${finding.discoverer || "安全研究者"} |`);
  if (finding.cveId) {
    lines.push(`| CVE编号 | ${finding.cveId} |`);
  }
  lines.push("");

  // 漏洞描述
  lines.push("## 漏洞描述");
  lines.push("");
  lines.push(finding.description || `${finding.productName || "该产品"} ${finding.affectedVersion || ""} 版本中存在${vulnType.name}。攻击者可利用该漏洞${getImpactDescription(finding.vulnTypeId)}。`);
  lines.push("");

  // 影响范围
  lines.push("## 影响范围");
  lines.push("");
  if (finding.affectedScope) {
    lines.push(finding.affectedScope);
  } else {
    lines.push(`- 产品名称：${finding.productName || "未指定"}`);
    lines.push(`- 影响版本：${finding.affectedVersion || "全版本"}`);
    if (finding.deploymentCount) {
      lines.push(`- 预估影响站点数：${finding.deploymentCount}`);
    }
    if (finding.productUrl) {
      lines.push(`- 产品地址：${finding.productUrl}`);
    }
  }
  lines.push("");

  // 漏洞复现
  lines.push("## 漏洞复现");
  lines.push("");
  lines.push("### 环境搭建");
  lines.push("");
  if (finding.environment) {
    lines.push(finding.environment);
  } else {
    lines.push("```");
    lines.push(`产品: ${finding.productName || "未指定"}`);
    lines.push(`版本: ${finding.affectedVersion || "最新版"}`);
    lines.push(`操作系统: ${finding.os || "Linux"}`);
    lines.push(`Web服务: ${finding.webServer || "Apache/Nginx"}`);
    if (finding.databaseType) {
      lines.push(`数据库: ${finding.databaseType}`);
    }
    lines.push("```");
  }
  lines.push("");

  lines.push("### 复现步骤");
  lines.push("");
  if (Array.isArray(finding.steps) && finding.steps.length) {
    finding.steps.forEach((step, i) => {
      lines.push(`**Step ${i + 1}:** ${step}`);
      lines.push("");
    });
  } else {
    lines.push("1. 搭建目标环境");
    lines.push("2. 构造漏洞利用请求");
    lines.push("3. 发送请求并验证结果");
    lines.push("");
  }

  // PoC
  if (finding.poc) {
    lines.push("### PoC (概念验证)");
    lines.push("");
    lines.push("```http");
    lines.push(finding.poc);
    lines.push("```");
    lines.push("");
  }

  // 请求包
  if (finding.requestPacket) {
    lines.push("### 请求数据包");
    lines.push("");
    lines.push("```http");
    lines.push(finding.requestPacket);
    lines.push("```");
    lines.push("");
  }

  // 响应
  if (finding.response) {
    lines.push("### 响应结果");
    lines.push("");
    lines.push("```");
    lines.push(finding.response);
    lines.push("```");
    lines.push("");
  }

  // 漏洞证明（截图说明）
  if (finding.evidence) {
    lines.push("### 漏洞证明");
    lines.push("");
    lines.push(finding.evidence);
    lines.push("");
  }

  // 危害说明
  lines.push("## 危害分析");
  lines.push("");
  lines.push(finding.impact || getDefaultImpact(finding.vulnTypeId, finding.severity));
  lines.push("");

  // 修复建议
  lines.push("## 修复建议");
  lines.push("");
  if (Array.isArray(finding.fixSuggestions) && finding.fixSuggestions.length) {
    finding.fixSuggestions.forEach((fix, i) => {
      lines.push(`${i + 1}. ${fix}`);
    });
  } else {
    const defaultFixes = getDefaultFix(finding.vulnTypeId);
    defaultFixes.forEach((fix, i) => {
      lines.push(`${i + 1}. ${fix}`);
    });
  }
  lines.push("");

  // 参考链接
  if (Array.isArray(finding.references) && finding.references.length) {
    lines.push("## 参考链接");
    lines.push("");
    finding.references.forEach((ref) => {
      lines.push(`- ${ref}`);
    });
    lines.push("");
  }

  // 声明
  lines.push("---");
  lines.push("");
  lines.push("**声明：** 本报告仅用于安全研究目的，漏洞发现过程未对任何生产系统造成影响。所有测试均在本地搭建的环境中完成。");
  lines.push("");

  return lines.join("\n");
}

function buildCveMarkdown(finding) {
  const vulnType = CNVD_VULN_TYPES[finding.vulnTypeId] || CNVD_VULN_TYPES["other"];
  const now = new Date().toISOString().slice(0, 10);

  const lines = [];

  lines.push(`# ${finding.productName || "Unknown Product"} - ${getEnglishVulnType(finding.vulnTypeId)}`);
  lines.push("");
  lines.push("## Vulnerability Information");
  lines.push("");
  lines.push(`- **Product:** ${finding.productName || "Unknown"}`);
  lines.push(`- **Version:** ${finding.affectedVersion || "All versions"}`);
  lines.push(`- **Type:** ${getEnglishVulnType(finding.vulnTypeId)}`);
  lines.push(`- **Severity:** ${(finding.severity || "medium").charAt(0).toUpperCase() + (finding.severity || "medium").slice(1)}`);
  lines.push(`- **Discovered:** ${finding.foundAt || now}`);
  lines.push(`- **Discoverer:** ${finding.discoverer || "Security Researcher"}`);
  if (finding.productUrl) {
    lines.push(`- **Product URL:** ${finding.productUrl}`);
  }
  lines.push("");

  lines.push("## Description");
  lines.push("");
  lines.push(finding.descriptionEn || `${finding.productName || "The product"} version ${finding.affectedVersion || "all versions"} contains a ${getEnglishVulnType(finding.vulnTypeId).toLowerCase()} vulnerability. An attacker can exploit this vulnerability to ${getEnglishImpact(finding.vulnTypeId)}.`);
  lines.push("");

  lines.push("## Proof of Concept");
  lines.push("");
  if (finding.poc) {
    lines.push("```http");
    lines.push(finding.poc);
    lines.push("```");
  } else if (finding.requestPacket) {
    lines.push("```http");
    lines.push(finding.requestPacket);
    lines.push("```");
  }
  lines.push("");

  if (finding.response) {
    lines.push("### Response");
    lines.push("");
    lines.push("```");
    lines.push(finding.response);
    lines.push("```");
    lines.push("");
  }

  lines.push("## Impact");
  lines.push("");
  lines.push(finding.impactEn || `This vulnerability allows an attacker to ${getEnglishImpact(finding.vulnTypeId)}. This may lead to unauthorized access, data leakage, or system compromise.`);
  lines.push("");

  lines.push("## Remediation");
  lines.push("");
  const fixes = getDefaultFixEn(finding.vulnTypeId);
  fixes.forEach((fix, i) => {
    lines.push(`${i + 1}. ${fix}`);
  });
  lines.push("");

  lines.push("## Timeline");
  lines.push("");
  lines.push(`- ${finding.foundAt || now}: Vulnerability discovered`);
  lines.push(`- ${now}: Report submitted`);
  lines.push("");

  lines.push("---");
  lines.push("*This report is for authorized security research purposes only.*");

  return lines.join("\n");
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────

function getImpactDescription(vulnTypeId) {
  const map = {
    "sql-injection": "获取数据库敏感信息，甚至控制数据库服务器",
    "xss": "窃取用户Cookie，劫持用户会话，进行钓鱼攻击",
    "command-injection": "在服务器上执行任意系统命令，获取服务器控制权",
    "file-upload": "上传恶意文件获取服务器webshell，进而控制服务器",
    "file-include": "包含任意文件，读取敏感信息或执行恶意代码",
    "path-traversal": "读取服务器任意文件，获取敏感配置信息",
    "unauthorized": "未经授权访问敏感接口或数据",
    "info-leak": "获取系统敏感信息（数据库配置、API密钥等）",
    "weak-password": "使用默认或弱密码登录系统获取管理权限",
    "deserialization": "通过反序列化执行任意代码，获取服务器权限",
    "ssrf": "探测内网服务、读取云元数据、访问内部接口",
    "rce": "远程执行任意代码，完全控制目标服务器",
    "auth-bypass": "绕过认证机制，未经授权访问系统",
    "idor": "越权访问其他用户的数据或执行操作",
    "logic": "利用业务逻辑缺陷获利或造成平台损失",
    "hardcoded-secret": "利用硬编码凭证获取未授权访问权限"
  };
  return map[vulnTypeId] || "造成安全风险";
}

function getDefaultImpact(vulnTypeId, severity) {
  const sev = CNVD_SEVERITY[severity] || "中危";
  const desc = getImpactDescription(vulnTypeId);
  return `该漏洞等级为**${sev}**。攻击者利用该漏洞可${desc}。由于该产品在国内有大量部署，漏洞影响面较广。`;
}

function getDefaultFix(vulnTypeId) {
  const map = {
    "sql-injection": ["使用参数化查询（PreparedStatement）替代字符串拼接", "对所有用户输入进行严格的类型和长度校验", "使用ORM框架避免直接拼接SQL"],
    "xss": ["对所有输出到页面的用户输入进行HTML实体编码", "使用Content-Security-Policy响应头", "使用模板引擎的自动转义功能"],
    "command-injection": ["避免直接拼接用户输入到系统命令中", "使用白名单限制允许的命令和参数", "使用语言原生API替代系统命令调用"],
    "file-upload": ["在服务端校验文件扩展名（白名单方式）", "校验文件Content-Type和文件头魔数", "限制上传目录的执行权限", "随机重命名上传文件"],
    "unauthorized": ["对所有敏感接口添加身份认证和权限校验", "使用RBAC或ABAC权限模型", "删除不必要的对外接口"],
    "info-leak": ["关闭调试模式（DEBUG=false）", "移除不必要的错误信息输出", "限制敏感接口的访问权限"],
    "weak-password": ["修改默认密码为强密码（大小写字母+数字+特殊字符，不少于12位）", "禁止使用常见弱密码", "增加登录失败锁定机制"],
    "deserialization": ["避免对不可信数据进行反序列化", "使用安全的序列化替代方案（如JSON）", "如必须反序列化，使用白名单过滤允许的类"],
    "ssrf": ["对请求URL进行白名单校验", "禁止访问内网地址（10.x, 172.16.x, 192.168.x, 127.x）", "禁止使用file://等非HTTP协议"],
    "rce": ["升级到最新安全版本", "如使用第三方组件，及时关注安全通告并打补丁", "限制服务器出网权限"],
    "auth-bypass": ["修复认证逻辑缺陷", "对所有路径进行统一的认证拦截", "避免在前端做关键认证判断"],
    "idor": ["在服务端校验请求者对目标资源的访问权限", "使用不可预测的资源标识符", "实施访问控制矩阵"],
    "logic": ["在服务端实现完整的业务规则校验", "不信任客户端传入的金额/数量/状态等参数", "对关键操作添加幂等性保护"],
    "hardcoded-secret": ["将凭证移到环境变量或专用密钥管理服务", "立即轮换已泄露的密钥", "在代码审查中检查硬编码凭证"]
  };
  return map[vulnTypeId] || ["升级到最新版本", "对用户输入进行严格校验", "加强访问控制"];
}

function getEnglishVulnType(vulnTypeId) {
  const map = {
    "sql-injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "command-injection": "OS Command Injection",
    "file-upload": "Arbitrary File Upload",
    "file-include": "File Inclusion",
    "path-traversal": "Path Traversal",
    "unauthorized": "Unauthorized Access",
    "info-leak": "Information Disclosure",
    "weak-password": "Default/Weak Credentials",
    "deserialization": "Insecure Deserialization",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "rce": "Remote Code Execution (RCE)",
    "auth-bypass": "Authentication Bypass",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "logic": "Business Logic Vulnerability",
    "hardcoded-secret": "Hardcoded Credentials"
  };
  return map[vulnTypeId] || "Security Vulnerability";
}

function getEnglishImpact(vulnTypeId) {
  const map = {
    "sql-injection": "extract sensitive data from the database or gain full database control",
    "xss": "steal user session cookies, perform phishing attacks, or hijack user sessions",
    "command-injection": "execute arbitrary operating system commands on the server",
    "file-upload": "upload malicious files and gain remote code execution on the server",
    "unauthorized": "access sensitive functionality or data without authentication",
    "info-leak": "obtain sensitive system information including database credentials and API keys",
    "weak-password": "log in with default credentials and gain administrative access",
    "deserialization": "achieve remote code execution through deserialization of untrusted data",
    "ssrf": "scan internal network services, access cloud metadata, or reach internal APIs",
    "rce": "execute arbitrary code and fully compromise the target server",
    "auth-bypass": "bypass authentication mechanisms and gain unauthorized access",
    "idor": "access or modify data belonging to other users without authorization",
    "logic": "exploit business logic flaws to cause financial loss or gain unauthorized benefits"
  };
  return map[vulnTypeId] || "compromise the security of the application";
}

function getDefaultFixEn(vulnTypeId) {
  const map = {
    "sql-injection": ["Use parameterized queries or prepared statements", "Validate and sanitize all user inputs", "Apply the principle of least privilege for database accounts"],
    "xss": ["Encode all user-controlled output using context-appropriate encoding", "Implement Content-Security-Policy headers", "Use auto-escaping template engines"],
    "command-injection": ["Avoid passing user input to OS commands", "Use allowlists for permitted commands and arguments", "Use language-native APIs instead of shell commands"],
    "file-upload": ["Validate file extensions using a whitelist approach", "Check file content-type and magic bytes", "Store uploaded files outside the web root"],
    "unauthorized": ["Implement proper authentication and authorization checks on all endpoints", "Use role-based access control (RBAC)"],
    "rce": ["Upgrade to the latest patched version", "Apply available security patches immediately", "Restrict outbound network access from the server"],
    "weak-password": ["Change default credentials immediately", "Enforce strong password policies", "Implement account lockout after failed attempts"]
  };
  return map[vulnTypeId] || ["Upgrade to the latest version", "Implement proper input validation", "Apply security patches"];
}
