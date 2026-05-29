import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Known dangerous/deprecated/EOL packages and their risks.
 * This is a curated list based on real CVEs and known security issues.
 */
const DANGEROUS_PACKAGES = {
  // ===== Node.js =====
  "vm2": {
    severity: "critical",
    reason: "vm2 已 EOL (2023年停止维护)，存在多个沙箱逃逸 CVE (CVE-2023-37466 等)，可导致 RCE。",
    remediation: "迁移到 isolated-vm 或使用 Web Workers / 子进程隔离。"
  },
  "node-serialize": {
    severity: "critical",
    reason: "node-serialize 的 unserialize 函数可以执行任意代码，存在反序列化 RCE 漏洞。",
    remediation: "改用 JSON.parse 或 protobuf 等安全序列化方案。"
  },
  "serialize-javascript": {
    severity: "medium",
    reason: "旧版本存在 XSS 漏洞 (CVE-2020-7660)，需确认版本是否已修复。",
    remediation: "升级到最新版本 (>=3.1.0)。"
  },
  "merge": {
    severity: "high",
    reason: "旧版本存在原型污染漏洞 (CVE-2020-28499)。",
    remediation: "升级到 >=2.1.1 或改用 lodash.merge / Object.assign。"
  },
  "lodash": {
    severity: "medium",
    reason: "旧版本 (<4.17.21) 存在原型污染漏洞 (CVE-2021-23337, CVE-2020-28500)。",
    remediation: "升级到 >=4.17.21，或按需引入 lodash-es 子模块。",
    minSafeVersion: "4.17.21"
  },
  "express-fileupload": {
    severity: "high",
    reason: "旧版本存在原型污染和路径遍历漏洞。",
    remediation: "升级到最新版并启用 createParentPath: false 和路径检查。"
  },
  "js-yaml": {
    severity: "high",
    reason: "旧版本 (<3.13.1) 的 yaml.load 默认不安全，可执行任意代码。",
    remediation: "升级到 >=3.13.1 并始终使用 yaml.load(content, { schema: yaml.SAFE_SCHEMA })。",
    minSafeVersion: "3.13.1"
  },
  "mathjs": {
    severity: "medium",
    reason: "旧版本存在 eval 注入漏洞。",
    remediation: "升级到最新版本。"
  },
  "minimist": {
    severity: "medium",
    reason: "旧版本 (<1.2.6) 存在原型污染漏洞 (CVE-2021-44906)。",
    remediation: "升级到 >=1.2.6。",
    minSafeVersion: "1.2.6"
  },
  "shelljs": {
    severity: "medium",
    reason: "如果用户输入传入 shell 命令拼接，存在命令注入风险。",
    remediation: "避免将用户输入直接传入 shelljs 命令；使用 child_process.execFile 做安全执行。"
  },
  "ejs": {
    severity: "high",
    reason: "旧版本 (<3.1.7) 存在服务端模板注入 (SSTI) 可导致 RCE。",
    remediation: "升级到 >=3.1.7，并避免将用户输入作为模板内容。",
    minSafeVersion: "3.1.7"
  },
  "handlebars": {
    severity: "high",
    reason: "旧版本 (<4.7.7) 存在原型污染 RCE (CVE-2021-23369)。",
    remediation: "升级到 >=4.7.7。",
    minSafeVersion: "4.7.7"
  },
  "marked": {
    severity: "medium",
    reason: "旧版本存在多个 XSS 和 ReDoS 漏洞。",
    remediation: "升级到最新版本并启用 sanitize 选项或配合 DOMPurify 使用。"
  },
  "mongoose": {
    severity: "medium",
    reason: "旧版本 (<5.13.15 / <6.0) 存在查询注入和原型污染。",
    remediation: "升级到最新 6.x 版本。"
  },
  "tar": {
    severity: "high",
    reason: "旧版本 (<6.1.9) 存在路径遍历漏洞 (CVE-2021-37701 等)。",
    remediation: "升级到 >=6.1.9。",
    minSafeVersion: "6.1.9"
  },
  "jsonwebtoken": {
    severity: "medium",
    reason: "旧版本 (<9.0.0) 对 algorithm 校验不严格，可被降级攻击。",
    remediation: "升级到 >=9.0.0 并显式指定 algorithms 参数。",
    minSafeVersion: "9.0.0"
  },
  "passport-saml": {
    severity: "critical",
    reason: "旧版本存在认证绕过漏洞 (CVE-2022-39299)。",
    remediation: "升级到最新版本。"
  },
  "xmldom": {
    severity: "high",
    reason: "已废弃，存在多个 XML 解析漏洞。",
    remediation: "迁移到 @xmldom/xmldom (fork 维护版)。"
  },
  "request": {
    severity: "low",
    reason: "已废弃 (2020年停止维护)，不再接收安全补丁。",
    remediation: "迁移到 node-fetch、axios 或 undici。"
  },

  // ===== Python =====
  "pyyaml": {
    severity: "high",
    reason: "如果使用 yaml.load() 而非 yaml.safe_load()，可执行任意代码。",
    remediation: "始终使用 yaml.safe_load() 或 yaml.load(data, Loader=yaml.SafeLoader)。"
  },
  "django": {
    severity: "medium",
    reason: "旧版本存在多个 SQL 注入、XSS 和认证绕过漏洞。",
    remediation: "升级到最新 LTS 版本。"
  },
  "flask": {
    severity: "low",
    reason: "旧版本 (<2.2.5) 存在安全问题。",
    remediation: "升级到最新版本。"
  },
  "jinja2": {
    severity: "high",
    reason: "旧版本 (<2.11.3) 的 SandboxedEnvironment 存在沙箱逃逸。",
    remediation: "升级到最新版本并启用自动转义。"
  },
  "pillow": {
    severity: "medium",
    reason: "旧版本存在多个图像解析缓冲区溢出 CVE。",
    remediation: "保持最新版本。"
  },
  "paramiko": {
    severity: "high",
    reason: "旧版本存在认证绕过 (CVE-2023-48795 Terrapin Attack)。",
    remediation: "升级到 >=3.4.0。"
  },
  "cryptography": {
    severity: "medium",
    reason: "旧版本存在多个内存安全问题。",
    remediation: "保持最新版本。"
  }
};

/**
 * Deprecated/dangerous API patterns found in code that relate to dependencies.
 */
const DEPRECATED_API_PATTERNS = [
  {
    regex: /\bcrypto\.createCipher\s*\(/,
    package: "crypto (Node.js built-in)",
    severity: "high",
    reason: "createCipher 已废弃，不使用 IV，容易受到确定性加密攻击。",
    remediation: "使用 crypto.createCipheriv() 并提供随机 IV。"
  },
  {
    regex: /\bnew\s+Buffer\s*\(/,
    package: "Buffer (Node.js built-in)",
    severity: "medium",
    reason: "new Buffer() 已废弃，存在未初始化内存泄露风险。",
    remediation: "使用 Buffer.from()、Buffer.alloc() 或 Buffer.allocUnsafe()。"
  },
  {
    regex: /\burl\.parse\s*\(/,
    package: "url (Node.js built-in)",
    severity: "low",
    reason: "url.parse() 已废弃，解析行为与浏览器不一致，可被利用绕过安全检查。",
    remediation: "使用 new URL() 构造函数。"
  },
  {
    regex: /\bchild_process\.(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^)]*\+\s*)/,
    package: "child_process (Node.js built-in)",
    severity: "critical",
    reason: "exec/execSync 使用 shell 执行，拼接用户输入会导致命令注入 (RCE)。",
    remediation: "使用 child_process.execFile() 或 spawn() 并传入参数数组。"
  }
];

/**
 * Scan project dependencies for known dangerous packages and deprecated APIs.
 */
export async function scanDependencies(sourceRoot) {
  const findings = [];

  // Scan package.json (Node.js)
  await scanNodePackages(sourceRoot, findings);

  // Scan requirements.txt / Pipfile (Python)
  await scanPythonPackages(sourceRoot, findings);

  // Scan for deprecated API usage in source files
  await scanDeprecatedAPIs(sourceRoot, findings);

  return findings;
}

async function scanNodePackages(sourceRoot, findings) {
  const packageJsonPath = path.join(sourceRoot, "package.json");
  try {
    const content = await fs.readFile(packageJsonPath, "utf8");
    const pkg = JSON.parse(content);
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {})
    };

    for (const [name, version] of Object.entries(allDeps)) {
      const risk = DANGEROUS_PACKAGES[name];
      if (risk) {
        // If there's a min safe version, check if current version might be safe
        if (risk.minSafeVersion && version) {
          const cleanVersion = version.replace(/^[\^~>=<]+/, "");
          if (isVersionSafe(cleanVersion, risk.minSafeVersion)) continue;
        }

        findings.push({
          source: "dependency-scan",
          skillId: "dependency-risk",
          title: `危险依赖：${name} (${risk.severity})`,
          severity: risk.severity,
          confidence: 0.85,
          location: "package.json",
          impact: risk.reason,
          evidence: `package.json 中声明了 "${name}": "${version}"`,
          remediation: risk.remediation,
          safeValidation: `检查 ${name} 是否可以升级或替换。`
        });
      }
    }
  } catch {
    // No package.json or parse error, skip
  }
}

async function scanPythonPackages(sourceRoot, findings) {
  const requirementsPaths = [
    path.join(sourceRoot, "requirements.txt"),
    path.join(sourceRoot, "requirements", "base.txt"),
    path.join(sourceRoot, "requirements", "production.txt")
  ];

  for (const reqPath of requirementsPaths) {
    try {
      const content = await fs.readFile(reqPath, "utf8");
      const lines = content.split("\n");

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;

        const match = trimmed.match(/^([a-zA-Z0-9_-]+)/);
        if (!match) continue;

        const pkgName = match[1].toLowerCase();
        const risk = DANGEROUS_PACKAGES[pkgName];
        if (risk) {
          const relPath = path.relative(sourceRoot, reqPath).replaceAll("\\", "/");
          findings.push({
            source: "dependency-scan",
            skillId: "dependency-risk",
            title: `危险依赖：${pkgName} (${risk.severity})`,
            severity: risk.severity,
            confidence: 0.83,
            location: relPath,
            impact: risk.reason,
            evidence: `${relPath} 中声明了 "${trimmed}"`,
            remediation: risk.remediation,
            safeValidation: `检查 ${pkgName} 是否可以升级或替换。`
          });
        }
      }
    } catch {
      // File doesn't exist, skip
    }
  }

  // Also check Pipfile
  try {
    const pipfilePath = path.join(sourceRoot, "Pipfile");
    const content = await fs.readFile(pipfilePath, "utf8");
    const lines = content.split("\n");
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9_-]+)\s*=/);
      if (!match) continue;
      const pkgName = match[1].toLowerCase();
      const risk = DANGEROUS_PACKAGES[pkgName];
      if (risk) {
        findings.push({
          source: "dependency-scan",
          skillId: "dependency-risk",
          title: `危险依赖：${pkgName} (${risk.severity})`,
          severity: risk.severity,
          confidence: 0.83,
          location: "Pipfile",
          impact: risk.reason,
          evidence: `Pipfile 中声明了 ${pkgName}`,
          remediation: risk.remediation,
          safeValidation: `检查 ${pkgName} 是否可以升级或替换。`
        });
      }
    }
  } catch {
    // No Pipfile, skip
  }
}

async function scanDeprecatedAPIs(sourceRoot, findings) {
  // Quick scan of top-level source files for deprecated API usage
  const scanDirs = ["src", "lib", "app", "routes", "controllers", "server", "api", "."];
  const scannedFiles = new Set();

  for (const dir of scanDirs) {
    const dirPath = path.join(sourceRoot, dir);
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isFile()) continue;
        if (!/\.(js|ts|mjs|cjs)$/.test(entry.name)) continue;

        const filePath = path.join(dirPath, entry.name);
        if (scannedFiles.has(filePath)) continue;
        scannedFiles.add(filePath);

        try {
          const content = await fs.readFile(filePath, "utf8");
          const relative = path.relative(sourceRoot, filePath).replaceAll("\\", "/");

          for (const pattern of DEPRECATED_API_PATTERNS) {
            if (pattern.regex.test(content)) {
              findings.push({
                source: "dependency-scan",
                skillId: "dependency-risk",
                title: `废弃/危险 API：${pattern.package}`,
                severity: pattern.severity,
                confidence: 0.8,
                location: relative,
                impact: pattern.reason,
                evidence: `在 ${relative} 中发现了废弃 API 的使用。`,
                remediation: pattern.remediation,
                safeValidation: `确认该 API 调用是否可以安全替换。`
              });
              break; // One finding per file per pattern category
            }
          }
        } catch {
          // Can't read file, skip
        }
      }
    } catch {
      // Directory doesn't exist, skip
    }
  }
}

/**
 * Simple semver comparison: returns true if current >= minSafe
 */
function isVersionSafe(current, minSafe) {
  try {
    const currentParts = current.split(".").map(Number);
    const safeParts = minSafe.split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      const c = currentParts[i] || 0;
      const s = safeParts[i] || 0;
      if (c > s) return true;
      if (c < s) return false;
    }
    return true; // equal
  } catch {
    return false; // can't parse, assume unsafe
  }
}
