import { promises as fs } from "node:fs";
import path from "node:path";
import { resolveAuditSkills } from "../config/auditSkills.js";
import { suggestSkillIdsForProject } from "../config/skillRegistry.js";
import { scanDependencies } from "../services/dependencyAudit.js";

const BOUNTY_SKILL_PRIORITY = {
  "access-control": 1.0,
  "query-safety": 0.94,
  ssrf: 0.92,
  "upload-storage": 0.86,
  "command-injection": 0.84,
  "path-traversal": 0.78,
  "dependency-risk": 0.58,
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

const BOUNTY_REPORTABLE_PATTERNS = /(idor|越权|权限|认证|鉴权|auth|permission|owner|role|tenant|admin|bypass|绕过|sql|nosql|注入|injection|ssrf|callback|webhook|redirect|upload|文件上传|path traversal|路径穿越|rce|command|命令|deserialize|反序列化|payment|order|coupon|wallet|billing|business|逻辑)/i;
const LOW_REPORTABILITY_PATTERNS = /(信息泄露|敏感信息|secret|token|api key|apikey|硬编码|env|debug|backup|日志|swagger|openapi|health|metrics|fingerprint|version|banner|missing header|security header)/i;

// 精确规则模式：每个规则包含多个必须同时满足的条件 + 排除逻辑
const PRECISE_RULES = {
  // 访问控制规则
  "access-control": [
    {
      id: "ac-obj-params",
      name: "路由参数对象级访问控制缺失",
      severity: "high",
      minConfidence: 0.82,
      requireA: /(?:(?:req\.)?params\s*\.\s*[a-zA-Z_][a-zA-Z0-9_]*[\s\S]{0,240}\b(?:where|find|findOne|findById|getOne|select|query)\s*\(|\b(?:where|find|findOne|findById|getOne|select|query)\s*\([^)]*(?:req\.)?params\s*\.\s*[a-zA-Z_][a-zA-Z0-9_]*)/i,
      requireB: /./,
      exclude: /\b(authorize|can|permission|policy|guard|checkOwnership|verifyOwner|tenant|isOwner|ownerId\s*===|owner_id\s*===)\s*\(/i,
      pathFilter: /(controller|route|router|handler|service|api|resolver)/i,
      evidence: "路由参数直接进入对象查询，未发现所有权或租户权限校验"
    },
    {
      id: "ac-obj-1",
      name: "对象级访问控制缺失",
      severity: "high",
      minConfidence: 0.75,
      requireA: /\brequest\s*\.\s*(params|query|body)\s*\.\s*[a-zA-Z_][a-zA-Z0-9_]*/,
      requireB: /\b(where|find|findOne|findById|getOne|filter)\s*\(/,
      exclude: /\b(authorize|can|permission|policy|guard|checkOwnership|verifyOwner|tenant|isOwner)\s*\(/i,
      pathFilter: /(controller|route|handler|service|api|resolver)/i,
      evidence: "客户端可控对象标识直接用于数据库查询，未发现权限校验逻辑"
    },
    {
      id: "ac-obj-2",
      name: "用户ID直接用于数据查询",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\b(userId|user_id|uid|authorId|author_id)\s*[=.]/,
      requireB: /\b(where|find|findOne|select|query)\s*\(/,
      exclude: /\b(authorize|can|permission|policy)\s*\(/i,
      pathFilter: /(model|schema|controller|service)/i,
      evidence: "userId 直接作为查询条件，缺少权限校验"
    },
    {
      id: "ac-role-1",
      name: "公共角色权限过宽",
      severity: "critical",
      minConfidence: 0.85,
      requireA: /\b(public|anonymous|guest|visitor)\s*[:=]/i,
      requireB: /\b(create|update|delete|write|admin|manage|upload|execute)\b/i,
      exclude: /\bread\s*[-=]|\breadonly\b/i,
      pathFilter: /(permission|role|acl|rbac|access)/i,
      evidence: "公共/匿名角色被授予写入或管理权限"
    },
    {
      id: "ac-route-1",
      name: "管理路由显式关闭认证",
      severity: "critical",
      minConfidence: 0.9,
      requireA: /auth\s*[:\s]*false|skipAuth|bypassAuth|isPublic\s*[:\s]*true/i,
      requireB: /(admin|manage|setting|plugin|system|user|role)/i,
      pathFilter: /(route|router|app\.use|controller)/i,
      evidence: "管理相关路由显式关闭认证"
    },
    {
      id: "ac-api-1",
      name: "API 无认证保护",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\b@Public\b|@AllowAnonymous\b|@NoAuth\b/i,
      requireB: /@Query|@Param|@Body/i,
      pathFilter: /(controller|resolver|api)/i,
      evidence: "API endpoint 允许匿名访问且接受用户输入"
    }
  ],

  // 初始化配置规则
  "bootstrap-config": [
    {
      id: "bc-init-1",
      name: "首次管理员创建可重复触发",
      severity: "critical",
      minConfidence: 0.85,
      requireA: /\b(bootstrap|seed|init|createFirst|registerInitial)\b.*(Admin|User)/i,
      requireB: /if\s*\([^)]*(!|count|exists|length)/,
      exclude: /process\.env\.NODE_ENV\s*===\s*['"]production['"]|RUN_ONCE/,
      pathFilter: /(seed|migration|init|setup|bootstrap)/i,
      evidence: "管理员初始化逻辑缺少生产环境强制校验或一次性执行保护"
    },
    {
      id: "bc-dev-1",
      name: "开发模式硬编码启用",
      severity: "high",
      minConfidence: 0.85,
      requireA: /\b(DEBUG|DEBUG_MODE|DEV_MODE|DEVELOPMENT)\s*[:=]\s*true/i,
      requireB: /./,
      exclude: /process\.env/i,
      pathFilter: /(config|env|setting)/i,
      evidence: "开发调试模式在代码中硬编码为 true"
    },
    {
      id: "bc-pass-1",
      name: "默认弱密码",
      severity: "critical",
      minConfidence: 0.95,
      requireA: /\b(password|passwd)\s*[:=]\s*['"](?!.*\$\{)[a-zA-Z0-9!@#$%^&*]{0,12}['"]/i,
      requireB: /^(?!.*\$\{).*(admin|root|test|demo|default|123456|password|changeme)/i,
      exclude: /process\.env|generatePassword|hashPassword/,
      pathFilter: /(config|seed|init)/i,
      evidence: "配置中存在默认弱密码"
    }
  ],

  // 上传存储规则
  "upload-storage": [
    {
      id: "us-path-1",
      name: "文件路径存在遍历风险",
      severity: "critical",
      minConfidence: 0.85,
      requireA: /(?:\b(?:upload|move|rename|copy|writeFile|createWriteStream)\s*\([^;\n]*(?:req\.|(?:req\.)?(?:params|query|body)\.|originalname|filename|file\.name)|\bpath\.(?:join|resolve)\s*\([^;\n]*(?:req\.|(?:req\.)?(?:params|query|body)\.|originalname|filename|file\.name))/i,
      requireB: /path|file|fileName|filename|originalname|name|upload|destination/i,
      exclude: /\b(?:normalize|sanitize|safeJoin|basename|allowedPath|validatePath)\b/i,
      pathFilter: /(upload|middleware|controller|service)/i,
      evidence: "文件操作中直接使用用户输入的路径"
    },
    {
      id: "us-type-1",
      name: "文件类型校验缺失",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\b(upload|multer|formidable|busboy)\b/i,
      requireB: /file|mime|type|ext\s*\(/i,
      exclude: /\b(mimeType|fileType|checkType|validateType|allowedTypes|whitelist)\b/i,
      pathFilter: /(upload|middleware|config)/i,
      evidence: "上传处理未发现严格的文件类型校验"
    },
    {
      id: "us-ext-1",
      name: "允许危险文件扩展名",
      severity: "high",
      minConfidence: 0.9,
      requireA: /\.(exe|sh|bat|cmd|ps1|vbs|jar|asp|jsp|php|cgi)\b/i,
      requireB: /\b(upload|move|write|save)\s*\(/i,
      exclude: /\b(allowedExt|permitted|whiteList)\b/i,
      pathFilter: /(upload|middleware)/i,
      evidence: "文件上传允许危险扩展名"
    }
  ],

  // 查询安全规则
  "query-safety": [
    {
      id: "qs-sql-1",
      name: "SQL 原始查询存在注入风险",
      severity: "critical",
      minConfidence: 0.85,
      requireA: /\b(raw|query|execute|run)\s*\(\s*[`'"]/i,
      requireB: /(\$\{|req\.|params\.|body\.|query\.)/,
      exclude: /\b(stmt|prepared|parameterized|bind|escape|sanitize|placeholder)\b/i,
      pathFilter: /(model|repository|dao|service)/i,
      evidence: "原始 SQL 查询直接拼接用户输入"
    },
    {
      id: "qs-sql-2",
      name: "动态排序字段未白名单校验",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\b(orderBy|order|sort)\s*\(\s*req\.|params\.|body\./i,
      requireB: /./,
      exclude: /\b(allowed|whitelist|permit|map|switch)\b/i,
      pathFilter: /(controller|service)/i,
      evidence: "排序字段直接来自用户输入"
    },
    {
      id: "qs-nosql-1",
      name: "NoSQL 注入风险",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\bfind\([^}]*\$where|\$\s*ne\s*|\$gt\s*|\$lt\s*|\$nin\b/i,
      requireB: /req\.|params\.|body\./,
      exclude: /\b(sanitize|validate|escape)\b/i,
      pathFilter: /(model|controller|service)/i,
      evidence: "NoSQL 查询中使用用户输入的操作符"
    }
  ],

  // 敏感信息规则
  "secret-exposure": [
    {
      id: "se-env-1",
      name: "前端暴露敏感环境变量",
      severity: "critical",
      minConfidence: 0.95,
      requireA: /\b(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)[A-Z0-9_]*\b/i,
      requireB: /\b(secret|key|token|password|auth|PRIVATE|API_KEY)\b/i,
      exclude: /\b(URL|ENDPOINT|PUBLIC)\b/,
      pathFilter: /\.env\.|\.env\./i,
      evidence: "前端环境变量中包含敏感信息"
    },
    {
      id: "se-hard-1",
      name: "硬编码密钥",
      severity: "critical",
      minConfidence: 0.9,
      requireA: /(apiKey|apiSecret|clientSecret|privateKey|accessToken)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/i,
      requireB: /./,
      exclude: /process\.env|generate|create.*Key/,
      pathFilter: /(config|constant|setting)/i,
      evidence: "代码中硬编码了 API 密钥"
    },
    {
      id: "se-jwt-1",
      name: "JWT 密钥弱或硬编码",
      severity: "critical",
      minConfidence: 0.95,
      requireA: /\bjwt\s*\(\s*\{[^}]*secret\s*[:=]\s*['"][^'"]+['"]/i,
      requireB: /./,
      exclude: /process\.env|generateSecret/,
      pathFilter: /(config|auth|middleware)/i,
      evidence: "JWT 密钥为硬编码"
    },
    {
      id: "se-aws-1",
      name: "AWS 密钥硬编码",
      severity: "critical",
      minConfidence: 0.95,
      requireA: /\b(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*['"][A-Z0-9]{20,}['"]/i,
      requireB: /./,
      exclude: /process\.env/,
      pathFilter: /(config|env)/i,
      evidence: "AWS 密钥硬编码在代码中"
    }
  ],

  // SSRF 规则
  "ssrf": [
    {
      id: "sr-fetch-1",
      name: "用户可控 URL 存在 SSRF 风险",
      severity: "critical",
      minConfidence: 0.85,
      // Improved: match fetch/axios/request/http.get with user input in URL position
      // Covers: fetch(req.query.url), axios.get(req.body.callback), http.get(url) where url = req.query.x
      requireA: /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|request|got|http\.(?:get|request)|urllib\.request)\s*\(/i,
      requireB: /\b(?:req\.|(?:req\.)?(?:params|query|body)\.|url|link|href|callback|webhook|redirect|target|endpoint)\b/i,
      exclude: /\b(validateUrl|isValidUrl|whitelist|allowedHosts|allowedDomains|isLocal|isPrivateHost|isInternal|blockPrivateIp|urlValidator)\b/i,
      pathFilter: /(controller|service|proxy|route|handler|middleware|api)/i,
      evidence: "允许用户控制 URL 进行网络请求，未发现 URL 白名单或内网地址过滤"
    },
    {
      id: "sr-fetch-2",
      name: "URL 参数直接用于 HTTP 请求",
      severity: "critical",
      minConfidence: 0.88,
      // Catches the specific pattern: fetch(variable) where variable comes from req
      requireA: /(?:(?:const|let|var)\s+\w+\s*=\s*(?:req\.|(?:req\.)?(?:params|query|body)\.)[\w.[\]]+[\s\S]{0,100}\b(?:fetch|axios|request|got|http)\s*\()|(?:\b(?:fetch|axios|request|got)\s*\(\s*(?:req\.|(?:req\.)?(?:params|query|body)\.))/i,
      requireB: /./,
      exclude: /\b(validateUrl|whitelist|allowedHosts|isPrivate|blockInternal)\b/i,
      pathFilter: /(controller|service|proxy|route|handler|api)/i,
      evidence: "URL 直接从请求参数获取后用于发起 HTTP 请求"
    }
  ],

  // 命令注入规则
  "command-injection": [
    {
      id: "ci-exec-1",
      name: "命令注入风险",
      severity: "critical",
      minConfidence: 0.9,
      requireA: /\b(exec|spawn|execSync|system|popen|execFile)\s*\([^)]*(req\.|params\.|body\.|argv)/i,
      requireB: /./,
      exclude: /\b(escape|sanitize|arg|command)\b/i,
      pathFilter: /(controller|service)/i,
      evidence: "用户输入直接用于命令执行"
    },
    {
      id: "ci-spawn-1",
      name: "child_process 参数注入",
      severity: "critical",
      minConfidence: 0.9,
      requireA: /\bspawn\([^)]*shell\s*:\s*true/i,
      requireB: /req\.|params\.|body\./,
      pathFilter: /(service)/i,
      evidence: "使用 shell 执行且参数来自用户输入"
    }
  ],

  // 路径穿越规则
  "path-traversal": [
    {
      id: "pt-path-1",
      name: "路径穿越风险",
      severity: "critical",
      minConfidence: 0.85,
      requireA: /\b(readFile|readFileSync|createReadStream|open)\s*\([^)]*\+.*req\.|params\.|body\./i,
      requireB: /path|file/,
      exclude: /\b(path\.join|path\.resolve|normalize|baseDir|rootPath)\b/i,
      pathFilter: /(controller|service|middleware)/i,
      evidence: "文件读取路径中可能存在路径穿越"
    }
  ],

  // XSS 规则
  "xss": [
    {
      id: "xs-ref-1",
      name: "反射型 XSS 风险",
      severity: "high",
      minConfidence: 0.8,
      // Fixed: requireA now requires res.send/render with req input in the SAME expression
      // OR innerHTML/outerHTML assigned from req input (not just co-existing in same file)
      requireA: /(?:\bres\.(?:send|write|end)\s*\([^;\n]{0,120}(?:req\.|(?:req\.)?(?:params|query|body)\.)|(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,80}(?:req\.|(?:req\.)?(?:params|query|body)\.))/i,
      requireB: /./,
      exclude: /\b(escape|encode|sanitize|xss|escapeHtml|textContent|DOMPurify|createTextNode|encodeURI)\b/i,
      pathFilter: /(controller|route|view|handler|api)/i,
      evidence: "用户输入未经过滤直接输出到响应体"
    },
    {
      id: "xs-render-1",
      name: "模板渲染 XSS 风险",
      severity: "high",
      minConfidence: 0.8,
      requireA: /\bres\.render\s*\([^)]*,\s*\{[^}]*(?:req\.|(?:req\.)?(?:params|query|body)\.)/i,
      requireB: /./,
      exclude: /\b(escape|encode|sanitize|xss|escapeHtml)\b/i,
      pathFilter: /(controller|route|view|handler)/i,
      evidence: "模板渲染时直接传入用户输入变量"
    },
    {
      id: "xs-vue-1",
      name: "Vue v-html 可能存在 XSS",
      severity: "high",
      minConfidence: 0.85,
      requireA: /v-html\s*=/i,
      requireB: /req\.|params\.|body\./,
      exclude: /\b(sanitize|DOMPurify|escape)\b/,
      pathFilter: /\.vue|\.jsx|\.tsx/i,
      evidence: "使用 v-html 绑定用户输入"
    }
  ],

  // 不安全的反序列化
  "deserialization": [
    {
      id: "ds-eval-1",
      name: "Eval 不安全使用",
      severity: "critical",
      minConfidence: 0.95,
      // Fixed: requireA must match eval() with req input IN the same call expression
      // Old regex had alternation that matched params./body. independently
      requireA: /\beval\s*\(\s*(?:req\.|(?:req\.)?(?:params|query|body)\.)/i,
      requireB: /./,
      pathFilter: /(controller|route|service|handler|api)/i,
      evidence: "eval() 中直接使用用户输入"
    },
    {
      id: "ds-parse-1",
      name: "不安全的反序列化",
      severity: "critical",
      minConfidence: 0.9,
      // Fixed: require that parse/load and req input appear in the same statement (within 80 chars)
      requireA: /\b(?:JSON\.parse|yaml\.load|pickle\.load|unserialize)\s*\([^;\n]{0,80}(?:req\.|(?:req\.)?(?:params|query|body)\.)/i,
      requireB: /./,
      exclude: /\b(safe|loadSilent|safeLoad|JSON\.parse\(\s*JSON\.stringify)\b/i,
      pathFilter: /(controller|service|middleware|handler|api)/i,
      evidence: "反序列化用户输入的数据"
    }
  ],

  // 护网补充：暴露面排查
  "exposed-surface": [
    {
      id: "hw-exp-1",
      name: "管理或调试入口暴露",
      severity: "medium",
      minConfidence: 0.7,
      requireA: /(swagger|openapi|actuator|admin|debug|health|metrics|grafana|kibana|jenkins)/i,
      requireB: /(route|router|endpoint|path|url|proxy|public|allow|permit|anonymous|noauth|auth\s*[:=]\s*false)/i,
      exclude: /(test|mock|example|fixture)/i,
      pathFilter: /(route|router|controller|config|gateway|nginx|yaml|yml|json)/i,
      evidence: "管理、调试或接口文档入口可能公开暴露"
    }
  ],

  // 护网补充：弱口令与默认口令
  "weak-credential": [
    {
      id: "hw-cred-1",
      name: "默认账号或弱口令",
      severity: "high",
      minConfidence: 0.82,
      requireA: /(admin|root|demo|test|default|guest)/i,
      requireB: /(password|passwd|pwd|secret)\s*[:=]\s*['\"]?(admin|root|demo|test|default|guest|123456|password|changeme)/i,
      exclude: /(example|sample|placeholder|documentation only)/i,
      pathFilter: /(config|seed|init|setup|env|credential|password|readme|md|yaml|yml|json)/i,
      evidence: "配置、初始化或文档中存在默认账号/弱口令迹象"
    }
  ],

  // 护网补充：云配置误露
  "cloud-misconfig": [
    {
      id: "hw-cloud-1",
      name: "对象存储公开权限过宽",
      severity: "high",
      minConfidence: 0.78,
      requireA: /(s3|oss|cos|bucket|storage|cdn|acl|policy)/i,
      requireB: /(public-read|public-write|allUsers|anonymous|Allow|Principal\s*:\s*['\"]?\*|readwrite|read-write)/i,
      exclude: /(deny|private|example|sample)/i,
      pathFilter: /(terraform|tf|yaml|yml|json|config|policy|cloud|storage)/i,
      evidence: "云存储或访问策略可能允许公开读写"
    }
  ],

  // 护网补充：CI/CD 暴露面
  "cicd-exposure": [
    {
      id: "hw-cicd-1",
      name: "CI/CD 密钥或制品暴露",
      severity: "high",
      minConfidence: 0.76,
      requireA: /(jenkins|github actions|gitlab-ci|runner|artifact|deploy|pipeline|workflow)/i,
      requireB: /(token|secret|password|api_key|private_key|env|artifact|public|upload)/i,
      exclude: /(secrets\.[A-Z0-9_]+|process\.env|example|sample)/i,
      pathFilter: /(\.github|gitlab-ci|jenkins|workflow|pipeline|deploy|ci|cd|yaml|yml|json)/i,
      evidence: "流水线或发布配置中可能存在密钥、制品或权限暴露"
    }
  ],

  // 护网补充：调试与备份暴露
  "debug-backup": [
    {
      id: "hw-debug-1",
      name: "调试日志或备份文件暴露",
      severity: "medium",
      minConfidence: 0.72,
      requireA: /(debug|trace|log|logs|backup|bak|old|tmp|dump|archive|\.sql|\.zip|\.tar|\.gz)/i,
      requireB: /(public|static|serve|download|sendFile|express\.static|alias|root|location|assets)/i,
      exclude: /(test|fixture|example|sample)/i,
      pathFilter: /(route|router|controller|nginx|apache|config|static|public|download|file)/i,
      evidence: "调试、日志、备份或历史文件可能通过公开路径暴露"
    }
  ]
};

// 规则匹配函数
function matchPreciseRule(content, rule, relativePath = "") {
  // Path filters must match the file path, not arbitrary text inside the file.
  if (rule.pathFilter && !rule.pathFilter.test(relativePath)) {
    return false;
  }

  // 检查 A 条件
  if (!rule.requireA.test(content)) {
    return false;
  }

  // 检查 B 条件
  if (!rule.requireB.test(content)) {
    return false;
  }

  // 排除条件
  if (rule.exclude && rule.exclude.test(content)) {
    return false;
  }

  return true;
}

function createFinding(finding) {
  const bountyPriority = estimateBountyPriority(finding);
  return {
    source: "rule",
    bountyPriority,
    reportabilityScore: bountyPriority,
    ...finding
  };
}

function prioritizeFindings(findings) {
  const deduped = [];
  const seen = new Set();
  for (const finding of findings) {
    const key = `${finding.skillId || "any"}::${finding.title}::${finding.location}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(finding);
  }

  // 涓ラ噸鎬т紭鍏堢骇锛歝ritical > high > medium > low
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  return deduped
    .map((finding) => ({
      ...finding,
      bountyPriority: estimateBountyPriority(finding),
      reportabilityScore: estimateReportabilityScore(finding)
    }))
    .filter((finding) => finding.confidence >= minConfidenceForBounty(finding))
    .sort((a, b) => {
      const bountyDiff = (b.reportabilityScore || 0) - (a.reportabilityScore || 0);
      if (Math.abs(bountyDiff) > 1e-6) return bountyDiff;
      const sevDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;
      const signalDiff = (b.signalScore || 0) - (a.signalScore || 0);
      if (signalDiff !== 0) return signalDiff;
      return b.confidence - a.confidence;
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

  return clamp(score, 0.05, 1);
}

function estimateReportabilityScore(finding) {
  const confidence = Number(finding?.confidence || 0);
  const signal = Number(finding?.signalScore || 0);
  const severityBoost = { critical: 0.18, high: 0.12, medium: 0.05, low: 0 };
  return clamp(
    estimateBountyPriority(finding)
      + confidence * 0.18
      + signal * 0.1
      + (severityBoost[String(finding?.severity || "").toLowerCase()] || 0),
    0,
    1
  );
}

function minConfidenceForBounty(finding) {
  const skillId = finding?.skillId || "";
  if (skillId === "secret-exposure") return 0.88;
  if (["exposed-surface", "debug-backup", "cloud-misconfig", "cicd-exposure", "weak-credential"].includes(skillId)) return 0.78;
  if (estimateBountyPriority(finding) >= 0.75) return 0.52;
  return 0.6;
}

function buildProjectSkillProfile(project, baseProfile) {
  const derivedIds = suggestSkillIdsForProject(project, baseProfile.map((skill) => skill.id));
  return resolveAuditSkills(derivedIds);
}

export class AuditAnalystAgent {
  constructor({ llmReviewer }) {
    this.llmReviewer = llmReviewer;
  }

  async run({ projects, selectedSkillIds, llmConfig, onProgress }) {
    const reviewProfile = resolveAuditSkills(selectedSkillIds);
    const skillUsage = new Map(reviewProfile.map((skill) => [skill.id, skill]));
    const results = [];

    for (const [index, project] of projects.entries()) {
      onProgress?.({
        stage: "heuristic",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        label: `正在分析规则层：${project.name}`
      });

      const projectProfile = buildProjectSkillProfile(project, reviewProfile);
      for (const skill of projectProfile) {
        skillUsage.set(skill.id, skill);
      }

      const heuristicFindings = await buildHeuristicFindings(project, projectProfile);
      const llmReview = this.llmReviewer
        ? await this.llmReviewer.reviewProject({
            project,
            selectedSkills: projectProfile,
            heuristicFindings,
            llmConfig,
            onProgress: (detail) =>
              onProgress?.({
                stage: "llm-review",
                projectId: project.id,
                projectName: project.name,
                projectIndex: index + 1,
                totalProjects: projects.length,
                ...detail
              })
          })
        : {
            status: "skipped",
            called: false,
            skipReason: "reviewer-unavailable",
            summary: "未配置 LLM 复核器。",
            findings: [],
            warnings: []
          };

      const mergedFindings = prioritizeFindings([
        ...heuristicFindings,
        ...(Array.isArray(llmReview.findings) ? llmReview.findings : [])
      ]);

      results.push({
        projectId: project.id,
        projectName: project.name,
        repoUrl: project.repoUrl,
        localPath: project.localPath || "",
        reviewProfile,
        projectProfile,
        heuristicFindings,
        llmReview,
        findings: mergedFindings
      });

      onProgress?.({
        stage: "project-complete",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        heuristicCount: heuristicFindings.length,
        llmCount: llmReview?.findings?.length || 0,
        label: `已完成：${project.name}`
      });
    }

    return {
      reviewedAt: new Date().toISOString(),
      policy: "defensive-only",
      skillsUsed: Array.from(skillUsage.values()).map((skill) => ({ id: skill.id, name: skill.name })),
      findingsCount: results.reduce((sum, item) => sum + item.findings.length, 0),
      heuristicFindingsCount: results.reduce((sum, item) => sum + item.heuristicFindings.length, 0),
      llmFindingsCount: results.reduce((sum, item) => sum + (item.llmReview?.findings?.length || 0), 0),
      llmCallCount: results.reduce((sum, item) => sum + (item.llmReview?.called ? 1 : 0), 0),
      llmSkippedCount: results.reduce((sum, item) => sum + (item.llmReview?.called ? 0 : 1), 0),
      projects: results
    };
  }
}

async function buildHeuristicFindings(project, reviewProfile) {
  const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
  const files = await collectFiles(sourceRoot);
  const findings = [];
  const enabledSkills = new Set(reviewProfile.map((skill) => skill.id));

  // 收集所有文件内容用于跨文件分析
  const fileContents = new Map();
  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    const relative = path.relative(sourceRoot, file).replaceAll("\\", "/");
    fileContents.set(relative, content);
  }

  // 应用精确规则
  for (const [relative, content] of fileContents) {
    const loweredPath = relative.toLowerCase();

    // 跳过测试文件和文档
    if (loweredPath.includes("/test/") || loweredPath.includes("/spec/") || loweredPath.includes(".md") || loweredPath.includes("readme")) {
      continue;
    }

    for (const [skillId, rules] of Object.entries(PRECISE_RULES)) {
      if (!enabledSkills.has(skillId)) continue;

      for (const rule of rules) {
        if (matchPreciseRule(content, rule, relative)) {
          findings.push(createFinding({
            skillId,
            title: rule.name,
            severity: rule.severity,
            confidence: rule.minConfidence,
            location: relative,
            evidence: rule.evidence,
            impact: `该代码存在 ${rule.name} 风险，需要重点人工复核。`,
            remediation: `建议添加 ${rule.name} 的安全防护措施。`,
            safeValidation: "建议在本地代码审查中验证此问题是否真实存在。"
          }));
        }
      }
    }
  }

  if (enabledSkills.has("dependency-risk")) {
    const dependencyFindings = await scanDependencies(sourceRoot);
    findings.push(
      ...dependencyFindings.map((finding) =>
        createFinding({
          ...finding,
          confidence: Number(finding.confidence || 0.8),
          safeValidation: finding.safeValidation || "Treat dependency hits as leads until a reachable code path and vulnerable version are confirmed."
        })
      )
    );
  }

  // ═══ Semgrep 集成（如果可用）═══
  try {
    const { execSync } = await import("node:child_process");
    const semgrepBin = execSync("which semgrep 2>/dev/null", { encoding: "utf8" }).trim();
    if (semgrepBin) {
      const semgrepOutput = path.join(sourceRoot, ".semgrep-results.json");
      try {
        execSync(
          `semgrep --config=p/security-audit ${sourceRoot} --json -o ${semgrepOutput} --quiet --timeout 60 2>/dev/null`,
          { timeout: 120_000 }
        );
        const semgrepData = JSON.parse(await fs.readFile(semgrepOutput, "utf8"));
        const semgrepResults = semgrepData?.results || [];
        for (const item of semgrepResults.slice(0, 20)) {
          const severity = item?.extra?.severity === "ERROR" ? "high" : "medium";
          const ruleId = item?.check_id || "semgrep-rule";
          const message = item?.extra?.message || "";
          const filePath = path.relative(sourceRoot, item?.path || "").replaceAll("\\", "/");
          // Map semgrep rule to our skill IDs
          let skillId = "query-safety";
          if (/sql|inject/i.test(ruleId)) skillId = "query-safety";
          else if (/xss|html/i.test(ruleId)) skillId = "xss";
          else if (/ssrf|url|fetch/i.test(ruleId)) skillId = "ssrf";
          else if (/path|traversal|file/i.test(ruleId)) skillId = "path-traversal";
          else if (/command|exec|shell/i.test(ruleId)) skillId = "command-injection";
          else if (/secret|key|token|password/i.test(ruleId)) skillId = "secret-exposure";
          else if (/deserial|eval|yaml/i.test(ruleId)) skillId = "deserialization";

          if (enabledSkills.has(skillId)) {
            findings.push(createFinding({
              skillId,
              title: `[Semgrep] ${ruleId.split(".").pop()}`,
              severity,
              confidence: severity === "high" ? 0.82 : 0.7,
              location: filePath,
              evidence: message.slice(0, 300),
              impact: `Semgrep rule ${ruleId} flagged potential ${skillId} issue.`,
              remediation: item?.extra?.fix || "Review and fix the flagged code pattern.",
              safeValidation: "Semgrep finding — verify exploitability manually before reporting."
            }));
          }
        }
        // Clean up
        await fs.unlink(semgrepOutput).catch(() => {});
      } catch {
        // Semgrep run failed — non-fatal
      }
    }
  } catch {
    // semgrep not installed — skip silently
  }

  // 按置信度排序并限制结果数
  return prioritizeFindings(findings).slice(0, 15);
}

async function collectFiles(root) {
  try {
    const entries = await fs.readdir(root, { withFileTypes: true });
    const output = [];
    for (const entry of entries) {
      const target = path.join(root, entry.name);
      if (entry.isDirectory()) output.push(...(await collectFiles(target)));
      else output.push(target);
    }
    return output;
  } catch {
    return [];
  }
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, Number.isFinite(Number(value)) ? Number(value) : min));
}

