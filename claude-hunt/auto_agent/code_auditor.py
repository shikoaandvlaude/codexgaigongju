#!/usr/bin/env python3
"""
Code Auditor — 白盒代码审计模块
移植自 Shannon 框架的 5 类并行漏洞分析能力

功能：
1. 5 类并行代码分析 (Injection/XSS/Auth/Authz/SSRF)
2. 数据流追踪 (Source → Sanitizer → Sink)
3. LLM 辅助代码审计（DeepSeek/OpenAI）
4. 结构化漏洞队列输出
5. 与黑盒 Fuzz 结果交叉验证

用法：
    auditor = CodeAuditor(repo_path="/path/to/source", llm_config={...})
    results = await auditor.run_full_audit()
    # 或单类审计
    injection_results = await auditor.audit_injection()
"""

import asyncio
import json
import os
import re
import glob
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class DataFlowPath:
    """数据流路径：从 Source 到 Sink"""
    source_param: str = ""
    source_file: str = ""
    source_line: int = 0
    # 路径上的跳转
    hops: List[str] = field(default_factory=list)
    # 遇到的 Sanitizer
    sanitizers: List[Dict[str, str]] = field(default_factory=list)
    # Sink 信息
    sink_call: str = ""
    sink_file: str = ""
    sink_line: int = 0
    sink_type: str = ""  # SQL-val/SQL-ident/CMD-argument/FILE-path/TEMPLATE-expression
    # 是否有 concat 在 sanitizer 之后
    post_sanitize_concat: bool = False



@dataclass
class CodeVulnFinding:
    """代码审计漏洞发现"""
    id: str = ""
    vuln_type: str = ""  # injection/xss/auth/authz/ssrf
    subtype: str = ""  # sqli/cmdi/ssti/lfi/reflected/stored/dom/idor/...
    title: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    # 数据流
    data_flow: Optional[DataFlowPath] = None
    # 分析结论
    verdict: str = ""  # vulnerable/safe
    mismatch_reason: str = ""
    witness_payload: str = ""
    # 是否可外部利用
    externally_exploitable: bool = False
    # 备注
    notes: str = ""


@dataclass
class AuditResult:
    """单类审计结果"""
    vuln_type: str = ""
    findings: List[CodeVulnFinding] = field(default_factory=list)
    safe_vectors: List[Dict[str, str]] = field(default_factory=list)
    duration_seconds: float = 0
    files_analyzed: int = 0
    error: str = ""


# ═══════════════════════════════════════════════════════════════
# 代码扫描引擎（静态分析 — 无需 LLM）
# ═══════════════════════════════════════════════════════════════

class StaticScanner:
    """
    轻量级静态代码扫描
    基于正则匹配发现潜在 Source/Sink 对
    """

    # Source 模式 — 用户输入入口
    SOURCE_PATTERNS = {
        "python": [
            r'request\.(GET|POST|args|form|json|data|files|cookies|headers)',
            r'request\.get\(["\'](\w+)',
            r'input\(\s*["\']',
            r'sys\.argv',
            r'os\.environ',
        ],
        "javascript": [
            r'req\.(body|query|params|headers|cookies)\[?["\']?(\w+)',
            r'req\.param\(["\'](\w+)',
            r'document\.(location|URL|referrer|cookie)',
            r'window\.location',
            r'URLSearchParams',
        ],
        "php": [
            r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\[',
            r'file_get_contents\(["\']php://input',
            r'\$argv',
        ],
        "java": [
            r'request\.getParameter\(["\'](\w+)',
            r'request\.getAttribute',
            r'@RequestParam',
            r'@PathVariable',
            r'@RequestBody',
        ],
    }

    # Sink 模式 — 危险函数
    SINK_PATTERNS = {
        "injection": [
            (r'execute\s*\(.*[+%]', "SQL-val", "SQL query with concatenation"),
            (r'cursor\.(execute|executemany)\s*\(.*[fF]["\']', "SQL-val", "f-string SQL"),
            (r'\.raw\s*\(', "SQL-val", "Raw SQL query"),
            (r'subprocess\.(call|run|Popen|check_output)', "CMD-argument", "Command execution"),
            (r'os\.(system|popen|exec)', "CMD-argument", "OS command"),
            (r'eval\s*\(', "CMD-argument", "Dynamic eval"),
            (r'exec\s*\(', "CMD-argument", "Dynamic exec"),
            (r'render_template_string\s*\(', "TEMPLATE-expression", "SSTI"),
            (r'Template\s*\(.*\+', "TEMPLATE-expression", "Template concatenation"),
            (r'(pickle|yaml)\.load', "DESERIALIZE-object", "Insecure deserialization"),
        ],
        "xss": [
            (r'innerHTML\s*=', "DOM-sink", "DOM XSS via innerHTML"),
            (r'document\.write\s*\(', "DOM-sink", "document.write"),
            (r'\.html\s*\(', "DOM-sink", "jQuery .html()"),
            (r'dangerouslySetInnerHTML', "DOM-sink", "React dangerouslySetInnerHTML"),
            (r'Markup\s*\(', "TEMPLATE-expression", "Flask Markup (no escape)"),
            (r'\|\s*safe\b', "TEMPLATE-expression", "Template |safe filter"),
            (r'<%=.*%>', "TEMPLATE-expression", "ERB unescaped output"),
        ],
        "ssrf": [
            (r'requests?\.(get|post|put|delete|head)\s*\(', "HTTP-request", "Python requests"),
            (r'urllib\.request\.urlopen', "HTTP-request", "urllib request"),
            (r'http\.get\s*\(', "HTTP-request", "HTTP client"),
            (r'fetch\s*\(', "HTTP-request", "JS fetch"),
            (r'axios\.(get|post)', "HTTP-request", "Axios request"),
            (r'curl_exec', "HTTP-request", "PHP curl"),
        ],
        "auth": [
            (r'password.*==', "AUTH-compare", "Timing-unsafe password compare"),
            (r'md5\s*\(', "AUTH-hash", "Weak hash (MD5)"),
            (r'sha1\s*\(', "AUTH-hash", "Weak hash (SHA1)"),
            (r'jwt\.decode.*verify\s*=\s*False', "AUTH-token", "JWT without verification"),
            (r'SECRET_KEY\s*=\s*["\'][^"\']{1,10}["\']', "AUTH-secret", "Weak secret"),
        ],
        "authz": [
            (r'user_id.*request', "AUTHZ-idor", "User ID from request"),
            (r'\.objects\.(get|filter).*id\s*=', "AUTHZ-idor", "Direct object reference"),
            (r'@login_required', "AUTHZ-decorator", "Auth decorator (check scope)"),
        ],
    }


    # Sanitizer 模式 — 防御函数
    SANITIZER_PATTERNS = [
        (r'parameterized|placeholder|\?\s*,|\%s', "prepared_statement"),
        (r'escape|quote|sanitize|clean|strip_tags|bleach', "escape_function"),
        (r'int\(|float\(|\.isdigit\(\)', "type_cast"),
        (r'whitelist|allowlist|ALLOWED_', "whitelist"),
        (r'html\.escape|markupsafe\.escape|cgi\.escape', "html_encode"),
        (r'shlex\.quote|pipes\.quote', "shell_escape"),
        (r'urlencode|quote_plus', "url_encode"),
        (r'csrf_token|csrf_protect', "csrf_protection"),
    ]

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.language = self._detect_language()

    def _detect_language(self) -> str:
        """检测项目主语言"""
        ext_count = {}
        for root, _, files in os.walk(self.repo_path):
            if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'vendor', '.venv']):
                continue
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                ext_count[ext] = ext_count.get(ext, 0) + 1

        lang_map = {
            '.py': 'python', '.js': 'javascript', '.ts': 'javascript',
            '.php': 'php', '.java': 'java', '.rb': 'python',
        }
        top_ext = max(ext_count, key=ext_count.get, default='.py')
        return lang_map.get(top_ext, 'python')

    def scan_sources(self) -> List[Dict[str, Any]]:
        """扫描所有用户输入入口"""
        sources = []
        patterns = self.SOURCE_PATTERNS.get(self.language, self.SOURCE_PATTERNS['python'])

        for filepath in self._get_source_files():
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in patterns:
                            if re.search(pattern, line):
                                sources.append({
                                    "file": os.path.relpath(filepath, self.repo_path),
                                    "line": line_num,
                                    "code": line.strip()[:120],
                                    "pattern": pattern,
                                })
                                break
            except (IOError, OSError):
                continue

        return sources

    def scan_sinks(self, vuln_type: str = "injection") -> List[Dict[str, Any]]:
        """扫描指定类型的危险 Sink"""
        sinks = []
        patterns = self.SINK_PATTERNS.get(vuln_type, [])

        for filepath in self._get_source_files():
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, slot_type, desc in patterns:
                            if re.search(pattern, line):
                                sinks.append({
                                    "file": os.path.relpath(filepath, self.repo_path),
                                    "line": line_num,
                                    "code": line.strip()[:120],
                                    "slot_type": slot_type,
                                    "description": desc,
                                })
                                break
            except (IOError, OSError):
                continue

        return sinks

    def scan_sanitizers(self) -> List[Dict[str, Any]]:
        """扫描防御措施"""
        sanitizers = []
        for filepath in self._get_source_files():
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern, san_type in self.SANITIZER_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                sanitizers.append({
                                    "file": os.path.relpath(filepath, self.repo_path),
                                    "line": line_num,
                                    "code": line.strip()[:120],
                                    "type": san_type,
                                })
                                break
            except (IOError, OSError):
                continue

        return sanitizers

    def _get_source_files(self) -> List[str]:
        """获取所有源码文件"""
        extensions = {
            'python': ['*.py'],
            'javascript': ['*.js', '*.ts', '*.jsx', '*.tsx'],
            'php': ['*.php'],
            'java': ['*.java'],
        }
        exts = extensions.get(self.language, ['*.py', '*.js', '*.ts'])
        files = []
        for ext in exts:
            files.extend(glob.glob(
                os.path.join(self.repo_path, '**', ext),
                recursive=True
            ))
        # 排除测试/依赖目录
        skip_dirs = ['node_modules', '.git', '__pycache__', 'vendor', '.venv', 'test', 'tests', 'dist', 'build']
        return [f for f in files if not any(s in f for s in skip_dirs)]



# ═══════════════════════════════════════════════════════════════
# LLM 代码审计引擎
# ═══════════════════════════════════════════════════════════════

# Shannon 风格的审计 Prompt 模板（中文化）
AUDIT_PROMPTS = {
    "injection": """你是注入漏洞分析专家。分析以下代码中的数据流，判断用户输入是否能到达危险 Sink（SQL查询/命令执行/模板引擎/反序列化）。

## 分析要求
1. 追踪每个 Source 参数到 Sink 的完整路径
2. 标注路径上的所有 Sanitizer 及其位置
3. 判断 Sanitizer 是否与 Sink 上下文匹配
4. 如果存在 Sanitizer 之后的字符串拼接，视为防御无效
5. 对每条路径给出 verdict: vulnerable 或 safe

## Sink 类型标注规则
- SQL-val: SQL 值位置（应使用参数绑定）
- SQL-ident: SQL 标识符（应使用白名单）
- CMD-argument: 命令参数（应使用数组传递或 shlex.quote）
- TEMPLATE-expression: 模板表达式（应使用自动转义）
- DESERIALIZE-object: 反序列化（应限制来源）

## 输出格式（JSON数组）
[{
  "source": "参数名 & 文件:行",
  "path": "controller → fn → sink 简要跳转",
  "sink_call": "文件:行 & 函数名",
  "slot_type": "SQL-val|CMD-argument|...",
  "sanitization_observed": "所有防御步骤",
  "verdict": "vulnerable|safe",
  "mismatch_reason": "如果vulnerable, 1-2行说明原因",
  "witness_payload": "最小验证payload",
  "confidence": "high|med|low"
}]

## 代码片段
""",

    "xss": """你是 XSS 分析专家。分析以下代码，追踪用户输入如何到达 DOM/模板输出点，判断是否存在上下文编码不匹配。

## 分析要求
1. 识别所有输出上下文：HTML正文/属性/JS字符串/URL/CSS
2. 对每个输出点，检查编码是否匹配上下文
3. 注意 |safe 过滤器、innerHTML、dangerouslySetInnerHTML 等绕过
4. CSP/HttpOnly Cookie 作为缓解措施记录，不影响漏洞判定

## 输出格式（JSON数组）
[{
  "source": "输入参数 & 来源",
  "render_context": "HTML-body|HTML-attr|JS-string|URL|CSS",
  "encoding_applied": "已应用的编码",
  "verdict": "vulnerable|safe",
  "mismatch_reason": "编码与上下文不匹配的原因",
  "witness_payload": "针对该上下文的最小XSS payload",
  "confidence": "high|med|low"
}]

## 代码片段
""",

    "auth": """你是认证安全分析专家。审计以下代码的身份验证机制，查找认证绕过/会话管理/凭据处理缺陷。

## 检查项
1. 密码存储（是否使用 bcrypt/argon2，是否有 salt）
2. 会话管理（token 生成随机性、过期、固定）
3. 认证绕过（缺少验证中间件的端点）
4. 暴力破解防护（速率限制、账户锁定）
5. 密码重置流程安全性
6. JWT 实现（算法、密钥强度、声明验证）

## 输出格式（JSON数组）
[{
  "issue": "问题标题",
  "location": "文件:行",
  "severity": "critical|high|medium|low",
  "description": "具体问题描述",
  "evidence": "相关代码片段",
  "remediation": "修复建议",
  "confidence": "high|med|low"
}]

## 代码片段
""",

    "authz": """你是授权安全分析专家。审计以下代码的访问控制逻辑，查找越权/IDOR/权限提升缺陷。

## 检查项
1. 水平越权：用 A 的身份访问 B 的资源（检查 object ownership 验证）
2. 垂直越权：普通用户访问管理员功能（检查 role/permission 中间件）
3. IDOR：直接通过 ID 访问对象（检查是否验证 ownership）
4. 功能级访问控制：每个端点是否都有权限检查
5. 多租户隔离：是否正确隔离不同组织的数据

## 输出格式（JSON数组）
[{
  "issue": "问题标题",
  "endpoint": "HTTP方法 路径",
  "location": "文件:行",
  "authz_type": "horizontal|vertical|idor|function_level",
  "missing_check": "缺失的具体检查",
  "evidence": "相关代码",
  "exploit_hypothesis": "如何利用",
  "confidence": "high|med|low"
}]

## 代码片段
""",

    "ssrf": """你是 SSRF 分析专家。追踪用户输入如何影响服务端发出的 HTTP 请求。

## 检查项
1. URL 参数是否直接传入 HTTP 客户端
2. 是否有协议/主机白名单验证
3. 重定向跟随是否受控
4. DNS Rebinding 防护
5. 内部服务/云元数据端点可达性

## 输出格式（JSON数组）
[{
  "source": "用户可控输入",
  "sink": "HTTP请求函数 & 位置",
  "url_validation": "已有的URL验证措施",
  "bypass_possible": true/false,
  "bypass_method": "绕过方法（如有）",
  "targets_reachable": ["internal_service", "cloud_metadata", "..."],
  "witness_payload": "验证payload",
  "confidence": "high|med|low"
}]

## 代码片段
""",
}



class CodeAuditor:
    """
    白盒代码审计主引擎
    
    结合静态扫描 + LLM 分析，实现 Shannon 风格的 5 类并行审计
    
    用法:
        auditor = CodeAuditor(
            repo_path="/path/to/source",
            llm_config={"api_key": "sk-...", "model": "deepseek-chat"}
        )
        results = await auditor.run_full_audit()
    """

    def __init__(self, repo_path: str, llm_config: Optional[Dict] = None):
        self.repo_path = repo_path
        self.llm_config = llm_config or {}
        self.scanner = StaticScanner(repo_path)
        self._finding_counter = 0

    async def run_full_audit(self, vuln_classes: Optional[List[str]] = None) -> Dict[str, AuditResult]:
        """
        运行完整 5 类并行审计
        
        Args:
            vuln_classes: 要审计的类型列表，默认全部
        
        Returns:
            {vuln_type: AuditResult} 字典
        """
        classes = vuln_classes or ["injection", "xss", "auth", "authz", "ssrf"]

        # 并行执行所有类型的审计
        tasks = []
        for cls in classes:
            tasks.append(self._audit_single_class(cls))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for cls, result in zip(classes, results):
            if isinstance(result, Exception):
                output[cls] = AuditResult(vuln_type=cls, error=str(result))
            else:
                output[cls] = result

        return output

    async def _audit_single_class(self, vuln_type: str) -> AuditResult:
        """审计单个漏洞类型"""
        import time
        start = time.time()

        result = AuditResult(vuln_type=vuln_type)

        # Step 1: 静态扫描找 Source/Sink 对
        sources = self.scanner.scan_sources()
        sinks = self.scanner.scan_sinks(vuln_type)
        sanitizers = self.scanner.scan_sanitizers()

        result.files_analyzed = len(self.scanner._get_source_files())

        # Step 2: 如果有 LLM，用 LLM 做深度分析
        if self.llm_config.get("api_key") and sinks:
            llm_findings = await self._llm_audit(vuln_type, sources, sinks, sanitizers)
            result.findings = llm_findings
        else:
            # 无 LLM：基于启发式匹配 Source-Sink 对
            result.findings = self._heuristic_audit(vuln_type, sources, sinks, sanitizers)

        result.duration_seconds = time.time() - start
        return result

    def _heuristic_audit(
        self,
        vuln_type: str,
        sources: List[Dict],
        sinks: List[Dict],
        sanitizers: List[Dict],
    ) -> List[CodeVulnFinding]:
        """启发式审计（无 LLM 时使用）"""
        findings = []

        # 简单策略：同文件中的 Source + Sink 且无对应 Sanitizer
        source_files = set(s["file"] for s in sources)
        sink_by_file = {}
        for sink in sinks:
            sink_by_file.setdefault(sink["file"], []).append(sink)

        sanitizer_files = set(s["file"] for s in sanitizers)

        for src_file in source_files:
            if src_file in sink_by_file:
                file_sinks = sink_by_file[src_file]
                has_sanitizer = src_file in sanitizer_files

                for sink in file_sinks:
                    if not has_sanitizer:
                        self._finding_counter += 1
                        prefix = vuln_type.upper()[:3]
                        findings.append(CodeVulnFinding(
                            id=f"{prefix}-VULN-{self._finding_counter:03d}",
                            vuln_type=vuln_type,
                            title=f"{sink['description']} in {src_file}",
                            severity="high" if vuln_type in ("injection", "auth") else "medium",
                            confidence="low",  # 启发式 = low confidence
                            data_flow=DataFlowPath(
                                source_file=src_file,
                                sink_file=sink["file"],
                                sink_line=sink["line"],
                                sink_call=sink["code"],
                                sink_type=sink["slot_type"],
                            ),
                            verdict="vulnerable",
                            mismatch_reason=f"No sanitizer found between source and {sink['slot_type']} sink",
                            externally_exploitable=True,
                            notes="Heuristic detection - requires manual verification",
                        ))

        return findings


    async def _llm_audit(
        self,
        vuln_type: str,
        sources: List[Dict],
        sinks: List[Dict],
        sanitizers: List[Dict],
    ) -> List[CodeVulnFinding]:
        """LLM 辅助深度审计"""
        findings = []

        # 收集相关代码片段（以 sink 所在文件为单位）
        sink_files = set(s["file"] for s in sinks)
        code_chunks = []

        for sink_file in list(sink_files)[:10]:  # 限制分析文件数
            filepath = os.path.join(self.repo_path, sink_file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # 截取前 3000 字符（避免 token 超限）
                    code_chunks.append(f"=== {sink_file} ===\n{content[:3000]}")
            except (IOError, OSError):
                continue

        if not code_chunks:
            return findings

        # 构建 prompt
        prompt = AUDIT_PROMPTS.get(vuln_type, AUDIT_PROMPTS["injection"])
        prompt += "\n".join(code_chunks[:5])  # 最多 5 个文件

        # 调用 LLM
        response = await self._call_llm(prompt)
        if not response:
            return findings

        # 解析 LLM 返回的 JSON
        try:
            # 提取 JSON 数组
            json_match = re.search(r'\[[\s\S]*?\]', response)
            if json_match:
                items = json.loads(json_match.group())
                for item in items:
                    if item.get("verdict") == "vulnerable" or item.get("severity"):
                        self._finding_counter += 1
                        prefix = vuln_type.upper()[:3]
                        finding = CodeVulnFinding(
                            id=f"{prefix}-VULN-{self._finding_counter:03d}",
                            vuln_type=vuln_type,
                            title=item.get("issue", item.get("mismatch_reason", "LLM-detected vulnerability")),
                            severity=item.get("severity", "medium"),
                            confidence=item.get("confidence", "med"),
                            verdict=item.get("verdict", "vulnerable"),
                            mismatch_reason=item.get("mismatch_reason", item.get("description", "")),
                            witness_payload=item.get("witness_payload", ""),
                            externally_exploitable=item.get("externally_exploitable", True),
                            notes=item.get("notes", ""),
                        )
                        # 数据流信息
                        if item.get("source") or item.get("location"):
                            finding.data_flow = DataFlowPath(
                                source_param=item.get("source", ""),
                                sink_call=item.get("sink_call", item.get("sink", "")),
                                sink_type=item.get("slot_type", item.get("render_context", "")),
                            )
                        findings.append(finding)
        except (json.JSONDecodeError, ValueError):
            # LLM 返回格式不标准，尝试提取关键信息
            pass

        return findings

    async def _call_llm(self, prompt: str) -> str:
        """调用 LLM API"""
        api_key = self.llm_config.get("api_key", "")
        base_url = self.llm_config.get("base_url", "https://api.deepseek.com/v1")
        model = self.llm_config.get("model", "deepseek-chat")

        if not api_key:
            return ""

        try:
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": "你是一个专业的代码安全审计员。严格按照要求的JSON格式输出分析结果。"},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.2,
                        "max_tokens": 4096,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[CodeAuditor] LLM call failed: {e}")

        return ""


    def get_exploitation_queue(self, results: Dict[str, AuditResult]) -> List[Dict]:
        """
        生成可利用漏洞队列（供 exploit 阶段使用）
        兼容 Shannon 的 exploitation_queue.json 格式
        """
        queue = []
        for vuln_type, result in results.items():
            for finding in result.findings:
                if finding.verdict == "vulnerable" and finding.externally_exploitable:
                    entry = {
                        "ID": finding.id,
                        "vulnerability_type": finding.vuln_type,
                        "subtype": finding.subtype,
                        "externally_exploitable": finding.externally_exploitable,
                        "source": finding.data_flow.source_param if finding.data_flow else "",
                        "path": finding.data_flow.hops if finding.data_flow else [],
                        "sink_call": finding.data_flow.sink_call if finding.data_flow else "",
                        "slot_type": finding.data_flow.sink_type if finding.data_flow else "",
                        "verdict": finding.verdict,
                        "mismatch_reason": finding.mismatch_reason,
                        "witness_payload": finding.witness_payload,
                        "confidence": finding.confidence,
                        "severity": finding.severity,
                        "notes": finding.notes,
                    }
                    queue.append(entry)
        return queue

    def export_to_findings(self, results: Dict[str, AuditResult]) -> List[Dict]:
        """
        导出为 auto_hunt 兼容的 findings 格式
        可以直接注入到现有的 findings["vulnerabilities"] 中
        """
        vulns = []
        for vuln_type, result in results.items():
            for finding in result.findings:
                if finding.verdict == "vulnerable":
                    vuln = {
                        "id": finding.id,
                        "type": finding.vuln_type,
                        "title": finding.title,
                        "severity": finding.severity,
                        "confidence": finding.confidence,
                        "url": "",  # 白盒没有 URL，需后续黑盒验证补充
                        "source_file": finding.data_flow.source_file if finding.data_flow else "",
                        "source_line": finding.data_flow.source_line if finding.data_flow else 0,
                        "sink_file": finding.data_flow.sink_file if finding.data_flow else "",
                        "sink_line": finding.data_flow.sink_line if finding.data_flow else 0,
                        "data_flow": finding.data_flow.sink_call if finding.data_flow else "",
                        "payload": finding.witness_payload,
                        "evidence": finding.mismatch_reason,
                        "verified": False,  # 需要黑盒验证
                        "source": "code_audit",
                    }
                    vulns.append(vuln)
        return vulns


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

async def run_code_audit(
    repo_path: str,
    llm_config: Optional[Dict] = None,
    vuln_classes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    一键代码审计入口
    
    Args:
        repo_path: 源码目录
        llm_config: LLM 配置 {"api_key": "...", "model": "...", "base_url": "..."}
        vuln_classes: 审计类型列表
    
    Returns:
        {
            "results": {type: AuditResult},
            "exploitation_queue": [...],
            "findings": [...],  # 兼容 auto_hunt 格式
            "summary": {...}
        }
    """
    auditor = CodeAuditor(repo_path, llm_config)
    results = await auditor.run_full_audit(vuln_classes)

    exploitation_queue = auditor.get_exploitation_queue(results)
    findings = auditor.export_to_findings(results)

    # 汇总统计
    total_findings = sum(len(r.findings) for r in results.values())
    vulnerable_count = sum(
        len([f for f in r.findings if f.verdict == "vulnerable"])
        for r in results.values()
    )
    files_analyzed = max(r.files_analyzed for r in results.values()) if results else 0

    summary = {
        "repo_path": repo_path,
        "language": auditor.scanner.language,
        "files_analyzed": files_analyzed,
        "total_findings": total_findings,
        "vulnerable_count": vulnerable_count,
        "by_type": {t: len(r.findings) for t, r in results.items()},
        "exploitation_queue_size": len(exploitation_queue),
    }

    return {
        "results": results,
        "exploitation_queue": exploitation_queue,
        "findings": findings,
        "summary": summary,
    }
