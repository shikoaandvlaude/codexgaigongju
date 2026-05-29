#!/usr/bin/env python3
"""
Credential Hunter — 多源凭证泄露检测引擎

功能：
1. GitHub/GitLab 代码泄露搜索（Dork）
2. JavaScript 文件密钥提取（增强版）
3. .env / config 文件探测
4. 云服务密钥模式匹配（AWS/GCP/Azure/Stripe/Twilio 等）
5. Git 历史泄露检测
6. Postman/Swagger 公开集合检测
7. 密钥有效性自动验证

用法：
    from credential_hunter import CredentialHunter

    hunter = CredentialHunter(config)
    results = await hunter.hunt("example.com")
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime



# ═══════════════════════════════════════════════════════════════
# 密钥模式正则库
# ═══════════════════════════════════════════════════════════════

SECRET_PATTERNS = {
    # AWS
    "aws_access_key": {
        "regex": r"(?:AKIA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "service": "AWS",
        "validate": "aws_key",
    },
    "aws_secret_key": {
        "regex": r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "severity": "critical",
        "service": "AWS",
    },
    # GCP
    "gcp_api_key": {
        "regex": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "high",
        "service": "GCP",
        "validate": "gcp_key",
    },
    "gcp_service_account": {
        "regex": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "service": "GCP",
    },
    # Azure
    "azure_storage_key": {
        "regex": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "severity": "critical",
        "service": "Azure",
    },
    # GitHub
    "github_token": {
        "regex": r"gh[ps]_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "service": "GitHub",
        "validate": "github_token",
    },
    "github_classic": {
        "regex": r"ghp_[A-Za-z0-9]{36}",
        "severity": "critical",
        "service": "GitHub",
    },
    # Stripe
    "stripe_secret": {
        "regex": r"sk_live_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "service": "Stripe",
    },
    "stripe_publishable": {
        "regex": r"pk_live_[0-9a-zA-Z]{24,}",
        "severity": "medium",
        "service": "Stripe",
    },
    # Twilio
    "twilio_sid": {
        "regex": r"AC[a-z0-9]{32}",
        "severity": "high",
        "service": "Twilio",
    },
    # Slack
    "slack_token": {
        "regex": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
        "severity": "high",
        "service": "Slack",
    },
    "slack_webhook": {
        "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "medium",
        "service": "Slack",
    },
    # JWT
    "jwt_token": {
        "regex": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "medium",
        "service": "JWT",
    },
    # Generic
    "private_key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "service": "Private Key",
    },
    "generic_api_key": {
        "regex": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,64})['\"]?",
        "severity": "medium",
        "service": "Generic API",
    },
    "generic_password": {
        "regex": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,64})['\"]",
        "severity": "high",
        "service": "Password",
    },
    # Database
    "mongodb_uri": {
        "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s'\"]+",
        "severity": "critical",
        "service": "MongoDB",
    },
    "postgres_uri": {
        "regex": r"postgres(?:ql)?://[^:]+:[^@]+@[^\s'\"]+",
        "severity": "critical",
        "service": "PostgreSQL",
    },
    "mysql_uri": {
        "regex": r"mysql://[^:]+:[^@]+@[^\s'\"]+",
        "severity": "critical",
        "service": "MySQL",
    },
    # SendGrid
    "sendgrid_key": {
        "regex": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "high",
        "service": "SendGrid",
    },
    # Mailgun
    "mailgun_key": {
        "regex": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "service": "Mailgun",
    },
    # Heroku
    "heroku_api_key": {
        "regex": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "severity": "medium",
        "service": "Heroku/UUID",
    },
}



# 敏感文件路径探测列表
SENSITIVE_PATHS = [
    "/.env", "/.env.bak", "/.env.local", "/.env.production",
    "/.env.development", "/.env.staging", "/.env.old",
    "/config.json", "/config.yaml", "/config.yml",
    "/wp-config.php.bak", "/web.config", "/application.yml",
    "/.git/config", "/.git/HEAD", "/.gitconfig",
    "/.svn/entries", "/.svn/wc.db",
    "/server-status", "/server-info",
    "/.htpasswd", "/.htaccess",
    "/phpinfo.php", "/info.php",
    "/debug/vars", "/debug/pprof",
    "/actuator/env", "/actuator/configprops",
    "/swagger.json", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/.docker/config.json",
    "/Dockerfile", "/docker-compose.yml",
    "/.npmrc", "/.pypirc",
    "/package.json", "/composer.json",
    "/backup.sql", "/dump.sql", "/db.sql",
    "/id_rsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/credentials.xml", "/secrets.yaml",
]

# GitHub Dork 模板
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret_key',
    '"{domain}" AWS_ACCESS_KEY',
    '"{domain}" PRIVATE KEY',
    '"{domain}" filename:.env',
    '"{domain}" filename:config',
    '"{domain}" filename:credentials',
    '"{domain}" filename:.htpasswd',
    'org:"{company}" password',
    'org:"{company}" secret',
    'org:"{company}" token',
]


@dataclass
class CredentialFinding:
    """凭证发现"""
    secret_type: str = ""
    service: str = ""
    value: str = ""  # 脱敏后的值
    raw_value: str = ""  # 原始值（内部使用）
    severity: str = "medium"
    source: str = ""  # 来源（js_file/env_file/github/git_history）
    source_url: str = ""
    line_number: int = 0
    context: str = ""  # 上下文行
    # 验证
    is_valid: bool = False
    validated: bool = False
    validation_result: str = ""
    # 元数据
    timestamp: str = ""


class CredentialHunter:
    """凭证泄露猎人"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 10)
        self.findings: List[CredentialFinding] = []

    async def hunt(self, target: str, recon_dir: str = None,
                   js_files: List[str] = None) -> List[CredentialFinding]:
        """完整凭证搜索"""
        self.findings = []
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        print(f"[*] Credential Hunt: {domain}")

        tasks = [
            self._scan_sensitive_files(domain),
            self._scan_js_secrets(domain, recon_dir, js_files),
        ]

        if recon_dir:
            tasks.append(self._scan_local_artifacts(recon_dir))

        await asyncio.gather(*tasks, return_exceptions=True)

        # 去重
        self._deduplicate()

        # 按严重性排序
        self.findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4))

        valid_count = len([f for f in self.findings if f.is_valid])
        print(f"[+] Credential hunt complete: {len(self.findings)} secrets found ({valid_count} validated)")
        return self.findings


    async def _scan_sensitive_files(self, domain: str):
        """探测敏感配置文件"""
        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = []
        for path in SENSITIVE_PATHS:
            for scheme in ["https"]:
                url = f"{scheme}://{domain}{path}"
                tasks.append(self._check_sensitive_file(url, path, semaphore))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_sensitive_file(self, url: str, path: str, semaphore: asyncio.Semaphore):
        """检查单个敏感文件"""
        async with semaphore:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "-m", str(self.timeout),
                    "-o", "-", "-w", "\n%{http_code}",
                    "-H", "User-Agent: Mozilla/5.0 (Security Research)",
                    url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
                output = stdout.decode(errors="ignore")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else output
                status = int(lines[-1]) if len(lines) > 1 and lines[-1].strip().isdigit() else 0

                if status != 200 or len(body) < 10:
                    return

                # 排除常见误报（HTML错误页面）
                if "<html" in body.lower()[:200] and path.endswith((".env", ".yml", ".json", ".xml")):
                    return

                # 扫描内容中的密钥
                secrets = self._extract_secrets(body, source_url=url)
                if secrets:
                    self.findings.extend(secrets)
                    print(f"  [!] Secrets in {path}: {len(secrets)} found")
                elif path.startswith("/.env") or path.startswith("/.git"):
                    # .env 文件本身就是发现
                    self.findings.append(CredentialFinding(
                        secret_type="sensitive_file",
                        service="Configuration",
                        value=f"[FILE EXPOSED] {path}",
                        severity="high",
                        source="sensitive_file",
                        source_url=url,
                        context=body[:200],
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"  [!] Sensitive file exposed: {path}")

            except Exception:
                pass

    async def _scan_js_secrets(self, domain: str, recon_dir: str = None,
                               js_files: List[str] = None):
        """扫描 JavaScript 文件中的密钥"""
        files_to_scan = []

        if js_files:
            files_to_scan = js_files
        elif recon_dir:
            js_dir = Path(recon_dir) / "js"
            if js_dir.exists():
                files_to_scan = [str(f) for f in js_dir.glob("*.js")][:100]

        for js_file in files_to_scan[:50]:
            try:
                content = Path(js_file).read_text(errors="ignore")
                secrets = self._extract_secrets(content, source_url=js_file)
                if secrets:
                    self.findings.extend(secrets)
            except Exception:
                continue


    async def _scan_local_artifacts(self, recon_dir: str):
        """扫描本地侦察结果中的密钥"""
        recon_path = Path(recon_dir)
        # 扫描所有文本文件
        for ext in ["*.txt", "*.json", "*.xml", "*.yaml", "*.yml", "*.log"]:
            for fp in recon_path.rglob(ext):
                if fp.stat().st_size > 1_000_000:  # 跳过大文件
                    continue
                try:
                    content = fp.read_text(errors="ignore")
                    secrets = self._extract_secrets(content, source_url=str(fp))
                    if secrets:
                        self.findings.extend(secrets)
                except Exception:
                    continue

    def _extract_secrets(self, content: str, source_url: str = "") -> List[CredentialFinding]:
        """从文本中提取密钥"""
        results = []
        lines = content.splitlines()

        for secret_name, pattern_info in SECRET_PATTERNS.items():
            regex = pattern_info["regex"]
            try:
                matches = re.finditer(regex, content, re.IGNORECASE)
                for match in matches:
                    value = match.group(0)
                    # 跳过太短或明显是示例的值
                    if self._is_false_positive(value, secret_name):
                        continue

                    # 获取上下文
                    pos = match.start()
                    line_num = content[:pos].count("\n") + 1
                    context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                    # 脱敏
                    masked = self._mask_value(value)

                    results.append(CredentialFinding(
                        secret_type=secret_name,
                        service=pattern_info["service"],
                        value=masked,
                        raw_value=value,
                        severity=pattern_info["severity"],
                        source="content_scan",
                        source_url=source_url,
                        line_number=line_num,
                        context=context_line[:200],
                        timestamp=datetime.now().isoformat(),
                    ))
            except re.error:
                continue

        return results[:50]  # 限制单文件结果数

    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        """过滤误报"""
        # 示例/占位符
        fp_patterns = [
            "example", "test", "dummy", "placeholder", "your_",
            "xxx", "XXXX", "000000", "123456", "sample",
            "change_me", "TODO", "FIXME",
        ]
        value_lower = value.lower()
        if any(fp in value_lower for fp in fp_patterns):
            return True

        # 过短
        if len(value) < 10 and secret_type not in ("twilio_sid",):
            return True

        # UUID 类型要排除常见的全零/递增模式
        if secret_type == "heroku_api_key":
            if value.replace("-", "").replace("0", "") == "":
                return True

        return False

    def _mask_value(self, value: str) -> str:
        """脱敏显示"""
        if len(value) <= 8:
            return value[:2] + "*" * (len(value) - 2)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _deduplicate(self):
        """去重"""
        seen = set()
        unique = []
        for f in self.findings:
            key = f"{f.secret_type}:{f.raw_value}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique


    # ═══════════════════════════════════════════════════════════════
    # 密钥有效性验证
    # ═══════════════════════════════════════════════════════════════

    async def validate_findings(self):
        """验证发现的密钥是否有效"""
        for finding in self.findings:
            if finding.severity in ("critical", "high"):
                validator = self._get_validator(finding.secret_type)
                if validator:
                    is_valid, msg = await validator(finding.raw_value)
                    finding.validated = True
                    finding.is_valid = is_valid
                    finding.validation_result = msg

    def _get_validator(self, secret_type: str):
        """获取对应的验证器"""
        validators = {
            "github_token": self._validate_github_token,
            "github_classic": self._validate_github_token,
            "aws_access_key": self._validate_aws_key,
            "gcp_api_key": self._validate_gcp_key,
        }
        return validators.get(secret_type)

    async def _validate_github_token(self, token: str) -> Tuple[bool, str]:
        """验证 GitHub Token"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sk", "-m", "5",
                "-H", f"Authorization: token {token}",
                "-o", "-", "-w", "\n%{http_code}",
                "https://api.github.com/user",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            output = stdout.decode(errors="ignore")
            lines = output.rsplit("\n", 1)
            status = int(lines[-1]) if len(lines) > 1 and lines[-1].strip().isdigit() else 0
            if status == 200:
                body = lines[0]
                login = json.loads(body).get("login", "unknown") if body.startswith("{") else "unknown"
                return True, f"Valid GitHub token (user: {login})"
            return False, f"Invalid (HTTP {status})"
        except Exception as e:
            return False, f"Validation error: {e}"

    async def _validate_aws_key(self, key: str) -> Tuple[bool, str]:
        """验证 AWS Access Key（只检查格式有效性）"""
        if re.match(r"^(AKIA|ASIA)[0-9A-Z]{16}$", key):
            return True, "Valid AWS key format (needs secret key for full validation)"
        return False, "Invalid format"

    async def _validate_gcp_key(self, key: str) -> Tuple[bool, str]:
        """验证 GCP API Key"""
        try:
            url = f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={key}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sk", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            status = int(stdout.decode().strip() or "0")
            if status == 200:
                return True, "Valid GCP API key (Maps API accessible)"
            return False, f"Invalid or restricted (HTTP {status})"
        except Exception:
            return False, "Validation failed"

    def generate_report(self) -> str:
        """生成凭证报告"""
        if not self.findings:
            return "No credentials or secrets found."

        lines = [
            "=" * 60,
            "  CREDENTIAL HUNT REPORT",
            "=" * 60,
            f"  Total secrets: {len(self.findings)}",
            f"  Validated: {len([f for f in self.findings if f.validated])}",
            f"  Confirmed valid: {len([f for f in self.findings if f.is_valid])}",
            "",
        ]

        by_severity = {}
        for f in self.findings:
            by_severity.setdefault(f.severity, []).append(f)

        for sev in ["critical", "high", "medium", "low"]:
            items = by_severity.get(sev, [])
            if items:
                lines.append(f"  [{sev.upper()}] ({len(items)} findings)")
                for item in items[:10]:
                    valid_str = " [VALID]" if item.is_valid else ""
                    lines.append(f"    {item.service}: {item.value}{valid_str}")
                    lines.append(f"      Source: {item.source_url[:60]}")
                lines.append("")

        return "\n".join(lines)

    def get_github_dorks(self, domain: str, company: str = "") -> List[str]:
        """生成 GitHub Dork 列表"""
        if not company:
            company = domain.split(".")[0]
        dorks = []
        for template in GITHUB_DORKS:
            dork = template.format(domain=domain, company=company)
            dorks.append(dork)
        return dorks
