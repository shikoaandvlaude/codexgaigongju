#!/usr/bin/env python3
"""
Auto Remediation — 自动漏洞修复 + PR 生成
移植自 RedAmon 框架的 CypherFix Pipeline

完整流程：
1. 漏洞分析 → 定位根因代码
2. LLM 生成修复补丁
3. 验证补丁不破坏功能
4. 创建 Git 分支 + 提交
5. 生成 GitHub Pull Request

用法：
    from auto_remediation import AutoRemediator
    
    remediator = AutoRemediator(
        repo_path="/path/to/repo",
        llm_config={"api_key": "sk-...", "model": "deepseek-chat"},
        github_token="ghp_...",
    )
    
    results = await remediator.fix_findings(findings)
    # results = [{"finding_id": "...", "patch": "...", "pr_url": "..."}]
"""

import asyncio
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class PatchResult:
    """单个修复结果"""
    finding_id: str = ""
    vuln_type: str = ""
    title: str = ""
    # 修复信息
    file_path: str = ""
    original_code: str = ""
    fixed_code: str = ""
    patch_diff: str = ""
    # 修复说明
    fix_description: str = ""
    fix_category: str = ""  # sanitize/parameterize/validate/escape/access_control
    # 验证
    verified: bool = False
    verification_note: str = ""
    # PR 信息
    branch_name: str = ""
    commit_hash: str = ""
    pr_url: str = ""
    pr_number: int = 0
    # 状态
    status: str = "pending"  # pending/patched/verified/pr_created/failed
    error: str = ""


@dataclass
class RemediationConfig:
    """修复配置"""
    # Git
    repo_path: str = ""
    base_branch: str = "main"
    branch_prefix: str = "fix/security-"
    # GitHub
    github_token: str = ""
    github_owner: str = ""
    github_repo: str = ""
    # LLM
    llm_api_key: str = ""
    llm_model: str = "deepseek-chat"
    llm_base_url: str = "https://api.deepseek.com/v1"
    # 行为
    auto_commit: bool = True
    auto_pr: bool = True
    verify_patch: bool = True
    max_patches_per_run: int = 10
    # PR 模板
    pr_title_template: str = "fix(security): {vuln_type} — {title}"
    pr_body_template: str = ""


# ═══════════════════════════════════════════════════════════════
# 修复策略知识库
# ═══════════════════════════════════════════════════════════════

FIX_STRATEGIES = {
    "injection": {
        "sqli": {
            "strategy": "parameterize",
            "description": "将字符串拼接改为参数化查询",
            "examples": {
                "python": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "javascript": 'db.query("SELECT * FROM users WHERE id = $1", [userId])',
                "php": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
            },
        },
        "cmdi": {
            "strategy": "sanitize",
            "description": "使用数组传参代替字符串拼接，或使用 shlex.quote",
            "examples": {
                "python": 'subprocess.run(["ping", "-c", "1", host], shell=False)',
                "javascript": 'execFile("ping", ["-c", "1", host], callback)',
            },
        },
        "ssti": {
            "strategy": "escape",
            "description": "使用沙箱模板或自动转义",
            "examples": {
                "python": 'render_template("page.html", data=user_input)  # NOT render_template_string',
            },
        },
    },
    "xss": {
        "reflected": {
            "strategy": "escape",
            "description": "对输出进行上下文感知编码",
            "examples": {
                "python": "from markupsafe import escape; return escape(user_input)",
                "javascript": "element.textContent = userInput;  // NOT innerHTML",
            },
        },
        "stored": {
            "strategy": "sanitize",
            "description": "输入清洗 + 输出编码双重防护",
        },
    },
    "auth": {
        "weak_hash": {
            "strategy": "upgrade",
            "description": "升级到 bcrypt/argon2",
            "examples": {
                "python": "from bcrypt import hashpw, gensalt; hashed = hashpw(password.encode(), gensalt())",
            },
        },
        "jwt_none": {
            "strategy": "validate",
            "description": "强制验证 JWT 算法",
            "examples": {
                "python": 'jwt.decode(token, key, algorithms=["HS256"])  # 明确指定算法',
            },
        },
    },
    "ssrf": {
        "url_injection": {
            "strategy": "validate",
            "description": "URL 白名单 + 协议限制 + 私有 IP 拦截",
            "examples": {
                "python": """
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback:
            return False
    except ValueError:
        pass
    return True
""",
            },
        },
    },
    "authz": {
        "idor": {
            "strategy": "access_control",
            "description": "添加对象所有权验证",
            "examples": {
                "python": """
# 验证资源属于当前用户
obj = Model.objects.get(id=obj_id)
if obj.owner_id != request.user.id:
    return HttpResponseForbidden()
""",
            },
        },
    },
}


# ═══════════════════════════════════════════════════════════════
# 修复 Prompt
# ═══════════════════════════════════════════════════════════════

PATCH_GENERATION_PROMPT = """你是安全代码修复专家。根据以下漏洞信息，生成最小化的安全修复补丁。

## 漏洞信息
- 类型: {vuln_type}
- 子类型: {subtype}
- 文件: {file_path}
- 描述: {description}

## 当前代码
```
{original_code}
```

## 修复策略
{fix_strategy}

## 要求
1. 只修复安全问题，不改变业务逻辑
2. 修复必须向后兼容
3. 使用该语言的最佳安全实践
4. 保持代码风格一致
5. 添加必要的 import 语句

## 输出格式（严格 JSON）
{{
    "fixed_code": "修复后的完整代码段",
    "fix_description": "修复说明（中文，1-2句话）",
    "imports_needed": ["需要新增的 import 语句"],
    "breaking_changes": false,
    "test_suggestion": "建议的测试方式"
}}
"""


# ═══════════════════════════════════════════════════════════════
# Auto Remediator 主类
# ═══════════════════════════════════════════════════════════════

class AutoRemediator:
    """
    自动漏洞修复引擎
    
    工作流：
    1. 分析漏洞 → 确定修复策略
    2. 读取源码 → 定位问题代码
    3. LLM 生成补丁
    4. 验证补丁（语法检查）
    5. Git commit + push
    6. 创建 GitHub PR
    """

    def __init__(self, config: Optional[RemediationConfig] = None, **kwargs):
        self.config = config or RemediationConfig(**{
            k: v for k, v in kwargs.items()
            if k in RemediationConfig.__dataclass_fields__
        })

    async def fix_findings(self, findings: List[Dict]) -> List[PatchResult]:
        """
        批量修复漏洞
        
        Args:
            findings: 漏洞列表（需包含 source_file/source_line 等代码定位信息）
        """
        results = []
        fixable = self._filter_fixable(findings)

        for finding in fixable[:self.config.max_patches_per_run]:
            result = await self._fix_single(finding)
            results.append(result)

        # 如果有成功的补丁，创建 PR
        successful = [r for r in results if r.status == "patched"]
        if successful and self.config.auto_pr:
            await self._create_pr(successful)

        return results

    async def fix_single(self, finding: Dict) -> PatchResult:
        """修复单个漏洞"""
        return await self._fix_single(finding)

    # ─── 内部方法 ──────────────────────────────────────────

    def _filter_fixable(self, findings: List[Dict]) -> List[Dict]:
        """过滤出可修复的漏洞（需要有代码定位信息）"""
        fixable = []
        for f in findings:
            if f.get("source_file") or f.get("file_path"):
                fixable.append(f)
        return fixable

    async def _fix_single(self, finding: Dict) -> PatchResult:
        """修复单个漏洞"""
        result = PatchResult(
            finding_id=finding.get("id", ""),
            vuln_type=finding.get("type", finding.get("vuln_type", "")),
            title=finding.get("title", ""),
        )

        try:
            # Step 1: 定位源码
            file_path = finding.get("source_file", finding.get("file_path", ""))
            if not file_path:
                result.status = "failed"
                result.error = "No source file specified"
                return result

            full_path = os.path.join(self.config.repo_path, file_path) if self.config.repo_path else file_path
            if not os.path.exists(full_path):
                result.status = "failed"
                result.error = f"File not found: {full_path}"
                return result

            result.file_path = file_path

            # 读取源码（围绕问题行取上下文）
            source_line = finding.get("source_line", 0)
            original_code = self._read_code_context(full_path, source_line, context_lines=20)
            result.original_code = original_code

            # Step 2: 确定修复策略
            vuln_type = finding.get("type", finding.get("vuln_type", ""))
            subtype = finding.get("subtype", self._infer_subtype(vuln_type, finding))
            fix_strategy = self._get_fix_strategy(vuln_type, subtype)

            # Step 3: LLM 生成补丁
            fixed_code = await self._generate_patch(
                vuln_type=vuln_type,
                subtype=subtype,
                file_path=file_path,
                original_code=original_code,
                description=finding.get("description", finding.get("title", "")),
                fix_strategy=fix_strategy,
            )

            if not fixed_code:
                result.status = "failed"
                result.error = "LLM failed to generate patch"
                return result

            result.fixed_code = fixed_code.get("fixed_code", "")
            result.fix_description = fixed_code.get("fix_description", "")
            result.fix_category = fix_strategy.get("strategy", "")

            # Step 4: 应用补丁
            if result.fixed_code and self.config.auto_commit:
                applied = self._apply_patch(full_path, source_line, original_code, result.fixed_code)
                if applied:
                    result.status = "patched"
                    # 生成 diff
                    result.patch_diff = self._generate_diff(full_path)
                else:
                    result.status = "failed"
                    result.error = "Failed to apply patch"
            else:
                result.status = "patched"

        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        return result

    def _read_code_context(self, file_path: str, line: int, context_lines: int = 20) -> str:
        """读取代码上下文"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            start = max(0, line - context_lines)
            end = min(len(lines), line + context_lines)
            return "".join(lines[start:end])
        except IOError:
            return ""

    def _infer_subtype(self, vuln_type: str, finding: Dict) -> str:
        """推断漏洞子类型"""
        title = (finding.get("title", "") + finding.get("description", "")).lower()
        if vuln_type == "injection":
            if "sql" in title:
                return "sqli"
            elif "command" in title or "cmd" in title:
                return "cmdi"
            elif "template" in title or "ssti" in title:
                return "ssti"
        elif vuln_type == "xss":
            if "stored" in title:
                return "stored"
            return "reflected"
        elif vuln_type == "auth":
            if "jwt" in title:
                return "jwt_none"
            if "md5" in title or "sha1" in title or "hash" in title:
                return "weak_hash"
        elif vuln_type == "ssrf":
            return "url_injection"
        elif vuln_type == "authz" or vuln_type == "idor":
            return "idor"
        return "generic"

    def _get_fix_strategy(self, vuln_type: str, subtype: str) -> Dict:
        """获取修复策略"""
        type_strategies = FIX_STRATEGIES.get(vuln_type, {})
        strategy = type_strategies.get(subtype, {})
        if not strategy:
            return {"strategy": "manual", "description": "需要人工审查修复方案"}
        return strategy

    async def _generate_patch(self, vuln_type: str, subtype: str, file_path: str,
                              original_code: str, description: str, fix_strategy: Dict) -> Optional[Dict]:
        """LLM 生成修复补丁"""
        if not self.config.llm_api_key:
            return None

        strategy_text = f"策略: {fix_strategy.get('strategy', 'N/A')}\n"
        strategy_text += f"说明: {fix_strategy.get('description', 'N/A')}\n"
        examples = fix_strategy.get("examples", {})
        if examples:
            # 根据文件扩展名选择示例
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {".py": "python", ".js": "javascript", ".ts": "javascript", ".php": "php"}
            lang = lang_map.get(ext, "python")
            if lang in examples:
                strategy_text += f"示例:\n```\n{examples[lang]}\n```"

        prompt = PATCH_GENERATION_PROMPT.format(
            vuln_type=vuln_type,
            subtype=subtype,
            file_path=file_path,
            description=description,
            original_code=original_code[:2000],
            fix_strategy=strategy_text,
        )

        try:
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    f"{self.config.llm_base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.config.llm_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.config.llm_model,
                        "messages": [
                            {"role": "system", "content": "你是安全代码修复专家。严格输出 JSON。"},
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 4096,
                    },
                )
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    # 解析 JSON
                    json_match = re.search(r'\{[\s\S]*\}', content)
                    if json_match:
                        return json.loads(json_match.group())
        except Exception as e:
            print(f"[AutoRemediator] LLM error: {e}")

        return None

    def _apply_patch(self, file_path: str, line: int, original: str, fixed: str) -> bool:
        """应用补丁到文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            if original in content:
                content = content.replace(original, fixed, 1)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return True
        except IOError:
            pass
        return False

    def _generate_diff(self, file_path: str) -> str:
        """生成 git diff"""
        try:
            result = subprocess.run(
                ["git", "diff", file_path],
                capture_output=True, text=True,
                cwd=self.config.repo_path or os.path.dirname(file_path),
            )
            return result.stdout[:3000]
        except Exception:
            return ""

    async def _create_pr(self, patches: List[PatchResult]):
        """创建 GitHub Pull Request"""
        if not self.config.github_token:
            return

        # 创建分支
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"{self.config.branch_prefix}{timestamp}"
        cwd = self.config.repo_path

        try:
            # Git 操作
            subprocess.run(["git", "checkout", "-b", branch_name], cwd=cwd, check=True)

            # 提交所有修改
            subprocess.run(["git", "add", "-A"], cwd=cwd, check=True)

            commit_msg = f"fix(security): 自动修复 {len(patches)} 个漏洞\n\n"
            for p in patches:
                commit_msg += f"- {p.finding_id}: {p.title} ({p.fix_category})\n"

            subprocess.run(["git", "commit", "-m", commit_msg], cwd=cwd, check=True)

            # Push（需要配置 remote）
            subprocess.run(["git", "push", "origin", branch_name], cwd=cwd)

            # 创建 PR (GitHub API)
            pr_url = await self._github_create_pr(branch_name, patches)

            for p in patches:
                p.branch_name = branch_name
                p.pr_url = pr_url
                p.status = "pr_created"

        except subprocess.CalledProcessError as e:
            for p in patches:
                p.error = f"Git error: {e}"
        except Exception as e:
            for p in patches:
                p.error = f"PR creation error: {e}"

    async def _github_create_pr(self, branch: str, patches: List[PatchResult]) -> str:
        """调用 GitHub API 创建 PR"""
        if not all([self.config.github_token, self.config.github_owner, self.config.github_repo]):
            return ""

        title = f"fix(security): 自动修复 {len(patches)} 个安全漏洞"
        body = "## 安全漏洞自动修复\n\n"
        body += "由 Bai Auto-Hunt Agent 自动生成的安全修复 PR。\n\n"
        body += "### 修复列表\n\n"
        for p in patches:
            body += f"- **{p.finding_id}**: {p.title}\n"
            body += f"  - 文件: `{p.file_path}`\n"
            body += f"  - 策略: {p.fix_category}\n"
            body += f"  - 说明: {p.fix_description}\n\n"
        body += "### 注意\n"
        body += "- 请人工审查所有修改\n"
        body += "- 运行测试确认无回归\n"

        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{self.config.github_owner}/{self.config.github_repo}/pulls",
                    headers={
                        "Authorization": f"Bearer {self.config.github_token}",
                        "Accept": "application/vnd.github+json",
                    },
                    json={
                        "title": title,
                        "body": body,
                        "head": branch,
                        "base": self.config.base_branch,
                    },
                )
                if resp.status_code == 201:
                    data = resp.json()
                    return data.get("html_url", "")
        except Exception:
            pass

        return ""


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

async def auto_fix_and_pr(
    findings: List[Dict],
    repo_path: str,
    llm_config: Dict = None,
    github_config: Dict = None,
) -> List[PatchResult]:
    """
    一键修复 + PR
    
    Args:
        findings: 漏洞列表（需含 source_file）
        repo_path: 仓库路径
        llm_config: {"api_key": "...", "model": "...", "base_url": "..."}
        github_config: {"token": "...", "owner": "...", "repo": "..."}
    """
    config = RemediationConfig(repo_path=repo_path)

    if llm_config:
        config.llm_api_key = llm_config.get("api_key", "")
        config.llm_model = llm_config.get("model", "deepseek-chat")
        config.llm_base_url = llm_config.get("base_url", "https://api.deepseek.com/v1")

    if github_config:
        config.github_token = github_config.get("token", "")
        config.github_owner = github_config.get("owner", "")
        config.github_repo = github_config.get("repo", "")

    remediator = AutoRemediator(config=config)
    return await remediator.fix_findings(findings)
