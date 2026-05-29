#!/usr/bin/env python3
"""
Tool Integrator — 外部安全工具统一接口

集成以下工具到 auto_hunt 工作流:
1. Slither — Solidity 静态分析（智能合约审计）
2. Semgrep — 多语言代码扫描（白盒审计增强）
3. Caido — HTTP 代理（被动流量收集 + 重放）
4. Amass — 深度资产发现（子域名 + 关联域）
5. SecLists — 字典管理（ffuf/nuclei 用）
6. mitmproxy — 流量拦截（替代 Burp MCP）

每个工具通过 run_* 方法调用，返回统一的结果格式。
"""

import json
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional


class ToolIntegrator:
    """外部工具统一调用接口"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.results_dir = os.path.expanduser(
            self.config.get("results_dir", "~/.bai-agent/tool_results")
        )
        Path(self.results_dir).mkdir(parents=True, exist_ok=True)

    # ═══════════════════════════════════════════════════════════
    # 1. Slither — 智能合约静态分析
    # ═══════════════════════════════════════════════════════════

    def run_slither(self, target: str, output_file: str = None) -> dict:
        """
        运行 Slither 分析 Solidity 合约。

        target: .sol 文件路径 或 合约目录
        返回: {"findings": [...], "summary": str, "detector_count": int}
        """
        if not shutil.which("slither"):
            return {"error": "slither 未安装。运行: pip install slither-analyzer solc-select"}

        output_file = output_file or os.path.join(self.results_dir, "slither_results.json")

        cmd = f"slither {target} --json {output_file} 2>&1"
        result = self._run_cmd(cmd, timeout=300)

        findings = []
        if os.path.exists(output_file):
            try:
                data = json.loads(Path(output_file).read_text())
                for detector in data.get("results", {}).get("detectors", []):
                    findings.append({
                        "type": detector.get("check", "unknown"),
                        "severity": detector.get("impact", "unknown"),
                        "confidence": detector.get("confidence", "unknown"),
                        "description": detector.get("description", ""),
                        "elements": [
                            e.get("source_mapping", {}).get("filename_short", "")
                            for e in detector.get("elements", [])[:3]
                        ],
                    })
            except (json.JSONDecodeError, KeyError):
                pass

        return {
            "tool": "slither",
            "target": target,
            "findings": findings,
            "high_count": len([f for f in findings if f["severity"] in ("High", "Medium")]),
            "total_count": len(findings),
            "output_file": output_file,
            "raw_output": result.get("output", "")[:2000],
        }

    # ═══════════════════════════════════════════════════════════
    # 2. Semgrep — 多语言代码审计
    # ═══════════════════════════════════════════════════════════

    def run_semgrep(self, target_dir: str, ruleset: str = "p/security-audit",
                    output_file: str = None) -> dict:
        """
        运行 Semgrep 代码扫描。

        target_dir: 代码目录
        ruleset: 规则集 (p/security-audit, p/owasp-top-ten, p/javascript, etc.)
        """
        if not shutil.which("semgrep"):
            return {"error": "semgrep 未安装。运行: pip install semgrep"}

        output_file = output_file or os.path.join(self.results_dir, "semgrep_results.json")

        cmd = f"semgrep --config={ruleset} {target_dir} --json -o {output_file} --quiet 2>&1"
        result = self._run_cmd(cmd, timeout=600)

        findings = []
        if os.path.exists(output_file):
            try:
                data = json.loads(Path(output_file).read_text())
                for item in data.get("results", []):
                    findings.append({
                        "rule_id": item.get("check_id", ""),
                        "severity": item.get("extra", {}).get("severity", "WARNING"),
                        "message": item.get("extra", {}).get("message", ""),
                        "file": item.get("path", ""),
                        "line": item.get("start", {}).get("line", 0),
                        "code": item.get("extra", {}).get("lines", "")[:200],
                    })
            except (json.JSONDecodeError, KeyError):
                pass

        return {
            "tool": "semgrep",
            "target": target_dir,
            "ruleset": ruleset,
            "findings": findings,
            "error_count": len([f for f in findings if f["severity"] == "ERROR"]),
            "warning_count": len([f for f in findings if f["severity"] == "WARNING"]),
            "total_count": len(findings),
            "output_file": output_file,
        }

    def run_semgrep_solidity(self, target_dir: str) -> dict:
        """Semgrep 专门针对 Solidity 的规则"""
        return self.run_semgrep(target_dir, ruleset="p/smart-contracts")

    # ═══════════════════════════════════════════════════════════
    # 3. Caido 代理集成（配置生成 + 流量导入）
    # ═══════════════════════════════════════════════════════════

    def setup_caido_config(self, proxy_port: int = 8080) -> dict:
        """
        生成 Caido 代理配置，让你的 HTTP Engine 通过 Caido 代理。
        这样 Caido 会记录所有请求，你可以在 UI 中分析。
        """
        config = {
            "proxy": f"http://127.0.0.1:{proxy_port}",
            "description": "将此 proxy 配置到 auto_agent/config.yaml 的 deep_hunt.proxy 字段",
            "config_yaml_snippet": {
                "deep_hunt": {"proxy": f"http://127.0.0.1:{proxy_port}"},
                "stealth_http": {"proxy": f"http://127.0.0.1:{proxy_port}"},
            },
            "caido_download": "https://caido.io/download",
            "usage": [
                "1. 下载并启动 Caido",
                f"2. 确认 Caido 监听在 127.0.0.1:{proxy_port}",
                "3. 在 config.yaml 的 deep_hunt.proxy 填入 http://127.0.0.1:8080",
                "4. 运行 auto_hunt.py，所有请求会被 Caido 记录",
                "5. 在 Caido UI 中查看/重放/修改请求",
            ],
        }
        return config

    def import_har_to_leads(self, har_file: str) -> list:
        """
        从 Caido/Burp 导出的 HAR 文件中提取 API 端点，
        转为 lead_collector 可用的格式。
        """
        if not os.path.exists(har_file):
            return []

        try:
            data = json.loads(Path(har_file).read_text())
            entries = data.get("log", {}).get("entries", [])
        except (json.JSONDecodeError, KeyError):
            return []

        endpoints = []
        seen = set()

        for entry in entries:
            request = entry.get("request", {})
            url = request.get("url", "")
            method = request.get("method", "GET")

            # 跳过静态资源
            if any(ext in url.lower() for ext in [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"]):
                continue

            key = f"{method}|{url.split('?')[0]}"
            if key in seen:
                continue
            seen.add(key)

            endpoints.append({
                "url": url,
                "method": method,
                "headers": {h["name"]: h["value"] for h in request.get("headers", [])[:10]},
                "status": entry.get("response", {}).get("status", 0),
                "content_type": entry.get("response", {}).get("content", {}).get("mimeType", ""),
            })

        return endpoints

    # ═══════════════════════════════════════════════════════════
    # 4. mitmproxy 集成（替代 Burp MCP）
    # ═══════════════════════════════════════════════════════════

    def generate_mitmproxy_script(self, output_file: str = None) -> str:
        """
        生成 mitmproxy 脚本，自动记录所有 API 请求到 JSON 文件。
        用法: mitmproxy -s generated_script.py
        """
        output_file = output_file or os.path.join(self.results_dir, "mitm_capture.py")

        script = '''"""
mitmproxy 自动记录脚本 — 替代 Burp MCP
用法: mitmproxy -s mitm_capture.py
     mitmweb -s mitm_capture.py  (带 Web UI)

所有 API 请求会被记录到 ~/.bai-agent/tool_results/captured_requests.json
"""
import json
import os
from pathlib import Path
from mitmproxy import http

CAPTURE_FILE = os.path.expanduser("~/.bai-agent/tool_results/captured_requests.json")
STATIC_EXTS = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map"}

captured = []

def response(flow: http.HTTPFlow):
    """拦截每个响应"""
    url = flow.request.pretty_url
    path_lower = flow.request.path.lower()

    # 跳过静态资源
    if any(path_lower.endswith(ext) for ext in STATIC_EXTS):
        return

    entry = {
        "method": flow.request.method,
        "url": url,
        "path": flow.request.path,
        "status": flow.response.status_code if flow.response else 0,
        "request_headers": dict(flow.request.headers),
        "request_body": flow.request.get_text()[:1000] if flow.request.content else "",
        "response_headers": dict(flow.response.headers) if flow.response else {},
        "response_body_preview": flow.response.get_text()[:500] if flow.response and flow.response.content else "",
        "content_type": flow.response.headers.get("content-type", "") if flow.response else "",
    }

    captured.append(entry)

    # 每 10 个请求写入文件
    if len(captured) % 10 == 0:
        _save()

def done():
    """mitmproxy 退出时保存"""
    _save()

def _save():
    Path(os.path.dirname(CAPTURE_FILE)).mkdir(parents=True, exist_ok=True)
    Path(CAPTURE_FILE).write_text(json.dumps(captured, indent=2, ensure_ascii=False))
'''
        Path(output_file).write_text(script)
        return output_file

    def load_mitmproxy_captures(self) -> list:
        """加载 mitmproxy 抓取的请求"""
        capture_file = os.path.join(self.results_dir, "captured_requests.json")
        if not os.path.exists(capture_file):
            return []
        try:
            return json.loads(Path(capture_file).read_text())
        except (json.JSONDecodeError, OSError):
            return []

    # ═══════════════════════════════════════════════════════════
    # 5. Amass — 深度资产发现
    # ═══════════════════════════════════════════════════════════

    def run_amass(self, target: str, output_file: str = None) -> dict:
        """
        运行 Amass 做深度子域名枚举。
        比 subfinder 更全面，但更慢。
        """
        if not shutil.which("amass"):
            return {"error": "amass 未安装。安装: go install github.com/owasp-amass/amass/v4/...@master"}

        output_file = output_file or os.path.join(self.results_dir, f"amass_{target}.txt")

        cmd = f"amass enum -passive -d {target} -o {output_file} -timeout 5 2>&1"
        result = self._run_cmd(cmd, timeout=360)

        subdomains = []
        if os.path.exists(output_file):
            subdomains = [l.strip() for l in Path(output_file).read_text().splitlines() if l.strip()]

        return {
            "tool": "amass",
            "target": target,
            "subdomains": subdomains,
            "count": len(subdomains),
            "output_file": output_file,
        }

    # ═══════════════════════════════════════════════════════════
    # 6. SecLists 字典管理
    # ═══════════════════════════════════════════════════════════

    def ensure_seclists(self, install_dir: str = None) -> str:
        """确保 SecLists 字典已下载"""
        install_dir = install_dir or os.path.expanduser("~/SecLists")

        if os.path.exists(os.path.join(install_dir, "Discovery")):
            return install_dir

        # 尝试常见位置
        for path in ["/usr/share/seclists", "/opt/seclists", os.path.expanduser("~/SecLists")]:
            if os.path.exists(os.path.join(path, "Discovery")):
                return path

        return ""

    def get_wordlist(self, category: str) -> str:
        """获取推荐字典路径"""
        seclists = self.ensure_seclists()
        if not seclists:
            return ""

        wordlists = {
            "api_endpoints": f"{seclists}/Discovery/Web-Content/api/api-endpoints.txt",
            "directories": f"{seclists}/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "parameters": f"{seclists}/Discovery/Web-Content/burp-parameter-names.txt",
            "subdomains": f"{seclists}/Discovery/DNS/subdomains-top1million-5000.txt",
            "passwords": f"{seclists}/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
            "usernames": f"{seclists}/Usernames/Names/names.txt",
        }
        return wordlists.get(category, "")

    # ═══════════════════════════════════════════════════════════
    # 7. kiterunner — API 路由暴力发现
    # ═══════════════════════════════════════════════════════════

    def run_kiterunner(self, target: str, wordlist: str = None,
                       output_file: str = None) -> dict:
        """
        运行 kiterunner 做 API 路由发现。比 ffuf 更适合 API。
        安装: go install github.com/assetnote/kiterunner/cmd/kr@latest
        """
        if not shutil.which("kr"):
            return {"error": "kiterunner 未安装。go install github.com/assetnote/kiterunner/cmd/kr@latest"}

        output_file = output_file or os.path.join(self.results_dir, "kiterunner.txt")
        wl_flag = f"-w {wordlist}" if wordlist else ""
        cmd = f"kr scan {target} {wl_flag} --fail-status-codes 404,403 -o text 2>&1 | head -100 | tee {output_file}"
        result = self._run_cmd(cmd, timeout=180)

        endpoints = []
        if os.path.exists(output_file):
            endpoints = [l.strip() for l in Path(output_file).read_text().splitlines() if l.strip() and "/" in l]

        return {"tool": "kiterunner", "target": target, "endpoints": endpoints[:50], "count": len(endpoints)}

    # ═══════════════════════════════════════════════════════════
    # 8. jwt_tool — JWT 深度测试
    # ═══════════════════════════════════════════════════════════

    def run_jwt_tool(self, token: str, target_url: str = "") -> dict:
        """
        JWT 安全测试: alg:none, RS256→HS256, kid injection, jku spoofing
        安装: git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool
        """
        jwt_path = None
        for p in [os.path.expanduser("~/jwt_tool/jwt_tool.py"), "/opt/jwt_tool/jwt_tool.py"]:
            if os.path.exists(p):
                jwt_path = p
                break
        if not jwt_path:
            return {"error": "jwt_tool 未安装。git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool"}

        target_flag = f"-t {target_url}" if target_url else ""
        cmd = f"python3 {jwt_path} {token} -M at {target_flag} 2>&1 | head -50"
        result = self._run_cmd(cmd, timeout=60)

        findings = [l for l in result.get("output", "").splitlines()
                    if any(k in l.upper() for k in ["VULNERABLE", "EXPLOITABLE", "FORGED", "ACCEPTED"])]
        return {"tool": "jwt_tool", "findings": findings, "vulnerable": len(findings) > 0}

    # ═══════════════════════════════════════════════════════════
    # 9. Schemathesis — OpenAPI/Swagger 自动 Fuzz
    # ═══════════════════════════════════════════════════════════

    def run_schemathesis(self, spec_url: str, base_url: str = None, auth_header: str = None) -> dict:
        """
        对 OpenAPI spec 做自动 fuzz（所有端点+所有参数+边界值）。
        安装: pip install schemathesis
        """
        st_cmd = shutil.which("st") or shutil.which("schemathesis")
        if not st_cmd:
            return {"error": "schemathesis 未安装。pip install schemathesis"}

        output_file = os.path.join(self.results_dir, "schemathesis.txt")
        auth_flag = f'-H "Authorization: {auth_header}"' if auth_header else ""
        base_flag = f"--base-url {base_url}" if base_url else ""

        cmd = (f"{st_cmd} run {spec_url} {base_flag} {auth_flag} "
               f"--checks all --max-response-time 5000 --hypothesis-max-examples 50 "
               f"2>&1 | tee {output_file}")
        result = self._run_cmd(cmd, timeout=300)

        failures = [l.strip() for l in result.get("output", "").splitlines()
                    if "FAILED" in l or "ERROR" in l or "5xx" in l.lower()]
        return {"tool": "schemathesis", "spec_url": spec_url, "failures": failures[:20], "has_issues": bool(failures)}

    # ═══════════════════════════════════════════════════════════
    # 10. MobSF — 移动应用静态分析
    # ═══════════════════════════════════════════════════════════

    def run_mobsf(self, apk_path: str, mobsf_url: str = "http://localhost:8000") -> dict:
        """
        调用 MobSF API 做 APK 静态分析。
        启动: docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf
        """
        import requests
        api_key = os.environ.get("MOBSF_API_KEY", "")
        if not api_key:
            return {"error": "需要 MOBSF_API_KEY。启动 MobSF 后在 REST API 页面获取"}

        headers = {"Authorization": api_key}
        with open(apk_path, "rb") as f:
            resp = requests.post(f"{mobsf_url}/api/v1/upload", files={"file": f}, headers=headers, timeout=120)
        if resp.status_code != 200:
            return {"error": f"Upload failed: {resp.text[:100]}"}

        scan_hash = resp.json().get("hash", "")
        requests.post(f"{mobsf_url}/api/v1/scan", data={"hash": scan_hash}, headers=headers, timeout=300)
        report = requests.post(f"{mobsf_url}/api/v1/report_json", data={"hash": scan_hash}, headers=headers, timeout=60).json()

        return {
            "tool": "mobsf", "package": report.get("package_name", ""),
            "score": report.get("security_score", ""),
            "urls": report.get("urls", [])[:20],
            "secrets": report.get("secrets", [])[:10],
            "api_calls": report.get("api", {}).get("api_calls", [])[:20],
        }

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _run_cmd(self, cmd: str, timeout: int = 120) -> dict:
        """执行命令"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                env={**os.environ, "PATH": f"{os.path.expanduser('~/go/bin')}:{os.environ.get('PATH', '')}"}
            )
            return {
                "success": result.returncode == 0,
                "output": (result.stdout + result.stderr)[:5000],
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": f"Timeout after {timeout}s", "returncode": -1}
        except Exception as e:
            return {"success": False, "output": str(e), "returncode": -1}

    def check_tools(self) -> dict:
        """检查所有集成工具的安装状态"""
        tools = {
            "slither": {"installed": bool(shutil.which("slither")), "install": "pip install slither-analyzer"},
            "semgrep": {"installed": bool(shutil.which("semgrep")), "install": "pip install semgrep"},
            "amass": {"installed": bool(shutil.which("amass")), "install": "go install github.com/owasp-amass/amass/v4/...@master"},
            "caido": {"installed": os.path.exists(os.path.expanduser("~/caido")) or shutil.which("caido"), "install": "https://caido.io/download"},
            "mitmproxy": {"installed": bool(shutil.which("mitmproxy")), "install": "pip install mitmproxy"},
            "ffuf": {"installed": bool(shutil.which("ffuf")), "install": "go install github.com/ffuf/ffuf/v2@latest"},
            "seclists": {"installed": bool(self.ensure_seclists()), "install": "git clone https://github.com/danielmiessler/SecLists ~/SecLists"},
            "kiterunner": {"installed": bool(shutil.which("kr")), "install": "go install github.com/assetnote/kiterunner/cmd/kr@latest"},
            "jwt_tool": {"installed": os.path.exists(os.path.expanduser("~/jwt_tool/jwt_tool.py")), "install": "git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool"},
            "schemathesis": {"installed": bool(shutil.which("st") or shutil.which("schemathesis")), "install": "pip install schemathesis"},
            "mobsf": {"installed": bool(os.environ.get("MOBSF_API_KEY")), "install": "docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf"},
        }
        return tools
