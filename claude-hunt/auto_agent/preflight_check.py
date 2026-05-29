#!/usr/bin/env python3
"""
Preflight Check — 运行前环境检查

在启动 auto_hunt 之前运行，验证所有依赖和配置是否就绪。
一次性告诉你还缺什么，不用跑到一半才报错。

用法:
    python preflight_check.py
    python preflight_check.py --fix  # 尝试自动修复可修复的问题
"""

import os
import sys
import shutil
import subprocess
import importlib
from pathlib import Path


# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
NC = "\033[0m"


def check_mark(ok: bool) -> str:
    return f"{GREEN}✓{NC}" if ok else f"{RED}✗{NC}"


def warn_mark() -> str:
    return f"{YELLOW}⚠{NC}"


class PreflightChecker:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passed = []

    def check_all(self):
        """运行所有检查"""
        print(f"\n{BOLD}{'='*60}{NC}")
        print(f"{BOLD}  Bai Auto-Hunt Agent — Preflight Check{NC}")
        print(f"{BOLD}{'='*60}{NC}\n")

        self._check_python_version()
        self._check_pip_deps()
        self._check_go_tools()
        self._check_config_yaml()
        self._check_api_keys()
        self._check_cookies()
        self._check_target()
        self._check_playwright()

        # 结果汇总
        print(f"\n{BOLD}{'─'*60}{NC}")
        print(f"\n{BOLD}结果汇总:{NC}")
        print(f"  {GREEN}通过: {len(self.passed)}{NC}")
        print(f"  {YELLOW}警告: {len(self.warnings)}{NC}")
        print(f"  {RED}错误: {len(self.errors)}{NC}")

        if self.errors:
            print(f"\n{RED}{BOLD}必须修复的问题:{NC}")
            for err in self.errors:
                print(f"  {RED}✗{NC} {err}")

        if self.warnings:
            print(f"\n{YELLOW}{BOLD}建议修复（不影响基本运行）:{NC}")
            for warn in self.warnings:
                print(f"  {YELLOW}⚠{NC} {warn}")

        if not self.errors:
            print(f"\n{GREEN}{BOLD}环境就绪！可以开始挖洞了。{NC}")
            print(f"\n  运行: python auto_hunt.py --target 你的目标.com")
            if not self._has_cookies():
                print(f"\n  {YELLOW}提示: 建议先抓取登录态:{NC}")
                print(f"    python session_capture.py --url https://目标.com/login --dual")
        else:
            print(f"\n{RED}请先修复以上错误再运行工具。{NC}")
            sys.exit(1)

    def _check_python_version(self):
        v = sys.version_info
        if v.major >= 3 and v.minor >= 10:
            self.passed.append("Python >= 3.10")
            print(f"  {check_mark(True)} Python {v.major}.{v.minor}.{v.micro}")
        elif v.major >= 3 and v.minor >= 8:
            self.warnings.append(f"Python {v.major}.{v.minor} — 建议升级到 3.10+")
            print(f"  {warn_mark()} Python {v.major}.{v.minor} (建议 3.10+)")
        else:
            self.errors.append(f"Python {v.major}.{v.minor} 太旧，需要 3.8+")
            print(f"  {check_mark(False)} Python {v.major}.{v.minor} (需要 3.8+)")

    def _check_pip_deps(self):
        """检查 Python 依赖"""
        deps = {
            "openai": "openai (LLM client)",
            "yaml": "pyyaml (配置文件)",
            "rich": "rich (终端 UI)",
            "requests": "requests (HTTP)",
            "httpx": "httpx (异步 HTTP 引擎)",
        }

        print(f"\n  {BOLD}Python 依赖:{NC}")
        all_ok = True
        missing = []
        for module, desc in deps.items():
            try:
                importlib.import_module(module)
                print(f"    {check_mark(True)} {desc}")
                self.passed.append(desc)
            except ImportError:
                print(f"    {check_mark(False)} {desc}")
                missing.append(module)
                all_ok = False

        if missing:
            fix = "pip install " + " ".join(
                m if m != "yaml" else "pyyaml" for m in missing
            )
            self.errors.append(f"缺少 Python 依赖: {fix}")

    def _check_go_tools(self):
        """检查 Go 安全工具"""
        tools = {
            "subfinder": "子域名枚举",
            "httpx": "存活探测",
            "nuclei": "漏洞扫描",
            "katana": "爬虫",
            "dalfox": "XSS 检测",
            "ffuf": "目录爆破",
        }

        optional_tools = {
            "sqlmap": "SQL 注入",
            "trufflehog": "密钥扫描",
            "gau": "URL 收集",
        }

        print(f"\n  {BOLD}安全工具 (必须):{NC}")
        for tool, desc in tools.items():
            path = shutil.which(tool)
            if path:
                print(f"    {check_mark(True)} {tool} — {desc}")
                self.passed.append(f"{tool}")
            else:
                print(f"    {check_mark(False)} {tool} — {desc}")
                self.errors.append(
                    f"未找到 {tool}。安装: go install github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest"
                    if tool != "dalfox" else
                    f"未找到 {tool}。安装: go install github.com/hahwul/dalfox/v2@latest"
                )

        print(f"\n  {BOLD}安全工具 (可选):{NC}")
        for tool, desc in optional_tools.items():
            path = shutil.which(tool)
            if path:
                print(f"    {check_mark(True)} {tool} — {desc}")
            else:
                print(f"    {warn_mark()} {tool} — {desc} (未安装)")
                self.warnings.append(f"{tool} 未安装，部分功能不可用")

    def _check_config_yaml(self):
        """检查 config.yaml 是否存在"""
        print(f"\n  {BOLD}配置文件:{NC}")
        config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
        if os.path.exists(config_path):
            print(f"    {check_mark(True)} config.yaml 存在")
            self.passed.append("config.yaml")
        else:
            example_path = config_path + ".example"
            if os.path.exists(example_path):
                print(f"    {check_mark(False)} config.yaml 不存在 (有 .example)")
                self.errors.append(
                    f"请复制配置: cp config.yaml.example config.yaml && 编辑填入 Key"
                )
            else:
                print(f"    {check_mark(False)} config.yaml 不存在")
                self.errors.append("缺少 config.yaml")

    def _check_api_keys(self):
        """检查 API Key"""
        print(f"\n  {BOLD}API Key:{NC}")
        has_key = False

        if os.environ.get("DEEPSEEK_API_KEY"):
            print(f"    {check_mark(True)} DEEPSEEK_API_KEY (环境变量)")
            has_key = True
        elif os.environ.get("OPENAI_API_KEY"):
            print(f"    {check_mark(True)} OPENAI_API_KEY (环境变量)")
            has_key = True
        elif os.environ.get("XAI_API_KEY"):
            print(f"    {check_mark(True)} XAI_API_KEY (环境变量)")
            has_key = True
        else:
            # 检查 config.yaml 里的 key
            try:
                import yaml
                config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
                if os.path.exists(config_path):
                    with open(config_path) as f:
                        config = yaml.safe_load(f) or {}
                    key = config.get("llm", {}).get("api_key", "")
                    if key and not key.startswith("sk-你的"):
                        print(f"    {check_mark(True)} LLM API Key (config.yaml)")
                        has_key = True
            except Exception:
                pass

        if not has_key:
            print(f"    {check_mark(False)} 未配置任何 LLM API Key")
            self.errors.append(
                "未配置 LLM API Key。设置环境变量 DEEPSEEK_API_KEY=sk-xxx "
                "或在 config.yaml 的 llm.api_key 中填入"
            )
            self.passed.append("API Key")

    def _check_cookies(self):
        """检查是否配置了登录态"""
        print(f"\n  {BOLD}登录态 (Cookie):{NC}")
        try:
            import yaml
            config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
            if not os.path.exists(config_path):
                print(f"    {warn_mark()} 无法检查（config.yaml 不存在）")
                return

            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

            session_cookie = config.get("session_monitor", {}).get("cookie", "")
            cookie_a = config.get("idor", {}).get("cookie_a", "")
            cookie_b = config.get("idor", {}).get("cookie_b", "")

            if session_cookie:
                print(f"    {check_mark(True)} session_monitor.cookie 已配置")
            else:
                print(f"    {warn_mark()} session_monitor.cookie 未配置")
                self.warnings.append(
                    "未配置主 session cookie — 只能测试公开面，建议运行 "
                    "python session_capture.py --url https://目标/login"
                )

            if cookie_a and cookie_b:
                print(f"    {check_mark(True)} 双账号 cookie 已配置 (IDOR 测试就绪)")
            elif cookie_a or cookie_b:
                print(f"    {warn_mark()} 只配了一个账号的 cookie")
                self.warnings.append("IDOR 测试需要两个账号的 cookie")
            else:
                print(f"    {warn_mark()} 双账号 cookie 未配置")
                self.warnings.append(
                    "未配置双账号 cookie — IDOR 测试不可用。运行: "
                    "python session_capture.py --url https://目标/login --dual"
                )
        except ImportError:
            print(f"    {warn_mark()} 无法检查（需要 pyyaml）")

    def _has_cookies(self) -> bool:
        try:
            import yaml
            config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return bool(config.get("session_monitor", {}).get("cookie", ""))
        except Exception:
            return False

    def _check_target(self):
        """检查目标是否配置"""
        print(f"\n  {BOLD}目标配置:{NC}")
        try:
            import yaml
            config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
            if not os.path.exists(config_path):
                return

            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

            target = config.get("target", {}).get("domain", "")
            if target:
                print(f"    {check_mark(True)} 目标: {target}")
            else:
                print(f"    {warn_mark()} 未在 config.yaml 中配置默认目标")
                print(f"        (可以通过 --target 参数指定)")
        except Exception:
            pass

    def _check_playwright(self):
        """检查 Playwright"""
        print(f"\n  {BOLD}浏览器引擎 (可选):{NC}")
        try:
            import playwright
            # Check if chromium is installed
            result = subprocess.run(
                ["playwright", "install", "--dry-run", "chromium"],
                capture_output=True, text=True, timeout=10
            )
            print(f"    {check_mark(True)} Playwright 已安装")
        except ImportError:
            print(f"    {warn_mark()} Playwright 未安装 (浏览器爬虫/session_capture 不可用)")
            self.warnings.append(
                "Playwright 未安装 — pip install playwright && playwright install chromium"
            )
        except Exception:
            print(f"    {warn_mark()} Playwright 状态未知")


if __name__ == "__main__":
    checker = PreflightChecker()
    checker.check_all()
