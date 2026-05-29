#!/usr/bin/env python3
"""
Recon Pipeline — reconftw 风格一键全流程编排

一条命令完成从信息搜集到漏洞验证的全链路自动化：
  subfinder → amass → httpx → katana → gau → nuclei → 自研模块

特点：
- 阶段化执行（每阶段输出作为下一阶段输入）
- 自动跳过未安装的工具（降级运行）
- 限速 + 代理集成（不影响目标）
- 断点续跑（崩溃后从上次阶段继续）
- 结果自动去重 + 分类存储
- 最终调用 enhanced_scanner 做深度测试

用法：
    python recon_pipeline.py --target example.com
    python recon_pipeline.py --target example.com --deep    # 含深度模块
    python recon_pipeline.py --target example.com --resume  # 断点续跑
    python recon_pipeline.py --target example.com --fast    # 快速模式

    # 作为库：
    from recon_pipeline import ReconPipeline
    pipeline = ReconPipeline(config)
    await pipeline.run("example.com")
"""

import asyncio
import argparse
import json
import os
import sys
import time
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))



# ═══════════════════════════════════════════════════════════════
# 颜色
# ═══════════════════════════════════════════════════════════════
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
MAGENTA = "\033[0;35m"
BOLD = "\033[1m"
DIM = "\033[2m"
NC = "\033[0m"

# 阶段定义
PHASES = [
    "subdomain_enum",      # 1. 子域名枚举
    "dns_resolve",         # 2. DNS 解析 + 去死域名
    "http_probe",          # 3. HTTP 存活探测 + 技术栈
    "url_collect",         # 4. URL/路径收集
    "js_analysis",         # 5. JS 文件分析
    "param_discovery",     # 6. 参数发现
    "vuln_scan",           # 7. 漏洞扫描（nuclei）
    "deep_modules",        # 8. 深度模块（403bypass/SSRF/缓存/Java）
    "report",             # 9. 报告生成
]


class ReconPipeline:
    """reconftw 风格一键全流程编排"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.target = ""
        self.output_dir = ""
        self.start_time = 0
        self.stats = {phase: {"status": "pending", "count": 0, "time": 0} for phase in PHASES}

        # 配置
        self.rate_limit = self.config.get("rate_limit", 3)  # req/s
        self.threads = self.config.get("threads", 5)
        self.timeout = self.config.get("timeout", 120)
        self.proxy = self.config.get("proxy", "")
        self.deep_mode = self.config.get("deep", False)
        self.fast_mode = self.config.get("fast", False)
        self.resume = self.config.get("resume", False)

        # 工具可用性缓存
        self._tools_available: Dict[str, bool] = {}

    # ═══════════════════════════════════════════════════════════════
    # 主入口
    # ═══════════════════════════════════════════════════════════════

    async def run(self, target: str) -> Dict:
        """执行完整 Pipeline"""
        self.target = target
        self.start_time = time.time()
        self.output_dir = self._setup_output_dir(target)

        self._print_banner()
        self._check_tools()

        # 断点续跑：跳过已完成的阶段
        start_phase = 0
        if self.resume:
            start_phase = self._get_resume_point()
            if start_phase > 0:
                print(f"  {CYAN}[*] Resuming from phase {start_phase + 1}: {PHASES[start_phase]}{NC}")

        # 执行各阶段
        for i, phase in enumerate(PHASES):
            if i < start_phase:
                continue
            if phase == "deep_modules" and not self.deep_mode:
                self.stats[phase]["status"] = "skipped"
                continue

            print(f"\n{BOLD}{'━'*60}{NC}")
            print(f"  {MAGENTA}Phase {i+1}/{len(PHASES)}: {phase}{NC}")
            print(f"{'━'*60}")

            phase_start = time.time()
            try:
                await self._run_phase(phase)
                self.stats[phase]["status"] = "done"
                self.stats[phase]["time"] = round(time.time() - phase_start, 1)
                self._save_checkpoint(i)
            except Exception as e:
                self.stats[phase]["status"] = "error"
                print(f"  {RED}[!] Phase {phase} error: {e}{NC}")
                self._save_checkpoint(i)  # 即使失败也保存断点

        # 最终摘要
        total_time = round(time.time() - self.start_time, 1)
        self._print_summary(total_time)

        return {
            "target": target,
            "output_dir": self.output_dir,
            "duration": total_time,
            "stats": self.stats,
        }


    # ═══════════════════════════════════════════════════════════════
    # 各阶段实现
    # ═══════════════════════════════════════════════════════════════

    async def _run_phase(self, phase: str):
        """分派到对应阶段"""
        dispatch = {
            "subdomain_enum": self._phase_subdomains,
            "dns_resolve": self._phase_dns_resolve,
            "http_probe": self._phase_http_probe,
            "url_collect": self._phase_url_collect,
            "js_analysis": self._phase_js_analysis,
            "param_discovery": self._phase_param_discovery,
            "vuln_scan": self._phase_vuln_scan,
            "deep_modules": self._phase_deep_modules,
            "report": self._phase_report,
        }
        handler = dispatch.get(phase)
        if handler:
            await handler()

    # ─── Phase 1: 子域名枚举 ──────────────────────────────────

    async def _phase_subdomains(self):
        """多源子域名枚举"""
        subs_file = f"{self.output_dir}/subdomains/all.txt"
        os.makedirs(f"{self.output_dir}/subdomains", exist_ok=True)

        all_subs = set()

        # subfinder（被动）
        if self._has_tool("subfinder"):
            print(f"  {DIM}[subfinder] 被动枚举...{NC}")
            out = await self._exec(f"subfinder -d {self.target} -silent -all -timeout 30")
            subs = set(out.strip().splitlines())
            all_subs.update(subs)
            print(f"    → {len(subs)} subdomains")

        # amass（被动+轻度主动）
        if self._has_tool("amass") and not self.fast_mode:
            print(f"  {DIM}[amass] 被动枚举...{NC}")
            out = await self._exec(
                f"amass enum -passive -d {self.target} -timeout 3", timeout=200)
            subs = set(s.strip() for s in out.splitlines() if s.strip() and self.target in s)
            all_subs.update(subs)
            print(f"    → {len(subs)} subdomains (amass)")

        # crt.sh（证书透明度）
        print(f"  {DIM}[crt.sh] 证书查询...{NC}")
        out = await self._exec(
            f'curl -sk "https://crt.sh/?q=%25.{self.target}&output=json" | '
            f'jq -r ".[].name_value" 2>/dev/null | sort -u',
            timeout=30)
        if out:
            crt_subs = set(s.strip() for s in out.splitlines()
                          if s.strip() and self.target in s and "*" not in s)
            all_subs.update(crt_subs)
            print(f"    → {len(crt_subs)} subdomains (crt.sh)")

        # 写入文件
        Path(subs_file).write_text("\n".join(sorted(all_subs)))
        self.stats["subdomain_enum"]["count"] = len(all_subs)
        print(f"\n  {GREEN}[+] Total unique subdomains: {len(all_subs)}{NC}")

    # ─── Phase 2: DNS 解析 ────────────────────────────────────

    async def _phase_dns_resolve(self):
        """DNS 解析，去掉无法解析的死域名"""
        subs_file = f"{self.output_dir}/subdomains/all.txt"
        resolved_file = f"{self.output_dir}/subdomains/resolved.txt"

        if not Path(subs_file).exists():
            return

        if self._has_tool("dnsx"):
            print(f"  {DIM}[dnsx] DNS 解析过滤...{NC}")
            out = await self._exec(
                f"dnsx -l {subs_file} -silent -a -resp-only=false -threads {self.threads}",
                timeout=120)
            resolved = set(line.split()[0] for line in out.splitlines() if line.strip())
        else:
            # fallback: 直接用全部子域名
            resolved = set(Path(subs_file).read_text().splitlines())

        Path(resolved_file).write_text("\n".join(sorted(resolved)))
        self.stats["dns_resolve"]["count"] = len(resolved)
        print(f"  {GREEN}[+] Resolved: {len(resolved)} domains{NC}")

    # ─── Phase 3: HTTP 存活探测 ───────────────────────────────

    async def _phase_http_probe(self):
        """HTTP 存活 + 技术栈 + 状态码"""
        resolved_file = f"{self.output_dir}/subdomains/resolved.txt"
        live_file = f"{self.output_dir}/live/httpx_full.txt"
        os.makedirs(f"{self.output_dir}/live", exist_ok=True)

        if not Path(resolved_file).exists():
            return

        if not self._has_tool("httpx"):
            print(f"  {YELLOW}[!] httpx not found, skipping{NC}")
            return

        proxy_arg = f"-proxy {self.proxy}" if self.proxy else ""
        rl = self.rate_limit * 2  # httpx 可以稍快

        print(f"  {DIM}[httpx] 探测存活主机 + 技术栈...{NC}")
        out = await self._exec(
            f"httpx -l {resolved_file} -silent -tech-detect -status-code "
            f"-content-length -title -web-server -cdn "
            f"-threads {self.threads} -rl {rl} {proxy_arg} -timeout 10",
            timeout=300)

        Path(live_file).write_text(out)
        live_count = len([l for l in out.splitlines() if l.strip()])
        self.stats["http_probe"]["count"] = live_count
        print(f"  {GREEN}[+] Live hosts: {live_count}{NC}")

        # 提取技术栈
        techs = set()
        for line in out.splitlines():
            if "[" in line:
                import re
                tech_match = re.findall(r'\[([^\]]+)\]', line)
                for t in tech_match:
                    techs.update(t.split(","))
        if techs:
            tech_file = f"{self.output_dir}/live/tech.txt"
            Path(tech_file).write_text("\n".join(sorted(techs)))
            print(f"    Tech detected: {', '.join(list(techs)[:10])}")

    # ─── Phase 4: URL/路径收集 ────────────────────────────────

    async def _phase_url_collect(self):
        """多源 URL 收集"""
        live_file = f"{self.output_dir}/live/httpx_full.txt"
        urls_dir = f"{self.output_dir}/urls"
        os.makedirs(urls_dir, exist_ok=True)

        all_urls = set()

        # 提取存活域名列表
        live_domains = []
        if Path(live_file).exists():
            for line in Path(live_file).read_text().splitlines():
                parts = line.split()
                if parts:
                    url = parts[0]
                    live_domains.append(url)

        if not live_domains:
            # fallback 到子域名文件
            resolved = f"{self.output_dir}/subdomains/resolved.txt"
            if Path(resolved).exists():
                live_domains = [f"https://{d.strip()}" for d in
                               Path(resolved).read_text().splitlines()[:50]]

        # gau（被动 URL 收集 — Wayback/CommonCrawl/OTX）
        if self._has_tool("gau"):
            print(f"  {DIM}[gau] 被动 URL 收集...{NC}")
            out = await self._exec(f"echo {self.target} | gau --threads 3 --timeout 30",
                                   timeout=120)
            gau_urls = set(u.strip() for u in out.splitlines() if u.strip().startswith("http"))
            all_urls.update(gau_urls)
            print(f"    → {len(gau_urls)} URLs (gau)")

        # katana（主动爬虫）
        if self._has_tool("katana") and live_domains:
            print(f"  {DIM}[katana] 主动爬虫...{NC}")
            # 只爬前20个域名，避免太慢
            targets = "\n".join(live_domains[:20])
            targets_file = f"{self.output_dir}/urls/_katana_input.txt"
            Path(targets_file).write_text(targets)

            depth = 2 if self.fast_mode else 3
            out = await self._exec(
                f"katana -list {targets_file} -d {depth} -silent "
                f"-js-crawl -known-files all -rl {self.rate_limit} "
                f"-timeout 10 -concurrency {self.threads}",
                timeout=300)
            katana_urls = set(u.strip() for u in out.splitlines() if u.strip().startswith("http"))
            all_urls.update(katana_urls)
            print(f"    → {len(katana_urls)} URLs (katana)")

        # waybackurls
        if self._has_tool("waybackurls"):
            print(f"  {DIM}[waybackurls] 历史 URL...{NC}")
            out = await self._exec(f"echo {self.target} | waybackurls", timeout=60)
            wb_urls = set(u.strip() for u in out.splitlines() if u.strip().startswith("http"))
            all_urls.update(wb_urls)
            print(f"    → {len(wb_urls)} URLs (waybackurls)")

        # 写入文件
        all_urls_file = f"{urls_dir}/all.txt"
        Path(all_urls_file).write_text("\n".join(sorted(all_urls)))

        # 分离带参数的 URL
        with_params = [u for u in all_urls if "?" in u and "=" in u]
        Path(f"{urls_dir}/with_params.txt").write_text("\n".join(sorted(with_params)))

        self.stats["url_collect"]["count"] = len(all_urls)
        print(f"\n  {GREEN}[+] Total URLs: {len(all_urls)} ({len(with_params)} with params){NC}")


    # ─── Phase 5: JS 分析 ─────────────────────────────────────

    async def _phase_js_analysis(self):
        """JS 文件提取端点/密钥"""
        urls_file = f"{self.output_dir}/urls/all.txt"
        js_dir = f"{self.output_dir}/js"
        os.makedirs(js_dir, exist_ok=True)

        if not Path(urls_file).exists():
            return

        # 筛选 .js URL
        all_urls = Path(urls_file).read_text().splitlines()
        js_urls = [u for u in all_urls if u.strip().endswith(".js")][:200]

        if not js_urls:
            print(f"  {DIM}No JS files found{NC}")
            return

        Path(f"{js_dir}/js_urls.txt").write_text("\n".join(js_urls))
        print(f"  {DIM}[*] Found {len(js_urls)} JS files{NC}")

        # 用 grep 提取敏感信息
        endpoints = set()
        secrets = []

        for js_url in js_urls[:50]:  # 限制数量
            out = await self._exec(
                f'curl -sk -m 10 "{js_url}" 2>/dev/null', timeout=15)
            if not out:
                continue

            # 提取 API 端点
            import re
            api_patterns = re.findall(
                r'["\']/(api/[^"\'\\s]+|v[0-9]+/[^"\'\\s]+)["\']', out)
            endpoints.update(api_patterns)

            # 提取密钥特征
            secret_patterns = [
                (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{20,})["\']', "API_KEY"),
                (r'(?:AKIA|ASIA)[A-Z0-9]{16}', "AWS_KEY"),
                (r'sk_live_[a-zA-Z0-9]{24,}', "STRIPE_KEY"),
                (r'ghp_[A-Za-z0-9]{36}', "GITHUB_TOKEN"),
            ]
            for pattern, label in secret_patterns:
                matches = re.findall(pattern, out)
                for m in matches:
                    secrets.append(f"[{label}] {js_url}: {m[:30]}...")

        if endpoints:
            Path(f"{js_dir}/endpoints.txt").write_text("\n".join(sorted(endpoints)))
            print(f"    → {len(endpoints)} API endpoints extracted")
        if secrets:
            Path(f"{js_dir}/secrets.txt").write_text("\n".join(secrets))
            print(f"    {RED}→ {len(secrets)} potential secrets found!{NC}")

        self.stats["js_analysis"]["count"] = len(endpoints) + len(secrets)

    # ─── Phase 6: 参数发现 ────────────────────────────────────

    async def _phase_param_discovery(self):
        """参数爆破（arjun）"""
        params_dir = f"{self.output_dir}/params"
        os.makedirs(params_dir, exist_ok=True)

        urls_with_params = f"{self.output_dir}/urls/with_params.txt"
        live_file = f"{self.output_dir}/live/httpx_full.txt"

        # 用 paramspider 被动发现
        if self._has_tool("paramspider"):
            print(f"  {DIM}[paramspider] 被动参数发现...{NC}")
            out = await self._exec(
                f"paramspider -d {self.target} --quiet 2>/dev/null | head -500",
                timeout=60)
            if out.strip():
                Path(f"{params_dir}/paramspider.txt").write_text(out)
                count = len(out.strip().splitlines())
                print(f"    → {count} parameterized URLs")
                self.stats["param_discovery"]["count"] = count

        # 从现有 URL 中提取参数名
        if Path(urls_with_params).exists():
            from urllib.parse import urlparse, parse_qs
            param_names = set()
            for url in Path(urls_with_params).read_text().splitlines()[:500]:
                try:
                    parsed = urlparse(url.strip())
                    params = parse_qs(parsed.query)
                    param_names.update(params.keys())
                except Exception:
                    pass
            if param_names:
                Path(f"{params_dir}/param_names.txt").write_text("\n".join(sorted(param_names)))
                print(f"    → {len(param_names)} unique parameter names")

    # ─── Phase 7: 漏洞扫描 ────────────────────────────────────

    async def _phase_vuln_scan(self):
        """Nuclei 漏洞扫描"""
        live_file = f"{self.output_dir}/live/httpx_full.txt"
        findings_dir = f"{self.output_dir}/findings"
        os.makedirs(findings_dir, exist_ok=True)

        if not self._has_tool("nuclei"):
            print(f"  {YELLOW}[!] nuclei not found, skipping vuln scan{NC}")
            return

        # 提取纯 URL 列表
        targets_file = f"{self.output_dir}/findings/_targets.txt"
        if Path(live_file).exists():
            lines = Path(live_file).read_text().splitlines()
            urls = [line.split()[0] for line in lines if line.strip()]
            Path(targets_file).write_text("\n".join(urls))
        else:
            resolved = f"{self.output_dir}/subdomains/resolved.txt"
            if Path(resolved).exists():
                urls = [f"https://{d.strip()}" for d in
                        Path(resolved).read_text().splitlines()]
                Path(targets_file).write_text("\n".join(urls))
            else:
                return

        proxy_arg = f"-proxy {self.proxy}" if self.proxy else ""

        # 快速模式：只跑 critical + high
        if self.fast_mode:
            severity = "-severity critical,high"
            extra = "-tags cve,rce,sqli,ssrf,lfi,auth-bypass"
        else:
            severity = "-severity critical,high,medium"
            extra = ""

        print(f"  {DIM}[nuclei] 漏洞扫描 ({severity})...{NC}")
        out = await self._exec(
            f"nuclei -l {targets_file} {severity} {extra} "
            f"-rl {self.rate_limit} -c {self.threads} -timeout 10 "
            f"-nc -silent {proxy_arg}",
            timeout=600)

        if out.strip():
            Path(f"{findings_dir}/nuclei.txt").write_text(out)
            vuln_count = len(out.strip().splitlines())
            self.stats["vuln_scan"]["count"] = vuln_count
            print(f"\n  {RED}[!] Nuclei findings: {vuln_count}{NC}")
            # 打印高危
            for line in out.splitlines()[:10]:
                if "critical" in line.lower() or "high" in line.lower():
                    print(f"    {RED}{line[:100]}{NC}")
        else:
            print(f"  {GREEN}[+] No vulnerabilities found by nuclei{NC}")

    # ─── Phase 8: 深度模块 ────────────────────────────────────

    async def _phase_deep_modules(self):
        """调用自研深度模块"""
        print(f"  {DIM}[*] Running deep analysis modules...{NC}")

        try:
            from enhanced_scanner import EnhancedScanner
            config = self.config.copy()
            config.setdefault("attack_surface", {})["history_dir"] = f"{self.output_dir}/attack_surface"
            config.setdefault("report", {})["output_dir"] = f"{self.output_dir}/reports"

            scanner = EnhancedScanner(config)
            results = await scanner.full_scan(
                self.target,
                recon_dir=self.output_dir,
                modules=["attack_surface", "takeover", "cloud", "api", "credentials", "waf"]
            )
            self.stats["deep_modules"]["count"] = sum(
                len(v) for v in results.values() if isinstance(v, list)
            )
        except ImportError:
            print(f"  {YELLOW}[!] enhanced_scanner not available, skipping deep modules{NC}")
        except Exception as e:
            print(f"  {YELLOW}[!] Deep modules error: {e}{NC}")

    # ─── Phase 9: 报告 ────────────────────────────────────────

    async def _phase_report(self):
        """生成最终报告"""
        report_dir = f"{self.output_dir}/reports"
        os.makedirs(report_dir, exist_ok=True)

        # 汇总所有发现
        summary = {
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "output_dir": self.output_dir,
            "phases": self.stats,
        }

        # 读取 nuclei 发现
        nuclei_file = f"{self.output_dir}/findings/nuclei.txt"
        if Path(nuclei_file).exists():
            summary["nuclei_findings"] = Path(nuclei_file).read_text().splitlines()[:50]

        # 读取 JS secrets
        secrets_file = f"{self.output_dir}/js/secrets.txt"
        if Path(secrets_file).exists():
            summary["js_secrets"] = Path(secrets_file).read_text().splitlines()

        # 保存 JSON 摘要
        Path(f"{report_dir}/summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False))

        # 生成 Markdown 报告
        md = self._generate_markdown_report(summary)
        Path(f"{report_dir}/report.md").write_text(md)

        print(f"  {GREEN}[+] Report saved: {report_dir}/report.md{NC}")


    # ═══════════════════════════════════════════════════════════════
    # 工具方法
    # ═══════════════════════════════════════════════════════════════

    async def _exec(self, cmd: str, timeout: int = None) -> str:
        """执行命令并返回 stdout"""
        t = timeout or self.timeout
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ,
                     "PATH": f"{os.path.expanduser('~/go/bin')}:{os.environ.get('PATH', '')}"}
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=t)
            return stdout.decode(errors="ignore")
        except asyncio.TimeoutError:
            return ""
        except Exception:
            return ""

    def _has_tool(self, name: str) -> bool:
        """检查工具是否可用"""
        if name not in self._tools_available:
            self._tools_available[name] = shutil.which(name) is not None or \
                shutil.which(os.path.expanduser(f"~/go/bin/{name}")) is not None
        return self._tools_available[name]

    def _check_tools(self):
        """检查所有工具可用性"""
        tools = ["subfinder", "amass", "httpx", "nuclei", "katana",
                 "gau", "waybackurls", "dnsx", "paramspider", "arjun"]
        available = [t for t in tools if self._has_tool(t)]
        missing = [t for t in tools if not self._has_tool(t)]

        print(f"  {GREEN}Tools available: {', '.join(available)}{NC}")
        if missing:
            print(f"  {YELLOW}Tools missing (will skip): {', '.join(missing)}{NC}")

    def _setup_output_dir(self, target: str) -> str:
        """创建输出目录"""
        base = os.path.expanduser(self.config.get("output_base", "~/.bai-agent/recon"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_")
        output_dir = f"{base}/{safe_target}/{timestamp}"
        os.makedirs(output_dir, exist_ok=True)

        # 创建 latest 软链接
        latest_link = f"{base}/{safe_target}/latest"
        if os.path.islink(latest_link):
            os.unlink(latest_link)
        try:
            os.symlink(output_dir, latest_link)
        except OSError:
            pass

        return output_dir

    def _save_checkpoint(self, phase_index: int):
        """保存断点"""
        checkpoint = {"phase": phase_index, "target": self.target,
                      "output_dir": self.output_dir, "time": time.time()}
        cp_file = f"{self.output_dir}/.checkpoint.json"
        Path(cp_file).write_text(json.dumps(checkpoint))

    def _get_resume_point(self) -> int:
        """获取断点续跑位置"""
        # 查找 latest 目录下的 checkpoint
        base = os.path.expanduser(self.config.get("output_base", "~/.bai-agent/recon"))
        safe_target = self.target.replace(".", "_").replace("/", "_")
        latest = f"{base}/{safe_target}/latest"

        if os.path.islink(latest):
            cp_file = f"{os.readlink(latest)}/.checkpoint.json"
            if os.path.exists(cp_file):
                data = json.loads(Path(cp_file).read_text())
                self.output_dir = data.get("output_dir", self.output_dir)
                return data.get("phase", 0) + 1  # 从下一个阶段开始
        return 0

    def _print_banner(self):
        """打印 Banner"""
        mode = "FAST" if self.fast_mode else "DEEP" if self.deep_mode else "NORMAL"
        print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║           BAI RECON PIPELINE v1.0                        ║
║     reconftw-style automated reconnaissance              ║
╠══════════════════════════════════════════════════════════╣
║  Target:  {self.target:<46s} ║
║  Mode:    {mode:<46s} ║
║  Output:  {self.output_dir[-44:]:<46s}║
║  Rate:    {self.rate_limit} req/s | Threads: {self.threads:<26s}║
╚══════════════════════════════════════════════════════════╝{NC}
""")

    def _print_summary(self, total_time: float):
        """打印最终摘要"""
        print(f"""
{BOLD}{'═'*60}{NC}
  {BOLD}RECON PIPELINE COMPLETE{NC}
{'═'*60}
  Target:   {self.target}
  Duration: {total_time:.0f}s ({total_time/60:.1f} min)
  Output:   {self.output_dir}
{'─'*60}""")
        for phase, info in self.stats.items():
            status = info["status"]
            count = info["count"]
            t = info["time"]
            if status == "done":
                icon = f"{GREEN}✓{NC}"
            elif status == "skipped":
                icon = f"{DIM}○{NC}"
            elif status == "error":
                icon = f"{RED}✗{NC}"
            else:
                icon = f"{DIM}·{NC}"
            print(f"  {icon} {phase:<20s} {count:>6} items  {t:>5.1f}s")
        print(f"{'═'*60}\n")

    def _generate_markdown_report(self, summary: Dict) -> str:
        """生成 Markdown 摘要报告"""
        lines = [
            f"# Recon Report: {summary['target']}",
            f"\n**Date:** {summary['scan_time']}",
            f"**Output:** `{summary['output_dir']}`\n",
            "## Phase Results\n",
            "| Phase | Items | Status |",
            "|-------|-------|--------|",
        ]
        for phase, info in summary["phases"].items():
            lines.append(f"| {phase} | {info['count']} | {info['status']} |")

        if summary.get("nuclei_findings"):
            lines.append("\n## Vulnerabilities (Nuclei)\n")
            lines.append("```")
            for f in summary["nuclei_findings"][:20]:
                lines.append(f)
            lines.append("```")

        if summary.get("js_secrets"):
            lines.append("\n## Secrets Found in JS\n")
            lines.append("```")
            for s in summary["js_secrets"][:10]:
                lines.append(s)
            lines.append("```")

        lines.append(f"\n---\n*Generated by Bai Recon Pipeline*")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Bai Recon Pipeline — 一键全流程自动化侦察",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_pipeline.py --target example.com
  python recon_pipeline.py --target example.com --deep
  python recon_pipeline.py --target example.com --fast
  python recon_pipeline.py --target example.com --resume
  python recon_pipeline.py --target example.com --proxy socks5://127.0.0.1:1080
        """)
    parser.add_argument("--target", "-t", required=True, help="目标域名")
    parser.add_argument("--deep", "-d", action="store_true", help="深度模式（含 403bypass/SSRF/缓存/Java）")
    parser.add_argument("--fast", "-f", action="store_true", help="快速模式（跳过慢扫描）")
    parser.add_argument("--resume", "-r", action="store_true", help="断点续跑")
    parser.add_argument("--proxy", "-p", help="代理 (socks5://ip:port)")
    parser.add_argument("--rate", type=int, default=3, help="限速 req/s (默认 3)")
    parser.add_argument("--threads", type=int, default=5, help="线程数 (默认 5)")
    parser.add_argument("--output", "-o", help="输出目录")

    args = parser.parse_args()

    config = {
        "rate_limit": args.rate,
        "threads": args.threads,
        "proxy": args.proxy or "",
        "deep": args.deep,
        "fast": args.fast,
        "resume": args.resume,
    }
    if args.output:
        config["output_base"] = args.output

    pipeline = ReconPipeline(config)
    asyncio.run(pipeline.run(args.target))


if __name__ == "__main__":
    main()
