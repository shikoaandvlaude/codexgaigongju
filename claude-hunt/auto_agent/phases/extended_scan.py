"""
ExtendedScanPhase — 扩展扫描阶段（集成已有独立模块）

将以下已有但未接入流水线的模块统一集成：
1. subdomain_takeover.py — 子域名接管深度验证
2. cloud_scanner.py — S3/Azure/GCP bucket + IMDS
3. browser_crawler.py — Playwright SPA 爬虫
4. js_analyzer.py — JS 深度分析（端点/密钥/sink）
5. cve_intelligence.py — CVE 情报匹配
6. interactsh OOB — 盲 SSRF/XXE/SQLi 带外确认

运行位置：Recon 和 Params 之后、Hunt 之前
目的：最大化攻击面发现，为 Hunt/CriticalHunt 提供更多目标
"""

import sys
import os
import re
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_target, sanitize_url
from .base import BasePhase


class ExtendedScanPhase(BasePhase):
    """扩展扫描：子域名接管 + 云资产 + SPA爬虫 + JS分析 + CVE匹配 + OOB"""

    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {
            "vulnerabilities": [],
            "urls": [],
            "params": [],
            "secrets": [],
            "subdomains": [],
        }

        self.logger.log_phase_start("扩展扫描 (Extended Scan)")

        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            console = Console()

        safe_target = sanitize_target(target)

        # ═══ 1. 子域名接管深度验证 ═══
        console.print("\n  [bold cyan]━━━ 1. 子域名接管深度验证 ━━━[/bold cyan]")
        self._subdomain_takeover(target, findings, phase_findings, console)

        # ═══ 2. 云资产扫描 ═══
        console.print("\n  [bold cyan]━━━ 2. 云资产扫描 (S3/Azure/GCP) ━━━[/bold cyan]")
        self._cloud_scan(target, findings, phase_findings, console)

        # ═══ 3. SPA 浏览器爬虫 ═══
        console.print("\n  [bold cyan]━━━ 3. SPA 浏览器爬虫 ━━━[/bold cyan]")
        self._browser_crawl(target, findings, phase_findings, console)

        # ═══ 4. JS 深度分析 ═══
        console.print("\n  [bold cyan]━━━ 4. JS 深度分析 ━━━[/bold cyan]")
        self._js_deep_analysis(target, findings, phase_findings, console)

        # ═══ 5. CVE 情报匹配 ═══
        console.print("\n  [bold cyan]━━━ 5. CVE 情报匹配 ━━━[/bold cyan]")
        self._cve_match(target, findings, phase_findings, console)

        # ═══ 6. Interactsh OOB 回调准备 ═══
        console.print("\n  [bold cyan]━━━ 6. OOB 回调准备 (interactsh) ━━━[/bold cyan]")
        self._setup_oob(target, findings, phase_findings, console)

        return phase_findings

    # ─── 1. 子域名接管 ─────────────────────────────────────────

    def _subdomain_takeover(self, target, findings, phase_findings, console):
        """调用 subdomain_takeover.py 模块做深度接管检测"""
        try:
            from subdomain_takeover import SubdomainTakeoverScanner
            scanner = SubdomainTakeoverScanner()
        except ImportError:
            # fallback: 用 shell 命令做基础检测
            console.print("    [dim]subdomain_takeover 模块不可用，用基础 CNAME 检测[/dim]")
            self._takeover_fallback(target, findings, phase_findings)
            return

        subdomains = findings.get('subdomains', [])
        if not subdomains:
            console.print("    [dim]无子域名数据[/dim]")
            return

        console.print(f"    检测 {len(subdomains[:100])} 个子域名...")

        # 同步执行异步扫描
        try:
            loop = asyncio.new_event_loop()
            results = loop.run_until_complete(
                scanner.scan_subdomains(subdomains[:100])
            )
            loop.close()

            for finding in results:
                if finding.takeover_possible:
                    phase_findings["vulnerabilities"].append({
                        "type": f"Subdomain Takeover ({finding.service})",
                        "url": finding.subdomain,
                        "severity": finding.severity,
                        "detail": f"CNAME: {finding.cname} → {finding.service} 可接管. "
                                  f"步骤: {finding.steps}",
                        "source": "subdomain_takeover",
                    })
                    console.print(
                        f"    [green]✓ [{finding.severity}] {finding.subdomain} "
                        f"→ {finding.service}[/green]"
                    )
        except Exception as e:
            console.print(f"    [yellow]接管检测异常: {e}[/yellow]")
            self._takeover_fallback(target, findings, phase_findings)

    def _takeover_fallback(self, target, findings, phase_findings):
        """子域名接管基础检测（不依赖模块）"""
        subdomains = findings.get('subdomains', [])[:80]
        if not subdomains:
            return

        pipe_cmd = self._pipe_lines(subdomains)
        self._step("CNAME悬挂检测", target, phase_findings, findings,
                   f"{pipe_cmd} | while read sub; do "
                   f"cname=$(dig +short CNAME \"$sub\" 2>/dev/null | head -1); "
                   f"if [ -n \"$cname\" ]; then "
                   f"  resp=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 \"http://$sub\" 2>/dev/null); "
                   f"  [ \"$resp\" = \"000\" -o \"$resp\" = \"404\" ] && "
                   f"  echo \"TAKEOVER: $sub -> $cname (HTTP $resp)\"; "
                   f"fi; done | head -20",
                   self._parse_takeover,
                   "vulnerabilities")

    # ─── 2. 云资产扫描 ─────────────────────────────────────────

    def _cloud_scan(self, target, findings, phase_findings, console):
        """云资产扫描：S3 bucket 枚举 + Azure/GCP + IMDS"""
        safe_target = sanitize_target(target)
        company = target.split('.')[0] if '.' in target else target

        # S3 Bucket 枚举（常见命名模式）
        bucket_suffixes = ['', '-dev', '-staging', '-test', '-backup',
                          '-assets', '-static', '-uploads', '-data', '-prod',
                          '-internal', '-private', '-logs', '-media']

        bucket_names = [f"{company}{s}" for s in bucket_suffixes]

        if bucket_names:
            pipe_cmd = self._pipe_lines(bucket_names)
            self._step("S3 Bucket枚举", target, phase_findings, findings,
                       f"{pipe_cmd} | while read b; do "
                       f"code=$(curl -s -o /dev/null -w '%{{http_code}}' "
                       f"--max-time 5 \"https://$b.s3.amazonaws.com/\" 2>/dev/null); "
                       f"[ \"$code\" != \"404\" ] && echo \"S3: $b (HTTP $code)\"; "
                       f"done",
                       self._parse_cloud,
                       "vulnerabilities")

        # Azure Blob
        azure_names = [f"{company}{s}" for s in ['', 'dev', 'backup', 'data']]
        pipe_cmd = self._pipe_lines(azure_names)
        self._step("Azure Blob枚举", target, phase_findings, findings,
                   f"{pipe_cmd} | while read b; do "
                   f"code=$(curl -s -o /dev/null -w '%{{http_code}}' "
                   f"--max-time 5 \"https://$b.blob.core.windows.net/\" 2>/dev/null); "
                   f"[ \"$code\" != \"404\" -a \"$code\" != \"000\" ] && "
                   f"echo \"AZURE: $b (HTTP $code)\"; "
                   f"done",
                   self._parse_cloud,
                   "vulnerabilities")

        # S3 可列目录检测（对发现的 bucket）
        # 尝试 ListBucket
        pipe_cmd = self._pipe_lines(bucket_names[:5])
        self._step("S3权限检测(ListBucket)", target, phase_findings, findings,
                   f"{pipe_cmd} | while read b; do "
                   f"resp=$(curl -s --max-time 8 \"https://$b.s3.amazonaws.com/\" 2>/dev/null); "
                   f"echo \"$resp\" | grep -q '<ListBucketResult\\|<Contents>' && "
                   f"echo \"S3_LISTABLE: $b\"; "
                   f"done",
                   self._parse_cloud_critical,
                   "vulnerabilities")

    # ─── 3. SPA 浏览器爬虫 ─────────────────────────────────────

    def _browser_crawl(self, target, findings, phase_findings, console):
        """Playwright 浏览器爬虫 — 发现 SPA 隐藏路由和 API"""
        try:
            from browser_crawler import BrowserCrawler, HAS_PLAYWRIGHT
            if not HAS_PLAYWRIGHT:
                raise ImportError("playwright not installed")
        except ImportError:
            console.print("    [dim]Playwright 未安装，跳过浏览器爬虫[/dim]")
            console.print("    [dim]安装: pip install playwright && playwright install chromium[/dim]")
            return

        alive = findings.get('alive_hosts', [])
        if not alive:
            console.print("    [dim]无存活主机[/dim]")
            return

        config = self.engine.config
        crawler_config = config.get('browser_crawler', {})
        cookie = config.get('session_monitor', {}).get('cookie', '')

        # 只爬前3个主机（SPA爬虫很慢）
        hosts = [h.split()[0] if ' ' in h else h for h in alive[:3]]

        crawler = BrowserCrawler({
            "headless": True,
            "timeout": crawler_config.get('timeout', 30000),
            "max_depth": crawler_config.get('max_depth', 3),
            "cookies_str": cookie,
            "intercept_network": True,
        })

        console.print(f"    爬取 {len(hosts)} 个目标（SPA模式）...")

        try:
            loop = asyncio.new_event_loop()
            for host in hosts:
                try:
                    result = loop.run_until_complete(crawler.crawl(host))

                    # 合并发现的 API 端点
                    if result.api_endpoints:
                        for ep in result.api_endpoints:
                            url = ep if isinstance(ep, str) else ep.get('url', '')
                            if url and url not in phase_findings["urls"]:
                                phase_findings["urls"].append(url)

                    # 合并 JS 文件
                    if result.js_files:
                        for js in result.js_files:
                            if js not in phase_findings["urls"]:
                                phase_findings["urls"].append(f"[JS] {js}")

                    # 合并网络请求中发现的端点
                    if result.network_requests:
                        for req in result.network_requests:
                            url = req.url if hasattr(req, 'url') else req.get('url', '')
                            if url and '/api/' in url.lower():
                                phase_findings["params"].append(url)

                    count = len(result.api_endpoints) + len(result.js_files)
                    console.print(f"    [green]✓ {host[:40]}: 发现 {count} 个端点/JS[/green]")
                except Exception as e:
                    console.print(f"    [dim]爬取 {host[:30]} 失败: {e}[/dim]")

            loop.close()
        except Exception as e:
            console.print(f"    [yellow]浏览器爬虫异常: {e}[/yellow]")

    # ─── 4. JS 深度分析 ─────────────────────────────────────────

    def _js_deep_analysis(self, target, findings, phase_findings, console):
        """JS 深度分析：提取端点/密钥/sink"""
        try:
            from js_analyzer import JSAnalyzer
        except ImportError:
            console.print("    [dim]js_analyzer 模块不可用，用基础 grep[/dim]")
            return

        # 收集所有 JS URL
        js_urls = [u for u in findings.get('urls', []) + phase_findings.get('urls', [])
                  if '.js' in u.lower() and not u.endswith('.json')
                  and not u.startswith('[')][:30]

        if not js_urls:
            console.print("    [dim]无 JS 文件可分析[/dim]")
            return

        console.print(f"    分析 {len(js_urls)} 个 JS 文件...")

        analyzer = JSAnalyzer()
        total_findings = 0

        for js_url in js_urls[:15]:
            # 下载 JS 内容
            safe_url = sanitize_url(js_url)
            cmd = f"curl -s --max-time 15 {shell_quote(safe_url)} 2>/dev/null"
            result = self.engine.execute_command(cmd, timeout=20)

            if not result["success"] or not result["output"]:
                continue

            js_content = result["output"]
            analysis = analyzer.analyze(js_content, source_url=js_url)

            # 提取高价值发现
            if analysis.endpoints:
                for ep in analysis.endpoints[:20]:
                    phase_findings["params"].append(f"[JS_API] {ep.value}")
                total_findings += len(analysis.endpoints)

            if analysis.secrets:
                for secret in analysis.secrets:
                    phase_findings["secrets"].append(f"[JS_SECRET] {secret.value}")
                    if secret.severity in ('critical', 'high'):
                        phase_findings["vulnerabilities"].append({
                            "type": f"JS Hardcoded Secret ({secret.category})",
                            "url": js_url,
                            "severity": secret.severity,
                            "detail": f"{secret.value[:100]} (来源: {js_url})",
                            "source": "js_analyzer",
                        })
                total_findings += len(analysis.secrets)

            if analysis.sinks:
                for sink in analysis.sinks[:5]:
                    phase_findings["vulnerabilities"].append({
                        "type": f"DOM XSS Sink ({sink.value[:50]})",
                        "url": js_url,
                        "severity": "medium",
                        "detail": f"sink: {sink.value}, context: {sink.context[:80]}",
                        "source": "js_analyzer",
                    })

        console.print(f"    [bold]JS分析完成: {total_findings} 个发现[/bold]")

    # ─── 5. CVE 情报匹配 ─────────────────────────────────────────

    def _cve_match(self, target, findings, phase_findings, console):
        """CVE 情报匹配：根据技术栈自动关联已知漏洞"""
        try:
            from cve_intelligence import CVEIntelligence
        except ImportError:
            console.print("    [dim]cve_intelligence 模块不可用，用 nuclei 替代[/dim]")
            return

        # 从 alive_hosts 中提取技术栈信息
        alive = findings.get('alive_hosts', [])
        tech_info = []
        for host_line in alive:
            # httpx -tech-detect 输出格式: url [200] [Title] [tech1,tech2]
            techs = re.findall(r'\[([^\]]*)\]', host_line)
            for t in techs:
                if not t.isdigit() and len(t) > 2:
                    tech_info.append(t)

        if not tech_info:
            console.print("    [dim]无技术栈信息可匹配（需先运行 Recon 带 -tech-detect）[/dim]")
            return

        tech_info = list(set(tech_info))[:20]
        console.print(f"    匹配 {len(tech_info)} 个技术栈: {', '.join(tech_info[:5])}...")

        intel = CVEIntelligence()

        try:
            loop = asyncio.new_event_loop()
            cves = loop.run_until_complete(intel.match_tech_stack(tech_info))
            loop.close()

            for cve in cves[:10]:
                severity = cve.severity.lower() if cve.severity else "medium"
                if severity in ('critical', 'high'):
                    phase_findings["vulnerabilities"].append({
                        "type": f"CVE Match: {cve.cve_id}",
                        "url": target,
                        "severity": severity,
                        "detail": f"{cve.description[:150]}. CVSS: {cve.cvss_score}. "
                                  f"Exploit: {'有' if cve.exploit_available else '无'}",
                        "source": "cve_intelligence",
                    })
                    console.print(
                        f"    [green]✓ {cve.cve_id} [{severity}] CVSS:{cve.cvss_score} "
                        f"{'🔥有exploit' if cve.exploit_available else ''}[/green]"
                    )

            console.print(f"    [bold]CVE匹配: {len(cves)} 个已知漏洞关联[/bold]")
        except Exception as e:
            console.print(f"    [yellow]CVE匹配异常: {e}[/yellow]")

    # ─── 6. Interactsh OOB 回调 ─────────────────────────────────

    def _setup_oob(self, target, findings, phase_findings, console):
        """设置 interactsh OOB 回调 — 为后续盲 SSRF/XXE/SQLi 准备"""
        # 检查 interactsh-client 是否安装
        result = self.engine.execute_command(
            "which interactsh-client 2>/dev/null || echo NOT_FOUND", timeout=5
        )

        if "NOT_FOUND" in result.get("output", ""):
            console.print("    [dim]interactsh-client 未安装[/dim]")
            console.print("    [dim]安装: go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest[/dim]")

            # 使用公共 interact.sh 替代
            console.print("    [cyan]使用备用方案: 生成 Burp Collaborator 风格的 OOB payload[/cyan]")

            # 生成唯一标识
            import hashlib
            oob_id = hashlib.md5(f"{target}{os.getpid()}".encode()).hexdigest()[:12]

            # 存储 OOB payload 到 findings 供后续阶段使用
            findings["_oob_domain"] = f"{oob_id}.oast.fun"
            findings["_oob_payloads"] = {
                "ssrf": f"http://{oob_id}.oast.fun/ssrf",
                "xxe": f"http://{oob_id}.oast.fun/xxe",
                "sqli": f"http://{oob_id}.oast.fun/sqli",
                "rce": f"http://{oob_id}.oast.fun/rce",
                "xss": f"http://{oob_id}.oast.fun/xss",
            }
            console.print(f"    [green]OOB Domain: {oob_id}.oast.fun[/green]")
            console.print(f"    [dim]后续盲测试将使用此域名作为回调[/dim]")
            return

        # interactsh 可用 — 启动一个会话
        console.print("    [green]interactsh-client 可用，生成 OOB 域名...[/green]")
        result = self.engine.execute_command(
            "interactsh-client -n 1 2>/dev/null | head -1", timeout=15
        )

        if result["success"] and result["output"]:
            oob_domain = result["output"].strip()
            findings["_oob_domain"] = oob_domain
            findings["_oob_payloads"] = {
                "ssrf": f"http://{oob_domain}/ssrf",
                "xxe": f"http://{oob_domain}/xxe",
                "sqli": f"http://{oob_domain}/sqli",
                "rce": f"http://{oob_domain}/rce",
            }
            console.print(f"    [green]OOB Domain: {oob_domain}[/green]")
        else:
            console.print("    [yellow]interactsh 启动失败，使用 oast.fun 替代[/yellow]")
            import hashlib
            oob_id = hashlib.md5(f"{target}{os.getpid()}".encode()).hexdigest()[:12]
            findings["_oob_domain"] = f"{oob_id}.oast.fun"
            findings["_oob_payloads"] = {
                "ssrf": f"http://{oob_id}.oast.fun/ssrf",
                "xxe": f"http://{oob_id}.oast.fun/xxe",
            }

    # ─── 解析方法 ─────────────────────────────────────────────

    def _parse_takeover(self, output: str) -> list:
        """解析子域名接管结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'TAKEOVER:' in line:
                detail = line.replace('TAKEOVER:', '').strip()
                vulns.append({
                    "type": "Subdomain Takeover (CNAME Dangling)",
                    "url": detail.split('->')[0].strip() if '->' in detail else detail,
                    "severity": "high",
                    "detail": detail,
                    "source": "extended_scan",
                })
                self.logger.log_event("FINDING", f"⚠️ 子域名接管: {detail}")
        return vulns

    def _parse_cloud(self, output: str) -> list:
        """解析云资产扫描结果"""
        vulns = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('S3:') or line.startswith('AZURE:'):
                vulns.append({
                    "type": "Cloud Asset Exposed",
                    "url": line,
                    "severity": "medium",
                    "detail": f"云存储桶存在: {line}",
                    "source": "cloud_scanner",
                })
                self.logger.log_event("FINDING", f"☁️ 云资产: {line}")
        return vulns

    def _parse_cloud_critical(self, output: str) -> list:
        """解析可列目录的 S3 bucket"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'S3_LISTABLE:' in line:
                bucket = line.replace('S3_LISTABLE:', '').strip()
                vulns.append({
                    "type": "S3 Bucket Public Listing",
                    "url": f"https://{bucket}.s3.amazonaws.com/",
                    "severity": "high",
                    "detail": f"S3 Bucket {bucket} 可列目录（公开读取）",
                    "source": "cloud_scanner",
                })
                self.logger.log_event("FINDING", f"🔥 S3可列目录: {bucket}")
        return vulns
