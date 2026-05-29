#!/usr/bin/env python3
"""
Deep Hunt Phase — 深度漏洞挖掘阶段
使用新的 HTTP 引擎 + 响应差异检测 + 真实验证

这是在原有 HuntPhase（工具编排）之后运行的第二层挖掘：
- 原有 HuntPhase: 调用 nuclei/dalfox 等外部工具
- DeepHuntPhase: 用自研 HTTP 引擎做精细化测试

流程：
1. 对已知参数做主动 Fuzz（响应差异检测）
2. 系统性 IDOR 越权测试
3. 业务逻辑测试（价格篡改/竞态/流程跳跃）
4. WAF 绕过尝试（对被拦截的 payload 做变异重试）
5. 真实验证（发请求确认，不问 LLM）
"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .base import BasePhase


class DeepHuntPhase(BasePhase):
    """深度漏洞挖掘：HTTP引擎 + 响应差异 + 真实验证"""

    def execute(self, target: str, findings: dict) -> dict:
        """同步入口（兼容原有 pipeline 的同步调用）"""
        # 在新的事件循环中运行异步逻辑
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 如果已经在异步环境中，创建新线程运行
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self._async_execute(target, findings))
                    return future.result()
            else:
                return loop.run_until_complete(self._async_execute(target, findings))
        except RuntimeError:
            return asyncio.run(self._async_execute(target, findings))

    async def _async_execute(self, target: str, findings: dict) -> dict:
        """异步主逻辑"""
        phase_findings = {"vulnerabilities": [], "secrets": []}

        self.logger.log_phase_start("深度挖掘 (Deep Hunt)")

        try:
            from rich.console import Console
            from rich.prompt import Confirm
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            class Confirm:
                @staticmethod
                def ask(msg, default=True): return input(f"{msg} (y/n): ").lower() != 'n'
            console = Console()

        # 初始化新模块
        try:
            from http_engine import HttpEngine
            from active_fuzzer import ActiveFuzzer
            from idor_tester import IDORTester
            from business_logic_tester import BusinessLogicTester
            from real_validator import RealValidator
            from waf_bypass import WAFBypass
        except ImportError as e:
            console.print(f"  [yellow]⚠ 深度挖掘模块导入失败: {e}[/yellow]")
            console.print(f"  [yellow]  请安装依赖: pip install httpx[/yellow]")
            self.logger.log_event("SKIP", f"深度挖掘模块不可用: {e}")
            return phase_findings

        # 读取配置
        config = self.engine.config
        deep_config = config.get("deep_hunt", {})

        # 构建 HTTP Engine 配置
        http_config = {
            "cookies": {},
            "headers": {},
            "rate_limit": config.get("rate_limit", {}).get("requests_per_second", 3),
            "timeout": deep_config.get("timeout", 15),
            "rotate_ua": True,
            "verify_ssl": False,
            "proxy": deep_config.get("proxy", None),
        }

        # 从 session_monitor 和 idor 配置中获取 cookie
        session_cookie = config.get("session_monitor", {}).get("cookie", "")
        if session_cookie:
            # 解析 cookie 字符串为 dict
            http_config["cookies"] = self._parse_cookie_string(session_cookie)

        # 初始化引擎
        http_engine = HttpEngine(http_config)

        try:
            # ═══════════════════════════════════════════════════
            # Step 1: 主动参数 Fuzz
            # ═══════════════════════════════════════════════════
            if deep_config.get("enable_fuzz", True):
                console.print("\n  [bold cyan]━━━ Step 1: 主动参数 Fuzz ━━━[/bold cyan]")
                
                if self.mode == "semi":
                    if not Confirm.ask("  执行主动参数 Fuzz？", default=True):
                        self.logger.log_event("SKIP", "用户跳过主动 Fuzz")
                    else:
                        fuzz_findings = await self._run_active_fuzz(
                            http_engine, findings, deep_config, console
                        )
                        phase_findings["vulnerabilities"].extend(fuzz_findings)
                else:
                    fuzz_findings = await self._run_active_fuzz(
                        http_engine, findings, deep_config, console
                    )
                    phase_findings["vulnerabilities"].extend(fuzz_findings)

            # ═══════════════════════════════════════════════════
            # Step 2: 系统性 IDOR 测试
            # ═══════════════════════════════════════════════════
            if deep_config.get("enable_idor", True):
                console.print("\n  [bold cyan]━━━ Step 2: 系统性 IDOR 测试 ━━━[/bold cyan]")
                
                if self.mode == "semi":
                    if not Confirm.ask("  执行 IDOR 越权测试？", default=True):
                        self.logger.log_event("SKIP", "用户跳过 IDOR 测试")
                    else:
                        idor_findings = await self._run_idor_test(
                            http_engine, findings, config, console
                        )
                        phase_findings["vulnerabilities"].extend(idor_findings)
                else:
                    idor_findings = await self._run_idor_test(
                        http_engine, findings, config, console
                    )
                    phase_findings["vulnerabilities"].extend(idor_findings)

            # ═══════════════════════════════════════════════════
            # Step 3: 业务逻辑测试
            # ═══════════════════════════════════════════════════
            if deep_config.get("enable_bizlogic", True):
                console.print("\n  [bold cyan]━━━ Step 3: 业务逻辑测试 ━━━[/bold cyan]")
                
                if self.mode == "semi":
                    if not Confirm.ask("  执行业务逻辑测试？", default=True):
                        self.logger.log_event("SKIP", "用户跳过业务逻辑测试")
                    else:
                        biz_findings = await self._run_bizlogic_test(
                            http_engine, findings, config, console
                        )
                        phase_findings["vulnerabilities"].extend(biz_findings)
                else:
                    biz_findings = await self._run_bizlogic_test(
                        http_engine, findings, config, console
                    )
                    phase_findings["vulnerabilities"].extend(biz_findings)

            # ═══════════════════════════════════════════════════
            # Step 4: 认证绕过测试
            # ═══════════════════════════════════════════════════
            if deep_config.get("enable_auth_bypass", True):
                console.print("\n  [bold cyan]━━━ Step 4: 认证绕过测试 ━━━[/bold cyan]")
                
                if self.mode == "semi":
                    if not Confirm.ask("  执行认证绕过测试？", default=True):
                        self.logger.log_event("SKIP", "用户跳过认证绕过")
                    else:
                        auth_findings = await self._run_auth_bypass(
                            http_engine, findings, deep_config, console
                        )
                        phase_findings["vulnerabilities"].extend(auth_findings)
                else:
                    auth_findings = await self._run_auth_bypass(
                        http_engine, findings, deep_config, console
                    )
                    phase_findings["vulnerabilities"].extend(auth_findings)

            # ═══════════════════════════════════════════════════
            # Step 5: 真实验证（对所有发现）
            # ═══════════════════════════════════════════════════
            if phase_findings["vulnerabilities"]:
                console.print("\n  [bold cyan]━━━ Step 5: 真实验证 ━━━[/bold cyan]")
                
                validator = RealValidator(http_engine, {
                    "cookies": http_config["cookies"],
                    "reproduction_attempts": deep_config.get("reproduction_attempts", 3),
                })

                verified = []
                for vuln in phase_findings["vulnerabilities"]:
                    result = await validator.validate(vuln)
                    
                    if result.is_valid:
                        vuln["deep_validated"] = True
                        vuln["validation_confidence"] = result.confidence
                        vuln["validation_evidence"] = result.evidence
                        vuln["reproducible"] = result.reproducible
                        verified.append(vuln)
                        console.print(
                            f"    [green]✓ {vuln.get('type', '?')}: "
                            f"confidence={result.confidence:.0%} — {result.evidence[:80]}[/green]"
                        )
                    else:
                        console.print(
                            f"    [dim]✗ {vuln.get('type', '?')}: "
                            f"验证未通过 — {result.evidence[:60]}[/dim]"
                        )

                # 只保留验证通过的
                phase_findings["vulnerabilities"] = verified
                console.print(
                    f"\n  [bold]验证结果: {len(verified)} 个确认 "
                    f"/ {len(phase_findings['vulnerabilities'])} 个总发现[/bold]"
                )

        except Exception as e:
            console.print(f"  [red]深度挖掘异常: {e}[/red]")
            self.logger.log_event("ERROR", f"DeepHunt异常: {e}")
            import traceback
            self.logger.log_event("ERROR", traceback.format_exc()[:500])
        finally:
            await http_engine.close()

        return phase_findings

    # ─── 子步骤实现 ─────────────────────────────────────────────

    async def _run_active_fuzz(self, http_engine, findings, deep_config, console) -> list:
        """运行主动参数 Fuzz"""
        from active_fuzzer import ActiveFuzzer

        fuzzer = ActiveFuzzer(http_engine, {
            "anomaly_threshold": deep_config.get("anomaly_threshold", 30),
            "confirm_threshold": deep_config.get("confirm_threshold", 60),
            "max_params_per_url": deep_config.get("max_params_per_url", 10),
            "auto_confirm": True,
        })

        vuln_findings = []

        # 从已有发现中选择有参数的 URL 进行 fuzz
        urls_to_fuzz = []
        
        # 优先 fuzz 带参数的 URL
        for url in findings.get("params", [])[:20]:
            if "?" in url:
                urls_to_fuzz.append(url)
        
        # 补充从 urls 中提取有参数的
        for url in findings.get("urls", [])[:50]:
            if "?" in url and url not in urls_to_fuzz:
                urls_to_fuzz.append(url)
            if len(urls_to_fuzz) >= 30:
                break

        if not urls_to_fuzz:
            console.print("    [dim]无带参数的URL可 fuzz[/dim]")
            return vuln_findings

        console.print(f"    Fuzz {len(urls_to_fuzz)} 个URL...")

        for i, url in enumerate(urls_to_fuzz):
            try:
                fuzz_results = await fuzzer.fuzz_url(url)
                for f in fuzz_results:
                    vuln_findings.append({
                        "type": f.vuln_type.upper(),
                        "url": f.url,
                        "param": f.param,
                        "payload": f.payload,
                        "severity": f.severity,
                        "detail": f.evidence,
                        "confirmed": f.confirmed,
                        "confidence": f.confidence,
                        "source": "deep_fuzz",
                    })
                    console.print(
                        f"    [green]✓ [{f.severity}] {f.vuln_type} @ {f.param} "
                        f"(score={f.anomaly_score})[/green]"
                    )
            except Exception as e:
                self.logger.log_event("ERROR", f"Fuzz {url[:50]} 异常: {e}")

            # 进度
            if (i + 1) % 10 == 0:
                console.print(f"    [dim]进度: {i+1}/{len(urls_to_fuzz)}[/dim]")

        console.print(f"    [bold]Fuzz 完成: 发现 {len(vuln_findings)} 个异常[/bold]")
        self.logger.log_event("FINDING", f"主动Fuzz发现 {len(vuln_findings)} 个异常")
        return vuln_findings

    async def _run_idor_test(self, http_engine, findings, config, console) -> list:
        """运行系统性 IDOR 测试"""
        from idor_tester import IDORTester

        # 配置双账号
        idor_config = config.get("idor", {})
        cookie_a_str = idor_config.get("cookie_a", "")
        cookie_b_str = idor_config.get("cookie_b", "")

        tester_config = {
            "cookie_a": self._parse_cookie_string(cookie_a_str) if cookie_a_str else {},
            "cookie_b": self._parse_cookie_string(cookie_b_str) if cookie_b_str else {},
            "id_range": 5,
            "test_methods": ["GET", "PUT", "PATCH", "DELETE"],
            "test_api_versions": True,
        }

        tester = IDORTester(http_engine, tester_config)

        vuln_findings = []

        # 从 URL 中选择可能有 IDOR 的接口
        idor_candidates = []
        import re
        for url in findings.get("urls", []) + findings.get("params", []):
            # 包含数字 ID 的 URL
            if re.search(r'/\d+[/\?]?', url) or re.search(r'[?&]\w*id=\d+', url, re.I):
                idor_candidates.append(url)

        # AI 辅助筛选（如果有 LLM）
        if not idor_candidates and findings.get("urls"):
            # 用简单规则筛选
            for url in findings.get("urls", [])[:100]:
                if any(kw in url.lower() for kw in [
                    "/user/", "/profile/", "/order/", "/message/",
                    "/account/", "/invoice/", "/file/", "/doc/",
                    "user_id=", "uid=", "id=", "order_id=",
                ]):
                    idor_candidates.append(url)

        idor_candidates = idor_candidates[:15]  # 最多测试 15 个

        if not idor_candidates:
            console.print("    [dim]未发现含 ID 的接口[/dim]")
            return vuln_findings

        console.print(f"    测试 {len(idor_candidates)} 个候选 IDOR 接口...")

        for url in idor_candidates:
            try:
                results = await tester.test_url(url)
                for f in results:
                    vuln_findings.append({
                        "type": f"IDOR ({f.vuln_type})",
                        "url": f.url,
                        "method": f.method,
                        "severity": f.severity,
                        "detail": f.evidence,
                        "confirmed": f.confirmed,
                        "confidence": f.confidence,
                        "source": "deep_idor",
                    })
                    console.print(
                        f"    [green]✓ [{f.severity}] {f.vuln_type} @ {f.url[:60]}[/green]"
                    )
            except Exception as e:
                self.logger.log_event("ERROR", f"IDOR {url[:50]} 异常: {e}")

        console.print(f"    [bold]IDOR 测试完成: 发现 {len(vuln_findings)} 个[/bold]")
        self.logger.log_event("FINDING", f"IDOR测试发现 {len(vuln_findings)} 个")
        return vuln_findings

    async def _run_bizlogic_test(self, http_engine, findings, config, console) -> list:
        """运行业务逻辑测试"""
        from business_logic_tester import BusinessLogicTester

        biz_config = config.get("business_logic", {})
        session_cookie = config.get("session_monitor", {}).get("cookie", "")

        tester = BusinessLogicTester(http_engine, {
            "cookies": self._parse_cookie_string(session_cookie) if session_cookie else {},
        })

        vuln_findings = []

        # 从 URL 中识别业务逻辑相关接口
        biz_urls = []
        biz_keywords = [
            "pay", "payment", "order", "checkout", "redeem",
            "coupon", "voucher", "discount", "transfer", "withdraw",
            "sign", "checkin", "vote", "like", "reward", "point",
            "balance", "wallet", "credit", "recharge", "topup",
        ]

        for url in findings.get("urls", []) + findings.get("params", []):
            url_lower = url.lower()
            if any(kw in url_lower for kw in biz_keywords):
                biz_urls.append(url)

        if not biz_urls:
            console.print("    [dim]未发现业务逻辑相关接口[/dim]")
            # 仍然可以做竞态测试（对写操作 URL）
            write_urls = [u for u in findings.get("urls", [])
                         if any(kw in u.lower() for kw in ["post", "create", "add", "submit", "send"])]
            if write_urls:
                biz_urls = write_urls[:5]

        if not biz_urls:
            return vuln_findings

        console.print(f"    发现 {len(biz_urls)} 个业务接口，开始测试...")

        # 竞态条件测试
        state_url = biz_config.get("state_url", "")
        state_field = biz_config.get("state_field", "")

        for url in biz_urls[:10]:
            try:
                # 竞态测试
                race_findings = await tester.test_race_condition(
                    url=url,
                    method="POST",
                    state_url=state_url if state_url else None,
                    state_field=state_field if state_field else None,
                    concurrency=10,
                )
                for f in race_findings:
                    vuln_findings.append({
                        "type": "Race Condition",
                        "url": f.url,
                        "method": f.method,
                        "severity": f.severity,
                        "detail": f.evidence,
                        "confirmed": f.confirmed,
                        "confidence": f.confidence,
                        "state_before": f.state_before,
                        "state_after": f.state_after,
                        "source": "deep_bizlogic",
                    })
                    console.print(
                        f"    [green]✓ [{f.severity}] 竞态: {f.evidence[:60]}[/green]"
                    )
            except Exception as e:
                self.logger.log_event("ERROR", f"BizLogic {url[:50]} 异常: {e}")

        console.print(f"    [bold]业务逻辑测试完成: 发现 {len(vuln_findings)} 个[/bold]")
        self.logger.log_event("FINDING", f"业务逻辑测试发现 {len(vuln_findings)} 个")
        return vuln_findings

    async def _run_auth_bypass(self, http_engine, findings, deep_config, console) -> list:
        """运行认证绕过测试"""
        from active_fuzzer import ActiveFuzzer

        fuzzer = ActiveFuzzer(http_engine, {"anomaly_threshold": 30})
        vuln_findings = []

        # 找到 403/401 的 URL 做绕过测试
        # 从 alive_hosts 中探测常见管理路径
        admin_paths = [
            "/admin", "/manage", "/dashboard", "/internal",
            "/api/admin", "/api/internal", "/debug", "/actuator",
        ]

        test_urls = []
        for host in findings.get("alive_hosts", [])[:5]:
            for path in admin_paths:
                test_urls.append(host.rstrip("/") + path)

        if not test_urls:
            console.print("    [dim]无存活主机可做认证绕过测试[/dim]")
            return vuln_findings

        console.print(f"    测试 {len(test_urls)} 个受限路径的绕过...")

        for url in test_urls:
            try:
                bypasses = await fuzzer.fuzz_auth_bypass(url)
                for bypass in bypasses:
                    vuln_findings.append({
                        "type": "Auth Bypass (403绕过)",
                        "url": bypass["url"],
                        "severity": "high",
                        "detail": bypass["evidence"],
                        "confirmed": True,
                        "confidence": 0.8,
                        "source": "deep_auth_bypass",
                    })
                    console.print(
                        f"    [green]✓ [high] 403绕过: {bypass['evidence'][:60]}[/green]"
                    )
            except Exception as e:
                pass  # 静默失败，很多 URL 本身就不存在

        console.print(f"    [bold]认证绕过测试完成: 发现 {len(vuln_findings)} 个[/bold]")
        self.logger.log_event("FINDING", f"认证绕过发现 {len(vuln_findings)} 个")
        return vuln_findings

    # ─── 辅助方法 ─────────────────────────────────────────────

    def _parse_cookie_string(self, cookie_str: str) -> dict:
        """解析 Cookie 字符串为 dict"""
        cookies = {}
        if not cookie_str:
            return cookies
        
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, value = part.partition("=")
                cookies[key.strip()] = value.strip()
        
        return cookies
