#!/usr/bin/env python3
"""
CNVD Hunt Phase — CNVD 通用型漏洞挖掘阶段（可选）

这是一个独立的可选阶段，专注于国产系统通用型漏洞挖掘。
不影响原有 pipeline，可单独调用或作为附加阶段插入。

目标：
- 通过 FOFA 收集国产 OA/ERP/BI 系统资产
- 批量验证已知 POC（SQL注入/RCE/文件上传等）
- 统计影响范围，达到 CNVD 通用型提交门槛（≥3实例）
- 生成 CNVD 格式报告

用法：
    # 作为 phase 插入 pipeline（在 auto_hunt.py 中可选启用）
    from phases.cnvd_hunt import CNVDHuntPhase

    # 或独立运行
    python cnvd_scanner.py --system 泛微 --all
"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .base import BasePhase



class CNVDHuntPhase(BasePhase):
    """
    CNVD 通用型漏洞批量挖掘阶段

    与原有 HuntPhase/DeepHuntPhase 并列，可选启用。
    专注于国产系统（OA/ERP/BI/网络设备）的已知漏洞批量验证。
    """

    def execute(self, target: str, findings: dict) -> dict:
        """同步入口（兼容原有 pipeline）"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
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
        phase_findings = {"vulnerabilities": [], "cnvd_results": []}

        self.logger.log_phase_start("CNVD 通用型漏洞挖掘 (CNVD Hunt)")

        try:
            from rich.console import Console
            from rich.prompt import Prompt, Confirm
            from rich.table import Table
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            class Prompt:
                @staticmethod
                def ask(msg, choices=None, default=""): return input(f"{msg}: ") or default
            class Confirm:
                @staticmethod
                def ask(msg, default=True): return input(f"{msg} (y/n): ").lower() != 'n'
            console = Console()

        # 导入 CNVD 模块
        try:
            from cnvd_scanner import CNVDScanner
            from cnvd_targets import ALL_TARGETS, get_system_by_name
        except ImportError as e:
            console.print(f"  [yellow]⚠ CNVD 模块导入失败: {e}[/yellow]")
            self.logger.log_event("SKIP", f"CNVD 模块不可用: {e}")
            return phase_findings

        config = self.engine.config
        cnvd_config = config.get("cnvd_scanner", {})

        # 检查是否启用
        if not cnvd_config.get("enabled", False):
            console.print("  [dim]CNVD 扫描未启用 (config.yaml → cnvd_scanner.enabled: true)[/dim]")
            return phase_findings

        console.print("\n[bold magenta]╔══════════════════════════════════════╗[/bold magenta]")
        console.print("[bold magenta]║   CNVD 通用型漏洞批量挖掘模式       ║[/bold magenta]")
        console.print("[bold magenta]╚══════════════════════════════════════╝[/bold magenta]\n")

        # 选择扫描模式
        scan_mode = "auto"
        if self.mode == "semi":
            console.print("  [bold]选择 CNVD 扫描模式:[/bold]")
            console.print("    1. 指定系统扫描（如：泛微、用友、帆软）")
            console.print("    2. 全量高优先级扫描")
            console.print("    3. 教育网目标（EDUSRC）")
            console.print("    4. 跳过 CNVD 阶段")
            choice = Prompt.ask("  选择", choices=["1", "2", "3", "4"], default="1")

            if choice == "4":
                self.logger.log_event("SKIP", "用户跳过 CNVD 阶段")
                return phase_findings
            elif choice == "1":
                scan_mode = "single"
            elif choice == "2":
                scan_mode = "all"
            elif choice == "3":
                scan_mode = "edu"

        # 初始化扫描器
        scanner = CNVDScanner(config)

        # 执行扫描
        if scan_mode == "single":
            # 显示可选系统列表
            console.print("\n  [bold]可选目标系统:[/bold]")
            for i, t in enumerate(ALL_TARGETS, 1):
                console.print(f"    {i:2d}. {t.name} ({t.vendor}) — POC: {len(t.pocs)}个")

            system_name = Prompt.ask("\n  输入系统名称", default="泛微")
            result = await scanner.scan_system(system_name)
            if result.findings:
                phase_findings["cnvd_results"].append(result)
                for f in result.findings:
                    phase_findings["vulnerabilities"].append({
                        "type": f"cnvd_{f.vuln_type}",
                        "url": f.target_url,
                        "detail": f.vuln_name,
                        "severity": f.severity,
                        "confirmed": f.confirmed,
                    })

        elif scan_mode == "all":
            results = await scanner.scan_all(priority="high")
            for result in results:
                if result.findings:
                    phase_findings["cnvd_results"].append(result)
                    for f in result.findings:
                        phase_findings["vulnerabilities"].append({
                            "type": f"cnvd_{f.vuln_type}",
                            "url": f.target_url,
                            "detail": f.vuln_name,
                            "severity": f.severity,
                            "confirmed": f.confirmed,
                        })

        elif scan_mode == "edu":
            await scanner.scan_edu()

        elif scan_mode == "auto":
            # 自动模式：尝试识别 target 是否为国产系统
            detected = self._detect_cn_system(target, findings)
            if detected:
                console.print(f"  [green]检测到目标可能是: {detected}[/green]")
                result = await scanner.scan_system(detected)
                if result.findings:
                    phase_findings["cnvd_results"].append(result)
            else:
                console.print("  [dim]目标未匹配国产系统指纹，跳过 CNVD 扫描[/dim]")

        # 输出汇总
        if phase_findings["vulnerabilities"]:
            console.print(f"\n  [bold green]CNVD 阶段发现 {len(phase_findings['vulnerabilities'])} 个漏洞[/bold green]")

            # 生成报告
            for result in phase_findings.get("cnvd_results", []):
                if result.cnvd_submittable:
                    report = scanner.generate_cnvd_report(result)
                    self.logger.log_event("CNVD_REPORT", report)
                    console.print(f"\n  [bold yellow]★ {result.system_name} 达到 CNVD 通用型提交门槛！[/bold yellow]")
                    console.print(f"    影响实例: {result.vulnerable} 个")

            console.print(scanner.generate_summary())

        return phase_findings



    def _detect_cn_system(self, target: str, findings: dict) -> str:
        """
        尝试从已有 findings 中检测目标是否为国产系统
        返回系统名称或空字符串
        """
        # 从页面内容/标题中检测
        keywords_map = {
            "泛微": ["ecology", "weaver", "e-cology", "wui/theme"],
            "用友": ["yonyou", "nccloud", "用友", "nc-cloud"],
            "致远": ["seeyon", "致远", "A8", "seeyonoa"],
            "通达": ["tongda", "通达", "ispirit"],
            "帆软": ["FineReport", "帆软", "ReportServer", "WebReport"],
            "蓝凌": ["landray", "蓝凌", "ekp"],
            "宏景": ["宏景", "eHR", "HCM"],
            "锐捷": ["Ruijie", "锐捷", "RG-"],
            "宝塔": ["宝塔", "BT-Panel"],
        }

        # 检查 target 域名
        target_lower = target.lower()

        # 检查已收集的 URL/响应中的关键字
        all_text = target_lower
        for url in findings.get("urls", [])[:50]:
            all_text += " " + url.lower()
        for sub in findings.get("subdomains", [])[:50]:
            all_text += " " + sub.lower()

        for system_name, keywords in keywords_map.items():
            for kw in keywords:
                if kw.lower() in all_text:
                    return system_name

        return ""
