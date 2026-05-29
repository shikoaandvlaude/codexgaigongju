#!/usr/bin/env python3
"""
Enhanced Scanner — 增强扫描集成入口
整合所有新增模块为统一接口，可作为独立工具或集成到 auto_hunt.py

新增模块：
  - ai_attack_surface.py    → 智能攻击面映射
  - subdomain_takeover.py   → 子域名接管检测
  - cloud_scanner.py        → 云安全扫描
  - api_security_scanner.py → API 安全测试
  - credential_hunter.py    → 凭证泄露检测
  - waf_evasion_advanced.py → 高级 WAF 绕过
  - report_generator.py     → 专业报告生成

用法（独立运行）：
    python enhanced_scanner.py --target example.com --all
    python enhanced_scanner.py --target example.com --cloud --takeover
    python enhanced_scanner.py --target example.com --api --creds
    python enhanced_scanner.py --target example.com --report markdown

用法（作为库导入）：
    from enhanced_scanner import EnhancedScanner
    scanner = EnhancedScanner(config)
    results = await scanner.full_scan("example.com")
"""

import asyncio
import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))



# 延迟导入各模块（避免硬依赖）
def _import_module(name):
    try:
        return __import__(name)
    except ImportError as e:
        print(f"[!] Module {name} import failed: {e}")
        return None


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


class EnhancedScanner:
    """增强扫描器 — 统一调度所有新模块"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.results = {
            "target": "",
            "scan_time": "",
            "modules_run": [],
            "attack_surface": None,
            "takeover": [],
            "cloud": [],
            "api": [],
            "credentials": [],
            "waf_info": None,
            "report_path": "",
        }

    async def full_scan(self, target: str, recon_dir: str = None,
                        modules: List[str] = None) -> Dict:
        """
        执行完整增强扫描

        Args:
            target: 目标域名
            recon_dir: 侦察数据目录（可选）
            modules: 要运行的模块列表（默认全部）
                     可选: attack_surface, takeover, cloud, api, credentials, waf
        """
        self.results["target"] = target
        self.results["scan_time"] = datetime.now().isoformat()

        if modules is None:
            modules = ["attack_surface", "takeover", "cloud", "api", "credentials", "waf"]

        print(f"\n{BOLD}{MAGENTA}{'═'*60}{NC}")
        print(f"{BOLD}{MAGENTA}  BAI ENHANCED SCANNER v2.0{NC}")
        print(f"{BOLD}{MAGENTA}  Target: {target}{NC}")
        print(f"{BOLD}{MAGENTA}  Modules: {', '.join(modules)}{NC}")
        print(f"{BOLD}{MAGENTA}{'═'*60}{NC}\n")

        start_time = time.time()

        # 按优先级执行模块
        if "attack_surface" in modules:
            await self._run_attack_surface(target, recon_dir)

        if "takeover" in modules:
            await self._run_takeover(target, recon_dir)

        if "cloud" in modules:
            await self._run_cloud_scan(target)

        if "api" in modules:
            await self._run_api_scan(target)

        if "credentials" in modules:
            await self._run_credential_hunt(target, recon_dir)

        if "waf" in modules:
            await self._run_waf_analysis(target)

        duration = time.time() - start_time
        self.results["duration"] = round(duration, 1)
        self.results["modules_run"] = modules

        # 生成报告
        report_path = await self._generate_report(target, duration)
        self.results["report_path"] = report_path

        # 打印摘要
        self._print_summary(duration)

        return self.results


    # ═══════════════════════════════════════════════════════════════
    # 模块执行器
    # ═══════════════════════════════════════════════════════════════

    async def _run_attack_surface(self, target: str, recon_dir: str = None):
        """运行攻击面映射"""
        print(f"\n{CYAN}[1/6] Attack Surface Mapping...{NC}")
        try:
            mod = _import_module("ai_attack_surface")
            if not mod:
                return
            mapper = mod.AttackSurfaceMapper(self.config.get("attack_surface", {}))
            surface = await mapper.map_target(target, recon_dir)
            self.results["attack_surface"] = {
                "total_assets": len(surface.assets),
                "high_risk": surface.high_risk_count,
                "vectors": len(surface.vectors),
                "new_assets": len(surface.new_assets),
            }
            # 输出可视化
            fmt = self.config.get("attack_surface", {}).get("visualize_format", "ascii")
            mapper.visualize(surface, format=fmt)
        except Exception as e:
            print(f"  {YELLOW}[!] Attack surface error: {e}{NC}")

    async def _run_takeover(self, target: str, recon_dir: str = None):
        """运行子域名接管检测"""
        print(f"\n{CYAN}[2/6] Subdomain Takeover Scan...{NC}")
        try:
            mod = _import_module("subdomain_takeover")
            if not mod:
                return
            scanner = mod.SubdomainTakeoverScanner(self.config.get("subdomain_takeover", {}))

            # 尝试加载子域名文件
            subs_file = None
            if recon_dir:
                for fn in ["resolved.txt", "all.txt", "subdomains.txt"]:
                    fp = Path(recon_dir) / fn
                    if fp.exists():
                        subs_file = str(fp)
                        break

            if subs_file:
                results = await scanner.scan(target, subdomains_file=subs_file)
            else:
                print(f"  {DIM}No subdomains file found, skipping takeover scan{NC}")
                return

            vulnerable = [r for r in results if r.vulnerable]
            self.results["takeover"] = [
                {"subdomain": r.subdomain, "service": r.service, "severity": r.severity}
                for r in vulnerable
            ]
            if vulnerable:
                print(scanner.generate_report())
        except Exception as e:
            print(f"  {YELLOW}[!] Takeover scan error: {e}{NC}")

    async def _run_cloud_scan(self, target: str):
        """运行云安全扫描"""
        print(f"\n{CYAN}[3/6] Cloud Security Scan...{NC}")
        try:
            mod = _import_module("cloud_scanner")
            if not mod:
                return
            scanner = mod.CloudSecurityScanner(self.config.get("cloud_scanner", {}))
            findings = await scanner.scan_target(target)
            self.results["cloud"] = [
                {"service": f.service, "resource": f.resource,
                 "vulnerability": f.vulnerability, "severity": f.severity}
                for f in findings
            ]
        except Exception as e:
            print(f"  {YELLOW}[!] Cloud scan error: {e}{NC}")

    async def _run_api_scan(self, target: str):
        """运行 API 安全测试"""
        print(f"\n{CYAN}[4/6] API Security Scan...{NC}")
        try:
            mod = _import_module("api_security_scanner")
            if not mod:
                return
            api_config = self.config.get("api_security", {})
            scanner = mod.APISecurityScanner(api_config)
            base_url = f"https://{target}" if not target.startswith("http") else target
            findings = await scanner.scan_api(base_url)
            self.results["api"] = [
                {"type": f.vuln_type, "endpoint": f.endpoint,
                 "severity": f.severity, "description": f.description}
                for f in findings
            ]
        except Exception as e:
            print(f"  {YELLOW}[!] API scan error: {e}{NC}")


    async def _run_credential_hunt(self, target: str, recon_dir: str = None):
        """运行凭证泄露检测"""
        print(f"\n{CYAN}[5/6] Credential Hunt...{NC}")
        try:
            mod = _import_module("credential_hunter")
            if not mod:
                return
            hunter = mod.CredentialHunter(self.config.get("credential_hunter", {}))
            findings = await hunter.hunt(target, recon_dir=recon_dir)

            # 验证关键发现
            if self.config.get("credential_hunter", {}).get("validate_secrets", True):
                await hunter.validate_findings()

            self.results["credentials"] = [
                {"type": f.secret_type, "service": f.service,
                 "value": f.value, "severity": f.severity,
                 "source": f.source_url, "valid": f.is_valid}
                for f in findings
            ]
        except Exception as e:
            print(f"  {YELLOW}[!] Credential hunt error: {e}{NC}")

    async def _run_waf_analysis(self, target: str):
        """运行 WAF 分析"""
        print(f"\n{CYAN}[6/6] WAF Analysis...{NC}")
        try:
            mod = _import_module("waf_evasion_advanced")
            if not mod:
                return
            engine = mod.WAFEvasionEngine(self.config.get("waf_evasion", {}))
            base_url = f"https://{target}" if not target.startswith("http") else target
            waf_info = await engine.fingerprint_waf(base_url)
            self.results["waf_info"] = {
                "waf_name": waf_info.waf_name,
                "confidence": waf_info.confidence,
                "known_bypasses": waf_info.known_bypasses,
            }

            # 如果启用了请求走私测试
            if self.config.get("waf_evasion", {}).get("test_smuggling", False):
                smuggling = await engine.test_request_smuggling(base_url)
                if smuggling:
                    self.results["waf_info"]["smuggling_vulns"] = smuggling
        except Exception as e:
            print(f"  {YELLOW}[!] WAF analysis error: {e}{NC}")

    # ═══════════════════════════════════════════════════════════════
    # 报告生成
    # ═══════════════════════════════════════════════════════════════

    async def _generate_report(self, target: str, duration: float) -> str:
        """生成综合报告"""
        try:
            mod = _import_module("report_generator")
            if not mod:
                return ""

            report_config = self.config.get("report", {})
            gen = mod.ReportGenerator(report_config)

            # 收集所有 findings 转为标准 Finding 格式
            raw_findings = []

            # 云扫描结果
            for cf in self.results.get("cloud", []):
                raw_findings.append({
                    "title": cf["vulnerability"],
                    "severity": cf["severity"],
                    "vuln_type": cf["service"],
                    "endpoint": cf.get("resource", ""),
                    "impact": f"Cloud resource {cf['service']} exposed",
                })

            # API 扫描结果
            for af in self.results.get("api", []):
                raw_findings.append({
                    "title": af.get("description", af["type"]),
                    "severity": af["severity"],
                    "vuln_type": af["type"],
                    "endpoint": af["endpoint"],
                })

            # 子域名接管
            for tk in self.results.get("takeover", []):
                raw_findings.append({
                    "title": f"Subdomain Takeover: {tk['subdomain']}",
                    "severity": tk["severity"],
                    "vuln_type": "subdomain_takeover",
                    "endpoint": tk["subdomain"],
                    "impact": f"Service: {tk['service']}",
                })

            # 凭证泄露
            for cr in self.results.get("credentials", []):
                if cr["severity"] in ("critical", "high"):
                    raw_findings.append({
                        "title": f"Credential Exposure: {cr['service']}",
                        "severity": cr["severity"],
                        "vuln_type": "credential_exposure",
                        "endpoint": cr.get("source", ""),
                        "evidence": cr["value"],
                    })

            if not raw_findings:
                return ""

            findings = gen.from_raw_findings(raw_findings)
            fmt = report_config.get("format", "markdown")
            report = gen.generate(findings, target=target, format=fmt, scan_duration=duration)
            return str(gen.output_dir / f"{target.replace('.', '_')}*.{fmt}")

        except Exception as e:
            print(f"  {YELLOW}[!] Report generation error: {e}{NC}")
            return ""


    # ═══════════════════════════════════════════════════════════════
    # 摘要输出
    # ═══════════════════════════════════════════════════════════════

    def _print_summary(self, duration: float):
        """打印扫描摘要"""
        print(f"\n{BOLD}{'═'*60}{NC}")
        print(f"{BOLD}  ENHANCED SCAN COMPLETE{NC}")
        print(f"{'═'*60}")
        print(f"  Target: {self.results['target']}")
        print(f"  Duration: {duration:.1f}s")
        print(f"  Modules: {', '.join(self.results['modules_run'])}")
        print(f"{'─'*60}")

        # 攻击面
        surface = self.results.get("attack_surface")
        if surface:
            print(f"  {GREEN}Attack Surface:{NC} {surface['total_assets']} assets, "
                  f"{surface['high_risk']} high-risk, "
                  f"{surface['vectors']} attack vectors")

        # 接管
        takeover = self.results.get("takeover", [])
        if takeover:
            print(f"  {RED}Takeover:{NC} {len(takeover)} vulnerable subdomains!")
        else:
            print(f"  {GREEN}Takeover:{NC} No vulnerable subdomains")

        # 云
        cloud = self.results.get("cloud", [])
        critical_cloud = [f for f in cloud if f.get("severity") in ("critical", "high")]
        if critical_cloud:
            print(f"  {RED}Cloud:{NC} {len(critical_cloud)} critical/high findings!")
        else:
            print(f"  {GREEN}Cloud:{NC} {len(cloud)} findings")

        # API
        api = self.results.get("api", [])
        critical_api = [f for f in api if f.get("severity") in ("critical", "high")]
        if critical_api:
            print(f"  {RED}API:{NC} {len(critical_api)} critical/high vulnerabilities!")
        else:
            print(f"  {GREEN}API:{NC} {len(api)} findings")

        # 凭证
        creds = self.results.get("credentials", [])
        valid_creds = [c for c in creds if c.get("valid")]
        if valid_creds:
            print(f"  {RED}Credentials:{NC} {len(valid_creds)} VALID secrets found!")
        else:
            print(f"  {GREEN}Credentials:{NC} {len(creds)} secrets detected")

        # WAF
        waf = self.results.get("waf_info")
        if waf:
            print(f"  {CYAN}WAF:{NC} {waf['waf_name']} "
                  f"(confidence: {waf['confidence']:.0%})")

        # 报告
        if self.results.get("report_path"):
            print(f"\n  {GREEN}Report saved to: {self.results['report_path']}{NC}")

        print(f"{'═'*60}\n")


# ═══════════════════════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════════════════════

def load_config() -> dict:
    """加载配置"""
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    return {}


def main():
    parser = argparse.ArgumentParser(
        description="Bai Enhanced Scanner v2.0 - 增强安全扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enhanced_scanner.py --target example.com --all
  python enhanced_scanner.py --target example.com --cloud --takeover
  python enhanced_scanner.py --target example.com --api --creds
  python enhanced_scanner.py --target example.com --waf
  python enhanced_scanner.py --target example.com --report html
        """
    )
    parser.add_argument("--target", "-t", required=True, help="目标域名")
    parser.add_argument("--recon-dir", "-r", help="侦察数据目录")
    parser.add_argument("--all", "-a", action="store_true", help="运行所有模块")
    parser.add_argument("--surface", action="store_true", help="攻击面映射")
    parser.add_argument("--takeover", action="store_true", help="子域名接管检测")
    parser.add_argument("--cloud", action="store_true", help="云安全扫描")
    parser.add_argument("--api", action="store_true", help="API 安全测试")
    parser.add_argument("--creds", action="store_true", help="凭证泄露检测")
    parser.add_argument("--waf", action="store_true", help="WAF 分析")
    parser.add_argument("--report", choices=["markdown", "html", "json", "hackerone", "bugcrowd", "butian"],
                       default="markdown", help="报告格式")
    parser.add_argument("--output", "-o", help="报告输出目录")

    args = parser.parse_args()

    # 确定要运行的模块
    modules = []
    if args.all:
        modules = ["attack_surface", "takeover", "cloud", "api", "credentials", "waf"]
    else:
        if args.surface:
            modules.append("attack_surface")
        if args.takeover:
            modules.append("takeover")
        if args.cloud:
            modules.append("cloud")
        if args.api:
            modules.append("api")
        if args.creds:
            modules.append("credentials")
        if args.waf:
            modules.append("waf")

    if not modules:
        modules = ["attack_surface", "takeover", "cloud", "api", "credentials", "waf"]

    # 加载配置
    config = load_config()
    config.setdefault("report", {})["format"] = args.report
    if args.output:
        config["report"]["output_dir"] = args.output

    # 运行
    scanner = EnhancedScanner(config)
    asyncio.run(scanner.full_scan(args.target, recon_dir=args.recon_dir, modules=modules))


if __name__ == "__main__":
    main()
