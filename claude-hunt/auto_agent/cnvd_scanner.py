#!/usr/bin/env python3
"""
CNVD Scanner — 面向 CNVD 通用型漏洞的批量扫描引擎

功能：
1. FOFA 资产收集（批量获取目标 URL）
2. 指纹识别（确认目标系统类型和版本）
3. POC 批量验证（检测已知漏洞是否存在）
4. 结果去重 + 影响范围统计
5. CNVD 通用型报告生成

用法：
    from cnvd_scanner import CNVDScanner

    scanner = CNVDScanner(config)

    # 扫描指定系统
    results = await scanner.scan_system("泛微")

    # 全量扫描
    results = await scanner.scan_all()

    # 只用 FOFA 收集资产
    urls = await scanner.fofa_collect("app=\"帆软-FineReport\"")

⚠️ 仅用于已授权的安全测试和漏洞提交
"""

import asyncio
import json
import hashlib
import time
import subprocess
import re
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class CNVDFinding:
    """CNVD 扫描发现"""
    system_name: str = ""          # 目标系统名称
    vendor: str = ""               # 厂商
    vuln_name: str = ""            # 漏洞名称
    vuln_type: str = ""            # sqli/rce/upload/unauth/ssrf/deserialize/lfi
    severity: str = "high"         # critical/high/medium/low
    # 目标信息
    target_url: str = ""           # 目标 URL
    target_ip: str = ""            # 目标 IP
    target_title: str = ""         # 页面标题
    # 验证信息
    poc_path: str = ""             # POC 请求路径
    poc_method: str = "GET"        # 请求方法
    response_status: int = 0       # 响应状态码
    response_excerpt: str = ""     # 响应片段（证据）
    confirmed: bool = False        # 是否确认存在
    # CNVD 提交相关
    affected_count: int = 0        # 影响实例数量
    cve_id: str = ""
    xve_id: str = ""
    # 元数据
    timestamp: str = ""
    fofa_query: str = ""           # 发现时使用的 FOFA 语法


@dataclass
class ScanResult:
    """扫描结果汇总"""
    system_name: str = ""
    total_targets: int = 0         # 总共发现的目标数
    scanned: int = 0               # 已扫描数
    vulnerable: int = 0            # 存在漏洞数
    findings: List[CNVDFinding] = field(default_factory=list)
    scan_time: str = ""
    cnvd_submittable: bool = False  # 是否达到 CNVD 通用型提交门槛（≥3个实例）



# ═══════════════════════════════════════════════════════════════
# CNVD 扫描引擎
# ═══════════════════════════════════════════════════════════════

class CNVDScanner:
    """CNVD 通用型漏洞批量扫描器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.cnvd_config = self.config.get("cnvd_scanner", {})
        self.timeout = self.cnvd_config.get("timeout", 10)
        self.concurrent = self.cnvd_config.get("concurrent", 5)
        self.max_targets = self.cnvd_config.get("max_targets_per_system", 50)
        self.fofa_key = self.cnvd_config.get("fofa_key", "") or os.environ.get("FOFA_KEY", "")
        self.fofa_email = self.cnvd_config.get("fofa_email", "") or os.environ.get("FOFA_EMAIL", "")
        self.delay = self.cnvd_config.get("delay_between_requests", 2)
        self.findings: List[CNVDFinding] = []
        self.results: List[ScanResult] = []

    async def scan_system(self, system_name: str) -> ScanResult:
        """扫描指定系统的所有已知漏洞"""
        from cnvd_targets import get_system_by_name

        target_system = get_system_by_name(system_name)
        if not target_system:
            print(f"[!] 未找到系统: {system_name}")
            return ScanResult()

        print(f"\n{'='*60}")
        print(f"[*] CNVD 扫描: {target_system.name} ({target_system.vendor})")
        print(f"{'='*60}")

        # Step 1: FOFA 收集目标
        targets = await self._fofa_collect_targets(target_system)
        if not targets:
            print(f"[!] 未收集到目标，跳过")
            return ScanResult(system_name=target_system.name)

        print(f"[+] 收集到 {len(targets)} 个目标")

        # Step 2: 指纹确认
        confirmed_targets = await self._fingerprint_verify(targets, target_system)
        print(f"[+] 指纹确认: {len(confirmed_targets)}/{len(targets)}")

        # Step 3: POC 批量验证
        result = await self._batch_poc_verify(confirmed_targets, target_system)

        # 判断是否达到 CNVD 通用型门槛
        result.cnvd_submittable = result.vulnerable >= 3

        if result.cnvd_submittable:
            print(f"\n[★] 达到 CNVD 通用型提交门槛！影响 {result.vulnerable} 个实例")
        else:
            print(f"\n[*] 发现 {result.vulnerable} 个脆弱实例（需≥3个才能提交通用型）")

        self.results.append(result)
        return result



    async def scan_all(self, priority: str = "high") -> List[ScanResult]:
        """扫描所有指定优先级的系统"""
        from cnvd_targets import get_targets_by_priority

        targets = get_targets_by_priority(priority)
        print(f"\n[*] CNVD 全量扫描: {len(targets)} 个系统 (优先级: {priority})")

        results = []
        for target_system in targets:
            result = await self.scan_system(target_system.name)
            results.append(result)
            # 系统间延迟
            await asyncio.sleep(5)

        # 汇总
        total_vuln = sum(r.vulnerable for r in results)
        submittable = [r for r in results if r.cnvd_submittable]

        print(f"\n{'='*60}")
        print(f"[★] 扫描完成汇总")
        print(f"    系统数: {len(targets)}")
        print(f"    总脆弱实例: {total_vuln}")
        print(f"    可提交 CNVD 通用型: {len(submittable)} 个系统")
        print(f"{'='*60}")

        return results

    async def scan_edu(self) -> List[ScanResult]:
        """专门扫描教育网目标（EDUSRC 用）"""
        from cnvd_targets import FOFA_EDU_QUERIES

        print(f"\n[*] EDUSRC 教育网扫描: {len(FOFA_EDU_QUERIES)} 个类别")

        results = []
        for category, query in FOFA_EDU_QUERIES.items():
            print(f"\n[*] 扫描类别: {category}")
            targets = await self.fofa_collect(query)
            if targets:
                print(f"[+] {category}: 发现 {len(targets)} 个目标")
                result = ScanResult(
                    system_name=f"EDU-{category}",
                    total_targets=len(targets),
                    scan_time=datetime.now().isoformat(),
                )
                results.append(result)
            await asyncio.sleep(3)

        return results



    # ═══════════════════════════════════════════════════════════
    # FOFA 资产收集
    # ═══════════════════════════════════════════════════════════

    async def fofa_collect(self, query: str, max_results: int = None) -> List[Dict]:
        """
        通过 FOFA API 收集目标资产
        返回: [{"url": "...", "ip": "...", "title": "...", "port": ...}, ...]
        """
        max_results = max_results or self.max_targets

        if not self.fofa_key or not self.fofa_email:
            print(f"[!] FOFA API 未配置，尝试使用 fofa-hack 工具")
            return await self._fofa_collect_cli(query, max_results)

        # FOFA API 调用
        import base64
        encoded_query = base64.b64encode(query.encode()).decode()
        api_url = (
            f"https://fofa.info/api/v1/search/all?"
            f"email={self.fofa_email}&key={self.fofa_key}"
            f"&qbase64={encoded_query}"
            f"&size={max_results}"
            f"&fields=host,ip,port,title,protocol"
        )

        try:
            result = await self._async_curl(api_url)
            if result and result.get("results"):
                targets = []
                for item in result["results"]:
                    host, ip, port, title, protocol = item[0], item[1], item[2], item[3], item[4]
                    url = f"{protocol}://{host}" if protocol else f"http://{host}"
                    targets.append({
                        "url": url,
                        "ip": ip,
                        "port": port,
                        "title": title,
                    })
                return targets[:max_results]
        except Exception as e:
            print(f"[!] FOFA API 调用失败: {e}")

        return []

    async def _fofa_collect_cli(self, query: str, max_results: int) -> List[Dict]:
        """使用命令行工具收集 FOFA 数据（备用方案）"""
        # 尝试使用 fofa-hack 或类似工具
        try:
            cmd = f'fofa search -s {max_results} "{query}" 2>/dev/null'
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            targets = []
            for line in output.strip().split("\n"):
                line = line.strip()
                if line and ("http" in line or ":" in line):
                    targets.append({"url": line, "ip": "", "port": "", "title": ""})

            return targets[:max_results]
        except Exception:
            print(f"[!] CLI FOFA 工具不可用，请配置 FOFA API Key")
            return []



    # ═══════════════════════════════════════════════════════════
    # 指纹识别
    # ═══════════════════════════════════════════════════════════

    async def _fofa_collect_targets(self, target_system) -> List[Dict]:
        """为指定系统收集 FOFA 目标"""
        all_targets = []
        seen_hosts = set()

        for query in target_system.fofa_queries[:3]:  # 最多用 3 个查询
            targets = await self.fofa_collect(query)
            for t in targets:
                host = urlparse(t.get("url", "")).netloc
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    all_targets.append(t)
            await asyncio.sleep(2)

        return all_targets[:self.max_targets]

    async def _fingerprint_verify(self, targets: List[Dict], target_system) -> List[Dict]:
        """指纹验证：确认目标确实是指定系统"""
        semaphore = asyncio.Semaphore(self.concurrent)
        confirmed = []

        async def verify_one(target):
            async with semaphore:
                url = target.get("url", "")
                if not url:
                    return
                try:
                    # 简单 GET 首页检查指纹
                    cmd = f'curl -sk -m {self.timeout} -o /dev/null -w "%{{http_code}}" "{url}/" 2>/dev/null'
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
                    status = stdout.decode().strip()

                    if status and status != "000":
                        # 获取响应体做指纹匹配
                        cmd2 = f'curl -sk -m {self.timeout} "{url}/" 2>/dev/null | head -c 5000'
                        proc2 = await asyncio.create_subprocess_shell(
                            cmd2,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=self.timeout + 5)
                        body = stdout2.decode(errors="ignore")

                        # 匹配指纹
                        for fp in target_system.fingerprints:
                            if fp.get("type") == "body" and fp.get("pattern", "").lower() in body.lower():
                                confirmed.append(target)
                                return
                            elif fp.get("type") == "title":
                                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
                                if title_match and fp.get("pattern", "").lower() in title_match.group(1).lower():
                                    confirmed.append(target)
                                    return
                except Exception:
                    pass
                finally:
                    await asyncio.sleep(self.delay)

        tasks = [verify_one(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        return confirmed



    # ═══════════════════════════════════════════════════════════
    # POC 批量验证
    # ═══════════════════════════════════════════════════════════

    async def _batch_poc_verify(self, targets: List[Dict], target_system) -> ScanResult:
        """对确认目标批量执行 POC 验证"""
        result = ScanResult(
            system_name=target_system.name,
            total_targets=len(targets),
            scan_time=datetime.now().isoformat(),
        )

        semaphore = asyncio.Semaphore(self.concurrent)

        async def verify_target(target):
            async with semaphore:
                url = target.get("url", "").rstrip("/")
                if not url:
                    return

                result.scanned += 1

                for poc in target_system.pocs:
                    finding = await self._execute_poc(url, poc, target)
                    if finding and finding.confirmed:
                        result.vulnerable += 1
                        result.findings.append(finding)
                        self.findings.append(finding)
                        print(f"  [!] 确认漏洞: {url} — {poc['name']}")
                        break  # 一个目标确认一个漏洞即可

                await asyncio.sleep(self.delay)

        tasks = [verify_target(t) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)
        return result

    async def _execute_poc(self, base_url: str, poc: Dict, target: Dict) -> Optional[CNVDFinding]:
        """执行单个 POC"""
        try:
            url = urljoin(base_url + "/", poc["path"].lstrip("/"))
            method = poc.get("method", "GET")
            content_type = poc.get("content_type", "")
            body = poc.get("body", "")

            # 构造 curl 命令
            cmd_parts = [f'curl -sk -m {self.timeout} -w "\\n%{{http_code}}"']
            cmd_parts.append(f'-X {method}')

            if content_type:
                cmd_parts.append(f'-H "Content-Type: {content_type}"')

            # 额外 headers
            for k, v in poc.get("headers", {}).items():
                cmd_parts.append(f'-H "{k}: {v}"')

            if body and method in ("POST", "PUT"):
                # 转义单引号
                safe_body = body.replace("'", "'\\''")
                cmd_parts.append(f"-d '{safe_body}'")

            cmd_parts.append(f'"{url}"')
            cmd_parts.append("2>/dev/null")

            cmd = " ".join(cmd_parts)

            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")

            # 解析响应
            lines = output.strip().split("\n")
            status_code = 0
            response_body = ""
            if lines:
                try:
                    status_code = int(lines[-1].strip())
                    response_body = "\n".join(lines[:-1])
                except ValueError:
                    response_body = output

            # 验证 POC 是否命中
            confirmed = self._verify_poc_result(poc, status_code, response_body)

            if confirmed:
                return CNVDFinding(
                    system_name=poc.get("name", "").split(" ")[0] if " " in poc.get("name", "") else "",
                    vendor="",
                    vuln_name=poc["name"],
                    vuln_type=poc.get("vuln_type", ""),
                    severity=poc.get("severity", "high"),
                    target_url=base_url,
                    target_ip=target.get("ip", ""),
                    target_title=target.get("title", ""),
                    poc_path=poc["path"],
                    poc_method=method,
                    response_status=status_code,
                    response_excerpt=response_body[:500],
                    confirmed=True,
                    cve_id=poc.get("cve_id", ""),
                    xve_id=poc.get("xve_id", ""),
                    timestamp=datetime.now().isoformat(),
                )

        except Exception as e:
            pass

        return None



    def _verify_poc_result(self, poc: Dict, status_code: int, response_body: str) -> bool:
        """验证 POC 执行结果是否确认漏洞存在"""
        # 检查状态码
        expected_status = poc.get("match_status", [])
        if expected_status and status_code not in expected_status:
            return False

        # 检查响应体必须包含的关键字
        match_body = poc.get("match_body", [])
        if match_body:
            body_lower = response_body.lower()
            if not any(kw.lower() in body_lower for kw in match_body):
                return False

        # 检查响应体不应包含的关键字（排除误报）
        not_match = poc.get("not_match_body", [])
        if not_match:
            body_lower = response_body.lower()
            if any(kw.lower() in body_lower for kw in not_match):
                return False

        # 如果没有任何匹配规则，只看状态码
        if not match_body and not expected_status:
            return False

        return True

    # ═══════════════════════════════════════════════════════════
    # 工具方法
    # ═══════════════════════════════════════════════════════════

    async def _async_curl(self, url: str) -> Optional[Dict]:
        """异步执行 curl 并返回 JSON"""
        try:
            cmd = f'curl -sk -m {self.timeout} "{url}" 2>/dev/null'
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            return json.loads(stdout.decode())
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════
    # 报告生成
    # ═══════════════════════════════════════════════════════════

    def generate_cnvd_report(self, result: ScanResult) -> str:
        """生成 CNVD 通用型漏洞报告"""
        if not result.findings:
            return ""

        # 取第一个 finding 作为代表
        sample = result.findings[0]

        report = f"""
{'='*60}
CNVD 通用型漏洞报告
{'='*60}

【漏洞名称】{sample.vuln_name}
【漏洞类型】{sample.vuln_type}
【危害等级】{sample.severity}
【影响产品】{result.system_name}
【影响实例数】{result.vulnerable} 个（已验证）

{'='*60}
漏洞描述
{'='*60}

{sample.vuln_name}，属于{sample.vuln_type}类漏洞。
经 FOFA 搜索引擎发现互联网上存在大量受影响实例，
已验证 {result.vulnerable} 个实例存在该漏洞。

{'='*60}
复现步骤
{'='*60}

目标URL（示例）: {sample.target_url}
请求方法: {sample.poc_method}
请求路径: {sample.poc_path}
响应状态码: {sample.response_status}

响应证据:
{sample.response_excerpt[:300]}

{'='*60}
影响范围（部分实例）
{'='*60}
"""
        for i, f in enumerate(result.findings[:10], 1):
            report += f"\n{i}. {f.target_url} (IP: {f.target_ip})"

        report += f"""

{'='*60}
修复建议
{'='*60}

1. 升级至最新版本
2. 对受影响接口添加认证控制
3. 部署 WAF 规则拦截恶意请求
4. 限制管理接口的公网访问

{'='*60}
"""
        return report



    def generate_summary(self) -> str:
        """生成扫描汇总"""
        lines = [
            f"\n{'='*60}",
            f"CNVD 批量扫描汇总 — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"{'='*60}\n",
        ]

        for r in self.results:
            status = "★ 可提交" if r.cnvd_submittable else "  待补充"
            lines.append(
                f"  {status} | {r.system_name:20s} | "
                f"目标:{r.total_targets:3d} | 脆弱:{r.vulnerable:3d}"
            )

        total_vuln = sum(r.vulnerable for r in self.results)
        submittable = sum(1 for r in self.results if r.cnvd_submittable)
        lines.append(f"\n  总计: {total_vuln} 个脆弱实例, {submittable} 个系统可提交 CNVD 通用型")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# CLI 入口（独立运行）
# ═══════════════════════════════════════════════════════════════

async def main():
    """CLI 入口"""
    import argparse
    import yaml

    parser = argparse.ArgumentParser(description="CNVD 通用型漏洞批量扫描器")
    parser.add_argument("--system", "-s", help="指定扫描系统（如: 泛微, 用友, 帆软）")
    parser.add_argument("--all", "-a", action="store_true", help="扫描所有高优先级系统")
    parser.add_argument("--edu", action="store_true", help="教育网目标扫描（EDUSRC）")
    parser.add_argument("--priority", "-p", default="high", choices=["high", "medium", "low"],
                        help="扫描优先级 (default: high)")
    parser.add_argument("--config", "-c", default="config.yaml", help="配置文件路径")
    parser.add_argument("--list", "-l", action="store_true", help="列出所有可扫描系统")
    args = parser.parse_args()

    # 列出系统
    if args.list:
        from cnvd_targets import ALL_TARGETS
        print("\n可扫描系统列表:\n")
        print(f"  {'系统名称':20s} | {'厂商':8s} | {'CNVD价值':8s} | POC数")
        print(f"  {'-'*20} | {'-'*8} | {'-'*8} | {'-'*5}")
        for t in ALL_TARGETS:
            print(f"  {t.name:20s} | {t.vendor:8s} | {t.cnvd_value:8s} | {len(t.pocs)}")
        return

    # 加载配置
    config = {}
    config_path = os.path.join(os.path.dirname(__file__), args.config)
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

    scanner = CNVDScanner(config)

    if args.system:
        result = await scanner.scan_system(args.system)
        if result.cnvd_submittable:
            report = scanner.generate_cnvd_report(result)
            print(report)
    elif args.edu:
        await scanner.scan_edu()
    elif args.all:
        await scanner.scan_all(priority=args.priority)
        print(scanner.generate_summary())
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
