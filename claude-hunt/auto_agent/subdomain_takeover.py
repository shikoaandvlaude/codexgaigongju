#!/usr/bin/env python3
"""
Subdomain Takeover Scanner — 子域名接管检测引擎

功能：
1. CNAME 悬挂检测（Dangling CNAME）
2. 多云服务商指纹匹配（AWS/Azure/GCP/GitHub/Heroku 等）
3. NS 委派接管检测
4. 自动验证可接管性
5. PoC 生成（声明接管步骤）

支持检测的服务：
- AWS S3/CloudFront/Elastic Beanstalk
- Azure (Blob/App Service/Traffic Manager)
- GitHub Pages / Heroku / Netlify / Vercel
- Shopify / Fastly / Pantheon / Zendesk
- Google Cloud Storage / Firebase

用法：
    from subdomain_takeover import SubdomainTakeoverScanner
    
    scanner = SubdomainTakeoverScanner()
    results = await scanner.scan("example.com", subdomains_file="subs.txt")
"""

import asyncio
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime



# ═══════════════════════════════════════════════════════════════
# 指纹库 — 可接管服务的特征
# ═══════════════════════════════════════════════════════════════

TAKEOVER_SIGNATURES = {
    "aws_s3": {
        "cnames": [".s3.amazonaws.com", ".s3-website"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "difficulty": "easy",
        "steps": "1. Create S3 bucket with matching name\n2. Upload index.html\n3. Verify control",
    },
    "aws_cloudfront": {
        "cnames": [".cloudfront.net"],
        "fingerprint": ["Bad Request", "ERROR: The request could not be satisfied"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create CloudFront distribution\n2. Add CNAME as alternate domain\n3. Verify",
    },
    "aws_eb": {
        "cnames": [".elasticbeanstalk.com"],
        "fingerprint": ["NXDOMAIN"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create EB environment with matching CNAME\n2. Deploy app\n3. Verify",
    },
    "github_pages": {
        "cnames": [".github.io", "github.map.fastly.net"],
        "fingerprint": ["There isn't a GitHub Pages site here", "For root URLs"],
        "severity": "medium",
        "difficulty": "easy",
        "steps": "1. Create GitHub repo with matching name\n2. Enable Pages\n3. Add CNAME file",
    },
    "heroku": {
        "cnames": [".herokuapp.com", ".herokudns.com", ".herokussl.com"],
        "fingerprint": ["No such app", "herokucdn.com/error-pages"],
        "severity": "high",
        "difficulty": "easy",
        "steps": "1. Create Heroku app with matching name\n2. Add custom domain\n3. Verify",
    },
    "azure_blob": {
        "cnames": [".blob.core.windows.net"],
        "fingerprint": ["BlobNotFound", "The specified blob does not exist"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create Azure storage account\n2. Create container\n3. Verify",
    },

    "azure_app_service": {
        "cnames": [".azurewebsites.net", ".azure-api.net", ".cloudapp.azure.com"],
        "fingerprint": ["404 Web Site not found", "Azure App Service"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create Azure App Service\n2. Add custom domain binding\n3. Verify",
    },
    "azure_traffic_manager": {
        "cnames": [".trafficmanager.net"],
        "fingerprint": ["NXDOMAIN"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create Traffic Manager with matching name\n2. Verify",
    },
    "shopify": {
        "cnames": [".myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable", "Only one step left"],
        "severity": "medium",
        "difficulty": "easy",
        "steps": "1. Create Shopify store\n2. Add custom domain\n3. Verify",
    },
    "netlify": {
        "cnames": [".netlify.app", ".netlify.com", "netlify.com"],
        "fingerprint": ["Not Found - Request ID", "Page not found"],
        "severity": "medium",
        "difficulty": "easy",
        "steps": "1. Create Netlify site\n2. Add custom domain\n3. Deploy\n4. Verify",
    },
    "vercel": {
        "cnames": [".vercel.app", "cname.vercel-dns.com"],
        "fingerprint": ["The deployment could not be found"],
        "severity": "medium",
        "difficulty": "easy",
        "steps": "1. Create Vercel project\n2. Add domain\n3. Verify",
    },
    "fastly": {
        "cnames": [".fastly.net", ".fastlylb.net"],
        "fingerprint": ["Fastly error: unknown domain"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create Fastly service\n2. Add domain to service\n3. Verify",
    },
    "google_cloud": {
        "cnames": [".storage.googleapis.com", ".c.storage.googleapis.com"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "severity": "high",
        "difficulty": "medium",
        "steps": "1. Create GCS bucket with matching name\n2. Upload content\n3. Verify",
    },
    "firebase": {
        "cnames": [".firebaseapp.com", ".web.app"],
        "fingerprint": ["Firebase Hosting Setup Complete", "Site Not Found"],
        "severity": "medium",
        "difficulty": "easy",
        "steps": "1. Create Firebase project\n2. Connect custom domain\n3. Deploy",
    },
    "zendesk": {
        "cnames": [".zendesk.com"],
        "fingerprint": ["Help Center Closed", "Oops, this help center"],
        "severity": "low",
        "difficulty": "medium",
        "steps": "1. Create Zendesk account\n2. Add custom host mapping\n3. Verify",
    },
    "pantheon": {
        "cnames": [".pantheonsite.io", ".pantheon.io"],
        "fingerprint": ["404 error unknown site", "The gods have no"],
        "severity": "medium",
        "difficulty": "medium",
        "steps": "1. Create Pantheon site\n2. Add custom domain\n3. Verify",
    },
}



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class TakeoverResult:
    """接管检测结果"""
    subdomain: str = ""
    cname: str = ""
    service: str = ""
    vulnerable: bool = False
    confidence: str = "low"  # low/medium/high/confirmed
    severity: str = "medium"
    difficulty: str = "medium"
    fingerprint_matched: str = ""
    takeover_steps: str = ""
    http_status: int = 0
    response_excerpt: str = ""
    timestamp: str = ""


# ═══════════════════════════════════════════════════════════════
# 扫描器
# ═══════════════════════════════════════════════════════════════

class SubdomainTakeoverScanner:
    """子域名接管扫描器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 20)
        self.results: List[TakeoverResult] = []

    async def scan(self, target: str, subdomains_file: str = None,
                   subdomains: List[str] = None) -> List[TakeoverResult]:
        """
        扫描子域名接管漏洞
        
        Args:
            target: 主域名
            subdomains_file: 子域名文件路径
            subdomains: 子域名列表
        """
        self.results = []

        # 收集子域名
        subs = []
        if subdomains:
            subs = subdomains
        elif subdomains_file and Path(subdomains_file).exists():
            subs = [l.strip() for l in Path(subdomains_file).read_text().splitlines() if l.strip()]
        else:
            print(f"[!] No subdomains provided for {target}")
            return []

        print(f"[*] Scanning {len(subs)} subdomains for takeover vulnerabilities...")

        # 并发扫描
        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = [self._check_subdomain(sub, semaphore) for sub in subs]
        await asyncio.gather(*tasks, return_exceptions=True)

        # 过滤有效结果
        vulnerable = [r for r in self.results if r.vulnerable]
        print(f"\n[+] Takeover scan complete: {len(vulnerable)} vulnerable / {len(subs)} total")

        return self.results


    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        """检查单个子域名"""
        async with semaphore:
            try:
                # Step 1: DNS 解析获取 CNAME
                cname = await self._resolve_cname(subdomain)
                if not cname:
                    return

                # Step 2: 匹配已知服务指纹
                service, sig = self._match_service(cname)
                if not service:
                    return

                # Step 3: HTTP 探测验证
                is_vuln, fingerprint, status, excerpt = await self._probe_http(subdomain, sig)

                result = TakeoverResult(
                    subdomain=subdomain,
                    cname=cname,
                    service=service,
                    vulnerable=is_vuln,
                    confidence="high" if is_vuln else "low",
                    severity=sig.get("severity", "medium"),
                    difficulty=sig.get("difficulty", "medium"),
                    fingerprint_matched=fingerprint,
                    takeover_steps=sig.get("steps", ""),
                    http_status=status,
                    response_excerpt=excerpt[:200],
                    timestamp=datetime.now().isoformat(),
                )
                self.results.append(result)

                if is_vuln:
                    print(f"  [!] VULNERABLE: {subdomain} -> {cname} ({service})")
                else:
                    pass  # 静默处理非漏洞

            except Exception as e:
                pass  # 忽略单个失败

    async def _resolve_cname(self, subdomain: str) -> str:
        """DNS 解析获取 CNAME"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            output = stdout.decode().strip()
            if output and not output.startswith(";"):
                # 取第一个 CNAME
                cname = output.splitlines()[0].rstrip(".")
                return cname
        except (asyncio.TimeoutError, Exception):
            pass
        return ""

    def _match_service(self, cname: str) -> Tuple[str, Dict]:
        """匹配 CNAME 到已知服务"""
        cname_lower = cname.lower()
        for service, sig in TAKEOVER_SIGNATURES.items():
            for pattern in sig["cnames"]:
                if pattern in cname_lower:
                    return service, sig
        return "", {}


    async def _probe_http(self, subdomain: str, sig: Dict) -> Tuple[bool, str, int, str]:
        """HTTP 探测验证指纹"""
        fingerprints = sig.get("fingerprint", [])
        
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
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

                # 分离 body 和 status code
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else output
                status = int(lines[-1]) if lines[-1].isdigit() else 0

                # 检查指纹
                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        return True, fp, status, body[:500]

                # NXDOMAIN 特殊检查
                if "NXDOMAIN" in fingerprints and status == 0:
                    # 验证 DNS 是否真的 NXDOMAIN
                    nxd = await self._check_nxdomain(subdomain)
                    if nxd:
                        return True, "NXDOMAIN", 0, "DNS resolution failed (NXDOMAIN)"

            except (asyncio.TimeoutError, Exception):
                continue

        return False, "", 0, ""

    async def _check_nxdomain(self, subdomain: str) -> bool:
        """检查是否为 NXDOMAIN"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode().strip()
            return not output  # 空结果 = NXDOMAIN
        except Exception:
            return False

    def generate_report(self) -> str:
        """生成接管检测报告"""
        vulnerable = [r for r in self.results if r.vulnerable]
        if not vulnerable:
            return "No subdomain takeover vulnerabilities found."

        lines = [
            "=" * 60,
            "  SUBDOMAIN TAKEOVER REPORT",
            "=" * 60,
            f"  Vulnerable: {len(vulnerable)} subdomains\n",
        ]
        for r in sorted(vulnerable, key=lambda x: x.severity, reverse=True):
            lines.append(f"  [{r.severity.upper()}] {r.subdomain}")
            lines.append(f"    CNAME: {r.cname}")
            lines.append(f"    Service: {r.service}")
            lines.append(f"    Fingerprint: {r.fingerprint_matched}")
            lines.append(f"    Difficulty: {r.difficulty}")
            lines.append(f"    Steps:")
            for step in r.takeover_steps.split("\n"):
                lines.append(f"      {step}")
            lines.append("")

        return "\n".join(lines)
