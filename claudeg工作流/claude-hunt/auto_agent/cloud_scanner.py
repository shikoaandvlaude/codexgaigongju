#!/usr/bin/env python3
"""
Cloud Security Scanner — 云环境安全扫描引擎

功能：
1. AWS S3 Bucket 枚举与权限检测
2. Azure Blob 存储公开访问检测
3. GCP Storage Bucket 检测
4. 云服务元数据泄露（SSRF→IMDS）
5. Kubernetes API 暴露检测
6. Docker Registry 未授权访问
7. 云配置错误检测（IAM/SG/公开资源）

用法：
    from cloud_scanner import CloudSecurityScanner
    
    scanner = CloudSecurityScanner(config)
    results = await scanner.scan_target("example.com")
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
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class CloudFinding:
    """云安全发现"""
    service: str = ""  # aws_s3/azure_blob/gcp_storage/k8s/docker/imds
    resource: str = ""
    vulnerability: str = ""
    severity: str = "medium"  # critical/high/medium/low/info
    # 详情
    url: str = ""
    evidence: str = ""
    permissions: List[str] = field(default_factory=list)
    data_exposed: str = ""
    # 利用
    exploitable: bool = False
    exploit_steps: str = ""
    impact: str = ""
    # 元数据
    timestamp: str = ""
    confidence: str = "medium"


# ═══════════════════════════════════════════════════════════════
# S3 Bucket 常见命名模式
# ═══════════════════════════════════════════════════════════════

BUCKET_PATTERNS = [
    "{domain}", "{domain}-backup", "{domain}-bak", "{domain}-dev",
    "{domain}-staging", "{domain}-prod", "{domain}-test",
    "{domain}-assets", "{domain}-static", "{domain}-media",
    "{domain}-uploads", "{domain}-files", "{domain}-data",
    "{domain}-logs", "{domain}-db", "{domain}-backup-db",
    "{company}-internal", "{company}-private", "{company}-public",
    "{company}-cdn", "{company}-images", "{company}-docs",
    "backup-{domain}", "dev-{domain}", "staging-{domain}",
    "{domain}-website", "{domain}-api", "{domain}-app",
]

# IMDS 端点（云实例元数据服务）
IMDS_ENDPOINTS = {
    "aws": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "token_url": "http://169.254.169.254/latest/api/token",
        "paths": [
            "iam/security-credentials/",
            "iam/info",
            "hostname",
            "public-keys/",
            "network/interfaces/macs/",
        ]
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "paths": [
            "project/project-id",
            "instance/service-accounts/default/token",
            "instance/attributes/",
        ]
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance",
        "params": "api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "paths": [
            "?api-version=2021-02-01",
            "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ]
    },
}



# K8s 常见暴露路径
K8S_PATHS = [
    "/api", "/api/v1", "/apis", "/version",
    "/api/v1/namespaces", "/api/v1/pods",
    "/api/v1/secrets", "/api/v1/configmaps",
    "/healthz", "/metrics", "/debug/pprof/",
    "/api/v1/namespaces/default/secrets",
    "/api/v1/namespaces/kube-system/secrets",
    "/apis/apps/v1/deployments",
]

# Docker Registry 路径
DOCKER_REGISTRY_PATHS = [
    "/v2/", "/v2/_catalog",
]


class CloudSecurityScanner:
    """云安全扫描器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 15)
        self.findings: List[CloudFinding] = []

    async def scan_target(self, target: str, subdomains: List[str] = None) -> List[CloudFinding]:
        """
        完整云安全扫描
        """
        self.findings = []
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        company = domain.split(".")[0]

        print(f"[*] Cloud Security Scan: {domain}")

        # 并行扫描各模块
        tasks = [
            self._scan_s3_buckets(domain, company),
            self._scan_azure_blobs(domain, company),
            self._scan_gcp_buckets(domain, company),
            self._scan_k8s_exposure(domain, subdomains or []),
            self._scan_docker_registries(domain, subdomains or []),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # 按严重性排序
        self.findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5))

        vuln_count = len([f for f in self.findings if f.severity in ("critical", "high")])
        print(f"[+] Cloud scan complete: {len(self.findings)} findings ({vuln_count} critical/high)")

        return self.findings

    # ═══════════════════════════════════════════════════════════════
    # AWS S3
    # ═══════════════════════════════════════════════════════════════

    async def _scan_s3_buckets(self, domain: str, company: str):
        """枚举和检测 S3 Bucket 权限"""
        candidates = self._generate_bucket_names(domain, company)
        semaphore = asyncio.Semaphore(self.concurrent)

        tasks = [self._check_s3_bucket(name, semaphore) for name in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)


    async def _check_s3_bucket(self, bucket_name: str, semaphore: asyncio.Semaphore):
        """检查单个 S3 Bucket"""
        async with semaphore:
            url = f"https://{bucket_name}.s3.amazonaws.com"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "-m", str(self.timeout),
                    "-o", "-", "-w", "\n%{http_code}", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
                output = stdout.decode(errors="ignore")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else output
                status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0

                if status == 200:
                    # Bucket exists and is listable
                    perms = ["LIST"]
                    if "<Contents>" in body or "<Key>" in body:
                        perms.append("READ")
                    self.findings.append(CloudFinding(
                        service="aws_s3",
                        resource=bucket_name,
                        vulnerability="S3 Bucket Public Listing",
                        severity="high",
                        url=url,
                        evidence=body[:300],
                        permissions=perms,
                        exploitable=True,
                        exploit_steps=f"aws s3 ls s3://{bucket_name} --no-sign-request",
                        impact="Data exposure - bucket contents are publicly listable",
                        timestamp=datetime.now().isoformat(),
                        confidence="high",
                    ))
                    print(f"  [!] S3 PUBLIC: {bucket_name} (listable)")

                elif status == 403:
                    # Bucket exists but not listable - still useful info
                    # Try PUT to check write access
                    await self._check_s3_write(bucket_name, semaphore)

            except (asyncio.TimeoutError, Exception):
                pass

    async def _check_s3_write(self, bucket_name: str, semaphore: asyncio.Semaphore):
        """检查 S3 写入权限"""
        url = f"https://{bucket_name}.s3.amazonaws.com/takeover-test-{int(time.time())}.txt"
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sk", "-m", str(self.timeout),
                "-X", "PUT", "-d", "security-test",
                "-o", "/dev/null", "-w", "%{http_code}", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            status = int(stdout.decode().strip() or "0")

            if status == 200:
                self.findings.append(CloudFinding(
                    service="aws_s3",
                    resource=bucket_name,
                    vulnerability="S3 Bucket Public Write",
                    severity="critical",
                    url=url,
                    permissions=["WRITE"],
                    exploitable=True,
                    impact="Arbitrary file upload to bucket - potential defacement or malware hosting",
                    timestamp=datetime.now().isoformat(),
                    confidence="high",
                ))
                print(f"  [!!] S3 WRITABLE: {bucket_name}")
        except Exception:
            pass


    # ═══════════════════════════════════════════════════════════════
    # Azure Blob
    # ═══════════════════════════════════════════════════════════════

    async def _scan_azure_blobs(self, domain: str, company: str):
        """检测 Azure Blob Storage 公开访问"""
        candidates = [
            f"{company}", f"{company}dev", f"{company}prod",
            f"{company}backup", f"{company}data", f"{company}files",
            f"{domain.replace('.', '')}", f"{company}storage",
        ]
        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = [self._check_azure_blob(name, semaphore) for name in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_azure_blob(self, account: str, semaphore: asyncio.Semaphore):
        """检查单个 Azure Storage Account"""
        async with semaphore:
            # 检查 blob 容器列表
            url = f"https://{account}.blob.core.windows.net/?comp=list"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "-m", str(self.timeout),
                    "-o", "-", "-w", "\n%{http_code}", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
                output = stdout.decode(errors="ignore")
                lines = output.rsplit("\n", 1)
                body = lines[0]
                status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0

                if status == 200 and "<Containers>" in body:
                    self.findings.append(CloudFinding(
                        service="azure_blob",
                        resource=account,
                        vulnerability="Azure Blob Container Public Listing",
                        severity="high",
                        url=url,
                        evidence=body[:300],
                        permissions=["LIST"],
                        exploitable=True,
                        exploit_steps=f"curl '{url}' | xmllint --format -",
                        impact="Storage containers publicly enumerable",
                        timestamp=datetime.now().isoformat(),
                        confidence="high",
                    ))
                    print(f"  [!] Azure Blob PUBLIC: {account}")
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════
    # GCP Storage
    # ═══════════════════════════════════════════════════════════════

    async def _scan_gcp_buckets(self, domain: str, company: str):
        """检测 GCP Storage Bucket"""
        candidates = [
            f"{company}", f"{company}-backup", f"{company}-data",
            f"{domain.replace('.', '-')}", f"{company}-prod",
            f"{company}-staging", f"{company}-assets",
        ]
        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = [self._check_gcp_bucket(name, semaphore) for name in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)


    async def _check_gcp_bucket(self, bucket: str, semaphore: asyncio.Semaphore):
        """检查 GCP Bucket"""
        async with semaphore:
            url = f"https://storage.googleapis.com/{bucket}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "-m", str(self.timeout),
                    "-o", "-", "-w", "\n%{http_code}", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
                output = stdout.decode(errors="ignore")
                lines = output.rsplit("\n", 1)
                body = lines[0]
                status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0

                if status == 200 and ("<Contents>" in body or "<Key>" in body):
                    self.findings.append(CloudFinding(
                        service="gcp_storage",
                        resource=bucket,
                        vulnerability="GCP Bucket Public Listing",
                        severity="high",
                        url=url,
                        evidence=body[:300],
                        permissions=["LIST", "READ"],
                        exploitable=True,
                        exploit_steps=f"gsutil ls gs://{bucket}/",
                        impact="GCP bucket contents publicly accessible",
                        timestamp=datetime.now().isoformat(),
                        confidence="high",
                    ))
                    print(f"  [!] GCP Bucket PUBLIC: {bucket}")
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════
    # Kubernetes API
    # ═══════════════════════════════════════════════════════════════

    async def _scan_k8s_exposure(self, domain: str, subdomains: List[str]):
        """检测 K8s API 暴露"""
        targets = [domain] + [s for s in subdomains if any(
            k in s for k in ["k8s", "kube", "cluster", "api", "rancher", "argo"]
        )][:20]

        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = []
        for target in targets:
            for port in [443, 6443, 8443, 10250, 2379]:
                tasks.append(self._check_k8s_endpoint(target, port, semaphore))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_k8s_endpoint(self, host: str, port: int, semaphore: asyncio.Semaphore):
        """检查 K8s API 端点"""
        async with semaphore:
            for path in K8S_PATHS[:6]:  # 只测试最关键的路径
                url = f"https://{host}:{port}{path}"
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-sk", "-m", "5",
                        "-o", "-", "-w", "\n%{http_code}", url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                    output = stdout.decode(errors="ignore")
                    lines = output.rsplit("\n", 1)
                    body = lines[0]
                    status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0

                    if status == 200 and any(k in body for k in ['"kind"', '"apiVersion"', '"resources"']):
                        self.findings.append(CloudFinding(
                            service="kubernetes",
                            resource=f"{host}:{port}",
                            vulnerability=f"K8s API Exposed: {path}",
                            severity="critical",
                            url=url,
                            evidence=body[:300],
                            exploitable=True,
                            exploit_steps=f"kubectl --server={url} --insecure-skip-tls-verify get pods -A",
                            impact="Kubernetes API unauthenticated access - full cluster compromise",
                            timestamp=datetime.now().isoformat(),
                            confidence="high",
                        ))
                        print(f"  [!!] K8s API EXPOSED: {url}")
                        return  # 一个端口确认即可
                except Exception:
                    continue


    # ═══════════════════════════════════════════════════════════════
    # Docker Registry
    # ═══════════════════════════════════════════════════════════════

    async def _scan_docker_registries(self, domain: str, subdomains: List[str]):
        """检测 Docker Registry 未授权访问"""
        targets = [domain] + [s for s in subdomains if any(
            k in s for k in ["docker", "registry", "harbor", "cr", "images"]
        )][:15]

        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = []
        for target in targets:
            for port in [443, 5000, 8080]:
                tasks.append(self._check_docker_registry(target, port, semaphore))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_docker_registry(self, host: str, port: int, semaphore: asyncio.Semaphore):
        """检查 Docker Registry"""
        async with semaphore:
            for path in DOCKER_REGISTRY_PATHS:
                url = f"https://{host}:{port}{path}"
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "curl", "-sk", "-m", "5",
                        "-o", "-", "-w", "\n%{http_code}", url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                    output = stdout.decode(errors="ignore")
                    lines = output.rsplit("\n", 1)
                    body = lines[0]
                    status = int(lines[-1]) if len(lines) > 1 and lines[-1].isdigit() else 0

                    if status == 200:
                        if path == "/v2/_catalog" and "repositories" in body:
                            self.findings.append(CloudFinding(
                                service="docker_registry",
                                resource=f"{host}:{port}",
                                vulnerability="Docker Registry Unauthenticated Catalog",
                                severity="high",
                                url=url,
                                evidence=body[:300],
                                permissions=["LIST", "PULL"],
                                exploitable=True,
                                exploit_steps=f"curl -sk {url} | jq '.repositories[]'",
                                impact="Docker images publicly enumerable - source code/secrets exposure",
                                timestamp=datetime.now().isoformat(),
                                confidence="high",
                            ))
                            print(f"  [!] Docker Registry OPEN: {url}")
                            return
                        elif path == "/v2/" and ("Docker-Distribution-Api" in body or status == 200):
                            # v2 endpoint exists, check catalog
                            pass
                except Exception:
                    continue

    # ═══════════════════════════════════════════════════════════════
    # SSRF → IMDS (云实例元数据)
    # ═══════════════════════════════════════════════════════════════

    def generate_ssrf_payloads(self, cloud_provider: str = "all") -> List[Dict[str, str]]:
        """生成 SSRF 探测 IMDS 的 payload 列表"""
        payloads = []

        providers = [cloud_provider] if cloud_provider != "all" else ["aws", "gcp", "azure"]

        for provider in providers:
            config = IMDS_ENDPOINTS.get(provider, {})
            base_url = config.get("url", "")

            for path in config.get("paths", []):
                full_url = f"{base_url}{path}"
                payloads.append({
                    "provider": provider,
                    "url": full_url,
                    "description": f"{provider.upper()} IMDS: {path}",
                    "headers": config.get("headers", {}),
                })

        # 通用绕过变体
        bypass_prefixes = [
            "http://169.254.169.254",
            "http://[::ffff:a9fe:a9fe]",
            "http://0xA9FEA9FE",
            "http://2852039166",
            "http://169.254.169.254.nip.io",
            "http://0251.0376.0251.0376",
        ]
        for prefix in bypass_prefixes:
            payloads.append({
                "provider": "aws_bypass",
                "url": f"{prefix}/latest/meta-data/",
                "description": f"IMDS bypass variant: {prefix}",
            })

        return payloads


    # ═══════════════════════════════════════════════════════════════
    # 工具函数
    # ═══════════════════════════════════════════════════════════════

    def _generate_bucket_names(self, domain: str, company: str) -> List[str]:
        """生成候选 Bucket 名"""
        names = set()
        domain_clean = domain.replace(".", "-")
        domain_nodot = domain.replace(".", "")

        for pattern in BUCKET_PATTERNS:
            name = pattern.format(domain=domain_clean, company=company)
            names.add(name)
            # 无点变体
            name2 = pattern.format(domain=domain_nodot, company=company)
            names.add(name2)

        return list(names)[:60]  # 限制数量

    def generate_report(self) -> str:
        """生成云安全扫描报告"""
        if not self.findings:
            return "No cloud security issues found."

        lines = [
            "=" * 60,
            "  CLOUD SECURITY SCAN REPORT",
            "=" * 60,
            f"  Total findings: {len(self.findings)}",
            f"  Critical: {len([f for f in self.findings if f.severity == 'critical'])}",
            f"  High: {len([f for f in self.findings if f.severity == 'high'])}",
            f"  Medium: {len([f for f in self.findings if f.severity == 'medium'])}",
            "",
        ]

        for finding in self.findings:
            lines.append(f"  [{finding.severity.upper()}] {finding.vulnerability}")
            lines.append(f"    Service: {finding.service}")
            lines.append(f"    Resource: {finding.resource}")
            lines.append(f"    URL: {finding.url}")
            if finding.permissions:
                lines.append(f"    Permissions: {', '.join(finding.permissions)}")
            if finding.exploit_steps:
                lines.append(f"    Exploit: {finding.exploit_steps}")
            lines.append(f"    Impact: {finding.impact}")
            lines.append("")

        return "\n".join(lines)
