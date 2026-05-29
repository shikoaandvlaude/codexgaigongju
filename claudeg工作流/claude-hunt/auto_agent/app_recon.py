#!/usr/bin/env python3
"""
APP Recon — APP/IoT 类目标专用信息搜集模块
解决传统 Recon（subfinder/gau）对 APP 目标完全无效的问题

当检测到目标是 APP 包名（如 com.dreame.smartlife）时自动切换到 APP Recon 流程：
1. 自动识别目标类型（域名 vs APP包名 vs IP）
2. APK 静态分析（反编译提取 API endpoint/密钥/证书）
3. 从抓包文件导入 API（支持 Charles/mitmproxy/Fiddler 格式）
4. 应用商店信息搜集（版本/权限/开发者/关联APP）
5. IoT 设备协议探测（MQTT/CoAP/自定义TCP端口）
6. 云服务指纹识别（AWS IoT/阿里云IoT/涂鸦云）

依赖: 
  - APK分析需要: jadx (Java反编译), apktool
  - 可选: frida (动态hook)
"""

import asyncio
import re
import os
import json
import tempfile
import subprocess
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class AppReconResult:
    """APP Recon 结果"""
    target_type: str = ""           # app/domain/ip
    package_name: str = ""
    app_name: str = ""
    # 发现的 API
    api_domains: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    # 密钥泄露
    hardcoded_secrets: list = field(default_factory=list)
    # 证书信息
    certificates: list = field(default_factory=list)
    # IoT 特征
    mqtt_brokers: list = field(default_factory=list)
    iot_protocols: list = field(default_factory=list)
    device_api_patterns: list = field(default_factory=list)

    # 云服务
    cloud_services: list = field(default_factory=list)
    # 权限和组件
    permissions: list = field(default_factory=list)
    exported_components: list = field(default_factory=list)
    # 原始发现（供后续阶段使用）
    raw_strings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
# 目标类型识别
# ═══════════════════════════════════════════════════════════════

def detect_target_type(target: str) -> str:
    """
    识别目标类型
    返回: "app" / "domain" / "ip" / "unknown"
    """
    target = target.strip()

    # APP 包名: com.xxx.xxx 或类似格式
    if re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$', target, re.I):
        # 排除正常域名（有常见TLD）
        common_tlds = ['.com', '.net', '.org', '.cn', '.io', '.co', '.app']
        # 包名通常是 com.company.appname 格式（3段以上）
        parts = target.split('.')
        if len(parts) >= 3 and parts[0].lower() in ('com', 'cn', 'org', 'net', 'io'):
            # 可能是包名也可能是域名，进一步判断
            if len(parts) >= 3 and not any(target.endswith(tld) for tld in common_tlds):
                return "app"
            # com.dreame.smartlife.com → 最后是.com，但中间有3段以上，按APP处理
            if len(parts) >= 4:
                return "app"
    
    # IP 地址
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"

    # 域名
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
        return "domain"

    # 带协议的URL
    if target.startswith('http://') or target.startswith('https://'):
        return "domain"

    return "unknown"



# ═══════════════════════════════════════════════════════════════
# APP Recon 主类
# ═══════════════════════════════════════════════════════════════

class AppRecon:
    """
    APP/IoT 专用信息搜集

    用法:
        recon = AppRecon(config={
            "apk_path": "/path/to/app.apk",       # 可选：本地APK文件
            "pcap_path": "/path/to/capture.har",   # 可选：抓包文件
            "package_name": "com.dreame.smartlife",
        })
        result = await recon.run()
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.package_name = self.config.get("package_name", "")
        self.apk_path = self.config.get("apk_path", "")
        self.pcap_path = self.config.get("pcap_path", "")
        self.har_path = self.config.get("har_path", "")
        self.result = AppReconResult()

        # IoT 常见域名模式
        self.iot_domain_patterns = [
            r'mqtt[.-]', r'iot[.-]', r'device[.-]', r'hub[.-]',
            r'broker[.-]', r'cloud[.-]', r'api[.-]', r'app[.-]',
            r'openapi[.-]', r'gateway[.-]', r'push[.-]', r'ota[.-]',
            r'firmware[.-]', r'upgrade[.-]', r'telemetry[.-]',
        ]

        # IoT 云服务指纹
        self.cloud_fingerprints = {
            "aws_iot": [r'iot\..*\.amazonaws\.com', r'a[a-z0-9]+\.iot\.',
                       r'cognito', r'amazonaws'],
            "aliyun_iot": [r'iot\.aliyuncs\.com', r'linkplatform',
                         r'iotx-', r'alink'],
            "tuya": [r'tuya', r'tuyacn', r'tuyaus', r'smartlife'],
            "xiaomi_iot": [r'xiaomi', r'mi\.com', r'miot-spec',
                          r'mijia'],
            "aws_general": [r's3\.amazonaws', r'execute-api',
                           r'lambda', r'cloudfront'],
            "firebase": [r'firebase', r'fcm\.googleapis',
                        r'firebaseio\.com'],
        }


    # ─── 主入口 ────────────────────────────────────────────────

    async def run(self) -> AppReconResult:
        """执行完整 APP Recon"""
        self.result.target_type = "app"
        self.result.package_name = self.package_name

        # 1. APK 静态分析（如果有APK文件）
        if self.apk_path and os.path.exists(self.apk_path):
            await self._analyze_apk()

        # 2. 从抓包文件导入
        if self.har_path and os.path.exists(self.har_path):
            self._parse_har_file()
        if self.pcap_path and os.path.exists(self.pcap_path):
            self._parse_pcap_file()

        # 3. 包名推导域名（无APK时的备选方案）
        if not self.result.api_domains:
            self._infer_domains_from_package()

        # 4. IoT 协议探测
        if self.result.api_domains:
            await self._probe_iot_protocols()

        # 5. 云服务识别
        self._identify_cloud_services()

        return self.result

    # ─── APK 分析 ──────────────────────────────────────────────

    async def _analyze_apk(self):
        """APK 静态分析：提取 API/密钥/证书"""

        # 检查 jadx 是否可用
        jadx_available = self._check_tool("jadx")
        apktool_available = self._check_tool("apktool")

        if not jadx_available and not apktool_available:
            self.result.errors.append(
                "需要安装 jadx 或 apktool 进行APK分析: "
                "brew install jadx 或 apt install jadx"
            )
            # 降级：直接用 strings + unzip 提取
            await self._basic_apk_strings()
            return

        # 用 jadx 反编译
        if jadx_available:
            await self._jadx_decompile()
        elif apktool_available:
            await self._apktool_decode()


    async def _basic_apk_strings(self):
        """降级方案：用 strings/unzip 从 APK 中提取信息"""
        try:
            # APK 本质是 ZIP，直接用 unzip 解压 + strings 提取
            tmp_dir = tempfile.mkdtemp(prefix="bai_apk_")

            # 解压 APK
            subprocess.run(
                ["unzip", "-q", "-o", self.apk_path, "-d", tmp_dir],
                capture_output=True, timeout=60
            )

            # 对所有 dex 文件运行 strings
            all_strings = []
            for root, dirs, files in os.walk(tmp_dir):
                for f in files:
                    if f.endswith('.dex') or f.endswith('.so'):
                        filepath = os.path.join(root, f)
                        result = subprocess.run(
                            ["strings", filepath],
                            capture_output=True, text=True, timeout=30
                        )
                        if result.returncode == 0:
                            all_strings.extend(result.stdout.split('\n'))

            # 从 strings 中提取有用信息
            self._extract_from_strings(all_strings)

            # 解析 AndroidManifest.xml（如果 apktool 解码过）
            manifest_path = os.path.join(tmp_dir, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                self._parse_manifest(manifest_path)

        except Exception as e:
            self.result.errors.append(f"APK strings 提取失败: {e}")

    async def _jadx_decompile(self):
        """用 jadx 反编译 APK"""
        try:
            tmp_dir = tempfile.mkdtemp(prefix="bai_jadx_")
            result = subprocess.run(
                ["jadx", "-d", tmp_dir, "--no-res", self.apk_path],
                capture_output=True, text=True, timeout=300
            )

            if result.returncode != 0:
                self.result.errors.append(f"jadx 反编译失败: {result.stderr[:200]}")
                await self._basic_apk_strings()
                return

            # 遍历反编译后的 Java 源码
            all_strings = []
            for root, dirs, files in os.walk(tmp_dir):
                for f in files:
                    if f.endswith('.java'):
                        filepath = os.path.join(root, f)
                        try:
                            with open(filepath, 'r', errors='ignore') as fh:
                                content = fh.read()
                                all_strings.extend(content.split('\n'))
                        except Exception:
                            pass

            self._extract_from_strings(all_strings)

        except subprocess.TimeoutExpired:
            self.result.errors.append("jadx 反编译超时(>5分钟)")
            await self._basic_apk_strings()
        except Exception as e:
            self.result.errors.append(f"jadx 异常: {e}")


    async def _apktool_decode(self):
        """用 apktool 解码 APK"""
        try:
            tmp_dir = tempfile.mkdtemp(prefix="bai_apktool_")
            result = subprocess.run(
                ["apktool", "d", "-f", "-o", tmp_dir, self.apk_path],
                capture_output=True, text=True, timeout=180
            )
            if result.returncode != 0:
                await self._basic_apk_strings()
                return

            # 读取 smali 文件中的字符串
            all_strings = []
            for root, dirs, files in os.walk(tmp_dir):
                for f in files:
                    if f.endswith('.smali') or f.endswith('.xml'):
                        filepath = os.path.join(root, f)
                        try:
                            with open(filepath, 'r', errors='ignore') as fh:
                                all_strings.extend(fh.read().split('\n'))
                        except Exception:
                            pass

            self._extract_from_strings(all_strings)

            # 解析 AndroidManifest
            manifest = os.path.join(tmp_dir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                self._parse_manifest(manifest)

        except Exception as e:
            self.result.errors.append(f"apktool 异常: {e}")

    # ─── 字符串提取 ────────────────────────────────────────────

    def _extract_from_strings(self, strings: list):
        """从字符串列表中提取 API/密钥/IoT 信息"""

        # URL/域名提取
        url_pattern = re.compile(
            r'https?://[a-zA-Z0-9\-_.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9\-_.?&=%]*'
        )
        domain_pattern = re.compile(
            r'["\']([a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,})["\']'
        )

        # API 路径模式
        api_path_pattern = re.compile(
            r'["\'](/(?:api|v[1-9]|device|iot|user|auth|oauth|app)'
            r'[/a-zA-Z0-9\-_{}:.]*)["\']'
        )

        # 密钥模式
        secret_patterns = [
            (r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']', "base64_key"),
            (r'(?:key|secret|token|password|api_key)\s*[=:]\s*["\']([^"\']{16,})["\']',
             "hardcoded_secret"),
            (r'(AKIA[0-9A-Z]{16})', "aws_key"),
            (r'(sk_live_[a-zA-Z0-9]{24,})', "stripe_key"),
        ]

        # MQTT broker 模式
        mqtt_pattern = re.compile(
            r'(?:mqtt|tcp|ssl)://([a-zA-Z0-9\-_.]+(?::\d+)?)'
        )

        seen_urls = set()
        seen_domains = set()

        for line in strings:
            if not line or len(line) > 2000:
                continue

            # 提取 URL
            for url_match in url_pattern.finditer(line):
                url = url_match.group(0)
                if url not in seen_urls and self._is_relevant_url(url):
                    seen_urls.add(url)
                    self.result.api_endpoints.append(url)
                    # 提取域名
                    parsed = urlparse(url)
                    if parsed.netloc and parsed.netloc not in seen_domains:
                        seen_domains.add(parsed.netloc)
                        self.result.api_domains.append(parsed.netloc)

            # 提取裸域名
            for domain_match in domain_pattern.finditer(line):
                domain = domain_match.group(1)
                if domain not in seen_domains and self._is_relevant_domain(domain):
                    seen_domains.add(domain)
                    self.result.api_domains.append(domain)

            # 提取 API 路径
            for api_match in api_path_pattern.finditer(line):
                path = api_match.group(1)
                if path not in self.result.device_api_patterns:
                    self.result.device_api_patterns.append(path)

            # 提取密钥
            for pattern, key_type in secret_patterns:
                for secret_match in re.finditer(pattern, line, re.I):
                    value = secret_match.group(1)
                    if not self._is_false_positive_key(value):
                        self.result.hardcoded_secrets.append({
                            "type": key_type,
                            "value": value[:50] + "..." if len(value) > 50 else value,
                            "context": line.strip()[:100],
                        })

            # 提取 MQTT broker
            for mqtt_match in mqtt_pattern.finditer(line):
                broker = mqtt_match.group(1)
                if broker not in self.result.mqtt_brokers:
                    self.result.mqtt_brokers.append(broker)


    # ─── 抓包文件导入 ──────────────────────────────────────────

    def _parse_har_file(self):
        """解析 HAR 抓包文件（Charles/Chrome/mitmproxy 导出）"""
        try:
            with open(self.har_path, 'r', errors='ignore') as f:
                har = json.load(f)

            entries = har.get("log", {}).get("entries", [])
            seen = set()

            for entry in entries:
                request = entry.get("request", {})
                url = request.get("url", "")
                method = request.get("method", "GET")

                if not url or url in seen:
                    continue
                seen.add(url)

                parsed = urlparse(url)
                if parsed.netloc:
                    if parsed.netloc not in self.result.api_domains:
                        self.result.api_domains.append(parsed.netloc)

                self.result.api_endpoints.append({
                    "method": method,
                    "url": url,
                    "headers": {h["name"]: h["value"]
                               for h in request.get("headers", [])
                               if h["name"].lower() in (
                                   "authorization", "x-token",
                                   "x-device-id", "content-type")},
                })

        except Exception as e:
            self.result.errors.append(f"HAR 解析失败: {e}")

    def _parse_pcap_file(self):
        """解析 PCAP/mitmproxy 文件（基本实现）"""
        # mitmproxy 的 flow 文件需要 mitmproxy 库
        # 这里做简单的 strings 提取
        try:
            result = subprocess.run(
                ["strings", self.pcap_path],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                self._extract_from_strings(lines)
        except Exception as e:
            self.result.errors.append(f"PCAP 解析失败: {e}")

    # ─── 包名推导域名 ──────────────────────────────────────────

    def _infer_domains_from_package(self):
        """从包名推导可能的 API 域名"""
        if not self.package_name:
            return

        # com.dreame.smartlife → dreame
        parts = self.package_name.split('.')
        company = ""
        if len(parts) >= 2:
            company = parts[1]  # 通常第二段是公司名

        if not company:
            return

        # 生成可能的域名
        domain_guesses = [
            f"api.{company}.com",
            f"app-api.{company}.com",
            f"iot.{company}.com",
            f"iot-api.{company}.com",
            f"mqtt.{company}.com",
            f"device.{company}.com",
            f"cloud.{company}.com",
            f"openapi.{company}.com",
            f"{company}.com",
            f"www.{company}.com",
            f"global.{company}.com",
            f"eu.{company}.com",
            f"us.{company}.com",
            # 国内 IoT 厂商常见模式
            f"api.{company}.cn",
            f"iot.{company}.cn",
            f"{company}.cn",
        ]

        self.result.api_domains.extend(domain_guesses)

    # ─── IoT 协议探测 ──────────────────────────────────────────

    async def _probe_iot_protocols(self):
        """探测 IoT 特有协议端口"""
        iot_ports = {
            1883: "MQTT (plaintext)",
            8883: "MQTT (TLS)",
            5683: "CoAP (UDP)",
            5684: "CoAP (DTLS)",
            8080: "HTTP API",
            8443: "HTTPS API",
            443: "HTTPS",
            6668: "Tuya Cloud",
            7000: "Custom IoT",
        }

        for domain in self.result.api_domains[:5]:  # 只探测前5个
            for port, protocol in iot_ports.items():
                # 用 nc/nmap 探测端口（非侵入性）
                try:
                    result = subprocess.run(
                        ["nc", "-z", "-w", "2", domain, str(port)],
                        capture_output=True, timeout=5
                    )
                    if result.returncode == 0:
                        self.result.iot_protocols.append({
                            "domain": domain,
                            "port": port,
                            "protocol": protocol,
                        })
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass


    # ─── 云服务识别 ────────────────────────────────────────────

    def _identify_cloud_services(self):
        """根据域名/endpoint 识别使用的云 IoT 平台"""
        all_text = " ".join(
            self.result.api_domains +
            [str(e) for e in self.result.api_endpoints] +
            self.result.mqtt_brokers
        )

        for service, patterns in self.cloud_fingerprints.items():
            for pattern in patterns:
                if re.search(pattern, all_text, re.I):
                    if service not in self.result.cloud_services:
                        self.result.cloud_services.append(service)
                    break

    # ─── AndroidManifest 解析 ──────────────────────────────────

    def _parse_manifest(self, manifest_path: str):
        """解析 AndroidManifest.xml 提取权限和导出组件"""
        try:
            with open(manifest_path, 'r', errors='ignore') as f:
                content = f.read()

            # 提取权限
            perms = re.findall(
                r'android\.permission\.([A-Z_]+)', content
            )
            self.result.permissions = list(set(perms))

            # 提取导出的组件（exported=true 的 Activity/Service/Receiver）
            exported = re.findall(
                r'android:name="([^"]+)"[^>]*android:exported="true"',
                content
            )
            self.result.exported_components = exported

        except Exception:
            pass

    # ─── 辅助方法 ──────────────────────────────────────────────

    def _check_tool(self, tool_name: str) -> bool:
        """检查工具是否已安装"""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _is_relevant_url(self, url: str) -> bool:
        """判断 URL 是否与目标相关（过滤SDK/广告/分析）"""
        irrelevant = [
            'google', 'facebook', 'twitter', 'firebase',
            'crashlytics', 'analytics', 'adsense', 'doubleclick',
            'umeng', 'jpush', 'getui', 'talkingdata',
            'bugly', 'sentry', 'appsflyer',
            'schemas.android.com', 'xmlns',
        ]
        url_lower = url.lower()
        return not any(irr in url_lower for irr in irrelevant)

    def _is_relevant_domain(self, domain: str) -> bool:
        """判断域名是否可能是目标的 API"""
        irrelevant_domains = [
            'google.com', 'googleapis.com', 'facebook.com',
            'twitter.com', 'apple.com', 'microsoft.com',
            'github.com', 'amazonaws.com', 'cloudflare.com',
        ]
        return domain.lower() not in irrelevant_domains

    def _is_false_positive_key(self, value: str) -> bool:
        """过滤明显的密钥误报"""
        if len(value) < 16:
            return True
        if len(set(value)) <= 3:
            return True
        if value.startswith('android.') or value.startswith('com.'):
            return True
        # 类名/包名不是密钥
        if re.match(r'^[a-z]+(\.[a-z]+){2,}$', value):
            return True
        return False

    def get_summary(self) -> dict:
        """获取 Recon 摘要"""
        return {
            "target_type": self.result.target_type,
            "package_name": self.result.package_name,
            "api_domains_found": len(self.result.api_domains),
            "api_endpoints_found": len(self.result.api_endpoints),
            "hardcoded_secrets": len(self.result.hardcoded_secrets),
            "mqtt_brokers": len(self.result.mqtt_brokers),
            "iot_protocols": len(self.result.iot_protocols),
            "cloud_services": self.result.cloud_services,
            "exported_components": len(self.result.exported_components),
            "errors": len(self.result.errors),
        }
