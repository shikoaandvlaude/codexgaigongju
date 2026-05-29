#!/usr/bin/env python3
"""
IoT Hunter — IoT/智能家居设备专用漏洞测试模块
针对 APP 控制的 IoT 设备（如追觅/小米/涂鸦生态）的特有攻击面

IoT 特有漏洞类型（传统 Web 扫描器完全覆盖不到）：
1. 设备绑定越权 — 用 A 的 token 绑定/控制 B 的设备
2. 设备 ID 可枚举 — MAC/SN/DID 可预测或可遍历
3. 固件未授权下载 — OTA 接口无需认证即可获取固件
4. MQTT 消息越权 — 订阅他人设备的 topic 获取数据
5. 指令重放 — 截获控制指令后无时间戳/nonce 保护
6. 云端 API 越权 — 通过 device_id 参数访问他人设备数据
7. 设备解绑逻辑缺陷 — 解绑后仍可控制
8. 共享权限提升 — 被分享者获得超出预期的权限
9. 批量数据泄露 — 设备列表接口返回所有用户的设备

依赖: http_engine.py (异步HTTP), 可选 paho-mqtt (MQTT测试)
"""

import asyncio
import re
import json
import time
import hashlib
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from typing import Optional, Any

from http_engine import HttpEngine, HttpResponse



# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class IoTFinding:
    """IoT 漏洞发现"""
    vuln_type: str = ""         # device_idor/firmware_leak/mqtt_unauth/replay/unbind_bypass
    severity: str = "high"
    url: str = ""
    method: str = ""
    evidence: str = ""
    device_id: str = ""
    confidence: float = 0.0
    impact: str = ""
    confirmed: bool = False


# ═══════════════════════════════════════════════════════════════
# IoT Hunter
# ═══════════════════════════════════════════════════════════════

class IoTHunter:
    """
    IoT 设备专用漏洞猎手

    用法:
        hunter = IoTHunter(http_engine, config={
            "token_a": "Bearer eyJ...",   # 账号A的token
            "token_b": "Bearer eyJ...",   # 账号B的token
            "device_id_a": "did_xxx",     # A的设备ID
            "device_id_b": "did_yyy",     # B的设备ID
            "base_url": "https://api.dreame.com",
        })
        findings = await hunter.run_all_tests()
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        self.token_a = self.config.get("token_a", "")
        self.token_b = self.config.get("token_b", "")
        self.device_id_a = self.config.get("device_id_a", "")
        self.device_id_b = self.config.get("device_id_b", "")
        self.base_url = self.config.get("base_url", "")
        self.findings: list[IoTFinding] = []

    async def run_all_tests(self) -> list[IoTFinding]:
        """运行所有 IoT 专项测试"""
        findings = []

        # 1. 设备 IDOR（用A的token访问B的设备）
        if self.token_a and self.device_id_b:
            idor_results = await self.test_device_idor()
            findings.extend(idor_results)

        # 2. 固件下载未授权
        firmware_results = await self.test_firmware_unauthorized()
        findings.extend(firmware_results)

        # 3. 设备ID枚举
        enum_results = await self.test_device_id_enumeration()
        findings.extend(enum_results)

        # 4. API 越权（通用IoT端点测试）
        api_results = await self.test_iot_api_auth()
        findings.extend(api_results)

        # 5. 设备信息泄露
        leak_results = await self.test_device_info_leak()
        findings.extend(leak_results)

        self.findings.extend(findings)
        return findings

    # ─── 设备 IDOR ────────────────────────────────────────────

    async def test_device_idor(self) -> list[IoTFinding]:
        """设备越权访问测试：用A的认证访问B的设备"""
        findings = []

        if not self.base_url or not self.token_a or not self.device_id_b:
            return findings

        # IoT 常见的设备操作端点模式
        device_endpoints = [
            "/device/{did}/info",
            "/device/{did}/status",
            "/device/{did}/data",
            "/device/{did}/history",
            "/device/{did}/control",
            "/device/{did}/settings",
            "/v1/device/{did}",
            "/api/device/{did}",
            "/app/device/{did}/detail",
            "/iot/device/{did}",
            "/user/device/{did}",
        ]

        headers_a = {"Authorization": self.token_a}
        headers_b = {"Authorization": self.token_b}

        for endpoint_template in device_endpoints:
            # 用 A 的 token 访问 B 的设备
            endpoint = endpoint_template.replace("{did}", self.device_id_b)
            url = self.base_url.rstrip("/") + endpoint

            resp = await self.http.request("GET", url, headers=headers_a)

            if resp.status_code == 200 and resp.body:
                # 检查是否真的返回了设备数据
                body_lower = resp.body.lower()
                device_indicators = [
                    "device", "status", "online", "battery",
                    "firmware", "model", "mac", "serial",
                ]
                if any(ind in body_lower for ind in device_indicators):
                    findings.append(IoTFinding(
                        vuln_type="device_idor",
                        severity="high",
                        url=url,
                        method="GET",
                        evidence=f"用账号A的token访问账号B的设备({self.device_id_b})成功,返回200且包含设备数据",
                        device_id=self.device_id_b,
                        confidence=0.85,
                        impact="可查看/控制他人的IoT设备",
                        confirmed=True,
                    ))
                    break  # 找到一个就够了

            # 也试试 POST（控制指令）
            control_bodies = [
                {"device_id": self.device_id_b, "command": "get_status"},
                {"did": self.device_id_b, "method": "get_prop"},
                {"deviceId": self.device_id_b, "action": "query"},
            ]
            for body in control_bodies:
                resp = await self.http.request(
                    "POST", url, headers=headers_a, json_data=body
                )
                if resp.status_code == 200:
                    findings.append(IoTFinding(
                        vuln_type="device_idor",
                        severity="critical",
                        url=url,
                        method="POST",
                        evidence=f"用账号A的token对账号B的设备发送控制指令成功",
                        device_id=self.device_id_b,
                        confidence=0.9,
                        impact="可远程控制他人的IoT设备（如扫地机器人）",
                        confirmed=True,
                    ))
                    break

        return findings


    # ─── 固件未授权下载 ────────────────────────────────────────

    async def test_firmware_unauthorized(self) -> list[IoTFinding]:
        """测试固件/OTA接口是否需要认证"""
        findings = []

        if not self.base_url:
            return findings

        # IoT 常见的固件/OTA 端点
        firmware_endpoints = [
            "/ota/firmware/latest",
            "/firmware/check",
            "/upgrade/check",
            "/device/firmware",
            "/api/ota/check",
            "/v1/ota/firmware",
            "/app/firmware/list",
            "/iot/ota/latest",
            "/fds/firmware",
        ]

        for endpoint in firmware_endpoints:
            url = self.base_url.rstrip("/") + endpoint

            # 不带认证访问
            resp = await self.http.request("GET", url)

            if resp.status_code == 200 and resp.body:
                body_lower = resp.body.lower()
                firmware_indicators = [
                    "firmware", "version", "download", "url",
                    "ota", "update", "bin", "upgrade", ".zip",
                    "md5", "sha256", "checksum",
                ]
                if any(ind in body_lower for ind in firmware_indicators):
                    # 检查是否包含下载链接
                    download_urls = re.findall(
                        r'https?://[^\s"\'<>]+(?:\.bin|\.zip|\.gz|\.img|firmware)[^\s"\'<>]*',
                        resp.body
                    )

                    findings.append(IoTFinding(
                        vuln_type="firmware_unauthorized",
                        severity="high",
                        url=url,
                        method="GET",
                        evidence=(
                            f"无需认证即可访问固件接口,返回固件信息"
                            + (f",含下载链接: {download_urls[0][:80]}" if download_urls else "")
                        ),
                        confidence=0.8,
                        impact="可下载设备固件进行逆向分析,发现更多漏洞",
                    ))
                    break

            # 带伪造的设备信息试试
            fake_headers = {
                "X-Device-Id": "test_device_001",
                "X-Device-Model": "dreame.vacuum.p2009",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 12)",
            }
            resp = await self.http.request("GET", url, headers=fake_headers)
            if resp.status_code == 200 and "firmware" in resp.body.lower():
                findings.append(IoTFinding(
                    vuln_type="firmware_unauthorized",
                    severity="high",
                    url=url,
                    method="GET",
                    evidence="使用伪造设备Header即可获取固件信息",
                    confidence=0.7,
                    impact="可通过伪造设备身份下载固件",
                ))
                break

        return findings

    # ─── 设备ID枚举 ───────────────────────────────────────────

    async def test_device_id_enumeration(self) -> list[IoTFinding]:
        """测试设备ID是否可枚举/可预测"""
        findings = []

        if not self.base_url or not self.token_a or not self.device_id_a:
            return findings

        headers = {"Authorization": self.token_a}

        # 分析设备ID格式
        did = self.device_id_a
        id_type = self._analyze_id_format(did)

        if id_type == "numeric":
            # 数字ID：尝试 ±1
            try:
                did_int = int(did)
                test_ids = [str(did_int + i) for i in range(1, 6)]
            except ValueError:
                return findings
        elif id_type == "sequential_hex":
            # 十六进制序列：尝试递增
            try:
                did_int = int(did, 16)
                test_ids = [hex(did_int + i)[2:] for i in range(1, 6)]
            except ValueError:
                return findings
        elif id_type == "mac_based":
            # MAC地址格式：修改最后几位
            parts = re.split(r'[:\-]', did)
            if len(parts) >= 6:
                last_byte = int(parts[-1], 16)
                test_ids = [
                    ":".join(parts[:-1] + [hex(last_byte + i)[2:].zfill(2)])
                    for i in range(1, 4)
                ]
            else:
                return findings
        else:
            # UUID/随机ID：不可枚举，跳过
            return findings

        # 用枚举的ID访问设备信息
        success_count = 0
        for test_id in test_ids:
            url = f"{self.base_url}/device/{test_id}/info"
            resp = await self.http.request("GET", url, headers=headers)

            if resp.status_code == 200 and resp.body and len(resp.body) > 50:
                success_count += 1

        if success_count >= 2:
            findings.append(IoTFinding(
                vuln_type="device_id_enumerable",
                severity="high",
                url=f"{self.base_url}/device/{{ID}}/info",
                method="GET",
                evidence=(
                    f"设备ID格式为{id_type},可枚举。"
                    f"测试{len(test_ids)}个相邻ID,{success_count}个返回有效数据"
                ),
                device_id=did,
                confidence=0.8,
                impact="可遍历获取所有用户的设备信息",
            ))

        return findings


    # ─── IoT API 认证测试 ─────────────────────────────────────

    async def test_iot_api_auth(self) -> list[IoTFinding]:
        """测试 IoT API 是否正确验证设备归属"""
        findings = []

        if not self.base_url or not self.token_a:
            return findings

        headers_a = {"Authorization": self.token_a}

        # 常见的 IoT 批量查询接口（可能泄露所有设备）
        batch_endpoints = [
            "/devices",
            "/device/list",
            "/api/devices",
            "/v1/devices",
            "/user/devices",
            "/app/device/list",
            "/iot/device/all",
        ]

        for endpoint in batch_endpoints:
            url = self.base_url.rstrip("/") + endpoint

            # 正常请求
            resp = await self.http.request("GET", url, headers=headers_a)

            if resp.status_code == 200 and resp.body:
                try:
                    data = json.loads(resp.body)
                    # 检查返回的设备数量是否异常（超过用户自己的设备数）
                    devices = []
                    if isinstance(data, list):
                        devices = data
                    elif isinstance(data, dict):
                        for key in ("data", "devices", "list", "result", "items"):
                            if key in data and isinstance(data[key], list):
                                devices = data[key]
                                break

                    if len(devices) > 10:
                        # 用户一般不会有10+设备，可能是泄露
                        findings.append(IoTFinding(
                            vuln_type="device_list_leak",
                            severity="high",
                            url=url,
                            method="GET",
                            evidence=f"设备列表接口返回 {len(devices)} 个设备,可能包含其他用户的设备",
                            confidence=0.6,
                            impact="可获取平台所有用户的设备列表",
                        ))

                except json.JSONDecodeError:
                    pass

            # 测试未认证访问
            resp_unauth = await self.http.request("GET", url)
            if resp_unauth.status_code == 200 and len(resp_unauth.body) > 100:
                findings.append(IoTFinding(
                    vuln_type="api_no_auth",
                    severity="critical",
                    url=url,
                    method="GET",
                    evidence="设备API无需认证即可访问",
                    confidence=0.9,
                    impact="任何人可查看/操作设备",
                    confirmed=True,
                ))

        return findings

    # ─── 设备信息泄露 ─────────────────────────────────────────

    async def test_device_info_leak(self) -> list[IoTFinding]:
        """测试设备信息接口是否泄露敏感数据"""
        findings = []

        if not self.base_url or not self.token_a or not self.device_id_a:
            return findings

        headers = {"Authorization": self.token_a}

        # 获取自己设备的详细信息
        info_endpoints = [
            f"/device/{self.device_id_a}/info",
            f"/device/{self.device_id_a}/detail",
            f"/v1/device/{self.device_id_a}",
        ]

        for endpoint in info_endpoints:
            url = self.base_url.rstrip("/") + endpoint
            resp = await self.http.request("GET", url, headers=headers)

            if resp.status_code == 200 and resp.body:
                body_lower = resp.body.lower()
                # 检查是否泄露了不该暴露的信息
                sensitive_fields = {
                    "wifi_password": "WiFi密码",
                    "wpa_key": "WiFi密钥",
                    "ssid": "WiFi名称",
                    "owner_phone": "主人手机号",
                    "owner_email": "主人邮箱",
                    "gps": "GPS位置",
                    "latitude": "纬度",
                    "longitude": "经度",
                    "location": "地理位置",
                    "ip_address": "内网IP",
                    "local_ip": "局域网IP",
                    "token": "设备Token",
                    "secret": "设备密钥",
                    "private_key": "私钥",
                }

                leaked = []
                for field, desc in sensitive_fields.items():
                    if field in body_lower:
                        leaked.append(desc)

                if leaked:
                    findings.append(IoTFinding(
                        vuln_type="device_info_leak",
                        severity="medium" if len(leaked) < 3 else "high",
                        url=url,
                        method="GET",
                        evidence=f"设备信息接口泄露敏感字段: {', '.join(leaked)}",
                        device_id=self.device_id_a,
                        confidence=0.8,
                        impact=f"泄露用户隐私: {', '.join(leaked[:3])}",
                    ))
                    break

        return findings

    # ─── 辅助方法 ──────────────────────────────────────────────

    def _analyze_id_format(self, device_id: str) -> str:
        """分析设备ID的格式类型"""
        if not device_id:
            return "unknown"

        # 纯数字
        if device_id.isdigit():
            return "numeric"

        # MAC地址格式
        if re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', device_id):
            return "mac_based"

        # 十六进制序列
        if re.match(r'^[0-9a-fA-F]{8,16}$', device_id):
            return "sequential_hex"

        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                   device_id, re.I):
            return "uuid"

        # 短随机ID
        if len(device_id) <= 10 and device_id.isalnum():
            return "short_random"

        return "unknown"

    def get_findings_summary(self) -> dict:
        """获取测试摘要"""
        return {
            "total": len(self.findings),
            "confirmed": len([f for f in self.findings if f.confirmed]),
            "by_type": {
                t: len([f for f in self.findings if f.vuln_type == t])
                for t in set(f.vuln_type for f in self.findings)
            },
            "critical": len([f for f in self.findings if f.severity == "critical"]),
            "high": len([f for f in self.findings if f.severity == "high"]),
        }
