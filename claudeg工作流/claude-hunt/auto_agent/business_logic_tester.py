#!/usr/bin/env python3
"""
Business Logic Tester — 业务逻辑漏洞测试模块
SRC 高价值漏洞集中区：支付/订单/优惠券/积分/提现

不同于传统漏洞扫描，业务逻辑漏洞需要：
1. 理解业务流程（不是简单发 payload）
2. 操纵请求参数/顺序/时序
3. 验证后端状态是否真的变了

测试维度：
- 金额篡改（价格/数量/折扣）
- 负数/零值/极大值测试
- 流程跳跃（跳过支付步骤）
- 优惠券/积分重复使用
- 竞态条件（真正带状态验证的）
- 权限提升（角色参数篡改）
- 签名/校验绕过
"""

import asyncio
import json
import time
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import Optional, Any

from http_engine import HttpEngine, HttpResponse


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class BizLogicFinding:
    """业务逻辑漏洞发现"""
    url: str = ""
    method: str = ""
    vuln_type: str = ""
    severity: str = "high"
    confidence: float = 0.0
    evidence: str = ""
    payload: Any = None
    # 状态验证
    state_before: str = ""
    state_after: str = ""
    state_changed: bool = False
    # 影响评估
    impact: str = ""
    confirmed: bool = False


# ═══════════════════════════════════════════════════════════════
# Business Logic Tester
# ═══════════════════════════════════════════════════════════════

class BusinessLogicTester:
    """
    业务逻辑漏洞测试器
    
    用法:
        tester = BusinessLogicTester(http_engine, {
            "cookies": {"session": "xxx"},
            "balance_check_url": "https://target.com/api/wallet/balance",
        })
        
        # 金额篡改测试
        findings = await tester.test_price_manipulation(
            order_url="https://target.com/api/order/create",
            order_body={"product_id": 1, "price": 9900, "quantity": 1}
        )
        
        # 竞态条件测试（带状态验证）
        findings = await tester.test_race_condition(
            url="https://target.com/api/coupon/redeem",
            body={"code": "PROMO50"},
            state_url="https://target.com/api/wallet/balance"
        )
    """

    def __init__(self, http_engine: HttpEngine, config: dict = None):
        self.http = http_engine
        self.config = config or {}
        self.cookies = self.config.get("cookies", {})
        self.headers = self.config.get("headers", {})
        self.findings: list[BizLogicFinding] = []

    # ─── 金额/数量篡改 ────────────────────────────────────────

    async def test_price_manipulation(
        self,
        order_url: str,
        order_body: dict,
        method: str = "POST",
        price_fields: list[str] = None,
        quantity_fields: list[str] = None,
    ) -> list[BizLogicFinding]:
        """
        金额/价格篡改测试
        
        测试场景：
        - 价格改为 0 / 0.01 / 负数
        - 数量改为 0 / -1 / 极大值
        - 折扣改为 100% / 超过100%
        - 总价字段直接篡改
        """
        findings = []

        if price_fields is None:
            price_fields = ["price", "amount", "total", "total_amount",
                          "unit_price", "pay_amount", "order_amount",
                          "discount_price", "final_price"]
        
        if quantity_fields is None:
            quantity_fields = ["quantity", "qty", "num", "count", "number"]

        # 价格篡改测试
        price_payloads = [0, 1, -1, 0.01, -100, 0.001, 99999999]
        
        for field_name in price_fields:
            if field_name not in order_body:
                continue
            
            original_value = order_body[field_name]
            
            for payload in price_payloads:
                test_body = dict(order_body)
                test_body[field_name] = payload

                resp = await self.http.request(
                    method, order_url,
                    json_data=test_body,
                    cookies=self.cookies,
                    headers=self.headers,
                )

                if resp.status_code in (200, 201):
                    # 服务器接受了异常金额！
                    findings.append(BizLogicFinding(
                        url=order_url,
                        method=method,
                        vuln_type="price_manipulation",
                        severity="critical" if payload <= 0 else "high",
                        confidence=0.7,
                        evidence=(
                            f"服务器接受了 {field_name}={payload} "
                            f"(原始值={original_value})，状态码={resp.status_code}"
                        ),
                        payload=test_body,
                        impact=f"可能以 {payload} 的价格下单（原价 {original_value}）",
                    ))

        # 数量篡改测试
        qty_payloads = [0, -1, -100, 99999999, 0.5]
        
        for field_name in quantity_fields:
            if field_name not in order_body:
                continue
            
            original_value = order_body[field_name]
            
            for payload in qty_payloads:
                test_body = dict(order_body)
                test_body[field_name] = payload

                resp = await self.http.request(
                    method, order_url,
                    json_data=test_body,
                    cookies=self.cookies,
                    headers=self.headers,
                )

                if resp.status_code in (200, 201):
                    findings.append(BizLogicFinding(
                        url=order_url,
                        method=method,
                        vuln_type="quantity_manipulation",
                        severity="high" if payload < 0 else "medium",
                        confidence=0.7,
                        evidence=(
                            f"服务器接受了 {field_name}={payload} "
                            f"(原始值={original_value})，状态码={resp.status_code}"
                        ),
                        payload=test_body,
                        impact=f"数量为 {payload} 时下单成功",
                    ))

        self.findings.extend(findings)
        return findings

    # ─── 竞态条件（带状态验证）─────────────────────────────────

    async def test_race_condition(
        self,
        url: str,
        method: str = "POST",
        body: dict = None,
        data: str = None,
        state_url: str = None,
        state_field: str = None,
        concurrency: int = 20,
    ) -> list[BizLogicFinding]:
        """
        竞态条件测试 — 带状态验证
        
        与简单的并发 curl 不同，这里会：
        1. 先检查初始状态（余额/积分/使用次数）
        2. 并发发送请求
        3. 再检查最终状态
        4. 对比 "应该变化的量" vs "实际变化的量"
        
        参数:
            url: 要并发测试的 URL
            body: 请求 body
            state_url: 用于检查状态的 URL（如余额查询）
            state_field: 状态 JSON 中的字段名（如 "balance"）
            concurrency: 并发数
        """
        findings = []

        # 1. 获取初始状态
        state_before = None
        if state_url and state_field:
            state_resp = await self.http.request(
                "GET", state_url, cookies=self.cookies, headers=self.headers
            )
            if state_resp.status_code == 200:
                try:
                    state_data = json.loads(state_resp.body)
                    state_before = self._extract_nested_field(state_data, state_field)
                except (json.JSONDecodeError, KeyError):
                    pass

        # 2. 并发发送请求
        race_result = await self.http.race_test(
            method=method,
            url=url,
            count=concurrency,
            headers=self.headers,
            cookies=self.cookies,
            json_data=body,
            data=data,
        )

        # 3. 获取最终状态
        state_after = None
        if state_url and state_field:
            await asyncio.sleep(1)  # 等待后端处理完
            state_resp = await self.http.request(
                "GET", state_url, cookies=self.cookies, headers=self.headers
            )
            if state_resp.status_code == 200:
                try:
                    state_data = json.loads(state_resp.body)
                    state_after = self._extract_nested_field(state_data, state_field)
                except (json.JSONDecodeError, KeyError):
                    pass

        # 4. 分析
        evidence_parts = [
            f"并发 {concurrency} 次请求",
            f"成功 {race_result['success_count']} 次",
            f"不同响应体 {race_result['unique_bodies']} 种",
        ]

        state_changed = False
        if state_before is not None and state_after is not None:
            evidence_parts.append(f"状态变化: {state_before} → {state_after}")
            
            # 判断是否多次生效
            try:
                before_num = float(state_before)
                after_num = float(state_after)
                diff = abs(after_num - before_num)
                
                # 如果只应该变化 1 次但变化了多次
                if race_result['success_count'] > 1 and diff > 0:
                    state_changed = True
                    evidence_parts.append(
                        f"⚠️ 数值变化={diff}，多个请求可能都生效了"
                    )
            except (ValueError, TypeError):
                if state_before != state_after:
                    state_changed = True

        # 判定
        is_vulnerable = race_result['likely_vulnerable'] or state_changed
        
        if is_vulnerable or race_result['success_count'] > 1:
            severity = "critical" if state_changed else "high"
            confidence = 0.9 if state_changed else 0.6
            
            findings.append(BizLogicFinding(
                url=url,
                method=method,
                vuln_type="race_condition",
                severity=severity,
                confidence=confidence,
                evidence="; ".join(evidence_parts),
                payload=body,
                state_before=str(state_before) if state_before else "",
                state_after=str(state_after) if state_after else "",
                state_changed=state_changed,
                impact="并发请求导致操作重复执行（可能重复领取/重复扣款/重复签到）",
                confirmed=state_changed,
            ))

        self.findings.extend(findings)
        return findings

    # ─── 流程跳跃 ─────────────────────────────────────────────

    async def test_workflow_skip(
        self,
        steps: list[dict],
    ) -> list[BizLogicFinding]:
        """
        流程跳跃测试 — 跳过中间步骤直接执行最后一步
        
        steps: [
            {"name": "选商品", "url": "...", "method": "POST", "body": {...}},
            {"name": "确认订单", "url": "...", "method": "POST", "body": {...}},
            {"name": "支付", "url": "...", "method": "POST", "body": {...}},
            {"name": "完成", "url": "...", "method": "POST", "body": {...}},
        ]
        
        测试：直接跳到"完成"步骤，看是否能绕过"支付"
        """
        findings = []

        if len(steps) < 2:
            return findings

        # 策略 1: 直接执行最后一步
        last_step = steps[-1]
        resp = await self.http.request(
            last_step.get("method", "POST"),
            last_step["url"],
            json_data=last_step.get("body"),
            cookies=self.cookies,
            headers=self.headers,
        )

        if resp.status_code in (200, 201):
            findings.append(BizLogicFinding(
                url=last_step["url"],
                method=last_step.get("method", "POST"),
                vuln_type="workflow_skip",
                severity="critical",
                confidence=0.7,
                evidence=(
                    f"跳过前 {len(steps)-1} 步直接执行'{last_step.get('name', '最后一步')}'，"
                    f"返回 {resp.status_code}"
                ),
                impact="可能绕过支付/验证等关键步骤",
            ))

        # 策略 2: 跳过中间步骤
        for i in range(1, len(steps) - 1):
            # 执行第一步
            first = steps[0]
            await self.http.request(
                first.get("method", "POST"),
                first["url"],
                json_data=first.get("body"),
                cookies=self.cookies,
                headers=self.headers,
            )

            # 跳过中间步骤，直接执行后续
            skip_step = steps[i]
            next_step = steps[i + 1] if i + 1 < len(steps) else steps[-1]
            
            resp = await self.http.request(
                next_step.get("method", "POST"),
                next_step["url"],
                json_data=next_step.get("body"),
                cookies=self.cookies,
                headers=self.headers,
            )

            if resp.status_code in (200, 201):
                findings.append(BizLogicFinding(
                    url=next_step["url"],
                    method=next_step.get("method", "POST"),
                    vuln_type="workflow_skip",
                    severity="high",
                    confidence=0.6,
                    evidence=(
                        f"跳过'{skip_step.get('name', f'步骤{i+1}')}'后"
                        f"直接执行'{next_step.get('name', f'步骤{i+2}')}'成功"
                    ),
                    impact=f"可绕过'{skip_step.get('name', '中间步骤')}'",
                ))

        self.findings.extend(findings)
        return findings

    # ─── 优惠券/积分重复使用 ────────────────────────────────────

    async def test_coupon_reuse(
        self,
        redeem_url: str,
        redeem_body: dict,
        method: str = "POST",
        max_attempts: int = 3,
    ) -> list[BizLogicFinding]:
        """
        优惠券/兑换码重复使用测试
        
        1. 第一次兑换（应该成功）
        2. 第二次兑换（应该失败）
        3. 如果第二次也成功 → 漏洞
        """
        findings = []
        responses = []

        for i in range(max_attempts):
            resp = await self.http.request(
                method, redeem_url,
                json_data=redeem_body,
                cookies=self.cookies,
                headers=self.headers,
            )
            responses.append(resp)
            await asyncio.sleep(0.5)

        # 分析
        success_count = len([r for r in responses if r.status_code in (200, 201)])
        
        if success_count > 1:
            findings.append(BizLogicFinding(
                url=redeem_url,
                method=method,
                vuln_type="coupon_reuse",
                severity="high",
                confidence=0.8,
                evidence=(
                    f"优惠券连续兑换 {max_attempts} 次，"
                    f"{success_count} 次成功（应该只有1次成功）"
                ),
                payload=redeem_body,
                impact="可重复使用优惠券/兑换码",
                confirmed=True,
            ))

        self.findings.extend(findings)
        return findings

    # ─── 权限提升 ─────────────────────────────────────────────

    async def test_privilege_escalation(
        self,
        profile_url: str,
        method: str = "PUT",
        current_body: dict = None,
    ) -> list[BizLogicFinding]:
        """
        权限提升测试 — 通过修改请求参数提升角色
        
        测试在个人信息修改/注册等接口中添加 role/is_admin 等字段
        """
        findings = []

        if current_body is None:
            current_body = {}

        escalation_params = [
            {"role": "admin"},
            {"is_admin": True},
            {"is_admin": 1},
            {"privilege": "admin"},
            {"type": "admin"},
            {"user_type": "administrator"},
            {"group": "administrators"},
            {"level": 99},
            {"permissions": ["*"]},
            {"role_id": 1},
        ]

        for extra_params in escalation_params:
            test_body = {**current_body, **extra_params}
            
            resp = await self.http.request(
                method, profile_url,
                json_data=test_body,
                cookies=self.cookies,
                headers=self.headers,
            )

            if resp.status_code in (200, 201):
                # 检查响应是否包含升级后的角色信息
                body_lower = resp.body.lower()
                if any(v in body_lower for v in ["admin", "administrator", "superuser"]):
                    findings.append(BizLogicFinding(
                        url=profile_url,
                        method=method,
                        vuln_type="privilege_escalation",
                        severity="critical",
                        confidence=0.7,
                        evidence=(
                            f"添加 {extra_params} 后服务器返回200，"
                            f"响应中包含管理员关键词"
                        ),
                        payload=test_body,
                        impact="可通过修改请求参数提升为管理员",
                    ))
                else:
                    # 服务器接受了但不确定是否生效
                    findings.append(BizLogicFinding(
                        url=profile_url,
                        method=method,
                        vuln_type="privilege_escalation",
                        severity="medium",
                        confidence=0.4,
                        evidence=(
                            f"服务器接受了 {extra_params} 参数(200)，"
                            f"需要手动验证是否生效"
                        ),
                        payload=test_body,
                        impact="可能的权限提升（需验证）",
                    ))

        self.findings.extend(findings)
        return findings

    # ─── 签到/限次操作绕过 ─────────────────────────────────────

    async def test_rate_limit_bypass(
        self,
        url: str,
        method: str = "POST",
        body: dict = None,
        expected_limit: int = 1,
        bypass_techniques: list[str] = None,
    ) -> list[BizLogicFinding]:
        """
        次数限制绕过测试
        
        bypass_techniques:
        - "header": 添加 X-Forwarded-For 等头
        - "case": 大小写变化
        - "encoding": URL编码变化
        - "param": 添加额外参数
        """
        findings = []

        if bypass_techniques is None:
            bypass_techniques = ["header", "case", "param"]

        # 先正常请求确认限制生效
        for _ in range(expected_limit + 2):
            resp = await self.http.request(
                method, url, json_data=body,
                cookies=self.cookies, headers=self.headers
            )
        
        # 现在应该被限制了，尝试绕过
        if "header" in bypass_techniques:
            for ip in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1"]:
                bypass_headers = {
                    **self.headers,
                    "X-Forwarded-For": ip,
                    "X-Real-IP": ip,
                }
                resp = await self.http.request(
                    method, url, json_data=body,
                    cookies=self.cookies, headers=bypass_headers
                )
                if resp.status_code in (200, 201):
                    findings.append(BizLogicFinding(
                        url=url,
                        method=method,
                        vuln_type="rate_limit_bypass",
                        severity="medium",
                        confidence=0.7,
                        evidence=f"通过 X-Forwarded-For: {ip} 绕过次数限制",
                        impact="可无限次执行限次操作",
                    ))
                    break

        if "case" in bypass_techniques:
            # URL 大小写变化
            parsed = urlparse(url)
            variations = [
                url.upper(),
                url + "/",
                url + "?",
            ]
            for var_url in variations:
                resp = await self.http.request(
                    method, var_url, json_data=body,
                    cookies=self.cookies, headers=self.headers
                )
                if resp.status_code in (200, 201):
                    findings.append(BizLogicFinding(
                        url=var_url,
                        method=method,
                        vuln_type="rate_limit_bypass",
                        severity="medium",
                        confidence=0.6,
                        evidence=f"通过 URL 变体 {var_url} 绕过次数限制",
                        impact="可无限次执行限次操作",
                    ))
                    break

        self.findings.extend(findings)
        return findings

    # ─── 辅助方法 ──────────────────────────────────────────────

    def _extract_nested_field(self, data: dict, field_path: str) -> Any:
        """从嵌套 JSON 中提取字段值"""
        parts = field_path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            else:
                return None
        return current

    def get_findings_summary(self) -> dict:
        """获取发现汇总"""
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
