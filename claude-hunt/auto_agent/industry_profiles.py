#!/usr/bin/env python3
"""
Industry Profiles — 行业专用检测配置

不同行业的目标有不同的高频漏洞模式。
选对 profile 可以让工具精准打击，不浪费时间在不相关的方向。

用法:
    config.yaml 中设置:
      target:
        industry: "education"  # education / finance / ecommerce / government

    或代码中:
      from industry_profiles import get_industry_profile, get_industry_focus_prompt
      prompt = get_industry_focus_prompt("education")
"""

INDUSTRY_PROFILES = {
    "education": {
        "name": "教育行业",
        "description": "高校教务/统一认证/在线教育/学生信息系统",
        "high_value_targets": [
            "教务系统(学号+默认密码)", "统一身份认证(CAS/SSO)",
            "学生信息管理", "VPN/WebVPN", "邮箱系统",
            "选课系统", "图书馆", "一卡通/充值",
        ],
        "common_vulns": [
            {"type": "weak_password", "desc": "学号+身份证后6位/123456", "severity": "high", "probability": 0.4},
            {"type": "idor", "desc": "改学号看别人成绩/个人信息", "severity": "high", "probability": 0.35},
            {"type": "sqli", "desc": "老PHP/Java教务系统", "severity": "critical", "probability": 0.2},
            {"type": "info_leak", "desc": "接口返回身份证/手机号/家庭住址", "severity": "high", "probability": 0.3},
            {"type": "unauthorized", "desc": "后台弱口令/无认证", "severity": "high", "probability": 0.25},
            {"type": "sso_bypass", "desc": "CAS票据伪造/回调URL", "severity": "critical", "probability": 0.1},
            {"type": "path_traversal", "desc": "下载接口读任意文件", "severity": "high", "probability": 0.15},
        ],
        "default_passwords": ["123456", "000000", "{身份证后6位}", "Aa123456", "a123456"],
        "sensitive_params": ["student_id", "xh", "sfzh", "id_card", "phone", "grade"],
        "test_steps": [
            "1. 找教务系统→学号+123456/身份证后6位登录",
            "2. 登录后改学号→IDOR看别人成绩",
            "3. 找CAS/SSO→测ticket重放/回调URL注入",
            "4. 找VPN→默认密码/未授权访问内网",
            "5. 找信息接口→遍历学号批量获取个人信息",
            "6. 找文件下载→路径穿越(../../etc/passwd)",
            "7. 找选课→并发竞态重复选课",
        ],
    },
    "finance": {
        "name": "金融行业",
        "description": "银行APP/证券/支付/保险/消费金融/借贷",
        "high_value_targets": [
            "网银/手机银行(转账/余额)", "支付接口(充值/提现)",
            "交易系统(买卖/订单)", "短信验证码", "用户中心(实名/银行卡)",
            "活动/优惠券", "贷款/分期", "回调接口(支付通知)",
        ],
        "common_vulns": [
            {"type": "idor", "desc": "改account_id看别人余额/交易", "severity": "critical", "probability": 0.3},
            {"type": "payment_tamper", "desc": "篡改金额/数量为0或负数", "severity": "critical", "probability": 0.15},
            {"type": "sms_bypass", "desc": "验证码爆破/万能码/重放", "severity": "high", "probability": 0.2},
            {"type": "race_condition", "desc": "并发提现/重复领券", "severity": "critical", "probability": 0.15},
            {"type": "unauthorized_api", "desc": "内部接口无鉴权", "severity": "high", "probability": 0.2},
            {"type": "info_leak", "desc": "响应返回完整银行卡/身份证", "severity": "high", "probability": 0.25},
            {"type": "ssrf", "desc": "回调URL→打内网", "severity": "high", "probability": 0.1},
        ],
        "sensitive_params": [
            "amount", "price", "total", "balance", "money",
            "account_id", "card_no", "id_card", "phone",
            "sms_code", "verify_code", "order_id", "trade_no",
            "callback_url", "notify_url", "return_url",
        ],
        "test_steps": [
            "1. 双账号→改ID看别人余额/交易记录",
            "2. 支付接口→抓包改amount为0或-1",
            "3. 验证码→爆破4位(0000-9999)/测试重放",
            "4. 提现/转账→并发20个相同请求",
            "5. 回调URL→改成http://内网IP",
            "6. 密码重置→测验证码是否可预测",
            "7. 导出功能→测能否导出全部用户",
            "8. 优惠券→竞态重复领取",
        ],
    },
    "ecommerce": {
        "name": "电商行业",
        "description": "电商/外卖/团购/票务",
        "high_value_targets": [
            "订单系统", "支付", "优惠券", "商家后台", "评价", "物流", "退款",
        ],
        "common_vulns": [
            {"type": "idor", "desc": "改订单号看别人订单", "severity": "high", "probability": 0.35},
            {"type": "payment_tamper", "desc": "0元购/负数/改运费", "severity": "critical", "probability": 0.15},
            {"type": "race_condition", "desc": "优惠券重复用/积分重复兑", "severity": "high", "probability": 0.2},
            {"type": "unauthorized", "desc": "商家后台未授权", "severity": "high", "probability": 0.15},
        ],
        "sensitive_params": ["price", "amount", "quantity", "coupon_id", "order_id", "freight"],
        "test_steps": [
            "1. 下单改价格→0元购", "2. 优惠券→并发重复用",
            "3. 改订单号→看别人订单", "4. 退款→超额退款",
        ],
    },
    "government": {
        "name": "政企行业",
        "description": "政府门户/OA/政务服务/档案",
        "high_value_targets": ["OA系统", "邮箱", "VPN", "政务平台", "审批系统"],
        "common_vulns": [
            {"type": "weak_password", "desc": "OA弱口令admin/123456", "severity": "high", "probability": 0.35},
            {"type": "sqli", "desc": "老PHP系统注入", "severity": "critical", "probability": 0.25},
            {"type": "unauthorized", "desc": "后台目录无鉴权", "severity": "high", "probability": 0.3},
            {"type": "file_upload", "desc": "上传getshell", "severity": "critical", "probability": 0.1},
        ],
        "default_passwords": ["admin", "admin123", "123456", "Aa123456!", "password"],
        "test_steps": [
            "1. 找后台→admin/admin123", "2. 老系统→SQL注入",
            "3. 文件上传→绕限制", "4. VPN→默认密码",
        ],
    },
}


def get_industry_profile(industry: str) -> dict:
    return INDUSTRY_PROFILES.get(industry, {})


def get_industry_focus_prompt(industry: str) -> str:
    """生成注入 LLM 的行业指南"""
    p = get_industry_profile(industry)
    if not p:
        return ""
    lines = [f"=== 行业指南: {p['name']} ===", ""]
    lines.append("【高频漏洞】")
    for v in sorted(p.get("common_vulns", []), key=lambda x: x["probability"], reverse=True):
        lines.append(f"  [{v['severity'].upper()}] {v['desc']} (~{int(v['probability']*100)}%概率)")
    lines.append("")
    lines.append("【测试步骤】")
    for s in p.get("test_steps", []):
        lines.append(f"  {s}")
    if p.get("sensitive_params"):
        lines.append(f"\n【重点参数】{', '.join(p['sensitive_params'][:12])}")
    lines.append("\n=== 指南结束 ===")
    return "\n".join(lines)



# ═══════════════════════════════════════════════════════════
# EduSRC 专用配置
# ═══════════════════════════════════════════════════════════

EDUSRC_CONFIG = {
    "name": "EduSRC 教育漏洞平台",
    "url": "https://src.sjtu.edu.cn/",
    "target_systems": [
        {"name": "统一身份认证(CAS/SSO)", "keywords": ["cas","sso","authserver","ids"], "vuln_rate": 0.4},
        {"name": "教务系统(正方/青果/强智)", "keywords": ["jwxt","jwgl","jw.","zfsoft","kingosoft"], "vuln_rate": 0.35},
        {"name": "VPN/WebVPN", "keywords": ["vpn","webvpn","wvpn","sslvpn","easyconnect"], "vuln_rate": 0.3},
        {"name": "邮件系统", "keywords": ["mail","email","coremail"], "vuln_rate": 0.25},
        {"name": "OA办公系统", "keywords": ["oa.","seeyon","tongda","weaver"], "vuln_rate": 0.25},
        {"name": "图书馆系统", "keywords": ["lib","opac","library"], "vuln_rate": 0.2},
        {"name": "一卡通/缴费", "keywords": ["ecard","card","pay","ykt"], "vuln_rate": 0.2},
        {"name": "网盘/文件系统", "keywords": ["pan.","cloud","nextcloud"], "vuln_rate": 0.15},
    ],
    "tech_stacks": {
        "正方教务": {"vulns": ["SQL注入","越权查成绩","弱口令"]},
        "致远OA": {"vulns": ["反序列化RCE","文件上传","SQL注入"]},
        "通达OA": {"vulns": ["文件上传","SQL注入","未授权"]},
        "泛微OA": {"vulns": ["SQL注入","SSRF","文件读取"]},
        "EasyConnect": {"vulns": ["RCE","任意文件读取","信息泄露"]},
        "Coremail": {"vulns": ["SSRF","XXE","信息泄露"]},
    },
    "default_passwords": [
        "123456","admin","admin123","Aa123456","000000",
        "{学号}","{身份证后6位}","{身份证后8位}","a123456","qwe123",
    ],
    "fofa_dorks": [
        'domain="edu.cn" && title="登录"',
        'domain="edu.cn" && body="正方"',
        'domain="edu.cn" && (title="VPN" || title="WebVPN")',
        'domain="edu.cn" && (body="致远" || body="seeyon")',
        'domain="edu.cn" && (body="通达" || title="通达OA")',
        'domain="edu.cn" && body="Coremail"',
        'domain="edu.cn" && title="后台"',
        'cert="edu.cn" && port="8080"',
    ],
    "nuclei_priority_tags": [
        "default-login","weak-password","seeyon","tongda","weaver",
        "easyconnect","vpn","coremail","sqli","idor","unauth","upload","rce",
    ],
}


def get_edusrc_config():
    return EDUSRC_CONFIG


def get_edusrc_scan_plan(domain):
    cfg = EDUSRC_CONFIG
    lines = [
        f"# EduSRC 扫描计划: {domain}", "",
        "## Step 1: 资产发现",
        f"subfinder -d {domain} | httpx -title -tech-detect", "",
        "## Step 2: 识别系统类型",
    ]
    for s in cfg["target_systems"][:6]:
        lines.append(f"  - {s['name']} (出洞率~{int(s['vuln_rate']*100)}%)")
    lines.extend(["", "## Step 3: Nuclei 定向",
        f"nuclei -l alive.txt -tags {','.join(cfg['nuclei_priority_tags'][:8])} -rl 5", "",
        "## Step 4: 弱口令",
        f"默认密码: {', '.join(cfg['default_passwords'][:6])}", "",
        "## Step 5: 越权（双学号）",
        "用学号A登录→抓包改学号为B→看到B的数据=越权", "",
        "## FOFA 搜索",
    ])
    for d in cfg["fofa_dorks"][:4]:
        lines.append(f"  {d}")
    return "\n".join(lines)
