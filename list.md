# 漏洞挖掘路线图 & 实战流程 (list.md)

> 从入门到赚钱的完整路径，配合本项目工具使用

---

## 一、阶段路线图

```
┌─────────────────────────────────────────────────────────────┐
│  阶段 1: 练手期（CNVD/CVE 刷编号）                           │
│  目标: 熟悉审计流程、建立信心、简历有东西写                    │
│  周期: 1-2 周                                                │
│  产出: 3-10 个 CNVD 编号                                     │
├─────────────────────────────────────────────────────────────┤
│  阶段 2: 赚钱期（SRC 赏金）                                  │
│  目标: 用工具打 SRC，直接拿钱                                 │
│  周期: 持续                                                  │
│  产出: 每月 3000-20000 RMB                                   │
├─────────────────────────────────────────────────────────────┤
│  阶段 3: 进阶期（H1/Bugcrowd 国际赏金）                      │
│  目标: 高质量漏洞 + 英文报告                                  │
│  周期: 持续                                                  │
│  产出: $1,000-$50,000 / 漏洞                                 │
├─────────────────────────────────────────────────────────────┤
│  阶段 4: 专家期（0day 研究 / 攻防比赛）                       │
│  目标: 知名软件漏洞 / 比赛成绩                                │
│  周期: 长期积累                                              │
│  产出: 行业顶级认可                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 二、阶段 1：CNVD/CVE 刷编号（练手）

### 为什么先做这个

- 零法律风险（本地环境复现）
- 门槛低（grep 危险函数就能出）
- 快速建立信心
- 简历/评级加分
- 为阶段 2 练手

### 每日流程

```
09:00  GitHub 搜目标（国产 PHP/Java 项目，star 100-3000）
10:00  git clone + Docker 搭环境
11:00  code_auditor.py 自动扫 / 手动 grep 危险函数
12:00  找到漏洞 → 本地验证 → 截图
14:00  写报告（中文）→ 提交 CNVD
14:30  同时写英文报告 → 提交 CVE（MITRE）
15:00  换下一个项目重复

产出: 一天 1-3 个漏洞，一周 5-10 个编号
```

### 选目标策略

```bash
# GitHub 搜索语法
language:PHP stars:100..3000 "管理系统" OR "后台" OR "admin"
language:Java stars:100..2000 "OA" OR "ERP" OR "CMS"
language:Python stars:100..2000 "management" OR "admin"

# 最容易出洞的类型
1. 国产 PHP CMS（织梦/PbootCMS/易优/各种小 CMS）
2. Java OA 系统（若依/JeecgBoot/各种 OA）
3. 进销存/酒店/物业管理系统
4. 各种 "XX管理平台"
5. star 100-500 的项目（基本没人审计过）
```

### 快速审计命令

```bash
# PHP — SQL注入
grep -rn "\$_GET\|\$_POST\|\$_REQUEST" --include="*.php" . | grep -i "query\|select\|where\|insert\|update\|delete" | grep -v "prepare\|bindParam"

# PHP — 命令执行
grep -rn "system\|exec\|passthru\|shell_exec\|popen\|eval" --include="*.php" . | grep "\$_"

# PHP — 文件上传
grep -rn "move_uploaded_file\|file_put_contents" --include="*.php" .

# PHP — 文件包含
grep -rn "include\|require" --include="*.php" . | grep "\$_"

# Java — SQL注入
grep -rn "Statement.*execute\|createQuery\|createNativeQuery" --include="*.java" . | grep -v "Prepared"

# Java — 反序列化
grep -rn "ObjectInputStream\|readObject\|XMLDecoder" --include="*.java" .

# Java — 命令执行
grep -rn "Runtime.exec\|ProcessBuilder" --include="*.java" . 

# Python — 命令执行/SSTI
grep -rn "os.system\|subprocess\|eval\|exec" --include="*.py" . | grep -v "# \|test\|example"
grep -rn "render_template_string\|Markup\|safe" --include="*.py" .
```

### 用项目工具自动审计

```bash
# 自动扫描（推荐）
python -c "
import asyncio
from code_auditor import run_code_audit

results = asyncio.run(run_code_audit(
    repo_path='/path/to/target/source',
    llm_config={'api_key': 'sk-xxx', 'model': 'deepseek-chat'}  # 可选
))

print(f'=== Found {len(results[\"findings\"])} vulnerabilities ===')
for f in results['findings']:
    print(f'  [{f[\"severity\"]}] {f[\"type\"]}: {f[\"file\"]}:{f[\"line\"]}')
    print(f'    {f[\"description\"][:80]}')
"
```

### CNVD 报告模板

```
【漏洞名称】XXX系统 vX.X 存在 [SQL注入/RCE/未授权访问] 漏洞
【影响产品】XXX系统（GitHub: https://github.com/xxx/xxx）
【影响版本】≤ vX.X（最新版仍受影响）
【漏洞类型】SQL注入 / 远程代码执行 / 越权访问
【危害等级】高危

【漏洞描述】
XXX系统的 /path/to/file.php 中，xxx 参数未经过滤直接拼接到 SQL 语句中，
攻击者可构造恶意请求实现 [SQL注入/任意命令执行/越权访问]。

【复现环境】
- 系统版本: XXX vX.X
- 运行环境: PHP 7.4 + MySQL 5.7 / Docker

【复现步骤】
1. 部署 XXX 系统（docker compose up -d）
2. 访问 http://localhost/admin/xxx.php?id=1
3. 修改参数为: id=1' AND 1=1-- （正常返回）
4. 修改参数为: id=1' AND 1=2-- （异常返回）
5. 确认存在 SQL 注入

【PoC】
GET /admin/xxx.php?id=1'+AND+extractvalue(1,concat(0x7e,version()))--+ HTTP/1.1
Host: localhost
Cookie: PHPSESSID=xxx

【漏洞证明截图】
（附截图）

【影响面评估】
FOFA 搜索 body="XXX系统" 结果约 XXX 条
（附 FOFA 截图）

【修复建议】
使用参数化查询 / PDO 预处理语句替代字符串拼接。
```

### 一洞多吃流程

```
发现漏洞
    │
    ├── 1. 提交 CNVD（中文报告）→ 拿 CNVD 编号
    │
    ├── 2. 提交 CVE（英文报告给 MITRE）→ 拿 CVE 编号
    │
    ├── 3. FOFA 搜使用该系统的企业
    │      └── 企业有 SRC？→ 验证漏洞存在 → 报 SRC 拿赏金
    │
    └── 4. 写 nuclei 模板 → 加入自己的模板库（以后批量用）
```

---

## 三、阶段 2：SRC 赏金（赚钱）

### 平台选择

| 平台 | 适合 | 赏金 | 难度 |
|------|------|------|------|
| 补天 | 国内企业/政府 | 200-20000 | ★★★☆ |
| 漏洞盒子 | 互联网企业 | 100-10000 | ★★★☆ |
| 火线 | 金融/互联网 | 500-30000 | ★★★★ |
| 各厂商 SRC | 大厂 | 1000-50000 | ★★★★★ |

### 每日流程

```
09:00  选目标（新上线的 SRC / 补天新企业）
09:30  跑 Pipeline:
       python recon_pipeline.py --target xxx.com --rate 2
10:30  查看结果:
       - findings/nuclei.txt → 有没有已知漏洞
       - js/secrets.txt → 有没有密钥泄露
       - urls/with_params.txt → 有没有可测参数
11:00  手动深入:
       - 403 路径 → bypass_403.py 测试
       - API 端点 → IDOR/越权测试
       - 登录口 → 弱口令/验证码绕过
       - Java 站 → java_deser.py
12:00  找到漏洞 → 验证 → 截图 → 写报告 → 提交
14:00  换下一个目标重复

产出: 一周 2-5 个有效漏洞提交
```

### 高价值目标优先级

```
1. 支付/钱包接口  → 金额篡改、并发提现（严重 → 5000+）
2. 用户数据 API   → IDOR 水平越权（高危 → 1000-5000）
3. 管理后台      → 弱口令/未授权（高危 → 1000-5000）
4. 文件上传      → getshell（严重 → 5000+）
5. 密码重置      → 任意用户重置（高危 → 1000-3000）
6. API Key 泄露  → JS 中的密钥（中危 → 200-1000）
7. CORS 错误配置  → 窃取数据（中危 → 200-500）
```

### 工具使用对应表

| 场景 | 用哪个模块 | 命令 |
|------|-----------|------|
| 全流程侦察 | `recon_pipeline.py` | `python recon_pipeline.py -t target.com --deep` |
| 403 绕过 | `bypass_403.py` | `from bypass_403 import Bypass403` |
| SSRF 利用 | `ssrf_exploiter.py` | `from ssrf_exploiter import SSRFExploiter` |
| Java 反序列化 | `java_deser.py` | `from java_deser import JavaDeserExploiter` |
| API 安全 | `api_security_scanner.py` | `from api_security_scanner import APISecurityScanner` |
| 缓存投毒 | `cache_poisoning.py` | `from cache_poisoning import CachePoisonScanner` |
| 密钥泄露 | `credential_hunter.py` | `from credential_hunter import CredentialHunter` |
| 云安全 | `cloud_scanner.py` | `from cloud_scanner import CloudSecurityScanner` |
| 子域名接管 | `subdomain_takeover.py` | `from subdomain_takeover import SubdomainTakeoverScanner` |
| 批量打点 | `mass_hunter.py` | `from mass_hunter import MassHunter` |

---

## 四、阶段 3：H1/Bugcrowd 国际赏金

### 为什么做国际

```
国内 SRC:  高危 1000-5000 RMB
HackerOne: Critical $5,000-$50,000 USD
Bugcrowd:  P1 $3,000-$25,000 USD

同样的漏洞，赏金差 10-50 倍
```

### 报告质量要求

H1 审核员看的核心是：
```
1. 清晰的 Impact（影响是什么）
2. 可复现的 Steps（步骤要精确）
3. PoC（代码/curl 命令/截图）
4. 没有废话（不要写 disclaimer 和 ethics 声明）
```

### 英文报告模板（你的 report_generator.py 可直接生成）

```markdown
## Summary
[一句话描述漏洞和影响]

## Steps to Reproduce
1. Navigate to `https://target.com/api/v1/users`
2. Change the `user_id` parameter from `123` to `124`
3. Observe that user 124's private data is returned

## Impact
An authenticated attacker can access any user's personal data
including email, phone number, and billing address by manipulating
the user_id parameter. This affects all ~500,000 registered users.

## PoC
```
curl -s 'https://target.com/api/v1/users/124' \
  -H 'Authorization: Bearer eyJ...' \
  -H 'Cookie: session=abc123'
```

## Suggested Fix
Implement server-side authorization check to verify the requesting
user has permission to access the requested resource.
```

### H1 高价值漏洞类型

| 漏洞 | 赏金范围 | 你的工具 |
|------|---------|---------|
| SSRF → AWS 凭证 | $10,000-$50,000 | `ssrf_exploiter.py` |
| RCE（Java 反序列化） | $10,000-$30,000 | `java_deser.py` |
| 认证绕过 → 全站接管 | $5,000-$25,000 | `bypass_403.py` + `api_security_scanner.py` |
| SQL注入 → 数据泄露 | $3,000-$15,000 | `exploit_engine.py` |
| 缓存投毒 → 全站 XSS | $3,000-$10,000 | `cache_poisoning.py` |
| 子域名接管 | $500-$3,000 | `subdomain_takeover.py` |

---

## 五、组合拳打法（性价比最高）

### 打法 1: CNVD + SRC 联动

```
1. 审计一个国产开源系统（比如某 OA）
2. 找到 SQL 注入
3. 提 CNVD 拿编号
4. 同时提 CVE 拿国际编号
5. FOFA 搜哪些企业在用这个 OA
6. 找到有 SRC 的企业 → 验证漏洞存在 → 报 SRC 拿赏金
7. 写 nuclei 模板 → mass_hunter.py 批量验证更多企业

一个洞 = CNVD编号 + CVE编号 + SRC赏金（可能多个企业）
```

### 打法 2: 新 CVE 抢首杀

```
1. 关注 NVD/GitHub Advisory 新披露的 CVE
2. 第一时间写 PoC（java_deser.py 里的模板）
3. FOFA/Shodan 搜受影响资产
4. 验证漏洞存在
5. 报对应 H1/SRC 程序
6. 比别人快 24 小时 = 拿到赏金

工具: mass_hunter.py 的 hunt_cve() 就是干这个的
```

### 打法 3: 批量指纹打点

```
1. 发现某个系统有漏洞（比如某 CMS 的 SQL 注入）
2. 计算 favicon hash
3. FOFA: icon_hash="xxxxxxxx" → 几百个站
4. nuclei 模板批量验证
5. 有 SRC 的报 SRC，没有的报 CNVD

工具: mass_hunter.py 的 hunt_fingerprint()
```

---

## 六、时间管理

### 工作日（2-3 小时/天）

```
方案 A: 纯 CNVD 刷量
  20:00-21:00  选目标 + 搭环境
  21:00-22:00  审计 + 找漏洞
  22:00-22:30  写报告 + 提交

方案 B: SRC 赏金
  20:00-20:30  选目标 + 跑 pipeline
  20:30-21:30  分析结果 + 手动测试
  21:30-22:00  验证漏洞 + 提交
```

### 周末（集中突破）

```
周六:
  上午: 跑 3-5 个目标的 pipeline（让它自己跑）
  下午: 逐个分析结果，手动深入测试
  
周日:
  上午: 继续测试 + 写报告
  下午: 提交所有发现 + 复盘本周成果
```

---

## 七、工具环境搭建清单

### VPS 一键装完

```bash
# 1. Go 工具（一键安装）
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/owasp-amass/amass/v4/...@master

# 2. Python 依赖
pip install pyyaml openai paramspider arjun

# 3. ysoserial（Java 反序列化）
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \
  -O ~/tools/ysoserial.jar

# 4. nuclei 模板更新
nuclei -ut

# 5. 配置 API Key
export DEEPSEEK_API_KEY="sk-xxx"
export FOFA_EMAIL="xxx@xxx.com"
export FOFA_KEY="xxxxxxxx"
```

### 验证安装

```bash
cd claude-hunt/auto_agent
python -c "from recon_pipeline import ReconPipeline; print('Pipeline OK')"
python -c "from enhanced_scanner import EnhancedScanner; print('Scanner OK')"
python -c "from java_deser import JavaDeserExploiter; print('Java OK')"
python -c "from mass_hunter import MassHunter; print('Hunter OK')"
```

---

## 八、收益预期（保守估计）

| 阶段 | 月投入时间 | 月收益 |
|------|-----------|--------|
| 纯刷 CNVD | 20h | 0（只有编号） |
| CNVD + SRC 联动 | 40h | 2000-8000 RMB |
| 国内 SRC | 60h | 5000-20000 RMB |
| H1 国际 | 80h | $2000-$20000 |
| 全职 BB | 160h | $5000-$50000 |

---

## 九、避坑指南

| 坑 | 怎么避 |
|----|--------|
| 花太多时间造工具 | 工具够了，去实战 |
| 目标太难（大厂） | 先打小目标练手 |
| 不限速被封 IP | 用 traffic_controller + proxy_rotator |
| 报告写不好被拒 | 参考 report_generator.py 的模板 |
| CNVD 被拒"影响面不够" | 一定要附 FOFA 搜索截图 |
| 一个目标死磕太久 | 5 分钟没进展就换 |
| 只会扫描不会手动 | 工具出结果后一定要手动验证 |
| 法律风险 | CNVD 用本地环境；SRC 严格在 scope 内 |

---

*最后更新: 2025-06*
