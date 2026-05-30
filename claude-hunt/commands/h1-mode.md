---
description: HackerOne 合规测试模式。加载项目规则、管理登录态、自动分类资产和发现、生成报告草稿。Usage: /h1-mode [init|import|triage|report|translate]
---

# /h1-mode

HackerOne/Bugcrowd 专业挖洞模式。从"能扫线索"升级到"能稳稳提交报告"。

## 核心模块

| 模块 | 文件 | 功能 |
|------|------|------|
| 合规模式 | `compliance_mode.py` | 记录项目规则，拦截违规操作 |
| 登录态导入 | `session_importer.py` | 从 Burp/cURL/HAR 导入认证信息 |
| 资产分类 | `asset_classifier.py` | Web/API/UAT/生产/移动/第三方 |
| 发现分类 | `finding_triage.py` | 自动标签：可提交/需复现/已排除 |
| 报告生成 | `report_drafter.py` | 证据链 + Markdown 报告草稿 |
| 规则翻译 | `program_translator.py` | 英文项目规则中文翻译 + 风险提醒 |

## 工作流程

```
1. 翻译规则    → 看懂项目收什么不收什么
2. 初始化合规  → 记录 scope、禁止动作、必带 header
3. 分类资产    → 区分生产/UAT/第三方
4. 导入登录态  → 从浏览器复制认证请求
5. 开始测试    → 合规模式自动拦截违规操作
6. 分类发现    → 自动标签：能不能报
7. 生成报告    → 一键 Markdown 草稿
```

## 快速开始

### Step 1: 翻译项目规则

```bash
# 直接粘贴 HackerOne 项目 Policy 文本
python3 auto_agent/program_translator.py --text "Non-qualifying: self-xss..." --program syfe

# 或从文件
python3 auto_agent/program_translator.py --file policy.txt --program syfe
```

输出会告诉你：
- 🚫 哪些漏洞类型别浪费时间测
- ⚠️ 哪些操作会导致封号
- ✅ 哪些资产可以测

### Step 2: 创建合规规则

```bash
# 交互式创建
python3 auto_agent/compliance_mode.py --init syfe

# 查看已有规则
python3 auto_agent/compliance_mode.py --list
```

### Step 3: 分类资产

```bash
# 自动分类一批 URL
python3 auto_agent/asset_classifier.py --classify \
    https://api.syfe.com \
    https://app.syfe.com \
    https://uat.syfe.com \
    https://cdn.cloudfront.net/syfe \
    --program syfe
```

### Step 4: 导入登录态

```bash
# 从浏览器 DevTools → Copy as cURL
python3 auto_agent/session_importer.py --curl \
    "curl 'https://api.syfe.com/me' -H 'Authorization: Bearer eyJ...' -H 'Cookie: sess=abc'"

# 从 Burp 导出的 raw request
python3 auto_agent/session_importer.py --raw request.txt

# 从 HAR 文件
python3 auto_agent/session_importer.py --har traffic.har --filter syfe.com
```

会话默认 2 小时过期，用完自动清除 token。

### Step 5: 分类发现结果

```bash
# 演示分类
python3 auto_agent/finding_triage.py --demo
```

标签体系：
- 🟢 **可提交** — 确认漏洞+有影响+在scope内
- 🟡 **需生产复现** — 在 UAT 发现，需要生产环境验证
- 🟠 **仅UAT** — 部分项目不收 UAT 的发现
- 🔴 **已排除** — 误报/不收/out-of-scope
- 🔵 **需要登录** — 需认证才能深入
- ⚪ **调查中** — 线索有潜力但需更多证据

### Step 6: 生成报告

```bash
# HackerOne 格式
python3 auto_agent/report_drafter.py --platform hackerone --title "IDOR on /api/users" --type idor --severity high

# EDUSRC 格式
python3 auto_agent/report_drafter.py --platform edusrc --title "未授权访问" --type unauth --severity high

# 补天格式
python3 auto_agent/report_drafter.py --platform butian --demo
```

## 配置

在 `config.yaml` 中添加：

```yaml
h1_mode:
  enabled: true
  session_ttl_minutes: 120
  auto_sanitize_tokens: true
  store_tokens_locally: false
  default_platform: "hackerone"
  auto_triage: true
  compliance_strict: true
```

## 与原有 pipeline 的关系

这些模块是**独立的补充工具**，不修改原有任何代码：

```
原有 pipeline:  Recon → Params → Hunt → DeepHunt → Validate → Report
                                 ↑                              ↑
H1 模式补充:   合规检查 ←──── 资产分类                  发现分类 → 报告草稿
               规则翻译         登录态导入
```

## 常见场景

### 场景 1: 新项目开始

```
1. /h1-mode translate  → 翻译规则
2. /h1-mode init       → 创建合规配置
3. /recon target.com   → 信息收集（自动受合规模式限制）
4. /h1-mode classify   → 分类发现的资产
5. /h1-mode import     → 导入测试账号的认证
6. /hunt target.com    → 开始挖洞
7. /h1-mode triage     → 分类发现
8. /h1-mode report     → 生成报告
```

### 场景 2: 收到 401 不知道怎么办

```
1. 浏览器登录目标
2. DevTools → Network → 右键请求 → Copy as cURL
3. python session_importer.py --curl "粘贴"
4. 工具自动提取认证头，后续请求自带
5. 2小时后 token 自动清除
```

### 场景 3: 不确定发现能不能报

```
1. finding_triage 自动判断标签
2. 如果标记 "excluded" → 说明项目不收，别浪费时间
3. 如果标记 "needs_prod" → 去生产环境复现
4. 如果标记 "submittable" → 直接用 report_drafter 生成报告
```
