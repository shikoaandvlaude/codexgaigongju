---
name: hermes-bridge
description: Hermes Agent 集成方案 + GPT留言板四层架构。GPT(Codex)做产品经理写TASKS.md, DS(CC壳)读留言板执行, Hermes做一线渗透自写skill, Kali MCP做执行层。含缓存命中率优化策略。中文触发词：hermes、桥接、渗透自动化、自写skill、四层架构、留言板、缓存命中、省钱
---

# Hermes Agent 集成方案 — 四层架构

GPT(Codex) 产品经理 → DS(CC壳) 技术负责人 → Hermes 一线渗透 → Kali MCP 执行层

---

## 一、Hermes Agent 安装配置

### Windows 安装

```powershell
# 1. 通过 pip 安装（推荐用 venv）
python -m venv ~/.hermes/venv
~/.hermes/venv\Scripts\pip install hermes-agent

# 2. 验证安装
~/.hermes/venv\Scripts\hermes --version

# 3. 创建配置目录
mkdir ~/.hermes/skills
mkdir ~/.hermes/logs
```

### 配置文件: `~/.hermes/config.yaml`

Hermes 用便宜模型跑渗透，不需要 Claude Opus。推荐用 DeepSeek V3 或本地 Ollama：

```yaml
model:
  default: "deepseek-chat"
  provider: "custom"
  base_url: "https://api.deepseek.com/v1"

# 渗透任务配置
penetration:
  max_depth: 3           # 自动扫描深度
  auto_skill: true       # 开启自写 skill
  skill_dir: "~/.hermes/skills"
  timeout: 300           # 单任务超时(秒)
  threads: 10            # 并发数

# 工具路径（指向你 E 盘的工具链）
tools:
  nuclei: "E:\\go\\bin\\nuclei.exe"
  subfinder: "E:\\go\\bin\\subfinder.exe"
  httpx: "E:\\go\\bin\\httpx.exe"
  katana: "E:\\go\\bin\\katana.exe"
  ffuf: "E:\\go\\bin\\ffuf.exe"

# 输出目录
output:
  reports: "D:\\hermes-reports"
  skills: "~/.hermes/skills"
  logs: "~/.hermes/logs"
```

### 环境变量: `~/.hermes/.env`

```
OPENAI_API_KEY=sk-your-deepseek-api-key
```

### 9router 集成（已有）

你的 9router 已经有 hermes-settings API（`/api/cli-tools/hermes-settings`），可以直接从 Web UI 管理 Hermes 配置。启动 9router 后在设置页填入 DeepSeek 的 API 信息即可。

---

## 二、种子 Skill 体系

从 claude-hunt/SKILL.md 的 1223 行知识库转换出 9 个 Hermes 种子 skill：

| # | Hermes Skill | 来源 | 用途 |
|---|-------------|------|------|
| 1 | `hermes-recon` | SKILL.md Phase 1 | 子域名、资产发现、指纹识别 |
| 2 | `hermes-idor` | IDOR章节 | 10种IDOR变体检测 |
| 3 | `hermes-ssrf` | SSRF + Bypass Table | SSRF检测 + 绕过表 |
| 4 | `hermes-xss` | XSS章节 | 存储/反射/DOM XSS |
| 5 | `hermes-auth` | Auth Bypass章节 | 认证绕过、JWT攻击 |
| 6 | `hermes-chain` | A→B Bug Signal | Bug链组合攻击 |
| 7 | `hermes-fingerprint` | Technology Fingerprinting | 技术栈识别 + 框架快扫 |
| 8 | `hermes-api` | API/GraphQL章节 | API端点挖掘、GraphQL |
| 9 | `hermes-cloud` | Cloud章节 | S3、云配置、CI/CD |

运行种子转换脚本生成这 9 个 skill 文件：
```bash
python skills/hermes-bridge/seed_converter.py
```

### Skill 自增长机制

Hermes 渗透过程中会自动扩展 skill：

```
初始9个种子 → Hermes扫目标 → 发现WordPress+WooCommerce
  → 自动写 hermes-wp-woocommerce skill (含SQLi检测)
  → 下次遇到同类目标直接复用
  → 稳定后回写 claude-hunt/SKILL.md
```

---

## 三、GPT 产品经理层（新增）

GPT (Codex) 不写代码，专职做三件事：

1. **项目规划** — 读项目→拆任务→写 TASKS.md
2. **代码审查** — DS 完成的任务，GPT 审查质量
3. **上下文接力** — 每次在 TASKS.md 底部更新"上下文摘要"，DS 新会话直接读

### TASKS.md 留言板协议

```
GPT 写任务 ──→ TASKS.md ──→ DS 读和执行
DS 标记 [DONE] ──→ GPT 审查 ──→ [APPROVED] 或 [REWORK]
```

这是 Karpathy 思想的延伸：给 AI 一个简单的约束文件，比长篇大论的提示有效得多。TASKS.md 对 DS 的作用 = CLAUDE.md 对 Claude Code 的作用。

## 四、四层桥接架构

```
┌─────────────────────────────────────────────────────────┐
│              GPT (Codex) — 产品经理                       │
│  • 项目规划 + 任务拆分                                    │
│  • 代码审查（不直接写代码）                                  │
│  • 写入 TASKS.md 留言板                                  │
└──────────┬──────────────────────────────────────────────┘
           │ 任务指令 (TASKS.md)
           ▼
┌─────────────────────────────────────────────────────────┐
│              DS (Claude Code 壳) — 技术负责人              │
│  • 读 TASKS.md → 按优先级执行                             │
│  • 深度分析 Hermes 发现                                   │
│  • 写代码 + 生成 PoC + 报告                               │
│  • 对照 audit-knowledge.md                               │
└──────────┬──────────────────────────┬───────────────────┘
           │ 分析需求                   │ 执行指令
           ▼                          ▼
┌──────────────────────┐    ┌──────────────────────┐
│   Hermes Agent        │    │     Kali MCP          │
│  • 一线渗透自写skill   │    │  • nuclei 批量扫描     │
│  • 自动化扫描(便宜模型) │    │  • sqlmap 注入验证     │
│  • 发现→标记→推送     │    │  • ffuf 模糊测试       │
└──────────────────────┘    └──────────────────────┘
```

### 桥接脚本: `hermes_bridge.py`

核心功能：
1. **接收 Hermes 发现** → 过滤低危 → 推送给 Claude Code 分析
2. **Claude Code 分析结果** → 回写给 Hermes 完善 skill
3. **定时任务调度** → 每天凌晨自动扫描 + 早上出报告

## 五、缓存命中率优化

> 前几天便宜是因为同一项目前缀重复率高、缓存命中多。换新目标后每次都走未命中价格(贵 4x)。

### 省钱核心三原则

1. **同一项目跑在一个会话里** — 别开新窗口，前缀复用 → 缓存命中高
2. **GPT 先写 TASKS.md 再让 DS 干活** — 避免 DS 自己探索浪费 token
3. **同类操作批量做** — 10 个目标的同端点一次扫完，别 1 个 1 个来

### 省钱对照表

| 行为 | 缓存命中率 | 价格 |
|------|-----------|------|
| 同一会话持续审计同一项目 | ~80%+ | ~$0.01/轮 |
| 每轮开关新会话但同项目 | ~30% | ~$0.03/轮 |
| 换新目标开新会话 | ~5% | ~$0.04/轮(4x) |
| 频繁切换项目+新会话 | ~0% | ~$0.05+/轮 |

### 实操

- 一天的 SRC 审计放在 1-2 个长会话里
- 会话中途不要切去干别的（前缀一换缓存全丢）
- 用 TASKS.md 做上下文接力（新会话读了就知道上下文，减少探索轮次）
- Hermes 的扫描结果用 `--review` 批量审查，不要逐个开会话

### 工作流

```yaml
# 日常SRC扫描 (Hermes 主导，几乎不烧钱)
schedule: "0 2 * * *"  # 每天凌晨2点
steps:
  - hermes: 读取 hermes-recon skill, 扫描目标列表
  - hermes: 自写针对性 skill, 运行漏洞检测
  - hermes: 标记发现 → 写入共享目录
  - claude-code: 读取标记的发现 → 深度分析
  - claude-code: 确认的漏洞 → 生成 PoC
  - claude-code: 更新 audit-knowledge.md
```

---

## 四、日常操作命令

```bash
# 启动 Hermes 对单个目标做渗透
hermes scan target.com --skills ~/.hermes/skills

# 用 Hermes 批量扫 SRC 目标
hermes batch targets.txt --auto-skill --output D:\hermes-reports\

# Claude Code 分析 Hermes 的输出
# 在 Claude Code 中运行: /hermes-review

# 把 Hermes 新写的 skill 同步回 claude-hunt
python skills/hermes-bridge/sync_skills.py --from-hermes --to-claude-hunt

# 定时任务（Windows Task Scheduler 或 cron）
# 每天凌晨跑: hermes batch targets.txt && python hermes_bridge.py --notify
```
