# Task — 已完成 + 候选目标

> 已完成项目归档 + HackerOne 候选目标池。优先打新鲜面。

---

## 已完成（不要重启）

### GitLab HackerOne（2026-05-27）
**结论**: gitlab.com 无可用漏洞。
覆盖：REST 50+端点 / GraphQL 309 mutations / SSRF 6向量 / OAuth 7手法 / XSS 11x8 / 子域名2569 / 源码审计8 / CVE-2025-27407 Lab验证

### vivo SRC（2026-05-25 → 2026-05-27）
**结论**: 无高危漏洞。核心阻塞：captcha+登录。
覆盖：2,150子域名/1,047存活 / VSIGN逆向 / Game/CloudDisk/Shop/Dev/第三方 / 浏览器自动化未实现

---

## HackerOne 候选目标池

按优先级排序。原则：新鲜面 > 窄范围深挖 > 大而全扫荡。

### 第一梯队 — 新鲜面，现在冲

#### 1. Cognition / Devin / Windsurf 🆕
**为什么**: 2026-05-26 新增 deepwiki.com / *.devin.ai / cognition.ai / windsurf.com / windsurf IDE/plugins
**攻击面**: AI coding agent 全家桶，正适合工具路线
**重点挖**:
- OAuth token scope / redirect
- workspace/project 越权
- repo 访问边界
- 插件权限
- prompt/agent 工具调用越权
- 文件读取边界

#### 2. Netlify
**攻击面**: app.netlify.com / api.netlify.com / build/deploy/team/site
**重点挖**:
- team/site IDOR
- deploy log 泄露
- 环境变量权限
- 邀请链接/OAuth app integration 权限绕过
- 跨站点构建触发

#### 3. Privy (Web3 Auth SaaS)
**攻击面**: api.privy.io / auth.privy.io / dashboard.privy.io / recovery.privy.io / @privy-io npm 包
**重点挖**:
- project/org 边界
- JWT/OAuth 配置错配
- webhook 签名验证
- API key 权限过大
- 钱包/身份恢复流程
- cross-app connect 权限边界

#### 4. Mergify
**攻击面**: api.mergify.com / dashboard.mergify.com — 范围窄但干净
**重点挖**:
- GitHub App 权限
- 别人 org/repo rule 读取
- webhook replay
- PR automation 越权

#### 5. GoCardless (Sandbox)
**攻击面**: api-sandbox.gocardless.com / connect-sandbox / oauth-sandbox / manage-sandbox
**注意**: 金融类只碰 sandbox 和自己数据
**重点挖**:
- OAuth redirect
- sandbox/prod 隔离
- mandate/payment 对象 IDOR
- 低权限操作越权

#### 6. Airtable (Staging)
**攻击面**: api-staging.airtable.com / staging.airtable.com / *.staging.airtable.com / airtable.js SDK
**重点挖**:
- base/workspace/table/view 权限边界
- API token scope
- staging 配置泄露
- SDK 参数污染

### 第二梯队 — 大但攻击面广

#### 7. Databricks
**攻击面**: accounts.cloud.databricks.com / Free Edition / cloud workspace / Open Scope
**重点挖**: workspace/account IAM / cluster/job/notebook 权限 / token scopes / Free Edition 隔离
**注意**: 高价值但学习成本高

#### 8. Vercel Open Source ❌ 无漏洞 (2026-05-27)
**结论**: Next.js防御极硬 / AI SDK利用场景窄 / Turborepo无代码漏洞 / CLI不算漏洞 / 全删已清
**教训**: 成熟框架源码审计产出低，优先新鲜面+API型目标

#### 9. Anthropic
**攻击面**: api.anthropic.com / console.anthropic.com / claude.ai / Claude Code / Claude Desktop Extensions / MCP servers / API & SDKs
**重点挖**:
- API key 权限边界
- console 组织边界
- MCP 扩展权限
- Claude Code 本地文件/命令边界
**注意**: 竞争硬，不要越狱提示词

#### 10. MongoDB
**攻击面**: Atlas / IAM / Billing / Data Federation / Charts / MCP Server / VS Code Plugin / Shell / Drivers
**重点挖**: Atlas org/project 越权 / API key 权限 / MCP server / IDE 插件 / 本地连接串泄露

### 第三梯队 — 价值高但需时间

#### 11. Elastic
**攻击面**: *.elastic.co / *.elastic.dev (大量 wildcard) — 低速 recon
**重点挖**: 子域资产 / Elastic Cloud 账号边界 / Kibana/Cloud 控制台 / 凭证类影响

#### 12. Mapbox
**攻击面**: api.mapbox.com / docs / GitHub / Android/iOS SDK / Mapbox GL JS
**重点挖**: API token 权限 / style/dataset/tileset IDOR / SDK key 限制绕过

#### 13. Neon (Serverless Postgres)
**重点挖**: org/project/db branch 权限 / connection string 泄露 / invite/role / snapshot/restore 越权
**注意**: 需账号和测试环境

#### 14. Yoti / Modern Treasury 类
**攻击面**: 自注册流程、多租户、KYC/文档/账单 API
**重点挖**: 组织隔离 / 成员权限 / 对象 IDOR
**注意**: 金融/KYC 类只用自己测试账号

### 工具-目标匹配

| 能力 | 最适合打 |
|------|---------|
| subfinder+httpx 子域名 | Cognition(新域多) / Netlify / Elastic(wildcard) |
| nuclei 12k CVE模板 | MongoDB(Atlas CVE) / Elastic(ES CVE) |
| API IDOR/越权 | Netlify(team/site) / Privy(app) / Mergify(org) / Airtable(base) |
| OAuth/redirect | Privy(JWT/OAuth) / GoCardless(OAuth sandbox) / Cognition(OAuth) |
| 源码审计+本地Lab | Vercel OSS(Next.js) / Anthropic(MCP/扩展) |
| 沙箱/Staging | GoCardless(sandbox) / Airtable(staging) / Databricks(Free) |
| Hermes 渗透 | Cognition / Privy / Netlify |

### 推荐启动顺序

```
Cognition → Netlify → Privy → Mergify → GoCardless sandbox
    ↓
Airtable staging → Vercel OSS → 循环看哪个出洞
```

避坑：Google / Meta / Shopify / Uber / GitLab / vivo — 已验证打不动
