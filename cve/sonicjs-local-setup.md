# SonicJs 本地搭建复现环境指南

## 概述

本文档指导你在本地搭建 SonicJs CMS 环境，用于复现 SONIC-2025-001 ~ 004 漏洞。

SonicJs 运行在 Cloudflare Workers 上，本地开发使用 `wrangler dev` 模拟 Workers 环境。

## 前置要求

```bash
# Node.js 18+
node --version  # >= 18.0.0

# npm
npm --version

# wrangler CLI (Cloudflare Workers CLI)
npm install -g wrangler

# 可选：注册 Cloudflare 账号（wrangler dev --local 不强制要求）
```

## 第一步：克隆源码

```bash
git clone https://github.com/SonicJs-Org/sonicjs.git
cd sonicjs
```

## 第二步：安装依赖

```bash
# 安装所有 workspace 依赖
npm install

# 构建核心包
npm run build:core
```

## 第三步：初始化本地 D1 数据库

```bash
cd my-sonicjs-app

# 应用数据库 migration（本地模式，不需要 Cloudflare 账号）
npx wrangler d1 migrations apply DB --local
```

这会在 `.wrangler/state/` 目录下创建一个本地 SQLite 数据库。

## 第四步：启动开发服务器

```bash
# 方式1：从根目录启动
cd ..  # 回到 sonicjs 根目录
npm run dev

# 方式2：直接从 my-sonicjs-app 启动
cd my-sonicjs-app
npx wrangler dev
```

服务器默认监听 `http://localhost:8787`

## 第五步：验证启动成功

```bash
# 检查服务是否启动
curl -s http://localhost:8787/auth/login | head -5
# 应该返回 HTML 登录页面

# 检查 API
curl -s http://localhost:8787/api/system/health
```

## 第六步：创建管理员账号（正常方式）

```bash
# 使用 seed 脚本（这是正常的初始化方式）
cd my-sonicjs-app
npm run seed

# 或者访问 http://localhost:8787/auth/register 注册第一个用户（自动获得 admin 角色）
```

默认管理员凭据：
- Email: `admin@sonicjs.com`
- Password: `sonicjs!`

## 环境变量说明

`wrangler.toml` 中的关键配置：

```toml
[vars]
ENVIRONMENT = "development"     # 环境标识
CORS_ORIGINS = "http://localhost:8787"

# 以下通过 wrangler secret 设置（本地开发可以不设置，会使用 fallback）:
# JWT_SECRET = "你的真实密钥"          ← 漏洞003 的关键
# JWT_EXPIRES_IN = "30d"
# JWT_REFRESH_GRACE_SECONDS = "7d"
```

## 本地开发 vs 生产的差异

| 项 | 本地 (wrangler dev) | 生产 (Cloudflare Workers) |
|----|---------------------|---------------------------|
| D1 数据库 | 本地 SQLite 文件 | Cloudflare D1 |
| R2 存储 | 本地 `.wrangler/state/r2/` | Cloudflare R2 Bucket |
| KV 缓存 | 本地模拟 | Cloudflare KV |
| JWT_SECRET | 可能没设置（使用 fallback） | 应该通过 wrangler secret 设置 |
| URL | http://localhost:8787 | https://your-app.workers.dev |

## 常用调试命令

```bash
# 查看本地 D1 数据库内容
npx wrangler d1 execute DB --local --command="SELECT * FROM users;"

# 查看本地 R2 存储文件
ls .wrangler/state/v3/r2/

# 查看所有表
npx wrangler d1 execute DB --local --command=".tables"

# 清空用户表重新测试
npx wrangler d1 execute DB --local --command="DELETE FROM users;"
```

## 注意事项

1. `wrangler dev` 默认使用 `--local` 模式，不需要 Cloudflare 账号
2. 如果遇到端口冲突，使用 `npx wrangler dev --port 8788`
3. 本地 R2 存储路径在 `.wrangler/state/v3/r2/sonicjs-ci-media/`
4. 每次重启 wrangler dev 后，本地数据持久存在（除非手动删除 .wrangler 目录）
