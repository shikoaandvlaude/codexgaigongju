/**
 * SRC 漏洞检测模板模块
 * 基于笔记中的漏洞类型：越权、并发、支付逻辑、IDOR、SSRF 等
 * 生成测试用例和检测思路
 */

// 漏洞分类及测试模板
const SRC_VULN_TEMPLATES = [
  // ============ 业务逻辑漏洞 ============
  {
    id: "biz-payment-negative",
    category: "支付漏洞",
    name: "负数/零值支付",
    severity: "critical",
    description: "修改商品数量为负数或价格为0，影响结算",
    testSteps: [
      "找到下单/支付接口，抓包查看请求参数",
      "定位价格/数量相关字段（price, qty, amount, num）",
      "尝试修改数量为负数（-1）、零（0）、小数（0.001）",
      "尝试修改价格为0或极小值",
      "观察返回包中 execute_status 或业务状态码",
      "刷新页面确认修改是否生效"
    ],
    params: ["price", "amount", "qty", "num", "count", "total", "money"],
    payloads: ["-1", "0", "0.001", "0.01", "-0.01", "99999999"],
    reportTemplate: {
      title: "支付金额/数量篡改漏洞",
      impact: "攻击者可通过修改支付参数，以极低价格或负数金额完成交易，造成平台经济损失",
      fix: "建议在服务端对金额、数量参数进行严格校验，包括类型、范围、符号检查"
    }
  },
  {
    id: "biz-payment-overflow",
    category: "支付漏洞",
    name: "整数最大值溢出",
    severity: "critical",
    description: "利用int类型最大值(2147483647)溢出，让实付金额变为极小值",
    testSteps: [
      "确定商品单价",
      "计算: 2147483647 / 单价 = 最大数量",
      "将数量设为最大数量+1，让总价溢出",
      "溢出后总价 = (数量 × 单价) - 2147483647",
      "创建订单查看实付金额",
      "注意：先不要支付，录视频后取消订单"
    ],
    params: ["qty", "num", "count", "amount"],
    payloads: ["2147483647", "2147483648", "4294967295", "9999999999"],
    reportTemplate: {
      title: "支付金额整数溢出漏洞",
      impact: "攻击者利用整数溢出，以极低价格购买大量商品，造成平台巨额损失",
      fix: "建议使用64位整数或decimal类型存储金额，并对数量上限进行业务校验"
    }
  },
  {
    id: "biz-payment-cancel-repay",
    category: "支付漏洞",
    name: "取消订单再支付",
    severity: "high",
    description: "生成订单后取消，再用第三方支付完成已取消的订单",
    testSteps: [
      "正常下单生成订单",
      "选择第三方支付但不支付，保留支付页面",
      "在另一个窗口取消该订单（优惠券/余额会退回）",
      "回到支付页面完成支付",
      "检查订单是否重新回到发货状态",
      "检查优惠券是否被重复使用"
    ],
    params: ["order_id", "trade_no", "out_trade_no"],
    payloads: [],
    reportTemplate: {
      title: "取消订单后仍可支付漏洞",
      impact: "攻击者可取消订单后再支付，导致优惠券重复使用或以错误金额完成订单",
      fix: "建议在支付回调时校验订单当前状态，已取消的订单不应接受支付回调"
    }
  },
  {
    id: "biz-gift-tamper",
    category: "支付漏洞",
    name: "赠品/礼包参数篡改",
    severity: "high",
    description: "修改cartItems/gift参数中的赠品数量或类型",
    testSteps: [
      "找到包含赠品的下单接口",
      "抓包查看 cartItems / gift / subSku 等参数",
      "尝试修改赠品数量：{1002,1002,1002,1002}",
      "尝试修改赠品ID为高价值商品ID",
      "提交订单查看结果"
    ],
    params: ["cartItems", "gift", "subSku", "giftId", "bonus"],
    payloads: [],
    reportTemplate: {
      title: "赠品参数篡改漏洞",
      impact: "攻击者可自定义赠品类型和数量，获取非授权商品",
      fix: "建议在服务端固定赠品配置，不信任客户端传入的赠品参数"
    }
  },
  {
    id: "biz-invoice-duplicate",
    category: "支付漏洞",
    name: "发票重复开具",
    severity: "medium",
    description: "同一订单重复开发票，叠加金额",
    testSteps: [
      "找到开发票接口",
      "正常开一次发票",
      "重放开票请求（相同订单号）",
      "检查是否能开出多张发票"
    ],
    params: ["order_id", "invoice_amount", "invoice_type"],
    payloads: [],
    reportTemplate: {
      title: "发票重复开具漏洞",
      impact: "攻击者可对同一订单重复开具发票，导致企业税务风险",
      fix: "建议对开票接口做幂等性校验，同一订单只允许开具一次发票"
    }
  },

  // ============ 越权漏洞 ============
  {
    id: "idor-horizontal",
    category: "越权漏洞",
    name: "水平越权（IDOR）",
    severity: "high",
    description: "修改请求中的用户ID/订单ID，访问他人数据",
    testSteps: [
      "注册两个测试账号A和B",
      "用A账号操作，抓包获取请求中的ID参数",
      "将ID替换为B账号的ID",
      "检查是否能查看/修改B账号的数据",
      "重点关注：订单详情、个人资料、收货地址、消息记录"
    ],
    params: ["userId", "user_id", "uid", "orderId", "order_id", "id", "accountId"],
    payloads: ["遍历ID：+1, -1, 其他用户ID"],
    reportTemplate: {
      title: "水平越权访问漏洞",
      impact: "攻击者可通过修改ID参数，未授权访问其他用户的敏感数据",
      fix: "建议在服务端校验当前用户是否有权访问请求的资源"
    }
  },
  {
    id: "idor-vertical",
    category: "越权漏洞",
    name: "垂直越权",
    severity: "critical",
    description: "普通用户访问管理员接口",
    testSteps: [
      "用普通用户登录，获取Cookie/Token",
      "找到管理员功能的接口（通过JS源码、API文档等）",
      "用普通用户的凭证请求管理员接口",
      "检查是否能执行管理操作"
    ],
    params: ["role", "roleId", "isAdmin", "type", "level"],
    payloads: ["admin", "1", "true", "administrator", "0"],
    reportTemplate: {
      title: "垂直越权漏洞",
      impact: "普通用户可未授权执行管理员操作，可能导致数据泄露或系统被控制",
      fix: "建议在服务端对每个管理接口校验用户角色权限"
    }
  },

  // ============ 并发漏洞 ============
  {
    id: "race-condition",
    category: "并发漏洞",
    name: "竞态条件",
    severity: "high",
    description: "短时间内发送大量相同请求，绕过余额/次数限制",
    testSteps: [
      "找到有限制的操作（提现、领券、签到、点赞）",
      "抓取一次正常请求的数据包",
      "使用Fiddler的Shift+U同时发送多次请求（10-50次）",
      "检查是否多次成功（余额变化、券数量等）",
      "注意：如果有随机参数/时间戳，需要用拦截并发方式"
    ],
    params: ["amount", "coupon_id", "sign_date"],
    payloads: ["同一请求并发10-50次"],
    reportTemplate: {
      title: "并发竞态条件漏洞",
      impact: "攻击者利用并发请求绕过业务限制，重复领取优惠券/积分/余额",
      fix: "建议使用数据库锁或分布式锁，对关键操作做幂等性保护"
    }
  },
  {
    id: "race-different-amount",
    category: "并发漏洞",
    name: "不同金额并发",
    severity: "high",
    description: "并发多笔不同金额的提现请求绕过限制",
    testSteps: [
      "开启Fiddler拦截模式（左下角红色图标）",
      "在客户端发起多次不同金额的提现操作",
      "拦截到多个独立的请求包",
      "一次性放行所有拦截的请求",
      "检查是否全部成功提现"
    ],
    params: ["amount", "withdraw_amount"],
    payloads: ["1.00", "2.00", "3.00", "5.00", "10.00"],
    reportTemplate: {
      title: "多金额并发提现漏洞",
      impact: "攻击者通过不同金额的并发请求绕过余额校验，导致超额提现",
      fix: "建议对提现操作加锁，确保同一账户同时只有一笔提现在处理"
    }
  },

  // ============ 短信/验证码漏洞 ============
  {
    id: "sms-leak",
    category: "验证码漏洞",
    name: "验证码返回包泄露",
    severity: "critical",
    description: "发送验证码后，验证码出现在响应包中",
    testSteps: [
      "发送短信验证码",
      "查看响应包中是否包含验证码（code, captcha, sms_code）",
      "如果有，直接使用该验证码完成验证"
    ],
    params: ["phone", "mobile", "tel"],
    payloads: [],
    reportTemplate: {
      title: "短信验证码响应泄露漏洞",
      impact: "攻击者可直接从响应中获取验证码，绕过短信验证",
      fix: "建议验证码仅保存在服务端，不在响应中返回"
    }
  },
  {
    id: "sms-bomb",
    category: "验证码漏洞",
    name: "短信轰炸",
    severity: "medium",
    description: "注册/登录/重置/注销等功能的短信发送无频率限制",
    testSteps: [
      "找到发送短信的接口",
      "连续重放请求，检查是否有频率限制",
      "尝试修改手机号格式绕过：+86手机号、手机号前加空格",
      "检查注销功能是否也能发短信"
    ],
    params: ["phone", "mobile", "type"],
    payloads: ["+8613800000000", " 13800000000", "13800000000 "],
    reportTemplate: {
      title: "短信发送频率无限制漏洞",
      impact: "攻击者可利用该接口对任意手机号进行短信轰炸",
      fix: "建议对发送接口做频率限制（如60秒内只允许发送一次）"
    }
  },
  {
    id: "sms-code-bruteforce",
    category: "验证码漏洞",
    name: "短信验证码爆破",
    severity: "high",
    description: "4-6位验证码可被爆破",
    testSteps: [
      "发送验证码，获取验证接口",
      "使用Burp Intruder对验证码字段爆破（0000-9999或000000-999999）",
      "观察正确验证码时返回包的差异",
      "注意：检查是否有验证码过期时间和错误次数限制"
    ],
    params: ["code", "captcha", "sms_code", "verify_code"],
    payloads: ["4位数字：0000-9999", "6位数字：000000-999999"],
    reportTemplate: {
      title: "短信验证码可爆破漏洞",
      impact: "攻击者可通过爆破验证码登录任意用户账号或重置密码",
      fix: "建议增加验证码错误次数限制（如5次后锁定）和验证码过期时间（如5分钟）"
    }
  },
  {
    id: "sms-response-tamper",
    category: "验证码漏洞",
    name: "修改返回包绕过验证",
    severity: "high",
    description: "修改返回包中的false为true或-1为0绕过验证",
    testSteps: [
      "输入任意验证码提交",
      "拦截响应包",
      "将false改为true，或将-1改为0/1，或将fail改为success",
      "放行修改后的响应包",
      "检查是否绕过验证"
    ],
    params: ["code", "captcha"],
    payloads: ["true", "0", "1", "success", "ok"],
    reportTemplate: {
      title: "验证码校验可通过修改响应绕过",
      impact: "攻击者通过篡改响应包绕过验证码校验，可接管任意账号",
      fix: "建议验证逻辑完全在服务端实现，不依赖客户端对响应的判断"
    }
  },

  // ============ SSRF ============
  {
    id: "ssrf-image",
    category: "SSRF",
    name: "图片/URL加载SSRF",
    severity: "high",
    description: "用户可控URL的图片加载、链接预览等功能",
    testSteps: [
      "找到有URL输入的功能（头像URL、文章图片、链接预览）",
      "将URL改为内网地址（http://127.0.0.1:端口）",
      "尝试探测内网服务：Redis(6379)、MySQL(3306)等",
      "尝试访问云元数据：http://169.254.169.254/"
    ],
    params: ["url", "link", "src", "image_url", "avatar_url", "callback"],
    payloads: [
      "http://127.0.0.1:6379/",
      "http://127.0.0.1:3306/",
      "http://169.254.169.254/latest/meta-data/",
      "http://[::1]:80/",
      "file:///etc/passwd"
    ],
    reportTemplate: {
      title: "SSRF 服务端请求伪造漏洞",
      impact: "攻击者可利用该漏洞探测内网服务、读取云元数据，可能获取敏感信息",
      fix: "建议对URL进行白名单校验，禁止访问内网地址和特殊协议"
    }
  },

  // ============ 云安全 ============
  {
    id: "cloud-key-leak",
    category: "云安全",
    name: "云服务Key泄露",
    severity: "critical",
    description: "AccessKeyId/SecretKey泄露在源码、GitHub、JS文件中",
    testSteps: [
      "在GitHub搜索: 公司名 + accesskeyid",
      "查看前端JS文件中是否有AK/SK",
      "检查.env文件、配置文件是否暴露",
      "搜索常见鉴权字段: token, Cookie, Authorization, x-API-Key"
    ],
    params: ["AccessKeyId", "AccessKeySecret", "SecretKey", "API-Key"],
    payloads: [],
    reportTemplate: {
      title: "云服务AccessKey泄露漏洞",
      impact: "攻击者获取AccessKey后可控制云服务（对象存储、服务器等），导致数据泄露或资源滥用",
      fix: "建议立即轮换泄露的Key，使用环境变量管理敏感凭证，不在代码中硬编码"
    }
  },
  {
    id: "cloud-bucket-public",
    category: "云安全",
    name: "对象存储公开读写",
    severity: "critical",
    description: "OSS/S3 Bucket权限配置为公共读写",
    testSteps: [
      "找到目标使用的对象存储域名（xxx.oss-cn-xxx.aliyuncs.com）",
      "尝试列出Bucket内容：GET /",
      "尝试上传文件：PUT /test.txt",
      "检查是否存在敏感文件"
    ],
    params: [],
    payloads: [],
    reportTemplate: {
      title: "对象存储Bucket权限配置错误",
      impact: "公共读写权限导致任何人可上传恶意文件或下载敏感数据",
      fix: "建议将Bucket权限设置为私有，通过签名URL提供临时访问"
    }
  },

  // ============ 登录相关 ============
  {
    id: "auth-any-user-register",
    category: "登录漏洞",
    name: "任意用户注册/重置",
    severity: "critical",
    description: "注册或密码重置流程存在逻辑缺陷",
    testSteps: [
      "用A手机收验证码，注册时填写B手机号",
      "密码重置时修改手机号参数",
      "检查是否只验证了验证码没验证手机号",
      "检查第三方登录（微博等）的uid是否可被修改"
    ],
    params: ["phone", "mobile", "uid", "openid"],
    payloads: [],
    reportTemplate: {
      title: "任意用户账号注册/重置漏洞",
      impact: "攻击者可注册或重置任意用户账号，接管他人账户",
      fix: "建议在服务端将验证码与手机号绑定校验，不分离处理"
    }
  },
  {
    id: "auth-sql-login",
    category: "登录漏洞",
    name: "登录口SQL注入",
    severity: "critical",
    description: "登录接口存在SQL注入，可万能密码登录",
    testSteps: [
      "在用户名输入: admin' or '1'='1",
      "密码随便填",
      "检查是否能登录",
      "或使用 admin'-- 绕过密码"
    ],
    params: ["username", "user", "account", "password", "passwd"],
    payloads: ["admin' or '1'='1", "admin'--", "' or 1=1--", "admin' or '1'='1'--"],
    reportTemplate: {
      title: "登录接口SQL注入漏洞",
      impact: "攻击者可通过SQL注入绕过认证，登录任意账号或获取数据库数据",
      fix: "建议使用参数化查询，不拼接SQL语句"
    }
  }
];

// 获取所有漏洞模板
export function getSrcVulnTemplates() {
  return SRC_VULN_TEMPLATES.map((t) => ({ ...t }));
}

// 按分类获取
export function getTemplatesByCategory(category) {
  return SRC_VULN_TEMPLATES.filter((t) => t.category === category);
}

// 获取所有分类
export function getVulnCategories() {
  const categories = new Set(SRC_VULN_TEMPLATES.map((t) => t.category));
  return [...categories];
}

// 根据功能点推荐测试模板
export function recommendTemplates(featureType) {
  const featureMap = {
    "payment": ["biz-payment-negative", "biz-payment-overflow", "biz-payment-cancel-repay", "biz-gift-tamper", "biz-invoice-duplicate"],
    "login": ["auth-any-user-register", "auth-sql-login", "sms-leak", "sms-code-bruteforce", "sms-response-tamper"],
    "register": ["auth-any-user-register", "sms-leak", "sms-bomb", "sms-code-bruteforce"],
    "profile": ["idor-horizontal", "idor-vertical"],
    "upload": ["ssrf-image"],
    "order": ["idor-horizontal", "biz-payment-cancel-repay", "race-condition"],
    "coupon": ["race-condition", "race-different-amount"],
    "withdraw": ["race-condition", "race-different-amount"],
    "image": ["ssrf-image"],
    "api": ["idor-horizontal", "idor-vertical", "cloud-key-leak"],
    "sms": ["sms-leak", "sms-bomb", "sms-code-bruteforce", "sms-response-tamper"]
  };

  const ids = featureMap[featureType] || [];
  return SRC_VULN_TEMPLATES.filter((t) => ids.includes(t.id));
}

// 根据抓包参数推荐可能的漏洞
export function analyzeParams(params) {
  const suggestions = [];

  for (const param of params) {
    const lower = param.toLowerCase();

    // 价格/金额相关
    if (/price|amount|money|total|fee|cost|pay/.test(lower)) {
      suggestions.push({ param, templates: ["biz-payment-negative", "biz-payment-overflow"], reason: "金额参数可能可篡改" });
    }

    // 数量相关
    if (/qty|num|count|quantity/.test(lower)) {
      suggestions.push({ param, templates: ["biz-payment-negative", "biz-payment-overflow"], reason: "数量参数可能存在负数/溢出" });
    }

    // ID相关
    if (/id|uid|user_id|order_id|account/.test(lower)) {
      suggestions.push({ param, templates: ["idor-horizontal", "idor-vertical"], reason: "ID参数可能存在越权" });
    }

    // 验证码相关
    if (/code|captcha|sms|verify/.test(lower)) {
      suggestions.push({ param, templates: ["sms-leak", "sms-code-bruteforce", "sms-response-tamper"], reason: "验证码可能可绕过" });
    }

    // URL相关
    if (/url|link|src|href|callback|redirect/.test(lower)) {
      suggestions.push({ param, templates: ["ssrf-image"], reason: "URL参数可能存在SSRF" });
    }

    // 手机号相关
    if (/phone|mobile|tel/.test(lower)) {
      suggestions.push({ param, templates: ["sms-bomb", "auth-any-user-register"], reason: "手机号参数可测试短信轰炸/任意用户" });
    }
  }

  return suggestions;
}
