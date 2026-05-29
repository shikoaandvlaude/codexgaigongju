/**
 * 信息搜集服务模块
 * 子域名枚举、CDN检测、端口扫描调度、指纹识别
 * 注意：这是辅助模块，不主动对未授权目标发起扫描
 */

// 常见端口及对应服务
const COMMON_PORTS = {
  21: { service: "FTP", attack: "爆破/匿名登录", risk: "high" },
  22: { service: "SSH", attack: "爆破", risk: "medium" },
  23: { service: "Telnet", attack: "爆破（九头蛇）", risk: "high" },
  25: { service: "SMTP", attack: "钓鱼邮件", risk: "medium" },
  53: { service: "DNS", attack: "域名解析", risk: "low" },
  80: { service: "HTTP", attack: "Web漏洞", risk: "medium" },
  110: { service: "POP3", attack: "邮件服务", risk: "low" },
  135: { service: "RPC", attack: "永恒之蓝（配合445）", risk: "high" },
  443: { service: "HTTPS", attack: "Web漏洞/SSL证书", risk: "medium" },
  445: { service: "SMB", attack: "永恒之蓝", risk: "critical" },
  873: { service: "Rsync", attack: "未授权访问", risk: "high" },
  1433: { service: "MSSQL", attack: "爆破", risk: "high" },
  2375: { service: "Docker API", attack: "Docker逃逸", risk: "critical" },
  2376: { service: "Docker TLS", attack: "Docker逃逸", risk: "critical" },
  3000: { service: "Grafana", attack: "默认口令 admin/admin", risk: "high" },
  3306: { service: "MySQL", attack: "默认口令爆破", risk: "high" },
  3389: { service: "RDP", attack: "远程登录爆破", risk: "high" },
  6379: { service: "Redis", attack: "未授权访问", risk: "critical" },
  8080: { service: "Tomcat", attack: "默认口令/Manager", risk: "high" },
  8443: { service: "HTTPS-ALT", attack: "Web漏洞", risk: "medium" },
  9200: { service: "Elasticsearch", attack: "未授权访问", risk: "critical" },
  27017: { service: "MongoDB", attack: "未授权/爆破", risk: "critical" },
  27018: { service: "MongoDB", attack: "未授权/爆破", risk: "critical" }
};

// 常见默认口令
const DEFAULT_CREDENTIALS = {
  "k8s": { user: "admin", pass: "P@88w0rd" },
  "zabbix": { user: "admin", pass: "zabbix" },
  "grafana": { user: "admin", pass: "admin" },
  "nacos": { user: "nacos", pass: "nacos" },
  "tomcat": { user: "tomcat", pass: "tomcat" },
  "activemq": { user: "admin", pass: "admin" },
  "weblogic": { user: "weblogic", pass: "weblogic" },
  "rabbitmq": { user: "admin", pass: "guest" },
  "druid": { user: "admin", pass: "123456" },
  "ruoyi": { user: "admin", pass: "admin123" }
};

// CDN 检测思路
const CDN_BYPASS_METHODS = [
  { id: "dns-history", name: "DNS历史记录", description: "查看网站未用CDN时的IP", tools: ["netcraft", "viewdns.info", "dnsdb.io"] },
  { id: "subdomain", name: "子域名探测", description: "子域名可能未挂CDN，ping子域名获取真实IP", tools: ["subfinder", "oneforall"] },
  { id: "email", name: "邮件回信", description: "诱导主站发邮件，查看邮件原文中的真实IP", tools: ["smtp"] },
  { id: "foreign-ping", name: "国外Ping", description: "CDN有防御范围，用国外服务器ping", tools: ["ping.chinaz.com", "ping.pe"] },
  { id: "ssl-cert", name: "SSL证书查找", description: "通过证书hash反查IP", tools: ["crt.sh", "censys.io"] },
  { id: "app-traffic", name: "APP/小程序抓包", description: "APP可能未挂CDN，抓包获取真实IP", tools: ["burp", "charles", "fiddler"] },
  { id: "phpinfo", name: "phpinfo泄露", description: "phpinfo页面可能暴露真实IP", tools: [] },
  { id: "c-segment", name: "C段扫描", description: "同机房服务器内网渗透", tools: ["nmap"] },
  { id: "f5-ltm", name: "F5 LTM解码", description: "通过Set-Cookie中BIGip字段解码真实IP", tools: [] },
  { id: "global-ping", name: "全球Ping", description: "全球各地ping查看IP是否一致", tools: ["ping.chinaz.com"] }
];

// 文件泄露检测路径
const FILE_LEAK_PATHS = [
  // 备份文件
  { path: "/data.zip", type: "backup", risk: "critical" },
  { path: "/data.rar", type: "backup", risk: "critical" },
  { path: "/data.tar.gz", type: "backup", risk: "critical" },
  { path: "/backup.zip", type: "backup", risk: "critical" },
  { path: "/backup.sql", type: "database", risk: "critical" },
  { path: "/db.sql", type: "database", risk: "critical" },
  { path: "/database.sql", type: "database", risk: "critical" },
  // 代码备份
  { path: "/index.php.bak", type: "source", risk: "high" },
  { path: "/index.phps", type: "source", risk: "high" },
  { path: "/index.php.swp", type: "source", risk: "high" },
  { path: "/.index.php.swp", type: "source", risk: "high" },
  // 版本控制
  { path: "/.git/config", type: "git", risk: "critical" },
  { path: "/.svn/entries", type: "svn", risk: "critical" },
  { path: "/.DS_Store", type: "dsstore", risk: "medium" },
  { path: "/.hg/", type: "hg", risk: "high" },
  // 配置文件
  { path: "/robots.txt", type: "config", risk: "info" },
  { path: "/sitemap.xml", type: "config", risk: "info" },
  { path: "/.env", type: "env", risk: "critical" },
  { path: "/config.php.bak", type: "config", risk: "critical" },
  { path: "/wp-config.php.bak", type: "config", risk: "critical" },
  // 安装目录
  { path: "/install/", type: "install", risk: "high" },
  { path: "/install.php", type: "install", risk: "high" },
  { path: "/install/index.php", type: "install", risk: "high" }
];

// 搜索引擎语法模板
const SEARCH_DORKS = {
  google: {
    login: (domain) => `inurl:login site:${domain}`,
    admin: (domain) => `intitle:管理 OR intitle:后台 site:${domain}`,
    register: (domain) => `inurl:register site:${domain}`,
    sql: (domain) => `site:${domain} inurl:"id="`,
    filetype: (domain, type) => `site:${domain} filetype:${type}`,
    sensitive: (domain) => `site:${domain} "手机号" OR "身份证" OR "密码"`,
    error: (domain) => `site:${domain} "mysql error" OR "warning" OR "fatal error"`,
    upload: (domain) => `site:${domain} inurl:upload OR inurl:file`
  },
  fofa: {
    domain: (domain) => `domain="${domain}"`,
    admin: (domain) => `domain="${domain}" && (title="管理" || title="后台" || title="平台")`,
    api: (domain) => `domain="${domain}" && (title="swagger" || body="api-docs")`,
    login: (domain) => `domain="${domain}" && body="password"`,
    stats: (domain) => `body="<!--统计代码，可删除-->" && domain="${domain}"`,
    cert: (domain) => `cert="${domain}"`
  },
  zoomeye: {
    app: (app) => `app:"${app}"`,
    port: (port) => `port:${port}`,
    service: (svc, os) => `service:${svc} os:${os}`,
    country: (country) => `country:"${country}"`
  }
};

// 子域名枚举相关工具和在线服务
const SUBDOMAIN_TOOLS = [
  { name: "SecurityTrails", url: (domain) => `https://securitytrails.com/list/apex_domain/${domain}` },
  { name: "站长工具", url: (domain) => `https://tool.chinaz.com/subdomain/${domain}` },
  { name: "phpinfo.me", url: (domain) => `https://phpinfo.me/domain/${domain}` },
  { name: "crt.sh", url: (domain) => `https://crt.sh/?q=%25.${domain}` },
  { name: "DNSDumpster", url: (domain) => `https://dnsdumpster.com/` },
  { name: "VirusTotal", url: (domain) => `https://www.virustotal.com/gui/domain/${domain}/relations` }
];

// DNS 历史查询服务
const DNS_HISTORY_TOOLS = [
  { name: "Netcraft", url: "https://toolbar.netcraft.com/site_report" },
  { name: "ViewDNS", url: "http://viewdns.info/iphistory/" },
  { name: "DNSHistory", url: "https://dnshistory.org/" },
  { name: "CompleteDNS", url: "https://completedns.com/dns-history/" },
  { name: "微步在线", url: "https://x.threatbook.cn/" },
  { name: "DNSDB", url: "https://dnsdb.io/zh-cn/" }
];

export function createReconService() {

  // 生成目标的信息搜集计划
  function generateReconPlan(domain, options = {}) {
    const plan = {
      domain,
      generatedAt: new Date().toISOString(),
      steps: []
    };

    // Step 1: 基础信息
    plan.steps.push({
      order: 1,
      name: "基础信息搜集",
      description: "确定目标基本信息",
      tasks: [
        { task: "Ping域名确定IP", command: `ping ${domain}` },
        { task: "查看robots.txt", url: `https://${domain}/robots.txt` },
        { task: "Whois查询", url: `https://whois.chinaz.com/${domain}` },
        { task: "ICP备案查询", url: `https://beian.miit.gov.cn/` }
      ]
    });

    // Step 2: 子域名枚举
    plan.steps.push({
      order: 2,
      name: "子域名枚举",
      description: "发现目标的子域名资产",
      tasks: SUBDOMAIN_TOOLS.map((tool) => ({
        task: `${tool.name} 查询`,
        url: tool.url(domain)
      })),
      commands: [
        `subfinder -d ${domain} -o subdomains.txt`,
        `httpx -l subdomains.txt -o alive.txt`
      ]
    });

    // Step 3: CDN检测
    plan.steps.push({
      order: 3,
      name: "CDN检测与绕过",
      description: "判断是否有CDN，尝试获取真实IP",
      methods: CDN_BYPASS_METHODS,
      tools: [
        { task: "多地Ping", url: "https://ping.chinaz.com/" },
        { task: "CDN检测", url: `https://cdn.chinaz.com/${domain}` }
      ]
    });

    // Step 4: 端口扫描
    plan.steps.push({
      order: 4,
      name: "端口扫描",
      description: "扫描开放端口，识别服务",
      commands: [
        `nmap -sT -T4 -p 21,22,23,25,53,80,110,135,443,445,873,1433,2375,3000,3306,3389,6379,8080,8443,9200,27017 [IP]`,
        `nmap -sV -p- -T4 [IP]`
      ],
      portReference: COMMON_PORTS
    });

    // Step 5: 文件泄露检测
    plan.steps.push({
      order: 5,
      name: "文件泄露检测",
      description: "检测常见的文件泄露路径",
      paths: FILE_LEAK_PATHS.map((p) => ({
        ...p,
        fullUrl: `https://${domain}${p.path}`
      }))
    });

    // Step 6: 搜索引擎语法
    plan.steps.push({
      order: 6,
      name: "搜索引擎信息搜集",
      description: "利用搜索引擎语法搜集信息",
      google: Object.entries(SEARCH_DORKS.google).map(([key, fn]) => ({
        name: key,
        query: fn(domain)
      })),
      fofa: Object.entries(SEARCH_DORKS.fofa).map(([key, fn]) => ({
        name: key,
        query: fn(domain)
      }))
    });

    // Step 7: 指纹识别
    plan.steps.push({
      order: 7,
      name: "指纹识别",
      description: "识别网站框架、CMS、中间件",
      commands: [
        `whatweb https://${domain}`,
        `wafw00f https://${domain}`
      ],
      manualChecks: [
        "查看响应头 Server / X-Powered-By",
        "查看页面源码中的框架特征",
        "查看 /favicon.ico hash",
        "尝试访问 index.php / index.asp / index.jsp 判断语言"
      ]
    });

    return plan;
  }

  // F5 LTM 解码
  function decodeF5Ltm(cookieValue) {
    // 例：487098378.24095.0000
    const match = cookieValue.match(/(\d+)\.\d+\.\d+/);
    if (!match) return null;

    const decimal = parseInt(match[1], 10);
    const hex = decimal.toString(16).padStart(8, "0");
    // 从后往前每两位
    const octets = [];
    for (let i = hex.length - 2; i >= 0; i -= 2) {
      octets.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return octets.join(".");
  }

  // 获取搜索语法
  function getSearchDorks(engine, domain) {
    const dorkSet = SEARCH_DORKS[engine];
    if (!dorkSet) return [];
    return Object.entries(dorkSet).map(([key, fn]) => ({
      name: key,
      query: typeof fn === "function" ? fn(domain) : fn
    }));
  }

  // 获取端口信息
  function getPortInfo(port) {
    return COMMON_PORTS[port] || { service: "Unknown", attack: "未知", risk: "low" };
  }

  // 获取默认口令
  function getDefaultCredentials(service) {
    return DEFAULT_CREDENTIALS[service.toLowerCase()] || null;
  }

  // 获取所有默认口令
  function getAllDefaultCredentials() {
    return { ...DEFAULT_CREDENTIALS };
  }

  return {
    generateReconPlan,
    decodeF5Ltm,
    getSearchDorks,
    getPortInfo,
    getDefaultCredentials,
    getAllDefaultCredentials,
    COMMON_PORTS,
    CDN_BYPASS_METHODS,
    FILE_LEAK_PATHS,
    SEARCH_DORKS,
    SUBDOMAIN_TOOLS,
    DNS_HISTORY_TOOLS
  };
}
