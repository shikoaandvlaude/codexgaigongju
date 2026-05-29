/**
 * 红线提醒系统
 * 校验操作是否违反 SRC 规则，防止踩红线
 */

// SRC 红线规则
const RED_LINES = [
  {
    id: "no-auto-scan",
    level: "critical",
    rule: "不要使用自动化扫描工具对实名SRC目标扫描",
    description: "实名情况下不要用sqlmap/awvs/nessus/dirsearch批量跑，WAF会记录IP+账号追溯到人。SQL注入让AI手工构造payload。",
    keywords: ["sqlmap", "自动扫描", "批量扫描", "awvs扫描", "nessus", "批量注入"],
    suggestion: "手动测试。SQL注入让Claude Code帮你手工构造union/盲注payload，一次一个请求，流量可控。"
  },
  {
    id: "no-crash-service",
    level: "critical",
    rule: "不要把目标网站打崩",
    description: "挖洞过程中不要影响在线业务，SRC公告里有明确红线",
    keywords: ["ddos", "压测", "并发过大", "打崩", "服务不可用"],
    suggestion: "并发测试控制在合理范围（10-50次），不要对生产环境做压力测试"
  },
  {
    id: "no-real-user-data",
    level: "critical",
    rule: "不要涉及线上真实用户数据",
    description: "最多用2个自己注册的账号验证漏洞，不接触真实用户数据",
    keywords: ["用户数据", "真实用户", "批量获取", "拖库"],
    suggestion: "只使用自己注册的测试账号，数据库漏洞只读取2-3行验证即可"
  },
  {
    id: "no-online-xss-platform",
    level: "high",
    rule: "不要使用在线XSS平台",
    description: "如果有人使用同款XSS平台被抓获，你也会被牵连",
    keywords: ["xss平台", "在线xss", "xss.io", "xsshunter"],
    suggestion: "自己搭建XSS接收平台，或者使用截图方式证明"
  },
  {
    id: "no-unauthorized",
    level: "critical",
    rule: "没有授权的目标不要碰",
    description: "只在有SRC授权的范围内测试",
    keywords: ["未授权", "没有src", "非授权目标"],
    suggestion: "确认目标在SRC授权范围内再测试"
  },
  {
    id: "no-gambling-site",
    level: "critical",
    rule: "BC站不要碰",
    description: "实名情况下不要测试博彩相关网站",
    keywords: ["bc站", "博彩", "赌博", "菠菜"],
    suggestion: "远离任何博彩相关目标"
  },
  {
    id: "no-intel-vuln",
    level: "high",
    rule: "情报漏洞不要做",
    description: "不做截图举报类情报漏洞（删差评、外挂销售等）",
    keywords: ["情报", "举报", "删差评", "外挂", "内鬼"],
    suggestion: "只提交技术漏洞，不做情报类提交"
  },
  {
    id: "careful-public-src",
    level: "medium",
    rule: "公益SRC谨慎参与",
    description: "某些公益SRC顺着排行榜抓人",
    keywords: ["公益src", "免费src"],
    suggestion: "优先选择有赏金的企业SRC"
  },
  {
    id: "db-read-only",
    level: "high",
    rule: "数据库漏洞只读取少量数据验证",
    description: "SQL注入等漏洞只需要读取2-3行数据证明即可",
    keywords: ["数据库", "sql注入", "读取数据"],
    suggestion: "只读取2-3行数据证明漏洞存在，不要大量获取数据"
  },
  {
    id: "max-two-accounts",
    level: "medium",
    rule: "最多使用2个测试账号",
    description: "验证越权等漏洞时，只允许使用2个自己注册的账号",
    keywords: ["多账号", "测试账号"],
    suggestion: "注册2个账号用于验证越权漏洞，不使用他人账号"
  }
];

// 操作风险评估
const RISK_ACTIONS = {
  "sql-injection": {
    level: "high",
    warnings: [
      "只读取2-3行数据验证漏洞存在",
      "不要使用sqlmap等自动化工具（实名情况下）",
      "不要尝试写入数据或提权"
    ]
  },
  "xss": {
    level: "medium",
    warnings: [
      "不使用在线XSS平台",
      "使用alert(1)或截图方式证明即可",
      "不要对真实用户触发XSS"
    ]
  },
  "file-upload": {
    level: "high",
    warnings: [
      "上传测试文件即可，不要上传真实webshell",
      "测试完成后清理上传的文件",
      "不要尝试获取服务器权限"
    ]
  },
  "concurrent": {
    level: "medium",
    warnings: [
      "并发次数控制在10-50次",
      "不要大量并发导致服务不可用",
      "测试成功后立即停止"
    ]
  },
  "payment": {
    level: "high",
    warnings: [
      "选择便宜的商品测试",
      "创建订单后先不要支付",
      "成功后立即取消订单",
      "录制全过程视频",
      "不要对平台造成实际经济损失"
    ]
  },
  "idor": {
    level: "medium",
    warnings: [
      "只使用自己注册的2个账号互相验证",
      "不要访问真实用户的数据",
      "证明存在即可，不需要大量遍历"
    ]
  },
  "ssrf": {
    level: "high",
    warnings: [
      "探测即可，不要深入利用",
      "不要访问或修改内网敏感服务",
      "使用无害的探测地址"
    ]
  }
};

export function createRedLineGuard() {

  // 检查操作是否触犯红线
  function checkRedLines(actionDescription) {
    const violations = [];
    const lower = actionDescription.toLowerCase();

    for (const rule of RED_LINES) {
      for (const keyword of rule.keywords) {
        if (lower.includes(keyword.toLowerCase())) {
          violations.push({
            ruleId: rule.id,
            level: rule.level,
            rule: rule.rule,
            description: rule.description,
            suggestion: rule.suggestion,
            triggeredBy: keyword
          });
          break;
        }
      }
    }

    return {
      safe: violations.length === 0,
      violations,
      criticalCount: violations.filter((v) => v.level === "critical").length,
      highCount: violations.filter((v) => v.level === "high").length
    };
  }

  // 获取操作类型的风险提示
  function getRiskWarnings(actionType) {
    const risk = RISK_ACTIONS[actionType];
    if (!risk) {
      return {
        level: "info",
        warnings: ["注意在授权范围内测试"]
      };
    }
    return risk;
  }

  // 获取全部红线规则
  function getAllRedLines() {
    return RED_LINES.map((r) => ({ ...r }));
  }

  // 生成安全检查清单（开始测试前）
  function generateSafetyChecklist(target) {
    return {
      target,
      generatedAt: new Date().toISOString(),
      checklist: [
        { item: "确认目标在SRC授权范围内", checked: false, level: "critical" },
        { item: "已注册SRC平台并签署协议", checked: false, level: "critical" },
        { item: "准备好2个测试账号", checked: false, level: "high" },
        { item: "录屏工具已开启", checked: false, level: "medium" },
        { item: "了解该SRC的红线和规则", checked: false, level: "high" },
        { item: "不使用自动化扫描工具", checked: false, level: "high" },
        { item: "Fiddler/Burp已配置好", checked: false, level: "medium" },
        { item: "测试环境网络正常", checked: false, level: "low" }
      ]
    };
  }

  // 测试完成后的收尾检查
  function generateCleanupChecklist(target) {
    return {
      target,
      generatedAt: new Date().toISOString(),
      checklist: [
        { item: "已取消所有测试订单", checked: false },
        { item: "已清理上传的测试文件", checked: false },
        { item: "未对真实用户造成影响", checked: false },
        { item: "录屏已保存", checked: false },
        { item: "测试数据已整理", checked: false },
        { item: "漏洞报告已准备好", checked: false }
      ]
    };
  }

  return {
    checkRedLines,
    getRiskWarnings,
    getAllRedLines,
    generateSafetyChecklist,
    generateCleanupChecklist,
    RED_LINES,
    RISK_ACTIONS
  };
}
