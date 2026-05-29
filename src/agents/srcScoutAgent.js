/**
 * SRC Scout Agent
 * 整合目标管理、信息搜集、漏洞模板、红线提醒的统一代理
 */
import { createSrcTargetManager } from "../services/srcTargetManager.js";
import { createReconService } from "../services/reconService.js";
import { createRedLineGuard } from "../services/redLineGuard.js";
import {
  getSrcVulnTemplates,
  getTemplatesByCategory,
  getVulnCategories,
  recommendTemplates,
  analyzeParams
} from "../config/srcVulnTemplates.js";

export class SrcScoutAgent {
  constructor({ targetFilePath }) {
    this.targetManager = createSrcTargetManager({ filePath: targetFilePath });
    this.reconService = createReconService();
    this.redLineGuard = createRedLineGuard();
  }

  // ============ 目标管理 ============

  async getTargets() {
    const data = await this.targetManager.read();
    return data.targets || [];
  }

  async getPlatforms() {
    const data = await this.targetManager.read();
    return data.platforms || [];
  }

  async addTarget(target) {
    // 添加前做红线检查
    if (!target.authorized) {
      return {
        success: false,
        error: "红线警告：目标未授权，请先确认在SRC授权范围内",
        redLine: true
      };
    }
    return await this.targetManager.addTarget(target);
  }

  async removeTarget(targetId) {
    return await this.targetManager.removeTarget(targetId);
  }

  async updateTarget(targetId, updates) {
    return await this.targetManager.updateTarget(targetId, updates);
  }

  // ============ 资产管理 ============

  async addAsset(asset) {
    return await this.targetManager.addAsset(asset);
  }

  async addAssets(assets) {
    return await this.targetManager.addAssets(assets);
  }

  async getTargetAssets(targetId) {
    await this.targetManager.read();
    return this.targetManager.getTargetAssets(targetId);
  }

  // ============ 信息搜集 ============

  generateReconPlan(domain) {
    return this.reconService.generateReconPlan(domain);
  }

  getSearchDorks(engine, domain) {
    return this.reconService.getSearchDorks(engine, domain);
  }

  decodeF5Ltm(cookieValue) {
    return this.reconService.decodeF5Ltm(cookieValue);
  }

  getPortInfo(port) {
    return this.reconService.getPortInfo(port);
  }

  getDefaultCredentials(service) {
    return this.reconService.getDefaultCredentials(service);
  }

  getAllDefaultCredentials() {
    return this.reconService.getAllDefaultCredentials();
  }

  analyzeCompanyAssets(companyName) {
    return this.targetManager.analyzeCompanyAssets(companyName);
  }

  // ============ 漏洞模板 ============

  getVulnTemplates() {
    return getSrcVulnTemplates();
  }

  getTemplatesByCategory(category) {
    return getTemplatesByCategory(category);
  }

  getVulnCategories() {
    return getVulnCategories();
  }

  recommendTemplates(featureType) {
    return recommendTemplates(featureType);
  }

  analyzeParams(params) {
    return analyzeParams(params);
  }

  // ============ 红线系统 ============

  checkRedLines(action) {
    return this.redLineGuard.checkRedLines(action);
  }

  getRiskWarnings(actionType) {
    return this.redLineGuard.getRiskWarnings(actionType);
  }

  getAllRedLines() {
    return this.redLineGuard.getAllRedLines();
  }

  generateSafetyChecklist(target) {
    return this.redLineGuard.generateSafetyChecklist(target);
  }

  generateCleanupChecklist(target) {
    return this.redLineGuard.generateCleanupChecklist(target);
  }

  // ============ 综合功能 ============

  // 开始一个新的 SRC 任务
  async startHunt({ target, featureType, params }) {
    const result = {
      target,
      startedAt: new Date().toISOString(),
      safetyChecklist: this.redLineGuard.generateSafetyChecklist(target.rootDomain || target.company),
      reconPlan: null,
      suggestedTemplates: [],
      paramAnalysis: [],
      riskWarnings: []
    };

    // 生成信息搜集计划
    if (target.rootDomain) {
      result.reconPlan = this.reconService.generateReconPlan(target.rootDomain);
    }

    // 推荐漏洞测试模板
    if (featureType) {
      result.suggestedTemplates = recommendTemplates(featureType);
    }

    // 分析参数
    if (params && params.length) {
      result.paramAnalysis = analyzeParams(params);
    }

    return result;
  }

  // 功能点分析：给一个 URL/功能描述，返回测试建议
  analyzeFunctionPoint(description) {
    const lower = description.toLowerCase();
    const suggestions = [];

    const featureKeywords = {
      payment: ["支付", "付款", "结算", "订单", "购买", "充值", "pay", "order", "checkout"],
      login: ["登录", "登入", "login", "signin", "sign in"],
      register: ["注册", "register", "signup", "sign up"],
      upload: ["上传", "upload", "文件", "图片", "头像"],
      sms: ["短信", "验证码", "手机", "sms", "captcha", "code"],
      profile: ["个人", "资料", "信息", "profile", "account"],
      order: ["订单", "order", "购物车", "cart"],
      coupon: ["优惠券", "红包", "积分", "coupon", "point", "bonus"],
      withdraw: ["提现", "取款", "withdraw", "转账", "transfer"],
      image: ["图片", "image", "url", "链接", "预览"],
      api: ["接口", "api", "后台", "管理", "admin"]
    };

    for (const [feature, keywords] of Object.entries(featureKeywords)) {
      if (keywords.some((k) => lower.includes(k))) {
        const templates = recommendTemplates(feature);
        if (templates.length) {
          suggestions.push({
            feature,
            templates,
            riskWarnings: this.redLineGuard.getRiskWarnings(
              feature === "payment" ? "payment" :
              feature === "login" || feature === "register" ? "sql-injection" :
              feature === "upload" ? "file-upload" :
              feature === "coupon" || feature === "withdraw" ? "concurrent" :
              feature === "image" ? "ssrf" :
              "idor"
            )
          });
        }
      }
    }

    return {
      description,
      analyzedAt: new Date().toISOString(),
      suggestions,
      generalTips: [
        "先确认目标在SRC授权范围内",
        "用Fiddler/Burp抓包，分析前后端交互",
        "区分前端校验和后端校验",
        "关注所有可修改的参数",
        "测试成功后立即录视频保存证据"
      ]
    };
  }
}
