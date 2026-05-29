/**
 * SRC 目标管理模块
 * 管理授权的 SRC 平台、域名列表、资产搜集逻辑
 */
import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_SRC_PLATFORMS = [
  {
    id: "butian",
    name: "补天 SRC",
    url: "https://www.butian.net",
    type: "public",
    description: "补天漏洞响应平台，支持公益SRC和企业SRC",
    notes: "专属SRC可以挖gov类"
  },
  {
    id: "vulbox",
    name: "漏洞盒子",
    url: "https://www.vulbox.com",
    type: "public",
    description: "漏洞盒子众测平台，金融类养号",
    notes: "金融项目需要养号"
  },
  {
    id: "huoxian",
    name: "火线平台",
    url: "https://www.huoxian.cn",
    type: "public",
    description: "火线安全平台",
    notes: "比较卷"
  },
  {
    id: "bytedance",
    name: "字节跳动 SRC",
    url: "https://security.bytedance.com",
    type: "enterprise",
    description: "字节跳动安全响应中心，资产多更新快",
    notes: "赏金高，资产多"
  },
  {
    id: "meituan",
    name: "美团 SRC",
    url: "https://security.meituan.com",
    type: "enterprise",
    description: "美团安全响应中心",
    notes: "赏金高，业务复杂"
  },
  {
    id: "bilibili",
    name: "B站 SRC",
    url: "https://security.bilibili.com",
    type: "enterprise",
    description: "哔哩哔哩安全应急响应中心",
    notes: "业务功能多，适合逻辑漏洞"
  },
  {
    id: "alibaba",
    name: "阿里巴巴 SRC",
    url: "https://security.alibaba.com",
    type: "enterprise",
    description: "阿里巴巴安全响应中心",
    notes: "电商业务，支付逻辑漏洞"
  },
  {
    id: "tencent",
    name: "腾讯 SRC",
    url: "https://security.tencent.com",
    type: "enterprise",
    description: "腾讯安全应急响应中心",
    notes: "社交+游戏+支付"
  }
];

export function createSrcTargetManager({ filePath }) {
  let data = null;

  async function ensureDir() {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
  }

  async function read() {
    if (data) return data;
    try {
      const raw = await fs.readFile(filePath, "utf8");
      data = JSON.parse(raw);
    } catch {
      data = {
        platforms: DEFAULT_SRC_PLATFORMS,
        targets: [],
        assets: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
    }
    return data;
  }

  async function write(newData) {
    await ensureDir();
    data = { ...newData, updatedAt: new Date().toISOString() };
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
    return data;
  }

  // 添加 SRC 目标（授权域名）
  async function addTarget(target) {
    const current = await read();
    const id = `src-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const newTarget = {
      id,
      platformId: target.platformId || "custom",
      company: target.company || "",
      rootDomain: target.rootDomain || "",
      subdomains: target.subdomains || [],
      authorized: target.authorized || false,
      authorizedAt: target.authorized ? new Date().toISOString() : null,
      scope: target.scope || "web",
      notes: target.notes || "",
      status: "active",
      createdAt: new Date().toISOString(),
      findings: []
    };
    current.targets.push(newTarget);
    await write(current);
    return newTarget;
  }

  // 删除目标
  async function removeTarget(targetId) {
    const current = await read();
    current.targets = current.targets.filter((t) => t.id !== targetId);
    await write(current);
    return { success: true };
  }

  // 更新目标状态
  async function updateTarget(targetId, updates) {
    const current = await read();
    const index = current.targets.findIndex((t) => t.id === targetId);
    if (index === -1) throw new Error("Target not found");
    current.targets[index] = { ...current.targets[index], ...updates };
    await write(current);
    return current.targets[index];
  }

  // 添加资产（子域名、IP等）
  async function addAsset(asset) {
    const current = await read();
    const id = `asset-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const newAsset = {
      id,
      targetId: asset.targetId || "",
      type: asset.type || "subdomain", // subdomain, ip, app, miniprogram
      value: asset.value || "",
      source: asset.source || "manual", // manual, fofa, subfinder, dns
      status: asset.status || "alive",
      technology: asset.technology || [],
      ports: asset.ports || [],
      notes: asset.notes || "",
      discoveredAt: new Date().toISOString()
    };
    current.assets.push(newAsset);
    await write(current);
    return newAsset;
  }

  // 批量添加资产
  async function addAssets(assets) {
    const current = await read();
    const results = [];
    for (const asset of assets) {
      const id = `asset-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const newAsset = {
        id,
        targetId: asset.targetId || "",
        type: asset.type || "subdomain",
        value: asset.value || "",
        source: asset.source || "manual",
        status: asset.status || "alive",
        technology: asset.technology || [],
        ports: asset.ports || [],
        notes: asset.notes || "",
        discoveredAt: new Date().toISOString()
      };
      current.assets.push(newAsset);
      results.push(newAsset);
    }
    await write(current);
    return results;
  }

  // 获取目标的所有资产
  function getTargetAssets(targetId) {
    if (!data) return [];
    return data.assets.filter((a) => a.targetId === targetId);
  }

  // 企查查/天眼查式的股权穿透逻辑（模拟）
  function analyzeCompanyAssets(companyName) {
    return {
      company: companyName,
      tips: [
        `在企查查搜索"${companyName}"，查看股权穿透图`,
        "占股超过51%的子公司算作本公司资产",
        "查看知识产权：备案网站、APP、小程序、公众号、软件著作权",
        "搜集所有根域名，再枚举子域名",
        `使用 FOFA: domain="${companyName相关域名}" && (title="管理" || title="后台")`,
        "七麦数据(qimai.cn)搜索公司旗下APP"
      ],
      searchEngines: [
        { name: "企查查", url: `https://www.qcc.com/web/search?key=${encodeURIComponent(companyName)}` },
        { name: "天眼查", url: `https://www.tianyancha.com/search?key=${encodeURIComponent(companyName)}` },
        { name: "小蓝本", url: `https://sou.xiaolanben.com/` },
        { name: "七麦数据", url: `https://www.qimai.cn/` }
      ]
    };
  }

  return {
    read,
    write,
    addTarget,
    removeTarget,
    updateTarget,
    addAsset,
    addAssets,
    getTargetAssets,
    analyzeCompanyAssets,
    DEFAULT_SRC_PLATFORMS
  };
}
