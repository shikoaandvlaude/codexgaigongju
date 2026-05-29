const FOFA_API_BASE = "https://api.fofa.com/v1";
const MAX_RESULTS = 30;

export class FofaScoutAgent {
  constructor({ getFofaConfig }) {
    this.getFofaConfig = getFofaConfig || (() => ({}));
  }

  async run({ query, size = 20 }) {
    const config = await this.getFofaConfig();
    if (!config.apiKey) {
      return {
        status: "skipped",
        skipReason: "no-api-key",
        message: "未配置 FOFA API Key，请先在设置中心填写 FOFA email 和 API Key。",
        projects: []
      };
    }

    try {
      const results = await this.searchAssets(query, config, Math.min(size || MAX_RESULTS, MAX_RESULTS));
      return {
        status: "completed",
        source: "fofa",
        query,
        discoveredAt: new Date().toISOString(),
        message: `FOFA 资产检索发现 ${results.length} 条结果。`,
        projects: results
      };
    } catch (error) {
      return {
        status: "error",
        skipReason: "api-error",
        message: `FOFA API 调用失败：${error instanceof Error ? error.message : String(error)}`,
        projects: []
      };
    }
  }

  async searchAssets(query, config, limit) {
    const email = config.email;
    const apiKey = config.apiKey;
    const q = this.buildQuery(query);

    const encoded = btoa(`${email}:${apiKey}`);
    const response = await fetch(`${FOFA_API_BASE}/search/all?size=${limit}&qbase64=${encodeURIComponent(q)}`, {
      headers: {
        Authorization: `Basic ${encoded}`,
        Accept: "application/json"
      }
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`FOFA 返回 ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    return this.normalizeResults(data);
  }

  buildQuery(raw) {
    const keywords = String(raw || "")
      .split(/[\s,]+/)
      .filter(Boolean)
      .join(" && ");

    if (!keywords) {
      return "";
    }

    return `(*="${keywords}")`;
  }

  normalizeResults(data) {
    const results = Array.isArray(data?.data) ? data.data : [];
    return results.map((item, index) => ({
      id: `fofa-${index}-${Date.now()}`,
      sourceType: "fofa",
      name: item.title || item.host || `Asset ${index + 1}`,
      host: item.host,
      protocol: item.protocol,
      port: item.port,
      banner: item.banner || "",
      server: item.server || "",
      country: item.country_name || "",
      province: item.province || "",
      city: item.city || "",
      organization: item.org || "",
      asn: item.asn || "",
      latitude: item.latitude,
      longitude: item.longitude,
      createdAt: item.created_at,
      lastUpdatedAt: item.updated_at || item.lastuptime
    }));
  }
}