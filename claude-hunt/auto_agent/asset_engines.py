#!/usr/bin/env python3
"""
Asset Engines — 全网资产搜索引擎聚合

集成 10+ 个资产搜索平台，Claude Code 调用一个函数就能从所有引擎拉资产。

国内引擎（SRC 流）：
  - FOFA
  - Hunter.how
  - 360 Quake
  - ZoomEye

国外引擎（H1/Bugcrowd 流）：
  - Shodan
  - Censys
  - Netlas
  - Criminal IP

免费引擎（不需要 Key）：
  - crt.sh（证书透明度）
  - Wayback CDX（历史 URL）
  - urlscan.io
  - SecurityTrails（需免费注册）
  - GitHub Code Search

本地工具（ProjectDiscovery 系列）：
  - uncover（聚合搜索）
  - subfinder / dnsx / httpx / katana / nuclei / naabu

用法：
    from asset_engines import AssetEngines
    ae = AssetEngines(config)

    # 一键全引擎搜索
    result = ae.search_all("target.com")

    # 国内 SRC 流
    result = ae.search_cn("target.com")

    # 国外 H1 流
    result = ae.search_global("target.com")

    # 单引擎
    result = ae.crtsh("target.com")
    result = ae.wayback("target.com")
    result = ae.fofa('title="目标"')
"""

import json
import os
import re
import subprocess
import time
import base64
from pathlib import Path
from datetime import datetime
from urllib.parse import quote, urlencode

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class AssetEngines:
    """全网资产搜索引擎聚合器"""

    def __init__(self, config=None):
        self.config = config or {}
        self.output_dir = os.path.expanduser('~/.bai-agent/assets')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

        # API Keys（从 config 或环境变量读取）
        engines_cfg = self.config.get('asset_engines', {})
        self.keys = {
            "fofa_key": os.environ.get("FOFA_KEY", engines_cfg.get("fofa_key", "")),
            "fofa_email": os.environ.get("FOFA_EMAIL", engines_cfg.get("fofa_email", "")),
            "hunter_key": os.environ.get("HUNTER_KEY", engines_cfg.get("hunter_key", "")),
            "quake_key": os.environ.get("QUAKE_KEY", engines_cfg.get("quake_key", "")),
            "zoomeye_key": os.environ.get("ZOOMEYE_KEY", engines_cfg.get("zoomeye_key", "")),
            "shodan_key": os.environ.get("SHODAN_KEY", engines_cfg.get("shodan_key", "")),
            "censys_id": os.environ.get("CENSYS_ID", engines_cfg.get("censys_id", "")),
            "censys_secret": os.environ.get("CENSYS_SECRET", engines_cfg.get("censys_secret", "")),
            "securitytrails_key": os.environ.get("SECURITYTRAILS_KEY", engines_cfg.get("securitytrails_key", "")),
            "netlas_key": os.environ.get("NETLAS_KEY", engines_cfg.get("netlas_key", "")),
            "criminalip_key": os.environ.get("CRIMINALIP_KEY", engines_cfg.get("criminalip_key", "")),
            "github_token": os.environ.get("GITHUB_TOKEN", engines_cfg.get("github_token", "")),
        }

    # ═══════════════════════════════════════════════════════════
    #  一键搜索
    # ═══════════════════════════════════════════════════════════

    def search_all(self, target, max_per_engine=50):
        """全引擎搜索（国内+国外+免费）"""
        results = {"target": target, "timestamp": datetime.now().isoformat(), "engines": {}, "total_assets": 0}

        # 免费引擎（始终跑）
        results["engines"]["crtsh"] = self.crtsh(target)
        results["engines"]["wayback"] = self.wayback(target)
        results["engines"]["urlscan"] = self.urlscan(target)

        # 国内引擎
        if self.keys["fofa_key"]:
            results["engines"]["fofa"] = self.fofa(f'domain="{target}"', max_per_engine)
        if self.keys["hunter_key"]:
            results["engines"]["hunter"] = self.hunter(f'domain="{target}"', max_per_engine)
        if self.keys["quake_key"]:
            results["engines"]["quake"] = self.quake(f'domain:"{target}"', max_per_engine)
        if self.keys["zoomeye_key"]:
            results["engines"]["zoomeye"] = self.zoomeye(f'site:{target}', max_per_engine)

        # 国外引擎
        if self.keys["shodan_key"]:
            results["engines"]["shodan"] = self.shodan(f'hostname:{target}', max_per_engine)
        if self.keys["censys_id"]:
            results["engines"]["censys"] = self.censys(target, max_per_engine)
        if self.keys["securitytrails_key"]:
            results["engines"]["securitytrails"] = self.securitytrails(target)
        if self.keys["github_token"]:
            results["engines"]["github"] = self.github_search(target)

        # uncover（本地聚合工具）
        results["engines"]["uncover"] = self.uncover(target)

        # 汇总
        all_assets = set()
        for engine_result in results["engines"].values():
            if isinstance(engine_result, dict):
                all_assets.update(engine_result.get("assets", []))
            elif isinstance(engine_result, list):
                all_assets.update(engine_result)
        results["total_assets"] = len(all_assets)
        results["all_assets"] = sorted(all_assets)

        # 保存
        out_file = os.path.join(self.output_dir, f"{target.replace('.','_')}_assets.json")
        Path(out_file).write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')

        return results

    def search_cn(self, target, max_per_engine=100):
        """国内 SRC 流：FOFA + Hunter + Quake + ZoomEye"""
        results = {"target": target, "engines": {}}
        if self.keys["fofa_key"]:
            results["engines"]["fofa"] = self.fofa(f'domain="{target}"', max_per_engine)
        if self.keys["hunter_key"]:
            results["engines"]["hunter"] = self.hunter(f'domain="{target}"', max_per_engine)
        if self.keys["quake_key"]:
            results["engines"]["quake"] = self.quake(f'domain:"{target}"', max_per_engine)
        if self.keys["zoomeye_key"]:
            results["engines"]["zoomeye"] = self.zoomeye(f'site:{target}', max_per_engine)
        # 免费补充
        results["engines"]["crtsh"] = self.crtsh(target)
        return results

    def search_global(self, target, max_per_engine=100):
        """国外 H1 流：crt.sh + SecurityTrails + Censys + Shodan + Wayback + urlscan + GitHub"""
        results = {"target": target, "engines": {}}
        results["engines"]["crtsh"] = self.crtsh(target)
        results["engines"]["wayback"] = self.wayback(target)
        results["engines"]["urlscan"] = self.urlscan(target)
        if self.keys["securitytrails_key"]:
            results["engines"]["securitytrails"] = self.securitytrails(target)
        if self.keys["censys_id"]:
            results["engines"]["censys"] = self.censys(target, max_per_engine)
        if self.keys["shodan_key"]:
            results["engines"]["shodan"] = self.shodan(f'hostname:{target}', max_per_engine)
        if self.keys["netlas_key"]:
            results["engines"]["netlas"] = self.netlas(target, max_per_engine)
        if self.keys["github_token"]:
            results["engines"]["github"] = self.github_search(target)
        return results

    # ═══════════════════════════════════════════════════════════
    #  免费引擎（不需要 Key）
    # ═══════════════════════════════════════════════════════════

    def crtsh(self, domain):
        """crt.sh — 证书透明度日志查子域名（免费）"""
        if not HAS_REQUESTS:
            return {"assets": [], "error": "requests not installed"}
        try:
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30)
            if r.status_code != 200:
                return {"assets": [], "error": f"HTTP {r.status_code}"}
            data = r.json()
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub and '*' not in sub and sub.endswith(domain):
                        subs.add(sub)
            return {"assets": sorted(subs), "count": len(subs), "source": "crt.sh"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def wayback(self, domain, limit=500):
        """Wayback Machine CDX — 历史 URL（免费）"""
        if not HAS_REQUESTS:
            return {"assets": [], "error": "requests not installed"}
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&limit={limit}&fl=original"
            r = requests.get(url, timeout=30)
            if r.status_code != 200:
                return {"assets": [], "error": f"HTTP {r.status_code}"}
            data = r.json()
            urls = [row[0] for row in data[1:] if row]  # 跳过 header
            return {"assets": urls[:limit], "count": len(urls), "source": "wayback"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def urlscan(self, domain, limit=100):
        """urlscan.io — 查别人扫过的结果（免费）"""
        if not HAS_REQUESTS:
            return {"assets": [], "error": "requests not installed"}
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size={limit}", timeout=15)
            if r.status_code != 200:
                return {"assets": [], "error": f"HTTP {r.status_code}"}
            data = r.json()
            urls = []
            for result in data.get("results", []):
                page = result.get("page", {})
                url = page.get("url", "")
                if url:
                    urls.append(url)
            return {"assets": urls, "count": len(urls), "source": "urlscan.io"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    #  国内引擎
    # ═══════════════════════════════════════════════════════════

    def fofa(self, query, limit=100):
        """FOFA 搜索"""
        if not self.keys["fofa_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "FOFA key not configured"}
        try:
            q_b64 = base64.b64encode(query.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?email={self.keys['fofa_email']}&key={self.keys['fofa_key']}&qbase64={q_b64}&size={limit}&fields=host,ip,port,title,server"
            r = requests.get(url, timeout=15)
            data = r.json()
            if data.get("error"):
                return {"assets": [], "error": data["errmsg"]}
            results = data.get("results", [])
            assets = [row[0] for row in results if row]
            return {"assets": assets, "count": len(assets), "raw": results[:20], "source": "fofa"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def hunter(self, query, limit=100):
        """Hunter.how 搜索"""
        if not self.keys["hunter_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "Hunter key not configured"}
        try:
            q_b64 = base64.b64encode(query.encode()).decode()
            url = f"https://hunter.qianxin.com/openApi/search?api-key={self.keys['hunter_key']}&search={q_b64}&page=1&page_size={limit}"
            r = requests.get(url, timeout=15)
            data = r.json()
            assets = []
            for item in data.get("data", {}).get("arr", []):
                url_val = item.get("url", "")
                if url_val:
                    assets.append(url_val)
            return {"assets": assets, "count": len(assets), "source": "hunter.how"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def quake(self, query, limit=100):
        """360 Quake 搜索"""
        if not self.keys["quake_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "Quake key not configured"}
        try:
            url = "https://quake.360.net/api/v3/search/quake_service"
            headers = {"X-QuakeToken": self.keys["quake_key"], "Content-Type": "application/json"}
            body = {"query": query, "start": 0, "size": limit}
            r = requests.post(url, json=body, headers=headers, timeout=15)
            data = r.json()
            assets = []
            for item in data.get("data", []):
                host = item.get("service", {}).get("http", {}).get("host", "")
                if host:
                    assets.append(host)
            return {"assets": assets, "count": len(assets), "source": "360quake"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def zoomeye(self, query, limit=100):
        """ZoomEye 搜索"""
        if not self.keys["zoomeye_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "ZoomEye key not configured"}
        try:
            url = f"https://api.zoomeye.org/web/search?query={quote(query)}&page=1"
            headers = {"API-KEY": self.keys["zoomeye_key"]}
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            assets = []
            for match in data.get("matches", []):
                site = match.get("site", "")
                if site:
                    assets.append(site)
            return {"assets": assets[:limit], "count": len(assets), "source": "zoomeye"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    #  国外引擎
    # ═══════════════════════════════════════════════════════════

    def shodan(self, query, limit=100):
        """Shodan 搜索"""
        if not self.keys["shodan_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "Shodan key not configured"}
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={self.keys['shodan_key']}&query={quote(query)}&page=1"
            r = requests.get(url, timeout=15)
            data = r.json()
            assets = []
            for match in data.get("matches", []):
                ip = match.get("ip_str", "")
                port = match.get("port", "")
                if ip:
                    assets.append(f"{ip}:{port}" if port else ip)
            return {"assets": assets[:limit], "count": len(assets), "source": "shodan"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def censys(self, domain, limit=100):
        """Censys 搜索（证书+主机）"""
        if not self.keys["censys_id"] or not HAS_REQUESTS:
            return {"assets": [], "error": "Censys credentials not configured"}
        try:
            url = "https://search.censys.io/api/v2/hosts/search"
            r = requests.get(url, params={"q": domain, "per_page": min(limit, 100)},
                           auth=(self.keys["censys_id"], self.keys["censys_secret"]), timeout=15)
            data = r.json()
            assets = []
            for hit in data.get("result", {}).get("hits", []):
                ip = hit.get("ip", "")
                if ip:
                    assets.append(ip)
            return {"assets": assets, "count": len(assets), "source": "censys"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def securitytrails(self, domain):
        """SecurityTrails — 子域名+DNS 历史"""
        if not self.keys["securitytrails_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "SecurityTrails key not configured"}
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": self.keys["securitytrails_key"]}
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            subs = [f"{s}.{domain}" for s in data.get("subdomains", [])]
            return {"assets": subs, "count": len(subs), "source": "securitytrails"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def netlas(self, domain, limit=100):
        """Netlas — 互联网扫描+DNS+证书"""
        if not self.keys["netlas_key"] or not HAS_REQUESTS:
            return {"assets": [], "error": "Netlas key not configured"}
        try:
            url = f"https://app.netlas.io/api/domains/?q=*.{domain}&source_type=include&start=0&indices="
            headers = {"X-API-Key": self.keys["netlas_key"]}
            r = requests.get(url, headers=headers, timeout=15)
            data = r.json()
            assets = [item.get("data", {}).get("domain", "") for item in data.get("items", [])]
            assets = [a for a in assets if a]
            return {"assets": assets[:limit], "count": len(assets), "source": "netlas"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    def github_search(self, domain):
        """GitHub Code Search — 搜泄露的配置/密钥/端点"""
        if not self.keys["github_token"] or not HAS_REQUESTS:
            return {"assets": [], "error": "GitHub token not configured"}
        try:
            queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" token',
                f'"{domain}" endpoint',
            ]
            assets = []
            headers = {"Authorization": f"token {self.keys['github_token']}", "Accept": "application/vnd.github.v3+json"}
            for q in queries[:3]:  # 限制请求数
                url = f"https://api.github.com/search/code?q={quote(q)}&per_page=10"
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    for item in r.json().get("items", []):
                        assets.append({
                            "repo": item.get("repository", {}).get("full_name", ""),
                            "file": item.get("path", ""),
                            "url": item.get("html_url", ""),
                        })
                time.sleep(2)  # GitHub rate limit
            return {"assets": assets, "count": len(assets), "source": "github_code_search"}
        except Exception as e:
            return {"assets": [], "error": str(e)}

    # ═══════════════════════════════════════════════════════════
    #  本地工具
    # ═══════════════════════════════════════════════════════════

    def uncover(self, domain):
        """ProjectDiscovery uncover — 聚合多引擎搜索"""
        try:
            cmd = f"uncover -q '{domain}' -silent -limit 100 2>/dev/null"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and r.stdout:
                assets = [l.strip() for l in r.stdout.split('\n') if l.strip()]
                return {"assets": assets, "count": len(assets), "source": "uncover"}
            return {"assets": [], "source": "uncover"}
        except Exception as e:
            return {"assets": [], "error": str(e)}
