"""
Asset Discovery — 资产关联发现模块（中国特色）
通过公司名/域名穿透关联资产：子公司域名、备案、APP、小程序
"""


class AssetDiscovery:
    """中国 SRC 资产关联发现"""

    def __init__(self, engine, logger):
        self.engine = engine
        self.logger = logger

    def discover(self, target: str, company_name: str = "") -> dict:
        """
        资产关联发现
        返回: {"domains": [], "ips": [], "apps": [], "tips": []}
        """
        self.logger.log_phase_start("资产关联发现 (Asset Discovery)")
        
        results = {
            "domains": [],
            "ips": [],
            "apps": [],
            "mini_programs": [],
            "tips": [],
        }

        # 1. 通过 uncover 查 FOFA/Shodan
        self._fofa_discovery(target, results)

        # 2. ICP 备案关联（通过AI分析）
        if company_name:
            self._icp_analysis(target, company_name, results)

        # 3. 子域名变异 (alterx)
        self._subdomain_mutation(target, results)

        # 4. AI 综合分析资产
        self._ai_asset_analysis(target, company_name, results)

        self.logger.log_phase_end("资产关联发现", results)
        return results

    def _fofa_discovery(self, target: str, results: dict):
        """通过 FOFA/Shodan 搜索关联资产"""
        # cert 证书关联
        cmd = f'uncover -q \'cert="{target}"\' -e fofa -silent 2>/dev/null | head -30'
        result = self.engine.execute_command(cmd)
        if result["success"] and result["output"]:
            for line in result["output"].strip().split("\n"):
                if line.strip() and line.strip() not in results["domains"]:
                    results["domains"].append(line.strip())
            self.logger.log_command(cmd, result, f"FOFA证书关联: {len(results['domains'])}个")

        # icon hash 关联（同一 favicon 的站点）
        cmd2 = f'uncover -q \'domain="{target}"\' -e fofa -silent 2>/dev/null | head -20'
        result2 = self.engine.execute_command(cmd2)
        if result2["success"] and result2["output"]:
            for line in result2["output"].strip().split("\n"):
                if line.strip() and line.strip() not in results["domains"]:
                    results["domains"].append(line.strip())

    def _icp_analysis(self, target: str, company_name: str, results: dict):
        """AI 分析 ICP 备案关联"""
        analysis = self.engine.think(f"""
作为资产搜集专家，对以下目标进行备案关联分析：

目标域名: {target}
公司名称: {company_name}

请推测：
1. 该公司可能还有哪些域名？（基于常见命名规律）
   - 例如：target.com → target.cn, target.net, m.target.com, api.target.com
2. 子公司可能的域名？
3. 可能的内部系统域名？(oa/crm/erp/hr)
4. 可能的测试/预发布环境？(test/staging/uat/pre)

只输出域名列表，每行一个。不要解释。
""")
        if analysis:
            for line in analysis.strip().split("\n"):
                domain = line.strip().strip("- ").strip()
                if "." in domain and domain not in results["domains"]:
                    results["domains"].append(domain)
            results["tips"].append(f"AI推测了 {len(analysis.strip().split(chr(10)))} 个关联域名")

    def _subdomain_mutation(self, target: str, results: dict):
        """子域名变异"""
        # 用 alterx 生成变种
        cmd = f'echo "{target}" | alterx -silent 2>/dev/null | head -50'
        result = self.engine.execute_command(cmd)
        if result["success"] and result["output"]:
            mutations = [l.strip() for l in result["output"].strip().split("\n") if l.strip()]
            results["domains"].extend(mutations[:30])
            self.logger.log_command(cmd, result, f"子域名变异: {len(mutations)}个")

    def _ai_asset_analysis(self, target: str, company_name: str, results: dict):
        """AI 综合分析，给出高价值目标建议"""
        all_domains = results["domains"][:50]

        if not all_domains:
            return

        analysis = self.engine.think(f"""
以下是目标 {target} ({company_name}) 的关联资产列表：

{chr(10).join(all_domains[:30])}

请分析：
1. 哪些域名最可能有漏洞？（优先级排序）
2. 为什么？（旧系统/测试环境/内部系统/API暴露）
3. 建议先测哪3个？

简短回答，每个建议一行。
""")

        if analysis:
            results["tips"].append(analysis[:500])
            self.logger.log_event("FINDING", f"AI资产分析: {analysis[:200]}")
