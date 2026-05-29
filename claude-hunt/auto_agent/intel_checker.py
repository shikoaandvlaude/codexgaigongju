"""
Intel Checker — 历史漏洞情报查询
提交前查重，避免重复提交被忽略/扣分
"""


class IntelChecker:
    """历史漏洞情报查询器"""

    def __init__(self, engine, logger):
        self.engine = engine
        self.logger = logger

    def check_duplicate(self, target: str, vuln_type: str, vuln_url: str) -> dict:
        """
        检查是否已有类似漏洞被报告过
        返回: {"is_duplicate": bool, "confidence": float, "references": [], "advice": str}
        """
        self.logger.log_event("FINDING", f"查重: {vuln_type} @ {target}")

        # 1. 用 AI 分析是否可能已知
        analysis = self.engine.think(f"""
我发现了一个漏洞，提交 SRC 之前需要判断是否已有人报告过。

目标: {target}
漏洞类型: {vuln_type}
URL: {vuln_url}

请分析：
1. 这种漏洞类型在这个目标上是否属于"常见已知问题"？
2. 如果目标是知名 CMS/框架，这个版本是否有已知 CVE 覆盖？
3. 中国 SRC 平台（补天/漏洞盒子）是否可能已有同类提交？
4. 你的判断：重复概率 0-100%

回答格式：
DUPLICATE_RISK: [低/中/高]
REASON: [一句话理由]
ADVICE: [建议动作：提交/先搜再决定/放弃]
""")

        # 解析结果
        result = {
            "is_duplicate": False,
            "confidence": 0.3,
            "references": [],
            "advice": "建议提交",
            "analysis": analysis,
        }

        if analysis:
            upper = analysis.upper()
            if "高" in analysis or "HIGH" in upper:
                result["is_duplicate"] = True
                result["confidence"] = 0.8
                result["advice"] = "高重复风险，建议先搜索平台确认"
            elif "中" in analysis:
                result["confidence"] = 0.5
                result["advice"] = "中等风险，建议搜索后决定"
            else:
                result["confidence"] = 0.2
                result["advice"] = "低重复风险，建议提交"

        self.logger.log_command("AI: 历史情报查重",
            {"success": True, "output": analysis or "无结果", "returncode": 0},
            f"重复风险: {result['confidence']:.0%}")

        return result

    def check_known_cve(self, target: str, tech_stack: str = "") -> dict:
        """
        检查目标技术栈的已知 CVE
        返回: {"cves": [], "advice": str}
        """
        # 通过 nuclei 的 CVE 模板快速检查
        cmd = f'nuclei -u {target} -tags cve -severity critical,high -rate-limit 3 -c 2 -silent 2>/dev/null | head -10'
        result = self.engine.execute_command(cmd, timeout=60)

        cves = []
        if result["success"] and result["output"]:
            for line in result["output"].strip().split("\n"):
                if line.strip():
                    cves.append(line.strip())

        return {
            "cves": cves,
            "advice": f"发现 {len(cves)} 个已知CVE" if cves else "未发现已知CVE"
        }

    def pre_submission_check(self, target: str, vulnerabilities: list) -> list:
        """
        提交前批量查重
        返回带查重结果的漏洞列表
        """
        checked = []
        for vuln in vulnerabilities:
            dup_result = self.check_duplicate(
                target,
                vuln.get("type", "unknown"),
                vuln.get("url", "")
            )
            vuln["duplicate_check"] = dup_result
            vuln["submission_ready"] = not dup_result["is_duplicate"]
            checked.append(vuln)

        # 汇总
        ready_count = sum(1 for v in checked if v["submission_ready"])
        self.logger.log_event("FINDING",
            f"查重完成: {ready_count}/{len(checked)} 个漏洞建议提交")

        return checked
