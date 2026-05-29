"""
Trace Analyzer — 痕迹分析模块
AI 判断当前发现是否有可挖的线索，给出下一步建议
"""


class TraceAnalyzer:
    """痕迹分析器：分析当前发现，找出可挖线索"""
    
    def __init__(self, engine):
        self.engine = engine  # AgentEngine 实例
    
    def analyze(self, target: str, findings: dict) -> dict:
        """
        分析当前所有发现，识别可挖线索
        返回: {"summary": str, "leads": list, "next_action": str, "confidence": float}
        """
        
        # 构建分析上下文
        context = self._build_context(target, findings)
        
        prompt = """作为 SRC 漏洞猎人，分析当前收集到的信息，回答以下问题：

1. 【总结】当前信息搜集情况如何？有多少有价值的攻击面？
2. 【线索】从已有数据中，你看到了哪些可能存在漏洞的痕迹？比如：
   - 有带 debug/admin/test 参数的 URL 吗？
   - 有暴露的 API 文档（swagger/graphql）吗？
   - 有旧版本/未维护的子域名吗？
   - 有文件上传/重定向/SSRF 可能的接口吗？
   - 有 JWT/Cookie 可以篡改的地方吗？
3. 【建议】下一步最应该做什么？优先级排序。

回答格式（JSON）：
{
  "summary": "一句话总结当前状态",
  "leads": ["线索1", "线索2", "线索3"],
  "next_action": "最建议的下一步操作",
  "confidence": 0.7
}"""
        
        response = self.engine.think(prompt, context)
        
        # 解析响应
        import json
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
            elif "{" in response and "}" in response:
                start = response.index("{")
                end = response.rindex("}") + 1
                json_str = response[start:end]
            else:
                return {"summary": response[:200], "leads": [], "next_action": "继续当前流程", "confidence": 0.5}
            
            result = json.loads(json_str)
            return result
        except (json.JSONDecodeError, ValueError):
            return {"summary": response[:200], "leads": [], "next_action": "继续当前流程", "confidence": 0.5}
    
    def _build_context(self, target: str, findings: dict) -> str:
        """构建分析上下文"""
        parts = [f"目标: {target}\n"]
        
        # 子域名
        subs = findings.get('subdomains', [])
        if subs:
            parts.append(f"子域名 ({len(subs)}个):")
            for s in subs[:30]:  # 最多30个
                parts.append(f"  - {s}")
        
        # URL（重点看有参数的）
        urls = findings.get('urls', [])
        if urls:
            interesting = [u for u in urls if '?' in u or 'api' in u.lower() or 'admin' in u.lower()]
            parts.append(f"\nURL ({len(urls)}个，其中有趣的 {len(interesting)} 个):")
            for u in interesting[:30]:
                parts.append(f"  - {u}")
        
        # 参数
        params = findings.get('params', [])
        if params:
            parts.append(f"\n发现的参数 ({len(params)}个):")
            for p in params[:20]:
                parts.append(f"  - {p}")
        
        # 密钥泄露
        secrets = findings.get('secrets', [])
        if secrets:
            parts.append(f"\n密钥泄露 ({len(secrets)}个):")
            for s in secrets[:10]:
                parts.append(f"  - {s}")
        
        # 已发现漏洞
        vulns = findings.get('vulnerabilities', [])
        if vulns:
            parts.append(f"\n已确认漏洞 ({len(vulns)}个):")
            for v in vulns:
                parts.append(f"  - [{v.get('severity', '?')}] {v.get('type', '?')} @ {v.get('url', '?')}")
        
        return "\n".join(parts)
