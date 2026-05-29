#!/usr/bin/env python3
"""
Experience Learner — 自我进化学习模块

每次 auto_hunt 跑完后自动调用 LLM 做"复盘总结"：
1. 分析本次运行的发现、误报、工具效率
2. 提取可复用的经验规则
3. 存为结构化的经验文件
4. 下次启动时自动加载相关经验，优化决策

经验类型：
- target_pattern: 目标特征 → 推荐工具/方法
- effective_payload: 有效的 payload 模式
- waste_pattern: 浪费时间的操作（下次跳过）
- false_positive: 确认的误报模式（下次过滤）
- skill_suggestion: 自动生成的新 Skill 建议

存储位置: ~/.bai-agent/experience/
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class ExperienceLearner:
    """
    自我进化学习器

    用法:
        learner = ExperienceLearner(engine, config)

        # 跑完后复盘
        learner.post_hunt_review(target, findings, leads, run_stats)

        # 下次启动时加载经验
        context = learner.get_relevant_experience(target, tech_stack)
    """

    def __init__(self, engine, config: dict = None):
        self.engine = engine  # AgentEngine (has .think() method)
        self.config = config or {}

        # 存储目录
        self.experience_dir = os.path.expanduser(
            self.config.get("experience_dir", "~/.bai-agent/experience")
        )
        Path(self.experience_dir).mkdir(parents=True, exist_ok=True)

        # 经验文件
        self.patterns_file = os.path.join(self.experience_dir, "patterns.json")
        self.skills_file = os.path.join(self.experience_dir, "generated_skills.json")
        self.waste_file = os.path.join(self.experience_dir, "waste_patterns.json")
        self.payloads_file = os.path.join(self.experience_dir, "effective_payloads.json")

        # 加载已有经验
        self.patterns = self._load_json(self.patterns_file, [])
        self.generated_skills = self._load_json(self.skills_file, [])
        self.waste_patterns = self._load_json(self.waste_file, [])
        self.effective_payloads = self._load_json(self.payloads_file, [])

    # ═══════════════════════════════════════════════════════════
    # 核心: 跑完后复盘
    # ═══════════════════════════════════════════════════════════

    def post_hunt_review(self, target: str, findings: dict,
                         leads_summary: dict = None, run_stats: dict = None) -> dict:
        """
        跑完一次 auto_hunt 后调用此方法。
        LLM 会分析本次运行并提取可复用经验。
        """
        # 构建复盘材料
        review_input = self._build_review_input(target, findings, leads_summary, run_stats)

        # 调用 LLM 做复盘
        review_prompt = f"""你是一个精英赏金猎人的教练。刚跑完一轮自动化扫描，请分析结果并提取可复用经验。

{review_input}

请严格按以下 JSON 格式输出你的分析：
{{
  "target_type": "该目标属于什么类型 (saas/fintech/cms/api/...)",
  "tech_stack_signals": ["从结果中推断的技术栈信号"],
  "effective_tools": ["本次有效的工具/方法"],
  "wasted_effort": ["本次浪费时间的操作及原因"],
  "new_patterns": [
    {{
      "pattern": "描述一个可复用的经验规则",
      "condition": "什么条件下适用",
      "action": "应该做什么",
      "priority": "high/medium/low"
    }}
  ],
  "false_positives": ["确认的误报模式，下次应该跳过"],
  "skill_suggestion": {{
    "name": "如果值得生成新 Skill，给出名称（否则留空）",
    "description": "Skill 描述",
    "triggers": ["什么关键词触发此 Skill"],
    "checklist": ["具体测试步骤"]
  }},
  "next_time_advice": "下次遇到类似目标时的最佳策略（一句话）"
}}

只输出 JSON，不要其他内容。"""

        response = self.engine.think(review_prompt)

        # 解析 LLM 输出
        review_result = self._parse_review_response(response)

        if review_result:
            # 存储学到的经验
            self._store_experience(target, review_result)
            return review_result

        return {"error": "LLM 复盘解析失败", "raw": response[:500]}

    # ═══════════════════════════════════════════════════════════
    # 加载经验（下次启动时用）
    # ═══════════════════════════════════════════════════════════

    def get_relevant_experience(self, target: str, tech_stack: list = None) -> str:
        """
        获取与当前目标相关的历史经验，格式化为可注入 LLM 上下文的文本。
        在 agent_engine.think() 调用时注入。
        """
        relevant = []

        # 1. 按目标类型匹配 patterns
        target_lower = target.lower()
        for pattern in self.patterns[-50:]:  # 最近 50 条
            condition = pattern.get("condition", "").lower()
            if any(kw in target_lower for kw in condition.split()):
                relevant.append(f"- [{pattern.get('priority', 'medium')}] {pattern.get('pattern')}")
                relevant.append(f"  动作: {pattern.get('action')}")

        # 2. 浪费时间模式（无条件加载，始终避免）
        if self.waste_patterns:
            relevant.append("\n避免重复以下无效操作:")
            for waste in self.waste_patterns[-10:]:
                relevant.append(f"  ✗ {waste}")

        # 3. 有效 payload（如果有）
        if self.effective_payloads:
            relevant.append("\n历史有效 payload:")
            for p in self.effective_payloads[-5:]:
                relevant.append(f"  ✓ {p.get('type', '?')}: {p.get('payload', '')[:80]}")

        # 4. 生成的 Skill
        for skill in self.generated_skills[-3:]:
            if skill.get("triggers"):
                if any(t.lower() in target_lower for t in skill["triggers"]):
                    relevant.append(f"\n相关 Skill [{skill.get('name')}]:")
                    for step in skill.get("checklist", [])[:5]:
                        relevant.append(f"  → {step}")

        if not relevant:
            return ""

        return "=== 历史经验（自动学习）===\n" + "\n".join(relevant) + "\n=== 经验结束 ===\n"

    def get_experience_stats(self) -> dict:
        """获取经验库统计"""
        return {
            "total_patterns": len(self.patterns),
            "generated_skills": len(self.generated_skills),
            "waste_patterns": len(self.waste_patterns),
            "effective_payloads": len(self.effective_payloads),
            "experience_dir": self.experience_dir,
        }

    # ═══════════════════════════════════════════════════════════
    # 内部方法
    # ═══════════════════════════════════════════════════════════

    def _build_review_input(self, target, findings, leads_summary, run_stats) -> str:
        """构建复盘输入材料"""
        lines = [f"目标: {target}"]

        # 发现汇总
        vulns = findings.get("vulnerabilities", [])
        lines.append(f"确认漏洞: {len(vulns)}")
        for v in vulns[:5]:
            lines.append(f"  - [{v.get('severity', '?')}] {v.get('type', '?')} @ {v.get('url', '?')[:60]}")

        # 线索汇总
        if leads_summary:
            lines.append(f"线索总数: {leads_summary.get('total', 0)}")
            by_cat = leads_summary.get('by_category', {})
            for cat, count in by_cat.items():
                lines.append(f"  {cat}: {count}")

        # 其他发现
        lines.append(f"子域名: {len(findings.get('subdomains', []))}")
        lines.append(f"存活主机: {len(findings.get('alive_hosts', []))}")
        lines.append(f"URL: {len(findings.get('urls', []))}")
        lines.append(f"参数: {len(findings.get('params', []))}")
        lines.append(f"密钥泄露: {len(findings.get('secrets', []))}")

        # 运行统计
        if run_stats:
            lines.append(f"\n运行时长: {run_stats.get('duration_minutes', '?')} 分钟")
            lines.append(f"总请求数: {run_stats.get('total_requests', '?')}")
            lines.append(f"WAF 类型: {run_stats.get('waf_type', 'unknown')}")

        return "\n".join(lines)

    def _parse_review_response(self, response: str) -> Optional[dict]:
        """解析 LLM 复盘输出"""
        try:
            # 找 JSON
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass
        return None

    def _store_experience(self, target: str, review: dict):
        """将复盘结果存储到经验库"""
        timestamp = datetime.now().isoformat()

        # 1. 存储 patterns
        new_patterns = review.get("new_patterns", [])
        for p in new_patterns:
            p["learned_from"] = target
            p["learned_at"] = timestamp
            self.patterns.append(p)
        # 限制大小
        self.patterns = self.patterns[-200:]
        self._save_json(self.patterns_file, self.patterns)

        # 2. 存储浪费模式
        wasted = review.get("wasted_effort", [])
        for w in wasted:
            if w not in self.waste_patterns:
                self.waste_patterns.append(w)
        self.waste_patterns = self.waste_patterns[-50:]
        self._save_json(self.waste_file, self.waste_patterns)

        # 3. 存储误报模式（也加入 waste）
        fps = review.get("false_positives", [])
        for fp in fps:
            if fp not in self.waste_patterns:
                self.waste_patterns.append(f"误报: {fp}")
        self._save_json(self.waste_file, self.waste_patterns)

        # 4. 存储新 Skill
        skill = review.get("skill_suggestion", {})
        if skill and skill.get("name"):
            skill["generated_at"] = timestamp
            skill["generated_from"] = target
            self.generated_skills.append(skill)
            self.generated_skills = self.generated_skills[-20:]
            self._save_json(self.skills_file, self.generated_skills)

        # 5. 存储完整复盘记录
        review_file = os.path.join(
            self.experience_dir,
            f"review_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        )
        review["target"] = target
        review["timestamp"] = timestamp
        Path(review_file).write_text(json.dumps(review, indent=2, ensure_ascii=False))

    def _load_json(self, filepath: str, default):
        """加载 JSON 文件"""
        try:
            if os.path.exists(filepath):
                return json.loads(Path(filepath).read_text())
        except (json.JSONDecodeError, OSError):
            pass
        return default

    def _save_json(self, filepath: str, data):
        """保存 JSON 文件"""
        Path(filepath).write_text(json.dumps(data, indent=2, ensure_ascii=False))
