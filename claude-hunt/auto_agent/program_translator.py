#!/usr/bin/env python3
"""
Program Translator — 英文项目规则翻译 + 风险提醒

解决问题：
- 英语吃力的研究员看 HackerOne 项目规则容易漏关键信息
- Non-Qualifying Bugs 不翻译就浪费时间测
- 项目 Policy 变更不易察觉

功能：
1. 自动翻译 HackerOne/Bugcrowd 项目规则为中文
2. 高亮 Non-Qualifying Bugs（这些别浪费时间测）
3. Scope 变更检测
4. 关键规则提取 + 风险提醒
5. 使用 LLM 翻译（DeepSeek/GPT）

用法：
    from program_translator import ProgramTranslator

    pt = ProgramTranslator(config)
    result = pt.translate_policy(policy_text)
    pt.show_warnings()

CLI:
    python program_translator.py --url "https://hackerone.com/syfe"
    python program_translator.py --file policy.txt
    python program_translator.py --text "Non-qualifying: self-xss..."
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from pathlib import Path


# ═══════════════════════════════════════════════════════════════
# 常见术语翻译表（不依赖 LLM 的快速翻译）
# ═══════════════════════════════════════════════════════════════

TERM_DICT = {
    # Scope
    "in scope": "在测试范围内",
    "out of scope": "不在测试范围/禁止测试",
    "eligible for bounty": "有赏金",
    "not eligible": "无赏金",
    "wildcard": "通配符（*.domain.com 的所有子域）",

    # Actions
    "do not test": "禁止测试",
    "do not attempt": "禁止尝试",
    "brute force": "暴力破解（禁止）",
    "denial of service": "拒绝服务攻击（禁止）",
    "social engineering": "社会工程学攻击（禁止）",
    "physical attack": "物理攻击（禁止）",
    "automated scanning": "自动化扫描",
    "rate limiting": "速率限制",
    "mass exploitation": "批量利用（禁止）",

    # Non-qualifying
    "non-qualifying": "不收的漏洞类型（别浪费时间）",
    "out of scope vulnerabilities": "不收的漏洞",
    "self-xss": "Self-XSS（不收）",
    "logout csrf": "登出CSRF（不收）",
    "missing security headers": "缺少安全头（不收）",
    "clickjacking": "点击劫持（大多不收）",
    "open redirect": "开放重定向（单独不收，需配合利用链）",
    "email spoofing": "邮件伪造（不收）",
    "spf/dkim/dmarc": "邮件安全配置（不收）",
    "content spoofing": "内容伪造（不收）",
    "missing rate limiting": "缺少速率限制（不收）",
    "best practice": "最佳实践（不是漏洞）",
    "informational": "信息性发现（通常不收）",
    "theoretical": "理论性漏洞（不收，必须有实际影响）",
    "scanner output": "扫描器原始输出（不收，需人工验证）",

    # Severity
    "critical": "严重/紧急",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "informational": "信息性",

    # Rewards
    "bounty range": "赏金范围",
    "safe harbor": "安全港（合法保护）",
    "responsible disclosure": "负责任披露",
    "coordinated disclosure": "协调披露",

    # Common phrases
    "proof of concept": "概念验证（PoC）",
    "impact": "影响/危害",
    "attack scenario": "攻击场景",
    "reproduction steps": "复现步骤",
    "first come first served": "先到先得（同一漏洞）",
    "duplicate": "重复提交（不给赏金）",
    "triaged": "已分类（正在审核）",
    "resolved": "已修复",
    "n/a": "不适用",
}

# 风险关键词（看到这些要注意）
RISK_KEYWORDS = {
    "do not": "⚠️ 禁止操作",
    "prohibited": "⚠️ 严禁",
    "will result in": "⚠️ 后果警告",
    "ban": "⚠️ 可能封号",
    "legal action": "🚨 可能法律追责",
    "production data": "⚠️ 涉及生产数据",
    "real user": "⚠️ 涉及真实用户",
    "do not access": "⚠️ 禁止访问",
    "do not modify": "⚠️ 禁止修改",
    "do not delete": "⚠️ 禁止删除",
    "only use test accounts": "⚠️ 只能用测试账号",
    "maximum": "注意上限",
    "minimum": "注意下限",
}


@dataclass
class TranslatedPolicy:
    """翻译后的策略"""
    program_name: str = ""
    platform: str = ""
    original_text: str = ""
    # 结构化信息
    in_scope_cn: List[str] = field(default_factory=list)
    out_of_scope_cn: List[str] = field(default_factory=list)
    non_qualifying_cn: List[str] = field(default_factory=list)
    rules_cn: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    rewards_cn: str = ""
    # 全文翻译
    full_translation: str = ""
    # 元数据
    translated_at: str = ""


class ProgramTranslator:
    """项目规则翻译器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.llm_config = self.config.get("llm", {})
        self.translations_dir = os.path.expanduser("~/.bai-agent/translations")
        Path(self.translations_dir).mkdir(parents=True, exist_ok=True)

    def translate_policy(self, text: str, program_name: str = "") -> TranslatedPolicy:
        """翻译项目规则"""
        result = TranslatedPolicy(
            program_name=program_name,
            original_text=text,
            translated_at=datetime.now().isoformat(),
        )

        print(f"\n[*] 翻译项目规则: {program_name or '(未命名)'}\n")

        # 1. 提取关键部分
        result.non_qualifying_cn = self._extract_non_qualifying(text)
        result.warnings = self._extract_warnings(text)
        result.in_scope_cn = self._extract_scope(text, "in")
        result.out_of_scope_cn = self._extract_scope(text, "out")

        # 2. 快速术语翻译
        result.full_translation = self._quick_translate(text)

        # 3. 尝试 LLM 深度翻译
        llm_result = self._llm_translate(text)
        if llm_result:
            result.full_translation = llm_result

        # 4. 输出
        self._print_result(result)

        # 5. 保存
        self._save(result)

        return result

    def show_warnings(self, result: TranslatedPolicy = None):
        """显示风险提醒"""
        warnings = result.warnings if result else []
        if not warnings:
            print("  暂无特殊风险提醒")
            return

        print("\n🚨 风险提醒（必读）:\n")
        for w in warnings:
            print(f"  {w}")

    def translate_term(self, term: str) -> str:
        """单个术语翻译"""
        term_lower = term.lower().strip()
        for en, cn in TERM_DICT.items():
            if en in term_lower:
                return cn
        return f"[未翻译] {term}"

    # ═══════════════════════════════════════════════════════════
    # 提取方法
    # ═══════════════════════════════════════════════════════════

    def _extract_non_qualifying(self, text: str) -> List[str]:
        """提取不收的漏洞类型"""
        results = []
        # 找到 non-qualifying 段落
        patterns = [
            r"non[- ]qualifying[^:]*:(.*?)(?=\n\n|\n[A-Z]|\Z)",
            r"out of scope vulnerabilities[^:]*:(.*?)(?=\n\n|\n[A-Z]|\Z)",
            r"will not be accepted[^:]*:(.*?)(?=\n\n|\n[A-Z]|\Z)",
            r"we do not accept[^:]*:(.*?)(?=\n\n|\n[A-Z]|\Z)",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                items = re.split(r'[\n•\-\*]', match)
                for item in items:
                    item = item.strip().rstrip(".,;")
                    if item and len(item) > 3:
                        cn = self._quick_translate_line(item)
                        results.append(f"❌ {cn}")

        return results

    def _extract_warnings(self, text: str) -> List[str]:
        """提取风险警告"""
        warnings = []
        text_lower = text.lower()

        for keyword, label in RISK_KEYWORDS.items():
            if keyword in text_lower:
                # 找到包含关键词的句子
                for sentence in re.split(r'[.!?\n]', text):
                    if keyword in sentence.lower():
                        cn = self._quick_translate_line(sentence.strip())
                        warnings.append(f"{label}: {cn}")
                        break

        return warnings[:10]  # 最多 10 条

    def _extract_scope(self, text: str, scope_type: str) -> List[str]:
        """提取 scope 信息"""
        results = []
        if scope_type == "in":
            patterns = [r"in[- ]scope[^:]*:(.*?)(?=out|non|$)", r"eligible.*?:(.*?)(?=\n\n|$)"]
        else:
            patterns = [r"out[- ]of[- ]scope[^:]*:(.*?)(?=in|non|$)"]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            for match in matches:
                items = re.split(r'[\n•\-\*]', match)
                for item in items:
                    item = item.strip()
                    if item and len(item) > 3:
                        results.append(item)

        return results[:20]

    # ═══════════════════════════════════════════════════════════
    # 翻译方法
    # ═══════════════════════════════════════════════════════════

    def _quick_translate(self, text: str) -> str:
        """快速术语替换翻译（不需要 LLM）"""
        result = text
        for en, cn in sorted(TERM_DICT.items(), key=lambda x: -len(x[0])):
            pattern = re.compile(re.escape(en), re.IGNORECASE)
            result = pattern.sub(f"{cn}({en})", result)
        return result

    def _quick_translate_line(self, line: str) -> str:
        """翻译单行"""
        result = line
        for en, cn in TERM_DICT.items():
            if en.lower() in line.lower():
                result = re.sub(re.escape(en), cn, result, flags=re.IGNORECASE)
        return result

    def _llm_translate(self, text: str) -> Optional[str]:
        """使用 LLM 翻译（如果配置了）"""
        api_key = (
            os.environ.get("DEEPSEEK_API_KEY") or
            os.environ.get("OPENAI_API_KEY") or
            self.llm_config.get("api_key", "")
        )
        if not api_key:
            return None

        try:
            from openai import OpenAI
            client = OpenAI(
                api_key=api_key,
                base_url=self.llm_config.get("base_url", "https://api.deepseek.com/v1"),
            )

            prompt = f"""请将以下 Bug Bounty 项目规则翻译为中文。要求：
1. 保留原有格式
2. 技术术语保留英文并加括号注释
3. 对"禁止操作"和"不收的漏洞类型"加 ⚠️ 标记
4. 对赏金金额保留原始数字

原文：
{text[:3000]}"""

            response = client.chat.completions.create(
                model=self.llm_config.get("model", "deepseek-chat"),
                messages=[{"role": "user", "content": prompt}],
                max_tokens=4000,
                temperature=0.3,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"  [!] LLM 翻译失败（回退到术语替换）: {e}")
            return None

    # ═══════════════════════════════════════════════════════════
    # 输出
    # ═══════════════════════════════════════════════════════════

    def _print_result(self, result: TranslatedPolicy):
        """打印翻译结果"""
        print(f"{'='*60}")
        print(f"项目规则翻译 — {result.program_name}")
        print(f"{'='*60}\n")

        if result.non_qualifying_cn:
            print("🚫 不收的漏洞（别浪费时间测这些）:\n")
            for item in result.non_qualifying_cn:
                print(f"  {item}")
            print()

        if result.warnings:
            print("🚨 风险提醒:\n")
            for w in result.warnings:
                print(f"  {w}")
            print()

        if result.in_scope_cn:
            print("✅ 可测范围:\n")
            for item in result.in_scope_cn[:10]:
                print(f"  • {item}")
            print()

        if result.out_of_scope_cn:
            print("⛔ 禁止测试:\n")
            for item in result.out_of_scope_cn[:10]:
                print(f"  • {item}")
            print()

    def _save(self, result: TranslatedPolicy):
        """保存翻译结果"""
        name = result.program_name or "unnamed"
        path = os.path.join(self.translations_dir, f"{name}_translated.json")
        from dataclasses import asdict
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(result), f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="项目规则翻译器")
    parser.add_argument("--file", "-f", help="从文件读取规则文本")
    parser.add_argument("--text", "-t", help="直接输入文本")
    parser.add_argument("--program", "-p", default="", help="项目名称")
    parser.add_argument("--term", help="翻译单个术语")
    parser.add_argument("--demo", action="store_true", help="演示")
    args = parser.parse_args()

    pt = ProgramTranslator()

    if args.term:
        print(f"\n  {args.term} → {pt.translate_term(args.term)}")
    elif args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
        pt.translate_policy(text, program_name=args.program)
    elif args.text:
        pt.translate_policy(args.text, program_name=args.program)
    elif args.demo:
        demo_text = """
In Scope:
- *.syfe.com
- api.syfe.com
- mobile app (iOS/Android)

Out of Scope:
- admin.syfe.com
- Third-party services

Non-Qualifying Vulnerabilities:
- Self-XSS
- Logout CSRF
- Missing security headers (CSP, X-Frame-Options, etc.)
- Clickjacking without demonstrated impact
- Open redirect without a chain to account takeover
- Rate limiting issues
- Email spoofing (SPF/DKIM/DMARC)
- Scanner output without manual verification
- Theoretical vulnerabilities without proof of concept

Rules:
- Do not attempt brute force attacks
- Do not perform denial of service testing
- Only use test accounts provided by the program
- Do not access real user data
- Maximum 2 requests per second
- Reports must include proof of concept
"""
        pt.translate_policy(demo_text, program_name="syfe_demo")
    else:
        parser.print_help()
