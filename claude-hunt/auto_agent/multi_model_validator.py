#!/usr/bin/env python3
"""
Multi-Model Validator — 多模型交叉验证
移植自 Raptor 框架的 Multi-Model Correlation

核心理念：同一个漏洞发现交给多个 LLM 独立分析，通过 Agreement Matrix
融合结果，显著降低误报率。

特性：
1. 多模型独立分析（互不可见对方结果）
2. Agreement Matrix 计算一致性
3. 置信度融合（加权投票）
4. 分歧检测 + 自动复审
5. 支持 DeepSeek / OpenAI / Anthropic / Ollama

用法：
    from multi_model_validator import MultiModelValidator
    
    validator = MultiModelValidator(models=[
        {"provider": "deepseek", "model": "deepseek-chat", "api_key": "sk-..."},
        {"provider": "openai", "model": "gpt-4o-mini", "api_key": "sk-..."},
    ])
    
    result = await validator.validate_finding(finding)
    print(f"共识: {result.consensus}")
    print(f"置信度: {result.confidence}")
"""

import asyncio
import json
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

class Verdict(str, Enum):
    """验证结论"""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"


@dataclass
class ModelOpinion:
    """单个模型的意见"""
    model_id: str = ""
    provider: str = ""
    verdict: str = ""  # true_positive/false_positive/uncertain
    confidence: float = 0.0  # 0-1
    reasoning: str = ""
    is_exploitable: bool = False
    severity: str = ""
    attack_scenario: str = ""
    # 元数据
    duration_seconds: float = 0
    token_count: int = 0
    cost_usd: float = 0
    error: str = ""


@dataclass
class ValidationResult:
    """多模型验证结果"""
    finding_id: str = ""
    # 共识结果
    consensus: str = ""  # true_positive/false_positive/disputed
    consensus_confidence: float = 0.0
    is_exploitable: bool = False
    final_severity: str = ""
    # 各模型意见
    opinions: List[ModelOpinion] = field(default_factory=list)
    # Agreement Matrix
    agreement_score: float = 0.0  # 0-1, 1=完全一致
    agreement_matrix: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # 分歧信息
    has_dispute: bool = False
    dispute_summary: str = ""
    unique_insights: List[str] = field(default_factory=list)
    # 统计
    models_used: int = 0
    total_cost_usd: float = 0
    total_duration: float = 0


@dataclass
class ModelConfig:
    """模型配置"""
    id: str = ""
    provider: str = "deepseek"  # deepseek/openai/anthropic/ollama
    model: str = "deepseek-chat"
    api_key: str = ""
    base_url: str = ""
    weight: float = 1.0  # 投票权重
    role: str = "analysis"  # analysis/consensus/judge


# ═══════════════════════════════════════════════════════════════
# 验证提示词
# ═══════════════════════════════════════════════════════════════

VALIDATION_PROMPT = """你是安全漏洞验证专家。请独立分析以下漏洞发现的真实性。

## 漏洞信息
- ID: {finding_id}
- 类型: {vuln_type}
- 位置: {url}
- 参数: {parameter}
- 描述: {description}
- 证据: {evidence}
- Payload: {payload}

## 分析要求
请从以下维度评估：
1. 这是真正的漏洞还是误报？
2. 如果是真实漏洞，严重程度如何？
3. 是否可以被外部攻击者利用？
4. 具体的攻击场景是什么？

## 输出格式（严格 JSON）
{{
    "verdict": "true_positive 或 false_positive 或 uncertain",
    "confidence": 0.0到1.0之间的数字,
    "is_exploitable": true或false,
    "severity": "critical/high/medium/low/info",
    "reasoning": "你的分析推理过程（2-3句话）",
    "attack_scenario": "如果可利用，描述攻击场景",
    "missed_considerations": "其他分析者可能忽略的点"
}}
"""

JUDGE_PROMPT = """你是高级安全评审。多个分析模型对同一个漏洞给出了不同意见。请做最终裁决。

## 漏洞信息
{finding_info}

## 各模型意见
{opinions_text}

## 你的任务
1. 分析各方论据的合理性
2. 指出每个意见的优缺点
3. 给出你的最终裁决

## 输出格式（严格 JSON）
{{
    "final_verdict": "true_positive 或 false_positive",
    "confidence": 0.0到1.0,
    "reasoning": "综合各方意见后的最终判断",
    "key_factor": "决定性因素是什么",
    "dissent_valid": true或false（少数派意见是否有价值）
}}
"""


# ═══════════════════════════════════════════════════════════════
# Multi-Model Validator 主类
# ═══════════════════════════════════════════════════════════════

class MultiModelValidator:
    """
    多模型交叉验证引擎
    
    工作流：
    1. 将漏洞发现独立发给 N 个模型
    2. 收集各模型独立意见
    3. 计算 Agreement Matrix
    4. 如有分歧，启动 Judge 模型裁决
    5. 输出融合后的最终结论
    """

    def __init__(
        self,
        models: List[Dict] = None,
        judge_model: Optional[Dict] = None,
        consensus_threshold: float = 0.7,
        dispute_threshold: float = 0.5,
    ):
        self.models: List[ModelConfig] = []
        self.judge: Optional[ModelConfig] = None
        self.consensus_threshold = consensus_threshold
        self.dispute_threshold = dispute_threshold

        # 解析模型配置
        for m in (models or []):
            cfg = ModelConfig(
                id=m.get("id", f"{m.get('provider', 'unknown')}_{m.get('model', 'unknown')}"),
                provider=m.get("provider", "deepseek"),
                model=m.get("model", "deepseek-chat"),
                api_key=m.get("api_key", ""),
                base_url=m.get("base_url", ""),
                weight=m.get("weight", 1.0),
            )
            self.models.append(cfg)

        if judge_model:
            self.judge = ModelConfig(**judge_model)

    async def validate_finding(self, finding: Dict) -> ValidationResult:
        """
        对单个漏洞发现进行多模型验证
        
        Args:
            finding: 漏洞发现字典（兼容 auto_hunt findings 格式）
        """
        start = time.time()
        result = ValidationResult(finding_id=finding.get("id", ""))

        if not self.models:
            # 无模型配置，直接返回
            result.consensus = "uncertain"
            result.consensus_confidence = 0.0
            return result

        # Step 1: 并行发给所有模型
        prompt = self._build_prompt(finding)
        opinions = await asyncio.gather(
            *[self._query_model(model, prompt) for model in self.models],
            return_exceptions=True
        )

        # 收集有效意见
        for i, opinion in enumerate(opinions):
            if isinstance(opinion, Exception):
                result.opinions.append(ModelOpinion(
                    model_id=self.models[i].id,
                    error=str(opinion),
                ))
            elif opinion:
                result.opinions.append(opinion)

        valid_opinions = [o for o in result.opinions if not o.error]
        result.models_used = len(valid_opinions)

        if not valid_opinions:
            result.consensus = "uncertain"
            return result

        # Step 2: 计算 Agreement Matrix
        result.agreement_score = self._calc_agreement(valid_opinions)
        result.agreement_matrix = self._build_agreement_matrix(valid_opinions)

        # Step 3: 判断共识
        verdicts = [o.verdict for o in valid_opinions]
        tp_count = verdicts.count("true_positive")
        fp_count = verdicts.count("false_positive")
        total = len(verdicts)

        tp_ratio = tp_count / total
        fp_ratio = fp_count / total

        if tp_ratio >= self.consensus_threshold:
            result.consensus = "true_positive"
            result.consensus_confidence = tp_ratio
            result.is_exploitable = any(o.is_exploitable for o in valid_opinions)
        elif fp_ratio >= self.consensus_threshold:
            result.consensus = "false_positive"
            result.consensus_confidence = fp_ratio
        else:
            result.has_dispute = True
            result.consensus = "disputed"
            result.consensus_confidence = max(tp_ratio, fp_ratio)

        # Step 4: 融合严重程度（取多数派）
        severities = [o.severity for o in valid_opinions if o.severity]
        if severities:
            from collections import Counter
            result.final_severity = Counter(severities).most_common(1)[0][0]

        # Step 5: 提取独特见解
        result.unique_insights = self._extract_unique_insights(valid_opinions)

        # Step 6: 分歧时启动 Judge
        if result.has_dispute and self.judge:
            judge_result = await self._run_judge(finding, valid_opinions)
            if judge_result:
                result.consensus = judge_result.get("final_verdict", result.consensus)
                result.consensus_confidence = judge_result.get("confidence", result.consensus_confidence)
                result.dispute_summary = judge_result.get("reasoning", "")

        # 统计
        result.total_cost_usd = sum(o.cost_usd for o in result.opinions)
        result.total_duration = time.time() - start

        return result

    async def validate_batch(self, findings: List[Dict], max_concurrent: int = 3) -> List[ValidationResult]:
        """批量验证（带并发限制）"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def limited(finding):
            async with semaphore:
                return await self.validate_finding(finding)

        return await asyncio.gather(*[limited(f) for f in findings])

    # ─── 内部方法 ──────────────────────────────────────────

    def _build_prompt(self, finding: Dict) -> str:
        """构建验证提示词"""
        return VALIDATION_PROMPT.format(
            finding_id=finding.get("id", "unknown"),
            vuln_type=finding.get("type", finding.get("vuln_type", "unknown")),
            url=finding.get("url", "N/A"),
            parameter=finding.get("parameter", finding.get("param", "N/A")),
            description=finding.get("description", finding.get("title", "N/A")),
            evidence=finding.get("evidence", "N/A")[:500],
            payload=finding.get("payload", "N/A")[:200],
        )

    async def _query_model(self, model: ModelConfig, prompt: str) -> Optional[ModelOpinion]:
        """查询单个模型"""
        start = time.time()
        opinion = ModelOpinion(model_id=model.id, provider=model.provider)

        try:
            response = await self._call_llm(model, prompt)
            if not response:
                opinion.error = "Empty response"
                return opinion

            # 解析 JSON 响应
            parsed = self._parse_json_response(response)
            if parsed:
                opinion.verdict = parsed.get("verdict", "uncertain")
                opinion.confidence = float(parsed.get("confidence", 0.5))
                opinion.is_exploitable = parsed.get("is_exploitable", False)
                opinion.severity = parsed.get("severity", "medium")
                opinion.reasoning = parsed.get("reasoning", "")
                opinion.attack_scenario = parsed.get("attack_scenario", "")
            else:
                opinion.error = "Failed to parse response"

            opinion.duration_seconds = time.time() - start

        except Exception as e:
            opinion.error = str(e)
            opinion.duration_seconds = time.time() - start

        return opinion

    async def _run_judge(self, finding: Dict, opinions: List[ModelOpinion]) -> Optional[Dict]:
        """运行 Judge 模型裁决分歧"""
        if not self.judge:
            return None

        opinions_text = "\n\n".join([
            f"### 模型 {o.model_id}\n- 结论: {o.verdict}\n- 置信度: {o.confidence}\n- 推理: {o.reasoning}"
            for o in opinions
        ])

        prompt = JUDGE_PROMPT.format(
            finding_info=json.dumps(finding, ensure_ascii=False, indent=2)[:1000],
            opinions_text=opinions_text,
        )

        response = await self._call_llm(self.judge, prompt)
        return self._parse_json_response(response) if response else None

    def _calc_agreement(self, opinions: List[ModelOpinion]) -> float:
        """计算一致性分数"""
        if len(opinions) < 2:
            return 1.0

        verdicts = [o.verdict for o in opinions]
        from collections import Counter
        most_common_count = Counter(verdicts).most_common(1)[0][1]
        return most_common_count / len(verdicts)

    def _build_agreement_matrix(self, opinions: List[ModelOpinion]) -> Dict:
        """构建 Agreement Matrix"""
        matrix = {}
        for i, o1 in enumerate(opinions):
            row = {}
            for j, o2 in enumerate(opinions):
                if i == j:
                    row[o2.model_id] = "self"
                elif o1.verdict == o2.verdict:
                    row[o2.model_id] = "agree"
                else:
                    row[o2.model_id] = "disagree"
            matrix[o1.model_id] = row
        return matrix

    def _extract_unique_insights(self, opinions: List[ModelOpinion]) -> List[str]:
        """提取各模型的独特见解"""
        insights = []
        seen_points = set()

        for o in opinions:
            # 从 attack_scenario 中提取
            if o.attack_scenario and o.attack_scenario not in seen_points:
                key = hashlib.md5(o.attack_scenario.encode()).hexdigest()[:8]
                if key not in seen_points:
                    seen_points.add(key)
                    insights.append(f"[{o.model_id}] {o.attack_scenario[:150]}")

        return insights[:5]

    def _parse_json_response(self, text: str) -> Optional[Dict]:
        """从 LLM 响应中提取 JSON"""
        if not text:
            return None

        # 尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 提取 JSON 块
        json_match = re.search(r'\{[\s\S]*?\}', text)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return None

    async def _call_llm(self, model: ModelConfig, prompt: str) -> str:
        """调用 LLM API"""
        api_key = model.api_key
        if not api_key:
            return ""

        # 确定 base_url
        base_url = model.base_url
        if not base_url:
            urls = {
                "deepseek": "https://api.deepseek.com/v1",
                "openai": "https://api.openai.com/v1",
                "anthropic": "https://api.anthropic.com",
                "ollama": "http://localhost:11434/v1",
            }
            base_url = urls.get(model.provider, "https://api.deepseek.com/v1")

        try:
            import httpx
            async with httpx.AsyncClient(timeout=60) as client:
                if model.provider == "anthropic":
                    # Anthropic 格式
                    resp = await client.post(
                        f"{base_url}/v1/messages",
                        headers={
                            "x-api-key": api_key,
                            "anthropic-version": "2023-06-01",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model.model,
                            "max_tokens": 2048,
                            "messages": [{"role": "user", "content": prompt}],
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return data.get("content", [{}])[0].get("text", "")
                else:
                    # OpenAI 兼容格式（DeepSeek/OpenAI/Ollama）
                    resp = await client.post(
                        f"{base_url}/chat/completions",
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": model.model,
                            "messages": [
                                {"role": "system", "content": "你是安全漏洞验证专家。严格按 JSON 格式输出。"},
                                {"role": "user", "content": prompt},
                            ],
                            "temperature": 0.2,
                            "max_tokens": 2048,
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return data["choices"][0]["message"]["content"]
        except Exception as e:
            raise RuntimeError(f"LLM call failed ({model.id}): {e}")

        return ""


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

def results_to_findings(results: List[ValidationResult], original_findings: List[Dict]) -> List[Dict]:
    """
    将验证结果合并回 findings（过滤误报，提升置信度）
    
    - consensus=true_positive → 保留，confidence 提升
    - consensus=false_positive → 标记为 false_positive
    - consensus=disputed → 保留但降低 confidence
    """
    output = []
    result_map = {r.finding_id: r for r in results}

    for finding in original_findings:
        fid = finding.get("id", "")
        vr = result_map.get(fid)

        if not vr:
            output.append(finding)
            continue

        updated = dict(finding)
        updated["multi_model_validated"] = True
        updated["agreement_score"] = vr.agreement_score
        updated["models_used"] = vr.models_used

        if vr.consensus == "true_positive":
            updated["confidence"] = "high"
            updated["verified"] = True
            if vr.is_exploitable:
                updated["verified_4proof"] = True
            if vr.final_severity:
                updated["severity"] = vr.final_severity
            output.append(updated)
        elif vr.consensus == "false_positive":
            updated["false_positive"] = True
            updated["is_fp"] = True
            updated["fp_reason"] = vr.dispute_summary or "Multi-model consensus: false positive"
            # 不加入输出（过滤掉）
        elif vr.consensus == "disputed":
            updated["confidence"] = "medium"
            updated["disputed"] = True
            updated["dispute_summary"] = vr.dispute_summary
            output.append(updated)
        else:
            output.append(updated)

    return output


async def run_multi_model_validation(
    findings: List[Dict],
    models: List[Dict],
    judge_model: Optional[Dict] = None,
    max_concurrent: int = 3,
) -> Tuple[List[Dict], List[ValidationResult]]:
    """
    一键多模型验证入口
    
    Args:
        findings: auto_hunt 的漏洞列表
        models: 模型配置列表
        judge_model: 裁判模型（可选）
        max_concurrent: 最大并发数
    
    Returns:
        (filtered_findings, validation_results)
    """
    validator = MultiModelValidator(
        models=models,
        judge_model=judge_model,
    )

    results = await validator.validate_batch(findings, max_concurrent)
    filtered = results_to_findings(results, findings)

    return filtered, results
