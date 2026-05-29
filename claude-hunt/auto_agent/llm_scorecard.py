#!/usr/bin/env python3
"""
LLM Scorecard — 模型可靠性追踪
移植自 Raptor 框架的 Model Reliability Tracking

功能：
1. 按决策类型追踪每个模型的准确率
2. Wilson 置信区间计算（小样本也能给出可靠估计）
3. 自动选择最佳模型（基于历史表现）
4. Fast-Tier 短路（高置信模型直接采信，跳过多模型验证）
5. 模型对比报告

决策类型：
- vuln_detection: 漏洞检测（是否为真正漏洞）
- exploitability: 可利用性判断
- severity_rating: 严重程度评级
- false_positive: 误报识别
- code_analysis: 代码分析准确性
- waf_bypass: WAF 绕过策略选择

用法：
    from llm_scorecard import LLMScorecard
    
    scorecard = LLMScorecard()
    
    # 记录模型表现
    scorecard.record("deepseek-chat", "vuln_detection", correct=True)
    scorecard.record("gpt-4o-mini", "vuln_detection", correct=False)
    
    # 查询最佳模型
    best = scorecard.get_best_model("vuln_detection")
    
    # 是否可以短路（跳过多模型验证）
    if scorecard.can_fast_tier("deepseek-chat", "vuln_detection"):
        # 直接采信该模型结果
        pass
"""

import json
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class ModelScore:
    """单个模型在单个决策类型上的得分"""
    model_id: str = ""
    decision_type: str = ""
    # 统计
    total: int = 0
    correct: int = 0
    # 计算结果
    accuracy: float = 0.0
    wilson_lower: float = 0.0  # Wilson 95% 置信区间下界
    wilson_upper: float = 0.0
    # 元数据
    last_updated: float = 0
    streak: int = 0  # 连续正确数（负数=连续错误）


@dataclass
class ScorecardConfig:
    """Scorecard 配置"""
    # Fast-tier 阈值
    fast_tier_min_samples: int = 10  # 最少样本数才能短路
    fast_tier_min_accuracy: float = 0.85  # 最低准确率
    fast_tier_min_wilson_lower: float = 0.7  # Wilson 下界最低要求
    # 衰减
    decay_enabled: bool = True
    decay_half_life: int = 50  # 半衰期（样本数）
    # 持久化
    save_path: str = "~/.bai-agent/scorecard.json"


# ═══════════════════════════════════════════════════════════════
# 决策类型定义
# ═══════════════════════════════════════════════════════════════

DECISION_TYPES = {
    "vuln_detection": "漏洞检测（是否为真正漏洞）",
    "exploitability": "可利用性判断（是否可实际利用）",
    "severity_rating": "严重程度评级准确性",
    "false_positive": "误报识别能力",
    "code_analysis": "代码分析准确性",
    "waf_bypass": "WAF 绕过策略选择",
    "fix_generation": "修复代码生成质量",
    "recon_quality": "侦察信息分析质量",
}


# ═══════════════════════════════════════════════════════════════
# Wilson Score 计算
# ═══════════════════════════════════════════════════════════════

def wilson_score_interval(successes: int, total: int, confidence: float = 0.95) -> Tuple[float, float]:
    """
    Wilson Score 置信区间
    
    比简单的 successes/total 更可靠，特别是小样本时。
    例：1/1=100% 但 Wilson 下界只有 ~25%（样本太少不可信）
    
    Args:
        successes: 成功次数
        total: 总次数
        confidence: 置信度（默认 95%）
    
    Returns:
        (lower_bound, upper_bound)
    """
    if total == 0:
        return (0.0, 0.0)

    # Z-score for confidence level
    z_map = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_map.get(confidence, 1.96)

    p_hat = successes / total
    n = total

    denominator = 1 + z * z / n
    center = (p_hat + z * z / (2 * n)) / denominator
    spread = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * n)) / n) / denominator

    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)

    return (lower, upper)


# ═══════════════════════════════════════════════════════════════
# LLM Scorecard 主类
# ═══════════════════════════════════════════════════════════════

class LLMScorecard:
    """
    LLM 模型可靠性追踪系统
    
    核心价值：
    - 知道哪个模型擅长什么类型的判断
    - 对高置信模型可以直接采信（省钱省时间）
    - 低置信模型的结果需要交叉验证
    """

    def __init__(self, config: Optional[ScorecardConfig] = None):
        self.config = config or ScorecardConfig()
        # {model_id: {decision_type: ModelScore}}
        self._scores: Dict[str, Dict[str, ModelScore]] = defaultdict(dict)
        # 尝试加载历史数据
        self._load()

    # ─── 记录 ──────────────────────────────────────────

    def record(self, model_id: str, decision_type: str, correct: bool):
        """
        记录一次模型判断结果
        
        Args:
            model_id: 模型标识（如 "deepseek-chat", "gpt-4o-mini"）
            decision_type: 决策类型
            correct: 判断是否正确
        """
        if decision_type not in self._scores[model_id]:
            self._scores[model_id][decision_type] = ModelScore(
                model_id=model_id, decision_type=decision_type
            )

        score = self._scores[model_id][decision_type]
        score.total += 1
        if correct:
            score.correct += 1
            score.streak = max(0, score.streak) + 1
        else:
            score.streak = min(0, score.streak) - 1

        # 重新计算
        score.accuracy = score.correct / score.total if score.total > 0 else 0
        score.wilson_lower, score.wilson_upper = wilson_score_interval(score.correct, score.total)
        score.last_updated = time.time()

        # 自动保存
        self._save()

    def record_batch(self, model_id: str, decision_type: str, results: List[bool]):
        """批量记录"""
        for correct in results:
            self.record(model_id, decision_type, correct)

    # ─── 查询 ──────────────────────────────────────────

    def get_score(self, model_id: str, decision_type: str) -> Optional[ModelScore]:
        """获取模型在特定决策类型上的得分"""
        return self._scores.get(model_id, {}).get(decision_type)

    def get_best_model(self, decision_type: str, min_samples: int = 5) -> Optional[str]:
        """
        获取某决策类型上表现最好的模型
        
        使用 Wilson 下界排序（保守估计，避免小样本偏差）
        """
        candidates = []
        for model_id, scores in self._scores.items():
            if decision_type in scores:
                score = scores[decision_type]
                if score.total >= min_samples:
                    candidates.append((score.wilson_lower, model_id))

        if not candidates:
            return None

        candidates.sort(reverse=True)
        return candidates[0][1]

    def get_model_ranking(self, decision_type: str) -> List[Dict]:
        """获取所有模型在某决策类型上的排名"""
        ranking = []
        for model_id, scores in self._scores.items():
            if decision_type in scores:
                score = scores[decision_type]
                ranking.append({
                    "model": model_id,
                    "accuracy": f"{score.accuracy:.1%}",
                    "wilson_lower": f"{score.wilson_lower:.1%}",
                    "wilson_upper": f"{score.wilson_upper:.1%}",
                    "samples": score.total,
                    "streak": score.streak,
                })

        ranking.sort(key=lambda x: float(x["wilson_lower"].rstrip('%')) / 100, reverse=True)
        return ranking

    def can_fast_tier(self, model_id: str, decision_type: str) -> bool:
        """
        判断是否可以对该模型做 Fast-Tier 短路
        
        条件：
        1. 样本数 >= 阈值
        2. 准确率 >= 阈值
        3. Wilson 下界 >= 阈值
        
        如果满足，可以直接采信该模型结果，跳过多模型验证
        """
        score = self.get_score(model_id, decision_type)
        if not score:
            return False

        return (
            score.total >= self.config.fast_tier_min_samples
            and score.accuracy >= self.config.fast_tier_min_accuracy
            and score.wilson_lower >= self.config.fast_tier_min_wilson_lower
        )

    def get_fast_tier_models(self, decision_type: str) -> List[str]:
        """获取可以 Fast-Tier 的所有模型"""
        fast_models = []
        for model_id in self._scores:
            if self.can_fast_tier(model_id, decision_type):
                fast_models.append(model_id)
        return fast_models

    # ─── 报告 ──────────────────────────────────────────

    def generate_report(self) -> str:
        """生成完整的 Scorecard 报告"""
        lines = ["# LLM Scorecard Report", ""]
        lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"追踪模型数: {len(self._scores)}")
        lines.append("")

        for decision_type, description in DECISION_TYPES.items():
            ranking = self.get_model_ranking(decision_type)
            if not ranking:
                continue

            lines.append(f"## {description} ({decision_type})")
            lines.append("")
            lines.append("| 模型 | 准确率 | Wilson 95% CI | 样本数 | 连胜/连败 | Fast-Tier |")
            lines.append("|------|--------|---------------|--------|-----------|-----------|")

            for r in ranking:
                model = r["model"]
                fast = "✓" if self.can_fast_tier(model, decision_type) else ""
                streak_str = f"+{r['streak']}" if r["streak"] > 0 else str(r["streak"])
                lines.append(
                    f"| {model} | {r['accuracy']} | [{r['wilson_lower']}, {r['wilson_upper']}] | {r['samples']} | {streak_str} | {fast} |"
                )
            lines.append("")

        return "\n".join(lines)

    def get_summary(self) -> Dict:
        """获取摘要统计"""
        total_records = sum(
            score.total
            for scores in self._scores.values()
            for score in scores.values()
        )
        models = list(self._scores.keys())
        fast_tier_count = sum(
            1 for model in models
            for dt in DECISION_TYPES
            if self.can_fast_tier(model, dt)
        )

        return {
            "models_tracked": len(models),
            "total_records": total_records,
            "decision_types": len(DECISION_TYPES),
            "fast_tier_eligible": fast_tier_count,
            "models": models,
        }

    # ─── 持久化 ──────────────────────────────────────────

    def _save(self):
        """保存到文件"""
        save_path = os.path.expanduser(self.config.save_path)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        data = {}
        for model_id, scores in self._scores.items():
            data[model_id] = {}
            for dt, score in scores.items():
                data[model_id][dt] = {
                    "total": score.total,
                    "correct": score.correct,
                    "accuracy": score.accuracy,
                    "wilson_lower": score.wilson_lower,
                    "wilson_upper": score.wilson_upper,
                    "streak": score.streak,
                    "last_updated": score.last_updated,
                }

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except IOError:
            pass

    def _load(self):
        """从文件加载"""
        save_path = os.path.expanduser(self.config.save_path)
        if not os.path.exists(save_path):
            return

        try:
            with open(save_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for model_id, scores in data.items():
                for dt, score_data in scores.items():
                    self._scores[model_id][dt] = ModelScore(
                        model_id=model_id,
                        decision_type=dt,
                        total=score_data.get("total", 0),
                        correct=score_data.get("correct", 0),
                        accuracy=score_data.get("accuracy", 0),
                        wilson_lower=score_data.get("wilson_lower", 0),
                        wilson_upper=score_data.get("wilson_upper", 0),
                        streak=score_data.get("streak", 0),
                        last_updated=score_data.get("last_updated", 0),
                    )
        except (IOError, json.JSONDecodeError):
            pass

    def reset(self, model_id: str = "", decision_type: str = ""):
        """重置统计"""
        if model_id and decision_type:
            if model_id in self._scores and decision_type in self._scores[model_id]:
                del self._scores[model_id][decision_type]
        elif model_id:
            if model_id in self._scores:
                del self._scores[model_id]
        else:
            self._scores.clear()
        self._save()


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

# 全局单例
_scorecard_instance: Optional[LLMScorecard] = None

def get_scorecard() -> LLMScorecard:
    """获取全局 Scorecard 实例"""
    global _scorecard_instance
    if _scorecard_instance is None:
        _scorecard_instance = LLMScorecard()
    return _scorecard_instance

def record_model_performance(model_id: str, decision_type: str, correct: bool):
    """快捷记录"""
    get_scorecard().record(model_id, decision_type, correct)

def should_trust_model(model_id: str, decision_type: str) -> bool:
    """判断是否可以直接信任该模型（Fast-Tier）"""
    return get_scorecard().can_fast_tier(model_id, decision_type)
