#!/usr/bin/env python3
"""
Red Team Reporter — 红队报告生成模块

生成标准红队/HVV 演练报告，包含攻击路径、截图证据、得分统计。

用法：
    from redteam_reporter import RedTeamReporter
    rr = RedTeamReporter()
    rr.add_finding(...)
    report = rr.generate()
"""

import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class AttackPath:
    """攻击路径"""
    step: int = 0
    action: str = ""
    target: str = ""
    result: str = ""
    evidence: str = ""
    timestamp: str = ""
    tools_used: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """红队发现"""
    title: str = ""
    category: str = ""  # 外网突破/内网横向/域控/靶标
    severity: str = ""  # critical/high/medium/low
    target: str = ""
    description: str = ""
    attack_path: List[AttackPath] = field(default_factory=list)
    evidence_files: List[str] = field(default_factory=list)
    score: int = 0
    timestamp: str = ""


class RedTeamReporter:
    """红队报告生成器"""

    def __init__(self, team_name="Red Team", engagement=""):
        self.team_name = team_name
        self.engagement = engagement
        self.findings: List[Finding] = []
        self.attack_paths: List[AttackPath] = []
        self.timeline: List[Dict] = []
        self.start_time = time.strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, title: str, category: str, severity: str,
                    target: str, description: str, score=0,
                    evidence: List[str] = None) -> Finding:
        """添加发现"""
        finding = Finding(
            title=title, category=category, severity=severity,
            target=target, description=description, score=score,
            evidence_files=evidence or [],
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.findings.append(finding)
        self.timeline.append({
            "time": finding.timestamp,
            "action": f"[{category}] {title}",
            "target": target,
        })
        return finding

    def add_path_step(self, action: str, target: str, result: str,
                      evidence: str = "", tools: List[str] = None):
        """添加攻击路径步骤"""
        step = AttackPath(
            step=len(self.attack_paths) + 1,
            action=action, target=target, result=result,
            evidence=evidence, tools_used=tools or [],
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        self.attack_paths.append(step)

    def calculate_score(self) -> Dict:
        """计算总得分（HVV 评分标准）"""
        score_map = {
            "外网突破": {"critical": 500, "high": 300, "medium": 100},
            "内网横向": {"critical": 400, "high": 200, "medium": 100},
            "域控": {"critical": 1000, "high": 500, "medium": 200},
            "靶标": {"critical": 2000, "high": 1000, "medium": 500},
            "数据获取": {"critical": 800, "high": 400, "medium": 200},
            "社工钓鱼": {"critical": 300, "high": 200, "medium": 100},
        }
        total = 0
        breakdown = {}
        for f in self.findings:
            cat_scores = score_map.get(f.category, {})
            pts = f.score or cat_scores.get(f.severity, 0)
            total += pts
            breakdown[f.category] = breakdown.get(f.category, 0) + pts

        return {"total": total, "breakdown": breakdown,
                "findings_count": len(self.findings)}


    def generate(self, format="markdown") -> str:
        """生成报告"""
        if format == "markdown":
            return self._gen_markdown()
        elif format == "json":
            return self._gen_json()
        return self._gen_markdown()

    def _gen_markdown(self) -> str:
        """生成 Markdown 格式报告"""
        score = self.calculate_score()

        report = f"""# 红队演练报告

## 基本信息

| 项目 | 内容 |
|------|------|
| 红队名称 | {self.team_name} |
| 演练名称 | {self.engagement} |
| 开始时间 | {self.start_time} |
| 报告时间 | {time.strftime("%Y-%m-%d %H:%M:%S")} |
| 总得分 | **{score['total']}** |
| 发现数量 | {score['findings_count']} |

## 得分明细

| 类别 | 得分 |
|------|------|
"""
        for cat, pts in score.get("breakdown", {}).items():
            report += f"| {cat} | {pts} |\n"
        report += f"| **总计** | **{score['total']}** |\n"

        # 攻击路径
        report += f"""
## 攻击路径

```
"""
        for step in self.attack_paths:
            tools_str = f" [{', '.join(step.tools_used)}]" if step.tools_used else ""
            report += f"Step {step.step}: {step.action} → {step.target}{tools_str}\n"
            report += f"         结果: {step.result}\n\n"
        report += "```\n"

        # 详细发现
        report += "\n## 详细发现\n\n"
        for i, f in enumerate(self.findings, 1):
            report += f"""### {i}. [{f.severity.upper()}] {f.title}

| 项目 | 内容 |
|------|------|
| 类别 | {f.category} |
| 目标 | {f.target} |
| 严重性 | {f.severity} |
| 得分 | {f.score} |
| 时间 | {f.timestamp} |

**描述：** {f.description}

"""
            if f.evidence_files:
                report += "**证据：**\n"
                for ev in f.evidence_files:
                    report += f"- {ev}\n"
            report += "\n---\n\n"

        # 时间线
        report += "## 攻击时间线\n\n"
        report += "| 时间 | 动作 | 目标 |\n|------|------|------|\n"
        for t in self.timeline:
            report += f"| {t['time']} | {t['action']} | {t['target']} |\n"

        # 修复建议
        report += """
## 修复建议

1. 外网暴露面收敛：关闭不必要的对外服务和端口
2. 补丁管理：及时修复高危漏洞
3. 内网分段：限制横向移动路径
4. 域安全加固：Kerberos 策略、特权账户管理
5. 日志监控：部署 SIEM，检测异常行为
6. 员工安全意识：定期社工演练

---

*本报告仅供授权安全演练使用*
"""
        return report

    def _gen_json(self) -> str:
        """生成 JSON 格式"""
        score = self.calculate_score()
        data = {
            "team": self.team_name,
            "engagement": self.engagement,
            "start_time": self.start_time,
            "report_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "score": score,
            "findings": [
                {
                    "title": f.title, "category": f.category,
                    "severity": f.severity, "target": f.target,
                    "description": f.description, "score": f.score,
                    "timestamp": f.timestamp,
                }
                for f in self.findings
            ],
            "attack_path": [
                {
                    "step": s.step, "action": s.action,
                    "target": s.target, "result": s.result,
                    "tools": s.tools_used,
                }
                for s in self.attack_paths
            ],
            "timeline": self.timeline,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def save(self, output_path: str, format="markdown"):
        """保存报告到文件"""
        content = self.generate(format)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return {"saved": output_path, "size": len(content)}
