#!/usr/bin/env python3
"""
Hermes Autopilot — Claude Code 自动启动并编排 Hermes

你只需要打开 Claude Code，这个模块会：
1. 自动检测 Hermes 是否安装/可用
2. 在合适的时机后台启动 Hermes 做批量侦察
3. 收集 Hermes 的发现推回 Claude Code 的上下文
4. 自动同步 skill（Hermes 学到的 → SKILL.md → Claude Code 能用）
5. 利用 Hermes 的持久记忆和 Cron 能力

用法（Claude Code 内部自动调用，你不需要手动跑）：
    from hermes_autopilot import HermesAutopilot
    hp = HermesAutopilot(config)

    # Claude Code 挖洞前，让 Hermes 先做侦察
    recon_data = hp.scout(target)

    # Claude Code 挖洞后，把结果推给 Hermes 进化
    hp.evolve(target, confirmed_findings)

    # 让 Hermes 后台持续监控目标变化
    hp.watch(targets_list)

    # 读取 Hermes 积累的记忆和 skill（跨会话持久）
    memory = hp.recall(target)
"""

import json
import os
import subprocess
import sys
import time
import platform
from pathlib import Path
from datetime import datetime


class HermesAutopilot:
    """
    Claude Code 的 Hermes 自动驾驶员。
    Claude Code 只需要调用这个类，不需要知道 Hermes 的细节。
    """

    def __init__(self, config=None):
        self.config = config or {}
        self.home = Path.home()

        # 自动检测 Hermes 路径（跨平台）
        if platform.system() == "Windows":
            self.hermes_exe = str(self.home / ".hermes" / "venv" / "Scripts" / "hermes.exe")
        else:
            # Linux/Mac: 可能在 venv 或全局
            candidates = [
                str(self.home / ".hermes" / "venv" / "bin" / "hermes"),
                "/usr/local/bin/hermes",
                str(self.home / ".local" / "bin" / "hermes"),
            ]
            self.hermes_exe = next((c for c in candidates if os.path.isfile(c)), "hermes")

        self.skills_dir = self.home / ".hermes" / "skills"
        self.memory_file = self.home / ".hermes" / "memory" / "MEMORY.md"
        self.user_file = self.home / ".hermes" / "memory" / "USER.md"
        self.reports_dir = Path(self.config.get("hermes", {}).get("reports_dir",
                               str(self.home / ".bai-agent" / "hermes-reports")))
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # 状态
        self._available = None
        self._bg_process = None

    # ═══════════════════════════════════════════════════════════════
    #  可用性检测
    # ═══════════════════════════════════════════════════════════════

    def is_available(self) -> bool:
        """检测 Hermes 是否已安装且可用"""
        if self._available is not None:
            return self._available

        try:
            result = subprocess.run(
                [self.hermes_exe, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # 尝试 shell 方式
            try:
                result = subprocess.run(
                    "hermes --version", shell=True,
                    capture_output=True, text=True, timeout=10
                )
                self._available = result.returncode == 0
                if self._available:
                    self.hermes_exe = "hermes"
            except Exception:
                self._available = False

        return self._available

    def get_status(self) -> dict:
        """获取 Hermes 当前状态"""
        status = {
            "installed": self.is_available(),
            "skills_count": 0,
            "memory_exists": self.memory_file.exists(),
            "last_scan": None,
        }

        if self.skills_dir.exists():
            status["skills_count"] = len(list(self.skills_dir.glob("*.md")))

        # 检查最近扫描报告
        if self.reports_dir.exists():
            reports = sorted(self.reports_dir.glob("hermes_scan_*.json"), reverse=True)
            if reports:
                status["last_scan"] = reports[0].stem.replace("hermes_scan_", "")

        return status

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 1: 侦察（Claude Code 挖洞前调用）
    # ═══════════════════════════════════════════════════════════════

    def scout(self, target: str, depth: int = 2) -> dict:
        """
        让 Hermes 对目标做快速侦察，结果返回给 Claude Code 用。
        Claude Code 可以基于这些信息决定挖掘策略。

        返回: {
            "findings": [...],
            "tech_stack": [...],
            "interesting_endpoints": [...],
            "suggested_focus": "...",
        }
        """
        if not self.is_available():
            return {"error": "Hermes 未安装", "findings": []}

        prompt = (
            f"Quick recon on {target}. "
            f"Load hermes-recon and hermes-fingerprint. "
            f"Identify: tech stack, interesting endpoints, potential vuln classes. "
            f"Depth: {depth}. "
            f"Output JSON with: tech_stack[], endpoints[], vuln_suggestions[], "
            f"and one-line suggested_focus string. "
            f"Be fast, no deep exploitation."
        )

        result = self._run_hermes(prompt, timeout=120)

        if not result["success"]:
            return {"error": result.get("output", ""), "findings": []}

        # 解析输出
        parsed = self._parse_json_output(result["output"])
        parsed["raw_output"] = result["output"][:2000]
        return parsed

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 2: 进化（Claude Code 挖洞后调用）
    # ═══════════════════════════════════════════════════════════════

    def evolve(self, target: str, findings: list) -> dict:
        """
        把 Claude Code 确认的漏洞推给 Hermes，让它学习新技巧。
        Hermes 会判断哪些是"新模式"，写入 skill。

        参数:
            target: 目标域名
            findings: 确认的漏洞列表 [{type, url, severity, detail}, ...]

        返回:
            {"new_skills": int, "updated_skills": [...]}
        """
        if not self.is_available():
            return {"new_skills": 0, "note": "Hermes 未安装，经验存储到本地 ExperienceLearner"}

        if not findings:
            return {"new_skills": 0}

        # 构建进化提示
        findings_text = "\n".join([
            f"- [{f.get('severity','?')}] {f.get('type','?')}: {f.get('detail','')[:100]}"
            for f in findings[:10]
        ])

        prompt = (
            f"I just confirmed these vulnerabilities on {target}:\n\n"
            f"{findings_text}\n\n"
            f"Review each finding. For any technique that is NOT already in your loaded skills, "
            f"create a new skill or update an existing one. "
            f"Tag genuinely novel techniques with is_novel=true. "
            f"Output JSON: {{new_skills: [...], updated_skills: [...], already_known: [...]}}"
        )

        result = self._run_hermes(prompt, timeout=90)

        if not result["success"]:
            return {"new_skills": 0, "error": result.get("output", "")}

        parsed = self._parse_json_output(result["output"])
        return parsed

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 3: 后台监控（持续盯目标变化）
    # ═══════════════════════════════════════════════════════════════

    def watch(self, targets: list, interval_hours: int = 12) -> dict:
        """
        让 Hermes 后台持续监控目标列表的变化。
        新增子域名/新接口/新技术栈变化时自动通知。

        参数:
            targets: 目标列表 ["a.com", "b.com"]
            interval_hours: 检查间隔（小时）

        返回:
            {"watching": int, "targets_file": str}
        """
        if not self.is_available():
            return {"error": "Hermes 未安装"}

        # 写目标文件
        targets_file = self.reports_dir / "watch_targets.txt"
        targets_file.write_text("\n".join(targets), encoding="utf-8")

        # 生成 cron 任务脚本
        cron_script = self.reports_dir / "hermes_watch.sh"
        cron_script.write_text(
            f"#!/bin/bash\n"
            f"# Hermes 自动监控 — 每 {interval_hours} 小时\n"
            f"cd {self.reports_dir}\n"
            f"{self.hermes_exe} -z \"Load hermes-recon. "
            f"Compare current scan of targets in {targets_file} with previous results. "
            f"Report only NEW findings (new subdomains, new endpoints, new services). "
            f"Save diff to {self.reports_dir}/watch_diff_$(date +%Y%m%d_%H%M).json\"\n",
            encoding="utf-8"
        )
        os.chmod(str(cron_script), 0o755)

        return {
            "watching": len(targets),
            "targets_file": str(targets_file),
            "cron_script": str(cron_script),
            "instruction": f"添加 cron: 0 */{interval_hours} * * * {cron_script}",
        }

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 4: 读取记忆（Hermes 跨会话持久记忆）
    # ═══════════════════════════════════════════════════════════════

    def recall(self, target: str = "") -> dict:
        """
        读取 Hermes 的持久记忆 — 这是 Claude Code 没有的跨会话记忆。
        包括：之前挖过什么、哪些技巧有效、目标的技术栈等。

        返回:
            {"memory": str, "user_profile": str, "relevant_skills": [...]}
        """
        result = {
            "memory": "",
            "user_profile": "",
            "relevant_skills": [],
            "all_skills": [],
        }

        # 读 MEMORY.md（Hermes 自己写的笔记）
        if self.memory_file.exists():
            result["memory"] = self.memory_file.read_text(encoding="utf-8")[:3000]

        # 读 USER.md（关于你的偏好）
        if self.user_file.exists():
            result["user_profile"] = self.user_file.read_text(encoding="utf-8")[:2000]

        # 列出所有 skill
        if self.skills_dir.exists():
            all_skills = list(self.skills_dir.glob("*.md"))
            result["all_skills"] = [s.stem for s in all_skills]

            # 如果指定了 target，找相关 skill
            if target:
                target_lower = target.lower()
                for skill_file in all_skills:
                    content = skill_file.read_text(encoding="utf-8")[:500]
                    if target_lower in content.lower() or any(
                        kw in skill_file.stem for kw in ['recon', 'idor', 'ssrf', 'xss', 'auth']
                    ):
                        result["relevant_skills"].append({
                            "name": skill_file.stem,
                            "preview": content[:200],
                        })

        # 读最近一次扫描结果
        if self.reports_dir.exists():
            recent_reports = sorted(self.reports_dir.glob("hermes_scan_*.json"), reverse=True)
            if recent_reports:
                try:
                    data = json.loads(recent_reports[0].read_text(encoding="utf-8"))
                    # 找到跟 target 相关的
                    for r in (data if isinstance(data, list) else []):
                        if target and target.lower() in str(r.get("target", "")).lower():
                            result["last_scan_of_target"] = r
                            break
                except Exception:
                    pass

        return result

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 5: 批量扫描（Claude Code 下发任务）
    # ═══════════════════════════════════════════════════════════════

    def batch_scan(self, targets: list, auto_skill: bool = True) -> dict:
        """
        Claude Code 让 Hermes 批量扫描多个目标。
        Hermes 用便宜模型跑，发现高危推回来。

        参数:
            targets: 目标列表
            auto_skill: 是否开启自进化

        返回:
            {"total_findings": int, "critical": [...], "report_file": str}
        """
        if not self.is_available():
            return {"error": "Hermes 未安装"}

        # 写目标文件
        targets_file = self.reports_dir / f"batch_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        targets_file.write_text("\n".join(targets), encoding="utf-8")

        # 调用 hermes_bridge 做批量扫描
        try:
            from hermes_bridge import HermesBridge
            bridge = HermesBridge()
            results = bridge.scan_targets(
                str(targets_file),
                max_workers=2,
                auto_skill=auto_skill,
            )

            # 提取高危
            critical = []
            total = 0
            for r in results:
                for f in r.get("findings", []):
                    total += 1
                    if f.get("severity", "").lower() in ("critical", "high"):
                        critical.append({**f, "target": r.get("target")})

            return {
                "total_findings": total,
                "critical": critical,
                "targets_scanned": len(targets),
                "report_file": str(targets_file).replace(".txt", "_results.json"),
            }

        except Exception as e:
            return {"error": str(e), "total_findings": 0}

    # ═══════════════════════════════════════════════════════════════
    #  核心功能 6: 写入 Hermes 记忆（让 Hermes 记住 Claude Code 的发现）
    # ═══════════════════════════════════════════════════════════════

    def remember(self, note: str) -> bool:
        """
        往 Hermes 的持久记忆里写东西。
        下次不管谁（Claude Code 还是 Hermes）打开，都能看到。

        用途：记录目标信息、有效技巧、注意事项等。
        """
        if not self.is_available():
            # fallback: 写到本地经验文件
            exp_file = Path.home() / ".bai-agent" / "experience" / "manual_notes.md"
            exp_file.parent.mkdir(parents=True, exist_ok=True)
            with open(exp_file, "a", encoding="utf-8") as f:
                f.write(f"\n- [{datetime.now().strftime('%Y-%m-%d %H:%M')}] {note}\n")
            return True

        # 通过 Hermes 写入持久记忆
        prompt = (
            f"Save this to your persistent memory (MEMORY.md): \n\n{note}\n\n"
            f"Acknowledge with 'Saved.'"
        )
        result = self._run_hermes(prompt, timeout=30)
        return result.get("success", False)

    # ═══════════════════════════════════════════════════════════════
    #  内部方法
    # ═══════════════════════════════════════════════════════════════

    def _run_hermes(self, prompt: str, timeout: int = 120) -> dict:
        """执行 Hermes 单次任务（-z oneshot 模式）"""
        try:
            cmd = [self.hermes_exe, "-z", prompt]

            env = {**os.environ, "HERMES_YOLO_MODE": "1"}

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=timeout,
                encoding="utf-8", errors="replace",
                env=env,
            )

            return {
                "success": proc.returncode == 0,
                "output": proc.stdout[:8000],
                "stderr": proc.stderr[:2000] if proc.stderr else "",
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "output": f"Hermes 超时 ({timeout}s)"}
        except FileNotFoundError:
            return {"success": False, "output": f"Hermes 未找到: {self.hermes_exe}"}
        except Exception as e:
            return {"success": False, "output": str(e)}

    def _parse_json_output(self, output: str) -> dict:
        """从 Hermes 输出中提取 JSON"""
        import re

        # 尝试找 JSON 块
        json_match = re.search(r'\{[\s\S]*?\}', output)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        # 尝试找 JSON 数组
        arr_match = re.search(r'\[[\s\S]*?\]', output)
        if arr_match:
            try:
                return {"findings": json.loads(arr_match.group(0))}
            except json.JSONDecodeError:
                pass

        # 回退：返回原始文本
        return {"raw": output[:2000], "findings": []}
