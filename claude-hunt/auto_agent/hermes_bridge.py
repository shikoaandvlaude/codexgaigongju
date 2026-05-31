#!/usr/bin/env python3
"""
Hermes Bridge — 四层架构编排器 v2 (自进化版)

Hermes (一线渗透) -> 自写skill发现 -> DS审核 (二线) -> Kali MCP (执行层)

新增自进化管道:
  扫描 -> Hermes 追加 [PENDING_REVIEW] 到 skill -> DS 审核 -> [APPROVED]/[REJECTED]
  -> sync_skills.py --merge-approved -> 合并进 SKILL.md

使用:
  python hermes_bridge.py --scan targets.txt           # Hermes 扫描 + 自进化
  python hermes_bridge.py --review hermes_output.json  # 审查 Hermes 输出
  python hermes_bridge.py --discoveries                # 检查所有待审核发现
  python hermes_bridge.py --daily-report               # 生成每日报告
  python hermes_bridge.py --schedule                   # 启动定时调度器(后台)
"""

import json, os, re, sys, time, subprocess, argparse, hashlib
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

HOME = Path.home()
HERMES_CONFIG = HOME / ".hermes"
SKILLS_DIR = HERMES_CONFIG / "skills"
LOGS_DIR = HERMES_CONFIG / "logs"
REPORTS_DIR = Path("D:/hermes-reports")

HERMES_EXE = str(HERMES_CONFIG / "venv" / "Scripts" / "hermes.exe")

# Severity filter: only forward these to Claude Code (save money)
CLAUDE_CODE_THRESHOLD = {"critical", "high", "medium"}

# Skill -> vuln class mapping (for routing discoveries)
SKILL_VULN_MAP = {
    "hermes-idor.md": "idor",
    "hermes-ssrf.md": "ssrf",
    "hermes-xss.md": "xss",
    "hermes-auth.md": "auth",
    "hermes-api.md": "api",
    "hermes-cloud.md": "cloud",
    "hermes-recon.md": "recon",
    "hermes-fingerprint.md": "fingerprint",
    "hermes-chain.md": "chain",
}

PENDING_REVIEW_RE = re.compile(
    r'- \[PENDING_REVIEW\]\s+(\S+)\s+\|\s+(\S+?)\s+\|\s+(.+?)\s+\|\s+(\S+)\s+\|\s+poc:([a-f0-9]{8})'
)

DISCOVERY_BLOCK_RE = re.compile(
    r'- \[PENDING_REVIEW\].*?\n(.*?)(?=\n- \[|## |\Z)',
    re.DOTALL,
)


class HermesBridge:
    def __init__(self):
        self.findings = []
        self.review_queue = []
        self.min_novel_hits = 2

    # ===== 1. 扫描 + 自进化 =====

    def scan_targets(self, targets_file, max_workers=2, auto_skill=True, model=None, provider=None):
        """Hermes 主导扫描，自动发现新技巧->写入skill"""
        targets = Path(targets_file).read_text(encoding="utf-8").strip().split("\n")
        targets = [t.strip() for t in targets if t.strip() and not t.startswith("#")]

        print(f"[Hermes] 开始扫描 {len(targets)} 个目标 (workers={max_workers})...")
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._scan_one, t, auto_skill, model, provider): t for t in targets}
            for f in as_completed(futures):
                target = futures[f]
                try:
                    result = f.result(timeout=600)
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"  [!] {target}: {e}")

        # 保存结果
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = REPORTS_DIR / f"hermes_scan_{timestamp}.json"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        # 检查自进化发现
        if auto_skill:
            discoveries = self._discover_novel_findings(results)
            if discoveries:
                print(f"\n[Evolve] Hermes 发现 {len(discoveries)} 个待审核新技术!")
                self._build_review_queue(discoveries)

        # 推送高危给 Claude Code
        self._forward_critical(results)

        print(f"\n[+] 扫描完成: {output_file}")
        return results

    def _scan_one(self, target, auto_skill, model=None, provider=None):
        """单目标扫描 — 调用 hermes -z oneshot 模式"""
        print(f"  [Hermes] {target}...")

        prompt = self._build_scan_prompt(target, auto_skill)
        result = {"target": target, "timestamp": datetime.now().isoformat(),
                  "findings": [], "skills_generated": [], "raw_output": ""}

        try:
            cmd = [HERMES_EXE, "-z", prompt]
            if model:
                cmd += ["-m", str(model)]
            if provider:
                cmd += ["--provider", str(provider)]

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=300, encoding="utf-8", errors="replace",
                env={**os.environ, "HERMES_YOLO_MODE": "1"},
            )
            result["raw_output"] = proc.stdout[:8000]
            if proc.stderr:
                result["stderr"] = proc.stderr[:2000]

            result["findings"] = self._parse_findings(proc.stdout)
            if result["findings"]:
                print(f"    [+] {len(result['findings'])} 个发现")

        except subprocess.TimeoutExpired:
            print(f"    [!] {target}: 超时 (300s)")
            result["error"] = "timeout"
        except FileNotFoundError:
            print(f"    [!] Hermes CLI 未找到: {HERMES_EXE}")
            result["error"] = "hermes_not_found"
        except Exception as e:
            print(f"    [!] {target}: {e}")
            result["error"] = str(e)[:500]

        return result

    def _build_scan_prompt(self, target, auto_skill):
        """构建 Hermes 扫描提示词 — 包含自进化指令"""
        base = (
            f"Security scan on {target}. "
            f"Load hermes-recon and hermes-fingerprint first. "
            f"Then test the top 5 most likely vulnerability classes based on the tech stack. "
            f"For each test: send actual HTTP requests, observe real responses. "
        )

        if auto_skill:
            base += (
                f"IMPORTANT: Tag any genuinely new technique with is_novel=true and a short novelty_note. "
                f"Do NOT claim novelty for 403/404 noise or theoretical 'could be' findings. "
                f"The bridge will stage only evidence-backed novelty candidates for review. "
            )

        base += (
            f"Output your findings as JSON with: vulnerability_class, endpoint, severity, "
            f"evidence (actual response snippet), and is_novel (true if technique not in skill). "
            f"Do NOT include findings without evidence."
        )
        return base

    def _parse_findings(self, output):
        """从 Hermes 输出中提取 JSON findings"""
        findings = []
        # Try to find JSON block
        json_match = re.search(r'\[[\s\S]*\{[\s\S]*?\}[\s\S]*\]', output)
        if json_match:
            try:
                findings = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        # Fallback: extract individual JSON objects
        if not findings:
            for m in re.finditer(r'\{[^{}]*"vulnerability_class"[^{}]*\}', output):
                try:
                    findings.append(json.loads(m.group(0)))
                except json.JSONDecodeError:
                    continue

        return findings

    def _discover_novel_findings(self, scan_results):
        """Build review candidates from Hermes output instead of letting Hermes edit skills directly."""
        candidates = {}
        technique_hits = {}
        for r in scan_results:
            target = r.get("target", "")
            for f in r.get("findings", []):
                if not f.get("is_novel"):
                    continue
                severity = str(f.get("severity", "info")).lower()
                if severity not in CLAUDE_CODE_THRESHOLD:
                    continue

                technique = (f.get("vulnerability_class") or f.get("technique") or "").strip()
                endpoint = (f.get("endpoint") or f.get("url") or "").strip()
                evidence = (f.get("evidence") or f.get("description") or "")[:300]
                novelty_note = (f.get("novelty_note") or "").strip()
                technique_key = technique or "unknown"
                technique_hits.setdefault(technique_key, set()).add(target)

                fingerprint = hashlib.sha256(
                    f"{target}|{technique}|{endpoint}|{evidence}".encode("utf-8", "ignore")
                ).hexdigest()[:8]
                key = (target, technique, endpoint, fingerprint)

                if key not in candidates:
                    skill_file = next(
                        (name for name, vuln_class in SKILL_VULN_MAP.items()
                         if vuln_class == f.get("vulnerability_class")),
                        "hermes-recon.md",
                    )
                    candidates[key] = {
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "target": target,
                        "technique": technique or "unknown",
                        "vuln_class": f.get("vulnerability_class", "unknown"),
                        "evidence_hash": fingerprint,
                        "skill_file": skill_file,
                        "skill_path": str(SKILLS_DIR / skill_file),
                        "novelty_note": novelty_note,
                        "severity": severity,
                        "endpoint": endpoint,
                    }

        return [
            d for d in candidates.values()
            if len(technique_hits.get(d["technique"], set())) >= self.min_novel_hits
        ]

    # ===== 2. 自进化引擎 =====

    def _check_for_discoveries(self):
        """扫描所有 Hermes skill 文件，提取 [PENDING_REVIEW] 条目"""
        discoveries = []

        if not SKILLS_DIR.exists():
            return discoveries

        for skill_file in SKILLS_DIR.glob("hermes-*.md"):
            content = skill_file.read_text(encoding="utf-8")
            for m in PENDING_REVIEW_RE.finditer(content):
                discoveries.append({
                    "date": m.group(1),
                    "target": m.group(2),
                    "technique": m.group(3).strip(),
                    "vuln_class": m.group(4),
                    "evidence_hash": m.group(5),
                    "skill_file": skill_file.name,
                    "skill_path": str(skill_file),
                })

        discoveries.sort(key=lambda d: d["date"], reverse=True)
        return discoveries

    def _build_review_queue(self, discoveries):
        """将 Hermes 自发现推送到 DS 审核队列"""
        queue_file = REPORTS_DIR / "discovery_review_queue.md"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        existing_ids = set()
        if queue_file.exists():
            for m in re.finditer(r'ID:\s*(\S+)', queue_file.read_text(encoding="utf-8")):
                existing_ids.add(m.group(1))

        new_count = 0
        with open(queue_file, "a", encoding="utf-8") as f:
            for d in discoveries:
                discovery_id = f"{d['skill_file'].replace('.md','')}-{d['evidence_hash']}"
                if discovery_id in existing_ids:
                    continue
                existing_ids.add(discovery_id)

                f.write(f"\n## Discovery: {d['technique'][:80]}\n\n")
                f.write(f"- **ID**: `{discovery_id}`\n")
                f.write(f"- **Status**: PENDING_REVIEW\n")
                f.write(f"- **Date**: {d['date']}\n")
                f.write(f"- **Target**: {d['target']}\n")
                f.write(f"- **Vuln Class**: {d['vuln_class']}\n")
                f.write(f"- **Severity**: {d.get('severity', 'unknown')}\n")
                f.write(f"- **Skill File**: {d['skill_file']}\n")
                if d.get("novelty_note"):
                    f.write(f"- **Novelty Note**: {d['novelty_note']}\n")
                f.write(f"- **Evidence Hash**: {d['evidence_hash']}\n\n")
                f.write(f"### DS Review Checklist\n\n")
                f.write(f"- [ ] 对照 audit-knowledge.md（已知模式？）\n")
                f.write(f"- [ ] 实际可复现？（非理论）\n")
                f.write(f"- [ ] 技术确实不在原 skill 中？\n")
                f.write(f"- [ ] 证据充分？（哈希匹配）\n\n")
                f.write(f"### Verdict\n\n")
                f.write(f"<!-- DS: write [APPROVED] or [REJECTED] with reason -->\n\n")
                f.write(f"---\n")
                skill_path = Path(d["skill_path"])
                if skill_path.exists():
                    existing = skill_path.read_text(encoding="utf-8")
                    marker = f"poc:{d['evidence_hash']}"
                    if marker not in existing:
                        with open(skill_path, "a", encoding="utf-8") as sf:
                            sf.write("\n\n## Hermes 自动发现 (待审核)\n\n")
                            sf.write(
                                f"- [PENDING_REVIEW] {d['date']} | {d['target']} | "
                                f"{d['technique']} | {d['vuln_class']} | poc:{d['evidence_hash']}\n"
                            )
                            if d.get("novelty_note"):
                                sf.write(f"  - note: {d['novelty_note']}\n")
                            sf.write(f"  - severity: {d.get('severity', 'unknown')}\n")
                            sf.write(f"  - endpoint: {d.get('endpoint', '')}\n")
                new_count += 1

        if new_count > 0:
            print(f"  [->] {new_count} 个新发现已加入审核队列: {queue_file}")
            print(f"  [->] 在 Claude Code 中运行: python hermes_bridge.py --review-discoveries")
        else:
            print(f"  [=] 无新发现（所有已存在的均在队列中）")

    def review_discoveries(self):
        """DS 交互式审核 Hermes 自发现"""
        discoveries = self._check_for_discoveries()
        if not discoveries:
            print("[[OK]] 无待审核发现")
            return

        print(f"待审核发现: {len(discoveries)} 个\n")
        for i, d in enumerate(discoveries):
            print(f"{'─'*60}")
            print(f"[{i+1}/{len(discoveries)}] {d['technique'][:100]}")
            print(f"  Skill: {d['skill_file']} | Vuln: {d['vuln_class']}")
            print(f"  Target: {d['target']} | Date: {d['date']}")
            print(f"  Hash: {d['evidence_hash']}")
            print(f"\n  审核操作:")
            print(f"    python hermes_bridge.py --approve {d['evidence_hash']}")
            print(f"    python hermes_bridge.py --reject {d['evidence_hash']} --reason '...'")

    def approve_discovery(self, evidence_hash, reason=""):
        """批准一个发现: [PENDING_REVIEW] -> [APPROVED]"""
        self._update_discovery_status(evidence_hash, "APPROVED", reason)

    def reject_discovery(self, evidence_hash, reason):
        """拒绝一个发现: [PENDING_REVIEW] -> [REJECTED]"""
        if not reason:
            print("[!] --reason 必填（例: '已知模式, audit-knowledge.md #L42'）")
            return
        self._update_discovery_status(evidence_hash, "REJECTED", reason)

    def _update_discovery_status(self, evidence_hash, new_status, reason):
        """更新 skill 文件中 discovery 的状态"""
        updated = 0
        for skill_file in SKILLS_DIR.glob("hermes-*.md"):
            content = skill_file.read_text(encoding="utf-8")
            pattern = rf'- \[PENDING_REVIEW\]\s+(\S+)\s+\|\s+(\S+?)\s+\|\s+(.+?)\s+\|\s+(\S+)\s+\|\s+poc:{re.escape(evidence_hash)}'
            replacement = f'- [{new_status}] \\1 | \\2 | \\3 | \\4 | poc:{evidence_hash}'
            if reason:
                replacement += f' | {new_status.lower()}_reason:{reason[:120]}'

            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                skill_file.write_text(new_content, encoding="utf-8")
                print(f"  [{new_status}] {skill_file.name}: poc:{evidence_hash}")
                if reason:
                    print(f"         原因: {reason}")
                updated += 1

        if updated == 0:
            print(f"  [!] 未找到 poc:{evidence_hash}")
        else:
            print(f"  [+] {updated} 个 skill 已更新")

    # ===== 3. 审查 + 推送 =====

    def _forward_critical(self, scan_results):
        """把高危发现推送给 Claude Code 做深度分析"""
        critical_findings = []
        for r in scan_results:
            for f in r.get("findings", []):
                severity = f.get("severity", "info").lower()
                if severity in CLAUDE_CODE_THRESHOLD:
                    critical_findings.append({**f, "target": r.get("target")})

        if not critical_findings:
            return

        prompt_file = REPORTS_DIR / "claude_analysis_queue.md"
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        with open(prompt_file, "w", encoding="utf-8") as f:
            f.write("# Hermes 高危发现 -> 待 Claude Code 深度分析\n\n")
            f.write(f"生成时间: {datetime.now().isoformat()}\n")
            f.write(f"待分析: {len(critical_findings)} 个发现\n\n---\n\n")

            for i, finding in enumerate(critical_findings):
                f.write(f"## Finding {i+1}: {finding.get('vulnerability_class')}\n")
                f.write(f"- Target: {finding.get('target')}\n")
                f.write(f"- Severity: {finding.get('severity')}\n")
                f.write(f"- Endpoint: {finding.get('endpoint')}\n")
                f.write(f"- Evidence: {finding.get('evidence', 'N/A')[:300]}\n")
                f.write(f"\n### DS 分析任务:\n")
                f.write(f"1. 对照 audit-knowledge.md 判断是否为已知模式\n")
                f.write(f"2. 评估是否可实际利用（非理论漏洞）\n")
                f.write(f"3. 如可确认 -> 生成 PoC\n")
                f.write(f"4. 如为误报 -> 标记原因\n\n")

        print(f"  [->] {len(critical_findings)} 个高危发现已推送: {prompt_file}")

    def review_output(self, hermes_json):
        """读取 Hermes JSON 输出，过滤后标记待 DS 分析"""
        with open(hermes_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            data if isinstance(data, list) else data.get("findings", []),
            key=lambda f: priority.get(f.get("severity", "info"), 99),
        )

        claude_queue = []
        for f in sorted_findings:
            severity = f.get("severity", "info").lower()
            desc = f.get("description", "").lower()
            sc = f.get("status_code", 0)

            if "theoretical" in desc:
                continue
            if sc in [401, 403, 404]:
                continue
            if severity in CLAUDE_CODE_THRESHOLD:
                claude_queue.append(f)

        print(f"  [Filter] {len(claude_queue)} -> DS | {len(sorted_findings) - len(claude_queue)} 跳过")
        if claude_queue:
            prompt_file = REPORTS_DIR / "claude_analysis_queue.md"
            REPORTS_DIR.mkdir(parents=True, exist_ok=True)
            with open(prompt_file, "w", encoding="utf-8") as f:
                f.write("# Hermes 发现 -> 待 DS 深度分析\n\n")
                f.write(f"时间: {datetime.now().isoformat()}\n")
                f.write(f"待分析: {len(claude_queue)} 个\n\n---\n\n")
                for i, finding in enumerate(claude_queue):
                    f.write(f"## Finding {i+1}: {finding.get('vulnerability_class')}\n")
                    f.write(f"- Target: {finding.get('target')}\n")
                    f.write(f"- Severity: {finding.get('severity')}\n")
                    f.write(f"- Endpoint: {finding.get('endpoint')}\n\n")
            print(f"  [->] 队列: {prompt_file}")

    # ===== 4. 每日报告 =====

    def daily_report(self):
        """生成今日扫描 + 自进化汇总"""
        today = datetime.now().strftime("%Y-%m-%d")
        report = REPORTS_DIR / f"daily_report_{today}.md"

        today_pattern = today.replace("-", "")
        today_files = list(REPORTS_DIR.glob(f"hermes_scan_{today_pattern}*.json"))
        total_findings = 0
        critical_high = 0

        for f in today_files:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                items = data if isinstance(data, list) else data.get("findings", [])
                total_findings += len(items)
                critical_high += sum(
                    1 for item in items
                    if item.get("severity") in ("critical", "high")
                )

        discoveries = self._check_for_discoveries()
        pending = [d for d in discoveries]

        with open(report, "w", encoding="utf-8") as f:
            f.write(f"# Hermes 每日扫描报告 — {today}\n\n")
            f.write(f"## 扫描概况\n")
            f.write(f"- 扫描文件: {len(today_files)} 个\n")
            f.write(f"- 总发现: {total_findings}\n")
            f.write(f"- 高危/Critical: {critical_high}\n")
            f.write(f"- 自进化发现: {len(pending)} 个待审核\n\n")
            f.write(f"## 自进化状态\n")
            if pending:
                for d in pending:
                    f.write(f"- [PENDING] `{d['technique'][:80]}` ({d['skill_file']})\n")
            else:
                f.write(f"- 无新发现\n")
            f.write(f"\n## 成本\n")
            f.write(f"- Hermes (DeepSeek): ~$0.01/目标\n")
            f.write(f"- DS 审核: 按需 ~$0.05/审核\n")
            f.write(f"\n## 下一步\n")
            f.write(f"- `python hermes_bridge.py --review-discoveries` 审核发现\n")
            f.write(f"- `python sync_skills.py --merge-approved` 合并到主库\n")

        print(f"[+] 每日报告: {report}")
        return report

    # ===== 5. 定时调度 =====

    def schedule(self):
        """持续运行的定时调度器"""
        print("[Hermes Scheduler] 启动定时调度...")
        print("  每天 02:00 — 自动扫描 (含自进化)")
        print("  每天 07:30 — DS 审核提醒")
        print("  每天 08:00 — 每日报告")

        while True:
            now = datetime.now()
            next_scan = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if now >= next_scan:
                next_scan += timedelta(days=1)
            wait = (next_scan - now).total_seconds()

            print(f"  下次扫描: {next_scan.strftime('%Y-%m-%d %H:%M')} ({wait/3600:.1f}h)")
            time.sleep(min(wait, 3600))


def main():
    parser = argparse.ArgumentParser(description="Hermes Bridge v2 — 四层架构 + 自进化")
    parser.add_argument("--scan", help="Hermes 扫描目标文件")
    parser.add_argument("--workers", type=int, default=2, help="并发数 (默认2)")
    parser.add_argument("--no-evolve", action="store_true", help="禁用自进化")
    parser.add_argument("--hermes-model", help="覆盖 Hermes 模型 (如: claude-opus-4-7, gpt-5.5)")
    parser.add_argument("--hermes-provider", help="覆盖 Hermes provider (如: custom, openrouter)")
    parser.add_argument("--review", help="审查 Hermes JSON 输出")
    parser.add_argument("--review-discoveries", action="store_true", help="审核 Hermes 自发现")
    parser.add_argument("--approve", help="批准发现 (传 evidence_hash)")
    parser.add_argument("--reject", help="拒绝发现 (传 evidence_hash)")
    parser.add_argument("--reason", help="批准/拒绝原因", default="")
    parser.add_argument("--daily-report", action="store_true", help="生成每日报告")
    parser.add_argument("--schedule", action="store_true", help="启动定时调度器")
    args = parser.parse_args()

    bridge = HermesBridge()

    if args.scan:
        bridge.scan_targets(
            args.scan,
            max_workers=args.workers,
            auto_skill=not args.no_evolve,
            model=args.hermes_model,
            provider=args.hermes_provider,
        )
    elif args.review:
        bridge.review_output(args.review)
    elif args.review_discoveries or args.approve or args.reject:
        if args.approve:
            bridge.approve_discovery(args.approve, args.reason)
        elif args.reject:
            bridge.reject_discovery(args.reject, args.reason)
        else:
            bridge.review_discoveries()
    elif args.daily_report:
        bridge.daily_report()
    elif args.schedule:
        bridge.schedule()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
