#!/usr/bin/env python3
"""
Skill 双向同步 v2 — 含自进化审核管道

Hermes <-> claude-hunt sync:
  --from-hermes      Hermes [APPROVED] 发现 -> 合并回 SKILL.md
  --to-hermes        SKILL.md 变更 -> 更新 Hermes 种子 skill
  --diff             对比双方差异
  --auto             自动双向同步（仅合入已批准项）

自进化审核:
  --review-pending   列出所有 [PENDING_REVIEW] 发现
  --approve ID       approve: [PENDING_REVIEW] -> [APPROVED]
  --reject ID       reject: [PENDING_REVIEW] -> [REJECTED]
  --merge-approved   将 [APPROVED] 发现合并回 SKILL.md
  --audit-log        查看审核历史
"""

import json, re, sys, argparse
from pathlib import Path
from datetime import datetime, timezone

HOME = Path.home()
HERMES_SKILLS = HOME / ".hermes" / "skills"
CLAUDE_HUNT = Path(__file__).resolve().parent.parent.parent
SKILL_MD = CLAUDE_HUNT / "SKILL.md"
SYNC_LOG = CLAUDE_HUNT / "skills" / "hermes-bridge" / "sync_log.json"

PENDING_REVIEW_RE = re.compile(
    r'- \[(PENDING_REVIEW|APPROVED|REJECTED)\]\s+(\S+)\s+\|\s+(\S+?)\s+\|\s+(.+?)\s+\|\s+(\S+)\s+\|\s+poc:([a-f0-9]{8})'
    r'(?:\s+\|\s+(approved_reason|rejected_reason):(.+))?'
)

CLAUDE_SKILL_MODULES = [
    "bb-methodology", "bug-bounty", "web2-recon", "web2-vuln-classes",
    "triage-validation", "report-writing", "security-arsenal",
    "meme-coin-audit", "web3-audit",
]

KNOWN_SEEDS = {
    "hermes-recon", "hermes-idor", "hermes-ssrf", "hermes-xss",
    "hermes-auth", "hermes-chain", "hermes-fingerprint", "hermes-api",
    "hermes-cloud", "hermes-evolve",
}


def load_sync_log():
    if SYNC_LOG.exists():
        return json.loads(SYNC_LOG.read_text(encoding="utf-8"))
    return {"last_sync": None, "hermes_to_claude": [], "claude_to_hermes": [],
            "audit_trail": []}


def save_sync_log(log):
    log["last_sync"] = datetime.now(timezone.utc).isoformat()
    SYNC_LOG.parent.mkdir(parents=True, exist_ok=True)
    SYNC_LOG.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")


def extract_discoveries_by_status(skill_path, status="APPROVED"):
    """提取指定状态的发现"""
    content = skill_path.read_text(encoding="utf-8")
    discoveries = []
    for m in PENDING_REVIEW_RE.finditer(content):
        if m.group(1) == status:
            discoveries.append({
                "date": m.group(2),
                "target": m.group(3),
                "technique": m.group(4).strip(),
                "vuln_class": m.group(5),
                "evidence_hash": m.group(6),
                "reason": (m.group(8) or "").strip() if m.lastindex and m.lastindex >= 8 else "",
            })
    return discoveries


def from_hermes():
    """Hermes -> SKILL.md: 合并已批准 ([APPROVED]) 的发现"""
    print("[Sync] Hermes -> SKILL.md (仅合并 APPROVED)\n")

    if not HERMES_SKILLS.exists():
        print("  [!] ~/.hermes/skills/ 不存在")
        return

    all_approved = {}
    for skill_file in HERMES_SKILLS.glob("hermes-*.md"):
        approved = extract_discoveries_by_status(skill_file, "APPROVED")
        if approved:
            name = skill_file.stem.replace("hermes-", "")
            all_approved[name] = approved
            print(f"  [APPROVED] {skill_file.name}: {len(approved)} 条")

    if not all_approved:
        print("  [[OK]] 无已批准发现，跳过")
        return

    # 追加到 SKILL.md
    skill_content = SKILL_MD.read_text(encoding="utf-8")
    append_block = "\n\n## Hermes 自动发现 (合并于 {})\n\n".format(
        datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    for category, discoveries in all_approved.items():
        append_block += f"### {category}\n"
        for d in discoveries:
            append_block += f"- [{d['vuln_class']}] {d['technique']} | poc:{d['evidence_hash']} | {d['target']}\n"
        append_block += "\n"

    # 避免重复追加
    if "Hermes 自动发现" in skill_content:
        last_block = skill_content.rfind("## Hermes 自动发现")
        skill_content = skill_content[:last_block]

    SKILL_MD.write_text(skill_content + append_block, encoding="utf-8")
    print(f"  [+] 已追加到 SKILL.md ({sum(len(v) for v in all_approved.values())} 条)")

    log = load_sync_log()
    log["hermes_to_claude"].append({
        "time": datetime.now(timezone.utc).isoformat(),
        "categories": list(all_approved.keys()),
        "total_techniques": sum(len(v) for v in all_approved.values()),
    })
    save_sync_log(log)


def to_hermes():
    """SKILL.md -> Hermes: 重新生成种子 skill"""
    print("[Sync] SKILL.md -> Hermes\n")
    if not HERMES_SKILLS.exists():
        print("  [!] ~/.hermes/skills/ 不存在")
        return

    from seed_converter import main as regenerate
    regenerate()
    print("  [+] 种子 skill 已更新")


def diff():
    """对比 Hermes 和 claude-hunt 差异"""
    print("[Diff] Hermes <-> claude-hunt\n")

    hermes_skills = set()
    if HERMES_SKILLS.exists():
        hermes_skills = {f.stem for f in HERMES_SKILLS.glob("*.md")}

    only_hermes = hermes_skills - KNOWN_SEEDS
    only_claude = KNOWN_SEEDS - hermes_skills

    if only_hermes:
        print(f"  Hermes custom skills ({len(only_hermes)}):")
        for s in only_hermes:
            print(f"    + {s}")
    if only_claude:
        print(f"  未安装种子 ({len(only_claude)}):")
        for s in only_claude:
            print(f"    - {s} (需 python seed_converter.py)")
    if not only_hermes and not only_claude:
        print("  [[OK]] 种子 skill 同步")

    # 统计发现
    total_pending = 0
    total_approved = 0
    total_rejected = 0
    for skill_file in HERMES_SKILLS.glob("hermes-*.md"):
        content = skill_file.read_text(encoding="utf-8")
        for m in PENDING_REVIEW_RE.finditer(content):
            status = m.group(1)
            if status == "PENDING_REVIEW":
                total_pending += 1
            elif status == "APPROVED":
                total_approved += 1
            elif status == "REJECTED":
                total_rejected += 1

    print(f"\n  自进化统计:")
    print(f"    待审核: {total_pending}")
    print(f"    已批准: {total_approved}")
    print(f"    已拒绝: {total_rejected}")


def review_pending():
    """列出所有待审核发现"""
    print("[Review] 待审核发现\n")

    pending = []
    for skill_file in sorted(HERMES_SKILLS.glob("hermes-*.md")):
        for m in PENDING_REVIEW_RE.finditer(skill_file.read_text(encoding="utf-8")):
            if m.group(1) == "PENDING_REVIEW":
                pending.append({
                    "skill": skill_file.name,
                    "date": m.group(2),
                    "target": m.group(3),
                    "technique": m.group(4).strip(),
                    "vuln_class": m.group(5),
                    "hash": m.group(6),
                })

    if not pending:
        print("  [[OK]] 无待审核发现")
        return

    for i, d in enumerate(pending):
        print(f"{'─'*60}")
        print(f"[{i+1}] {d['technique'][:100]}")
        print(f"    Skill: {d['skill']} | Class: {d['vuln_class']}")
        print(f"    Target: {d['target']} | Date: {d['date']}")
        print(f"    Hash: {d['hash']}")
        print(f"    操作: python sync_skills.py --approve {d['hash']}")
        print(f"          python sync_skills.py --reject {d['hash']} --reason '...'")


def update_discovery(hash_val, new_status, reason=""):
    """更新所有 skill 文件中指定 hash 的状态"""
    updated = 0
    for skill_file in HERMES_SKILLS.glob("hermes-*.md"):
        content = skill_file.read_text(encoding="utf-8")
        pattern = (
            r'- \[PENDING_REVIEW\]\s+(\S+)\s+\|\s+(\S+?)\s+\|\s+'
            + re.escape(hash_val[:100]) + r'.*?\|\s+poc:' + re.escape(hash_val)
        )

        # More precise: find the PENDING_REVIEW line with this exact hash
        new_content = content
        for m in re.finditer(
            r'- \[PENDING_REVIEW\]\s+(\S+)\s+\|\s+(\S+?)\s+\|\s+(.+?)\s+\|\s+(\S+)\s+\|\s+poc:('
            + re.escape(hash_val) + r')',
            content,
        ):
            old_line = m.group(0)
            fields = list(m.groups())
            new_line = f"- [{new_status}] {fields[0]} | {fields[1]} | {fields[2]} | {fields[3]} | poc:{hash_val}"
            status_key = "approved_reason" if new_status == "APPROVED" else "rejected_reason"
            if reason:
                new_line += f" | {status_key}:{reason[:120]}"
            new_content = new_content.replace(old_line, new_line, 1)
            updated += 1

        if new_content != content:
            skill_file.write_text(new_content, encoding="utf-8")
            print(f"  [{new_status}] {skill_file.name}: poc:{hash_val}")
            if reason:
                print(f"         原因: {reason}")

    if updated == 0:
        print(f"  [!] 未找到 poc:{hash_val}")
    else:
        audit = load_sync_log()
        audit["audit_trail"].append({
            "time": datetime.now(timezone.utc).isoformat(),
            "hash": hash_val,
            "status": new_status,
            "reason": reason,
        })
        save_sync_log(audit)


def audit_log():
    """查看审核历史"""
    log = load_sync_log()
    trail = log.get("audit_trail", [])
    if not trail:
        print("[Audit] 无审核记录")
        return

    print(f"[Audit] 审核历史 ({len(trail)} 条)\n")
    approved = sum(1 for e in trail if e["status"] == "APPROVED")
    rejected = sum(1 for e in trail if e["status"] == "REJECTED")
    print(f"  批准: {approved} | 拒绝: {rejected}\n")

    for entry in trail[-20:]:
        emoji = "+" if entry["status"] == "APPROVED" else "-"
        print(f"  [{emoji}] {entry['time'][:19]} | {entry['hash']} | {entry.get('reason', 'N/A')[:60]}")


def auto():
    """自动双向同步"""
    print("[Auto Sync] 双向同步中...\n")
    try:
        from_hermes()
    except Exception as e:
        print(f"  [WARN] Hermes -> Claude 失败: {e}")
    try:
        to_hermes()
    except Exception as e:
        print(f"  [WARN] Claude -> Hermes 失败: {e}")
    diff()


def main():
    parser = argparse.ArgumentParser(description="Skill 双向同步 v2 — 含自进化审核")
    parser.add_argument("--from-hermes", action="store_true", help="Hermes [APPROVED] -> SKILL.md")
    parser.add_argument("--to-hermes", action="store_true", help="SKILL.md -> Hermes seeds")
    parser.add_argument("--diff", action="store_true", help="对比差异")
    parser.add_argument("--auto", action="store_true", help="自动双向同步 (仅 APPROVED)")

    parser.add_argument("--review-pending", action="store_true", help="列出待审核发现")
    parser.add_argument("--approve", help="批准发现 (传 evidence_hash)")
    parser.add_argument("--reject", help="拒绝发现 (传 evidence_hash)")
    parser.add_argument("--reason", help="批准/拒绝原因", default="")
    parser.add_argument("--merge-approved", action="store_true", help="合并 APPROVED -> SKILL.md")
    parser.add_argument("--audit-log", action="store_true", help="审核历史")

    args = parser.parse_args()

    if args.approve:
        update_discovery(args.approve, "APPROVED", args.reason)
    elif args.reject:
        if not args.reason:
            print("[!] --reason 必填 (如: '已知模式, audit-knowledge.md #L42')")
            sys.exit(1)
        update_discovery(args.reject, "REJECTED", args.reason)
    elif args.review_pending:
        review_pending()
    elif args.merge_approved:
        from_hermes()
    elif args.audit_log:
        audit_log()
    elif args.from_hermes:
        from_hermes()
    elif args.to_hermes:
        to_hermes()
    elif args.diff:
        diff()
    elif args.auto:
        auto()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()



# ═══ 供 auto_hunt.py 直接调用的 API ═══

def sync_approved_to_skillmd():
    """
    程序化接口：把所有 [APPROVED] 的 Hermes 发现合入 SKILL.md。
    返回合入的条目数量。供 auto_hunt.py 自动调用。
    """
    if not HERMES_SKILLS.exists():
        return 0

    all_approved = {}
    for skill_file in HERMES_SKILLS.glob("hermes-*.md"):
        approved = extract_discoveries_by_status(skill_file, "APPROVED")
        if approved:
            name = skill_file.stem.replace("hermes-", "")
            all_approved[name] = approved

    if not all_approved:
        return 0

    total = sum(len(v) for v in all_approved.values())

    if not SKILL_MD.exists():
        return 0

    skill_content = SKILL_MD.read_text(encoding="utf-8")

    append_block = "\n\n## Hermes 自动发现 (合并于 {})\n\n".format(
        datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    for category, discoveries in all_approved.items():
        append_block += f"### {category}\n"
        for d in discoveries:
            append_block += f"- [{d['vuln_class']}] {d['technique']} | poc:{d['evidence_hash']} | {d['target']}\n"
        append_block += "\n"

    # 避免重复追加
    if "Hermes 自动发现" in skill_content:
        last_block = skill_content.rfind("## Hermes 自动发现")
        skill_content = skill_content[:last_block]

    SKILL_MD.write_text(skill_content + append_block, encoding="utf-8")

    log = load_sync_log()
    log["hermes_to_claude"].append({
        "time": datetime.now(timezone.utc).isoformat(),
        "categories": list(all_approved.keys()),
        "total_techniques": total,
    })
    save_sync_log(log)

    return total
