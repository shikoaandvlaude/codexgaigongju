#!/usr/bin/env python3
"""
SKILL.md → Hermes 种子 Skill 转换器

从 claude-hunt/SKILL.md (1223行) 提取9大模块，
转换为 Hermes Agent 可读取的 skill 格式。

输出目录: ~/.hermes/skills/
"""
import re, os, sys, yaml
from pathlib import Path

CLAUDE_HUNT = Path(__file__).resolve().parent.parent.parent
SKILL_MD = CLAUDE_HUNT / "SKILL.md"
HERMES_SKILLS = Path.home() / ".hermes" / "skills"

# 9个种子 skill 定义: (slug, name, description, start_marker, end_marker)
SEEDS = [
    ("recon", "Web2资产侦查",
     "Subdomain enumeration, asset discovery, fingerprinting, URL crawling, JS analysis, cloud asset enumeration",
     "# PHASE 1: RECON", "# PHASE 2: LEARN"),

    ("idor", "IDOR检测",
     "10 IDOR variants — sequential IDs, UUIDs, encoded hashes, batch operations, nested resources, role switching, cross-tenant, bulk operations, graph traversal, race conditions",
     "## IDOR -- Insecure Direct Object Reference", "## SSRF"),

    ("ssrf", "SSRF检测与绕过",
     "SSRF variants, bypass techniques, cloud metadata exfiltration, blind SSRF detection",
     "## SSRF", "## XSS"),

    ("xss", "XSS检测",
     "Stored/reflected/DOM XSS, CSP bypass, postMessage XSS, prototype pollution XSS",
     "## XSS", "## Auth / OAuth"),

    ("auth", "认证绕过",
     "JWT attacks, OAuth misconfig, session fixation, password reset poisoning, MFA bypass, rate limiting bypass",
     "## Auth / OAuth", "## Race Conditions"),

    ("chain", "漏洞链组合",
     "A→B→C bug chaining methodology, 10 known chain patterns, cluster hunting protocol",
     "## A->B BUG SIGNAL METHOD", "# TOP 1% HACKER MINDSET"),

    ("fingerprint", "技术栈指纹识别",
     "Framework detection, version fingerprinting, quick-win checks per technology stack",
     "## Technology Fingerprinting", "## Source Code Recon"),

    ("api", "API挖掘",
     "GraphQL, REST API fuzzing, endpoint discovery, API version inconsistency exploitation",
     "## API Endpoint Discovery", "## Quick Wins Checklist"),

    ("cloud", "云安全与CI/CD",
     "S3 bucket enumeration, cloud metadata SSRF, CI/CD pipeline attacks, Firebase open read",
     "## Cloud Asset Enumeration", "## Read Disclosed Reports"),
]

HERMES_SKILL_TEMPLATE = """---
name: hermes-{slug}
description: {description}
metadata:
  source: claude-hunt/SKILL.md
  auto_generated: true
  version: "1.0"
  category: penetration-testing
  technique_level: advanced
---

# {name}

> Auto-generated from claude-hunt/SKILL.md (Bai-codeagent v2)
> Category: {category}

## CONTEXT

{context}

## RULES

1. Only flag findings that demonstrate REAL exploitation potential
2. "Could" is not a bug — prove it works or drop it
3. Report must include: vulnerable request, exploitation proof, impact calculation
4. False positives cost trust — validate before reporting

## TOOLS

{shell_commands}

## DECISION TREE

```
1. Identify target technology stack
2. Match against known vulnerability patterns
3. Execute least-intrusive test first
4. If positive result → escalate to Claude Code for deep analysis
5. If negative → move to next pattern
```

## OUTPUT FORMAT

```json
{{
  "finding_id": "HERMES-{slug}-XXXX",
  "severity": "critical|high|medium|low",
  "vulnerability_class": "{slug}",
  "endpoint": "https://...",
  "exploitation_proof": "HTTP request/response proving impact",
  "recommendation": "Fix suggestion"
}}
```

## SELF-UPDATE

When you discover a new technique or bypass during testing, append it below:

{self_update_section}
"""


def extract_section(content, start_marker, end_marker):
    """Extract content between two markers"""
    start_idx = content.find(start_marker)
    if start_idx == -1:
        return ""
    end_idx = content.find(end_marker, start_idx + len(start_marker))
    if end_idx == -1:
        # Take next 200 lines
        lines = content[start_idx:].split("\n")
        return "\n".join(lines[:200])
    return content[start_idx:end_idx].strip()


def extract_shell_commands(section):
    """Extract bash commands from section for Hermes to reuse"""
    cmds = []
    in_code = False
    for line in section.split("\n"):
        if line.strip().startswith("```"):
            in_code = not in_code
            continue
        if in_code and line.strip() and not line.strip().startswith("#"):
            cmds.append(line)
    return "\n".join(cmds[:80])  # Max 80 commands


def infer_category(slug):
    cats = {
        "recon": "信息收集",
        "idor": "授权漏洞",
        "ssrf": "服务端漏洞",
        "xss": "客户端漏洞",
        "auth": "认证漏洞",
        "chain": "漏洞组合",
        "fingerprint": "信息收集",
        "api": "API安全",
        "cloud": "云安全",
    }
    return cats.get(slug, "通用")


def generate_seed(slug, name, description, start, end):
    """Generate a single Hermes seed skill from SKILL.md"""
    content = SKILL_MD.read_text(encoding="utf-8")
    section = extract_section(content, start, end)
    commands = extract_shell_commands(section)
    category = infer_category(slug)

    # Build self-update section
    self_update = f"""## Discovered Techniques (auto-populated during testing)
<!-- Hermes will append new findings here -->
"""

    return HERMES_SKILL_TEMPLATE.format(
        slug=slug,
        name=name,
        description=description,
        category=category,
        context=section[:3000],  # Truncate, Hermes doesn't need full 1223 lines
        shell_commands=commands or "# Run via Kali MCP: nuclei, ffuf, sqlmap, etc.",
        self_update_section=self_update,
    )


def main():
    if not SKILL_MD.exists():
        print(f"[!] SKILL.md not found at {SKILL_MD}")
        sys.exit(1)

    print(f"[+] Source: {SKILL_MD} ({SKILL_MD.stat().st_size} bytes)")
    print(f"[+] Target: {HERMES_SKILLS}")
    print(f"[+] Generating {len(SEEDS)} seed skills...\n")

    HERMES_SKILLS.mkdir(parents=True, exist_ok=True)

    for slug, name, description, start, end in SEEDS:
        skill_content = generate_seed(slug, name, description, start, end)
        skill_path = HERMES_SKILLS / f"hermes-{slug}.md"

        # Check if skill already exists (don't overwrite Hermes' self-modifications)
        if skill_path.exists():
            existing = skill_path.read_text(encoding="utf-8")
            if "Discovered Techniques" in existing or "hermes-evolve" in str(skill_path):
                print(f"  [SKIP] hermes-{slug}.md (已有自更新内容，保护不覆盖)")
                continue

        skill_path.write_text(skill_content, encoding="utf-8")
        print(f"  [OK] hermes-{slug}.md ({len(skill_content)} chars)")

    print(f"\n[+] Done! {len(list(HERMES_SKILLS.glob('hermes-*.md')))} skills in {HERMES_SKILLS}")


if __name__ == "__main__":
    main()
