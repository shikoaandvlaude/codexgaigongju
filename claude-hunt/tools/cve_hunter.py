#!/usr/bin/env python3
"""
CVE/CNVD Hunter — 白盒代码审计 + 通用漏洞挖掘主流程

工作流:
  1. 选目标 CMS/框架（从 cms_targets.yaml 或手动指定 GitHub 地址）
  2. 自动 clone 源码
  3. AI 代码审计（找危险函数调用）
  4. 生成 PoC
  5. 用 FOFA/Shodan 统计受影响资产（不攻击）
  6. 生成 CVE 格式报告（英文）+ CNVD 格式报告（中文）

用法:
  # 从目标列表中选择审计
  python3 cve_hunter.py --list

  # 指定 GitHub 仓库审计
  python3 cve_hunter.py --repo https://github.com/xxx/cms --branch main

  # 审计本地已有源码
  python3 cve_hunter.py --local /path/to/source

  # 指定语言过滤
  python3 cve_hunter.py --repo URL --lang php

  # 完整流程（审计+PoC+资产统计+报告）
  python3 cve_hunter.py --repo URL --full

依赖:
  pip install openai pyyaml rich requests
"""

import argparse
import os
import sys
import subprocess
import json
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    console = Console()
except ImportError:
    class Console:
        def print(self, *a, **k): print(*a)
    console = Console()
    class Prompt:
        @staticmethod
        def ask(msg, default=""): return input(f"{msg} [{default}]: ") or default
    class Confirm:
        @staticmethod
        def ask(msg, default=True): return input(f"{msg} (y/n): ").lower() != 'n'


# ─── 配置 ────────────────────────────────────────────────────────────────────

WORK_DIR = os.path.expanduser("~/.bai-agent/cve-audit")
REPORTS_DIR = os.path.expanduser("~/.bai-agent/cve-reports")
TARGETS_FILE = os.path.join(os.path.dirname(__file__), "cms_targets.yaml")


def ensure_dirs():
    os.makedirs(WORK_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)


def load_targets():
    """加载 cms_targets.yaml"""
    import yaml
    if not os.path.exists(TARGETS_FILE):
        console.print("[red]未找到 cms_targets.yaml[/red]")
        return []
    with open(TARGETS_FILE, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('targets', [])


def clone_repo(repo_url: str, branch: str = None) -> str:
    """Clone 目标仓库到工作目录"""
    repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
    dest = os.path.join(WORK_DIR, repo_name)

    if os.path.exists(dest):
        console.print(f"[yellow]目录已存在: {dest}，跳过 clone[/yellow]")
        return dest

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["-b", branch])
    cmd.extend([repo_url, dest])

    console.print(f"[cyan]Cloning {repo_url}...[/cyan]")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        console.print(f"[red]Clone 失败: {result.stderr}[/red]")
        return ""

    console.print(f"[green]Clone 成功: {dest}[/green]")
    return dest


def run_audit(source_dir: str, lang: str = "auto") -> list:
    """运行代码审计"""
    from code_auditor import CodeAuditor

    auditor = CodeAuditor(source_dir, lang)
    findings = auditor.audit()
    return findings


def generate_poc(finding: dict, source_dir: str) -> str:
    """为单个发现生成 PoC"""
    from poc_generator import PoCGenerator

    generator = PoCGenerator()
    poc = generator.generate(finding, source_dir)
    return poc


def count_assets(fingerprint: str) -> dict:
    """统计受影响资产"""
    from asset_counter import AssetCounter

    counter = AssetCounter()
    result = counter.count(fingerprint)
    return result


def generate_reports(finding: dict, poc: str, asset_count: dict, target_info: dict):
    """生成 CVE + CNVD 双报告"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vuln_type = finding.get('type', 'unknown').replace(' ', '_')

    # CVE 报告（英文）
    cve_path = os.path.join(REPORTS_DIR, f"CVE_{vuln_type}_{timestamp}.md")
    with open(cve_path, 'w', encoding='utf-8') as f:
        f.write(format_cve_report(finding, poc, asset_count, target_info))
    console.print(f"[green]CVE 报告: {cve_path}[/green]")

    # CNVD 报告（中文）
    cnvd_path = os.path.join(REPORTS_DIR, f"CNVD_{vuln_type}_{timestamp}.md")
    with open(cnvd_path, 'w', encoding='utf-8') as f:
        f.write(format_cnvd_report(finding, poc, asset_count, target_info))
    console.print(f"[green]CNVD 报告: {cnvd_path}[/green]")

    return cve_path, cnvd_path


def format_cve_report(finding, poc, asset_count, target_info) -> str:
    """格式化 CVE 英文报告"""
    return f"""# Vulnerability Report

## Summary

- **Product**: {target_info.get('name', 'Unknown')}
- **Version**: {target_info.get('version', 'All')}
- **Vendor**: {target_info.get('vendor', 'Unknown')}
- **Type**: {finding.get('type', 'Unknown')}
- **Severity**: {finding.get('severity', 'High')}
- **CWE**: {finding.get('cwe', 'CWE-Unknown')}

## Description

A {finding.get('type', 'vulnerability')} vulnerability was discovered in {target_info.get('name', 'the application')}.
The vulnerability exists in `{finding.get('file', 'unknown')}` at line {finding.get('line', '?')}.

{finding.get('description', '')}

## Affected Code

```{finding.get('lang', '')}
{finding.get('code_snippet', '')}
```

## Proof of Concept

```
{poc}
```

## Impact

- Affected assets (estimated): {asset_count.get('total', 'Unknown')}
- {finding.get('impact', 'Remote code execution / Data leakage')}

## Remediation

{finding.get('fix_suggestion', 'Update to the latest version or apply the vendor patch.')}

## Timeline

- **Discovered**: {datetime.now().strftime('%Y-%m-%d')}
- **Reported to Vendor**: [FILL]
- **Vendor Response**: [FILL]
- **Public Disclosure**: [FILL]

## References

- {target_info.get('repo_url', '')}
"""


def format_cnvd_report(finding, poc, asset_count, target_info) -> str:
    """格式化 CNVD 中文报告"""
    return f"""# 漏洞报告（CNVD 提交格式）

## 一、漏洞基本信息

| 项目 | 内容 |
|------|------|
| 漏洞名称 | {target_info.get('name', '')} {finding.get('type', '')}漏洞 |
| 影响产品 | {target_info.get('name', '')} |
| 影响版本 | {target_info.get('version', '全版本')} |
| 漏洞类型 | {finding.get('type', '')} |
| 危害等级 | {finding.get('severity', '高危')} |
| CWE 编号 | {finding.get('cwe', '')} |
| 发现日期 | {datetime.now().strftime('%Y-%m-%d')} |

## 二、漏洞描述

{target_info.get('name', '目标系统')}存在{finding.get('type', '')}漏洞。
漏洞位于 `{finding.get('file', '')}` 文件第 {finding.get('line', '?')} 行。

{finding.get('description_cn', finding.get('description', ''))}

## 三、漏洞成因分析

### 问题代码

```{finding.get('lang', '')}
{finding.get('code_snippet', '')}
```

### 分析

{finding.get('root_cause', '未对用户输入进行充分过滤/验证，导致攻击者可以注入恶意内容。')}

## 四、复现步骤

### 环境

- 系统: {target_info.get('name', '')} {target_info.get('version', '')}
- 搭建方式: {target_info.get('setup', 'Docker / 手动部署')}

### PoC

```
{poc}
```

## 五、影响范围

- 互联网受影响资产数（FOFA 统计）: 约 {asset_count.get('total', '未统计')} 个
- 主要分布地区: {asset_count.get('regions', '中国')}

## 六、修复建议

{finding.get('fix_suggestion_cn', finding.get('fix_suggestion', '建议升级到最新版本，或对用户输入进行严格过滤。'))}

## 七、参考信息

- 源码地址: {target_info.get('repo_url', '')}
- 相关 CVE: [如有同步提交 NVD 则填写]

---

> 声明：本漏洞仅用于安全研究目的，已在本地环境复现验证，未对互联网上的真实系统进行攻击。
"""


def show_target_list():
    """展示可审计目标列表"""
    targets = load_targets()
    if not targets:
        console.print("[yellow]目标列表为空，请手动指定 --repo[/yellow]")
        return

    table = Table(title="可审计目标列表")
    table.add_column("序号", style="dim")
    table.add_column("名称", style="cyan")
    table.add_column("语言", style="green")
    table.add_column("类型", style="yellow")
    table.add_column("难度", style="red")
    table.add_column("GitHub")

    for i, t in enumerate(targets, 1):
        table.add_row(
            str(i),
            t.get('name', '?'),
            t.get('lang', '?'),
            t.get('category', '?'),
            t.get('difficulty', '?'),
            t.get('repo', '?')[:50]
        )

    console.print(table)
    return targets


def main():
    parser = argparse.ArgumentParser(description="CVE/CNVD Hunter — 白盒审计自动化")
    parser.add_argument("--list", action="store_true", help="列出可审计目标")
    parser.add_argument("--repo", help="GitHub 仓库 URL")
    parser.add_argument("--branch", default=None, help="分支名")
    parser.add_argument("--local", help="本地源码路径")
    parser.add_argument("--lang", default="auto", help="语言过滤 (php/java/python/go/js)")
    parser.add_argument("--full", action="store_true", help="完整流程（审计+PoC+资产+报告）")
    parser.add_argument("--audit-only", action="store_true", help="只做审计不生成报告")
    args = parser.parse_args()

    ensure_dirs()

    console.print(Panel.fit(
        "[bold cyan]CVE/CNVD Hunter v1.0[/bold cyan]\n"
        "白盒代码审计 → PoC 生成 → 资产统计 → 双报告",
        border_style="cyan"
    ))

    # 列出目标
    if args.list:
        targets = show_target_list()
        if targets:
            choice = Prompt.ask("选择目标编号（或直接输入 GitHub URL）", default="1")
            if choice.startswith("http"):
                args.repo = choice
            else:
                idx = int(choice) - 1
                if 0 <= idx < len(targets):
                    args.repo = targets[idx]['repo']
                    args.lang = targets[idx].get('lang', 'auto')
                    console.print(f"[green]已选择: {targets[idx]['name']}[/green]")

    # 确定源码路径
    source_dir = ""
    target_info = {"name": "Unknown", "repo_url": args.repo or ""}

    if args.local:
        source_dir = args.local
        target_info["name"] = os.path.basename(source_dir)
    elif args.repo:
        source_dir = clone_repo(args.repo, args.branch)
        target_info["name"] = args.repo.rstrip('/').split('/')[-1]
        target_info["repo_url"] = args.repo
    else:
        console.print("[red]请指定 --repo 或 --local 或 --list[/red]")
        sys.exit(1)

    if not source_dir or not os.path.exists(source_dir):
        console.print("[red]源码目录不存在[/red]")
        sys.exit(1)

    # 运行审计
    console.print(f"\n[bold]开始审计: {source_dir}[/bold]\n")
    findings = run_audit(source_dir, args.lang)

    if not findings:
        console.print("[yellow]未发现明显漏洞[/yellow]")
        sys.exit(0)

    # 展示发现
    console.print(f"\n[bold green]发现 {len(findings)} 个潜在漏洞:[/bold green]\n")
    for i, f in enumerate(findings, 1):
        severity_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "dim"}.get(f.get('severity', ''), 'white')
        console.print(f"  {i}. [{severity_color}][{f.get('severity', '?').upper()}][/{severity_color}] "
                      f"{f.get('type', '?')} — {f.get('file', '?')}:{f.get('line', '?')}")
        console.print(f"     {f.get('description', '')[:100]}")

    if args.audit_only:
        # 保存审计结果
        result_path = os.path.join(REPORTS_DIR, f"audit_{target_info['name']}_{datetime.now().strftime('%Y%m%d')}.json")
        with open(result_path, 'w', encoding='utf-8') as fp:
            json.dump({"target": target_info, "findings": findings}, fp, ensure_ascii=False, indent=2)
        console.print(f"\n[green]审计结果已保存: {result_path}[/green]")
        sys.exit(0)

    # 完整流程
    if args.full or Confirm.ask("\n继续生成 PoC + 报告？", default=True):
        for i, finding in enumerate(findings[:5]):  # 最多处理前5个
            console.print(f"\n{'='*50}")
            console.print(f"[bold]处理第 {i+1} 个: {finding.get('type')}[/bold]")
            console.print(f"{'='*50}")

            # 生成 PoC
            console.print("[cyan]生成 PoC...[/cyan]")
            poc = generate_poc(finding, source_dir)
            if poc:
                console.print(f"[green]PoC 已生成[/green]")

            # 资产统计
            fingerprint = finding.get('fingerprint', target_info.get('name', ''))
            console.print(f"[cyan]统计受影响资产 (fingerprint: {fingerprint})...[/cyan]")
            asset_count = count_assets(fingerprint)
            console.print(f"[green]受影响资产: ~{asset_count.get('total', '?')} 个[/green]")

            # 生成报告
            console.print("[cyan]生成 CVE + CNVD 双报告...[/cyan]")
            cve_path, cnvd_path = generate_reports(finding, poc, asset_count, target_info)

    console.print(f"\n[bold green]完成！报告目录: {REPORTS_DIR}[/bold green]")


if __name__ == "__main__":
    main()
