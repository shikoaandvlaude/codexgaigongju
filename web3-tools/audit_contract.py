#!/usr/bin/env python3
"""
Web3 Smart Contract Audit Runner — 统一入口

将 GPTLens（LLM 审计）集成为一键审计流程：
  Auditor（找漏洞）→ Critic（验证打分）→ Rank（排序输出）

支持的 LLM 后端（通过环境变量配置）：
  - DeepSeek (最便宜，默认)
  - OpenAI (gpt-4o)
  - Ollama (本地免费)

用法:
    # 审计单个合约文件
    python audit_contract.py --file contract.sol

    # 审计目录下所有 .sol 文件
    python audit_contract.py --dir ./contracts/

    # 从 Etherscan 拉取合约源码并审计
    python audit_contract.py --address 0x1234...abcd --chain eth

    # 指定输出格式
    python audit_contract.py --file contract.sol --output report.md

    # 只跑 Auditor（快速模式，不做 Critic 验证）
    python audit_contract.py --file contract.sol --quick

环境变量:
    DEEPSEEK_API_KEY=sk-xxx     (推荐，最便宜)
    OPENAI_API_KEY=sk-xxx       (备选)
    LLM_MODEL=deepseek-chat     (可覆盖模型)
    ETHERSCAN_API_KEY=xxx       (用于 --address 模式)
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from datetime import datetime

# Add GPTLens src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GPTLENS_SRC = os.path.join(SCRIPT_DIR, "gptlens", "src")
sys.path.insert(0, GPTLENS_SRC)

from model import gpt, gpt_usage, get_config_summary
from prompts import (
    auditor_prompt, auditor_format_constrain,
    critic_zero_shot_prompt, critic_few_shot_prompt, critic_format_constrain,
    topk_prompt1, topk_prompt2,
)


# ═══════════════════════════════════════════════════════════════
# Core Audit Functions
# ═══════════════════════════════════════════════════════════════

def audit_contract(code: str, args) -> list:
    """Phase 1: Auditor — Find vulnerabilities in contract code."""
    prompt = (
        auditor_prompt
        + code
        + auditor_format_constrain
        + topk_prompt1.format(topk=args.topk)
        + topk_prompt2
    )

    print(f"  [Auditor] Analyzing contract ({len(code)} chars)...")
    outputs = gpt(prompt, temperature=args.temperature, n=args.num_auditor)

    findings = []
    for output in outputs:
        try:
            start = output.find("{")
            end = output.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(output[start:end])
                findings.extend(data.get("output_list", []))
        except (json.JSONDecodeError, KeyError):
            continue

    print(f"  [Auditor] Found {len(findings)} potential vulnerabilities")
    return findings


def critique_findings(findings: list, code: str, args) -> list:
    """Phase 2: Critic — Validate and score each finding."""
    if not findings:
        return []

    # Build critic input
    findings_text = json.dumps(findings, indent=2)
    prompt = (
        critic_few_shot_prompt
        + f"\n\nSmart contract code:\n{code[:3000]}\n\n"
        + f"Vulnerabilities to evaluate:\n{findings_text}\n"
        + critic_format_constrain
    )

    print(f"  [Critic] Evaluating {len(findings)} findings...")
    outputs = gpt(prompt, temperature=0.0, n=1)

    scored = []
    for output in outputs:
        try:
            start = output.find("{")
            end = output.rfind("}") + 1
            if start >= 0 and end > start:
                data = json.loads(output[start:end])
                scored.extend(data.get("output_list", []))
        except (json.JSONDecodeError, KeyError):
            continue

    # Merge scores back into findings
    for finding in findings:
        for score in scored:
            if finding.get("function_name") == score.get("function_name"):
                finding["criticism"] = score.get("criticism", "")
                finding["correctness"] = score.get("correctness", 0)
                finding["severity"] = score.get("severity", 0)
                finding["profitability"] = score.get("profitability", 0)
                break

    print(f"  [Critic] Scored {len(scored)} findings")
    return findings


def rank_findings(findings: list) -> list:
    """Phase 3: Rank — Sort by composite score."""
    for f in findings:
        correctness = f.get("correctness", 5)
        severity = f.get("severity", 5)
        profitability = f.get("profitability", 0)
        f["composite_score"] = correctness * 0.4 + severity * 0.35 + profitability * 0.25

    findings.sort(key=lambda x: x.get("composite_score", 0), reverse=True)
    return findings


# ═══════════════════════════════════════════════════════════════
# Etherscan Source Fetch
# ═══════════════════════════════════════════════════════════════

def fetch_contract_source(address: str, chain: str = "eth") -> str:
    """Fetch verified contract source from Etherscan."""
    import requests

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    base_urls = {
        "eth": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
        "polygon": "https://api.polygonscan.com/api",
        "arb": "https://api.arbiscan.io/api",
        "opt": "https://api-optimistic.etherscan.io/api",
        "base": "https://api.basescan.org/api",
    }

    base_url = base_urls.get(chain, base_urls["eth"])
    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }

    resp = requests.get(base_url, params=params, timeout=30)
    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        raise ValueError(f"Failed to fetch contract: {data.get('message', 'Unknown error')}")

    result = data["result"][0]
    source = result.get("SourceCode", "")

    # Handle Solidity multi-file format
    if source.startswith("{{"):
        # JSON format with multiple files
        try:
            sources = json.loads(source[1:-1])  # Remove outer braces
            files = sources.get("sources", {})
            # Concatenate all source files
            parts = []
            for filename, content in files.items():
                parts.append(f"// File: {filename}\n{content.get('content', '')}")
            source = "\n\n".join(parts)
        except json.JSONDecodeError:
            pass
    elif source.startswith("{"):
        try:
            sources = json.loads(source)
            parts = []
            for filename, content in sources.items():
                parts.append(f"// File: {filename}\n{content.get('content', '')}")
            source = "\n\n".join(parts)
        except json.JSONDecodeError:
            pass

    if not source:
        raise ValueError("Contract source code is empty or not verified")

    contract_name = result.get("ContractName", "Unknown")
    print(f"  [Etherscan] Fetched {contract_name} ({len(source)} chars)")
    return source


# ═══════════════════════════════════════════════════════════════
# Report Generation
# ═══════════════════════════════════════════════════════════════

def generate_report(findings: list, contract_name: str, args) -> str:
    """Generate Markdown audit report."""
    usage = gpt_usage()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"# Smart Contract Audit Report",
        f"",
        f"**Contract:** {contract_name}",
        f"**Date:** {timestamp}",
        f"**Tool:** GPTLens + Bai Auto-Hunt Agent",
        f"**LLM:** {usage['provider']}/{usage['model']}",
        f"**Cost:** ${usage['cost_usd']}",
        f"**Findings:** {len(findings)}",
        f"",
        f"---",
        f"",
    ]

    if not findings:
        lines.append("No vulnerabilities detected.")
        return "\n".join(lines)

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| # | Function | Vulnerability | Severity | Correctness | Profitability |")
    lines.append("|---|----------|--------------|----------|-------------|---------------|")

    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | `{f.get('function_name', '?')}` | "
            f"{f.get('vulnerability', '?')} | "
            f"{f.get('severity', '?')}/9 | "
            f"{f.get('correctness', '?')}/9 | "
            f"{f.get('profitability', '?')}/9 |"
        )

    lines.append("")
    lines.append("---")
    lines.append("")

    # Detailed findings
    lines.append("## Detailed Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", 0)
        sev_label = "CRITICAL" if sev >= 8 else "HIGH" if sev >= 6 else "MEDIUM" if sev >= 4 else "LOW"

        lines.append(f"### {i}. [{sev_label}] {f.get('vulnerability', 'Unknown')}")
        lines.append("")
        lines.append(f"**Function:** `{f.get('function_name', '?')}`")
        lines.append(f"**Severity:** {sev}/9 | **Correctness:** {f.get('correctness', '?')}/9 | **Profitability:** {f.get('profitability', '?')}/9")
        lines.append("")

        if f.get("reason"):
            lines.append(f"**Reasoning:** {f['reason']}")
            lines.append("")

        if f.get("criticism"):
            lines.append(f"**Critic Assessment:** {f['criticism']}")
            lines.append("")

        if f.get("code"):
            lines.append("**Vulnerable Code:**")
            lines.append("```solidity")
            lines.append(f['code'][:500])
            lines.append("```")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. Fix all CRITICAL and HIGH severity findings before deployment.")
    lines.append("2. Consider formal verification for financial logic.")
    lines.append("3. Add comprehensive unit tests for edge cases.")
    lines.append("4. Get a manual audit from a professional firm for production contracts.")
    lines.append("")
    lines.append(f"*Report generated by GPTLens + Bai Auto-Hunt Agent. Token usage: {usage['prompt_tokens']} input + {usage['completion_tokens']} output = ${usage['cost_usd']}*")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Web3 Smart Contract Audit — GPTLens + Multi-LLM"
    )
    parser.add_argument("--file", "-f", help="Solidity 文件路径")
    parser.add_argument("--dir", "-d", help="包含 .sol 文件的目录")
    parser.add_argument("--address", "-a", help="合约地址（从 Etherscan 拉取）")
    parser.add_argument("--chain", default="eth",
                        choices=["eth", "bsc", "polygon", "arb", "opt", "base"],
                        help="链 (default: eth)")
    parser.add_argument("--output", "-o", help="输出报告路径 (default: stdout)")
    parser.add_argument("--topk", type=int, default=5, help="每次审计输出 top-k 漏洞")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--num-auditor", type=int, default=1, help="并行审计者数量")
    parser.add_argument("--quick", action="store_true", help="快速模式（跳过 Critic）")
    parser.add_argument("--json", action="store_true", help="输出 JSON 而不是 Markdown")

    args = parser.parse_args()

    # Show config
    config = get_config_summary()
    print(f"\n{'='*60}")
    print(f"  Web3 Smart Contract Audit")
    print(f"  LLM: {config['provider']} / {config['model']}")
    print(f"  API Key: {'✓ configured' if config['api_key_set'] else '✗ MISSING'}")
    print(f"{'='*60}\n")

    if not config["api_key_set"]:
        print("[!] No API key configured!")
        print("    Set: export DEEPSEEK_API_KEY=sk-xxx")
        print("    Or:  export OPENAI_API_KEY=sk-xxx")
        sys.exit(1)

    # Collect source code
    contracts = []  # [(name, code)]

    if args.address:
        code = fetch_contract_source(args.address, args.chain)
        contracts.append((args.address[:10], code))
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        contracts.append((path.stem, path.read_text()))
    elif args.dir:
        dir_path = Path(args.dir)
        sol_files = list(dir_path.glob("**/*.sol"))
        if not sol_files:
            print(f"[!] No .sol files found in {args.dir}")
            sys.exit(1)
        for sf in sol_files[:20]:  # Limit to 20 files
            contracts.append((sf.stem, sf.read_text()))
        print(f"  Found {len(sol_files)} contracts, auditing {len(contracts)}")
    else:
        parser.print_help()
        print("\n[!] 必须指定 --file、--dir 或 --address")
        sys.exit(1)

    # Run audit pipeline
    all_findings = []

    for name, code in contracts:
        print(f"\n{'─'*40}")
        print(f"  Auditing: {name}")
        print(f"{'─'*40}")

        # Phase 1: Auditor
        findings = audit_contract(code, args)

        # Phase 2: Critic (unless --quick)
        if not args.quick and findings:
            findings = critique_findings(findings, code, args)

        # Phase 3: Rank
        findings = rank_findings(findings)

        for f in findings:
            f["contract"] = name

        all_findings.extend(findings)

    # Output
    if args.json:
        output = json.dumps(all_findings, indent=2, ensure_ascii=False)
    else:
        contract_name = contracts[0][0] if len(contracts) == 1 else f"{len(contracts)} contracts"
        output = generate_report(all_findings, contract_name, args)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"\n[+] Report saved: {args.output}")
    else:
        print(f"\n{'='*60}")
        print(output)

    # Print usage summary
    usage = gpt_usage()
    print(f"\n[i] LLM Usage: {usage['prompt_tokens']} input + {usage['completion_tokens']} output tokens = ${usage['cost_usd']}")


if __name__ == "__main__":
    main()
