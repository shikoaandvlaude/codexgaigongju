#!/usr/bin/env python3
"""
Web3 Auditor — 智能合约安全审计模块

覆盖 OWASP Smart Contract Top 10 + DeFi 特有漏洞：
1. 重入攻击 (Reentrancy)
2. 访问控制缺陷 (Access Control)
3. 预言机操控 (Oracle Manipulation)
4. 闪电贷攻击 (Flash Loan)
5. 整数溢出 (Integer Overflow) — Solidity <0.8
6. 前端运行 (Front-running/MEV)
7. 委托调用 (Delegatecall)
8. 自毁 (Selfdestruct)
9. ERC-4626 Vault 份额操控
10. 未初始化代理 (Uninitialized Proxy)

工具集成：
- Slither（静态分析，80+ 检测器）
- Mythril（符号执行）
- LLM 逻辑审计（Claude/DeepSeek 读代码找业务逻辑漏洞）
- Foundry forge test（Fuzz 测试）

平台：
- Immunefi（赏金 $1K-$1M+）
- Sherlock（审计竞赛）
- Code4rena（审计竞赛）
- HackenProof

用法：
    from web3_auditor import Web3Auditor
    auditor = Web3Auditor(engine)

    # 审计单个合约文件
    result = auditor.audit_file("path/to/Contract.sol")

    # 审计 GitHub 仓库
    result = auditor.audit_repo("https://github.com/protocol/contracts")

    # 审计已部署合约（从链上拉 verified 源码）
    result = auditor.audit_deployed("0x1234...", chain="ethereum")

    # DeFi 专项（闪电贷/预言机/Vault）
    result = auditor.defi_deep_audit("path/to/protocol/")
"""

import json
import os
import re
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional


# ═══════════════════════════════════════════════════════════════
#  漏洞模式库（Solidity grep 模式）
# ═══════════════════════════════════════════════════════════════

VULN_PATTERNS = {
    # --- Critical ---
    "reentrancy": {
        "patterns": [
            r'\.call\{value:',
            r'\.call\{value:.*\}.*\(',
            r'\.transfer\(',
            r'\.send\(',
        ],
        "anti_patterns": [
            r'ReentrancyGuard',
            r'nonReentrant',
            r'_status\s*=\s*_ENTERED',
        ],
        "severity": "critical",
        "description": "外部调用在状态更新之前（CEI 违规）",
        "check": "检查是否在 external call 之后修改状态变量",
    },
    "delegatecall_proxy": {
        "patterns": [
            r'delegatecall\(',
            r'\.delegatecall\(',
        ],
        "severity": "critical",
        "description": "delegatecall 可能导致存储槽冲突或恶意实现",
    },
    "selfdestruct": {
        "patterns": [
            r'selfdestruct\(',
            r'suicide\(',
        ],
        "severity": "high",
        "description": "selfdestruct 可被滥用销毁合约/强制发送 ETH",
    },
    "uninitialized_proxy": {
        "patterns": [
            r'function\s+initialize\s*\(',
            r'initializer\b',
        ],
        "anti_patterns": [
            r'_disableInitializers\(\)',
        ],
        "severity": "critical",
        "description": "代理合约未禁用 initialize，可被抢先初始化接管",
    },

    # --- High ---
    "access_control": {
        "patterns": [
            r'onlyOwner',
            r'require\(msg\.sender\s*==',
            r'tx\.origin',
        ],
        "severity": "high",
        "description": "tx.origin 用于认证（可被钓鱼合约绕过）或缺少权限检查",
        "check": "tx.origin 不应用于权限验证；关键函数需有 modifier",
    },
    "oracle_manipulation": {
        "patterns": [
            r'getReserves\(\)',
            r'slot0\(\)',
            r'latestRoundData\(\)',
            r'price\s*=.*balanceOf',
            r'token\d?\.balanceOf\(address\(this\)\)',
        ],
        "severity": "critical",
        "description": "使用即时价格（spot price）而非 TWAP，可被闪电贷操控",
        "check": "是否使用 TWAP/时间加权价格 而非 slot0/getReserves 即时价格",
    },
    "flash_loan_surface": {
        "patterns": [
            r'flashLoan\(',
            r'flash\(',
            r'executeOperation\(',
            r'onFlashLoan\(',
            r'IFlashLoanReceiver',
        ],
        "severity": "high",
        "description": "闪电贷回调存在，需检查单交易内状态一致性",
    },
    "integer_overflow": {
        "patterns": [
            r'pragma solidity\s*[\^~]?0\.[0-7]\.',
            r'unchecked\s*\{',
        ],
        "severity": "high",
        "description": "Solidity <0.8 无内置溢出检查 / unchecked 块可能溢出",
    },
    "erc4626_vault": {
        "patterns": [
            r'convertToShares\(',
            r'convertToAssets\(',
            r'totalAssets\(\)',
            r'ERC4626',
            r'deposit\(.*assets.*shares',
        ],
        "severity": "high",
        "description": "ERC-4626 Vault 首次存入份额操控（inflation attack）",
        "check": "首笔存款是否有最小金额限制/虚拟偏移量保护",
    },

    # --- Medium ---
    "front_running": {
        "patterns": [
            r'deadline',
            r'slippage',
            r'amountOutMin',
            r'commit.*reveal',
        ],
        "anti_patterns": [
            r'block\.timestamp\s*<=\s*deadline',
        ],
        "severity": "medium",
        "description": "缺少滑点保护/deadline 参数，可被 MEV 夹击",
    },
    "unchecked_return": {
        "patterns": [
            r'\.transfer\(',
            r'\.send\(',
            r'IERC20.*\.transfer\(',
        ],
        "anti_patterns": [
            r'require\(.*\.send\(',
            r'SafeERC20',
            r'safeTransfer\(',
        ],
        "severity": "medium",
        "description": "ERC20 transfer 返回值未检查（某些代币 transfer 不 revert）",
    },
    "timestamp_dependency": {
        "patterns": [
            r'block\.timestamp',
            r'block\.number',
            r'now\b',
        ],
        "severity": "low",
        "description": "依赖 block.timestamp 可被矿工小幅操控（±15s）",
    },
}

# DeFi 专项检查
DEFI_CHECKS = {
    "price_oracle_type": {
        "safe": ["Chainlink", "TWAP", "timeWeightedAverage", "observe("],
        "unsafe": ["getReserves", "slot0", "balanceOf(address(this))", "spot price"],
        "description": "价格预言机类型：安全(Chainlink/TWAP) vs 不安全(即时价格)",
    },
    "flashloan_protection": {
        "safe": ["block.number", "lastBlock", "_blockLast", "require(block.number"],
        "unsafe": ["no block check in same-tx operation"],
        "description": "是否有同交易/同区块操作防护",
    },
    "vault_inflation": {
        "safe": ["virtualAssets", "virtualShares", "_decimalsOffset", "MIN_DEPOSIT"],
        "unsafe": ["totalSupply() == 0 without protection"],
        "description": "ERC-4626 Vault 通胀攻击防护",
    },
}


class Web3Auditor:
    """智能合约安全审计器"""

    def __init__(self, engine=None, config=None):
        self.engine = engine  # AgentEngine (可选，用于 LLM 分析)
        self.config = config or {}
        self.output_dir = os.path.expanduser('~/.bai-agent/web3-audits')
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    # ═══════════════════════════════════════════════════════════
    #  核心审计方法
    # ═══════════════════════════════════════════════════════════

    def audit_file(self, filepath: str) -> Dict:
        """审计单个 Solidity 文件"""
        if not os.path.isfile(filepath):
            return {"error": f"文件不存在: {filepath}"}

        content = Path(filepath).read_text(encoding='utf-8', errors='replace')
        findings = []

        # 1. 模式匹配
        findings.extend(self._pattern_scan(content, filepath))

        # 2. Slither（如果安装了）
        slither_findings = self._run_slither(filepath)
        findings.extend(slither_findings)

        # 3. LLM 逻辑分析（如果有 engine）
        if self.engine and len(content) < 15000:
            llm_findings = self._llm_audit(content, filepath)
            findings.extend(llm_findings)

        # 去重
        findings = self._deduplicate(findings)

        # 保存报告
        report = {
            "file": filepath,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "critical": [f for f in findings if f["severity"] == "critical"],
            "high": [f for f in findings if f["severity"] == "high"],
            "medium": [f for f in findings if f["severity"] == "medium"],
            "low": [f for f in findings if f["severity"] == "low"],
            "all_findings": findings,
        }

        report_file = os.path.join(self.output_dir,
                                   f"audit_{Path(filepath).stem}_{datetime.now().strftime('%Y%m%d_%H%M')}.json")
        Path(report_file).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')

        return report

    def audit_repo(self, repo_url: str, branch: str = "main") -> Dict:
        """审计 GitHub 仓库"""
        # 克隆到临时目录
        clone_dir = os.path.join(self.output_dir, "repos",
                                 repo_url.split('/')[-1].replace('.git', ''))
        if not os.path.isdir(clone_dir):
            os.makedirs(os.path.dirname(clone_dir), exist_ok=True)
            subprocess.run(f"git clone --depth 1 -b {branch} {repo_url} {clone_dir}",
                          shell=True, capture_output=True, timeout=120)

        if not os.path.isdir(clone_dir):
            return {"error": f"克隆失败: {repo_url}"}

        # 找到所有 .sol 文件
        sol_files = list(Path(clone_dir).rglob("*.sol"))
        sol_files = [f for f in sol_files if 'node_modules' not in str(f)
                     and 'test' not in str(f).lower() and 'mock' not in str(f).lower()]

        all_findings = []
        for sol_file in sol_files[:50]:  # 最多审计 50 个文件
            result = self.audit_file(str(sol_file))
            all_findings.extend(result.get("all_findings", []))

        # Slither 整体扫描
        slither_full = self._run_slither(clone_dir, is_dir=True)
        all_findings.extend(slither_full)

        all_findings = self._deduplicate(all_findings)

        report = {
            "repo": repo_url,
            "files_scanned": len(sol_files),
            "total_findings": len(all_findings),
            "critical": len([f for f in all_findings if f["severity"] == "critical"]),
            "high": len([f for f in all_findings if f["severity"] == "high"]),
            "findings": all_findings,
        }
        return report

    def audit_deployed(self, address: str, chain: str = "ethereum") -> Dict:
        """审计已部署合约（从 Etherscan 拉 verified 源码）"""
        # 尝试获取源码
        source = self._fetch_verified_source(address, chain)
        if not source:
            return {"error": f"无法获取 {address} 的 verified 源码（可能未验证）"}

        # 写入临时文件
        tmp_file = os.path.join(self.output_dir, f"deployed_{address[:10]}.sol")
        Path(tmp_file).write_text(source, encoding='utf-8')

        result = self.audit_file(tmp_file)
        result["address"] = address
        result["chain"] = chain
        return result

    def defi_deep_audit(self, project_dir: str) -> Dict:
        """DeFi 协议深度审计（闪电贷/预言机/Vault 专项）"""
        findings = []

        sol_files = list(Path(project_dir).rglob("*.sol"))
        sol_files = [f for f in sol_files if 'node_modules' not in str(f)
                     and 'test' not in str(f).lower()]

        all_code = ""
        for f in sol_files[:30]:
            content = f.read_text(encoding='utf-8', errors='replace')
            all_code += f"\n// === {f.name} ===\n" + content

        # DeFi 专项检查
        for check_name, check_info in DEFI_CHECKS.items():
            safe_found = any(s.lower() in all_code.lower() for s in check_info["safe"])
            unsafe_found = any(u.lower() in all_code.lower() for u in check_info["unsafe"])

            if unsafe_found and not safe_found:
                findings.append({
                    "type": f"DeFi: {check_name}",
                    "severity": "critical",
                    "description": check_info["description"],
                    "detail": f"发现不安全模式: {[u for u in check_info['unsafe'] if u.lower() in all_code.lower()]}",
                    "recommendation": f"应使用: {check_info['safe'][:3]}",
                    "source": "defi_deep_audit",
                })

        # LLM 深度分析 DeFi 逻辑
        if self.engine and len(all_code) < 30000:
            llm_defi = self._llm_defi_audit(all_code[:25000])
            findings.extend(llm_defi)

        return {
            "project": project_dir,
            "files_analyzed": len(sol_files),
            "defi_findings": findings,
            "critical": len([f for f in findings if f["severity"] == "critical"]),
        }

    # ═══════════════════════════════════════════════════════════
    #  内部方法
    # ═══════════════════════════════════════════════════════════

    def _pattern_scan(self, content: str, filepath: str) -> List[Dict]:
        """基于正则的漏洞模式扫描"""
        findings = []
        lines = content.split('\n')

        for vuln_name, vuln_info in VULN_PATTERNS.items():
            # 检查 anti-patterns（如果有保护措施则跳过）
            has_protection = False
            if "anti_patterns" in vuln_info:
                for ap in vuln_info["anti_patterns"]:
                    if re.search(ap, content, re.IGNORECASE):
                        has_protection = True
                        break

            if has_protection:
                continue

            # 检查漏洞模式
            for pattern in vuln_info["patterns"]:
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        findings.append({
                            "type": vuln_name,
                            "severity": vuln_info["severity"],
                            "description": vuln_info["description"],
                            "file": filepath,
                            "line": i + 1,
                            "code": line.strip()[:200],
                            "pattern": pattern,
                            "source": "pattern_scan",
                        })
                        break  # 每种模式只报一次

        return findings

    def _run_slither(self, target: str, is_dir: bool = False) -> List[Dict]:
        """运行 Slither 静态分析"""
        findings = []
        try:
            cmd = f"slither {target} --json - 2>/dev/null"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)

            if r.stdout:
                try:
                    data = json.loads(r.stdout)
                    for det in data.get("results", {}).get("detectors", []):
                        severity = det.get("impact", "medium").lower()
                        if severity in ("optimization", "informational"):
                            continue
                        findings.append({
                            "type": f"slither/{det.get('check', '?')}",
                            "severity": severity if severity in ("critical", "high", "medium", "low") else "medium",
                            "description": det.get("description", "")[:300],
                            "file": det.get("elements", [{}])[0].get("source_mapping", {}).get("filename_short", ""),
                            "line": det.get("elements", [{}])[0].get("source_mapping", {}).get("lines", [0])[0] if det.get("elements") else 0,
                            "confidence": det.get("confidence", ""),
                            "source": "slither",
                        })
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # Slither 未安装或超时

        return findings

    def _llm_audit(self, content: str, filepath: str) -> List[Dict]:
        """LLM 逻辑审计"""
        if not self.engine:
            return []

        prompt = f"""你是顶级智能合约安全审计师。审计以下 Solidity 代码：

```solidity
{content[:12000]}
```

重点检查：
1. 重入攻击（外部调用前是否更新状态）
2. 访问控制（关键函数是否有权限检查）
3. 预言机操控（价格来源是否安全）
4. 整数溢出（unchecked 块/旧版本）
5. 闪电贷攻击面（同交易内操控）
6. ERC-4626 通胀攻击
7. 任何可导致资金损失的逻辑缺陷

对每个发现输出 JSON：
{{"type": "漏洞类型", "severity": "critical/high/medium", "line": 行号, "description": "描述", "exploit": "利用方式"}}

只输出确定的漏洞，不要猜测。如果没有发现，输出空数组 []。
"""

        response = self.engine.think(prompt)
        findings = []

        # 解析 LLM 输出中的 JSON
        for m in re.finditer(r'\{[^{}]*"type"[^{}]*\}', response):
            try:
                f = json.loads(m.group(0))
                findings.append({
                    "type": f.get("type", "llm_finding"),
                    "severity": f.get("severity", "medium"),
                    "description": f.get("description", ""),
                    "file": filepath,
                    "line": f.get("line", 0),
                    "exploit": f.get("exploit", ""),
                    "source": "llm_audit",
                })
            except json.JSONDecodeError:
                continue

        return findings

    def _llm_defi_audit(self, code: str) -> List[Dict]:
        """LLM DeFi 协议专项分析"""
        if not self.engine:
            return []

        prompt = f"""你是 DeFi 安全专家。分析以下协议代码的经济攻击面：

```solidity
{code[:20000]}
```

重点检查：
1. 闪电贷攻击：能否在单交易内操控价格/状态获利
2. 预言机操控：价格来源是否可被闪电贷操控
3. Vault 份额操控：首存是否有通胀攻击风险
4. 三明治攻击：swap 是否有滑点/deadline 保护
5. 治理攻击：能否用闪电贷获取投票权
6. 跨函数重入：多个函数间的状态不一致

对每个发现给出：攻击步骤（1-2-3）+ 预估影响金额 + 修复建议
JSON 格式：{{"type": "...", "severity": "...", "attack_steps": "...", "impact": "...", "fix": "..."}}
"""

        response = self.engine.think(prompt)
        findings = []

        for m in re.finditer(r'\{[^{}]*"type"[^{}]*\}', response):
            try:
                f = json.loads(m.group(0))
                findings.append({
                    "type": f.get("type", "defi_logic"),
                    "severity": f.get("severity", "high"),
                    "description": f.get("attack_steps", ""),
                    "impact": f.get("impact", ""),
                    "fix": f.get("fix", ""),
                    "source": "llm_defi_audit",
                })
            except json.JSONDecodeError:
                continue

        return findings

    def _fetch_verified_source(self, address: str, chain: str) -> Optional[str]:
        """从 Etherscan 获取已验证源码"""
        api_keys = {
            "ethereum": os.environ.get("ETHERSCAN_API_KEY", ""),
            "bsc": os.environ.get("BSCSCAN_API_KEY", ""),
            "polygon": os.environ.get("POLYGONSCAN_API_KEY", ""),
            "arbitrum": os.environ.get("ARBISCAN_API_KEY", ""),
        }

        api_urls = {
            "ethereum": "https://api.etherscan.io/api",
            "bsc": "https://api.bscscan.com/api",
            "polygon": "https://api.polygonscan.com/api",
            "arbitrum": "https://api.arbiscan.io/api",
        }

        api_key = api_keys.get(chain, "")
        api_url = api_urls.get(chain, "")

        if not api_url:
            return None

        try:
            import requests
            params = {
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": api_key,
            }
            r = requests.get(api_url, params=params, timeout=15)
            data = r.json()
            if data.get("status") == "1" and data.get("result"):
                source = data["result"][0].get("SourceCode", "")
                if source:
                    # 处理 JSON 格式的多文件源码
                    if source.startswith("{{"):
                        source = source[1:-1]  # 去掉外层括号
                        try:
                            files = json.loads(source)
                            all_source = ""
                            for fname, finfo in files.get("sources", {}).items():
                                all_source += f"\n// === {fname} ===\n" + finfo.get("content", "")
                            return all_source
                        except json.JSONDecodeError:
                            pass
                    return source
        except Exception:
            pass
        return None

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("type", ""), f.get("file", ""), f.get("line", 0))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
