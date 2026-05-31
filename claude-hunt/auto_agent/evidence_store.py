#!/usr/bin/env python3
"""
Evidence Store — 证据自动保存模块（增强版）

每个发现自动保存完整证据包，可直接用于 H1/Bugcrowd 提交：
- 完整 curl 复现命令
- HTTP 请求/响应
- 时间戳
- Scope 判断（为什么在 scope 内）
- 为什么不是排除项
- 影响分析
- CVSS 评估
- 一键生成 H1 格式报告

用法：
    from evidence_store import EvidenceStore
    es = EvidenceStore(config)

    # 保存证据
    eid = es.save(finding, request, response, target, command)

    # 生成 H1 格式 PoC
    poc = es.generate_h1_report(eid)

    # 列出所有证据
    all_evidence = es.list_all(target)
"""

import json, os, time, hashlib, re
from pathlib import Path
from datetime import datetime


class EvidenceStore:
    def __init__(self, config=None):
        self.config = config or {}
        self.base_dir = os.path.expanduser('~/.bai-agent/evidence')
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
        self.index_file = os.path.join(self.base_dir, "index.json")
        self.index = self._load_index()

    def save(self, finding, request=None, response=None, target="",
             command="", output="", scope_reason="", not_excluded_reason=""):
        """保存完整证据包"""
        eid = hashlib.sha256(
            f"{finding.get('type','')}{finding.get('url','')}{time.time()}".encode()
        ).hexdigest()[:12]

        evidence = {
            "id": eid,
            "timestamp": datetime.now().isoformat(),
            "target": target,

            # 漏洞信息
            "finding": finding,
            "severity": finding.get("severity", "medium"),
            "vuln_type": finding.get("type", "unknown"),

            # 请求证据
            "request": request or {
                "curl_command": command,
                "method": "GET",
                "url": finding.get("url", ""),
                "headers": {},
            },

            # 响应证据
            "response": response or {
                "status_code": 0,
                "headers": {},
                "body": (output or "")[:10000],
                "size": len(output or ""),
            },

            # 复现
            "reproduction": {
                "curl_command": command,
                "steps": [
                    f"1. 执行: {command[:300]}",
                    f"2. 观察: {finding.get('detail', '')}",
                    f"3. 影响: {finding.get('severity', 'medium')} 级别漏洞确认",
                ],
                "prerequisites": "需要有效的账号Cookie" if "cookie" in command.lower() else "无需认证",
            },

            # Scope 合规
            "scope_compliance": {
                "in_scope": True,
                "scope_reason": scope_reason or f"目标 {target} 在项目 scope 列表中",
                "not_excluded_reason": not_excluded_reason or f"漏洞类型 {finding.get('type','')} 不在排除项中",
                "qualifies_for_bounty": True,
            },

            # 影响分析
            "impact": {
                "who_affected": "所有使用该功能的用户",
                "what_can_attacker_do": finding.get("detail", ""),
                "data_at_risk": "",
                "requires_interaction": "无需用户交互" if finding.get("severity") in ("critical", "high") else "可能需要",
            },
        }

        # 保存文件
        tdir = os.path.join(self.base_dir, target.replace('/', '_').replace(':', '_')[:50])
        Path(tdir).mkdir(parents=True, exist_ok=True)
        filepath = os.path.join(tdir, f"{eid}.json")
        Path(filepath).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')

        # 更新索引
        self.index.append({
            "id": eid, "target": target, "type": finding.get("type", ""),
            "severity": finding.get("severity", ""), "timestamp": evidence["timestamp"],
            "file": filepath,
        })
        self._save_index()

        return eid

    def generate_h1_report(self, evidence_id):
        """生成 HackerOne 格式的提交报告"""
        evidence = self._find(evidence_id)
        if not evidence:
            return ""

        finding = evidence.get("finding", {})
        repro = evidence.get("reproduction", {})
        scope = evidence.get("scope_compliance", {})
        impact = evidence.get("impact", {})
        req = evidence.get("request", {})

        report = f"""## Summary

**Vulnerability Type**: {finding.get('type', '?')}
**Severity**: {finding.get('severity', 'medium').upper()}
**Endpoint**: {finding.get('url', '')}

## Description

{finding.get('detail', 'N/A')}

## Steps to Reproduce

{chr(10).join(repro.get('steps', ['N/A']))}

## Reproduction Command

```bash
{repro.get('curl_command', 'N/A')}
```

## Impact

- **Who is affected**: {impact.get('who_affected', 'All users')}
- **What can an attacker do**: {impact.get('what_can_attacker_do', '')}
- **User interaction required**: {impact.get('requires_interaction', 'No')}

## Scope Confirmation

- **In scope**: {scope.get('scope_reason', '')}
- **Not excluded**: {scope.get('not_excluded_reason', '')}

## Supporting Evidence

- Timestamp: {evidence.get('timestamp', '')}
- Response status: {evidence.get('response', {}).get('status_code', 'N/A')}
- Response size: {evidence.get('response', {}).get('size', 'N/A')} bytes
"""
        return report

    def generate_poc(self, evidence_id, evidence_dir=""):
        """简化版 PoC 生成（向下兼容）"""
        return self.generate_h1_report(evidence_id)

    def list_all(self, target=""):
        """列出所有证据"""
        if target:
            return [e for e in self.index if target.lower() in e.get("target", "").lower()]
        return self.index

    def get_summary(self, target=""):
        """获取证据摘要"""
        items = self.list_all(target)
        return {
            "total": len(items),
            "critical": sum(1 for i in items if i.get("severity") == "critical"),
            "high": sum(1 for i in items if i.get("severity") == "high"),
            "medium": sum(1 for i in items if i.get("severity") == "medium"),
        }

    def _find(self, evidence_id):
        """查找证据"""
        for entry in self.index:
            if entry.get("id") == evidence_id:
                filepath = entry.get("file", "")
                if filepath and os.path.isfile(filepath):
                    return json.loads(Path(filepath).read_text(encoding='utf-8'))
        # fallback: 递归搜索
        for root, dirs, files in os.walk(self.base_dir):
            for f in files:
                if evidence_id in f and f.endswith('.json'):
                    return json.loads(Path(os.path.join(root, f)).read_text(encoding='utf-8'))
        return None

    def _load_index(self):
        if os.path.isfile(self.index_file):
            try:
                return json.loads(Path(self.index_file).read_text(encoding='utf-8'))
            except Exception:
                pass
        return []

    def _save_index(self):
        Path(self.index_file).write_text(
            json.dumps(self.index[-1000:], ensure_ascii=False, indent=2), encoding='utf-8'
        )
