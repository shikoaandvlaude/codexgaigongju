#!/usr/bin/env python3
"""
Evidence Store — 证据自动保存模块

每个发现自动保存完整证据包：请求/响应/时间/复现命令/scope判断

用法：
    from evidence_store import EvidenceStore
    es = EvidenceStore()
    es.save(finding, request, response, target)
    poc = es.generate_poc(evidence_id)
"""

import json, os, time, hashlib, re
from pathlib import Path
from datetime import datetime


class EvidenceStore:
    def __init__(self, config=None):
        self.config = config or {}
        self.base_dir = os.path.expanduser('~/.bai-agent/evidence')
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
        self.index = []

    def save(self, finding, request=None, response=None, target="", command="", output=""):
        eid = hashlib.sha256(f"{finding.get('type','')}{finding.get('url','')}{time.time()}".encode()).hexdigest()[:12]
        evidence = {
            "id": eid, "timestamp": datetime.now().isoformat(), "target": target,
            "finding": finding, "request": request or {"curl_cmd": command},
            "response": response or {"body": (output or "")[:5000]},
            "reproduction": {"curl_command": command, "steps": f"1. Run: {command[:200]}\n2. Observe: {finding.get('detail','')}"},
        }
        tdir = os.path.join(self.base_dir, target.replace('/','_').replace(':','_')[:50])
        Path(tdir).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(tdir, f"{eid}.json")).write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf-8')
        return eid

    def generate_poc(self, evidence_id, evidence_dir=""):
        for root, dirs, files in os.walk(evidence_dir or self.base_dir):
            for f in files:
                if evidence_id in f:
                    data = json.loads(Path(os.path.join(root, f)).read_text(encoding='utf-8'))
                    finding = data.get("finding", {})
                    repro = data.get("reproduction", {})
                    return f"## {finding.get('type','?')}\n\nSeverity: {finding.get('severity','')}\nURL: {finding.get('url','')}\n\n### Steps\n{repro.get('steps','')}\n\n### Command\n```\n{repro.get('curl_command','')}\n```"
        return ""
