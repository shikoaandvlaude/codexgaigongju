#!/usr/bin/env python3
"""
Scope Resolver — H1/Bugcrowd 项目规则解析器

自动导入 scope，实时判断目标是否 in-scope。

用法：
    from scope_resolver import ScopeResolver
    sr = ScopeResolver()
    sr.import_h1_program("shopify")
    sr.is_in_scope("admin.shopify.com")  # True
"""

import json, os, re, fnmatch
from pathlib import Path
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class ScopeResolver:
    def __init__(self, config=None):
        self.config = config or {}
        self.data_dir = os.path.expanduser('~/.bai-agent/scopes')
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        self.in_scope = []
        self.out_of_scope = []
        self.non_qualifying = []
        self.program_name = ""

    def import_h1_program(self, handle):
        if not HAS_REQUESTS:
            return False
        query = '{ team(handle: "%s") { name policy_scopes(archived: false) { edges { node { asset_identifier eligible_for_bounty instruction } } } } }' % handle
        try:
            r = requests.post("https://hackerone.com/graphql", json={"query": query}, headers={"Content-Type": "application/json"}, timeout=15)
            team = r.json().get("data", {}).get("team", {})
            if not team:
                return False
            self.program_name = team.get("name", handle)
            for edge in team.get("policy_scopes", {}).get("edges", []):
                node = edge["node"]
                asset = node.get("asset_identifier", "")
                if node.get("eligible_for_bounty"):
                    self.in_scope.append(asset)
                else:
                    self.out_of_scope.append(asset)
            self._save(handle)
            return True
        except Exception:
            return False

    def set_scope(self, in_scope=None, out_of_scope=None, non_qualifying=None):
        if in_scope: self.in_scope = in_scope
        if out_of_scope: self.out_of_scope = out_of_scope
        if non_qualifying: self.non_qualifying = non_qualifying

    def is_in_scope(self, url_or_domain):
        domain = re.sub(r'^https?://', '', url_or_domain.lower()).split('/')[0].split(':')[0]
        for p in self.out_of_scope:
            if self._match(domain, p): return False
        if not self.in_scope: return True
        for p in self.in_scope:
            if self._match(domain, p): return True
        return False

    def is_vuln_qualifying(self, vuln_type):
        if not self.non_qualifying: return True
        vt = vuln_type.lower().replace(' ', '_')
        return not any(nq.lower().replace(' ', '_') in vt or vt in nq.lower().replace(' ', '_') for nq in self.non_qualifying)

    def check_finding(self, finding):
        url = finding.get("url", "")
        vtype = finding.get("type", "")
        in_s = self.is_in_scope(url) if url else True
        qual = self.is_vuln_qualifying(vtype)
        return {"submittable": in_s and qual, "in_scope": in_s, "qualifying": qual}

    def _match(self, domain, pattern):
        pattern = re.sub(r'^https?://', '', pattern.lower()).split('/')[0]
        if fnmatch.fnmatch(domain, pattern): return True
        if pattern.startswith('*.'):
            base = pattern[2:]
            if domain == base or domain.endswith('.' + base): return True
        return domain == pattern

    def _save(self, handle):
        Path(os.path.join(self.data_dir, f"{handle}.json")).write_text(
            json.dumps({"program": self.program_name, "in_scope": self.in_scope, "out_of_scope": self.out_of_scope, "non_qualifying": self.non_qualifying, "updated": datetime.now().isoformat()}, ensure_ascii=False, indent=2), encoding='utf-8')

    def load(self, handle):
        fp = os.path.join(self.data_dir, f"{handle}.json")
        if not os.path.isfile(fp): return False
        data = json.loads(Path(fp).read_text(encoding='utf-8'))
        self.in_scope = data.get("in_scope", [])
        self.out_of_scope = data.get("out_of_scope", [])
        self.non_qualifying = data.get("non_qualifying", [])
        self.program_name = data.get("program", "")
        return True
