"""Params Phase — 参数发现阶段（增强版）

增强内容：
- POST 参数发现（表单提取 + arjun POST 模式）
- JSON body 参数推断（从 API 响应中提取字段名）
- GraphQL 端点发现 + introspection
- gf 多模式提取（xss/ssrf/sqli/redirect/idor/lfi）
- 更大覆盖量（200+ 参数化 URL）
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shell_utils import shell_quote, sanitize_target, sanitize_url
from .base import BasePhase


class ParamPhase(BasePhase):
    """参数发现：GET/POST参数、JSON body、GraphQL、隐藏参数探测"""
    
    def execute(self, target: str, findings: dict) -> dict:
        phase_findings = {"params": [], "urls": [], "graphql_endpoints": [], "post_endpoints": []}
        
        self.logger.log_phase_start("参数发现 (Param Discovery — Enhanced)")
        
        safe_target = sanitize_target(target)
        
        # ═══ Step 1: ParamSpider 被动参数发现 ═══
        self._step("ParamSpider被动参数", target, phase_findings, findings,
                   f"paramspider -d {shell_quote(safe_target)} 2>/dev/null | sort -u | head -200",
                   lambda out: [u for u in out.strip().split('\n') if u and '?' in u],
                   "urls")
        
        # ═══ Step 2: 从已有URL中提取带参数的（更大量）═══
        urls_with_params = [u for u in findings.get('urls', []) if '?' in u]
        if urls_with_params:
            phase_findings["params"].extend(list(set(urls_with_params))[:200])
            self.logger.log_event("FINDING", f"从已有URL中提取 {len(urls_with_params)} 个带参数URL")
        
        # ═══ Step 3: gf 多模式提取（XSS/SSRF/SQLi/Redirect/IDOR/LFI）═══
        if findings.get('urls'):
            all_urls = list(set(findings['urls']))[:300]
            pipe_cmd = self._pipe_lines(all_urls)
            
            # 一次性提取多种模式
            gf_patterns = ['xss', 'ssrf', 'sqli', 'redirect', 'idor', 'lfi']
            for pattern in gf_patterns:
                pipe_cmd = self._pipe_lines(all_urls)
                self._step(f"gf提取{pattern}参数", target, phase_findings, findings,
                           f"{pipe_cmd} | gf {pattern} 2>/dev/null | sort -u | head -50",
                           lambda out: [u for u in out.strip().split('\n') if u.strip()],
                           "params")
        
        # ═══ Step 4: GraphQL 端点发现 ═══
        alive_hosts = findings.get('alive_hosts', [])
        if alive_hosts:
            hosts = [h.split()[0] if ' ' in h else h for h in alive_hosts[:10]]
            graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', 
                           '/query', '/gql', '/__graphql']
            
            # 构建检测命令
            probe_cmds = []
            for host in hosts[:5]:
                host_clean = host.rstrip('/')
                for path in graphql_paths:
                    probe_cmds.append(f"{host_clean}{path}")
            
            if probe_cmds:
                pipe_cmd = self._pipe_lines(probe_cmds[:35])
                self._step("GraphQL端点探测", target, phase_findings, findings,
                           f"{pipe_cmd} | httpx -silent -mc 200,405 -rate-limit 5 2>/dev/null",
                           self._parse_graphql_endpoints,
                           "graphql_endpoints")
            
            # 对发现的 GraphQL 端点做 introspection
            if phase_findings["graphql_endpoints"]:
                for gql_url in phase_findings["graphql_endpoints"][:3]:
                    safe_gql = sanitize_url(gql_url)
                    self._step(f"GraphQL Introspection: {gql_url[:40]}", target, phase_findings, findings,
                               f'curl -s -X POST {shell_quote(safe_gql)} '
                               f'-H "Content-Type: application/json" '
                               f'-d \'{{"query":"{{__schema{{types{{name fields{{name type{{name}}}}}}}}}}"}}\' '
                               f'--max-time 10 2>/dev/null | head -500',
                               self._parse_graphql_schema,
                               "params")
        
        # ═══ Step 5: POST 参数发现（表单 + API）═══
        if alive_hosts:
            hosts = [h.split()[0] if ' ' in h else h for h in alive_hosts[:5]]
            
            # 用 katana 提取表单（带 form 解析）
            pipe_cmd = self._pipe_lines(hosts)
            self._step("表单/POST端点提取", target, phase_findings, findings,
                       f"{pipe_cmd} | katana -d 2 -jc -f qurl -silent -rate-limit 5 2>/dev/null | "
                       f"grep -iE '(login|register|search|upload|submit|create|update|delete|add|edit|save|send|post)' | "
                       f"sort -u | head -50",
                       self._parse_post_endpoints,
                       "post_endpoints")
        
        # ═══ Step 6: JSON API 参数推断 ═══
        # 从已有URL中找 API 端点，发请求看响应 JSON 字段
        api_urls = [u for u in findings.get('urls', []) 
                   if re.search(r'/api/|/v[0-9]/|/rest/', u, re.I)][:10]
        if api_urls:
            pipe_cmd = self._pipe_lines(api_urls)
            self._step("JSON API字段提取", target, phase_findings, findings,
                       f"{pipe_cmd} | while read url; do "
                       f"curl -s --max-time 8 \"$url\" 2>/dev/null | "
                       f"grep -oE '\"[a-zA-Z_]{{2,30}}\"\\s*:' | "
                       f"tr -d '\"' | tr -d ':' | sort -u; "
                       f"done | sort | uniq -c | sort -rn | head -30",
                       self._parse_json_fields,
                       "params")
        
        # ═══ Step 7: Arjun 主动参数探测（对关键接口）═══
        if self.mode == "auto" and alive_hosts:
            # 选择最有价值的接口做主动探测
            high_value_urls = self._select_high_value_targets(findings, phase_findings)
            
            for url in high_value_urls[:3]:
                safe_url = sanitize_url(url)
                # GET 参数探测
                self._step(f"Arjun GET探测: {url[:40]}", target, phase_findings, findings,
                           f"arjun -u {shell_quote(safe_url)} --stable -t 5 2>/dev/null | tail -20",
                           lambda out: [out] if out.strip() and 'parameter' in out.lower() else [],
                           "params")
                
                # POST 参数探测
                self._step(f"Arjun POST探测: {url[:40]}", target, phase_findings, findings,
                           f"arjun -u {shell_quote(safe_url)} -m POST --stable -t 5 2>/dev/null | tail -20",
                           lambda out: [f"[POST] {out}"] if out.strip() and 'parameter' in out.lower() else [],
                           "params")
        
        # ═══ Step 8: 从 JS 中提取的端点补充参数 ═══
        js_endpoints = [u for u in findings.get('urls', []) if '[JS_ENDPOINT]' in u]
        if js_endpoints and alive_hosts:
            # 把 JS 中发现的相对路径补全为完整 URL
            base_host = alive_hosts[0].split()[0] if ' ' in alive_hosts[0] else alive_hosts[0]
            base_host = base_host.rstrip('/')
            
            full_js_urls = []
            for ep in js_endpoints[:20]:
                path = ep.replace('[JS_ENDPOINT]', '').strip()
                full_js_urls.append(f"{base_host}{path}")
            
            if full_js_urls:
                pipe_cmd = self._pipe_lines(full_js_urls)
                self._step("JS隐藏端点存活验证", target, phase_findings, findings,
                           f"{pipe_cmd} | httpx -silent -mc 200,201,301,302,401,403,405 -rate-limit 5 2>/dev/null",
                           lambda out: [u for u in out.strip().split('\n') if u.strip()],
                           "urls")
        
        return phase_findings
    
    # ─── 解析方法 ─────────────────────────────────────────────
    
    def _parse_graphql_endpoints(self, output: str) -> list:
        """解析 GraphQL 端点探测结果"""
        endpoints = []
        for line in output.strip().split('\n'):
            url = line.strip()
            if url and ('graphql' in url.lower() or 'gql' in url.lower() or 'query' in url.lower()):
                endpoints.append(url)
                self.logger.log_event("FINDING", f"发现 GraphQL 端点: {url}")
        return endpoints
    
    def _parse_graphql_schema(self, output: str) -> list:
        """解析 GraphQL introspection 结果，提取可测试的 type/field"""
        params = []
        if '__schema' in output or 'types' in output:
            self.logger.log_event("FINDING", "⚠️ GraphQL Introspection 开启！可提取完整 schema")
            # 提取 type 名和 field 名
            types_found = re.findall(r'"name"\s*:\s*"([A-Z][a-zA-Z]+)"', output)
            fields_found = re.findall(r'"name"\s*:\s*"([a-z][a-zA-Z_]+)"', output)
            
            if types_found:
                params.append(f"[GRAPHQL_TYPES] {', '.join(set(types_found)[:20])}")
            if fields_found:
                params.append(f"[GRAPHQL_FIELDS] {', '.join(set(fields_found)[:30])}")
                # 高价值字段标记
                sensitive_fields = [f for f in fields_found 
                                   if any(kw in f.lower() for kw in 
                                         ['password', 'token', 'secret', 'admin', 'role',
                                          'email', 'phone', 'ssn', 'credit', 'balance'])]
                if sensitive_fields:
                    params.append(f"[GRAPHQL_SENSITIVE] {', '.join(set(sensitive_fields))}")
                    self.logger.log_event("FINDING", f"⚠️ GraphQL 敏感字段: {sensitive_fields}")
        return params
    
    def _parse_post_endpoints(self, output: str) -> list:
        """解析 POST 端点"""
        endpoints = []
        for line in output.strip().split('\n'):
            url = line.strip()
            if url and url.startswith('http'):
                endpoints.append(url)
        if endpoints:
            self.logger.log_event("FINDING", f"发现 {len(endpoints)} 个可能的 POST 端点")
        return endpoints
    
    def _parse_json_fields(self, output: str) -> list:
        """解析 JSON 响应字段，标记可能的可注入参数"""
        params = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            # 格式: "  count field_name"
            parts = line.split()
            if len(parts) >= 2:
                field = parts[-1]
                # 标记高价值参数（可能有 IDOR/SQLi/SSRF）
                if any(kw in field.lower() for kw in 
                      ['id', 'user', 'uid', 'url', 'path', 'file', 'query', 
                       'search', 'redirect', 'callback', 'next', 'ref']):
                    params.append(f"[JSON_PARAM_HIGH] {field}")
                else:
                    params.append(f"[JSON_PARAM] {field}")
        return params
    
    def _select_high_value_targets(self, findings: dict, phase_findings: dict) -> list:
        """选择最有价值的接口做主动参数探测"""
        candidates = []
        alive = findings.get('alive_hosts', [])
        
        # 优先选择 API 类端点
        for url in findings.get('urls', []):
            if re.search(r'/api/|/v[0-9]/|/rest/|/admin|/manage|/dashboard', url, re.I):
                candidates.append(url.split()[0] if ' ' in url else url)
        
        # 补充存活主机根路径
        if not candidates and alive:
            candidates = [h.split()[0] if ' ' in h else h for h in alive[:3]]
        
        return list(set(candidates))[:5]
