#!/usr/bin/env python3
"""
Code Auditor — AI 辅助源码审计模块

功能：
  1. 扫描源码中的危险函数调用（按语言分类）
  2. 识别常见漏洞模式（SQL拼接、命令注入、反序列化、文件操作等）
  3. 对每个发现用 AI 进行二次确认（减少误报）
  4. 输出结构化审计结果

支持语言: PHP, Java, Python, Go, JavaScript/Node.js

用法（独立运行）:
  python3 code_auditor.py /path/to/source
  python3 code_auditor.py /path/to/source --lang php
  python3 code_auditor.py /path/to/source --no-ai  # 不用AI确认，只做静态匹配
"""

import os
import re
import sys
import json
import argparse
from typing import List, Dict
from pathlib import Path

# ─── 危险函数/模式定义 ────────────────────────────────────────────────────────

DANGEROUS_PATTERNS = {
    "php": {
        "RCE (命令执行)": {
            "patterns": [
                r'\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(',
                r'\b(eval|assert)\s*\(\s*\$',
                r'`\$[^`]+`',  # backtick with variable
            ],
            "cwe": "CWE-78",
            "severity": "critical",
        },
        "SQL Injection": {
            "patterns": [
                r'(\$_(GET|POST|REQUEST|COOKIE)\[.*?\])\s*[^;]*\b(mysql_query|mysqli_query|->query)\b',
                r'(\"|\').*?\.\s*\$_(GET|POST|REQUEST)',
                r'\bquery\s*\(\s*["\'].*?\$',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
        },
        "File Inclusion": {
            "patterns": [
                r'\b(include|require|include_once|require_once)\s*\(\s*\$',
            ],
            "cwe": "CWE-98",
            "severity": "high",
        },
        "File Upload": {
            "patterns": [
                r'move_uploaded_file\s*\(',
                r'\$_FILES\[.*?\]\[.name.\]',
            ],
            "cwe": "CWE-434",
            "severity": "high",
        },
        "Deserialization": {
            "patterns": [
                r'\bunserialize\s*\(\s*\$',
            ],
            "cwe": "CWE-502",
            "severity": "critical",
        },
        "SSRF": {
            "patterns": [
                r'\b(file_get_contents|curl_exec|fopen)\s*\(\s*\$',
            ],
            "cwe": "CWE-918",
            "severity": "high",
        },
        "XSS": {
            "patterns": [
                r'echo\s+\$_(GET|POST|REQUEST)',
                r'print\s+\$_(GET|POST|REQUEST)',
            ],
            "cwe": "CWE-79",
            "severity": "medium",
        },
    },
    "java": {
        "RCE (命令执行)": {
            "patterns": [
                r'Runtime\.getRuntime\(\)\.exec\s*\(',
                r'ProcessBuilder\s*\(',
                r'ScriptEngine.*eval\s*\(',
            ],
            "cwe": "CWE-78",
            "severity": "critical",
        },
        "SQL Injection": {
            "patterns": [
                r'Statement.*execute(Query|Update)\s*\(\s*["\'].*\+',
                r'String\.format.*%s.*execute',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
        },
        "Deserialization": {
            "patterns": [
                r'ObjectInputStream.*readObject\s*\(',
                r'XMLDecoder.*readObject\s*\(',
                r'fromXML\s*\(',  # XStream
            ],
            "cwe": "CWE-502",
            "severity": "critical",
        },
        "SpEL Injection": {
            "patterns": [
                r'SpelExpressionParser.*parseExpression\s*\(',
                r'ExpressionParser.*parseExpression\s*\(',
            ],
            "cwe": "CWE-917",
            "severity": "critical",
        },
        "SSRF": {
            "patterns": [
                r'new\s+URL\s*\(.*request\.getParameter',
                r'HttpClient.*execute\s*\(',
            ],
            "cwe": "CWE-918",
            "severity": "high",
        },
        "Path Traversal": {
            "patterns": [
                r'new\s+File\s*\(.*request\.getParameter',
                r'Paths\.get\s*\(.*getParameter',
            ],
            "cwe": "CWE-22",
            "severity": "high",
        },
    },
    "python": {
        "RCE (命令执行)": {
            "patterns": [
                r'\b(os\.system|os\.popen|subprocess\.call|subprocess\.run)\s*\(.*\+',
                r'\beval\s*\(\s*(request|input|sys\.argv)',
                r'\bexec\s*\(\s*(request|input)',
            ],
            "cwe": "CWE-78",
            "severity": "critical",
        },
        "SQL Injection": {
            "patterns": [
                r'execute\s*\(\s*["\'].*%[sd].*%\s*\(',
                r'execute\s*\(\s*f["\']',
                r'execute\s*\(\s*["\'].*\+\s*request',
                r'cursor\.execute\s*\(\s*["\'].*\.format\(',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
        },
        "Deserialization": {
            "patterns": [
                r'\bpickle\.loads?\s*\(',
                r'\byaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)',
            ],
            "cwe": "CWE-502",
            "severity": "critical",
        },
        "SSTI": {
            "patterns": [
                r'render_template_string\s*\(.*request',
                r'Template\s*\(.*request',
                r'Jinja2.*from_string\s*\(',
            ],
            "cwe": "CWE-1336",
            "severity": "critical",
        },
        "SSRF": {
            "patterns": [
                r'requests\.(get|post|put)\s*\(.*request\.(args|form|json)',
                r'urllib\.request\.urlopen\s*\(.*request',
            ],
            "cwe": "CWE-918",
            "severity": "high",
        },
    },
    "go": {
        "RCE (命令执行)": {
            "patterns": [
                r'exec\.Command\s*\(.*r\.FormValue',
                r'exec\.Command\s*\(.*r\.URL\.Query',
            ],
            "cwe": "CWE-78",
            "severity": "critical",
        },
        "SQL Injection": {
            "patterns": [
                r'db\.(Query|Exec)\s*\(\s*["`].*\+',
                r'fmt\.Sprintf.*db\.(Query|Exec)',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
        },
        "Path Traversal": {
            "patterns": [
                r'os\.Open\s*\(.*r\.FormValue',
                r'http\.ServeFile\s*\(.*r\.URL',
            ],
            "cwe": "CWE-22",
            "severity": "high",
        },
    },
    "javascript": {
        "RCE (命令执行)": {
            "patterns": [
                r'child_process\.(exec|spawn|execSync)\s*\(.*req\.(body|params|query)',
                r'eval\s*\(\s*req\.',
            ],
            "cwe": "CWE-78",
            "severity": "critical",
        },
        "SQL Injection": {
            "patterns": [
                r'query\s*\(\s*[`"\'].*\$\{.*req\.',
                r'query\s*\(\s*["\'].*\+\s*req\.',
            ],
            "cwe": "CWE-89",
            "severity": "critical",
        },
        "Prototype Pollution": {
            "patterns": [
                r'Object\.assign\s*\(\s*\{\}.*req\.(body|query)',
                r'_\.merge\s*\(.*req\.(body|query)',
                r'\[req\.(body|query|params)\[',
            ],
            "cwe": "CWE-1321",
            "severity": "high",
        },
        "SSRF": {
            "patterns": [
                r'(axios|fetch|request)\s*\(\s*req\.(body|query|params)',
            ],
            "cwe": "CWE-918",
            "severity": "high",
        },
    },
}

# 文件扩展名映射
LANG_EXTENSIONS = {
    "php": [".php", ".phtml", ".inc"],
    "java": [".java", ".jsp"],
    "python": [".py"],
    "go": [".go"],
    "javascript": [".js", ".ts", ".mjs"],
}

# 排除目录
EXCLUDE_DIRS = {
    'node_modules', 'vendor', '.git', '__pycache__', 'venv',
    'env', '.idea', '.vscode', 'dist', 'build', 'target',
    'test', 'tests', 'spec', 'docs', 'examples',
}


class CodeAuditor:
    """源码审计器"""

    def __init__(self, source_dir: str, lang: str = "auto", use_ai: bool = True):
        self.source_dir = source_dir
        self.lang = lang
        self.use_ai = use_ai
        self.findings = []

    def audit(self) -> List[Dict]:
        """执行审计"""
        # 自动检测语言
        if self.lang == "auto":
            self.lang = self._detect_language()
            print(f"[*] 检测到语言: {self.lang}")

        if self.lang not in DANGEROUS_PATTERNS:
            print(f"[!] 不支持的语言: {self.lang}")
            return []

        # 收集文件
        files = self._collect_files()
        print(f"[*] 待审计文件: {len(files)} 个")

        # 逐文件扫描
        for filepath in files:
            self._scan_file(filepath)

        print(f"[*] 初步发现: {len(self.findings)} 个")

        # AI 二次确认（去除误报）
        if self.use_ai and self.findings:
            self.findings = self._ai_confirm(self.findings)
            print(f"[*] AI 确认后: {len(self.findings)} 个")

        return self.findings

    def _detect_language(self) -> str:
        """根据文件类型统计自动判断主要语言"""
        counts = {}
        for root, dirs, files in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                for lang, exts in LANG_EXTENSIONS.items():
                    if ext in exts:
                        counts[lang] = counts.get(lang, 0) + 1

        if not counts:
            return "php"  # 默认
        return max(counts, key=counts.get)

    def _collect_files(self) -> List[str]:
        """收集目标语言的所有源码文件"""
        extensions = LANG_EXTENSIONS.get(self.lang, [])
        files = []

        for root, dirs, filenames in os.walk(self.source_dir):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for f in filenames:
                if any(f.endswith(ext) for ext in extensions):
                    files.append(os.path.join(root, f))

        return files

    def _scan_file(self, filepath: str):
        """扫描单个文件"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return

        patterns = DANGEROUS_PATTERNS.get(self.lang, {})
        rel_path = os.path.relpath(filepath, self.source_dir)

        for vuln_type, config in patterns.items():
            for pattern in config['patterns']:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        # 提取上下文（前后3行）
                        start = max(0, i - 4)
                        end = min(len(lines), i + 3)
                        context = '\n'.join(lines[start:end])

                        self.findings.append({
                            "type": vuln_type,
                            "file": rel_path,
                            "line": i,
                            "code_snippet": context,
                            "matched_line": line.strip(),
                            "pattern": pattern,
                            "cwe": config['cwe'],
                            "severity": config['severity'],
                            "lang": self.lang,
                            "description": f"Potential {vuln_type} in {rel_path} at line {i}",
                            "description_cn": f"在 {rel_path} 第 {i} 行发现疑似 {vuln_type} 漏洞",
                        })

    def _ai_confirm(self, findings: List[Dict]) -> List[Dict]:
        """用 AI 对每个发现做二次确认"""
        try:
            from openai import OpenAI
            api_key = os.environ.get('DEEPSEEK_API_KEY') or os.environ.get('OPENAI_API_KEY', '')
            base_url = os.environ.get('LLM_BASE_URL', 'https://api.deepseek.com/v1')
            model = os.environ.get('LLM_MODEL', 'deepseek-chat')

            if not api_key:
                print("[!] 未配置 API Key，跳过 AI 确认")
                return findings

            client = OpenAI(api_key=api_key, base_url=base_url)
        except ImportError:
            print("[!] openai 未安装，跳过 AI 确认")
            return findings

        confirmed = []
        for finding in findings[:20]:  # 最多确认20个
            prompt = f"""你是代码安全审计专家。请分析以下代码是否存在真实的安全漏洞。

文件: {finding['file']}
行号: {finding['line']}
疑似类型: {finding['type']}

代码:
```{finding['lang']}
{finding['code_snippet']}
```

请回答:
1. 这是否是一个真实的漏洞？(YES/NO/MAYBE)
2. 如果是，攻击者如何利用？(一句话)
3. 修复建议？(一句话)

格式: VERDICT | 利用方式 | 修复建议"""

            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=200,
                    temperature=0.2,
                )
                answer = response.choices[0].message.content.strip()

                if "YES" in answer.upper() or "MAYBE" in answer.upper():
                    parts = answer.split('|')
                    if len(parts) >= 3:
                        finding['impact'] = parts[1].strip()
                        finding['fix_suggestion'] = parts[2].strip()
                        finding['fix_suggestion_cn'] = parts[2].strip()
                    finding['ai_confirmed'] = True
                    confirmed.append(finding)
            except Exception as e:
                # AI 失败时保留原始发现
                confirmed.append(finding)

        return confirmed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Code Auditor — 源码审计")
    parser.add_argument("source", help="源码目录路径")
    parser.add_argument("--lang", default="auto", help="语言 (php/java/python/go/javascript)")
    parser.add_argument("--no-ai", action="store_true", help="不使用 AI 确认")
    parser.add_argument("--output", "-o", help="输出 JSON 文件路径")
    args = parser.parse_args()

    auditor = CodeAuditor(args.source, args.lang, use_ai=not args.no_ai)
    findings = auditor.audit()

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
        print(f"[+] 结果已保存: {args.output}")
    else:
        print(json.dumps(findings, ensure_ascii=False, indent=2))
