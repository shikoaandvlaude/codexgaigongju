"""
Hunt Logger — 日志系统
输出到桌面 doing_YYYY-MM-DD.md
"""

import os
import platform
from datetime import datetime


class HuntLogger:
    """渗透日志记录器"""
    
    def __init__(self, config: dict):
        self.config = config
        self.log_config = config.get('log', {})
        self.verbose = self.log_config.get('verbose', True)
        self.entries = []
        self.start_time = datetime.now()
        
        # 确定日志路径（桌面）
        if self.log_config.get('desktop', True):
            desktop = self._get_desktop_path()
        else:
            desktop = os.path.dirname(os.path.abspath(__file__))
        
        prefix = self.log_config.get('filename_prefix', 'doing')
        date_str = self.start_time.strftime('%Y-%m-%d')
        self.log_path = os.path.join(desktop, f"{prefix}_{date_str}.md")
        
        # 如果文件已存在，追加
        self.file_mode = 'a' if os.path.exists(self.log_path) else 'w'
    
    def _get_desktop_path(self) -> str:
        """获取日志输出路径（跨平台 + Docker 兼容）"""
        # 优先使用环境变量指定的输出目录
        env_output = os.environ.get('BAI_LOG_DIR')
        if env_output:
            os.makedirs(env_output, exist_ok=True)
            return env_output
        
        system = platform.system()
        if system == "Windows":
            return os.path.join(os.path.expanduser("~"), "Desktop")
        elif system == "Darwin":  # macOS
            return os.path.join(os.path.expanduser("~"), "Desktop")
        else:  # Linux
            # 先试 XDG Desktop
            xdg = os.path.join(os.path.expanduser("~"), "Desktop")
            if os.path.exists(xdg):
                return xdg
            # 中文系统
            cn_desktop = os.path.join(os.path.expanduser("~"), "桌面")
            if os.path.exists(cn_desktop):
                return cn_desktop
            # Docker/服务器环境: 使用 output 子目录
            fallback = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
            os.makedirs(fallback, exist_ok=True)
            return fallback
    
    def write_header(self, target: str, mode: str):
        """写日志头"""
        header = f"""
---

# 🎯 SRC 挖掘日志 — {target}

| 项目 | 值 |
|------|-----|
| 目标 | `{target}` |
| 模式 | {mode} |
| 开始时间 | {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} |
| Agent | Bai Auto-Hunt v1.0 |

---

"""
        self._write(header)
    
    def log_phase_start(self, phase_name: str):
        """记录阶段开始"""
        now = datetime.now().strftime('%H:%M:%S')
        entry = f"\n## 📌 {phase_name} [{now}]\n\n"
        self._write(entry)
    
    def log_phase_end(self, phase_name: str, findings: dict):
        """记录阶段结束"""
        now = datetime.now().strftime('%H:%M:%S')
        summary_parts = []
        for key, value in findings.items():
            if isinstance(value, list) and value:
                summary_parts.append(f"- {key}: {len(value)} 条")
        
        summary = "\n".join(summary_parts) if summary_parts else "- 无新发现"
        entry = f"\n### ✅ {phase_name} 结束 [{now}]\n\n{summary}\n\n---\n"
        self._write(entry)
    
    def log_command(self, command: str, result: dict, ai_analysis: str = ""):
        """记录一条命令执行"""
        now = datetime.now().strftime('%H:%M:%S')
        status = "✓" if result.get('success') else "✗"
        
        output = result.get('output', '')
        # 截断过长输出
        if len(output) > 1000:
            output = output[:1000] + "\n... (截断)"
        
        entry = f"""
#### [{now}] {status} 命令执行

```bash
{command}
```

<details>
<summary>输出 ({len(result.get('output', ''))} 字符)</summary>

```
{output}
```

</details>

"""
        if ai_analysis:
            entry += f"> 🤖 AI分析: {ai_analysis}\n\n"
        
        self._write(entry)
    
    def log_event(self, event_type: str, message: str):
        """记录事件"""
        now = datetime.now().strftime('%H:%M:%S')
        emoji_map = {
            "REDLINE_STOP": "🚨",
            "USER_INTERRUPT": "⏸️",
            "ERROR": "❌",
            "SKIP": "⏭️",
            "FINDING": "🎯",
            "WARNING": "⚠️",
        }
        emoji = emoji_map.get(event_type, "📝")
        entry = f"\n> {emoji} **[{event_type}]** [{now}] {message}\n\n"
        self._write(entry)
    
    def log_trace_analysis(self, trace_result: dict):
        """记录痕迹分析"""
        now = datetime.now().strftime('%H:%M:%S')
        entry = f"""
### 🔍 痕迹分析 [{now}]

**总结:** {trace_result.get('summary', '无')}

**可挖线索:**
"""
        leads = trace_result.get('leads', [])
        if leads:
            for lead in leads:
                entry += f"- {lead}\n"
        else:
            entry += "- 暂无明显线索\n"
        
        entry += f"\n**建议下一步:** {trace_result.get('next_action', '继续当前流程')}\n\n"
        self._write(entry)
    
    def log_redline_check(self, result: dict):
        """记录红线检查"""
        now = datetime.now().strftime('%H:%M:%S')
        status = "🟢 通过" if not result.get('stop') else "🔴 触发停止"
        entry = f"\n> 🛡️ **红线审查** [{now}] {status}"
        if result.get('warnings'):
            entry += f" | 警告: {', '.join(result['warnings'])}"
        entry += "\n\n"
        self._write(entry)
    
    def write_footer(self, findings: dict):
        """写日志尾"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        footer = f"""
---

## 📊 最终汇总

| 指标 | 数量 |
|------|------|
| 子域名 | {len(findings.get('subdomains', []))} |
| 存活主机 | {len(findings.get('alive_hosts', []))} |
| URL | {len(findings.get('urls', []))} |
| 参数 | {len(findings.get('params', []))} |
| **漏洞** | **{len(findings.get('vulnerabilities', []))}** |
| 密钥泄露 | {len(findings.get('secrets', []))} |

**耗时:** {duration}
**结束时间:** {end_time.strftime('%Y-%m-%d %H:%M:%S')}

---
"""
        # 如果有漏洞，列出来
        vulns = findings.get('vulnerabilities', [])
        if vulns:
            footer += "\n### 🎯 发现的漏洞\n\n"
            for i, v in enumerate(vulns, 1):
                footer += f"{i}. **{v.get('type', '未知')}** — {v.get('url', '?')} — {v.get('severity', '?')}\n"
                if v.get('detail'):
                    footer += f"   - {v['detail']}\n"
        
        self._write(footer)
    
    def _write(self, content: str):
        """写入文件"""
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print(f"[日志写入失败] {e}")
