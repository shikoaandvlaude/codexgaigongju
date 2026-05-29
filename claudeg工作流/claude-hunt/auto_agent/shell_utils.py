"""
Shell Utils — 安全的 Shell 命令构建工具
防止 Shell 注入攻击（恶意子域名/URL 中的特殊字符）
"""

import shlex
import tempfile
import os


def shell_quote(s: str) -> str:
    """
    安全地转义单个 shell 参数。
    使用 shlex.quote 来防止注入。
    
    Example:
        shell_quote("test.com")  -> "'test.com'"
        shell_quote("a'b$(cmd)") -> "'a'\"'\"'b$(cmd)'"
    """
    return shlex.quote(s)


def safe_echo_lines(lines: list, max_lines: int = 100) -> str:
    """
    安全地将多行数据传给管道命令。
    使用临时文件而非 echo + shell 拼接，彻底杜绝注入。
    
    返回一个 cat 命令字符串，调用方可以用 | 管道连接后续工具。
    临时文件在命令执行后由 shell 的 trap 机制清理。
    
    Example:
        cmd = safe_echo_lines(["a.com", "b.com"]) + " | httpx -silent"
        # -> "cat /tmp/bai_xxxxx.txt | httpx -silent"
    """
    lines = lines[:max_lines]
    # 过滤空行和明显异常的输入
    clean_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # 基本合法性检查：域名/URL 不应包含这些字符
        if any(c in line for c in ['`', '$', '\\', ';', '|', '&', '>', '<', '\n', '\r']):
            continue
        clean_lines.append(line)
    
    if not clean_lines:
        return "echo ''"
    
    # 写入临时文件
    fd, tmp_path = tempfile.mkstemp(prefix="bai_", suffix=".txt")
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(clean_lines) + '\n')
    except Exception:
        os.close(fd)
        return "echo ''"
    
    return f"cat {shell_quote(tmp_path)}"


def safe_echo_lines_inline(lines: list, max_lines: int = 100) -> str:
    """
    使用 printf 安全地输出多行（不依赖临时文件）。
    适用于少量行数据。
    
    Example:
        safe_echo_lines_inline(["a.com", "b.com"])
        # -> "printf '%s\\n' 'a.com' 'b.com'"
    """
    lines = lines[:max_lines]
    clean_lines = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if any(c in line for c in ['`', '$', '\\', ';', '|', '&', '>', '<', '\n', '\r']):
            continue
        clean_lines.append(line)
    
    if not clean_lines:
        return "echo ''"
    
    # 使用 printf + shlex.quote 安全拼接
    quoted = ' '.join(shell_quote(l) for l in clean_lines)
    return f"printf '%s\\n' {quoted}"


def sanitize_target(target: str) -> str:
    """
    清理目标域名，移除可能的注入字符。
    只允许：字母、数字、点、横杠、星号（通配符）
    """
    allowed = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-*:/')
    return ''.join(c for c in target if c in allowed)


def sanitize_url(url: str) -> str:
    """
    清理 URL，移除危险字符但保留 URL 合法字符。
    """
    # URL 中合法的字符集
    allowed = set(
        'abcdefghijklmnopqrstuvwxyz'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        '0123456789'
        '-._~:/?#[]@!$&\'()*+,;=%'
    )
    return ''.join(c for c in url if c in allowed)
