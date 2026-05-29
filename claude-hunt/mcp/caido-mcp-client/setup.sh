#!/bin/bash
# Caido MCP 一键安装脚本
# 用法: bash setup.sh

set -e

echo "=== Caido MCP Server 安装 ==="
echo ""

# 检查 Caido 是否运行
if curl -s http://127.0.0.1:8080/health > /dev/null 2>&1; then
    echo "[✓] Caido 已在运行 (127.0.0.1:8080)"
else
    echo "[!] Caido 未运行。请先启动 Caido:"
    echo "    下载: https://caido.io/download"
    echo "    启动后默认监听 127.0.0.1:8080"
    echo ""
fi

# 安装 MCP server
echo "[*] 安装 caido-mcp-server..."
if command -v caido-mcp-server &> /dev/null; then
    echo "[✓] caido-mcp-server 已安装"
else
    curl -fsSL https://raw.githubusercontent.com/c0tton-fluff/caido-mcp-server/main/install.sh | bash
    echo "[✓] caido-mcp-server 安装完成"
fi

# 检查环境变量
echo ""
if [ -z "$CAIDO_PAT" ]; then
    echo "[!] CAIDO_PAT 未设置。请在 Caido 中生成 Personal Access Token:"
    echo "    Settings → Developer → Personal Access Tokens"
    echo ""
    echo "    然后设置环境变量:"
    echo "    export CAIDO_URL=http://127.0.0.1:8080"
    echo "    export CAIDO_PAT=your-token-here"
    echo ""
    echo "    添加到 ~/.bashrc 或 ~/.zshrc 持久化"
else
    echo "[✓] CAIDO_PAT 已设置"
fi

# 配置到 auto_agent
echo ""
echo "=== 配置到你的工具 ==="
echo ""
echo "在 claude-hunt/auto_agent/config.yaml 中添加:"
echo ""
echo "  deep_hunt:"
echo "    proxy: \"http://127.0.0.1:8080\""
echo ""
echo "这样 auto_hunt.py 的所有请求都会被 Caido 记录。"
echo ""
echo "=== 完成 ==="
