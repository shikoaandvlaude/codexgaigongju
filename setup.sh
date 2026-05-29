#!/bin/bash
# ============================================================
# Bai-codeagent 一键安装 + 启动脚本
# 用法:
#   chmod +x setup.sh
#   ./setup.sh              # 安装所有依赖
#   ./setup.sh --run        # 安装后启动 Web 面板 + RedOps
#   ./setup.sh --hunt target.com   # 直接启动自动挖掘
#   ./setup.sh --check      # 仅检查工具是否安装
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 确保 PATH 包含所有工具路径
export PATH="/root/.local/share/mise/installs/go/1.25.1/bin:/root/.local/share/mise/shims:/root/.pyenv/shims:/root/.pyenv/bin:/root/.nvm/versions/node/v22.22.3/bin:/root/go/bin:$PATH"
export PYENV_ROOT="/root/.pyenv"
if command -v pyenv &>/dev/null; then
    eval "$(pyenv init -)"
    pyenv global 3.11.15 2>/dev/null
fi
if [ -f "/root/.nvm/nvm.sh" ]; then
    source /root/.nvm/nvm.sh
    nvm use 22 &>/dev/null
fi

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════╗"
echo "║       Bai-codeagent Setup Script             ║"
echo "║       一键安装 + 环境配置                    ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ═══════════════════════════════════════════════════
# 工具检查函数
# ═══════════════════════════════════════════════════

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $1 $(command -v $1)"
        return 0
    else
        echo -e "  ${RED}✗${NC} $1 — 未安装"
        return 1
    fi
}

check_all_tools() {
    echo -e "\n${CYAN}[检查工具安装状态]${NC}\n"
    
    local missing=0
    
    echo "--- 基础运行时 ---"
    check_tool node || ((missing++))
    check_tool python3 || ((missing++))
    check_tool go || ((missing++))
    check_tool curl || ((missing++))
    
    echo ""
    echo "--- Go 安全工具 ---"
    check_tool nuclei || ((missing++))
    check_tool subfinder || ((missing++))
    check_tool httpx || ((missing++))
    check_tool dnsx || ((missing++))
    check_tool dalfox || ((missing++))
    check_tool katana || ((missing++))
    check_tool gau || ((missing++))
    check_tool ffuf || ((missing++))
    
    echo ""
    echo "--- 系统工具 ---"
    check_tool nmap || ((missing++))
    
    echo ""
    echo "--- Python 依赖 ---"
    python3 -c "import httpx" 2>/dev/null && echo -e "  ${GREEN}✓${NC} httpx (Python)" || { echo -e "  ${RED}✗${NC} httpx (Python)"; ((missing++)); }
    python3 -c "import rich" 2>/dev/null && echo -e "  ${GREEN}✓${NC} rich (Python)" || { echo -e "  ${RED}✗${NC} rich (Python)"; ((missing++)); }
    python3 -c "import openai" 2>/dev/null && echo -e "  ${GREEN}✓${NC} openai (Python)" || { echo -e "  ${RED}✗${NC} openai (Python)"; ((missing++)); }
    python3 -c "import playwright" 2>/dev/null && echo -e "  ${GREEN}✓${NC} playwright (Python)" || { echo -e "  ${RED}✗${NC} playwright (Python)"; ((missing++)); }
    python3 -c "import fastapi" 2>/dev/null && echo -e "  ${GREEN}✓${NC} fastapi (Python)" || { echo -e "  ${RED}✗${NC} fastapi (Python)"; ((missing++)); }
    python3 -c "import uvicorn" 2>/dev/null && echo -e "  ${GREEN}✓${NC} uvicorn (Python)" || { echo -e "  ${RED}✗${NC} uvicorn (Python)"; ((missing++)); }
    
    echo ""
    echo "--- 浏览器 ---"
    if [ -d "$HOME/.cache/ms-playwright/chromium-"* ] 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Playwright Chromium"
    else
        echo -e "  ${RED}✗${NC} Playwright Chromium"
        ((missing++))
    fi
    
    echo ""
    if [ $missing -eq 0 ]; then
        echo -e "${GREEN}✅ 所有工具已就绪！${NC}"
    else
        echo -e "${YELLOW}⚠️  缺少 $missing 项依赖${NC}"
    fi
    
    return $missing
}

# ═══════════════════════════════════════════════════
# 安装函数
# ═══════════════════════════════════════════════════

install_go_tools() {
    echo -e "\n${CYAN}[安装 Go 安全工具]${NC}\n"
    
    local tools=(
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/ffuf/ffuf/v2@latest"
    )
    
    for tool in "${tools[@]}"; do
        name=$(echo "$tool" | grep -oP '[^/]+(?=@)')
        if command -v "$name" &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $name 已安装，跳过"
        else
            echo -e "  ${YELLOW}→${NC} 安装 $name ..."
            go install "$tool" 2>&1 | tail -1
            if command -v "$name" &>/dev/null; then
                echo -e "  ${GREEN}✓${NC} $name 安装成功"
            else
                echo -e "  ${RED}✗${NC} $name 安装失败"
            fi
        fi
    done
}

install_system_tools() {
    echo -e "\n${CYAN}[安装系统工具]${NC}\n"
    
    if command -v nmap &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} nmap 已安装"
    else
        echo -e "  ${YELLOW}→${NC} 安装 nmap ..."
        if command -v dnf &>/dev/null; then
            sudo dnf install -y nmap 2>&1 | tail -3
        elif command -v apt-get &>/dev/null; then
            sudo apt-get install -y nmap 2>&1 | tail -3
        elif command -v brew &>/dev/null; then
            brew install nmap 2>&1 | tail -3
        fi
    fi
}

install_python_deps() {
    echo -e "\n${CYAN}[安装 Python 依赖]${NC}\n"
    
    # auto_agent 依赖
    echo -e "  ${YELLOW}→${NC} 安装 claude-hunt/auto_agent 依赖..."
    pip install -r "$SCRIPT_DIR/claude-hunt/auto_agent/requirements.txt" -q 2>&1 | tail -3
    
    # redops 依赖
    if [ -f "$SCRIPT_DIR/redops/requirements.txt" ]; then
        echo -e "  ${YELLOW}→${NC} 安装 redops 依赖..."
        pip install -r "$SCRIPT_DIR/redops/requirements.txt" -q 2>&1 | tail -3
    fi
    
    echo -e "  ${GREEN}✓${NC} Python 依赖安装完成"
}

install_playwright_browser() {
    echo -e "\n${CYAN}[安装 Playwright 浏览器]${NC}\n"
    
    if ls "$HOME/.cache/ms-playwright/chromium-"* &>/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Chromium 已安装"
    else
        echo -e "  ${YELLOW}→${NC} 下载 Chromium..."
        playwright install chromium 2>&1 | tail -3
        echo -e "  ${GREEN}✓${NC} Chromium 安装完成"
    fi
}

setup_config() {
    echo -e "\n${CYAN}[配置文件]${NC}\n"
    
    local config_file="$SCRIPT_DIR/claude-hunt/auto_agent/config.yaml"
    
    if [ -f "$config_file" ]; then
        echo -e "  ${GREEN}✓${NC} config.yaml 已存在"
    else
        cp "$SCRIPT_DIR/claude-hunt/auto_agent/config.yaml.example" "$config_file"
        echo -e "  ${GREEN}✓${NC} 已创建 config.yaml（从 example 复制）"
    fi
    
    # 检查 API Key
    if [ -n "$DEEPSEEK_API_KEY" ]; then
        echo -e "  ${GREEN}✓${NC} DEEPSEEK_API_KEY 已设置（环境变量）"
    elif [ -n "$OPENAI_API_KEY" ]; then
        echo -e "  ${GREEN}✓${NC} OPENAI_API_KEY 已设置（环境变量）"
    else
        echo -e "  ${YELLOW}⚠${NC} 未检测到 LLM API Key"
        echo -e "    设置方式: export DEEPSEEK_API_KEY=\"sk-你的key\""
        echo -e "    或编辑: $config_file"
    fi
    
    # 创建工作目录
    mkdir -p "$HOME/.bai-agent/checkpoints"
    mkdir -p "$HOME/.bai-agent/scope"
    echo -e "  ${GREEN}✓${NC} 工作目录已创建: ~/.bai-agent/"
}

setup_symlink() {
    # 修复 redops 的 import 路径问题
    if [ ! -e "$SCRIPT_DIR/web" ]; then
        ln -s "$SCRIPT_DIR/redops" "$SCRIPT_DIR/web"
        echo -e "  ${GREEN}✓${NC} 创建符号链接: web -> redops"
    fi
}

# ═══════════════════════════════════════════════════
# 启动函数
# ═══════════════════════════════════════════════════

start_web_panel() {
    echo -e "\n${CYAN}[启动 Web 面板]${NC}\n"
    cd "$SCRIPT_DIR"
    echo -e "  ${GREEN}→${NC} http://localhost:3000"
    node server.js &
    WEB_PID=$!
    echo -e "  ${GREEN}✓${NC} Web 面板已启动 (PID: $WEB_PID)"
}

start_redops() {
    echo -e "\n${CYAN}[启动 RedOps Agent]${NC}\n"
    cd "$SCRIPT_DIR/redops"
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
    echo -e "  ${GREEN}→${NC} http://localhost:8000"
    python3 main.py &
    REDOPS_PID=$!
    echo -e "  ${GREEN}✓${NC} RedOps Agent 已启动 (PID: $REDOPS_PID)"
}

start_auto_hunt() {
    local target="$1"
    local mode="${2:-auto}"
    
    echo -e "\n${CYAN}[启动自动挖掘]${NC}\n"
    echo -e "  目标: ${YELLOW}$target${NC}"
    echo -e "  模式: ${YELLOW}$mode${NC}"
    echo ""
    
    cd "$SCRIPT_DIR/claude-hunt/auto_agent"
    python3 auto_hunt.py --target "$target" --mode "$mode"
}

# ═══════════════════════════════════════════════════
# 主入口
# ═══════════════════════════════════════════════════

case "${1:-install}" in
    --check|-c)
        check_all_tools
        ;;
    --run|-r)
        echo -e "${GREEN}启动所有服务...${NC}"
        setup_symlink
        start_web_panel
        start_redops
        echo -e "\n${GREEN}═══════════════════════════════════════${NC}"
        echo -e "${GREEN}  Web 面板: http://localhost:3000${NC}"
        echo -e "${GREEN}  RedOps:   http://localhost:8000${NC}"
        echo -e "${GREEN}═══════════════════════════════════════${NC}"
        echo -e "\n按 Ctrl+C 停止所有服务"
        wait
        ;;
    --hunt|-h)
        if [ -z "$2" ]; then
            echo -e "${RED}用法: ./setup.sh --hunt target.com [auto|semi]${NC}"
            exit 1
        fi
        start_auto_hunt "$2" "${3:-auto}"
        ;;
    install|--install|-i|"")
        echo -e "${GREEN}开始完整安装...${NC}\n"
        
        install_go_tools
        install_system_tools
        install_python_deps
        install_playwright_browser
        setup_config
        setup_symlink
        
        echo -e "\n${GREEN}════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}  ✅ 安装完成！${NC}"
        echo -e "${GREEN}════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${CYAN}启动服务:${NC}     ./setup.sh --run"
        echo -e "  ${CYAN}自动挖掘:${NC}     ./setup.sh --hunt target.com"
        echo -e "  ${CYAN}半自动挖掘:${NC}   ./setup.sh --hunt target.com semi"
        echo -e "  ${CYAN}检查状态:${NC}     ./setup.sh --check"
        echo ""
        echo -e "  ${YELLOW}⚠ 别忘了设置 API Key:${NC}"
        echo -e "    export DEEPSEEK_API_KEY=\"sk-你的key\""
        echo ""
        
        # 最终检查
        check_all_tools
        ;;
    *)
        echo "用法: ./setup.sh [命令]"
        echo ""
        echo "命令:"
        echo "  (空)/install    完整安装所有依赖"
        echo "  --check/-c      检查工具安装状态"
        echo "  --run/-r        启动 Web面板 + RedOps"
        echo "  --hunt/-h       启动自动挖掘 (需要目标参数)"
        echo ""
        echo "示例:"
        echo "  ./setup.sh                      # 安装"
        echo "  ./setup.sh --run                # 启动服务"
        echo "  ./setup.sh --hunt example.com   # 全自动挖掘"
        echo "  ./setup.sh --hunt example.com semi  # 半自动"
        ;;
esac
