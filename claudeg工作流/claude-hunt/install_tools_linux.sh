#!/bin/bash
# =============================================================================
# Bug Bounty Tool Installer — Linux 版本
# 支持: Kali Linux / Parrot OS / Ubuntu / Debian
# 用法: chmod +x install_tools_linux.sh && sudo bash install_tools_linux.sh
#
# 注意事项:
#   - 国内用户建议先配置 Go 代理: export GOPROXY=https://goproxy.cn,direct
#   - 如果 GitHub 访问困难，可以设置代理或使用镜像
#   - 首次运行需要 root 权限 (sudo)
# =============================================================================

set -euo pipefail

# ── 颜色输出 ────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_err()   { echo -e "${RED}[-]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_info()  { echo -e "${CYAN}[*]${NC} $1"; }

# ── 检测系统 ────────────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$ID"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS_NAME="$DISTRIB_ID"
        OS_VERSION="$DISTRIB_RELEASE"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi
    echo "$OS_NAME"
}

OS=$(detect_os)

echo ""
echo "============================================="
echo "  Bug Bounty 工具安装器 — Linux 版"
echo "  系统: $OS ($OS_VERSION)"
echo "  时间: $(date)"
echo "============================================="
echo ""

# ── 检测是否有 root 权限 ────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
    log_warn "建议使用 sudo 运行以安装系统级工具"
    log_warn "部分工具将安装到 ~/go/bin (不需要 root)"
    USE_SUDO=""
else
    USE_SUDO="sudo"
fi

# ── 配置 Go 代理（国内用户必备）────────────────────────────────────────────
setup_go_proxy() {
    if [ -z "${GOPROXY:-}" ]; then
        log_info "配置 Go 代理 (国内加速)..."
        export GOPROXY="https://goproxy.cn,direct"
        export GONOSUMCHECK="*"
        
        # 写入 shell 配置文件（持久化）
        SHELL_RC=""
        if [ -f "$HOME/.zshrc" ]; then
            SHELL_RC="$HOME/.zshrc"
        elif [ -f "$HOME/.bashrc" ]; then
            SHELL_RC="$HOME/.bashrc"
        fi
        
        if [ -n "$SHELL_RC" ]; then
            if ! grep -q "GOPROXY" "$SHELL_RC" 2>/dev/null; then
                echo "" >> "$SHELL_RC"
                echo "# Go 代理 (国内加速)" >> "$SHELL_RC"
                echo 'export GOPROXY="https://goproxy.cn,direct"' >> "$SHELL_RC"
                echo 'export GOPATH="$HOME/go"' >> "$SHELL_RC"
                echo 'export PATH="$HOME/go/bin:$PATH"' >> "$SHELL_RC"
                log_ok "Go 代理已写入 $SHELL_RC"
            fi
        fi
    else
        log_ok "Go 代理已配置: $GOPROXY"
    fi
}

# ── Step 1: 安装系统依赖 ────────────────────────────────────────────────────
install_system_deps() {
    log_info "Step 1: 安装系统依赖..."
    
    $USE_SUDO apt update -qq 2>/dev/null
    
    # 基础工具
    PKGS=(
        "git"
        "curl"
        "wget"
        "jq"
        "python3"
        "python3-pip"
        "nmap"
        "dnsutils"      # dig, nslookup
        "whois"
        "chromium-browser"  # 用于无头浏览器截图
        "unzip"
        "build-essential"
        "tesseract-ocr"         # 本地OCR引擎
        "tesseract-ocr-chi-sim" # 中文识别语言包
        "proxychains4"          # 代理链
    )
    
    for pkg in "${PKGS[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            log_ok "$pkg 已安装"
        else
            log_info "  安装 $pkg..."
            $USE_SUDO apt install -y "$pkg" 2>/dev/null && log_ok "$pkg 安装成功" || log_warn "$pkg 安装失败，继续..."
        fi
    done
}

# ── Step 2: 安装 Go 语言 ────────────────────────────────────────────────────
install_golang() {
    log_info "Step 2: 安装 Go 语言..."
    
    if command -v go &>/dev/null; then
        GO_VER=$(go version | grep -oP 'go\d+\.\d+')
        log_ok "Go 已安装: $GO_VER"
        return 0
    fi
    
    # 下载最新 Go
    GO_VERSION="1.22.4"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  GO_ARCH="amd64" ;;
        aarch64) GO_ARCH="arm64" ;;
        armv7l)  GO_ARCH="armv6l" ;;
        *)       GO_ARCH="amd64" ;;
    esac
    
    GO_URL="https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    log_info "  下载 Go $GO_VERSION ($GO_ARCH)..."
    
    # 国内镜像备选
    if ! curl -sI "$GO_URL" &>/dev/null; then
        GO_URL="https://golang.google.cn/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        log_info "  使用国内镜像下载..."
    fi
    
    wget -q "$GO_URL" -O /tmp/go.tar.gz || { log_err "Go 下载失败"; return 1; }
    $USE_SUDO rm -rf /usr/local/go
    $USE_SUDO tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    
    # 配置 PATH
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    export GOPATH="$HOME/go"
    mkdir -p "$GOPATH/bin"
    
    if go version &>/dev/null; then
        log_ok "Go $(go version | grep -oP 'go\d+\.\d+') 安装成功"
    else
        log_err "Go 安装失败"
        return 1
    fi
}

# ── Step 3: 安装 Ollama（本地 LLM 运行时 — brain.py 核心依赖）────────────────
install_ollama() {
    log_info "Step 3: 安装 Ollama (本地LLM引擎)..."
    
    if command -v ollama &>/dev/null; then
        log_ok "Ollama 已安装: $(ollama --version 2>&1 | head -1)"
        return 0
    fi
    
    log_info "  下载并安装 Ollama..."
    if curl -fsSL https://ollama.com/install.sh | sh 2>/dev/null; then
        log_ok "Ollama 安装成功"
        log_warn "提示: 安装后运行 'ollama pull deepseek-r1:8b' 下载模型"
    else
        log_warn "Ollama 安装失败，手动安装: curl -fsSL https://ollama.com/install.sh | sh"
    fi
}

# ── Step 4: 安装 Go 安全工具 (ProjectDiscovery 全家桶) ──────────────────────
install_go_tools() {
    log_info "Step 4: 安装 Go 安全工具 (ProjectDiscovery)..."
    
    setup_go_proxy
    
    export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"
    export GOPATH="${GOPATH:-$HOME/go}"
    
    # ProjectDiscovery 工具集（完整）
    declare -A GO_TOOLS=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        ["uncover"]="github.com/projectdiscovery/uncover/cmd/uncover@latest"
        ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
        ["alterx"]="github.com/projectdiscovery/alterx/cmd/alterx@latest"
        ["pdtm"]="github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
    )
    
    # 其他 Go 工具
    declare -A OTHER_GO_TOOLS=(
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["anew"]="github.com/tomnomnom/anew@latest"
        ["gf"]="github.com/tomnomnom/gf@latest"
        ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
        ["subjack"]="github.com/haccer/subjack@latest"
        ["kiterunner"]="github.com/assetnote/kiterunner/cmd/kr@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
        ["gowitness"]="github.com/sensepost/gowitness@latest"
        ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/...@master"
        ["trufflehog"]="github.com/trufflesecurity/trufflehog/v3@latest"
        ["gitleaks"]="github.com/gitleaks/gitleaks/v8@latest"
        ["subzy"]="github.com/PentestPad/subzy@latest"
    )
    
    echo ""
    log_info "  [ProjectDiscovery 工具]"
    for tool in "${!GO_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "  $tool 已安装 ($(which "$tool"))"
        else
            log_info "  安装 $tool..."
            if go install "${GO_TOOLS[$tool]}" 2>/dev/null; then
                log_ok "  $tool 安装成功"
            else
                log_err "  $tool 安装失败"
            fi
        fi
    done
    
    echo ""
    log_info "  [其他 Go 工具]"
    for tool in "${!OTHER_GO_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "  $tool 已安装"
        else
            log_info "  安装 $tool..."
            if go install "${OTHER_GO_TOOLS[$tool]}" 2>/dev/null; then
                log_ok "  $tool 安装成功"
            else
                log_err "  $tool 安装失败"
            fi
        fi
    done
}

# ── Step 5: 安装 Python 工具 ────────────────────────────────────────────────
install_python_tools() {
    log_info "Step 5: 安装 Python 工具..."
    
    # 确保 pip 可用
    if ! command -v pip3 &>/dev/null; then
        $USE_SUDO apt install -y python3-pip 2>/dev/null
    fi
    
    PY_TOOLS=(
        "arjun"             # 参数发现（主动）
        "paramspider"       # 参数发现（被动，从WebArchive挖）
        "dirsearch"         # 目录扫描（注意：对SRC慎用批量模式）
        "pyjwt"             # JWT 解析
        "requests"          # HTTP 库
        "pytesseract"       # 本地OCR（验证码识别备选）
        "Pillow"            # 图像处理
        "graphqlmap"        # GraphQL测试
        "corsscanner"       # CORS错配检测
        "wafw00f"           # WAF识别
        "linkfinder"        # JS端点提取
        "openredirex"       # 开放重定向检测
        "uro"               # URL去重（智能去相似URL）
        "beautifulsoup4"    # HTML解析
        "selenium"          # 浏览器自动化（Playwright备选）
        "rich"              # 终端美化输出
        "ollama"            # Ollama Python SDK（brain.py核心依赖）
        "langgraph"         # LLM Agent图引擎
        "langchain-ollama"  # LangChain Ollama集成
        "playwright"        # 无头浏览器自动化
        # 注意：sqlmap 不自动安装 — SRC实名情况下不要用自动化注入工具
        # SQL注入应该让AI手工构造payload，流量可控
    )
    
    for tool in "${PY_TOOLS[@]}"; do
        if pip3 show "$tool" &>/dev/null 2>&1 || command -v "$tool" &>/dev/null; then
            log_ok "  $tool 已安装"
        else
            log_info "  安装 $tool..."
            pip3 install "$tool" --break-system-packages 2>/dev/null || \
            pip3 install "$tool" 2>/dev/null && log_ok "  $tool 安装成功" || log_warn "  $tool 安装失败"
        fi
    done
    
    # 安装 Playwright 浏览器
    if command -v playwright &>/dev/null || pip3 show playwright &>/dev/null 2>&1; then
        log_info "  安装 Playwright Chromium..."
        playwright install chromium 2>/dev/null && log_ok "  Playwright Chromium 安装成功" || log_warn "  Playwright 浏览器安装失败，手动运行: playwright install chromium"
    fi
}

# ── Step 6: 更新 Nuclei 模板 ────────────────────────────────────────────────
update_nuclei_templates() {
    log_info "Step 6: 更新 Nuclei 模板..."
    
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates 2>/dev/null && log_ok "Nuclei 模板已更新" || log_warn "模板更新失败，手动运行: nuclei -update-templates"
    else
        log_warn "nuclei 未安装，跳过模板更新"
    fi
    
    # 安装自定义国产 CMS 模板
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    CN_TEMPLATES="$SCRIPT_DIR/tools/nuclei-templates-cn"
    if [ -d "$CN_TEMPLATES" ]; then
        log_ok "国产 CMS 模板目录已就位: $CN_TEMPLATES"
        TEMPLATE_COUNT=$(find "$CN_TEMPLATES" -name "*.yaml" | wc -l)
        log_ok "  共 $TEMPLATE_COUNT 个自定义模板"
    fi
}

# ── Step 7: 配置 gf patterns ────────────────────────────────────────────────
setup_gf_patterns() {
    log_info "Step 7: 配置 gf patterns (URL分类规则)..."
    
    GF_DIR="$HOME/.gf"
    if [ -d "$GF_DIR" ] && [ "$(ls -A "$GF_DIR" 2>/dev/null)" ]; then
        log_ok "gf patterns 已存在 ($GF_DIR)"
        return 0
    fi
    
    mkdir -p "$GF_DIR"
    
    # 克隆常用 patterns
    if git clone https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null; then
        cp /tmp/gf-patterns/*.json "$GF_DIR/" 2>/dev/null
        rm -rf /tmp/gf-patterns
        log_ok "gf patterns 安装成功 ($(ls "$GF_DIR"/*.json 2>/dev/null | wc -l) 个规则)"
    else
        log_warn "gf patterns 下载失败（可能需要代理访问 GitHub）"
        log_warn "手动安装: git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf"
    fi
}

# ── Step 8: 下载 Wordlists ──────────────────────────────────────────────────
setup_wordlists() {
    log_info "Step 8: 下载 Wordlists (字典)..."
    
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    WORDLIST_DIR="$SCRIPT_DIR/tools/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    declare -A WORDLISTS=(
        ["common.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        ["api-endpoints.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt"
        ["params-common.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
        ["directories.txt"]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
    )
    
    for name in "${!WORDLISTS[@]}"; do
        filepath="$WORDLIST_DIR/$name"
        if [ -f "$filepath" ] && [ -s "$filepath" ]; then
            log_ok "  $name 已存在 ($(wc -l < "$filepath") 行)"
        else
            log_info "  下载 $name..."
            if curl -sL "${WORDLISTS[$name]}" -o "$filepath" && [ -s "$filepath" ]; then
                log_ok "  $name 下载成功 ($(wc -l < "$filepath") 行)"
            else
                log_warn "  $name 下载失败"
            fi
        fi
    done
    
    # 中文目录字典（国产CMS常见路径）
    CN_WORDLIST="$WORDLIST_DIR/cn-common-paths.txt"
    if [ ! -f "$CN_WORDLIST" ]; then
        log_info "  生成中国常见路径字典..."
        cat > "$CN_WORDLIST" << 'EOF'
# 国产 CMS / 框架常见路径
/admin
/admin.php
/admin/login
/admin/login.php
/manage
/manager
/system
/login.php
/user/login
/api/user/login
# 若依
/prod-api/login
/prod-api/captchaImage
/prod-api/system/user/list
/dev-api/login
# ThinkPHP
/index.php/Home/Login/index
/index.php?s=/Home/Login/index
/public/index.php
/runtime/
/application/database.php
# 泛微 OA
/weaver/
/ecology/
/seeyon/
/wui/
/mobile/
/api/hrm/
/bsh.servlet.BshServlet
# 用友
/NCCloud/
/nc/
/servlet/
/uapws/
/yyoa/
# Nacos
/nacos/
/nacos/v1/auth/login
/nacos/v1/cs/configs
/actuator
/actuator/env
/actuator/heapdump
# Spring Boot
/actuator/health
/actuator/info
/actuator/mappings
/swagger-ui.html
/swagger-ui/
/v2/api-docs
/v3/api-docs
/druid/
/druid/login.html
# 宝塔面板
/bt
/phpmyadmin
/pma
# 常见备份
/backup.zip
/backup.rar
/backup.tar.gz
/data.zip
/db.sql
/database.sql
/.env
/.git/config
/.svn/entries
/.DS_Store
/web.config
/crossdomain.xml
/sitemap.xml
/robots.txt
# 安装目录
/install/
/install.php
/install/index.php
/setup/
EOF
        log_ok "  cn-common-paths.txt 生成成功 ($(wc -l < "$CN_WORDLIST") 行)"
    fi
}

# ── Step 9: 验证安装结果 ────────────────────────────────────────────────────
verify_installation() {
    echo ""
    echo "============================================="
    log_info "Step 9: 验证安装结果"
    echo "============================================="
    echo ""
    
    # 确保 PATH 包含 go/bin
    export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"
    
    CRITICAL_TOOLS=("subfinder" "httpx" "nuclei" "ffuf" "nmap" "katana" "gau" "dalfox" "interactsh-client" "paramspider" "arjun" "kiterunner" "ollama")
    OPTIONAL_TOOLS=("dnsx" "naabu" "anew" "gf" "qsreplace" "subjack" "subzy" "gowitness" "waybackurls" "hakrawler" "crlfuzz" "wafw00f" "tesseract" "proxychains4" "amass" "gospider" "uncover" "notify" "alterx" "pdtm" "trufflehog" "gitleaks" "openredirex" "corscanner" "uro" "jq")
    
    INSTALLED=0
    MISSING=0
    
    echo -e "  ${BOLD}[核心工具]${NC}"
    for tool in "${CRITICAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "  $tool: $(which "$tool")"
            ((INSTALLED++))
        else
            log_err "  $tool: 未安装 ❌"
            ((MISSING++))
        fi
    done
    
    echo ""
    echo -e "  ${BOLD}[辅助工具]${NC}"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_ok "  $tool: $(which "$tool")"
            ((INSTALLED++))
        else
            log_warn "  $tool: 未安装 (可选)"
        fi
    done
    
    echo ""
    echo "============================================="
    echo -e "  核心工具: ${GREEN}$INSTALLED${NC} 已安装, ${RED}$MISSING${NC} 缺失"
    echo "============================================="
    
    if [ "$MISSING" -gt 0 ]; then
        echo ""
        log_warn "部分核心工具未安装。可能的原因："
        log_warn "  1. 网络问题 → 配置代理: export https_proxy=http://127.0.0.1:7890"
        log_warn "  2. Go 代理 → export GOPROXY=https://goproxy.cn,direct"
        log_warn "  3. 权限问题 → 用 sudo 重新运行"
        echo ""
        log_warn "手动安装单个工具:"
        log_warn "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    fi
}

# ── Step 10: 生成环境配置总结 ────────────────────────────────────────────────
print_summary() {
    echo ""
    echo "============================================="
    echo -e "  ${BOLD}安装完成！下一步操作：${NC}"
    echo "============================================="
    echo ""
    echo "  1. 重新加载 shell 配置:"
    echo "     source ~/.bashrc  或  source ~/.zshrc"
    echo ""
    echo "  2. 验证工具是否在 PATH 中:"
    echo "     which subfinder httpx nuclei"
    echo ""
    echo "  3. 安装 Claude Code skills:"
    echo "     bash claude-hunt/install.sh"
    echo ""
    echo "  4. 开始使用:"
    echo "     claude"
    echo "     /recon target.com"
    echo "     /autopilot target.com --normal"
    echo ""
    echo "  ⚠️  提醒:"
    echo "     - 确保你在 SRC 授权范围内测试"
    echo "     - 国内目标不要用 sqlmap 等自动化工具（实名制）"
    echo "     - 首次使用先运行: python3 claude-hunt/tools/hunt.py --setup-wordlists"
    echo ""
    echo "============================================="
    echo ""
    
    # 写入 PATH 提示
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo ""
        log_warn "⚠️  请将以下内容加入你的 shell 配置文件 (~/.bashrc 或 ~/.zshrc):"
        echo ""
        echo '    export GOPATH="$HOME/go"'
        echo '    export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"'
        echo '    export GOPROXY="https://goproxy.cn,direct"'
        echo ""
    fi
}

# ── 主流程 ──────────────────────────────────────────────────────────────────
main() {
    install_system_deps
    echo ""
    install_golang
    echo ""
    install_ollama
    echo ""
    install_go_tools
    echo ""
    install_python_tools
    echo ""
    update_nuclei_templates
    echo ""
    setup_gf_patterns
    echo ""
    setup_wordlists
    echo ""
    verify_installation
    print_summary
}

main "$@"
