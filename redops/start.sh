#!/bin/bash

# RedOps 一键启动脚本 (Kali Linux)
# 作者: RedOps Team
# 功能: 检查环境、安装依赖、启动Web服务和桌宠

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     RedOps 渗透测试Agent ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查Python环境
echo -e "${YELLOW}[*] 检查Python环境...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] 未找到Python3，正在安装...${NC}"
    sudo apt update && sudo apt install -y python3 python3-pip python3-venv
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[+] Python版本: $PYTHON_VERSION${NC}"

# 检查并创建虚拟环境
echo ""
echo -e "${YELLOW}[*] 检查虚拟环境...${NC}"
VENV_DIR="$SCRIPT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}[*] 创建虚拟环境...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# 激活虚拟环境
source "$VENV_DIR/bin/activate"

# 检查并安装依赖
echo ""
echo -e "${YELLOW}[*] 检查并安装依赖...${NC}"

# 检查pip
if ! command -v pip &> /dev/null; then
    python3 -m ensurepip --upgrade
fi

# 安装核心依赖
pip install --upgrade pip -q

# 检查并安装Web服务依赖
echo -e "${YELLOW}[*] 安装Web服务依赖...${NC}"
pip install fastapi uvicorn pydantic requests pyyaml -q 2>/dev/null

# 检查并安装桌宠依赖
echo -e "${YELLOW}[*] 安装桌宠依赖...${NC}"
pip install Pillow tk -q 2>/dev/null

# 检查Nuclei（可选）
echo ""
echo -e "${YELLOW}[*] 检查渗透测试工具...${NC}"
if ! command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[!] Nuclei未安装（可选）${NC}"
    echo -e "${YELLOW}[!] 安装: ${GREEN}pip install nuclei${NC}"
fi

echo ""
echo -e "${GREEN}[+] 环境准备完成！${NC}"
echo ""

# 启动选项
echo -e "${BLUE}请选择启动模式:${NC}"
echo -e "${GREEN}1${NC}. 启动Web界面 (推荐)"
echo -e "${GREEN}2${NC}. 启动桌宠"
echo -e "${GREEN}3${NC}. 同时启动Web和桌宠"
echo -e "${GREEN}4${NC}. 仅安装依赖"
echo ""
read -p "请输入选项 [1-4]: " choice

case $choice in
    1)
        echo ""
        echo -e "${GREEN}[*] 启动Web界面...${NC}"
        echo -e "${GREEN}[*] 访问地址: http://localhost:8000${NC}"
        cd "$SCRIPT_DIR/web"
        python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
        ;;
    2)
        echo ""
        echo -e "${GREEN}[*] 启动桌宠...${NC}"
        cd "$SCRIPT_DIR"
        python3 desktop_pet.py
        ;;
    3)
        echo ""
        echo -e "${GREEN}[*] 同时启动Web和桌宠...${NC}"
        # 后台启动Web
        cd "$SCRIPT_DIR/web"
        python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 &
        WEB_PID=$!
        sleep 2
        
        # 启动桌宠
        cd "$SCRIPT_DIR"
        python3 desktop_pet.py
        
        # 清理
        kill $WEB_PID 2>/dev/null
        ;;
    4)
        echo ""
        echo -e "${GREEN}[+] 依赖安装完成！${NC}"
        ;;
    *)
        echo ""
        echo -e "${RED}[!] 无效选项${NC}"
        ;;
esac

# 退出虚拟环境
deactivate 2>/dev/null
