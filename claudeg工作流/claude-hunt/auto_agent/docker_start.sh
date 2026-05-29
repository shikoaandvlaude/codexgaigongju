#!/bin/bash
# =============================================================================
# Auto-Hunt Agent Docker 启动脚本
# 用法: ./docker_start.sh [auto_hunt.py 参数...]
# 示例: ./docker_start.sh --target example.com --mode auto
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Auto-Hunt Agent Docker 启动${NC}"

# 检查config.yaml是否存在，不存在则从example复制
if [ ! -f "config.yaml" ]; then
    if [ -f "config.yaml.example" ]; then
        cp config.yaml.example config.yaml
        echo -e "${YELLOW}[!] 已从 config.yaml.example 创建 config.yaml${NC}"
        echo -e "${YELLOW}[!] 请编辑 config.yaml 配置你的API密钥和目标后重新运行${NC}"
        exit 1
    else
        echo -e "${YELLOW}[!] config.yaml.example 不存在，请手动创建 config.yaml${NC}"
        exit 1
    fi
fi

# 创建必要的目录
mkdir -p ~/.bai-agent/checkpoints
mkdir -p ~/.bai-agent/scope
mkdir -p output

echo -e "${GREEN}[*] 构建Docker镜像...${NC}"
docker compose -f docker-compose.hunter.yml build hunter

echo -e "${GREEN}[*] 启动Hunter容器...${NC}"
docker compose -f docker-compose.hunter.yml run --rm hunter "$@"
