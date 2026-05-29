# Web3 Smart Contract Audit Tools

智能合约安全审计工具集，支持 DeepSeek/OpenAI/Ollama 多 LLM 后端。

## 快速开始

```bash
# 1. 安装依赖
pip install openai requests

# 2. 配置 API Key (三选一)
export DEEPSEEK_API_KEY=sk-你的key      # 最便宜，推荐
# export OPENAI_API_KEY=sk-xxx          # 备选
# export OLLAMA_HOST=http://localhost:11434  # 本地免费

# 3. 审计合约
python audit_contract.py --file your_contract.sol

# 4. 从 Etherscan 直接审计（需要 ETHERSCAN_API_KEY）
python audit_contract.py --address 0x1234...abcd --chain eth

# 5. 批量审计目录
python audit_contract.py --dir ./contracts/ --output report.md
```

## 工具说明

| 工具 | 用途 | 状态 |
|------|------|------|
| `audit_contract.py` | **统一入口** — 一键审计，支持文件/目录/链上地址 | ✅ 可用 |
| `gptlens/` | LLM 审计引擎 — Auditor→Critic→Rank 三步验证 | ✅ 已改为多 LLM |
| `oyente/` | EVM 字节码符号执行 — 重入/溢出检测（参考用） | ⚠️ 需 Python 2.7 |
| `events-watcher/` | 区块链事件监控 — 实时监听链上事件存 MySQL | ⚠️ 需 Node.js + MySQL |

## 审计流程

```
合约源码(.sol)
    ↓
[Phase 1: Auditor]  LLM 找出 top-k 漏洞
    ↓
[Phase 2: Critic]   LLM 验证每个漏洞的正确性/严重性/可利用性
    ↓
[Phase 3: Rank]     按综合评分排序
    ↓
Markdown/JSON 报告
```

## 检测的漏洞类型

- 重入攻击 (Reentrancy)
- 整数溢出/下溢 (Integer Overflow)
- tx.origin 认证绕过
- 未检查的外部调用 (Unchecked Call)
- 闪电贷攻击向量
- 价格操纵 (Oracle Manipulation)
- 权限控制缺失 (Access Control)
- 前端运行攻击 (Front-running)
- 自毁函数暴露 (selfdestruct)
- delegatecall 注入

## 赚钱平台

| 平台 | 链接 | 单笔赏金 |
|------|------|---------|
| Immunefi | immunefi.com | $1K - $10M |
| Code4rena | code4rena.com | $500 - $100K |
| Sherlock | sherlock.xyz | $500 - $50K |
| HackenProof | hackenproof.com | $100 - $50K |

## 环境变量

```bash
# LLM (必须配一个)
DEEPSEEK_API_KEY=sk-xxx
OPENAI_API_KEY=sk-xxx
LLM_MODEL=deepseek-chat        # 可覆盖模型
LLM_BASE_URL=https://...       # 可覆盖 API 地址

# Etherscan (可选，用于 --address 模式)
ETHERSCAN_API_KEY=xxx
```
