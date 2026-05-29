# RedOps MCP Server

让 Claude Code 通过 MCP 调用 RedOps Agent 执行渗透测试。

## 前提

RedOps 需要先启动：
```bash
cd redops && python main.py
# 默认运行在 localhost:8000
```

## 配置

```bash
claude mcp add redops python3 /path/to/redops-mcp/server.py
```

## 工具列表

- `redops_chat` — 自然语言对话（让 RedOps Agent 执行任务）
- `redops_scan` — 漏洞扫描（Nuclei）
- `redops_exec` — 执行系统命令
- `redops_fofa` — FOFA 资产搜索
- `redops_targets` — 目标管理
- `redops_status` — 查看状态

## 使用

配好后在 Claude Code 里直接说：
```
用 RedOps 对 target.com 做一个快速漏洞扫描
用 FOFA 搜索 domain="target.com" 的资产
```
