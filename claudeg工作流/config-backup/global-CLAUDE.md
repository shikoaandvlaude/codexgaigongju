# CLAUDE.md

> DS (DeepSeek V4) 套 CC 壳执行，GPT 套 Codex 做产品经理。

## Karpathy 规则
- 不吞异常、函数≤50行、不猜测性代码、不引入不必要依赖
- 编辑现有文件优先、三条相似>一条抽象、不写注释/docstring 除非 WHY 不显然
- 安全红线: 命令注入/XSS/SQL注入 → 写了立刻修
- 不创建 README/md 除非要求、不半成品、不回退兼容 hack
- 测试=真数据库不mock、UI改动先浏览器验证

## 省钱
- 同项目同会话不换窗口、先读TASKS.md再干活、批量操作
- 缓存: 同会话~80%命中 / 新目标~5%命中 → 4x价格差

## 四层架构
GPT(Codex/PM)→DS(CC壳/执行)→Hermes(渗透/便宜模型)→Kali MCP(执行)
详见 memory → four-layer-architecture.md | 留言板协议 → TASKS.md

## 路径
- 项目: C:\Users\admin\Desktop\newgj | 启动: node server.js (:3000)
- 工具: E:\go\bin\ (nuclei/subfinder/httpx/katana/ffuf等30个)
- 模板: E:\tools\nuclei-templates\ (12,648个)
- Hermes: ~/.hermes/venv/Scripts/hermes.exe | Web: localhost:9119
- Kali MCP: ~/tools/MCP-Kali-Server | RedOps: ~/tools/RedOps-Agent (:18001)
- 审计知识库: ~/.claude/audit-knowledge.md

## Cursor
执行层 Compose 2.5（默认），不要 Fast(6x价格) 或 Composer 2(同价更差)

## 语言
中文 | 日志: ~/.claude/logs/

## 当前任务
读 TASKS.md
