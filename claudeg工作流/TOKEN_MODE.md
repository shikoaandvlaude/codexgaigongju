# Token Mode

这是给日常跑工具用的短版指南。目标只有一个：**少读、少传、少重复**。

## 推荐默认

```bash
$env:BRAIN_MAX_CTX="24576"
$env:BRAIN_MAX_RESP="4096"
$env:AGENT_MAX_OBS_CHARS="1800"
$env:AGENT_MAX_CTX_CHARS="12000"
$env:AGENT_RECENT_OBS="2"
```

## 工作流

1. 先做 recon，只保留活跃资产和关键技术栈。
2. 再做 hunt，只把高置信结果送给模型。
3. 每步只保留最近结果和少量笔记。
4. 报告单独生成，不要把整轮过程反复塞回上下文。
5. 无新发现就停，别让模型陪跑。

## 省 token 习惯

- 不要把 `know.md` 整份塞进上下文。
- 只读当前阶段需要的命令或规则。
- 缓存已验证 findings，避免重复问模型。
- 让摘要进上下文，让原始日志留在磁盘。
- 低价值目标直接降级，不要硬搜。

## 入口

```bash
npm start
python C:\Users\admin\Desktop\newgj\claude-hunt\agent.py --target example.com
```

## 什么时候看长文档

- 需要完整战术库时看 `know.md`
- 需要全面流程时看 `readmefirst.md`
- 需要自动化细节时看 `claude-hunt/SKILL.md`
