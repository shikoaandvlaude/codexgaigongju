# MEMORY

这是工作流的短记忆，不是长文档仓库。

## 只保留 5 栏

- 当前目标
- 已验证事实
- 当前假设
- 下一步
- 阻塞项

## 记录规则

1. 只写已经验证过的内容。
2. 同类结果只保留最新一条。
3. 原始日志留磁盘，不进对话上下文。
4. 每次关机前产出一份 `resume pack`。
5. 新会话先读这一页，再读需要的子文档。

## 推荐读取顺序

1. `MEMORY.md`
2. `output-compression.md`
3. `hermes-skill-evolution.md`
4. 具体任务文档

## 典型 resume pack

```md
- target: ...
- verified: ...
- next: ...
- blockers: ...
- approved skills: ...
```
