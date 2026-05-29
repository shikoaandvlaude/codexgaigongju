---
name: output-compression
description: 工具输出压缩策略 - 只保留证据、结论和下一步，不回贴整段原文。
metadata:
  node_type: memory
  type: feedback
---

## 压缩模板

每次工具返回后，只输出这 4 项：

- 结论
- 证据
- 风险等级
- 下一步

## 规则

1. 超过 20 行的原始日志，压成 1-3 行摘要。
2. 只保留和目标相关的内容。
3. 原始输出进文件，不进上下文。
4. 同类结果只保留最新一次。
5. 没有新信息就写“无变化”。

## 推荐格式

```md
- conclusion: ...
- evidence: ...
- severity: high|medium|low
- next: ...
```
