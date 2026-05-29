---
name: hermes-skill-evolution
description: Hermes 发现必须先进入待审队列，再由 Codex/Claude 复核后才能晋升为 skill，避免自写噪音和一次性技巧。
metadata:
  node_type: memory
  type: feedback
---

Hermes 只负责发现和归档，不直接改写自己的 skill。

晋升门槛:
1. 同一 technique 至少在两个独立目标或两个独立会话中重复命中。
2. 必须有可复现的证据，不接受 403/404、理论推断、单次偶发命中。
3. 先进入 `[PENDING_REVIEW]` 队列，再由 Codex / Claude Code 审核。
4. 只有 `[APPROVED]` 才能同步进 `SKILL.md`。

落盘规则:
- Hermes 只产出候选，不直接修改 skill 文件。
- `sync_skills.py --merge-approved` 只合并已批准项。
- 未通过门槛的内容只保留在会话记录或日常报告里。

这样做的目的很简单:
- 把一次性噪音挡在长期记忆外面。
- 让 skill 只积累稳定、可复用的模式。
- 让 Hermes 持续进化，但不发疯。
