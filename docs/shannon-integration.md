# Shannon 接法

这个项目里，主工具负责发现候选目标和生成审计重点，Shannon 负责二次审计和出最终报告。

## 流程

1. 先正常跑主工具，选中你要审计的项目。
2. 审计完成后，系统会自动在 `workspace/reports/` 里生成：
   - `audit-report-<task>.html`
   - `shannon-handoff-<task>.md`
   - `shannon-handoff-<task>.json`
3. 打开 `shannon-handoff-<task>.md`，里面已经按项目列好了 Shannon 命令。

## 目录

- Shannon 仓库：`integrations/shannon`
- Shannon 输出：`workspace/shannon`

## 注意

- 这个 Shannon 仓库在 Windows 上可能因为个别文件名无法完整 checkout。
- 你这台机器可以直接走 WSL2，Docker Desktop 不必装。
- 现在推荐的启动方式是 `scripts/start-shannon-wsl.sh`。
- Bai 生成的报告和 Shannon 交接包会自动吸收 `workspace/scans/` 里的 Nuclei / Semgrep 结果。
