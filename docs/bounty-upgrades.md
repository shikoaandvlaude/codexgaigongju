# 赏金挖洞增强包

已经接入三个辅助项目：

- `integrations/semgrep-rules`：白盒规则库，适合审计本地镜像代码。
- `integrations/nuclei-templates`：黑盒模板库，适合授权范围内的指纹、CVE、配置错误验证。
- `integrations/shannon`：二次审计和报告整理，适合 Bai 跑完之后接手复核。

## 推荐用法

1. Bai 先跑发现和审计，筛出像样的候选。
2. 对白盒项目，用 Semgrep 规则做第二层静态扫描。
3. 对线上资产，只在 HackerOne/SRC 明确授权范围内用 Nuclei 模板验证。
4. 对高价值候选，用 Shannon 做二次审计和中文报告整理。

你这台机器如果装不上 Docker Desktop，Shannon 仍然能走 WSL2 里的 Docker。优先用 `scripts/start-shannon-wsl.sh`。

## 更新

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\admin\Desktop\Bai-codeagent-main\scripts\update-bounty-integrations.ps1"
```

如果你只想更新白盒规则，不想拉很大的 Nuclei 模板：

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\admin\Desktop\Bai-codeagent-main\scripts\update-bounty-integrations.ps1" -SkipNucleiTemplates
```

## 本地接口

启动 Bai 后访问：

```text
http://localhost:3000/api/bounty/integrations
```

这个接口会显示增强包是否已安装、规则数量和更新命令。

## 运行模板

Nuclei 已经适合你的电脑本地跑。先把 HackerOne/SRC 明确授权的目标放进一个文本文件，一行一个 URL，然后运行：

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\admin\Desktop\Bai-codeagent-main\scripts\run-nuclei-authorized.ps1" -TargetsFile "C:\path\to\in-scope-targets.txt"
```

结果会写到 `workspace/scans/nuclei/`，Bai 之后会自动把它带进报告和 Shannon 交接包。

Semgrep 需要先安装命令行工具：

```powershell
python -m pip install semgrep
```

然后对白盒仓库或 Bai 下载出来的镜像运行：

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Users\admin\Desktop\Bai-codeagent-main\scripts\run-semgrep-whitebox.ps1" -RepoPath "C:\path\to\repo"
```

结果会写到 `workspace/scans/semgrep/`，Bai 之后会自动把它带进报告和 Shannon 交接包。
