#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Bai-codeagent 渗透工具一键安装脚本 (Windows)
.DESCRIPTION
    自动安装 Go、nmap，并通过 go install / pip 批量拉取所有黑盒渗透工具。
    覆盖完整攻击链：信息搜集 → 参数发现 → 漏洞检测 → OOB验证 → 密钥泄露 → 通知推送
    
    运行方式: 右键 PowerShell → 以管理员身份运行 → .\install_tools_windows.ps1
.NOTES
    Author: Bai
    Date:   2025-06-14
    Updated: 2025-06-18 — 加入全部缺失黑盒工具
#>

$ErrorActionPreference = "Stop"

# ============================================================
# 颜色输出辅助
# ============================================================
function Write-Step  { param($msg) Write-Host "`n[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Bai-codeagent 渗透工具安装器 (Windows)" -ForegroundColor White
Write-Host "  覆盖: 信息搜集/参数发现/漏洞检测/OOB/密钥泄露" -ForegroundColor DarkGray
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. 检查 / 安装 Go
# ============================================================
Write-Step "Step 1: 检查 Go 运行时..."

$goVersion = "1.24.4"
$goInstaller = "go${goVersion}.windows-amd64.msi"
$goUrl = "https://go.dev/dl/$goInstaller"

if (Get-Command go -ErrorAction SilentlyContinue) {
    $currentGo = (go version) -replace 'go version go', '' -replace ' windows/amd64', ''
    Write-Ok "Go 已安装: $currentGo"
} else {
    Write-Warn "Go 未安装，正在下载 $goInstaller ..."
    $dlPath = "$env:TEMP\$goInstaller"
    Invoke-WebRequest -Uri $goUrl -OutFile $dlPath -UseBasicParsing
    Write-Step "正在安装 Go (静默模式)..."
    Start-Process msiexec.exe -ArgumentList "/i `"$dlPath`" /quiet /norestart" -Wait
    # 刷新 PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Ok "Go 安装成功: $(go version)"
    } else {
        Write-Err "Go 安装可能失败，请手动检查 https://go.dev/dl/"
        exit 1
    }
}

# 确保 GOPATH/bin 在 PATH 中
$goBin = "$env:USERPROFILE\go\bin"
if (-not (Test-Path $goBin)) { New-Item -ItemType Directory -Path $goBin -Force | Out-Null }
if ($env:Path -notlike "*$goBin*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$env:Path;$goBin", "User")
    $env:Path += ";$goBin"
    Write-Ok "已将 $goBin 加入用户 PATH"
}

# 配置 Go 代理（国内加速）
$currentProxy = & go env GOPROXY 2>$null
if ($currentProxy -notlike "*goproxy.cn*") {
    & go env -w GOPROXY="https://goproxy.cn,direct"
    Write-Ok "已配置 Go 代理: goproxy.cn (国内加速)"
}

# ============================================================
# 2. 检查 / 安装 Ollama（本地 LLM 运行时 — brain.py 核心依赖）
# ============================================================
Write-Step "Step 2: 检查 Ollama (本地LLM引擎)..."

if (Get-Command ollama -ErrorAction SilentlyContinue) {
    Write-Ok "Ollama 已安装: $((ollama --version 2>&1) -replace 'ollama version ','')"
} else {
    Write-Warn "Ollama 未安装，正在下载..."
    $ollamaUrl = "https://ollama.com/download/OllamaSetup.exe"
    $dlPath = "$env:TEMP\OllamaSetup.exe"
    try {
        Invoke-WebRequest -Uri $ollamaUrl -OutFile $dlPath -UseBasicParsing
        Write-Step "正在安装 Ollama..."
        Start-Process $dlPath -ArgumentList "/S" -Wait
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        if (Get-Command ollama -ErrorAction SilentlyContinue) {
            Write-Ok "Ollama 安装成功"
            Write-Warn "提示: 安装后运行 'ollama pull deepseek-r1:8b' 下载模型"
        } else {
            Write-Warn "Ollama 可能需要重启终端。手动安装: https://ollama.com/download"
        }
    } catch {
        Write-Warn "Ollama 下载失败，请手动安装: https://ollama.com/download"
    }
}

# ============================================================
# 3. 检查 / 安装 jq（JSON处理工具）
# ============================================================
Write-Step "Step 3: 检查 jq..."

if (Get-Command jq -ErrorAction SilentlyContinue) {
    Write-Ok "jq 已安装"
} else {
    Write-Warn "jq 未安装，正在下载..."
    $jqUrl = "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-windows-amd64.exe"
    $jqDir = "$env:LOCALAPPDATA\jq"
    $jqPath = "$jqDir\jq.exe"
    try {
        if (-not (Test-Path $jqDir)) { New-Item -ItemType Directory -Path $jqDir -Force | Out-Null }
        Invoke-WebRequest -Uri $jqUrl -OutFile $jqPath -UseBasicParsing
        if ($env:Path -notlike "*$jqDir*") {
            [System.Environment]::SetEnvironmentVariable("Path", "$env:Path;$jqDir", "User")
            $env:Path += ";$jqDir"
        }
        Write-Ok "jq 安装成功: $jqPath"
    } catch {
        Write-Warn "jq 下载失败。手动下载: https://github.com/jqlang/jq/releases"
    }
}

# ============================================================
# 4. 检查 / 安装 Nmap
# ============================================================
Write-Step "Step 4: 检查 nmap..."

$nmapVersion = "7.95"
$nmapInstaller = "nmap-${nmapVersion}-setup.exe"
$nmapUrl = "https://nmap.org/dist/$nmapInstaller"

if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Ok "nmap 已安装: $((nmap --version | Select-Object -First 1))"
} else {
    Write-Warn "nmap 未安装，正在下载 $nmapInstaller ..."
    $dlPath = "$env:TEMP\$nmapInstaller"
    Invoke-WebRequest -Uri $nmapUrl -OutFile $dlPath -UseBasicParsing
    Write-Step "正在安装 nmap (静默模式)..."
    Start-Process $dlPath -ArgumentList "/S" -Wait
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        Write-Ok "nmap 安装成功"
    } else {
        $nmapDir = "C:\Program Files (x86)\Nmap"
        if (Test-Path $nmapDir) {
            [System.Environment]::SetEnvironmentVariable("Path", "$env:Path;$nmapDir", "Machine")
            $env:Path += ";$nmapDir"
            Write-Ok "nmap 已安装，已手动加入 PATH"
        } else {
            Write-Warn "nmap 可能需要手动安装: https://nmap.org/download.html"
        }
    }
}

# ============================================================
# 3. 批量 go install 渗透工具（按优先级分组）
# ============================================================
Write-Step "Step 5: 批量安装 Go 渗透工具..."

$tools = @(
    # ═══════════════════════════════════════════════════════════
    # P0 — 必装（没有这些工具链不完整）
    # ═══════════════════════════════════════════════════════════
    
    # ── 子域名枚举 ──
    @{ Name = "subfinder";          Pkg = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest";          Desc = "被动子域名枚举"; Priority = "P0" }
    @{ Name = "amass";              Pkg = "github.com/owasp-amass/amass/v4/...@master";                             Desc = "深度资产发现"; Priority = "P0" }
    
    # ── DNS解析 ──
    @{ Name = "dnsx";               Pkg = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest";                       Desc = "DNS批量解析(subfinder后接)"; Priority = "P0" }
    
    # ── HTTP探活 ──
    @{ Name = "httpx";              Pkg = "github.com/projectdiscovery/httpx/cmd/httpx@latest";                     Desc = "HTTP探活+指纹+技术栈"; Priority = "P0" }
    
    # ── 端口扫描 ──
    @{ Name = "naabu";              Pkg = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest";                  Desc = "快速端口扫描"; Priority = "P0" }
    
    # ── URL收集 ──
    @{ Name = "katana";             Pkg = "github.com/projectdiscovery/katana/cmd/katana@latest";                   Desc = "爬虫(JS渲染友好)"; Priority = "P0" }
    @{ Name = "gau";                Pkg = "github.com/lc/gau/v2/cmd/gau@latest";                                   Desc = "Wayback/URLscan历史URL"; Priority = "P0" }
    @{ Name = "waybackurls";        Pkg = "github.com/tomnomnom/waybackurls@latest";                                Desc = "Wayback Machine补充"; Priority = "P0" }
    @{ Name = "gospider";           Pkg = "github.com/jaeles-project/gospider@latest";                              Desc = "另一爬虫引擎"; Priority = "P0" }
    
    # ── 目录爆破 ──
    @{ Name = "ffuf";               Pkg = "github.com/ffuf/ffuf/v2@latest";                                         Desc = "目录/参数Fuzz"; Priority = "P0" }
    
    # ── 漏洞扫描 ──
    @{ Name = "nuclei";             Pkg = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest";                Desc = "模板化漏洞检测"; Priority = "P0" }
    
    # ── XSS ──
    @{ Name = "dalfox";             Pkg = "github.com/hahwul/dalfox/v2@latest";                                     Desc = "XSS自动化验证"; Priority = "P0" }
    
    # ── OOB回调（验证SSRF/XXE/RCE的唯一方式）──
    @{ Name = "interactsh-client";  Pkg = "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest";    Desc = "OOB回调服务器(验证SSRF必备)"; Priority = "P0" }
    
    # ═══════════════════════════════════════════════════════════
    # P1 — 强烈推荐（显著提升效率）
    # ═══════════════════════════════════════════════════════════
    
    # ── 资产搜索引擎整合 ──
    @{ Name = "uncover";            Pkg = "github.com/projectdiscovery/uncover/cmd/uncover@latest";                 Desc = "Shodan/Censys/FOFA整合查询"; Priority = "P1" }
    
    # ── 密钥泄露扫描 ──
    @{ Name = "trufflehog";         Pkg = "github.com/trufflesecurity/trufflehog/v3@latest";                        Desc = "Git/云密钥泄露扫描+验证"; Priority = "P1" }
    @{ Name = "gitleaks";           Pkg = "github.com/gitleaks/gitleaks/v8@latest";                                 Desc = "Git泄露扫描(规则库互补)"; Priority = "P1" }
    
    # ── 子域名接管 ──
    @{ Name = "subjack";            Pkg = "github.com/haccer/subjack@latest";                                        Desc = "子域名接管检测"; Priority = "P1" }
    @{ Name = "subzy";              Pkg = "github.com/PentestPad/subzy@latest";                                      Desc = "子域名接管检测(更新更活跃)"; Priority = "P1" }
    
    # ── 子域名变异 ──
    @{ Name = "alterx";             Pkg = "github.com/projectdiscovery/alterx/cmd/alterx@latest";                   Desc = "子域名变异生成(dev→staging/test)"; Priority = "P1" }
    
    # ── 通知推送 ──
    @{ Name = "notify";             Pkg = "github.com/projectdiscovery/notify/cmd/notify@latest";                   Desc = "发现高危→推送手机/钉钉/微信"; Priority = "P1" }
    
    # ── CRLF注入 ──
    @{ Name = "crlfuzz";            Pkg = "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest";                      Desc = "CRLF注入检测"; Priority = "P1" }
    
    # ═══════════════════════════════════════════════════════════
    # P2 — 推荐（特定场景很有用）
    # ═══════════════════════════════════════════════════════════
    
    # ── 管道工具 ──
    @{ Name = "anew";               Pkg = "github.com/tomnomnom/anew@latest";                                        Desc = "管道去重追加"; Priority = "P2" }
    @{ Name = "qsreplace";          Pkg = "github.com/tomnomnom/qsreplace@latest";                                  Desc = "URL参数替换(批量注入测试)"; Priority = "P2" }
    @{ Name = "gf";                 Pkg = "github.com/tomnomnom/gf@latest";                                          Desc = "URL模式匹配(提取XSS/SQLi参数)"; Priority = "P2" }
    @{ Name = "uro";                Pkg = "github.com/s0md3v/uro@latest";                                            Desc = "URL去重(智能去相似URL)"; Priority = "P2" }
    
    # ── 隐藏API发现 ──
    @{ Name = "kiterunner";         Pkg = "github.com/assetnote/kiterunner/cmd/kr@latest";                           Desc = "隐藏API端点发现"; Priority = "P2" }
    
    # ── 爬虫补充 ──
    @{ Name = "hakrawler";          Pkg = "github.com/hakluke/hakrawler@latest";                                     Desc = "快速爬虫(补充katana)"; Priority = "P2" }
    
    # ── 截图 ──
    @{ Name = "gowitness";          Pkg = "github.com/sensepost/gowitness@latest";                                   Desc = "批量网页截图"; Priority = "P2" }
    
    # ═══════════════════════════════════════════════════════════
    # P3 — 可选（锦上添花）
    # ═══════════════════════════════════════════════════════════
    
    # ── PD工具管理器 ──
    @{ Name = "pdtm";               Pkg = "github.com/projectdiscovery/pdtm/cmd/pdtm@latest";                       Desc = "PD工具一键更新管理器"; Priority = "P3" }
)

$installed = 0
$failed = @()

foreach ($tool in $tools) {
    $name = $tool.Name
    $pkg  = $tool.Pkg
    $desc = $tool.Desc
    $pri  = $tool.Priority

    # 检查是否已安装
    if (Get-Command $name -ErrorAction SilentlyContinue) {
        Write-Host "  [$pri] $($name.PadRight(20))" -NoNewline
        Write-Host "已安装 ✓" -ForegroundColor Green
        $installed++
        continue
    }

    Write-Host "  [$pri] 安装 $name ($desc) ... " -NoNewline

    try {
        $output = & go install $pkg 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "OK" -ForegroundColor Green
            $installed++
        } else {
            Write-Host "FAIL" -ForegroundColor Red
            $failed += "$name : $output"
        }
    } catch {
        Write-Host "ERROR" -ForegroundColor Red
        $failed += "$name : $_"
    }
}

# ============================================================
# 4. 安装 Python 工具 (pip)
# ============================================================
Write-Step "Step 6: 安装 Python 渗透工具 (pip)..."

$pipTools = @(
    # P0 — 参数发现
    @{ Name = "paramspider";    Pkg = "paramspider";        Desc = "被动参数发现(从WebArchive挖带参URL)"; Priority = "P0" }
    @{ Name = "arjun";          Pkg = "arjun";              Desc = "主动参数发现(探测隐藏参数)"; Priority = "P0" }
    
    # P0 — AI/LLM 核心依赖（brain.py 需要）
    @{ Name = "ollama";         Pkg = "ollama";             Desc = "Ollama Python SDK(brain.py核心)"; Priority = "P0" }
    @{ Name = "rich";           Pkg = "rich";               Desc = "终端美化输出"; Priority = "P0" }
    @{ Name = "langgraph";      Pkg = "langgraph";          Desc = "LLM Agent图引擎"; Priority = "P0" }
    @{ Name = "langchain-ollama"; Pkg = "langchain-ollama"; Desc = "LangChain Ollama集成"; Priority = "P0" }
    
    # P1 — 漏洞检测
    @{ Name = "wafw00f";        Pkg = "wafw00f";            Desc = "WAF识别"; Priority = "P1" }
    @{ Name = "corscanner";     Pkg = "corscanner";         Desc = "CORS错配检测(批量出中危)"; Priority = "P1" }
    @{ Name = "openredirex";    Pkg = "openredirex";        Desc = "开放重定向检测(OAuth链高危)"; Priority = "P1" }
    
    # P2 — 辅助
    @{ Name = "dirsearch";      Pkg = "dirsearch";          Desc = "目录扫描(SRC慎用批量)"; Priority = "P2" }
    @{ Name = "linkfinder";     Pkg = "linkfinder";         Desc = "JS端点提取"; Priority = "P2" }
    @{ Name = "graphqlmap";     Pkg = "graphqlmap";         Desc = "GraphQL测试"; Priority = "P2" }
    @{ Name = "pyjwt";          Pkg = "pyjwt";              Desc = "JWT解析库"; Priority = "P2" }
    @{ Name = "Pillow";         Pkg = "Pillow";             Desc = "图像处理(截图/OCR)"; Priority = "P2" }
    @{ Name = "selenium";       Pkg = "selenium";           Desc = "浏览器自动化(Playwright备选)"; Priority = "P2" }
    @{ Name = "beautifulsoup4"; Pkg = "beautifulsoup4";     Desc = "HTML解析"; Priority = "P2" }
    
    # P3 — 浏览器自动化
    @{ Name = "playwright";     Pkg = "playwright";         Desc = "无头浏览器自动化"; Priority = "P3" }
)

foreach ($tool in $pipTools) {
    $name = $tool.Name
    $pri  = $tool.Priority
    
    Write-Host "  [$pri] pip install $name ($($tool.Desc)) ... " -NoNewline
    try {
        $output = & pip install $tool.Pkg --quiet 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "SKIP" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "SKIP" -ForegroundColor Yellow
    }
}

# 安装 Playwright 浏览器
Write-Host "  [P3] 安装 Playwright Chromium ... " -NoNewline
try {
    & playwright install chromium 2>&1 | Out-Null
    Write-Host "OK" -ForegroundColor Green
} catch {
    Write-Host "SKIP" -ForegroundColor Yellow
}

# ============================================================
# 5. 更新 nuclei 模板
# ============================================================
Write-Step "Step 5: 更新 nuclei 模板库..."
if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    & nuclei -update-templates 2>&1 | Out-Null
    Write-Ok "nuclei 模板已更新"
} else {
    Write-Warn "nuclei 未安装成功，跳过模板更新"
}

# ============================================================
# 6. 配置 notify（推送通知）
# ============================================================
Write-Step "Step 6: 配置 notify 推送..."

$notifyConfigDir = "$env:USERPROFILE\.config\notify"
$notifyConfigFile = "$notifyConfigDir\provider-config.yaml"

if (-not (Test-Path $notifyConfigFile)) {
    New-Item -ItemType Directory -Path $notifyConfigDir -Force | Out-Null
    @"
# notify 推送配置
# 文档: https://github.com/projectdiscovery/notify

# 钉钉机器人（推荐国内用户）
# dingtalk:
#   - id: "ding-bot"
#     dingtalk_webhook: "https://oapi.dingtalk.com/robot/send?access_token=你的token"
#     dingtalk_secret: "你的secret"

# 企业微信
# wechat:
#   - id: "wechat-bot"
#     wechat_webhook: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=你的key"

# Telegram
# telegram:
#   - id: "tg-bot"
#     telegram_api_key: "你的bot_token"
#     telegram_chat_id: "你的chat_id"

# Discord
# discord:
#   - id: "discord-hook"
#     discord_webhook_url: "https://discord.com/api/webhooks/xxx/yyy"
"@ | Out-File -FilePath $notifyConfigFile -Encoding utf8
    Write-Ok "notify 配置模板已生成: $notifyConfigFile"
    Write-Warn "请编辑配置文件填入你的推送 Token"
} else {
    Write-Ok "notify 配置已存在"
}

# ============================================================
# 7. 配置 uncover（搜索引擎API Key）
# ============================================================
Write-Step "Step 7: 配置 uncover 搜索引擎..."

$uncoverConfigDir = "$env:USERPROFILE\.config\uncover"
$uncoverConfigFile = "$uncoverConfigDir\provider-config.yaml"

if (-not (Test-Path $uncoverConfigFile)) {
    New-Item -ItemType Directory -Path $uncoverConfigDir -Force | Out-Null
    @"
# uncover 搜索引擎 API Key 配置
# 支持: Shodan, Censys, FOFA, ZoomEye, Hunter, Quake

# shodan:
#   - YOUR_SHODAN_API_KEY

# censys:
#   - YOUR_CENSYS_API_ID:YOUR_CENSYS_API_SECRET

# fofa:
#   - YOUR_FOFA_EMAIL:YOUR_FOFA_KEY

# zoomeye:
#   - YOUR_ZOOMEYE_API_KEY

# hunter:
#   - YOUR_HUNTER_API_KEY

# quake:
#   - YOUR_QUAKE_API_KEY
"@ | Out-File -FilePath $uncoverConfigFile -Encoding utf8
    Write-Ok "uncover 配置模板已生成: $uncoverConfigFile"
    Write-Warn "请编辑配置文件填入你的 FOFA/Shodan API Key"
} else {
    Write-Ok "uncover 配置已存在"
}

# ============================================================
# 8. 验证安装结果
# ============================================================
Write-Step "Step 8: 验证安装结果..."
Write-Host ""

# 分组验证
$groups = @(
    @{
        Name = "信息搜集"
        Tools = @("subfinder", "amass", "dnsx", "httpx", "naabu", "nmap", "uncover", "alterx")
    }
    @{
        Name = "URL/爬虫"
        Tools = @("katana", "gau", "waybackurls", "gospider", "hakrawler", "gowitness")
    }
    @{
        Name = "参数发现"
        Tools = @("paramspider", "arjun", "ffuf", "kiterunner", "gf", "qsreplace")
    }
    @{
        Name = "漏洞检测"
        Tools = @("nuclei", "dalfox", "crlfuzz", "subjack", "subzy", "corscanner", "openredirex")
    }
    @{
        Name = "OOB/验证"
        Tools = @("interactsh-client")
    }
    @{
        Name = "密钥泄露"
        Tools = @("trufflehog", "gitleaks")
    }
    @{
        Name = "辅助/管道"
        Tools = @("anew", "uro", "notify", "pdtm", "wafw00f", "jq")
    }
    @{
        Name = "AI/LLM"
        Tools = @("ollama")
    }
    }
)

$totalOk = 0
$totalMissing = 0

foreach ($group in $groups) {
    Write-Host "  [$($group.Name)]" -ForegroundColor White
    foreach ($t in $group.Tools) {
        $exists = Get-Command $t -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Host "    $($t.PadRight(20))" -NoNewline
            Write-Host "OK" -ForegroundColor Green
            $totalOk++
        } else {
            Write-Host "    $($t.PadRight(20))" -NoNewline
            Write-Host "MISSING" -ForegroundColor Red
            $totalMissing++
        }
    }
    Write-Host ""
}

$totalTools = $totalOk + $totalMissing
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Ok "安装完成! $totalOk / $totalTools 工具就绪"

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Warn "以下 Go 工具安装失败:"
    foreach ($f in $failed) { Write-Host "    $f" -ForegroundColor Red }
    Write-Host ""
    Write-Warn "可能原因: 网络问题。建议:"
    Write-Host "    1. 确认 Go 代理: go env GOPROXY" -ForegroundColor Yellow
    Write-Host "    2. 手动重试: go install <package>@latest" -ForegroundColor Yellow
    Write-Host "    3. 如果有梯子: set HTTPS_PROXY=http://127.0.0.1:7890" -ForegroundColor Yellow
}

# ============================================================
# 9. 打印限速提醒
# ============================================================
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "  SRC 测试安全限速提醒" -ForegroundColor Yellow
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""
Write-Host "  对SRC授权目标测试时，务必加限速参数：" -ForegroundColor White
Write-Host ""
Write-Host "  nuclei   → -rate-limit 5 -c 3" -ForegroundColor Gray
Write-Host "  ffuf     → -t 3 -rate 5" -ForegroundColor Gray
Write-Host "  httpx    → -threads 5 -rate-limit 10" -ForegroundColor Gray
Write-Host "  dalfox   → --worker 2 --delay 300" -ForegroundColor Gray
Write-Host "  katana   → -d 2 -delay 1 -c 3" -ForegroundColor Gray
Write-Host "  naabu    → -rate 100 -c 10" -ForegroundColor Gray
Write-Host ""
Write-Host "  有WAF: 每秒1-2请求 | 无WAF: 每秒5-10请求" -ForegroundColor Yellow
Write-Host "  SQL注入: 不用sqlmap，让AI手工构造payload" -ForegroundColor Yellow
Write-Host ""
Write-Host "  重启终端让 PATH 生效后即可使用所有工具。" -ForegroundColor Cyan
Write-Host ""
