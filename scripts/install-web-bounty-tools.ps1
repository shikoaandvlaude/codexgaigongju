param(
  [string] $ToolRoot = "",
  [switch] $Install,
  [switch] $IncludeGoTools,
  [switch] $IncludeUrlTools,
  [switch] $IncludePythonTools,
  [switch] $AddUserPath,
  [switch] $Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$common = Join-Path $root "scripts\SecurityScanCommon.psm1"
Import-Module $common -Force

function Get-DefaultToolRoot {
  param([string] $Value)
  if ($Value) { return $Value }
  if ($env:BAI_TOOL_ROOT) { return $env:BAI_TOOL_ROOT }
  return Join-Path $env:USERPROFILE "Desktop\codex\tools"
}

function Get-BinaryName {
  param([string] $Name)
  if ($IsWindows -or $env:OS -eq "Windows_NT") { return "$Name.exe" }
  return $Name
}

function Get-ToolCommand {
  param(
    [string] $Name,
    [string] $BinDir
  )
  $binary = Get-BinaryName -Name $Name
  $local = Join-Path $BinDir $binary
  if (Test-Path -LiteralPath $local) { return $local }
  $commands = @(Get-Command $Name -All -ErrorAction SilentlyContinue)
  if ($Name -eq "httpx") {
    $commands = @($commands | Where-Object { $_.Source -notmatch '\\venv\\Scripts\\httpx\.exe$|\\Python\d*\\Scripts\\httpx\.exe$' })
  }
  $cmd = @($commands | Where-Object { $_.Source -match '\\go\\bin\\|\\codex\\tools\\bin\\' } | Select-Object -First 1)
  if (-not $cmd) {
    $cmd = @($commands | Select-Object -First 1)
  }
  if ($cmd) { return $cmd.Source }
  return ""
}

function Get-LatestGithubAsset {
  param(
    [string] $Repo,
    [string] $Pattern
  )
  $api = "https://api.github.com/repos/$Repo/releases/latest"
  try {
    $release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "BaiCodeAgent tool installer" }
  } catch {
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) { throw }
    $raw = & gh api "repos/$Repo/releases/latest"
    $release = $raw | ConvertFrom-Json
  }
  $asset = @($release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1)
  if (-not $asset) {
    throw "No matching release asset for $Repo using pattern $Pattern"
  }
  return [pscustomobject]@{
    repo = $Repo
    tag = $release.tag_name
    name = $asset.name
    url = $asset.browser_download_url
  }
}

function Install-ArchiveTool {
  param(
    [string] $Name,
    [string] $BinaryName = "",
    [string] $Repo,
    [string] $Pattern,
    [string] $BinDir,
    [string] $CacheDir,
    [switch] $ForceInstall
  )

  $commandName = if ($BinaryName) { $BinaryName } else { $Name }
  $existing = Get-ToolCommand -Name $commandName -BinDir $BinDir
  if ($existing -and -not $ForceInstall) {
    return [pscustomobject]@{ name = $commandName; status = "present"; path = $existing; detail = "already available" }
  }

  $asset = Get-LatestGithubAsset -Repo $Repo -Pattern $Pattern
  $download = Join-Path $CacheDir $asset.name
  $extractDir = Join-Path $CacheDir "$Name-$($asset.tag)"
  if (Test-Path -LiteralPath $extractDir) {
    Remove-Item -LiteralPath $extractDir -Recurse -Force
  }
  New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

  Write-Host "Downloading $Name $($asset.tag)..." -ForegroundColor Cyan
  Invoke-WebRequest -Uri $asset.url -OutFile $download -Headers @{ "User-Agent" = "BaiCodeAgent tool installer" }

  if ($asset.name.ToLowerInvariant().EndsWith(".zip")) {
    Expand-Archive -LiteralPath $download -DestinationPath $extractDir -Force
  } else {
    tar -xf $download -C $extractDir
  }

  $binary = Get-BinaryName -Name $commandName
  $found = Get-ChildItem -Path $extractDir -Recurse -File -Filter $binary | Select-Object -First 1
  if (-not $found) {
    throw "Downloaded $Name but could not find $binary in $extractDir"
  }
  $target = Join-Path $BinDir $binary
  Copy-Item -LiteralPath $found.FullName -Destination $target -Force
  return [pscustomobject]@{ name = $commandName; status = "installed"; path = $target; detail = "$Repo $($asset.tag)" }
}

function Install-GoTool {
  param(
    [string] $CommandName,
    [string] $Package,
    [string] $BinDir
  )
  $existing = Get-ToolCommand -Name $CommandName -BinDir $BinDir
  if ($existing -and -not $Force) {
    return [pscustomobject]@{ name = $CommandName; status = "present"; path = $existing; detail = "already available" }
  }
  $go = Get-Command go -ErrorAction SilentlyContinue
  if (-not $go) {
    return [pscustomobject]@{ name = $CommandName; status = "missing"; path = ""; detail = "go not found" }
  }
  Write-Host "Installing Go package $Package..." -ForegroundColor Cyan
  $previousGoBin = $env:GOBIN
  try {
    $env:GOBIN = $BinDir
    & go install $Package
    if ($LASTEXITCODE -ne 0) {
      throw "go install failed with exit code $LASTEXITCODE"
    }
  } finally {
    $env:GOBIN = $previousGoBin
  }
  $resolved = Get-ToolCommand -Name $CommandName -BinDir $BinDir
  return [pscustomobject]@{ name = $CommandName; status = $(if ($resolved) { "installed" } else { "unknown" }); path = $resolved; detail = "go package $Package" }
}

function Install-PythonTool {
  param(
    [string] $Package,
    [string] $CommandName,
    [string] $BinDir
  )
  $existing = Get-ToolCommand -Name $CommandName -BinDir $BinDir
  if ($existing -and -not $Force) {
    return [pscustomobject]@{ name = $CommandName; status = "present"; path = $existing; detail = "already available" }
  }
  $python = Get-PythonWithPip
  if (-not $python) {
    return [pscustomobject]@{ name = $CommandName; status = "missing"; path = ""; detail = "python with pip not found" }
  }
  Write-Host "Installing Python package $Package..." -ForegroundColor Cyan
  $oldUtf8 = $env:PYTHONUTF8
  $oldIoEncoding = $env:PYTHONIOENCODING
  try {
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    & $python.exe @($python.prefix + @("-m", "pip", "install", "--user", $Package))
    if ($LASTEXITCODE -ne 0) {
      throw "pip install failed with exit code $LASTEXITCODE using $($python.exe) $($python.prefix -join ' ')"
    }
  } finally {
    $env:PYTHONUTF8 = $oldUtf8
    $env:PYTHONIOENCODING = $oldIoEncoding
  }
  $resolved = Get-ToolCommand -Name $CommandName -BinDir $BinDir
  return [pscustomobject]@{ name = $CommandName; status = $(if ($resolved) { "installed" } else { "unknown" }); path = $resolved; detail = "pip package $Package" }
}

function Get-PythonWithPip {
  $candidates = @()
  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    $candidates += [pscustomobject]@{ exe = $py.Source; prefix = @("-3") }
  }
  $pythonCommands = @(Get-Command python -All -ErrorAction SilentlyContinue)
  foreach ($cmd in $pythonCommands) {
    $candidates += [pscustomobject]@{ exe = $cmd.Source; prefix = @() }
  }
  $python3 = Get-Command python3 -ErrorAction SilentlyContinue
  if ($python3) {
    $candidates += [pscustomobject]@{ exe = $python3.Source; prefix = @() }
  }

  $seen = @{}
  foreach ($candidate in $candidates) {
    $key = "$($candidate.exe)|$($candidate.prefix -join ' ')"
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    & $candidate.exe @($candidate.prefix + @("-m", "pip", "--version")) *> $null
    if ($LASTEXITCODE -eq 0) {
      return $candidate
    }
  }
  return $null
}

$toolRootPath = Get-DefaultToolRoot -Value $ToolRoot
$binDir = Join-Path $toolRootPath "bin"
$cacheDir = Join-Path $toolRootPath "cache"
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

$tools = @(
  @{ name = "nuclei"; repo = "projectdiscovery/nuclei"; pattern = "windows_amd64\.zip$" },
  @{ name = "subfinder"; repo = "projectdiscovery/subfinder"; pattern = "windows_amd64\.zip$" },
  @{ name = "httpx"; repo = "projectdiscovery/httpx"; pattern = "windows_amd64\.zip$" },
  @{ name = "dnsx"; repo = "projectdiscovery/dnsx"; pattern = "windows_amd64\.zip$" },
  @{ name = "katana"; repo = "projectdiscovery/katana"; pattern = "windows_amd64\.zip$" },
  @{ name = "interactsh-client"; repo = "projectdiscovery/interactsh"; pattern = "interactsh-client_.*windows_amd64\.zip$" },
  @{ name = "gau"; repo = "lc/gau"; pattern = "windows_amd64\.zip$" },
  @{ name = "naabu"; repo = "projectdiscovery/naabu"; pattern = "windows_amd64\.zip$" },
  @{ name = "ffuf"; repo = "ffuf/ffuf"; pattern = "windows_amd64\.zip$" },
  @{ name = "gitleaks"; repo = "gitleaks/gitleaks"; pattern = "windows_x64\.zip$|windows_amd64\.zip$" },
  @{ name = "trufflehog"; repo = "trufflesecurity/trufflehog"; pattern = "windows_amd64\.tar\.gz$|windows_amd64\.zip$" },
  @{ name = "cloudfox"; repo = "BishopFox/cloudfox"; pattern = "cloudfox-windows-amd64\.zip$" },
  @{ name = "trivy"; repo = "aquasecurity/trivy"; pattern = "windows-64bit\.zip$" },
  @{ name = "grype"; repo = "anchore/grype"; pattern = "windows_amd64\.zip$" },
  @{ name = "kingfisher"; repo = "mongodb/kingfisher"; pattern = "kingfisher-windows-x64\.zip$" },
  @{ name = "feroxbuster"; repo = "epi052/feroxbuster"; pattern = "x86_64-windows-feroxbuster\.exe\.zip$" },
  @{ name = "dalfox"; repo = "hahwul/dalfox"; pattern = "windows-x86_64\.zip$" }
)

$goTools = @(
  @{ name = "kiterunner"; package = "github.com/assetnote/kiterunner/cmd/kiterunner@latest" },
  @{ name = "waybackurls"; package = "github.com/tomnomnom/waybackurls@latest" }
)

$pythonUrlTools = @(
  @{ package = "arjun"; command = "arjun" },
  @{ package = "uro"; command = "uro" },
  @{ package = "git+https://github.com/xnl-h4ck3r/xnLinkFinder.git"; command = "xnLinkFinder" },
  @{ package = "git+https://github.com/xnl-h4ck3r/waymore.git"; command = "waymore" }
)

$pythonHeavyTools = @(
  @{ package = "semgrep"; command = "semgrep" },
  @{ package = "checkov"; command = "checkov" },
  @{ package = "prowler"; command = "prowler" },
  @{ package = "ScoutSuite"; command = "scout" }
)

$results = @()
foreach ($tool in $tools) {
  $path = Get-ToolCommand -Name $tool.name -BinDir $binDir
  if ($path -and -not ($Install -and $Force)) {
    $results += [pscustomobject]@{ name = $tool.name; status = "present"; path = $path; detail = "available" }
    continue
  }
  if (-not $Install) {
    $results += [pscustomobject]@{ name = $tool.name; status = "missing"; path = ""; detail = "run with -Install to download" }
    continue
  }
  try {
    $binaryName = if ($tool.binaryName) { $tool.binaryName } else { "" }
    $results += Install-ArchiveTool -Name $tool.name -BinaryName $binaryName -Repo $tool.repo -Pattern $tool.pattern -BinDir $binDir -CacheDir $cacheDir -ForceInstall:$Force
  } catch {
    $results += [pscustomobject]@{ name = $tool.name; status = "failed"; path = ""; detail = $_.Exception.Message }
  }
}

foreach ($tool in $goTools) {
  $path = Get-ToolCommand -Name $tool.name -BinDir $binDir
  if ($path -and -not ($Install -and $Force)) {
    $results += [pscustomobject]@{ name = $tool.name; status = "present"; path = $path; detail = "available" }
    continue
  }
  if (-not ($Install -and $IncludeGoTools)) {
    $results += [pscustomobject]@{ name = $tool.name; status = "optional"; path = $path; detail = "run with -Install -IncludeGoTools" }
    continue
  }
  try {
    $results += Install-GoTool -CommandName $tool.name -Package $tool.package -BinDir $binDir
  } catch {
    $results += [pscustomobject]@{ name = $tool.name; status = "failed"; path = ""; detail = $_.Exception.Message }
  }
}

$pythonTools = @($pythonUrlTools + $pythonHeavyTools)

if ($IncludePythonTools -or $IncludeUrlTools) {
  $selectedPythonTools = if ($IncludePythonTools) { $pythonTools } else { $pythonUrlTools }
  foreach ($tool in $selectedPythonTools) {
    try {
      $results += Install-PythonTool -Package $tool.package -CommandName $tool.command -BinDir $binDir
    } catch {
      $results += [pscustomobject]@{ name = $tool.command; status = "failed"; path = ""; detail = $_.Exception.Message }
    }
  }
  if (-not $IncludePythonTools) {
    foreach ($tool in $pythonHeavyTools) {
      $path = Get-ToolCommand -Name $tool.command -BinDir $binDir
      $results += [pscustomobject]@{
        name = $tool.command
        status = $(if ($path) { "present" } else { "optional" })
        path = $path
        detail = $(if ($path) { "available" } else { "run with -Install -IncludePythonTools" })
      }
    }
  }
} else {
  foreach ($tool in $pythonTools) {
    $path = Get-ToolCommand -Name $tool.command -BinDir $binDir
    $isUrlTool = @($pythonUrlTools | Where-Object { $_.command -eq $tool.command }).Count -gt 0
    $results += [pscustomobject]@{
      name = $tool.command
      status = $(if ($path) { "present" } else { "optional" })
      path = $path
      detail = $(if ($path) { "available" } elseif ($isUrlTool) { "run with -Install -IncludeUrlTools" } else { "run with -Install -IncludePythonTools" })
    }
  }
}

if ($AddUserPath) {
  $current = [Environment]::GetEnvironmentVariable("Path", "User")
  $paths = @($current -split ";" | Where-Object { $_ })
  if ($paths -notcontains $binDir) {
    [Environment]::SetEnvironmentVariable("Path", ($paths + $binDir -join ";"), "User")
    Write-Host "Added $binDir to the user PATH. Open a new terminal to use it globally." -ForegroundColor Yellow
  }
}

$manifest = Join-Path $toolRootPath "tools-manifest.json"
[pscustomobject]@{
  createdAt = (Get-Date).ToString("o")
  toolRoot = $toolRootPath
  binDir = $binDir
  results = $results
} | ConvertTo-Json -Depth 8 | Set-Content -Path $manifest -Encoding UTF8

$results | Sort-Object name | Format-Table -AutoSize
Write-Host "Tool manifest: $manifest" -ForegroundColor Green
