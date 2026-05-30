---
description: CNVD 通用型漏洞批量挖掘。通过 FOFA 收集国产系统资产，批量验证已知 POC，达到 CNVD 提交门槛。Usage: /cnvd-hunt [system|--all|--edu]
---

# /cnvd-hunt

CNVD 通用型漏洞批量挖掘模式。专注国产 OA/ERP/BI/网络设备的已知漏洞批量验证。

## 快速开始

```bash
# 列出所有可扫描的系统
python3 auto_agent/cnvd_scanner.py --list

# 扫描指定系统（推荐入门）
python3 auto_agent/cnvd_scanner.py --system 泛微
python3 auto_agent/cnvd_scanner.py --system 用友
python3 auto_agent/cnvd_scanner.py --system 帆软

# 全量扫描所有高优先级系统
python3 auto_agent/cnvd_scanner.py --all

# 教育网目标（EDUSRC 用）
python3 auto_agent/cnvd_scanner.py --edu
```

## 前置条件

1. **FOFA API Key**（推荐）— 在 `config.yaml` 或环境变量中配置：
   ```bash
   export FOFA_KEY=your_fofa_key
   export FOFA_EMAIL=your_email
   ```

2. 或安装 `fofa` CLI 工具作为备用方案

## 支持的目标系统

### 第一梯队（CNVD 高收录率）

| 系统 | 厂商 | 常见漏洞 | FOFA 语法 |
|------|------|---------|-----------|
| 泛微 e-cology | 泛微 | SQL注入、文件上传 | `app="泛微-协同办公OA"` |
| 用友 NC Cloud | 用友 | RCE、反序列化、SQL注入 | `app="用友-NC-Cloud"` |
| 致远 OA | 致远互联 | 文件上传、RCE | `app="致远互联-OA"` |
| 通达 OA | 通达信科 | 任意用户登录、文件上传 | `app="通达OA"` |

### 第二梯队

| 系统 | 厂商 | 常见漏洞 | FOFA 语法 |
|------|------|---------|-----------|
| 帆软 FineReport | 帆软 | SQL注入→RCE、目录遍历 | `app="帆软-FineReport"` |
| 蓝凌 EKP | 蓝凌 | SSRF、反序列化 | `app="蓝凌-EKP"` |

### 第三梯队

| 系统 | 厂商 | 常见漏洞 | FOFA 语法 |
|------|------|---------|-----------|
| 宏景 eHR | 宏景科技 | SQL注入 | `body="eHR" && body="宏景"` |
| 万户 OA | 万户网络 | SQL注入 | `app="万户网络-ezOFFICE"` |
| 锐捷网络设备 | 锐捷 | 命令执行 | `app="Ruijie-RG"` |
| 宝塔面板 | 宝塔 | 未授权访问 | `app="宝塔-Linux面板"` |

## 工作流程

```
FOFA 资产收集 → 指纹确认 → POC 批量验证 → 影响统计 → 报告生成
```

1. **FOFA 收集**：通过 API 或 CLI 获取目标 URL 列表
2. **指纹确认**：访问首页匹配指纹关键字，排除误报
3. **POC 验证**：对确认目标执行已知漏洞 POC
4. **影响统计**：统计脆弱实例数量
5. **报告生成**：达到 ≥3 个实例自动生成 CNVD 通用型报告

## CNVD 通用型提交要求

- 漏洞必须是**产品代码缺陷**（不是配置失误）
- 需要影响 **≥3 个不同单位**的实例
- 提交时附带：Word 报告 + POC 脚本 + 复现录屏
- 不能是已有 CVE/CNVD 编号的已知漏洞

## 与原有 pipeline 的关系

这是一个**可选的补充阶段**，不影响原有挖掘流程：

```
原有 pipeline:  Recon → Params → Hunt → DeepHunt → Validate → Report
CNVD 补充:      ────────────────────── CNVDHunt (可选) ──────────────
```

在 `config.yaml` 中启用：
```yaml
cnvd_scanner:
  enabled: true
```

## 配置参考

```yaml
cnvd_scanner:
  enabled: true
  fofa_key: ""              # FOFA API Key（或环境变量 FOFA_KEY）
  fofa_email: ""            # FOFA 邮箱（或环境变量 FOFA_EMAIL）
  timeout: 10               # HTTP 请求超时（秒）
  concurrent: 5             # 并发数
  max_targets_per_system: 50  # 每个系统最多扫描目标数
  delay_between_requests: 2   # 请求间隔（秒）
  priority: "high"          # 默认扫描优先级
  auto_report: true         # 达到门槛自动生成报告
```

## 注意事项

- ⚠️ 确保有合法授权再进行扫描
- ⚠️ 控制扫描速率，避免对目标造成影响
- ⚠️ CNVD 通用型需要新漏洞，不能是已公开的老洞
- ⚠️ 提交前确认漏洞仍可复现
