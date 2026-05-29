#!/usr/bin/env python3
"""
Bai Auto-Hunt Agent — AI 自动化 SRC 漏洞挖掘
支持全自动/半自动模式，带日志记录+红线审查+痕迹分析

用法:
    python auto_hunt.py
    python auto_hunt.py --target example.com --mode auto
    python auto_hunt.py --target example.com --mode semi
"""

import sys
import os
import argparse
from datetime import datetime

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_engine import AgentEngine
from hunt_logger import HuntLogger
from redline_checker import RedlineChecker
from trace_analyzer import TraceAnalyzer
from waf_adapter import WAFAdapter
from session_monitor import SessionMonitor
from asset_discovery import AssetDiscovery
from intel_checker import IntelChecker
from checkpoint_manager import CheckpointManager
from scope_updater import ScopeUpdater
from false_positive_filter import FalsePositiveFilter
from phases.recon import ReconPhase
from phases.params import ParamPhase
from phases.hunt import HuntPhase
from phases.deep_hunt import DeepHuntPhase
from phases.validate import ValidatePhase
from phases.verify import VerifyPhase
from phases.report import ReportPhase

# APP/IoT 目标适配
from app_recon import detect_target_type, AppRecon

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    console = Console()
except ImportError:
    # fallback 如果没装 rich
    class Console:
        def print(self, *args, **kwargs): print(*args)
    console = Console()
    class Prompt:
        @staticmethod
        def ask(msg, default=""): return input(f"{msg} [{default}]: ") or default
    class Confirm:
        @staticmethod
        def ask(msg, default=True): return input(f"{msg} (y/n): ").lower() != 'n'


def load_config():
    """加载配置文件，支持环境变量覆盖"""
    import yaml
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    
    if not os.path.exists(config_path):
        example_path = config_path + ".example"
        # 如果有环境变量配置了 API Key，可以用 example 作为基础配置
        if os.environ.get('DEEPSEEK_API_KEY') or os.environ.get('OPENAI_API_KEY'):
            config_path = example_path
            console.print(f"[yellow]使用 config.yaml.example 作为基础配置（API Key 从环境变量读取）[/yellow]")
        else:
            console.print(f"[red]错误: 未找到 config.yaml[/red]")
            console.print(f"请复制 config.yaml.example 为 config.yaml 并填入 API Key:")
            console.print(f"  cp {example_path} {config_path}")
            console.print(f"或设置环境变量: export DEEPSEEK_API_KEY=sk-xxx")
            sys.exit(1)
    
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    
    # 环境变量覆盖配置
    if os.environ.get('DEEPSEEK_API_KEY'):
        config.setdefault('llm', {})['api_key'] = os.environ['DEEPSEEK_API_KEY']
    elif os.environ.get('OPENAI_API_KEY'):
        config.setdefault('llm', {})['api_key'] = os.environ['OPENAI_API_KEY']
    
    if os.environ.get('LLM_BASE_URL'):
        config.setdefault('llm', {})['base_url'] = os.environ['LLM_BASE_URL']
    if os.environ.get('LLM_MODEL'):
        config.setdefault('llm', {})['model'] = os.environ['LLM_MODEL']
    
    return config


def show_banner():
    """显示启动横幅"""
    banner = """
╔══════════════════════════════════════════════╗
║       Bai Auto-Hunt Agent v1.0               ║
║       AI 驱动的 SRC 自动化挖掘               ║
╠══════════════════════════════════════════════╣
║  全自动: AI 全权决策，发现高危时暂停          ║
║  半自动: 每个关键步骤等你确认再继续           ║
╠══════════════════════════════════════════════╣
║  日志: 桌面 doing_日期.md                     ║
║  红线: 自动审查是否越界                       ║
║  痕迹: AI 分析可挖线索                        ║
╚══════════════════════════════════════════════╝
"""
    console.print(banner, style="cyan")


def select_mode():
    """选择运行模式"""
    console.print("\n[bold]选择运行模式:[/bold]\n")
    console.print("  [green]1.[/green] 全自动模式 (YOLO) — AI 全权决策，发现高危时暂停确认")
    console.print("  [yellow]2.[/yellow] 半自动模式 (SAFE) — 每个关键步骤等你确认")
    console.print("  [red]3.[/red] 退出\n")
    
    choice = Prompt.ask("选择", default="2")
    
    if choice == "1":
        return "auto"
    elif choice == "2":
        return "semi"
    else:
        console.print("[red]退出[/red]")
        sys.exit(0)


def select_target(config):
    """选择/输入目标"""
    target = Prompt.ask("\n[bold]输入目标域名[/bold]", default=config.get('target', {}).get('domain', ''))
    
    if not target:
        console.print("[red]错误: 必须输入目标域名[/red]")
        sys.exit(1)
    
    # 确认 scope
    console.print(f"\n[yellow]目标: {target}[/yellow]")
    console.print("[yellow]请确认你有 SRC 授权测试该目标！[/yellow]")
    
    if not Confirm.ask("确认有授权？", default=False):
        console.print("[red]没有授权不能测试。退出。[/red]")
        sys.exit(1)
    
    return target


def run_agent(target, mode, config):
    """主运行逻辑"""
    
    # 初始化各模块
    logger = HuntLogger(config)
    engine = AgentEngine(config)
    redline = RedlineChecker(config)
    tracer = TraceAnalyzer(engine)
    waf = WAFAdapter(engine, logger)
    session_mon = SessionMonitor(engine, logger, config)
    asset_disc = AssetDiscovery(engine, logger)
    intel = IntelChecker(engine, logger)
    checkpoint_mgr = CheckpointManager(config)
    
    # Scope 检查
    scope_updater = ScopeUpdater(config)
    scope_updater.warn_if_stale()
    
    # 检查目标是否在授权范围内
    merged_scope, merged_out_of_scope = scope_updater.get_merged_scope()
    if merged_scope and not scope_updater.is_target_in_scope(target, merged_scope, merged_out_of_scope):
        console.print(f"[bold red]警告: {target} 不在配置的授权范围内![/bold red]")
        if mode == "semi":
            if not Confirm.ask("目标不在 scope 内，确认继续？", default=False):
                console.print("[red]退出[/red]")
                sys.exit(1)
        elif mode == "auto":
            console.print("[red]自动模式: 目标不在 scope 内，终止运行[/red]")
            sys.exit(1)
    
    # 写日志头
    logger.write_header(target, mode)
    
    console.print(f"\n[bold green]开始挖掘: {target} (模式: {mode})[/bold green]\n")
    
    # ═══ Phase 0: WAF 检测 + 资产发现 ═══
    console.print(f"\n{'='*50}")
    console.print("[bold cyan]Phase 0: 前置侦察[/bold cyan]")
    console.print(f"{'='*50}\n")
    
    # WAF 检测 → 动态调整限速
    waf_result = waf.detect(target)
    console.print(f"  WAF: {waf_result['strategy']['name']} → {waf_result['strategy']['requests_per_second']} req/s")
    console.print(f"  提示: {waf_result['tips']}")
    
    # 更新 engine 的限速
    engine.config.setdefault('rate_limit', {})['requests_per_second'] = waf.get_rate_limit()
    
    # 资产关联发现（可选）
    company_name = config.get('target', {}).get('company_name', '')
    if mode == "semi":
        if Confirm.ask("执行资产关联发现？(推荐)", default=True):
            asset_result = asset_disc.discover(target, company_name)
            if asset_result["domains"]:
                console.print(f"  [green]发现 {len(asset_result['domains'])} 个关联域名[/green]")
    elif mode == "auto":
        asset_result = asset_disc.discover(target, company_name)
    
    # ═══ APP/IoT 目标检测 ═══
    target_type = detect_target_type(target)
    if target_type == "app":
        console.print(f"\n[bold yellow]⚡ 检测到 APP 类目标: {target}[/bold yellow]")
        console.print("[yellow]  自动切换到 APP Recon 模式（APK分析+包名推导域名）[/yellow]")
        
        # APP 专用 Recon
        app_recon = AppRecon({
            "package_name": target,
            "apk_path": config.get('app', {}).get('apk_path', ''),
            "har_path": config.get('app', {}).get('har_path', ''),
        })
        
        import asyncio as _asyncio
        try:
            loop = _asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    app_result = pool.submit(_asyncio.run, app_recon.run()).result()
            else:
                app_result = loop.run_until_complete(app_recon.run())
        except RuntimeError:
            app_result = _asyncio.run(app_recon.run())
        
        # 将 APP Recon 结果注入到 findings 中
        if app_result.api_domains:
            console.print(f"  [green]发现 {len(app_result.api_domains)} 个 API 域名[/green]")
            for d in app_result.api_domains[:10]:
                console.print(f"    • {d}")
            findings["subdomains"].extend(app_result.api_domains)
        
        if app_result.api_endpoints:
            console.print(f"  [green]发现 {len(app_result.api_endpoints)} 个 API 端点[/green]")
            for ep in app_result.api_endpoints[:5]:
                ep_str = ep if isinstance(ep, str) else ep.get("url", str(ep))
                console.print(f"    • {ep_str[:80]}")
            findings["urls"].extend(
                [e if isinstance(e, str) else e.get("url", "") for e in app_result.api_endpoints]
            )
        
        if app_result.hardcoded_secrets:
            console.print(f"  [red]发现 {len(app_result.hardcoded_secrets)} 个硬编码密钥![/red]")
            findings["secrets"].extend(
                [s.get("value", "") for s in app_result.hardcoded_secrets]
            )
        
        if app_result.mqtt_brokers:
            console.print(f"  [cyan]发现 MQTT Broker: {app_result.mqtt_brokers}[/cyan]")
        
        if app_result.cloud_services:
            console.print(f"  [cyan]云服务: {', '.join(app_result.cloud_services)}[/cyan]")
        
        # 更新 target 为发现的主 API 域名（后续阶段用）
        if app_result.api_domains:
            primary_domain = app_result.api_domains[0]
            console.print(f"\n  [bold]主 API 域名: {primary_domain}[/bold]")
            # 不替换原 target，但把域名加到 alive_hosts 供后续使用
            findings["alive_hosts"].append(f"https://{primary_domain}")
        
        logger.log_event("APP_RECON", f"APP目标识别完成: {len(app_result.api_domains)} 域名, "
                        f"{len(app_result.api_endpoints)} 端点, "
                        f"{len(app_result.hardcoded_secrets)} 密钥")
    
    # ═══ 主流程阶段 ═══
    phases = [
        ReconPhase(engine, logger, redline, tracer, mode),
        ParamPhase(engine, logger, redline, tracer, mode),
        HuntPhase(engine, logger, redline, tracer, mode),
        DeepHuntPhase(engine, logger, redline, tracer, mode),
        ValidatePhase(engine, logger, redline, tracer, mode),
        VerifyPhase(engine, logger, redline, tracer, mode),
        ReportPhase(engine, logger, redline, tracer, mode),
    ]
    
    # 全局发现汇总
    findings = {
        "subdomains": [],
        "alive_hosts": [],
        "urls": [],
        "params": [],
        "vulnerabilities": [],
        "secrets": [],
    }
    
    step_count = 0
    start_phase_index = 0
    last_checkpoint_path = ""
    
    # ═══ 断点恢复检查 ═══
    checkpoint_data = checkpoint_mgr.load_latest_checkpoint(target)
    if checkpoint_data:
        if mode == "auto" and checkpoint_mgr.auto_resume:
            # 全自动模式：直接恢复
            console.print(f"\n[bold yellow]发现上次未完成的检查点，自动恢复进度...[/bold yellow]")
            findings = checkpoint_data.get("findings", findings)
            step_count = checkpoint_data.get("step_count", 0)
            start_phase_index = checkpoint_data.get("current_phase_index", 0) + 1
            last_checkpoint_path = checkpoint_data.get("_checkpoint_path", "")
            console.print(f"  恢复到阶段 {start_phase_index}，已完成步数 {step_count}")
            # 注意: Phase 0 (WAF检测) 总是重新执行（条件可能已变化）
            # 资产发现结果已保存在 checkpoint 的 findings 中（由 ReconPhase 合并）
        elif mode == "semi":
            # 半自动模式：询问用户
            console.print(f"\n[bold yellow]发现上次未完成的检查点[/bold yellow]")
            if Confirm.ask("是否恢复上次进度？", default=True):
                findings = checkpoint_data.get("findings", findings)
                step_count = checkpoint_data.get("step_count", 0)
                start_phase_index = checkpoint_data.get("current_phase_index", 0) + 1
                last_checkpoint_path = checkpoint_data.get("_checkpoint_path", "")
                console.print(f"  恢复到阶段 {start_phase_index}，已完成步数 {step_count}")
                # 注意: Phase 0 (WAF检测) 总是重新执行（条件可能已变化）
                # 资产发现结果已保存在 checkpoint 的 findings 中（由 ReconPhase 合并）
    
    try:
        for phase_idx, phase in enumerate(phases):
            # 跳过已完成的阶段（断点恢复时）
            if phase_idx < start_phase_index:
                continue
            
            phase_name = phase.__class__.__name__
            
            console.print(f"\n{'='*50}")
            console.print(f"[bold cyan]阶段: {phase_name}[/bold cyan]")
            console.print(f"{'='*50}\n")
            
            logger.log_phase_start(phase_name)
            
            # 半自动模式：阶段开始前确认
            if mode == "semi":
                if not Confirm.ask(f"开始 {phase_name} 阶段？", default=True):
                    logger.log_event("SKIP", f"用户跳过 {phase_name}")
                    continue
            
            # 执行阶段
            phase_findings = phase.execute(target, findings)
            
            # 合并发现
            for key, value in phase_findings.items():
                if key in findings and isinstance(findings[key], list):
                    findings[key].extend(value)
            
            step_count += 1
            
            # 保存检查点
            last_checkpoint_path = checkpoint_mgr.save_checkpoint(
                target, mode, phase_idx, findings, step_count, waf_result
            )
            
            # Session 状态监控（每阶段后检查）
            if session_mon.should_check(step_count):
                sess_result = session_mon.check(step_count)
                logger.log_redline_check({"stop": not sess_result["alive"], "warnings": [sess_result["reason"]]})
                if not sess_result["alive"]:
                    console.print(f"\n[bold red]⚠️ Session异常: {sess_result['reason']}[/bold red]")
                    logger.log_event("REDLINE_STOP", sess_result["reason"])
                    break
                elif sess_result["action"] == "slow_down":
                    # 动态降速
                    engine.config['rate_limit']['requests_per_second'] = max(1, waf.get_rate_limit() - 1)
                    console.print(f"  [yellow]⚠ 降速到 {engine.config['rate_limit']['requests_per_second']} req/s[/yellow]")
            
            # 红线审查（每个阶段结束后）
            redline_result = redline.check(findings, step_count)
            if redline_result["stop"]:
                console.print(f"\n[bold red]⚠️ 红线触发: {redline_result['reason']}[/bold red]")
                logger.log_event("REDLINE_STOP", redline_result['reason'])
                break
            
            # 痕迹分析
            if step_count % config.get('agent', {}).get('trace_analysis_interval', 5) == 0:
                trace_result = tracer.analyze(target, findings)
                logger.log_trace_analysis(trace_result)
                console.print(f"\n[magenta]📍 痕迹分析: {trace_result['summary']}[/magenta]")
            
            logger.log_phase_end(phase_name, phase_findings)
    
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断 (Ctrl+C)[/yellow]")
        logger.log_event("USER_INTERRUPT", "Ctrl+C")
    except Exception as e:
        console.print(f"\n[red]异常: {e}[/red]")
        logger.log_event("ERROR", str(e))
    
    # 标记检查点为已完成
    if last_checkpoint_path:
        checkpoint_mgr.mark_completed(last_checkpoint_path)
    
    # ═══ 误报过滤 ═══
    if findings.get('vulnerabilities'):
        fp_filter = FalsePositiveFilter(engine, logger, config)
        original_count = len(findings['vulnerabilities'])
        findings['vulnerabilities'] = fp_filter.apply_filter(findings['vulnerabilities'], mode)
        filtered_count = original_count - len(findings['vulnerabilities'])
        if filtered_count > 0:
            console.print(f"\n[yellow]误报过滤: 移除了 {filtered_count} 个可疑误报[/yellow]")
    
    # ═══ 提交前情报查重 ═══
    vulns = [v for v in findings.get('vulnerabilities', []) if v.get('verified_4proof')]
    if vulns:
        console.print(f"\n{'='*50}")
        console.print("[bold cyan]提交前查重[/bold cyan]")
        console.print(f"{'='*50}\n")
        checked_vulns = intel.pre_submission_check(target, vulns)
        findings['vulnerabilities'] = checked_vulns
    
    # 写日志尾
    logger.write_footer(findings)
    
    # 最终汇总
    console.print(f"\n{'='*50}")
    console.print("[bold green]运行结束[/bold green]")
    console.print(f"  发现子域名: {len(findings['subdomains'])}")
    console.print(f"  存活主机: {len(findings['alive_hosts'])}")
    console.print(f"  URL: {len(findings['urls'])}")
    console.print(f"  参数: {len(findings['params'])}")
    console.print(f"  漏洞: {len(findings['vulnerabilities'])}")
    console.print(f"  密钥泄露: {len(findings['secrets'])}")
    console.print(f"\n  日志: {logger.log_path}")
    console.print(f"{'='*50}")


def main():
    parser = argparse.ArgumentParser(description="Bai Auto-Hunt Agent")
    parser.add_argument("--target", "-t", help="目标域名")
    parser.add_argument("--mode", "-m", choices=["auto", "semi"], help="运行模式")
    parser.add_argument("--scope-update", help="从文件更新 scope (每行一个域名)")
    args = parser.parse_args()
    
    show_banner()
    config = load_config()
    
    # 处理 scope 更新请求
    if args.scope_update:
        updater = ScopeUpdater(config)
        updater.update_from_file(args.scope_update)
        console.print("[green]Scope 更新完成[/green]")
        sys.exit(0)
    
    # 模式选择
    mode = args.mode or select_mode()
    
    # 目标选择
    target = args.target or select_target(config)
    
    # 更新配置中的目标
    config.setdefault('target', {})['domain'] = target
    
    # 开跑
    run_agent(target, mode, config)


if __name__ == "__main__":
    main()
