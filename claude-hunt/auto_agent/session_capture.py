#!/usr/bin/env python3
"""
Session Capture — 快速抓取登录态 Cookie

解决最大痛点：用户不知道怎么拿 cookie 填到 config.yaml 里。
本脚本打开一个真实浏览器窗口，让你手动登录目标网站，
登录完成后自动导出 cookie 并写入 config.yaml。

用法:
    # 抓取单账号（存为 session_monitor.cookie）
    python session_capture.py --url https://target.com/login

    # 抓取攻击者账号（存为 idor.cookie_a）
    python session_capture.py --url https://target.com/login --role attacker

    # 抓取受害者账号（存为 idor.cookie_b）
    python session_capture.py --url https://target.com/login --role victim

    # 同时抓两个账号（引导你分别登录）
    python session_capture.py --url https://target.com/login --dual

    # 从 Chrome DevTools 导入（如果你已经手动登录了）
    python session_capture.py --from-chrome --domain target.com

依赖: pip install playwright && playwright install chromium
"""

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def cookie_list_to_string(cookies: list) -> str:
    """将 cookie 列表转为 header 字符串格式"""
    return "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))


def save_cookies_to_config(cookies_str: str, role: str, config_path: str):
    """将 cookie 写入 config.yaml"""
    if not HAS_YAML:
        print(f"[!] 未安装 pyyaml，请手动把以下 cookie 填入 config.yaml:")
        print(f"    {role}: \"{cookies_str}\"")
        return

    if not os.path.exists(config_path):
        print(f"[!] config.yaml 不存在: {config_path}")
        print(f"    请手动填入: {role} = \"{cookies_str}\"")
        return

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # 根据 role 写入不同位置
    if role == "main":
        config.setdefault("session_monitor", {})["cookie"] = cookies_str
    elif role == "attacker":
        config.setdefault("idor", {})["cookie_a"] = cookies_str
    elif role == "victim":
        config.setdefault("idor", {})["cookie_b"] = cookies_str

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

    print(f"[+] Cookie 已写入 config.yaml ({role})")


async def capture_session(url: str, role: str = "main", config_path: str = "config.yaml"):
    """打开浏览器让用户登录，然后抓取 cookie"""
    if not HAS_PLAYWRIGHT:
        print("[!] 需要安装 playwright:")
        print("    pip install playwright && playwright install chromium")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Session Capture — {role.upper()} 账号")
    print(f"{'='*60}")
    print(f"\n  即将打开浏览器窗口，请你：")
    print(f"  1. 在浏览器中手动登录 {url}")
    print(f"  2. 登录成功后，回到这里按 Enter 键")
    print(f"  3. 脚本会自动抓取 Cookie 并保存\n")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,  # 必须可见，用户要手动操作
            args=["--disable-blink-features=AutomationControlled"]
        )
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )
        page = await context.new_page()
        await page.goto(url)

        input("\n  [按 Enter 键继续] 登录完成后按 Enter...")

        # 抓取所有 cookie
        cookies = await context.cookies()
        await browser.close()

    if not cookies:
        print("[!] 未获取到任何 Cookie，可能登录失败或目标不设 Cookie")
        return ""

    # 转为字符串
    cookies_str = cookie_list_to_string(cookies)

    print(f"\n[+] 获取到 {len(cookies)} 个 Cookie:")
    for c in cookies[:10]:
        print(f"    {c['name']}={c['value'][:20]}...")

    # 保存到 config
    save_cookies_to_config(cookies_str, role, config_path)

    # 也保存原始 JSON（可用于 Playwright 恢复）
    json_path = os.path.join(
        os.path.dirname(config_path),
        f"cookies_{role}.json"
    )
    Path(json_path).write_text(json.dumps(cookies, indent=2, ensure_ascii=False))
    print(f"[+] 原始 Cookie JSON 已保存: {json_path}")

    return cookies_str


async def capture_dual(url: str, config_path: str = "config.yaml"):
    """连续抓取两个账号的 cookie"""
    print("\n" + "="*60)
    print("  双账号 Session Capture")
    print("  先登录【攻击者】账号，再登录【受害者】账号")
    print("="*60)

    print("\n\n--- 第 1 步：登录【攻击者】账号 ---")
    await capture_session(url, role="attacker", config_path=config_path)

    print("\n\n--- 第 2 步：登录【受害者】账号 ---")
    await capture_session(url, role="victim", config_path=config_path)

    # 也把攻击者的设为主 session
    if HAS_YAML and os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        cookie_a = config.get("idor", {}).get("cookie_a", "")
        if cookie_a:
            config.setdefault("session_monitor", {})["cookie"] = cookie_a
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False)

    print("\n\n[+] 双账号抓取完成！")
    print("    攻击者 cookie → idor.cookie_a")
    print("    受害者 cookie → idor.cookie_b")
    print("    主 session → session_monitor.cookie")
    print("\n    现在可以运行: python auto_hunt.py --target 目标域名")


def import_from_string(cookie_str: str, role: str, config_path: str):
    """从粘贴的 cookie 字符串导入"""
    save_cookies_to_config(cookie_str, role, config_path)


def main():
    parser = argparse.ArgumentParser(
        description="Session Capture — 快速抓取登录态 Cookie"
    )
    parser.add_argument("--url", "-u", help="目标登录页面 URL")
    parser.add_argument(
        "--role", "-r",
        choices=["main", "attacker", "victim"],
        default="main",
        help="账号角色: main(主测试)/attacker(攻击者)/victim(受害者)"
    )
    parser.add_argument("--dual", action="store_true", help="双账号模式（连续抓两个）")
    parser.add_argument("--config", default="config.yaml", help="config.yaml 路径")
    parser.add_argument(
        "--from-string", "-s",
        help="直接从字符串导入 cookie (格式: 'name1=val1; name2=val2')"
    )

    args = parser.parse_args()

    if args.from_string:
        import_from_string(args.from_string, args.role, args.config)
        return

    if not args.url:
        print("[!] 必须指定 --url 参数（目标登录页面）")
        print("    示例: python session_capture.py --url https://target.com/login")
        print("    双账号: python session_capture.py --url https://target.com/login --dual")
        sys.exit(1)

    if args.dual:
        asyncio.run(capture_dual(args.url, args.config))
    else:
        asyncio.run(capture_session(args.url, args.role, args.config))


if __name__ == "__main__":
    main()
