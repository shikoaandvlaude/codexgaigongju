#!/usr/bin/env python3
"""
浏览器自动化工具 — Playwright 无头浏览器

用途：让 Claude Code 能自动操控浏览器完成需要 JavaScript 渲染的操作：
  - 自动登录网站（填表单、点按钮）
  - 处理前后端分离的 SPA 页面
  - 截图取证
  - 提取动态加载的内容（AJAX数据）
  - 拦截/修改网络请求（类似Fiddler但可编程）
  - Cookie/Token 提取

依赖安装：
  pip install playwright
  playwright install chromium

使用方式：
  # 访问页面并截图
  python3 browser_auto.py --url "https://target.com" --screenshot page.png

  # 自动登录
  python3 browser_auto.py --url "https://target.com/login" \
    --fill "#username=admin" --fill "#password=123456" \
    --click "button[type=submit]" \
    --wait 3 --screenshot after_login.png

  # 提取页面所有链接
  python3 browser_auto.py --url "https://target.com" --extract links

  # 提取所有表单
  python3 browser_auto.py --url "https://target.com" --extract forms

  # 提取 Cookie
  python3 browser_auto.py --url "https://target.com" --extract cookies

  # 提取 localStorage / sessionStorage
  python3 browser_auto.py --url "https://target.com" --extract storage

  # 拦截 API 请求（记录所有 XHR）
  python3 browser_auto.py --url "https://target.com" --intercept --output requests.json

  # 执行自定义 JavaScript
  python3 browser_auto.py --url "https://target.com" --eval "document.title"

  # 带认证访问（设置Cookie）
  python3 browser_auto.py --url "https://target.com/admin" \
    --cookie "session=abc123" --screenshot admin.png

  # 模拟手机浏览器
  python3 browser_auto.py --url "https://target.com" --mobile --screenshot mobile.png

  # 批量截图多个URL
  python3 browser_auto.py --url-file urls.txt --screenshot-dir ./screenshots/

注意事项：
  - 需要先安装 playwright 和浏览器: pip install playwright && playwright install chromium
  - 默认无头模式（不显示窗口），加 --headed 显示
  - 所有操作在授权范围内进行
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


def check_deps():
    if not HAS_PLAYWRIGHT:
        print("[!] playwright 未安装。请运行:")
        print("    pip install playwright")
        print("    playwright install chromium")
        sys.exit(1)


async def run_browser(args):
    """主浏览器自动化逻辑"""
    check_deps()

    async with async_playwright() as p:
        # 浏览器启动参数
        launch_opts = {
            "headless": not args.headed,
        }
        if args.proxy:
            launch_opts["proxy"] = {"server": args.proxy}

        browser = await p.chromium.launch(**launch_opts)

        # 上下文配置
        context_opts = {}
        if args.mobile:
            context_opts = p.devices["iPhone 13"]
        if args.user_agent:
            context_opts["user_agent"] = args.user_agent

        context = await browser.new_context(**context_opts)

        # 设置 Cookie
        if args.cookie:
            cookies = []
            for c in args.cookie:
                parts = c.split("=", 1)
                if len(parts) == 2:
                    domain = urlparse(args.url).hostname if args.url else "localhost"
                    cookies.append({
                        "name": parts[0],
                        "value": parts[1],
                        "domain": domain,
                        "path": "/"
                    })
            if cookies:
                await context.add_cookies(cookies)

        page = await context.new_page()

        # 网络请求拦截
        intercepted_requests = []
        if args.intercept:
            async def on_request(request):
                intercepted_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                    "resource_type": request.resource_type,
                    "timestamp": datetime.now().isoformat()
                })
            page.on("request", on_request)

        # 访问页面
        if args.url:
            print(f"[*] 访问: {args.url}")
            try:
                response = await page.goto(args.url, wait_until="domcontentloaded", timeout=30000)
                print(f"[+] 状态: {response.status if response else 'N/A'}")
            except Exception as e:
                print(f"[!] 访问失败: {e}")
                if not args.fill and not args.click_selector:
                    await browser.close()
                    return

        # 等待
        if args.wait_time:
            await asyncio.sleep(args.wait_time)

        # 填写表单
        if args.fill:
            for fill_cmd in args.fill:
                if "=" in fill_cmd:
                    selector, value = fill_cmd.split("=", 1)
                    try:
                        await page.fill(selector, value)
                        print(f"[+] 填写: {selector} = {value}")
                    except Exception as e:
                        print(f"[!] 填写失败 {selector}: {e}")

        # 点击
        if args.click_selector:
            for selector in args.click_selector:
                try:
                    await page.click(selector)
                    print(f"[+] 点击: {selector}")
                    await asyncio.sleep(1)
                except Exception as e:
                    print(f"[!] 点击失败 {selector}: {e}")

        # 等待导航完成
        if args.wait_time:
            await asyncio.sleep(args.wait_time)

        # 执行 JavaScript
        if args.js_eval:
            try:
                result = await page.evaluate(args.js_eval)
                print(f"[+] JS结果: {json.dumps(result, ensure_ascii=False, default=str)}")
            except Exception as e:
                print(f"[!] JS执行失败: {e}")

        # 提取信息
        if args.extract:
            await extract_info(page, args.extract)

        # 截图
        if args.screenshot_path:
            await page.screenshot(path=args.screenshot_path, full_page=args.full_page)
            size = os.path.getsize(args.screenshot_path)
            print(f"[+] 截图保存: {args.screenshot_path} ({size} bytes)")

        # 保存拦截的请求
        if args.intercept and intercepted_requests:
            output_file = args.output or "intercepted_requests.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(intercepted_requests, f, ensure_ascii=False, indent=2)
            print(f"[+] 拦截了 {len(intercepted_requests)} 个请求 → {output_file}")

            # 过滤出 API 请求
            api_requests = [r for r in intercepted_requests if r["resource_type"] in ("xhr", "fetch")]
            if api_requests:
                print(f"\n[*] API 请求 ({len(api_requests)} 个):")
                for req in api_requests[:20]:
                    print(f"    {req['method']} {req['url'][:100]}")

        # 获取页面HTML（用于后续分析）
        if args.save_html:
            html = await page.content()
            with open(args.save_html, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"[+] HTML已保存: {args.save_html}")

        await browser.close()


async def extract_info(page, extract_type):
    """从页面提取信息"""
    if extract_type == "links":
        links = await page.evaluate("""
            () => Array.from(document.querySelectorAll('a[href]'))
                .map(a => ({text: a.textContent.trim().slice(0, 50), href: a.href}))
                .filter(a => a.href && !a.href.startsWith('javascript:'))
        """)
        print(f"\n[*] 页面链接 ({len(links)} 个):")
        for link in links[:30]:
            print(f"    {link['href']}")
            if link['text']:
                print(f"      └─ {link['text']}")

    elif extract_type == "forms":
        forms = await page.evaluate("""
            () => Array.from(document.querySelectorAll('form')).map(form => ({
                action: form.action,
                method: form.method,
                inputs: Array.from(form.querySelectorAll('input,select,textarea')).map(inp => ({
                    type: inp.type || inp.tagName.toLowerCase(),
                    name: inp.name,
                    id: inp.id,
                    placeholder: inp.placeholder
                }))
            }))
        """)
        print(f"\n[*] 页面表单 ({len(forms)} 个):")
        for i, form in enumerate(forms):
            print(f"    Form #{i+1}: {form['method'].upper()} {form['action']}")
            for inp in form['inputs']:
                print(f"      - [{inp['type']}] name={inp['name']} id={inp['id']}")

    elif extract_type == "cookies":
        cookies = await page.context.cookies()
        print(f"\n[*] Cookies ({len(cookies)} 个):")
        for c in cookies:
            flags = []
            if c.get("httpOnly"):
                flags.append("HttpOnly")
            if c.get("secure"):
                flags.append("Secure")
            print(f"    {c['name']}={c['value'][:40]}{'...' if len(c['value'])>40 else ''} [{','.join(flags)}]")

    elif extract_type == "storage":
        local_storage = await page.evaluate("() => ({...localStorage})")
        session_storage = await page.evaluate("() => ({...sessionStorage})")
        print(f"\n[*] localStorage ({len(local_storage)} 项):")
        for k, v in list(local_storage.items())[:20]:
            print(f"    {k} = {str(v)[:60]}")
        print(f"\n[*] sessionStorage ({len(session_storage)} 项):")
        for k, v in list(session_storage.items())[:20]:
            print(f"    {k} = {str(v)[:60]}")

    elif extract_type == "scripts":
        scripts = await page.evaluate("""
            () => Array.from(document.querySelectorAll('script[src]'))
                .map(s => s.src)
        """)
        print(f"\n[*] 外部JS ({len(scripts)} 个):")
        for s in scripts:
            print(f"    {s}")

    elif extract_type == "meta":
        meta = await page.evaluate("""
            () => {
                const title = document.title;
                const metas = Array.from(document.querySelectorAll('meta'))
                    .map(m => ({name: m.name || m.getAttribute('property'), content: m.content}))
                    .filter(m => m.name && m.content);
                const generator = document.querySelector('meta[name=generator]');
                return {title, metas, generator: generator ? generator.content : null};
            }
        """)
        print(f"\n[*] 页面元信息:")
        print(f"    Title: {meta['title']}")
        if meta['generator']:
            print(f"    Generator: {meta['generator']}")
        for m in meta['metas'][:10]:
            print(f"    {m['name']}: {m['content'][:60]}")


async def batch_screenshot(url_file, output_dir, args):
    """批量截图"""
    check_deps()
    os.makedirs(output_dir, exist_ok=True)

    with open(url_file, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[*] 批量截图: {len(urls)} 个URL → {output_dir}/")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        for i, url in enumerate(urls):
            page = await context.new_page()
            filename = f"{i+1:03d}_{urlparse(url).hostname or 'unknown'}.png"
            filepath = os.path.join(output_dir, filename)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                await page.screenshot(path=filepath)
                print(f"  [+] {i+1}/{len(urls)} {url} → {filename}")
            except Exception as e:
                print(f"  [!] {i+1}/{len(urls)} {url} → 失败: {e}")
            finally:
                await page.close()

        await browser.close()

    print(f"[+] 完成，截图保存在: {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="浏览器自动化工具 — Playwright")

    # 目标
    parser.add_argument("--url", help="目标URL")
    parser.add_argument("--url-file", help="URL列表文件（批量截图用）")

    # 浏览器选项
    parser.add_argument("--headed", action="store_true", help="显示浏览器窗口（默认无头）")
    parser.add_argument("--mobile", action="store_true", help="模拟手机浏览器")
    parser.add_argument("--proxy", help="代理地址（如 http://127.0.0.1:8080）")
    parser.add_argument("--user-agent", help="自定义 User-Agent")

    # 认证
    parser.add_argument("--cookie", action="append", help="设置Cookie（格式: name=value，可重复）")

    # 操作
    parser.add_argument("--fill", action="append", help="填写表单（格式: selector=value，可重复）")
    parser.add_argument("--click", dest="click_selector", action="append", help="点击元素（CSS选择器，可重复）")
    parser.add_argument("--wait", dest="wait_time", type=float, help="等待秒数")
    parser.add_argument("--eval", dest="js_eval", help="执行JavaScript代码")

    # 提取
    parser.add_argument("--extract", choices=["links", "forms", "cookies", "storage", "scripts", "meta"],
                       help="提取页面信息")

    # 输出
    parser.add_argument("--screenshot", dest="screenshot_path", help="截图保存路径")
    parser.add_argument("--screenshot-dir", help="批量截图输出目录")
    parser.add_argument("--full-page", action="store_true", help="截取完整页面（包括滚动区域）")
    parser.add_argument("--save-html", help="保存页面HTML到文件")
    parser.add_argument("--intercept", action="store_true", help="拦截所有网络请求")
    parser.add_argument("--output", "-o", help="输出文件路径")

    args = parser.parse_args()

    if not args.url and not args.url_file:
        parser.print_help()
        print("\n安装说明:")
        print("  pip install playwright")
        print("  playwright install chromium")
        return

    # 批量截图模式
    if args.url_file and args.screenshot_dir:
        asyncio.run(batch_screenshot(args.url_file, args.screenshot_dir, args))
        return

    # 单页面模式
    asyncio.run(run_browser(args))


if __name__ == "__main__":
    main()
