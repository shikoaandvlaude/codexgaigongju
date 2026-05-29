#!/usr/bin/env python3
"""
Traffic Capture — 一键浏览器抓包，替代手动看 F12

打开浏览器，你正常操作，所有API请求自动记录。
不需要配代理、不需要Burp、不需要看F12。

用法:
    python traffic_capture.py --url https://target.com
    python traffic_capture.py --url https://target.com --login https://target.com/login
    python traffic_capture.py --url https://target.com --analyze

依赖: pip install playwright && playwright install chromium
"""
import asyncio, json, os, sys, time, argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    HAS_PW = True
except ImportError:
    HAS_PW = False

STATIC = {".css",".js",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".ttf",".map"}

class TrafficCapture:
    def __init__(self, url, login_url=""):
        self.url = url
        self.login_url = login_url
        self.requests = []
        self.api_eps = []
        self.interesting = []
        self.ws_messages = []
        self.cookies = []

    async def run(self):
        if not HAS_PW:
            print("[!] pip install playwright && playwright install chromium")
            sys.exit(1)
        print(f"\n{'='*60}\n  Traffic Capture\n  目标: {self.url}\n{'='*60}")
        print("\n  浏览器即将打开。你正常操作网站，操作完按 Enter 停止。\n")
        async with async_playwright() as p:
            br = await p.chromium.launch(headless=False, args=["--disable-blink-features=AutomationControlled"])
            ctx = await br.new_context(viewport={"width":1920,"height":1080})
            page = await ctx.new_page()
            page.on("request", self._req)
            page.on("response", self._resp)
            page.on("websocket", self._ws)
            if self.login_url:
                await page.goto(self.login_url)
                input("  [登录完成后按 Enter...]")
            await page.goto(self.url)
            input("  [操作完成后按 Enter 停止抓包...]")
            self.cookies = await ctx.cookies()
            await br.close()
        return self._report()

    def _req(self, req):
        url, method = req.url, req.method
        if any(urlparse(url).path.lower().endswith(e) for e in STATIC): return
        entry = {"method":method,"url":url,"headers":dict(req.headers),"body":req.post_data[:2000] if req.post_data else "","ts":time.time()}
        self.requests.append(entry)
        if "/api/" in url.lower() or "/v1/" in url.lower() or "/v2/" in url.lower() or "/graphql" in url.lower() or method in ("POST","PUT","DELETE","PATCH"):
            self.api_eps.append(entry)

    async def _resp(self, resp):
        ct = resp.headers.get("content-type","")
        if "json" not in ct and "text" not in ct: return
        if any(urlparse(resp.url).path.lower().endswith(e) for e in STATIC): return
        try:
            body = await resp.text()
            keys = [k for k in ["system_prompt","definition","character_def","personality","instruction","secret","private","hidden","config","prompt"] if k in body.lower()]
            if keys or resp.status in (401,403,500):
                self.interesting.append({"url":resp.url,"status":resp.status,"keys":keys,"preview":body[:800],"length":len(body)})
        except: pass

    def _ws(self, ws):
        def on_msg(payload):
            text = payload if isinstance(payload,str) else ""
            if len(text) > 50:
                self.ws_messages.append({"url":ws.url,"data":text[:1000]})
        ws.on("framereceived", on_msg)

    def _report(self):
        return {"target":self.url,"time":datetime.now().isoformat(),
                "stats":{"requests":len(self.requests),"api":len(self.api_eps),"interesting":len(self.interesting),"ws":len(self.ws_messages),"cookies":len(self.cookies)},
                "api_endpoints":self.api_eps,"interesting":self.interesting,"ws_messages":self.ws_messages,
                "cookies":[{"name":c["name"],"value":c["value"],"domain":c.get("domain","")} for c in self.cookies]}

def main():
    ap = argparse.ArgumentParser(description="一键浏览器抓包")
    ap.add_argument("--url","-u",required=True)
    ap.add_argument("--login","-l",default="")
    ap.add_argument("--output","-o",default="")
    ap.add_argument("--analyze","-a",action="store_true")
    args = ap.parse_args()
    cap = TrafficCapture(args.url, args.login)
    report = asyncio.run(cap.run())
    # Print
    print(f"\n{'='*60}\n  抓包完成!\n{'='*60}")
    print(f"  请求: {report['stats']['requests']} | API: {report['stats']['api']} | 有趣: {report['stats']['interesting']} | WS: {report['stats']['ws']}")
    if report["api_endpoints"]:
        print(f"\n  API 端点:")
        seen=set()
        for ep in report["api_endpoints"]:
            k=f"{ep['method']} {urlparse(ep['url']).path}"
            if k in seen: continue
            seen.add(k)
            print(f"    {ep['method']:6s} {ep['url'][:70]}")
    if report["interesting"]:
        print(f"\n  ⚠ 有趣的响应:")
        for r in report["interesting"][:10]:
            print(f"    [{r['status']}] {r['url'][:60]}")
            if r["keys"]: print(f"         发现关键词: {', '.join(r['keys'])}")
            print(f"         {r['preview'][:100]}...")
    if report["ws_messages"]:
        print(f"\n  WebSocket 消息 ({len(report['ws_messages'])} 条):")
        for m in report["ws_messages"][:5]:
            print(f"    {m['url'][:50]}: {m['data'][:80]}...")
    # Save
    out = args.output or os.path.expanduser(f"~/.bai-agent/captures/capture_{urlparse(args.url).netloc}_{datetime.now().strftime('%H%M')}.json")
    Path(out).parent.mkdir(parents=True,exist_ok=True)
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False))
    print(f"\n  [+] 保存: {out}")
    if cap.cookies:
        cs="; ".join(f"{c['name']}={c['value']}" for c in cap.cookies)
        print(f"  [+] Cookie: {cs[:80]}...")
    if args.analyze:
        print(f"\n  自动分析:")
        for r in report["interesting"]:
            if "system_prompt" in str(r.get("keys",[])):
                print(f"    [!!!] SYSTEM PROMPT 泄露: {r['url']}")
            if "definition" in str(r.get("keys",[])):
                print(f"    [!!!] 角色定义泄露: {r['url']}")

if __name__=="__main__":
    main()
