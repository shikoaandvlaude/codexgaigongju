#!/usr/bin/env python3
"""
Race Condition / 并发竞态测试工具

用途：对同一个请求短时间内并发发送多次，检测是否存在竞态条件漏洞。
适用场景：领券、签到、提现、点赞、积分兑换等有次数/余额限制的操作。

使用方式：
  # 基本用法：并发20次相同请求
  python3 race_tester.py --url "https://target.com/api/withdraw" \
    --method POST \
    --headers '{"Cookie": "session=xxx", "Content-Type": "application/json"}' \
    --body '{"amount": 1}' \
    --threads 20

  # 不同金额并发（绕过相同金额检测）
  python3 race_tester.py --url "https://target.com/api/withdraw" \
    --method POST \
    --headers '{"Cookie": "session=xxx"}' \
    --body-template '{"amount": {FUZZ}}' \
    --fuzz-values "1,2,3,5,10" \
    --threads 5

  # 从 Fiddler 导出的请求文件
  python3 race_tester.py --request-file request.txt --threads 30

注意事项（红线）：
  - 只在授权SRC范围内使用
  - 并发次数控制在 10-50 次
  - 测试成功后立即停止
  - 不要导致服务不可用
"""

import argparse
import json
import sys
import time
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class RaceTester:
    """并发竞态条件测试器"""

    def __init__(self, url, method="POST", headers=None, body=None, timeout=10):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.body = body
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()

    def send_single(self, request_id, body_override=None):
        """发送单个请求并记录结果"""
        start_time = time.time()
        actual_body = body_override or self.body

        try:
            data = actual_body.encode("utf-8") if actual_body else None
            req = urllib.request.Request(
                self.url,
                data=data,
                headers=self.headers,
                method=self.method
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                elapsed = int((time.time() - start_time) * 1000)
                response_body = resp.read().decode("utf-8", errors="replace")
                result = {
                    "id": request_id,
                    "status": resp.status,
                    "time_ms": elapsed,
                    "body_preview": response_body[:500],
                    "success": True,
                    "timestamp": datetime.now().isoformat()
                }

        except urllib.error.HTTPError as e:
            elapsed = int((time.time() - start_time) * 1000)
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                pass
            result = {
                "id": request_id,
                "status": e.code,
                "time_ms": elapsed,
                "body_preview": body_text,
                "success": False,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            result = {
                "id": request_id,
                "status": 0,
                "time_ms": elapsed,
                "body_preview": str(e),
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

        with self.lock:
            self.results.append(result)

        return result

    def run_concurrent(self, threads=20, fuzz_values=None):
        """并发执行请求"""
        self.results = []

        print(f"\n{'='*60}")
        print(f"  Race Condition Tester")
        print(f"  Target: {self.url}")
        print(f"  Method: {self.method}")
        print(f"  Threads: {threads}")
        print(f"  Time: {datetime.now().isoformat()}")
        print(f"{'='*60}\n")

        # 预热连接（可选）
        print("[*] Sending requests concurrently...")

        start_all = time.time()

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []

            if fuzz_values:
                # 不同值并发模式
                for i, val in enumerate(fuzz_values):
                    body_override = self.body.replace("{FUZZ}", str(val)) if self.body else None
                    futures.append(executor.submit(self.send_single, i + 1, body_override))
            else:
                # 相同请求并发模式
                for i in range(threads):
                    futures.append(executor.submit(self.send_single, i + 1))

            for future in as_completed(futures):
                result = future.result()
                status_icon = "+" if result["status"] == 200 else "-"
                print(f"  [{status_icon}] #{result['id']:02d} | HTTP {result['status']} | {result['time_ms']}ms")

        total_time = int((time.time() - start_all) * 1000)

        return self.analyze_results(total_time)

    def analyze_results(self, total_time_ms):
        """分析并发结果，判断是否存在竞态"""
        print(f"\n{'='*60}")
        print(f"  Results Analysis")
        print(f"{'='*60}\n")

        total = len(self.results)
        success_count = sum(1 for r in self.results if r["status"] == 200)
        fail_count = total - success_count

        # 按状态码分组
        status_groups = {}
        for r in self.results:
            s = r["status"]
            if s not in status_groups:
                status_groups[s] = 0
            status_groups[s] += 1

        print(f"  Total requests: {total}")
        print(f"  Total time: {total_time_ms}ms")
        print(f"  Success (200): {success_count}")
        print(f"  Failed: {fail_count}")
        print(f"  Status distribution: {status_groups}")
        print()

        # 判断是否存在竞态
        is_vulnerable = False
        vulnerability_reason = ""

        if success_count > 1:
            # 多次成功 = 可能存在竞态
            # 检查响应体是否包含成功标志
            success_bodies = [r["body_preview"] for r in self.results if r["status"] == 200]
            unique_bodies = set(success_bodies)

            if len(unique_bodies) == 1:
                # 所有成功响应相同 → 大概率是竞态
                is_vulnerable = True
                vulnerability_reason = f"并发{total}次中{success_count}次返回200且响应相同，存在竞态条件"
            elif success_count >= total * 0.5:
                is_vulnerable = True
                vulnerability_reason = f"并发{total}次中{success_count}次成功（超过50%），可能存在竞态"

        # 检查时间窗口
        if self.results:
            times = sorted([r["time_ms"] for r in self.results])
            time_spread = times[-1] - times[0]
            if time_spread < 100 and success_count > 1:
                is_vulnerable = True
                vulnerability_reason += f" | 响应时间窗口仅{time_spread}ms（服务端未加锁）"

        if is_vulnerable:
            print(f"  [!] VULNERABLE — 可能存在竞态条件漏洞")
            print(f"  [!] Reason: {vulnerability_reason}")
            print()
            print(f"  建议：")
            print(f"    1. 立即停止继续测试")
            print(f"    2. 录制视频作为证据")
            print(f"    3. 检查余额/次数是否真的多扣/多加了")
            print(f"    4. 写报告提交")
        else:
            print(f"  [✓] 未发现明显竞态条件")
            if success_count == 1:
                print(f"      只有1次成功，服务端可能有锁/幂等保护")
            elif success_count == 0:
                print(f"      所有请求都失败了，可能被频率限制")

        print(f"\n{'='*60}\n")

        return {
            "vulnerable": is_vulnerable,
            "reason": vulnerability_reason,
            "total_requests": total,
            "success_count": success_count,
            "fail_count": fail_count,
            "status_distribution": status_groups,
            "total_time_ms": total_time_ms,
            "results": self.results
        }


def parse_request_file(filepath):
    """解析 HTTP 请求文件（从 Fiddler/Burp 导出的格式）"""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.split("\n")
    if not lines:
        raise ValueError("Empty request file")

    # 第一行: METHOD URL HTTP/1.1
    first_line = lines[0].strip()
    parts = first_line.split(" ")
    method = parts[0] if len(parts) >= 1 else "GET"
    path = parts[1] if len(parts) >= 2 else "/"

    # 解析 headers
    headers = {}
    body_start = 0
    host = ""
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()
            if key.strip().lower() == "host":
                host = val.strip()

    # Body
    body = "\n".join(lines[body_start:]).strip() if body_start > 0 else ""

    # 构造完整 URL
    scheme = "https" if "443" in host else "http"
    url = f"{scheme}://{host}{path}"

    return url, method, headers, body


def main():
    parser = argparse.ArgumentParser(description="Race Condition / 并发竞态测试工具")
    parser.add_argument("--url", help="目标URL")
    parser.add_argument("--method", default="POST", help="HTTP方法 (默认POST)")
    parser.add_argument("--headers", default="{}", help="JSON格式的请求头")
    parser.add_argument("--body", default="", help="请求体")
    parser.add_argument("--body-template", help="请求体模板，{FUZZ}会被替换")
    parser.add_argument("--fuzz-values", help="逗号分隔的fuzz值（配合body-template）")
    parser.add_argument("--threads", type=int, default=20, help="并发线程数 (默认20，建议不超过50)")
    parser.add_argument("--request-file", help="从文件加载请求（Fiddler/Burp导出格式）")
    parser.add_argument("--timeout", type=int, default=10, help="单请求超时秒数")
    parser.add_argument("--output", help="结果输出JSON文件")

    args = parser.parse_args()

    # 从文件加载 or 从参数构造
    if args.request_file:
        url, method, headers, body = parse_request_file(args.request_file)
    elif args.url:
        url = args.url
        method = args.method
        headers = json.loads(args.headers)
        body = args.body_template if args.body_template else args.body
    else:
        parser.error("需要 --url 或 --request-file")
        return

    # 安全检查
    if args.threads > 100:
        print("[!] 警告：线程数超过100可能导致目标服务不可用，已限制为50")
        args.threads = 50

    # Fuzz 值
    fuzz_values = None
    if args.fuzz_values:
        fuzz_values = [v.strip() for v in args.fuzz_values.split(",")]

    # 执行测试
    tester = RaceTester(
        url=url,
        method=method,
        headers=headers,
        body=body,
        timeout=args.timeout
    )

    result = tester.run_concurrent(threads=args.threads, fuzz_values=fuzz_values)

    # 输出结果
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"[+] 结果已保存到: {args.output}")

    sys.exit(0 if not result["vulnerable"] else 1)


if __name__ == "__main__":
    main()
