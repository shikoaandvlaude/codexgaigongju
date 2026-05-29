#!/usr/bin/env python3
"""
IDOR / 越权自动对比工具

用途：用两个不同身份的账号请求同一接口，对比响应差异，自动判断是否存在越权。

使用方式：
  # 水平越权测试：A用户访问B用户的资源
  python3 idor_diff.py \
    --url "https://target.com/api/user/{ID}/orders" \
    --ids "123,456,789" \
    --auth-a "Cookie: session=user_A_cookie" \
    --auth-b "Cookie: session=user_B_cookie" \
    --own-id 123

  # 垂直越权测试：普通用户访问管理员接口
  python3 idor_diff.py \
    --url "https://target.com/api/admin/users" \
    --auth-a "Cookie: session=admin_cookie" \
    --auth-b "Cookie: session=normal_user_cookie" \
    --mode vertical

  # 批量接口测试（从文件加载）
  python3 idor_diff.py \
    --url-file endpoints.txt \
    --auth-a "Bearer admin_token" \
    --auth-b "Bearer user_token" \
    --mode vertical

  # 无认证测试（检测接口是否需要登录）
  python3 idor_diff.py \
    --url "https://target.com/api/user/123/profile" \
    --auth-a "Cookie: session=logged_in" \
    --no-auth-test

注意事项（红线）：
  - 只用自己注册的2个账号测试
  - 不遍历大量ID（证明存在即可）
  - 不访问真实用户数据
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from difflib import unified_diff, SequenceMatcher
from datetime import datetime


class IDORTester:
    """越权漏洞自动对比测试器"""

    def __init__(self, timeout=10):
        self.timeout = timeout
        self.findings = []

    def send_request(self, url, auth_header=None, method="GET"):
        """发送HTTP请求"""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        if auth_header:
            # 支持 "Cookie: xxx" 或 "Bearer xxx" 格式
            if ": " in auth_header:
                key, val = auth_header.split(": ", 1)
                headers[key] = val
            elif auth_header.startswith("Bearer "):
                headers["Authorization"] = auth_header
            else:
                headers["Cookie"] = auth_header

        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                    "length": len(body),
                    "error": None
                }
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": body,
                "length": len(body),
                "error": None
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "length": 0,
                "error": str(e)
            }

    def compare_responses(self, resp_a, resp_b, context=""):
        """对比两个响应，判断是否存在越权"""
        result = {
            "context": context,
            "status_a": resp_a["status"],
            "status_b": resp_b["status"],
            "length_a": resp_a["length"],
            "length_b": resp_b["length"],
            "vulnerable": False,
            "vuln_type": None,
            "confidence": 0,
            "detail": ""
        }

        # 情况1：B用户能访问A用户的资源（状态码都是200）
        if resp_a["status"] == 200 and resp_b["status"] == 200:
            # 计算响应相似度
            similarity = SequenceMatcher(None, resp_a["body"][:2000], resp_b["body"][:2000]).ratio()

            if similarity > 0.8:
                # 响应高度相似 → 大概率越权
                result["vulnerable"] = True
                result["vuln_type"] = "IDOR - 水平越权"
                result["confidence"] = min(95, int(similarity * 100))
                result["detail"] = f"两个身份访问响应相似度{similarity:.1%}，B用户可能能访问A的数据"
            elif similarity > 0.3:
                # 部分相似 → 需要人工确认
                result["vulnerable"] = True
                result["vuln_type"] = "IDOR - 可能越权"
                result["confidence"] = int(similarity * 70)
                result["detail"] = f"响应相似度{similarity:.1%}，需要人工确认返回的是否是不同用户的数据"

        # 情况2：垂直越权 — 普通用户也能访问管理接口
        elif resp_a["status"] == 200 and resp_b["status"] == 200:
            result["vulnerable"] = True
            result["vuln_type"] = "垂直越权"
            result["confidence"] = 85
            result["detail"] = "低权限用户也能成功访问该接口"

        # 情况3：无认证也能访问
        elif resp_a["status"] == 200 and resp_b.get("no_auth") and resp_b["status"] == 200:
            result["vulnerable"] = True
            result["vuln_type"] = "未授权访问"
            result["confidence"] = 90
            result["detail"] = "无需认证即可访问该接口"

        # 正常情况：B被拒绝
        elif resp_b["status"] in (401, 403, 404):
            result["detail"] = f"B用户被拒绝(HTTP {resp_b['status']})，接口权限正常"

        return result

    def test_horizontal(self, url_template, ids, auth_a, auth_b, own_id=None):
        """水平越权测试：A的身份访问B的资源"""
        print(f"\n{'='*60}")
        print(f"  IDOR 水平越权测试")
        print(f"  URL模板: {url_template}")
        print(f"  测试ID: {ids}")
        print(f"  自己的ID: {own_id or '未指定'}")
        print(f"{'='*60}\n")

        results = []

        for target_id in ids:
            url = url_template.replace("{ID}", str(target_id))
            is_own = str(target_id) == str(own_id) if own_id else False

            print(f"  [*] 测试 ID={target_id} {'(自己)' if is_own else '(他人)'}...")

            # A身份（合法拥有者或高权限）请求
            resp_a = self.send_request(url, auth_a)
            # B身份（攻击者）请求同一资源
            resp_b = self.send_request(url, auth_b)

            comparison = self.compare_responses(resp_a, resp_b, f"ID={target_id}")

            if not is_own and comparison["vulnerable"]:
                print(f"  [!] VULNERABLE — {comparison['vuln_type']} (置信度{comparison['confidence']}%)")
                print(f"      Detail: {comparison['detail']}")
                self.findings.append({
                    "url": url,
                    "target_id": target_id,
                    **comparison
                })
            elif is_own:
                print(f"  [✓] 自己的资源，跳过")
            else:
                print(f"  [✓] 安全 — {comparison['detail']}")

            results.append(comparison)

        return results

    def test_vertical(self, urls, auth_admin, auth_user):
        """垂直越权测试：普通用户访问管理员接口"""
        print(f"\n{'='*60}")
        print(f"  垂直越权测试")
        print(f"  接口数: {len(urls)}")
        print(f"{'='*60}\n")

        results = []

        for url in urls:
            url = url.strip()
            if not url:
                continue

            print(f"  [*] 测试: {url}")

            # 管理员请求
            resp_admin = self.send_request(url, auth_admin)
            # 普通用户请求
            resp_user = self.send_request(url, auth_user)

            if resp_admin["status"] == 200 and resp_user["status"] == 200:
                similarity = SequenceMatcher(
                    None,
                    resp_admin["body"][:2000],
                    resp_user["body"][:2000]
                ).ratio()

                if similarity > 0.5:
                    print(f"  [!] VULNERABLE — 普通用户可访问 (HTTP 200, 相似度{similarity:.0%})")
                    finding = {
                        "url": url,
                        "vuln_type": "垂直越权",
                        "vulnerable": True,
                        "confidence": int(similarity * 90),
                        "admin_status": resp_admin["status"],
                        "user_status": resp_user["status"],
                        "detail": f"普通用户返回200且内容相似度{similarity:.0%}"
                    }
                    self.findings.append(finding)
                    results.append(finding)
                else:
                    print(f"  [?] 都是200但内容差异大(相似度{similarity:.0%})，需人工确认")
                    results.append({"url": url, "vulnerable": False, "detail": "内容差异大，需人工确认"})
            elif resp_admin["status"] == 200 and resp_user["status"] in (401, 403):
                print(f"  [✓] 安全 — 普通用户被拒绝 (HTTP {resp_user['status']})")
                results.append({"url": url, "vulnerable": False, "detail": f"用户被拒绝({resp_user['status']})"})
            else:
                print(f"  [?] Admin={resp_admin['status']}, User={resp_user['status']}")
                results.append({"url": url, "vulnerable": False, "detail": f"需人工分析"})

        return results

    def test_no_auth(self, urls, auth_valid):
        """无认证测试：去掉认证头看接口是否仍然可访问"""
        print(f"\n{'='*60}")
        print(f"  未授权访问测试")
        print(f"{'='*60}\n")

        results = []

        for url in urls:
            url = url.strip()
            if not url:
                continue

            print(f"  [*] 测试: {url}")

            # 有认证
            resp_auth = self.send_request(url, auth_valid)
            # 无认证
            resp_no_auth = self.send_request(url, None)

            if resp_auth["status"] == 200 and resp_no_auth["status"] == 200:
                similarity = SequenceMatcher(
                    None,
                    resp_auth["body"][:2000],
                    resp_no_auth["body"][:2000]
                ).ratio()

                if similarity > 0.5:
                    print(f"  [!] VULNERABLE — 无需认证即可访问！")
                    finding = {
                        "url": url,
                        "vuln_type": "未授权访问",
                        "vulnerable": True,
                        "confidence": 90,
                        "detail": f"去掉认证头后仍返回200且内容相似(相似度{similarity:.0%})"
                    }
                    self.findings.append(finding)
                    results.append(finding)
                else:
                    print(f"  [?] 都200但内容不同，可能是返回了登录页面")
                    results.append({"url": url, "vulnerable": False, "detail": "可能返回了登录页"})
            elif resp_no_auth["status"] in (401, 403, 302):
                print(f"  [✓] 安全 — 无认证被拒绝/重定向 (HTTP {resp_no_auth['status']})")
                results.append({"url": url, "vulnerable": False})
            else:
                print(f"  [?] Auth={resp_auth['status']}, NoAuth={resp_no_auth['status']}")
                results.append({"url": url, "vulnerable": False, "detail": "需人工分析"})

        return results

    def print_summary(self):
        """打印总结"""
        print(f"\n{'='*60}")
        print(f"  测试总结")
        print(f"{'='*60}\n")

        if self.findings:
            print(f"  [!] 发现 {len(self.findings)} 个越权漏洞:\n")
            for i, f in enumerate(self.findings, 1):
                print(f"  {i}. [{f.get('vuln_type', 'IDOR')}] {f.get('url', '')}")
                print(f"     置信度: {f.get('confidence', 0)}%")
                print(f"     Detail: {f.get('detail', '')}")
                print()
        else:
            print(f"  [✓] 未发现越权漏洞")

        print(f"{'='*60}\n")
        return self.findings


def main():
    parser = argparse.ArgumentParser(description="IDOR / 越权自动对比工具")
    parser.add_argument("--url", help="目标URL（用{ID}标记可替换的ID位置）")
    parser.add_argument("--url-file", help="从文件加载URL列表（每行一个）")
    parser.add_argument("--ids", help="逗号分隔的ID列表（水平越权）")
    parser.add_argument("--own-id", help="自己账号的ID（用于区分自己和他人的资源）")
    parser.add_argument("--auth-a", required=True, help="A账号认证头（如 'Cookie: session=xxx'）")
    parser.add_argument("--auth-b", help="B账号认证头")
    parser.add_argument("--mode", choices=["horizontal", "vertical", "no-auth"], default="horizontal",
                       help="测试模式: horizontal(水平越权), vertical(垂直越权), no-auth(未授权)")
    parser.add_argument("--no-auth-test", action="store_true", help="同时测试无认证访问")
    parser.add_argument("--method", default="GET", help="HTTP方法")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--output", help="结果输出JSON文件")

    args = parser.parse_args()

    tester = IDORTester(timeout=args.timeout)

    # 获取URL列表
    urls = []
    if args.url_file:
        with open(args.url_file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif args.url:
        urls = [args.url]
    else:
        parser.error("需要 --url 或 --url-file")

    # 执行测试
    if args.mode == "horizontal":
        if not args.ids:
            parser.error("水平越权模式需要 --ids")
        if not args.auth_b:
            parser.error("水平越权模式需要 --auth-b（攻击者账号）")
        ids = [x.strip() for x in args.ids.split(",")]
        tester.test_horizontal(urls[0], ids, args.auth_a, args.auth_b, args.own_id)

    elif args.mode == "vertical":
        if not args.auth_b:
            parser.error("垂直越权模式需要 --auth-b（普通用户账号）")
        tester.test_vertical(urls, args.auth_a, args.auth_b)

    elif args.mode == "no-auth":
        tester.test_no_auth(urls, args.auth_a)

    # 额外的无认证测试
    if args.no_auth_test and args.mode != "no-auth":
        tester.test_no_auth(urls, args.auth_a)

    # 总结
    findings = tester.print_summary()

    # 输出
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)
        print(f"[+] 结果已保存: {args.output}")

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
