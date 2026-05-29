#!/usr/bin/env python3
"""
截图识图工具 — 验证码识别 + 页面截图分析

用途：
  1. 验证码识别（图片验证码 → 文字）
  2. 网页截图并用视觉AI分析内容（发现按钮、表单、敏感信息）
  3. 对比两张截图差异（越权前后对比）

支持的视觉 AI 后端（需要额外配置 API Key）：
  - OpenAI GPT-4o (gpt-4o / gpt-4o-mini)
  - 通义千问 Qwen-VL (qwen-vl-plus)
  - 智谱 GLM-4V (glm-4v)
  - 本地 OCR (pytesseract, 不需要API但精度低)

配置方式：
  设置环境变量或创建 ~/.config/screenshot_ocr.json:
  {
    "provider": "openai",
    "api_key": "sk-xxx",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4o-mini"
  }

  国内推荐用通义千问（便宜）:
  {
    "provider": "qwen",
    "api_key": "sk-xxx",
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "model": "qwen-vl-plus"
  }

使用方式：
  # 识别验证码图片
  python3 screenshot_ocr.py --captcha captcha.png

  # 分析网页截图（发现功能点）
  python3 screenshot_ocr.py --analyze screenshot.png --prompt "这个页面有哪些可能的漏洞点"

  # 网页截图（需要 Chrome/Chromium）
  python3 screenshot_ocr.py --screenshot "https://target.com/login" --output login.png

  # 对比两张截图（越权前后）
  python3 screenshot_ocr.py --diff before.png after.png

  # 批量识别验证码（用于测试验证码强度）
  python3 screenshot_ocr.py --captcha-url "https://target.com/captcha" --count 5
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime


# ── 配置加载 ──────────────────────────────────────────────────────────────

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/screenshot_ocr.json")

def load_config():
    """加载视觉AI配置"""
    config = {
        "provider": "openai",
        "api_key": "",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini"
    }

    # 从环境变量
    if os.environ.get("VISION_API_KEY"):
        config["api_key"] = os.environ["VISION_API_KEY"]
    if os.environ.get("VISION_BASE_URL"):
        config["base_url"] = os.environ["VISION_BASE_URL"]
    if os.environ.get("VISION_MODEL"):
        config["model"] = os.environ["VISION_MODEL"]
    if os.environ.get("VISION_PROVIDER"):
        config["provider"] = os.environ["VISION_PROVIDER"]

    # 从配置文件
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            with open(DEFAULT_CONFIG_PATH, "r") as f:
                file_config = json.load(f)
                config.update({k: v for k, v in file_config.items() if v})
        except Exception:
            pass

    return config


def image_to_base64(image_path):
    """图片转 base64"""
    with open(image_path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")


def detect_image_type(image_path):
    """检测图片MIME类型"""
    ext = Path(image_path).suffix.lower()
    mime_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp"
    }
    return mime_map.get(ext, "image/png")


# ── 视觉 AI 调用 ──────────────────────────────────────────────────────────

def call_vision_api(image_path, prompt, config=None):
    """调用视觉AI分析图片"""
    if config is None:
        config = load_config()

    if not config.get("api_key"):
        return {"error": "未配置视觉AI API Key。请设置环境变量 VISION_API_KEY 或创建 ~/.config/screenshot_ocr.json"}

    img_base64 = image_to_base64(image_path)
    img_type = detect_image_type(image_path)

    # OpenAI / 兼容接口格式（通义千问、智谱等都兼容）
    url = f"{config['base_url'].rstrip('/')}/chat/completions"

    payload = {
        "model": config["model"],
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{img_type};base64,{img_base64}"
                        }
                    }
                ]
            }
        ],
        "max_tokens": 1000
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config['api_key']}"
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {"success": True, "text": content, "model": config["model"]}
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")[:300]
        return {"error": f"API错误 HTTP {e.code}: {error_body}"}
    except Exception as e:
        return {"error": f"请求失败: {str(e)}"}


def call_local_ocr(image_path):
    """使用本地 OCR（pytesseract）— 不需要API但精度低"""
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img, lang="chi_sim+eng")
        return {"success": True, "text": text.strip(), "model": "tesseract-local"}
    except ImportError:
        return {"error": "本地OCR需要安装: pip install pytesseract Pillow\n并安装 tesseract-ocr: sudo apt install tesseract-ocr tesseract-ocr-chi-sim"}
    except Exception as e:
        return {"error": f"OCR失败: {str(e)}"}


# ── 功能实现 ──────────────────────────────────────────────────────────────

def recognize_captcha(image_path, config=None, use_local=False):
    """识别验证码"""
    if use_local:
        return call_local_ocr(image_path)

    prompt = (
        "这是一个网站的图片验证码。请识别验证码中的所有字符（字母和数字）。"
        "只输出验证码内容，不要任何其他文字。如果看不清请尽力猜测。"
    )
    return call_vision_api(image_path, prompt, config)


def analyze_screenshot(image_path, custom_prompt=None, config=None):
    """分析网页截图"""
    default_prompt = (
        "分析这个网页截图，告诉我：\n"
        "1. 这是什么类型的页面（登录、注册、支付、后台等）\n"
        "2. 页面上有哪些输入框和按钮\n"
        "3. 有没有可能的安全测试点（如ID参数、金额字段、文件上传等）\n"
        "4. 有没有泄露的敏感信息（版本号、错误信息、内部路径等）\n"
        "请用中文回答，简洁列出。"
    )
    prompt = custom_prompt or default_prompt
    return call_vision_api(image_path, prompt, config)


def diff_screenshots(image_a, image_b, config=None):
    """对比两张截图差异"""
    if config is None:
        config = load_config()

    if not config.get("api_key"):
        return {"error": "未配置视觉AI API Key"}

    img_a_b64 = image_to_base64(image_a)
    img_b_b64 = image_to_base64(image_b)
    type_a = detect_image_type(image_a)
    type_b = detect_image_type(image_b)

    url = f"{config['base_url'].rstrip('/')}/chat/completions"

    payload = {
        "model": config["model"],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "对比这两张网页截图的差异。第一张是正常用户视角，第二张是用另一个身份访问的结果。\n"
                            "请告诉我：\n"
                            "1. 两张图的主要内容差异\n"
                            "2. 第二张是否能看到不属于该用户的数据（越权迹象）\n"
                            "3. 是否存在安全风险\n"
                            "用中文简洁回答。"
                        )
                    },
                    {"type": "image_url", "image_url": {"url": f"data:{type_a};base64,{img_a_b64}"}},
                    {"type": "image_url", "image_url": {"url": f"data:{type_b};base64,{img_b_b64}"}}
                ]
            }
        ],
        "max_tokens": 1000
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config['api_key']}"
    }

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=45) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {"success": True, "text": content, "model": config["model"]}
    except Exception as e:
        return {"error": str(e)}


def take_screenshot(url, output_path, width=1920, height=1080):
    """用 Chrome/Chromium 无头模式截图"""
    chrome_paths = [
        "google-chrome", "chromium-browser", "chromium",
        "/usr/bin/google-chrome", "/usr/bin/chromium-browser",
        "C:/Program Files/Google/Chrome/Application/chrome.exe",
        "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"
    ]

    chrome_bin = None
    for p in chrome_paths:
        try:
            subprocess.run([p, "--version"], capture_output=True, timeout=5)
            chrome_bin = p
            break
        except Exception:
            continue

    if not chrome_bin:
        return {"error": "未找到 Chrome/Chromium。请安装: sudo apt install chromium-browser"}

    cmd = [
        chrome_bin,
        "--headless", "--disable-gpu", "--no-sandbox",
        f"--window-size={width},{height}",
        f"--screenshot={output_path}",
        url
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if os.path.exists(output_path):
            return {"success": True, "file": output_path, "size": os.path.getsize(output_path)}
        else:
            return {"error": f"截图失败: {result.stderr[:200]}"}
    except subprocess.TimeoutExpired:
        return {"error": "截图超时（30秒）"}
    except Exception as e:
        return {"error": str(e)}


def fetch_captcha_image(url, output_path, headers=None):
    """下载验证码图片"""
    try:
        req_headers = {"User-Agent": "Mozilla/5.0"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, headers=req_headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            with open(output_path, "wb") as f:
                f.write(resp.read())
        return True
    except Exception as e:
        print(f"  [!] 下载失败: {e}")
        return False


# ── 主程序 ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="截图识图工具 — 验证码识别 + 页面分析")
    parser.add_argument("--captcha", help="识别验证码图片文件")
    parser.add_argument("--captcha-url", help="验证码图片URL（自动下载并识别）")
    parser.add_argument("--count", type=int, default=1, help="验证码识别次数（测试验证码强度）")
    parser.add_argument("--analyze", help="分析网页截图")
    parser.add_argument("--prompt", help="自定义分析提示词")
    parser.add_argument("--screenshot", help="对URL截图")
    parser.add_argument("--diff", nargs=2, metavar=("IMG_A", "IMG_B"), help="对比两张截图")
    parser.add_argument("--output", help="截图输出路径")
    parser.add_argument("--local-ocr", action="store_true", help="使用本地OCR（不需要API，精度低）")
    parser.add_argument("--config", help="配置文件路径")

    # 配置覆盖
    parser.add_argument("--api-key", help="视觉AI API Key（覆盖配置文件）")
    parser.add_argument("--base-url", help="API Base URL")
    parser.add_argument("--model", help="模型名称")
    parser.add_argument("--provider", help="提供商: openai/qwen/glm")

    args = parser.parse_args()

    # 加载配置
    config = load_config()
    if args.config:
        with open(args.config, "r") as f:
            config.update(json.load(f))
    if args.api_key:
        config["api_key"] = args.api_key
    if args.base_url:
        config["base_url"] = args.base_url
    if args.model:
        config["model"] = args.model
    if args.provider:
        config["provider"] = args.provider

    print(f"\n{'='*60}")
    print(f"  Screenshot OCR Tool")
    print(f"  Provider: {config.get('provider', 'unknown')}")
    print(f"  Model: {config.get('model', 'unknown')}")
    print(f"  API configured: {'Yes' if config.get('api_key') else 'No'}")
    print(f"{'='*60}\n")

    # 截图
    if args.screenshot:
        output = args.output or f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        print(f"[*] 截图: {args.screenshot} → {output}")
        result = take_screenshot(args.screenshot, output)
        if result.get("success"):
            print(f"[+] 截图成功: {result['file']} ({result['size']} bytes)")
            # 自动分析
            if config.get("api_key"):
                print(f"[*] 自动分析截图...")
                analysis = analyze_screenshot(output, args.prompt, config)
                if analysis.get("success"):
                    print(f"\n{analysis['text']}\n")
                else:
                    print(f"[!] {analysis.get('error')}")
        else:
            print(f"[!] {result.get('error')}")
        return

    # 验证码识别
    if args.captcha or args.captcha_url:
        for i in range(args.count):
            if args.captcha_url:
                tmp_path = f"/tmp/captcha_{i}_{datetime.now().strftime('%H%M%S')}.png"
                print(f"  [*] 下载验证码 #{i+1}...")
                if not fetch_captcha_image(args.captcha_url, tmp_path):
                    continue
                image_path = tmp_path
            else:
                image_path = args.captcha

            print(f"  [*] 识别验证码: {image_path}")
            result = recognize_captcha(image_path, config, use_local=args.local_ocr)

            if result.get("success"):
                print(f"  [+] 验证码内容: {result['text']} (model: {result.get('model', '?')})")
            else:
                print(f"  [!] 识别失败: {result.get('error')}")

            if args.count > 1:
                print()
        return

    # 分析截图
    if args.analyze:
        print(f"[*] 分析截图: {args.analyze}")
        if args.local_ocr:
            result = call_local_ocr(args.analyze)
        else:
            result = analyze_screenshot(args.analyze, args.prompt, config)

        if result.get("success"):
            print(f"\n{'─'*40}")
            print(result["text"])
            print(f"{'─'*40}\n")
        else:
            print(f"[!] {result.get('error')}")
        return

    # 对比截图
    if args.diff:
        img_a, img_b = args.diff
        print(f"[*] 对比截图: {img_a} vs {img_b}")
        result = diff_screenshots(img_a, img_b, config)
        if result.get("success"):
            print(f"\n{'─'*40}")
            print(result["text"])
            print(f"{'─'*40}\n")
        else:
            print(f"[!] {result.get('error')}")
        return

    # 没有指定操作
    parser.print_help()
    print("\n配置说明:")
    print("  1. 设置环境变量: export VISION_API_KEY='你的key'")
    print("  2. 或创建配置文件: ~/.config/screenshot_ocr.json")
    print("  3. 推荐用通义千问(便宜): provider=qwen, model=qwen-vl-plus")
    print("  4. 不要API可以用 --local-ocr（精度低，只能识别简单验证码）")


if __name__ == "__main__":
    main()
