#!/usr/bin/env python3
"""
UI 控制工具 — 鼠标键盘自动化操作

用途：让 Claude Code 能够控制桌面 GUI，实现：
  - 自动点击按钮、填写表单
  - 滑动验证码
  - 截取屏幕指定区域
  - 模拟键盘输入
  - 定位屏幕上的图像元素

适用场景：
  - SRC测试时自动操作网页（配合Fiddler抓包）
  - 自动化填写登录表单
  - 滑块验证码自动化
  - 截图取证

依赖安装：
  pip install pyautogui pillow pyscreeze

使用方式：
  # 截取全屏
  python3 ui_controller.py --screenshot full --output screen.png

  # 截取指定区域
  python3 ui_controller.py --screenshot region --x 100 --y 200 --width 400 --height 300

  # 点击指定坐标
  python3 ui_controller.py --click 500 300

  # 双击
  python3 ui_controller.py --dblclick 500 300

  # 右键点击
  python3 ui_controller.py --rightclick 500 300

  # 输入文字
  python3 ui_controller.py --type "admin123"

  # 按键
  python3 ui_controller.py --key "enter"
  python3 ui_controller.py --hotkey "ctrl" "a"

  # 移动鼠标
  python3 ui_controller.py --move 500 300

  # 拖拽（滑块验证码）
  python3 ui_controller.py --drag 200 300 500 300 --duration 0.5

  # 查找屏幕上的图片并点击
  python3 ui_controller.py --find-and-click button.png

  # 获取鼠标当前位置
  python3 ui_controller.py --position

  # 等待图片出现再点击
  python3 ui_controller.py --wait-and-click button.png --timeout 10

  # 滚动
  python3 ui_controller.py --scroll -3

注意事项：
  - Windows/Linux 桌面环境下使用
  - WSL 不支持（没有 GUI），需要在 Windows 主机或 Kali VM 桌面运行
  - 操作前建议先 --screenshot 确认当前屏幕状态
  - pyautogui 有 FAILSAFE：鼠标移到左上角(0,0)会中止程序
"""

import argparse
import json
import sys
import time
import os
from datetime import datetime

try:
    import pyautogui
    pyautogui.FAILSAFE = True  # 鼠标移到左上角中止（安全机制）
    pyautogui.PAUSE = 0.1      # 每个操作间隔0.1秒
    HAS_PYAUTOGUI = True
except ImportError:
    HAS_PYAUTOGUI = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


def check_deps():
    """检查依赖"""
    if not HAS_PYAUTOGUI:
        print("[!] pyautogui 未安装。请运行: pip install pyautogui")
        print("    Windows: pip install pyautogui")
        print("    Linux (桌面): pip install pyautogui python3-xlib")
        sys.exit(1)


def screenshot_full(output_path=None):
    """全屏截图"""
    check_deps()
    if not output_path:
        output_path = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    img = pyautogui.screenshot()
    img.save(output_path)
    size = os.path.getsize(output_path)
    print(json.dumps({
        "action": "screenshot",
        "type": "full",
        "file": output_path,
        "size": size,
        "resolution": f"{img.width}x{img.height}"
    }))
    return output_path


def screenshot_region(x, y, width, height, output_path=None):
    """区域截图"""
    check_deps()
    if not output_path:
        output_path = f"region_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    img = pyautogui.screenshot(region=(x, y, width, height))
    img.save(output_path)
    print(json.dumps({
        "action": "screenshot",
        "type": "region",
        "file": output_path,
        "region": {"x": x, "y": y, "width": width, "height": height}
    }))
    return output_path


def click(x, y, button="left", clicks=1):
    """点击"""
    check_deps()
    pyautogui.click(x, y, button=button, clicks=clicks)
    print(json.dumps({"action": "click", "x": x, "y": y, "button": button, "clicks": clicks}))


def move_to(x, y, duration=0.3):
    """移动鼠标"""
    check_deps()
    pyautogui.moveTo(x, y, duration=duration)
    print(json.dumps({"action": "move", "x": x, "y": y}))


def drag(start_x, start_y, end_x, end_y, duration=0.5):
    """拖拽（用于滑块验证码等）"""
    check_deps()
    pyautogui.moveTo(start_x, start_y, duration=0.1)
    time.sleep(0.1)
    pyautogui.mouseDown()
    time.sleep(0.05)
    # 模拟人类拖拽（非匀速）
    steps = max(5, int(abs(end_x - start_x) / 10))
    for i in range(1, steps + 1):
        progress = i / steps
        # 缓动函数（模拟人手）
        eased = progress * (2 - progress)
        current_x = start_x + (end_x - start_x) * eased
        current_y = start_y + (end_y - start_y) * eased
        pyautogui.moveTo(int(current_x), int(current_y), duration=duration / steps)
    pyautogui.mouseUp()
    print(json.dumps({
        "action": "drag",
        "from": {"x": start_x, "y": start_y},
        "to": {"x": end_x, "y": end_y},
        "duration": duration
    }))


def type_text(text, interval=0.05):
    """输入文字"""
    check_deps()
    pyautogui.typewrite(text, interval=interval) if text.isascii() else pyautogui.write(text)
    print(json.dumps({"action": "type", "text": text}))


def press_key(key):
    """按键"""
    check_deps()
    pyautogui.press(key)
    print(json.dumps({"action": "key", "key": key}))


def hotkey(*keys):
    """组合键"""
    check_deps()
    pyautogui.hotkey(*keys)
    print(json.dumps({"action": "hotkey", "keys": list(keys)}))


def get_position():
    """获取鼠标位置"""
    check_deps()
    x, y = pyautogui.position()
    print(json.dumps({"action": "position", "x": x, "y": y}))
    return x, y


def find_on_screen(image_path, confidence=0.8):
    """在屏幕上查找图片"""
    check_deps()
    try:
        location = pyautogui.locateOnScreen(image_path, confidence=confidence)
        if location:
            center = pyautogui.center(location)
            result = {
                "action": "find",
                "found": True,
                "image": image_path,
                "location": {"x": center.x, "y": center.y, "left": location.left, "top": location.top, "width": location.width, "height": location.height}
            }
            print(json.dumps(result))
            return center
        else:
            print(json.dumps({"action": "find", "found": False, "image": image_path}))
            return None
    except Exception as e:
        print(json.dumps({"action": "find", "found": False, "error": str(e)}))
        return None


def find_and_click(image_path, confidence=0.8):
    """找到图片并点击"""
    center = find_on_screen(image_path, confidence)
    if center:
        click(center.x, center.y)
        return True
    return False


def wait_and_click(image_path, timeout=10, confidence=0.8):
    """等待图片出现然后点击"""
    check_deps()
    start = time.time()
    while time.time() - start < timeout:
        try:
            location = pyautogui.locateOnScreen(image_path, confidence=confidence)
            if location:
                center = pyautogui.center(location)
                click(center.x, center.y)
                return True
        except Exception:
            pass
        time.sleep(0.5)
    print(json.dumps({"action": "wait_and_click", "found": False, "timeout": timeout}))
    return False


def scroll(amount):
    """滚动"""
    check_deps()
    pyautogui.scroll(amount)
    print(json.dumps({"action": "scroll", "amount": amount}))


def get_screen_size():
    """获取屏幕分辨率"""
    check_deps()
    w, h = pyautogui.size()
    print(json.dumps({"action": "screen_size", "width": w, "height": h}))
    return w, h


def main():
    parser = argparse.ArgumentParser(description="UI 控制工具 — 鼠标键盘自动化")

    # 截图
    parser.add_argument("--screenshot", choices=["full", "region"], help="截图模式")
    parser.add_argument("--output", "-o", help="截图输出路径")

    # 区域参数
    parser.add_argument("--x", type=int, default=0)
    parser.add_argument("--y", type=int, default=0)
    parser.add_argument("--width", type=int, default=400)
    parser.add_argument("--height", type=int, default=300)

    # 鼠标操作
    parser.add_argument("--click", nargs=2, type=int, metavar=("X", "Y"), help="左键点击")
    parser.add_argument("--dblclick", nargs=2, type=int, metavar=("X", "Y"), help="双击")
    parser.add_argument("--rightclick", nargs=2, type=int, metavar=("X", "Y"), help="右键点击")
    parser.add_argument("--move", nargs=2, type=int, metavar=("X", "Y"), help="移动鼠标")
    parser.add_argument("--drag", nargs=4, type=int, metavar=("X1", "Y1", "X2", "Y2"), help="拖拽")
    parser.add_argument("--duration", type=float, default=0.5, help="拖拽持续时间")
    parser.add_argument("--scroll", type=int, help="滚动（正数向上，负数向下）")

    # 键盘操作
    parser.add_argument("--type", dest="type_text", help="输入文字")
    parser.add_argument("--key", help="按键（enter/tab/esc/f5等）")
    parser.add_argument("--hotkey", nargs="+", help="组合键（如 ctrl a）")

    # 图像识别
    parser.add_argument("--find", help="在屏幕上查找图片")
    parser.add_argument("--find-and-click", help="找到图片并点击")
    parser.add_argument("--wait-and-click", help="等待图片出现再点击")
    parser.add_argument("--timeout", type=int, default=10, help="等待超时秒数")
    parser.add_argument("--confidence", type=float, default=0.8, help="图像匹配置信度(0-1)")

    # 状态
    parser.add_argument("--position", action="store_true", help="获取鼠标位置")
    parser.add_argument("--size", action="store_true", help="获取屏幕分辨率")

    args = parser.parse_args()

    # 执行操作
    if args.screenshot == "full":
        screenshot_full(args.output)
    elif args.screenshot == "region":
        screenshot_region(args.x, args.y, args.width, args.height, args.output)
    elif args.click:
        click(args.click[0], args.click[1])
    elif args.dblclick:
        click(args.dblclick[0], args.dblclick[1], clicks=2)
    elif args.rightclick:
        click(args.rightclick[0], args.rightclick[1], button="right")
    elif args.move:
        move_to(args.move[0], args.move[1])
    elif args.drag:
        drag(args.drag[0], args.drag[1], args.drag[2], args.drag[3], args.duration)
    elif args.scroll is not None:
        scroll(args.scroll)
    elif args.type_text:
        type_text(args.type_text)
    elif args.key:
        press_key(args.key)
    elif args.hotkey:
        hotkey(*args.hotkey)
    elif args.find:
        find_on_screen(args.find, args.confidence)
    elif args.find_and_click:
        find_and_click(args.find_and_click, args.confidence)
    elif args.wait_and_click:
        wait_and_click(args.wait_and_click, args.timeout, args.confidence)
    elif args.position:
        get_position()
    elif args.size:
        get_screen_size()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
