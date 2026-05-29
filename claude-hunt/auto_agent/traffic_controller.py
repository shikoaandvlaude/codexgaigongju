#!/usr/bin/env python3
"""
Traffic Controller — 智能流量控制器

功能：
1. 自适应限速（基于目标响应自动调整 RPS）
2. WAF/封禁检测 + 自动降速/暂停
3. 时段调度（高峰期自动降速，凌晨提速）
4. 请求预算管理（总量/每分钟/每小时上限）
5. 滑动窗口流量统计
6. 熔断机制（连续失败自动暂停）
7. 与 proxy_rotator / stealth_http 联动

用法：
    from traffic_controller import TrafficController

    tc = TrafficController(config)
    await tc.acquire()           # 获取发送许可（会自动等待）
    tc.record_response(200)      # 记录响应状态
    tc.record_response(429)      # 检测到限速 → 自动降速

    # 作为装饰器
    @tc.rate_limited
    async def scan_url(url):
        ...
"""

import asyncio
import time
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from datetime import datetime, timedelta
from collections import deque


# ═══════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════

@dataclass
class TrafficStats:
    """流量统计"""
    total_requests: int = 0
    total_success: int = 0
    total_failed: int = 0
    total_blocked: int = 0
    # 滑动窗口
    requests_last_minute: int = 0
    requests_last_hour: int = 0
    # 速率
    current_rps: float = 0
    target_rps: float = 2.0
    min_rps: float = 0.2
    max_rps: float = 5.0
    # 状态
    is_paused: bool = False
    pause_reason: str = ""
    pause_until: float = 0
    # 连续失败
    consecutive_fails: int = 0
    consecutive_blocks: int = 0


# 时段速率配置
TIME_SCHEDULES = {
    "aggressive": {
        # 凌晨全速
        (0, 6): 5.0,
        (6, 9): 2.0,
        (9, 12): 1.5,
        (12, 14): 2.0,
        (14, 18): 1.5,
        (18, 22): 2.5,
        (22, 24): 4.0,
    },
    "normal": {
        (0, 6): 3.0,
        (6, 9): 1.5,
        (9, 18): 1.0,
        (18, 22): 2.0,
        (22, 24): 3.0,
    },
    "conservative": {
        (0, 6): 2.0,
        (6, 22): 0.5,
        (22, 24): 1.5,
    },
    "stealth": {
        (0, 24): 0.3,  # 全天极慢
    },
}


# ═══════════════════════════════════════════════════════════════
# 流量控制器
# ═══════════════════════════════════════════════════════════════

class TrafficController:
    """智能流量控制器"""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self._lock = asyncio.Lock()

        # 配置
        self.initial_rps = self.config.get("requests_per_second", 2.0)
        self.min_rps = self.config.get("min_rps", 0.1)
        self.max_rps = self.config.get("max_rps", 5.0)
        self.max_concurrent = self.config.get("max_concurrent", 3)
        self.schedule_mode = self.config.get("schedule", "normal")  # aggressive/normal/conservative/stealth

        # 预算
        self.budget_total = self.config.get("max_total_requests", 500)
        self.budget_per_minute = self.config.get("max_per_minute", 30)
        self.budget_per_hour = self.config.get("max_per_hour", 500)

        # 熔断
        self.circuit_break_threshold = self.config.get("circuit_break_fails", 10)
        self.circuit_break_duration = self.config.get("circuit_break_duration", 120)
        self.block_pause_duration = self.config.get("block_pause_duration", 60)
        self.block_threshold = self.config.get("block_threshold", 3)

        # 自适应参数
        self.speedup_factor = self.config.get("speedup_factor", 1.1)
        self.slowdown_factor = self.config.get("slowdown_factor", 0.5)

        # 状态
        self.stats = TrafficStats(target_rps=self.initial_rps,
                                  min_rps=self.min_rps, max_rps=self.max_rps)
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._last_request_time = 0.0
        self._request_times: deque = deque(maxlen=1000)  # 最近 1000 次请求时间
        self._minute_window: deque = deque(maxlen=200)
        self._hour_window: deque = deque(maxlen=5000)
        self._response_codes: deque = deque(maxlen=100)  # 最近 100 个状态码

        # 回调
        self._on_pause: Optional[Callable] = None
        self._on_resume: Optional[Callable] = None
        self._on_slowdown: Optional[Callable] = None

    # ─── 核心：获取发送许可 ────────────────────────────────────

    async def acquire(self) -> bool:
        """
        获取发送许可（核心方法）
        - 如果当前暂停/熔断 → 等待
        - 如果超出预算 → 拒绝
        - 按当前 RPS 限速等待
        返回 True 表示可以发送，False 表示预算耗尽
        """
        # 检查暂停状态
        await self._wait_if_paused()

        # 检查预算
        if not self._check_budget():
            return False

        # 并发控制
        await self._semaphore.acquire()
        try:
            # 时段调度：调整目标 RPS
            self._apply_schedule()

            # 计算等待时间
            interval = 1.0 / self.stats.target_rps
            # 加入随机抖动（±30%），避免固定间隔特征
            jitter = random.uniform(-0.3, 0.3) * interval
            interval = max(0.1, interval + jitter)

            elapsed = time.time() - self._last_request_time
            wait = interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)

            # 记录
            now = time.time()
            self._last_request_time = now
            self._request_times.append(now)
            self._minute_window.append(now)
            self._hour_window.append(now)
            self.stats.total_requests += 1

            return True
        finally:
            self._semaphore.release()

    async def release(self):
        """释放（配合手动 semaphore 使用）"""
        pass

    # ─── 响应反馈 ─────────────────────────────────────────────

    def record_response(self, status_code: int, response_time_ms: int = 0):
        """
        记录响应状态 → 自动调速
        - 200/301/302: 成功 → 缓慢提速
        - 429: 被限速 → 立即降速 50%
        - 403: 被封 → 暂停 + 降速
        - 503: 服务过载 → 降速
        - 0/超时: 失败 → 小幅降速
        """
        self._response_codes.append(status_code)

        if status_code in (200, 201, 204, 301, 302, 304):
            # 成功
            self.stats.total_success += 1
            self.stats.consecutive_fails = 0
            self.stats.consecutive_blocks = 0
            # 缓慢提速（每 10 次成功提速一点）
            if self.stats.total_success % 10 == 0:
                self._speed_up()

        elif status_code == 429:
            # 被限速 → 立即降速
            self.stats.total_blocked += 1
            self.stats.consecutive_blocks += 1
            self._slow_down(reason="429 Too Many Requests")
            # 连续被限速 → 暂停
            if self.stats.consecutive_blocks >= self.block_threshold:
                self._pause(self.block_pause_duration, "连续被限速")

        elif status_code == 403:
            # 可能被封
            self.stats.total_blocked += 1
            self.stats.consecutive_blocks += 1
            self._slow_down(reason="403 Forbidden")
            if self.stats.consecutive_blocks >= self.block_threshold:
                self._pause(self.block_pause_duration * 2, "疑似 IP 被封")

        elif status_code == 503:
            # 服务过载
            self.stats.total_failed += 1
            self._slow_down(reason="503 Service Unavailable")
            self._pause(30, "目标过载，等待 30s")

        elif status_code == 0:
            # 超时/连接失败
            self.stats.total_failed += 1
            self.stats.consecutive_fails += 1
            if self.stats.consecutive_fails >= self.circuit_break_threshold:
                self._circuit_break()

        else:
            # 其他状态码
            self.stats.consecutive_fails = 0

        # 更新实时 RPS 统计
        self._update_current_rps()

    # ─── 自适应速率调整 ────────────────────────────────────────

    def _speed_up(self):
        """提速（谨慎）"""
        new_rps = min(self.stats.target_rps * self.speedup_factor, self.stats.max_rps)
        if new_rps != self.stats.target_rps:
            self.stats.target_rps = round(new_rps, 2)

    def _slow_down(self, reason: str = ""):
        """降速"""
        new_rps = max(self.stats.target_rps * self.slowdown_factor, self.stats.min_rps)
        old_rps = self.stats.target_rps
        self.stats.target_rps = round(new_rps, 2)
        if old_rps != new_rps:
            print(f"  [!] 降速: {old_rps:.1f} → {new_rps:.1f} req/s ({reason})")
            if self._on_slowdown:
                self._on_slowdown(old_rps, new_rps, reason)

    def _pause(self, duration: float, reason: str):
        """暂停"""
        self.stats.is_paused = True
        self.stats.pause_reason = reason
        self.stats.pause_until = time.time() + duration
        print(f"  [!!] 暂停 {duration:.0f}s: {reason}")
        if self._on_pause:
            self._on_pause(duration, reason)

    def _resume(self):
        """恢复"""
        if self.stats.is_paused:
            self.stats.is_paused = False
            self.stats.pause_reason = ""
            print(f"  [*] 恢复发送 (RPS: {self.stats.target_rps:.1f})")
            if self._on_resume:
                self._on_resume()

    def _circuit_break(self):
        """熔断（连续大量失败）"""
        duration = self.circuit_break_duration
        self._pause(duration, f"熔断: 连续 {self.stats.consecutive_fails} 次失败")
        self.stats.consecutive_fails = 0
        # 熔断后大幅降速
        self.stats.target_rps = self.stats.min_rps

    async def _wait_if_paused(self):
        """等待暂停结束"""
        while self.stats.is_paused:
            remaining = self.stats.pause_until - time.time()
            if remaining <= 0:
                self._resume()
                break
            # 每秒检查一次
            await asyncio.sleep(min(remaining, 1.0))

    # ─── 时段调度 ──────────────────────────────────────────────

    def _apply_schedule(self):
        """根据当前时间调整目标 RPS"""
        schedule = TIME_SCHEDULES.get(self.schedule_mode)
        if not schedule:
            return

        current_hour = datetime.now().hour
        for (start, end), rps in schedule.items():
            if start <= current_hour < end:
                # 时段 RPS 作为上限，不超过当前自适应值
                scheduled_rps = min(rps, self.max_rps)
                # 如果自适应降速后比时段值还低，保持低值
                self.stats.target_rps = min(self.stats.target_rps, scheduled_rps)
                # 但不低于 min_rps
                self.stats.target_rps = max(self.stats.target_rps, self.stats.min_rps)
                break

    # ─── 预算控制 ──────────────────────────────────────────────

    def _check_budget(self) -> bool:
        """检查请求预算"""
        now = time.time()

        # 总预算
        if self.stats.total_requests >= self.budget_total:
            print(f"  [!!] 预算耗尽: 已达总量上限 {self.budget_total}")
            return False

        # 每分钟预算
        cutoff_1m = now - 60
        while self._minute_window and self._minute_window[0] < cutoff_1m:
            self._minute_window.popleft()
        if len(self._minute_window) >= self.budget_per_minute:
            # 等到下一分钟
            return False

        # 每小时预算
        cutoff_1h = now - 3600
        while self._hour_window and self._hour_window[0] < cutoff_1h:
            self._hour_window.popleft()
        if len(self._hour_window) >= self.budget_per_hour:
            return False

        return True

    # ─── 统计 ─────────────────────────────────────────────────

    def _update_current_rps(self):
        """计算实时 RPS"""
        now = time.time()
        cutoff = now - 10  # 最近 10 秒
        recent = [t for t in self._request_times if t > cutoff]
        if len(recent) >= 2:
            duration = recent[-1] - recent[0]
            if duration > 0:
                self.stats.current_rps = round(len(recent) / duration, 2)

        # 更新窗口计数
        cutoff_1m = now - 60
        self.stats.requests_last_minute = sum(1 for t in self._minute_window if t > cutoff_1m)
        cutoff_1h = now - 3600
        self.stats.requests_last_hour = sum(1 for t in self._hour_window if t > cutoff_1h)

    def get_stats(self) -> Dict:
        """获取统计信息"""
        self._update_current_rps()
        return {
            "total_requests": self.stats.total_requests,
            "success": self.stats.total_success,
            "failed": self.stats.total_failed,
            "blocked": self.stats.total_blocked,
            "current_rps": self.stats.current_rps,
            "target_rps": self.stats.target_rps,
            "requests_last_minute": self.stats.requests_last_minute,
            "requests_last_hour": self.stats.requests_last_hour,
            "is_paused": self.stats.is_paused,
            "pause_reason": self.stats.pause_reason,
            "budget_remaining": self.budget_total - self.stats.total_requests,
            "schedule_mode": self.schedule_mode,
        }

    def print_status(self):
        """打印当前状态"""
        s = self.get_stats()
        status = "PAUSED" if s["is_paused"] else "RUNNING"
        print(f"\n{'─'*50}")
        print(f"  流量控制器 [{status}]")
        print(f"{'─'*50}")
        print(f"  速率: {s['current_rps']:.1f} / {s['target_rps']:.1f} req/s "
              f"(范围: {self.min_rps}-{self.max_rps})")
        print(f"  请求: {s['total_requests']} 总 | "
              f"{s['success']} 成功 | "
              f"{s['failed']} 失败 | "
              f"{s['blocked']} 被封")
        print(f"  窗口: {s['requests_last_minute']}/min | "
              f"{s['requests_last_hour']}/hour")
        print(f"  预算: 剩余 {s['budget_remaining']}/{self.budget_total}")
        print(f"  时段: {s['schedule_mode']} | "
              f"当前时间: {datetime.now().strftime('%H:%M')}")
        if s["is_paused"]:
            remaining = self.stats.pause_until - time.time()
            print(f"  暂停: {s['pause_reason']} (剩余 {remaining:.0f}s)")
        print(f"{'─'*50}\n")

    # ─── 手动控制 ──────────────────────────────────────────────

    def set_rps(self, rps: float):
        """手动设置 RPS"""
        self.stats.target_rps = max(self.min_rps, min(rps, self.max_rps))

    def pause(self, duration: float = 60, reason: str = "手动暂停"):
        """手动暂停"""
        self._pause(duration, reason)

    def resume(self):
        """手动恢复"""
        self._resume()

    def reset(self):
        """重置所有状态"""
        self.stats = TrafficStats(target_rps=self.initial_rps,
                                  min_rps=self.min_rps, max_rps=self.max_rps)
        self._request_times.clear()
        self._minute_window.clear()
        self._hour_window.clear()
        self._response_codes.clear()
        self._last_request_time = 0

    # ─── 回调注册 ──────────────────────────────────────────────

    def on_pause(self, callback: Callable):
        """注册暂停回调"""
        self._on_pause = callback

    def on_resume(self, callback: Callable):
        """注册恢复回调"""
        self._on_resume = callback

    def on_slowdown(self, callback: Callable):
        """注册降速回调"""
        self._on_slowdown = callback

    # ─── 装饰器 ───────────────────────────────────────────────

    def rate_limited(self, func):
        """装饰器：自动限速"""
        async def wrapper(*args, **kwargs):
            can_send = await self.acquire()
            if not can_send:
                return None
            try:
                result = await func(*args, **kwargs)
                # 尝试从结果提取状态码
                if hasattr(result, 'status_code'):
                    self.record_response(result.status_code)
                elif isinstance(result, dict) and 'status' in result:
                    self.record_response(result['status'])
                return result
            except Exception as e:
                self.record_response(0)
                raise
        return wrapper

    # ─── 上下文管理器 ─────────────────────────────────────────

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *args):
        pass

    # ─── 健康评估 ──────────────────────────────────────────────

    def get_health_score(self) -> float:
        """
        返回 0-100 健康分数
        100 = 一切正常，全速
        50 = 有些问题，已降速
        0 = 熔断/完全被封
        """
        if self.stats.is_paused:
            return 0

        score = 100.0

        # 成功率
        total = self.stats.total_success + self.stats.total_failed + self.stats.total_blocked
        if total > 10:
            success_rate = self.stats.total_success / total
            score *= success_rate

        # 被封次数惩罚
        if self.stats.total_blocked > 0:
            block_ratio = self.stats.total_blocked / max(total, 1)
            score *= (1 - block_ratio * 2)

        # 速率降低程度
        rps_ratio = self.stats.target_rps / self.initial_rps
        score *= min(rps_ratio, 1.0)

        return max(0, min(100, round(score, 1)))

    def should_continue(self) -> bool:
        """是否应该继续扫描（综合判断）"""
        # 预算耗尽
        if self.stats.total_requests >= self.budget_total:
            return False
        # 健康分太低
        if self.get_health_score() < 10:
            return False
        return True
