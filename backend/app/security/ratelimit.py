"""Fixed-window rate limiting: Redis when REDIS_URL is set, in-process otherwise.

If Redis becomes unreachable the limiter falls back to the in-process window
(degraded, per-instance limiting) rather than failing open or rejecting all
traffic; the fallback is logged.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Protocol

from app.observability.logging import get_logger

log = get_logger("ratelimit")


class RateLimiter(Protocol):
    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        """Returns (allowed, seconds until the window resets)."""


class MemoryRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[int, int]] = {}

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        now = int(time.time())
        window = now - now % window_seconds
        with self._lock:
            start, count = self._windows.get(key, (window, 0))
            if start != window:
                start, count = window, 0
            count += 1
            self._windows[key] = (start, count)
            if len(self._windows) > 50_000:  # bound memory: drop expired windows
                self._windows = {k: v for k, v in self._windows.items() if v[0] == window}
        return count <= limit, window + window_seconds - now


class RedisRateLimiter:
    def __init__(self, client: Any, fallback: MemoryRateLimiter | None = None) -> None:
        self.client = client
        self.fallback = fallback or MemoryRateLimiter()
        self.degraded = False

    @staticmethod
    def from_url(url: str) -> RedisRateLimiter:
        import redis

        return RedisRateLimiter(redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5))

    def hit(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        now = int(time.time())
        window = now - now % window_seconds
        redis_key = f"aegis:rl:{key}:{window}"
        try:
            pipe = self.client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, window_seconds + 5)
            count = int(pipe.execute()[0])
            if self.degraded:
                log.info("redis rate limiter recovered")
                self.degraded = False
        except Exception as exc:  # noqa: BLE001 - any Redis failure falls back
            if not self.degraded:
                log.warning("redis rate limiter unavailable; using in-process fallback", extra={"error": str(exc)})
                self.degraded = True
            return self.fallback.hit(key, limit, window_seconds)
        return count <= limit, window + window_seconds - now
