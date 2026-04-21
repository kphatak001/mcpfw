"""Token bucket rate limiter."""

from __future__ import annotations
import time


class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: float):
        self.max_calls = max_calls
        self.window = window_seconds
        self._calls: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < self.window]
        if len(self._calls) >= self.max_calls:
            return False
        self._calls.append(now)
        return True

    @classmethod
    def from_spec(cls, spec: str) -> RateLimiter:
        """Parse '10/minute', '100/hour', '5/second'."""
        count_str, unit = spec.strip().split("/")
        count = int(count_str)
        windows = {"second": 1, "minute": 60, "hour": 3600}
        return cls(count, windows.get(unit, 60))
