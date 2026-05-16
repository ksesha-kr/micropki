import time
from collections import defaultdict
from typing import Dict, Tuple
import threading


class TokenBucket:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def get_retry_after(self) -> int:
        with self._lock:
            if self.tokens >= 1:
                return 0
            return int((1 - self.tokens) / self.rate) + 1


class RateLimiter:
    def __init__(self, rate: float = 0, burst: int = 10):
        self.rate = rate
        self.burst = burst
        self.buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> Tuple[bool, int]:
        if self.rate <= 0:
            return True, 0
        with self._lock:
            if client_ip not in self.buckets:
                self.buckets[client_ip] = TokenBucket(self.rate, self.burst)
            bucket = self.buckets[client_ip]
            allowed = bucket.consume()
            retry_after = bucket.get_retry_after() if not allowed else 0
            return allowed, retry_after


_rate_limiter = None


def get_rate_limiter(rate: float = 0, burst: int = 10) -> RateLimiter:
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(rate, burst)
    return _rate_limiter