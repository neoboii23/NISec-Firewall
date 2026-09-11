from __future__ import annotations
import time
import math
from collections import defaultdict, deque
from threading import Lock


class RateLimiter:
    """Small lock-protected, in-memory per-IP sliding-window limiter."""
    def __init__(self, requests: int, window: int):
        self.requests, self.window = requests, window
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = Lock()

    def allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        with self.lock:
            for ip, entries in list(self.events.items()):
                while entries and now - entries[0] >= self.window:
                    entries.popleft()
                if not entries:
                    del self.events[ip]
            bucket = self.events[client_ip]
            while bucket and now - bucket[0] >= self.window:
                bucket.popleft()
            if len(bucket) >= self.requests:
                return False
            bucket.append(now)
            return True

    def snapshot(self):
        now = time.monotonic()
        with self.lock:
            return [{"source_ip": ip, "request_count": sum(now-t < self.window for t in entries),
                     "limit": self.requests, "window": self.window,
                     "remaining_seconds": max(0, int(self.window-(now-entries[0])))}
                    for ip, entries in list(self.events.items())[:100] if entries and now-entries[-1] < self.window]

    def configure(self,requests,window):
        with self.lock:
            self.requests,self.window=requests,window

    def retry_after(self,ip):
        with self.lock:
            bucket=self.events.get(ip)
            return max(1,math.ceil(self.window-(time.monotonic()-bucket[0]))) if bucket else 1
