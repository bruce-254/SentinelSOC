"""Simple in-process sliding-window rate limiter.

For a single instance this is sufficient. In a horizontally scaled deployment,
swap this for a Redis-backed implementation behind the same interface.
"""
from __future__ import annotations

import time
import threading
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int, name: str = "default"):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.name = name
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _client_key(self, request: Request) -> str:
        xff = request.headers.get("x-forwarded-for")
        ip = (xff.split(",")[0].strip() if xff else None) or request.client.host
        return f"{self.name}:{ip}"

    def allow(self, request: Request) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        key = self._client_key(request)
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window_seconds:
                q.popleft()
            if len(q) >= self.max_requests:
                retry = int(self.window_seconds - (now - q[0])) + 1
                return False, retry
            q.append(now)
            return True, 0


class RateLimitMiddleware:
    """Starlette middleware applying a configured limit per client IP."""

    def __init__(
        self,
        app,
        limiter: RateLimiter,
        exempt_paths: tuple[str, ...] = (),
    ):
        self.app = app
        self.limiter = limiter
        self.exempt_paths = exempt_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        if any(request.url.path.startswith(p) for p in self.exempt_paths):
            await self.app(scope, receive, send)
            return
        allowed, retry = self.limiter.allow(request)
        if not allowed:
            response = JSONResponse(
                status_code=429,
                content={"detail": "Too many requests", "code": "rate_limited"},
                headers={"Retry-After": str(retry)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
