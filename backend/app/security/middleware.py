"""HTTP hardening and observability middleware (pure ASGI).

Order (outermost first): request context and access log -> security headers ->
body size limit -> rate limit -> application.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.observability.context import request_id_var
from app.observability.logging import get_logger
from app.observability.metrics import Metrics
from app.security.ratelimit import RateLimiter

log = get_logger("http")
EXEMPT_FROM_RATE_LIMIT = ("/api/health", "/metrics")
SECURITY_HEADERS = [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer")]
API_CSP = b"default-src 'none'; frame-ancestors 'none'"


def _header(scope: Scope, name: bytes) -> str:
    for key, value in scope.get("headers", []):
        if key == name:
            return str(value.decode("latin-1"))
    return ""


async def _json_response(send: Send, status: int, body: dict[str, Any],
                         extra: list[tuple[bytes, bytes]] | None = None) -> None:
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode()),
                            *(extra or [])]})
    await send({"type": "http.response.body", "body": data})


class RequestContextMiddleware:
    """Request ID propagation, access logging and request metrics."""

    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app, self.metrics = app, metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = _header(scope, b"x-request-id")
        rid = incoming if 0 < len(incoming) <= 64 and incoming.replace("-", "").isalnum() else uuid.uuid4().hex
        token = request_id_var.set(rid)
        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", rid.encode()))
                message = {**message, "headers": headers}
            await send(message)

        started_response = {"sent": False}

        async def tracking_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                started_response["sent"] = True
            await send_wrapper(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:  # noqa: BLE001 - convert to a generic 500 without internals
            log.error("unhandled error", exc_info=exc)
            status_holder["status"] = 500
            if started_response["sent"]:
                raise
            await _json_response(send, 500, {"detail": "internal server error", "request_id": rid},
                                 [(b"x-request-id", rid.encode())])
        finally:
            route = scope.get("route")
            route_label = getattr(route, "path", None) or "unmatched"
            duration = time.perf_counter() - started
            status = status_holder["status"]
            self.metrics.requests.labels(scope["method"], route_label, str(status)).inc()
            self.metrics.latency.labels(scope["method"], route_label).observe(duration)
            if status >= 500:
                self.metrics.errors.labels(route_label).inc()
            principal = scope.get("state", {}).get("principal")
            log.info("request", extra={"method": scope["method"], "route": route_label, "status": status,
                                       "duration_ms": round(duration * 1000, 2),
                                       "actor": getattr(principal, "name", None)})
            request_id_var.reset(token)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                headers += [h for h in SECURITY_HEADERS if h[0] not in present]
                if path.startswith("/api/") and b"content-security-policy" not in present:
                    headers.append((b"content-security-policy", API_CSP))
                if path.startswith("/api/") and b"cache-control" not in present:
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """413 when the declared or streamed request body exceeds `max_bytes`."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _header(scope, b"content-length")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await _json_response(send, 413, {"detail": f"request body exceeds {self.max_bytes} bytes"})
            return
        received = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        sent_start = False

        async def guarded_send(message: Message) -> None:
            nonlocal sent_start
            if too_large:
                return
            sent_start = sent_start or message["type"] == "http.response.start"
            await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if too_large and not sent_start:
            await _json_response(send, 413, {"detail": f"request body exceeds {self.max_bytes} bytes"})


class RateLimitMiddleware:
    """Per-client fixed window; clients are keyed by token hash when present, else IP."""

    def __init__(self, app: ASGIApp, limiter: RateLimiter, per_minute: int, metrics: Metrics) -> None:
        self.app, self.limiter, self.per_minute, self.metrics = app, limiter, per_minute, metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path", "") in EXEMPT_FROM_RATE_LIMIT:
            await self.app(scope, receive, send)
            return
        auth = _header(scope, b"authorization")
        if auth:
            key = "t:" + hashlib.sha256(auth.encode()).hexdigest()[:24]
        else:
            client = scope.get("client") or ("unknown", 0)
            key = f"ip:{client[0]}"
        allowed, retry_after = self.limiter.hit(key, self.per_minute)
        if not allowed:
            self.metrics.rate_limited.inc()
            await _json_response(send, 429, {"detail": "rate limit exceeded"},
                                 [(b"retry-after", str(max(1, retry_after)).encode())])
            return
        await self.app(scope, receive, send)
