"""Small ASGI ingress budget for the official GoreeCloud MCP HTTP listener.

This only counts inbound HTTP header fields and their encoded bytes. It does
not limit request bodies (handled by the MCP SDK), slow clients, TCP socket
counts or stdio. No header value or credential is logged or echoed on denial.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable


MAX_MCP_HEADER_BYTES = 8 * 1024
MAX_MCP_HEADER_FIELDS = 64


class MCPHeaderBudget:
    """Reject oversized HTTP request headers *before* auth and MCP dispatch."""

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        max_bytes: int = MAX_MCP_HEADER_BYTES,
        max_fields: int = MAX_MCP_HEADER_FIELDS,
    ) -> None:
        if max_bytes <= 0 or max_fields <= 0:
            raise ValueError("HTTP header budgets must be positive")
        self.app = app
        self.max_bytes = max_bytes
        self.max_fields = max_fields

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", ())
        too_large = len(headers) > self.max_fields
        if not too_large:
            size = 0
            for item in headers:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    too_large = True
                    break
                name, value = item
                if not isinstance(name, bytes) or not isinstance(value, bytes):
                    too_large = True
                    break
                size += len(name) + len(value) + 4  # colon, space and CRLF.
                if size > self.max_bytes:
                    too_large = True
                    break

        if too_large:
            # Fixed generic denial; never echo attacker-controlled headers or
            # bearer tokens in HTTP responses.
            body = b"MCP request headers exceed the allowed budget"
            await send({
                "type": "http.response.start",
                "status": 431,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
