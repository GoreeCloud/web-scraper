"""Offline ASGI security regression tests for inbound MCP HTTP header limits."""

from __future__ import annotations

import asyncio

import pytest

from scrapling.core.ai._header_limit import (
    MAX_MCP_HEADER_BYTES,
    MAX_MCP_HEADER_FIELDS,
    MCPHeaderBudget,
)
from scrapling.core.ai.server import ScraplingMCPServer


class FakeApp:
    def __init__(self):
        self.called = 0

    async def __call__(self, scope, receive, send):
        self.called += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _run(header_list, *, scope_type="http"):
    called = FakeApp()
    middleware = MCPHeaderBudget(called)
    responses = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        responses.append(message)

    await middleware({"type": scope_type, "headers": header_list}, receive, send)
    return called.called, responses


@pytest.mark.asyncio
async def test_over_budget_bytes_returns_431_without_invoking_app_or_leaking_token():
    secret = b"never-echo-this-token"
    called, messages = await _run([
        (b"authorization", b"Bearer " + secret),
        (b"x-padded", b"x" * MAX_MCP_HEADER_BYTES),
    ])
    assert called == 0
    assert messages[0]["status"] == 431
    assert b"".join(message.get("body", b"") for message in messages).find(secret) == -1
    assert (b"cache-control", b"no-store") in messages[0]["headers"]


@pytest.mark.asyncio
async def test_over_budget_header_count_returns_431_before_app():
    called, messages = await _run([(b"x", b"v")] * (MAX_MCP_HEADER_FIELDS + 1))
    assert called == 0
    assert messages[0]["status"] == 431


@pytest.mark.asyncio
async def test_exact_encoded_header_byte_budget_is_accepted():
    field_name = b"x-okay"
    allowed_size = MAX_MCP_HEADER_BYTES - len(field_name) - 4
    called, messages = await _run([(field_name, b"z" * allowed_size)])
    assert called == 1
    assert messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_malformed_headers_rejected_without_logging_input():
    for bad in ([(b"bad",)], [("untrusted-text", b"value")], [(b"name", "value")]):
        called, messages = await _run(bad)
        assert called == 0
        assert messages[0]["status"] == 431


@pytest.mark.asyncio
async def test_non_http_scope_is_not_blocked_by_header_budget():
    called, messages = await _run([(b"x", b"x" * (MAX_MCP_HEADER_BYTES + 1))], scope_type="lifespan")
    assert called == 1
    assert messages[0]["status"] == 200


def test_invalid_header_budget_configuration_fails_closed():
    for maximum in (0, -1):
        with pytest.raises(ValueError):
            MCPHeaderBudget(FakeApp(), max_bytes=maximum)
        with pytest.raises(ValueError):
            MCPHeaderBudget(FakeApp(), max_fields=maximum)


def test_built_sdk_http_app_has_guard_without_network_listener():
    server = ScraplingMCPServer()
    sdk_server = server._build_server("127.0.0.1", 8000)
    app = sdk_server.streamable_http_app(host="127.0.0.1")
    assert any(layer.cls is MCPHeaderBudget for layer in app.user_middleware)
