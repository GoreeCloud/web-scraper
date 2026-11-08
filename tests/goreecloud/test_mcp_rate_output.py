"""Official served MCP HTTP rate, metadata and extracted-output limits.

All real network operations run against an owned ephemeral 127.0.0.1 fixture.
These per-process guards are not distributed quotas or OS egress isolation.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import AsyncMock, patch

import pytest

from scrapling.core.ai.server import (
    MCP_HTTP_RATE_WINDOW_SECONDS,
    MCP_MAX_CONCURRENT_HTTP_CALLS,
    MCP_MAX_HTTP_CALLS_PER_MINUTE,
    MCP_MAX_HTTP_METADATA_BYTES,
    MCP_MAX_HTTP_OUTPUT_BYTES,
    ResponseModel,
    ScraplingMCPServer,
)


def _server() -> ScraplingMCPServer:
    server = ScraplingMCPServer()
    server._served = True
    return server


@pytest.mark.asyncio
async def test_rate_admission_shared_between_one_shot_and_persistent_tools_and_resets():
    server = _server()
    # No DNS, sockets, or external calls. Rate is consumed for admitted
    # attempts even when they are subsequently denied by destination policy.
    with patch("scrapling.core.ai.server.monotonic", return_value=100.0):
        for index in range(MCP_MAX_HTTP_CALLS_PER_MINUTE - 1):
            with pytest.raises(ValueError, match="origin allowlist"):
                await server.make_request(f"https://blocked.invalid/{index}")
        with pytest.raises(ValueError, match="not found"):
            await server.session_make_request(
                url="https://blocked.invalid/", session_id="never-opened"
            )
        with pytest.raises(ValueError, match="rate budget"):
            await server.make_request("https://blocked.invalid/overflow")
        assert len(server._served_http_recent_calls) == MCP_MAX_HTTP_CALLS_PER_MINUTE
    with patch(
        "scrapling.core.ai.server.monotonic",
        return_value=100.0 + MCP_HTTP_RATE_WINDOW_SECONDS + 0.001,
    ):
        with pytest.raises(ValueError, match="origin allowlist"):
            await server.make_request("https://blocked.invalid/after-window")
    assert len(server._served_http_recent_calls) == 1
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS


@pytest.mark.asyncio
async def test_simultaneous_rate_admission_is_atomic():
    server = _server()
    with patch("scrapling.core.ai.server.monotonic", return_value=23.0):
        results = await asyncio.gather(
            *(server._served_http_rate_budget() for _ in range(MCP_MAX_HTTP_CALLS_PER_MINUTE + 12)),
            return_exceptions=True,
        )
    assert sum(result is None for result in results) == MCP_MAX_HTTP_CALLS_PER_MINUTE
    assert sum(isinstance(result, ValueError) for result in results) == 12
    assert len(server._served_http_recent_calls) == MCP_MAX_HTTP_CALLS_PER_MINUTE


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["a" * (MCP_MAX_HTTP_METADATA_BYTES + 1), "❤" * 12000])
@pytest.mark.parametrize("field", ["headers", "cookies", "params", "auth"])
async def test_large_metadata_refused_before_dns_and_session_lookup(field, value):
    server = _server()
    target = {"X-Budget-Test": value}
    with patch.object(server, "_require_static_target", new_callable=AsyncMock) as preflight:
        with pytest.raises(ValueError, match="32 KiB"):
            await server.make_request("https://blocked.invalid", **{field: target})
        with pytest.raises(ValueError, match="32 KiB"):
            await server.session_make_request(
                "https://blocked.invalid", session_id="not-opened", **{field: target}
            )
        preflight.assert_not_called()


def test_utf8_and_json_escaping_accounted_for_in_output_budget():
    small = ResponseModel(status=200, content=["❤" * 100], url="http://localhost/")
    ScraplingMCPServer._served_http_output_budget(small)
    large = ResponseModel(
        status=200, content=["❤" * (MCP_MAX_HTTP_OUTPUT_BYTES // 3 + 12)],
        url="http://localhost/"
    )
    with pytest.raises(ValueError, match="256 KiB"):
        ScraplingMCPServer._served_http_output_budget(large)


class _Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/large":
            # Below the 4 MiB *transport* response limit, but above the
            # 256 KiB *extracted JSON output* limit.
            body = (
                b"<html><body><p>" + b"X" * (MCP_MAX_HTTP_OUTPUT_BYTES + 14000)
                + b"</p></body></html>"
            )
        else:
            body = b"<html><body><p>Authorized small response</p></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, *args):
        return


@contextmanager
def _owned_http_fixture():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Fixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.asyncio
async def test_real_loopback_response_output_budget_for_one_shot_and_persistent():
    with _owned_http_fixture() as port:
        server = ScraplingMCPServer(
            allowed_target_origins=(f"http://127.0.0.1:{port}",),
            allow_loopback_targets=True,
        )
        server._served = True
        small_url = f"http://127.0.0.1:{port}/small"
        large_url = f"http://127.0.0.1:{port}/large"
        common = dict(impersonate=None, stealthy_headers=False, extraction_type="text")
        small = await server.make_request(small_url, **common)
        assert small.status == 200
        assert any("Authorized small response" in value for value in small.content)
        with pytest.raises(ValueError, match="256 KiB"):
            await server.make_request(large_url, **common)
        assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
        opened = await server.open_request_session("bounded-output", impersonate=None)
        try:
            with pytest.raises(ValueError, match="256 KiB"):
                await server.session_make_request(large_url, session_id=opened.session_id, extraction_type="text", stealthy_headers=False)
            again = await server.session_make_request(
                small_url, session_id=opened.session_id, extraction_type="text", stealthy_headers=False,
            )
            assert again.status == 200
            assert "Authorized small response" in " ".join(again.content)
        finally:
            await server.close_session(opened.session_id)
        assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
        assert server._sessions == {}
