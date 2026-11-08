"""Cooperative end-to-end deadline checks for official served MCP static HTTP tools.

Mocked preflight deliberately waits without resolving DNS or opening a socket.
An asyncio deadline is not a CPU preemption or OS network-isolation boundary.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from scrapling.core.ai.server import (
    MCP_MAX_CONCURRENT_HTTP_CALLS,
    ScraplingMCPServer,
)


def _served():
    server = ScraplingMCPServer()
    server._served = True
    return server


def _stalled_preflight(started: asyncio.Event, cancelled: asyncio.Event):
    async def preflight(*args, **kwargs):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    return preflight


@pytest.mark.asyncio
async def test_served_one_shot_deadline_includes_slow_target_authorization():
    server = _served()
    started = asyncio.Event()
    cancelled = asyncio.Event()
    with patch("scrapling.core.ai.server.MCP_MAX_HTTP_OPERATION_SECONDS", 0.03):
        with patch.object(server, "_require_static_target", side_effect=_stalled_preflight(started, cancelled)):
            with pytest.raises(ValueError, match="async budget"):
                await server.make_request("https://blocked.invalid/")
    assert started.is_set()
    assert cancelled.is_set()
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
    # A following tool can be admitted; it still cannot access an unapproved target.
    with pytest.raises(ValueError, match="origin allowlist"):
        await server.make_request("https://blocked.invalid/again")


@pytest.mark.asyncio
async def test_served_persistent_session_survives_preflight_deadline_and_closes():
    server = _served()
    opened = await server.open_request_session("deadline-test", impersonate=None)
    started = asyncio.Event()
    cancelled = asyncio.Event()
    try:
        with patch("scrapling.core.ai.server.MCP_MAX_HTTP_OPERATION_SECONDS", 0.03):
            with patch.object(server, "_require_static_target", side_effect=_stalled_preflight(started, cancelled)):
                with pytest.raises(ValueError, match="async budget"):
                    await server.session_make_request(
                        "https://blocked.invalid/", session_id=opened.session_id
                    )
        assert started.is_set()
        assert cancelled.is_set()
        assert server._sessions[opened.session_id].session._is_alive
        assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
    finally:
        await server.close_session(opened.session_id)
    assert server._sessions == {}


@pytest.mark.asyncio
async def test_external_task_cancellation_releases_served_slot():
    server = _served()
    started = asyncio.Event()
    cancelled = asyncio.Event()
    with patch.object(server, "_require_static_target", side_effect=_stalled_preflight(started, cancelled)):
        task = asyncio.create_task(server.make_request("https://blocked.invalid/"))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert cancelled.is_set()
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS


@pytest.mark.asyncio
async def test_unserved_direct_library_call_does_not_inherit_mcp_async_deadline():
    server = ScraplingMCPServer()
    started = asyncio.Event()
    cancelled = asyncio.Event()
    with patch("scrapling.core.ai.server.MCP_MAX_HTTP_OPERATION_SECONDS", 0.01):
        with patch.object(server, "_require_static_target", side_effect=_stalled_preflight(started, cancelled)):
            task = asyncio.create_task(server.make_request("https://blocked.invalid/"))
            try:
                await asyncio.wait_for(started.wait(), timeout=1)
                await asyncio.sleep(0.07)
                assert not task.done()
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_successful_preflight_still_checks_destination_policy():
    server = _served()
    with pytest.raises(ValueError, match="origin allowlist"):
        await server.make_request("http://127.0.0.1/")
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
