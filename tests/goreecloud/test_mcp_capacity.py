"""Official served MCP resource-admission regressions, all offline."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from scrapling.core.ai.server import (
    MCP_MAX_ACTIVE_SESSIONS,
    MCP_MAX_CONCURRENT_HTTP_CALLS,
    ScraplingMCPServer,
)


def _server():
    instance = ScraplingMCPServer()
    instance._served = True
    return instance


@pytest.mark.asyncio
async def test_served_session_limit_and_reuse_after_close():
    server = _server()
    try:
        for i in range(MCP_MAX_ACTIVE_SESSIONS):
            opened = await server.open_request_session(f"bounded-{i}", impersonate=None)
            assert opened.session_id == f"bounded-{i}"
        assert len((await server.list_sessions())) == MCP_MAX_ACTIVE_SESSIONS
        with pytest.raises(ValueError, match="session budget"):
            await server.open_request_session("overflow", impersonate=None)
        await server.close_session("bounded-0")
        added = await server.open_request_session("reused", impersonate=None)
        assert added.session_id == "reused"
    finally:
        for sid in list(server._sessions):
            await server.close_session(sid)
    assert server._sessions == {}


@pytest.mark.asyncio
async def test_served_pending_session_reserves_capacity_and_cancellation_releases_it():
    server = _server()
    started = asyncio.Event()
    proceed = asyncio.Event()

    class DelayedFetcher:
        _is_alive = True

        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            started.set()
            await proceed.wait()
            return self

        async def __aexit__(self, *args):
            self._is_alive = False

    with patch("scrapling.core.ai.server.FetcherSession", DelayedFetcher):
        tasks = [
            asyncio.create_task(server.open_request_session(f"pending-{i}", impersonate=None))
            for i in range(MCP_MAX_ACTIVE_SESSIONS)
        ]
        try:
            await asyncio.wait_for(started.wait(), timeout=2)
            for _ in range(100):
                if len(server._pending_session_ids) == MCP_MAX_ACTIVE_SESSIONS:
                    break
                await asyncio.sleep(0.01)
            assert len(server._pending_session_ids) == MCP_MAX_ACTIVE_SESSIONS
            with pytest.raises(ValueError, match="session budget"):
                await server.open_request_session("ninth", impersonate=None)
            with pytest.raises(ValueError, match="session.*budget|already starting"):
                await server.open_request_session("pending-0", impersonate=None)
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(isinstance(value, asyncio.CancelledError) for value in results)
            assert server._pending_session_ids == set()
            assert server._sessions == {}
            proceed.set()
            opened = await server.open_request_session("after-cancel", impersonate=None)
            assert opened.session_id == "after-cancel"
            await server.close_session(opened.session_id)
        finally:
            proceed.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_failed_browser_construction_does_not_leak_reserved_slot():
    server = ScraplingMCPServer(enable_unrestricted_browser_tools=True)
    server._served = True
    with patch("scrapling.core.ai.server.AsyncStealthySession", side_effect=RuntimeError("deliberate")):
        with pytest.raises(RuntimeError, match="deliberate"):
            await server.browser_open(session_id="browser-error")
    assert server._pending_session_ids == set()
    assert server._sessions == {}


@pytest.mark.asyncio
async def test_served_http_concurrency_cap_cancellation_and_recovery():
    server = _server()
    entered = 0
    all_entered = asyncio.Event()
    never = asyncio.Event()

    async def stalled_preflight(*args, **kwargs):
        nonlocal entered
        entered += 1
        if entered == MCP_MAX_CONCURRENT_HTTP_CALLS:
            all_entered.set()
        await never.wait()
        raise AssertionError("preflight should never be released")

    with patch.object(server, "_require_static_target", side_effect=stalled_preflight):
        tasks = [
            asyncio.create_task(server.make_request(f"http://example.invalid/{i}"))
            for i in range(MCP_MAX_CONCURRENT_HTTP_CALLS)
        ]
        try:
            await asyncio.wait_for(all_entered.wait(), timeout=3)
            with pytest.raises(ValueError, match="concurrency budget"):
                await server.make_request("http://example.invalid/overflow")
            assert entered == MCP_MAX_CONCURRENT_HTTP_CALLS
        finally:
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(isinstance(value, asyncio.CancelledError) for value in results)
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS
    # A subsequent admitted call must reach preflight, rather than fail because
    # cancellation leaked an occupied semaphore slot.
    with pytest.raises(ValueError, match="configured MCP origin allowlist"):
        await server.make_request("http://127.0.0.1/")
    assert server._served_http_slots._value == MCP_MAX_CONCURRENT_HTTP_CALLS


@pytest.mark.asyncio
async def test_direct_library_session_limit_not_injected():
    server = ScraplingMCPServer()
    try:
        for i in range(MCP_MAX_ACTIVE_SESSIONS + 1):
            await server.open_request_session(f"library-{i}", impersonate=None)
        assert len(server._sessions) == MCP_MAX_ACTIVE_SESSIONS + 1
    finally:
        for sid in list(server._sessions):
            await server.close_session(sid)
