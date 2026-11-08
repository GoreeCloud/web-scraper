"""Owned-loopback *real HTTP listener* acceptance for the branded MCP CLI.

No public target is contacted, no browser launched, and no service is deployed.
The isolated MCP subprocess receives a minimal environment and an ephemeral
bearer token. The fixture binds only 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import subprocess
import sys
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import httpx2
import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


class _TargetHandler(BaseHTTPRequestHandler):
    blocked_hits = 0

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/blocked")
            self.end_headers()
            return
        if self.path == "/blocked":
            type(self).blocked_hits += 1
        data = b"<html><body><h1>Owned MCP target</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        return


@contextmanager
def _owned_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _TargetHandler.blocked_hits = 0
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@contextmanager
def _owned_mcp_listener(tmp_path: Path, port: int, target_port: int, token: str):
    executable = Path(sys.executable).parent / "goreecloud-web-scraper-mcp"
    if not executable.is_file():
        raise AssertionError("The wheel-installed branded MCP CLI entry point is missing")
    # Do not inherit user credentials, proxies or unrelated environment data.
    env = {
        "PATH": str(executable.parent) + os.pathsep + os.defpath,
        "HOME": str(tmp_path),
        "PYTHONUNBUFFERED": "1",
        "SCRAPLING_MCP_AUTH_TOKEN": token,
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }
    args = [
        str(executable),
        "--http",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--allowed-target-origin", f"http://127.0.0.1:{target_port}",
        "--allow-loopback-targets",
    ]
    with (tmp_path / "local-mcp-subprocess.log").open("wb") as logfile:
        proc = subprocess.Popen(
            args,
            cwd=tmp_path,
            env=env,
            stdout=logfile,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


async def _wait_for_listener(proc: subprocess.Popen, port: int):
    # Require an actual auth-middleware response, not merely a bound socket.
    url = f"http://127.0.0.1:{port}/mcp"
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    request = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    async with httpx2.AsyncClient(trust_env=False, timeout=0.5) as client:
        for _ in range(120):
            if proc.poll() is not None:
                raise AssertionError(f"Owned MCP listener exited before readiness: exit {proc.returncode}")
            try:
                response = await client.post(url, headers=headers, json=request)
                if response.status_code == 401:
                    return
            except (httpx2.TransportError, httpx2.TimeoutException):
                pass
            await asyncio.sleep(0.1)
    raise AssertionError("Owned MCP listener was not ready within the loopback budget")


@pytest.mark.skipif(os.name != "posix", reason="The subprocess isolation test currently supports POSIX")
@pytest.mark.asyncio
async def test_live_authenticated_mcp_listener_and_allowed_owned_target(tmp_path):
    with _owned_target() as target_port:
        port = _free_loopback_port()
        token = secrets.token_urlsafe(24)
        with _owned_mcp_listener(tmp_path, port, target_port, token) as proc:
            await _wait_for_listener(proc, port)
            endpoint = f"http://127.0.0.1:{port}/mcp"
            headers = {
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2025-06-18",
            }
            ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}

            async with httpx2.AsyncClient(trust_env=False, timeout=5) as raw:
                unauthenticated = await raw.post(endpoint, headers=headers, json=ping)
                assert unauthenticated.status_code == 401
                wrong_token = await raw.post(
                    endpoint, headers={**headers, "Authorization": "Bearer wrong"}, json=ping
                )
                assert wrong_token.status_code == 401
                bad_host = await raw.post(
                    endpoint, headers={
                        **headers, "Authorization": f"Bearer {token}",
                        "Host": f"unapproved.example.invalid:{port}",
                    }, json=ping
                )
                assert bad_host.status_code == 421
                bad_origin = await raw.post(
                    endpoint, headers={
                        **headers, "Authorization": f"Bearer {token}",
                        "Origin": "http://unapproved.example.invalid",
                    }, json=ping
                )
                assert bad_origin.status_code == 403

            async with httpx2.AsyncClient(
                trust_env=False,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            ) as http_client:
                async with streamable_http_client(endpoint, http_client=http_client) as streams:
                    async with ClientSession(*streams) as session:
                        initialized = await session.initialize()
                        assert initialized.server_info.name == "GoreeCloud Web Scraper"
                        result = await session.call_tool("make_request", {
                            "url": f"http://127.0.0.1:{target_port}/",
                            "impersonate": None,
                            "extraction_type": "text",
                            "stealthy_headers": False,
                            "retries": 100000,  # the server must force only one attempt
                        })
                        assert not result.is_error
                        assert result.structured_content is not None
                        assert result.structured_content["status"] == 200
                        assert "Owned MCP target" in " ".join(result.structured_content["content"])

                        redirect = await session.call_tool("make_request", {
                            "url": f"http://127.0.0.1:{target_port}/redirect",
                            "impersonate": None,
                            "extraction_type": "text",
                            "stealthy_headers": False,
                        })
                        assert not redirect.is_error
                        assert redirect.structured_content["status"] == 302
                        assert _TargetHandler.blocked_hits == 0

                        denied = await session.call_tool("make_request", {
                            "url": "http://127.0.0.1:1/",
                            "impersonate": None,
                        })
                        assert denied.is_error
                        assert "allowlist" in " ".join(str(item) for item in denied.content)

                        disabled_browser = await session.call_tool("browser_fetch_once", {
                            "url": f"http://127.0.0.1:{target_port}/",
                        })
                        assert disabled_browser.is_error
                        assert "disabled by default" in " ".join(
                            str(item) for item in disabled_browser.content
                        )

                        opened = await session.call_tool("open_request_session", {
                            "session_id": "owned-live",
                            "impersonate": None,
                        })
                        assert not opened.is_error
                        via_session = await session.call_tool("session_make_request", {
                            "url": f"http://127.0.0.1:{target_port}/",
                            "session_id": "owned-live",
                            "extraction_type": "text",
                            "stealthy_headers": False,
                        })
                        assert not via_session.is_error
                        assert via_session.structured_content["status"] == 200
                        closed = await session.call_tool("close_session", {
                            "session_id": "owned-live"
                        })
                        assert not closed.is_error
        assert proc.poll() is not None
