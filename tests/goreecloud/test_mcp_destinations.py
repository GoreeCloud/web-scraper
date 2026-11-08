"""Served GoreeCloud MCP destination-authorization and redirect regression tests.

Only owned loopback listeners are used; public-DNS test results are mocked.
This validates a policy preflight, not kernel-level egress confinement.
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from mcp.server import MCPServer

from scrapling.cli import mcp
from scrapling.core.ai._target_policy import MCPDestinationPolicy
from scrapling.core.ai.server import ScraplingMCPServer


def _dns(host, port, family, socket_type):
    assert family == 0 and socket_type == socket.SOCK_STREAM
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/",
    "http://192.168.1.7/",
    "http://224.0.0.1/",
    "http://0.0.0.0/",
    "https://example.org:444/",
    "http://example.org/",
    "https://attacker.example/",
    "file:///etc/passwd",
    "http://example.org@localhost/",
    "https://example.org#fragment",
    "https://example.org\\@127.0.0.1/",
    "https://example.org%2f@127.0.0.1/",
    "https://example.org:0/",
    "https://example.org:65536/",
    "https://example.org:badport/",
    "https://example.org\r\nX-Test: true",
])
@pytest.mark.asyncio
async def test_deny_unapproved_or_ambiguous_urls(url):
    policy = MCPDestinationPolicy(("https://example.org",))
    with pytest.raises(ValueError):
        await policy.require(url)


def test_invalid_origin_configuration_fails_fast():
    for origin in (
        "https://example.org/path", "https://example.org?x=1",
        "http://user:pass@example.org", "https://[::1",
        "*", "https://*.example.org", "https://example.org:99999",
    ):
        with pytest.raises(ValueError):
            MCPDestinationPolicy((origin,))


@pytest.mark.asyncio
async def test_exact_public_origin_is_checked_with_mocked_dns(monkeypatch):
    monkeypatch.setattr("scrapling.core.ai._target_policy.getaddrinfo", _dns)
    policy = MCPDestinationPolicy(("https://example.org:443",))
    await policy.require("https://example.org/resources/page?q=1")
    with pytest.raises(ValueError, match="allowlist"):
        await policy.require("https://sub.example.org/resources/page")
    with pytest.raises(ValueError, match="allowlist"):
        await policy.require("https://example.org:8443/resources/page")


@pytest.mark.asyncio
async def test_mixed_public_and_private_dns_answers_fail_closed(monkeypatch):
    def poisoned(host, port, family, socket_type):
        return _dns(host, port, family, socket_type) + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ]
    monkeypatch.setattr("scrapling.core.ai._target_policy.getaddrinfo", poisoned)
    with pytest.raises(ValueError, match="private, local"):
        await MCPDestinationPolicy(("https://example.org",)).require("https://example.org/")


@pytest.mark.asyncio
async def test_loopback_opt_in_does_not_allow_public_alias_rebinding_to_local(monkeypatch):
    def rebinding(host, port, family, socket_type):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    monkeypatch.setattr("scrapling.core.ai._target_policy.getaddrinfo", rebinding)
    policy = MCPDestinationPolicy(("http://public.example.org:8080",), allow_loopback=True)
    with pytest.raises(ValueError, match="private, local"):
        await policy.require("http://public.example.org:8080")


@pytest.mark.asyncio
async def test_dns_failure_and_empty_answer_are_denied(monkeypatch):
    policy = MCPDestinationPolicy(("https://example.org",))
    def failed(*args):
        raise socket.gaierror("no DNS")
    monkeypatch.setattr("scrapling.core.ai._target_policy.getaddrinfo", failed)
    with pytest.raises(ValueError, match="DNS lookup failed"):
        await policy.require("https://example.org")
    monkeypatch.setattr("scrapling.core.ai._target_policy.getaddrinfo", lambda *args: [])
    with pytest.raises(ValueError, match="private, local"):
        await policy.require("https://example.org")


@pytest.mark.asyncio
async def test_local_target_requires_separate_explicit_opt_in():
    strict = MCPDestinationPolicy(("http://127.0.0.1:8123",))
    with pytest.raises(ValueError, match="private, local"):
        await strict.require("http://127.0.0.1:8123")
    allowed = MCPDestinationPolicy(("http://127.0.0.1:8123",), allow_loopback=True)
    await allowed.require("http://127.0.0.1:8123")
    with pytest.raises(ValueError, match="allowlist"):
        await allowed.require("http://127.0.0.1:8124")


@pytest.mark.asyncio
async def test_private_network_never_authorized_by_loopback_opt_in():
    policy = MCPDestinationPolicy(("http://10.0.0.5:7777",), allow_loopback=True)
    with pytest.raises(ValueError, match="private, local"):
        await policy.require("http://10.0.0.5:7777")


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [
    {"follow_redirects": True},
    {"verify": False},
    {"proxy": "http://127.0.0.1:8080"},
    {"headers": {"Host": "127.0.0.1"}},
    {"headers": {"Proxy-Authorization": "Basic unsafe"}},
])
async def test_forbidden_request_overrides_rejected_before_connect(kwargs):
    server = ScraplingMCPServer(allowed_target_origins=("https://example.org",))
    server._served = True
    with patch("scrapling.core.ai.server.FetcherSession") as session:
        with pytest.raises(ValueError):
            await server.make_request("https://example.org", **kwargs)
        session.assert_not_called()


@pytest.mark.asyncio
async def test_default_served_http_tools_deny_all_destinations():
    server = ScraplingMCPServer()
    server._served = True
    with patch("scrapling.core.ai.server.FetcherSession") as session:
        with pytest.raises(ValueError, match="allowlist"):
            await server.make_request("https://example.org")
        session.assert_not_called()


@pytest.mark.asyncio
async def test_browser_launch_and_fetch_require_explicit_unrestricted_mode():
    server = ScraplingMCPServer()
    server._served = True
    with patch("scrapling.core.ai.server.AsyncStealthySession") as browser:
        with pytest.raises(ValueError, match="disabled by default"):
            await server.browser_open()
        with pytest.raises(ValueError, match="disabled by default"):
            await server.browser_fetch_once(url="https://example.org")
        with pytest.raises(ValueError, match="disabled by default"):
            await server.browser_fetch(url="https://example.org", session_id="not-open")
        browser.assert_not_called()


@pytest.mark.asyncio
async def test_persistent_proxy_refused_before_session_start():
    server = ScraplingMCPServer()
    server._served = True
    with patch("scrapling.core.ai.server.FetcherSession") as session:
        with pytest.raises(ValueError, match="Persistent HTTP proxy"):
            await server.open_request_session(proxy="http://localhost:3128")
        session.assert_not_called()


def test_serve_enables_policy_without_opening_network_listener():
    server = ScraplingMCPServer()
    with patch.object(MCPServer, "run") as run:
        server.serve(http=True, host="127.0.0.1", port=8123, allow_unauthenticated=True)
    assert server._served
    run.assert_called_once()


def test_refuse_unrestricted_browser_or_loopback_target_on_external_bind():
    with patch.object(MCPServer, "run") as run:
        with pytest.raises(ValueError, match="Unrestricted browser"):
            ScraplingMCPServer(
                auth_token="test", enable_unrestricted_browser_tools=True
            ).serve(http=True, host="0.0.0.0", port=8123, allowed_hosts=("scraper.example.org:8123",))
        with pytest.raises(ValueError, match="Loopback target authorization"):
            ScraplingMCPServer(
                auth_token="test", allow_loopback_targets=True
            ).serve(http=True, host="0.0.0.0", port=8123, allowed_hosts=("scraper.example.org:8123",))
    run.assert_not_called()


def test_cli_rejects_bad_origin_and_documents_controls():
    runner = CliRunner()
    help_result = runner.invoke(mcp, ["--help"])
    assert help_result.exit_code == 0
    assert "--allowed-target-origin" in help_result.output
    assert "--unsafe-allow-browser-tools" in help_result.output
    bad = runner.invoke(mcp, ["--allowed-target-origin", "http://user:pass@example.org"])
    assert bad.exit_code == 2
    assert "without credentials" in bad.output


class _OwnedFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/private")
            self.end_headers()
            return
        if self.path == "/private":
            data = b"Should not be fetched automatically"
        else:
            data = b"<html><body><h1 id='ok'>Controlled page</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        return


@contextmanager
def _owned_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OwnedFixture)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.asyncio
async def test_real_owned_loopback_get_and_redirect_refusal(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    with _owned_http_server() as port:
        server = ScraplingMCPServer(
            allowed_target_origins=(f"http://127.0.0.1:{port}",), allow_loopback_targets=True
        )
        server._served = True
        response = await server.make_request(
            url=f"http://127.0.0.1:{port}/", impersonate=None,
            stealthy_headers=False, retries=1, follow_redirects=False,
            extraction_type="text"
        )
        assert response.status == 200
        assert any("Controlled page" in content for content in response.content)
        redirect = await server.make_request(
            url=f"http://127.0.0.1:{port}/redirect", impersonate=None,
            stealthy_headers=False, retries=1, extraction_type="text"
        )
        assert redirect.status == 302
