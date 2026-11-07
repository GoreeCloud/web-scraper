"""GoreeCloud MCP transport trust-boundary and branding regression tests.

Tests patch the server run call; none listen on an external interface or expose
MCP tools to real clients. In-memory tests validate metadata independently.
"""
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from mcp.client import Client
from mcp.server import MCPServer

from scrapling.cli import mcp
from scrapling.core.ai import ScraplingMCPServer
from scrapling.core.ai.server import _StaticTokenVerifier


@pytest.fixture(autouse=True)
def no_inherited_mcp_token(monkeypatch):
    monkeypatch.delenv("SCRAPLING_MCP_AUTH_TOKEN", raising=False)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.42", "service.example.org"])
def test_anonymous_http_refuses_non_loopback(host):
    with patch.object(MCPServer, "run") as run:
        with pytest.raises(ValueError, match="non-loopback"):
            ScraplingMCPServer().serve(True, host, 8000, allow_unauthenticated=True)
    run.assert_not_called()


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_anonymous_http_localhost_with_dns_rebinding_protection(host):
    with patch.object(MCPServer, "run") as run:
        ScraplingMCPServer().serve(True, host, 8123, allow_unauthenticated=True)
    settings = run.call_args.kwargs["transport_security"]
    assert settings.enable_dns_rebinding_protection
    assert set(settings.allowed_hosts) == {
        "localhost:8123", "127.0.0.1:8123", "[::1]:8123"
    }
    assert set(settings.allowed_origins) == {
        f"{scheme}://{hostname}"
        for scheme in ("http", "https")
        for hostname in settings.allowed_hosts
    }


def test_anonymous_loopback_rejects_foreign_host_header():
    with patch.object(MCPServer, "run") as run:
        with pytest.raises(ValueError, match="loopback Host/Origin"):
            ScraplingMCPServer().serve(
                True, "127.0.0.1", 8123,
                allowed_hosts=("arbitrary.example.net:8123",),
                allow_unauthenticated=True,
            )
    run.assert_not_called()


def test_remote_authenticated_must_declare_allowlist():
    with patch.object(MCPServer, "run") as run:
        with pytest.raises(ValueError, match="explicit --allowed-host"):
            ScraplingMCPServer(auth_token="isolated-test-token").serve(
                True, "0.0.0.0", 8123
            )
    run.assert_not_called()


def test_remote_authenticated_with_allowlist():
    with patch.object(MCPServer, "run") as run:
        ScraplingMCPServer(auth_token="isolated-test-token").serve(
            True, "0.0.0.0", 8123,
            allowed_hosts=("scraper.example.net:8123",),
        )
    assert run.call_count == 1
    params = run.call_args.kwargs
    assert params["transport"] == "streamable-http"
    assert params["host"] == "0.0.0.0"
    assert params["transport_security"].allowed_hosts == ["scraper.example.net:8123"]


@pytest.mark.asyncio
async def test_server_metadata_is_rebranded_without_upstream_external_logo():
    server = ScraplingMCPServer()._build_server("127.0.0.1", 8123)
    async with Client(server) as client:
        info = client.server_info
        tools = await client.list_tools()
    assert info is not None
    assert info.title == "GoreeCloud Web Scraper"
    assert info.name == "GoreeCloud Web Scraper"
    assert str(info.website_url) == "https://github.com/GoreeCloud/web-scraper"
    assert not info.icons
    assert any(tool.name == "make_request" for tool in tools.tools)


@pytest.mark.asyncio
async def test_bearer_verifier_accepts_only_identical_token():
    verifier = _StaticTokenVerifier("test-secret-string")
    assert await verifier.verify_token("test-secret-string") is not None
    assert await verifier.verify_token("wrong") is None


def test_branded_cli_refuses_unauthenticated_remote_bind():
    result = CliRunner().invoke(mcp, ["--http", "--host", "0.0.0.0", "--no-auth"])
    assert result.exit_code == 2
    assert "non-loopback" in result.output


def test_branded_cli_refuses_authenticated_remote_without_allowlist():
    result = CliRunner().invoke(mcp, [
        "--http", "--host", "0.0.0.0", "--auth-token", "test-token"
    ])
    assert result.exit_code == 2
    assert "--allowed-host" in result.output


@pytest.mark.asyncio
async def test_actual_mcp_http_asgi_rejects_bad_credentials_hosts_and_origins():
    """Exercise SDK auth and Host/Origin middleware without opening a network socket."""
    from httpx2 import ASGITransport, AsyncClient

    port = 8123
    server = ScraplingMCPServer(auth_token="ephemeral-transport-test-token")
    app = server._build_server("127.0.0.1", port).streamable_http_app(
        transport_security=server._transport_security(server._loopback_allowed_hosts(port)),
        host="127.0.0.1",
    )
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    request = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url=f"http://127.0.0.1:{port}",
        ) as client:
            no_token = await client.post("/mcp", headers=headers, json=request)
            wrong_token = await client.post(
                "/mcp", headers={**headers, "Authorization": "Bearer wrong"}, json=request
            )
            approved = {
                **headers, "Authorization": "Bearer ephemeral-transport-test-token"
            }
            valid = await client.post("/mcp", headers=approved, json=request)
            foreign_host = await client.post(
                "/mcp", headers={**approved, "Host": f"attacker.invalid:{port}"}, json=request
            )
            foreign_origin = await client.post(
                "/mcp", headers={**approved, "Origin": "https://attacker.invalid"}, json=request
            )
    assert no_token.status_code == 401
    assert wrong_token.status_code == 401
    # The valid bearer token reaches MCP's session validation instead of an auth refusal.
    assert valid.status_code == 400 and "Missing session ID" in valid.text
    assert foreign_host.status_code == 421
    assert foreign_origin.status_code == 403


@pytest.mark.asyncio
async def test_anonymous_mcp_http_asgi_rejects_dns_rebinding_attempt():
    """Even anonymous loopback service must reject a malicious Host or Origin."""
    from httpx2 import ASGITransport, AsyncClient

    port = 8124
    server = ScraplingMCPServer()
    app = server._build_server("127.0.0.1", port).streamable_http_app(
        transport_security=server._transport_security(server._loopback_allowed_hosts(port)),
        host="127.0.0.1",
    )
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-06-18",
    }
    request = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url=f"http://127.0.0.1:{port}",
        ) as client:
            allowed = await client.post("/mcp", headers=headers, json=request)
            foreign_host = await client.post(
                "/mcp", headers={**headers, "Host": f"attacker.invalid:{port}"}, json=request
            )
            foreign_origin = await client.post(
                "/mcp", headers={**headers, "Origin": "https://attacker.invalid"}, json=request
            )
    assert allowed.status_code == 400 and "Missing session ID" in allowed.text
    assert foreign_host.status_code == 421
    assert foreign_origin.status_code == 403
