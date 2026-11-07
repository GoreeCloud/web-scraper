"""No external hosts: HTTP fetcher tests use an owned loopback-only fixture."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from scrapling.fetchers import AsyncFetcher, Fetcher


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/ok":
            body = b"<html><body><h1>GoreeCloud</h1></body></html>"
            status = 200
        else:
            body = b"<html><body><h1>Not Found</h1></body></html>"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        # Avoid logging request paths or headers, even in development fixtures.
        return None


@pytest.fixture(scope="module")
def loopback_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


@pytest.fixture(autouse=True)
def no_proxy_for_loopback(monkeypatch):
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


def _request_options():
    return {"timeout": 5, "retries": 1, "impersonate": None, "stealthy_headers": False, "follow_redirects": False}


def test_sync_fetch_and_parse(loopback_url):
    response = Fetcher.get(f"{loopback_url}/ok", **_request_options())
    assert response.status == 200
    assert response.css("h1::text").get() == "GoreeCloud"


def test_status_and_no_unplanned_redirect(loopback_url):
    missing = Fetcher.get(f"{loopback_url}/missing", **_request_options())
    assert missing.status == 404
    redirect = Fetcher.get(f"{loopback_url}/redirect", **_request_options())
    assert redirect.status == 302


@pytest.mark.asyncio
async def test_async_fetch_and_parse(loopback_url):
    response = await AsyncFetcher.get(f"{loopback_url}/ok", **_request_options())
    assert response.status == 200
    assert response.css("h1::text").get() == "GoreeCloud"
