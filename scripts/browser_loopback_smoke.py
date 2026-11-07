"""Bounded, loopback-only browser smoke for GoreeCloud Web Scraper.

This script requires an explicitly supplied executable path and SHA-256. It does
not fetch third-party websites; Chromium itself must be independently isolated.
"""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import urlsplit
import os

from scrapling.fetchers import StealthyFetcher


BROWSER = Path(os.environ.get("GOREECLOUD_BROWSER_EXECUTABLE", ""))
EXPECTED_SHA256 = os.environ.get("GOREECLOUD_BROWSER_SHA256", "")


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        html = b"""<!DOCTYPE html><html><body><h1 id='test'>Before</h1><script>
            setTimeout(() => {
               document.querySelector('#test').textContent = 'Browser rendered';
               document.querySelector('#test').id='ready';
            }, 40);
        </script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

    def log_message(self, *args):
        return None


def make_page_setup(port):
    def page_setup(page):
        def on_request(route):
            target = urlsplit(route.request.url)
            if (target.scheme == "http" and target.hostname == "127.0.0.1"
                    and target.port == port):
                route.continue_()
            else:
                route.abort()
        page.route("**/*", on_request)
    return page_setup


def main():
    if not BROWSER.is_file() or len(EXPECTED_SHA256) != 64:
        raise ValueError("Explicit reviewed Chromium executable and SHA-256 are required")
    digest = sha256()
    with BROWSER.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != EXPECTED_SHA256.lower():
        raise ValueError("Chromium binary did not match the required SHA-256")
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    with TemporaryDirectory(prefix="goreecloud-scraper-browser-") as profile:
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            result = StealthyFetcher.fetch(
                url,
                headless=True,
                executable_path=str(BROWSER),
                user_data_dir=profile,
                page_setup=make_page_setup(server.server_port),
                google_search=False,
                dns_over_https=False,
                solve_cloudflare=False,
                block_ads=False,
                block_webrtc=True,
                allow_webgl=False,
                network_idle=False,
                wait_selector="#ready",
                timeout=10000,
                retries=1,
                wait=0,
                extra_flags=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--disable-domain-reliability",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
            )
            if result.status != 200 or result.css("#ready::text").get() != "Browser rendered":
                raise AssertionError("Loopback browser failed to render expected JavaScript")
            print("LOCAL_BROWSER_SMOKE_PASSED status=200 dynamic_render=Browser rendered")
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)


if __name__ == "__main__":
    main()
