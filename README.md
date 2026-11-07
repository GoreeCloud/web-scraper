# GoreeCloud Web Scraper

**Rebranded import of [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling)**, based on the upstream `main` commit [`bc602488b44e978da3266841e913af17577ec0fd`](https://github.com/D4Vinci/Scrapling/commit/bc602488b44e978da3266841e913af17577ec0fd).

GoreeCloud Web Scraper is an attributed, independently maintained Python web scraping framework. Its imported foundation provides HTML parsing, HTTP fetching, optional browser-assisted fetching, spiders, and command-line tools. Importing the upstream code does not independently validate these capabilities in the GoreeCloud repository.

**Important:** This is a *rebranded import*, not an original codebase. Original code and copyright belong to the original authors and contributors. This downstream project is not affiliated with or endorsed by D4Vinci, Karim Shoair, or the Scrapling contributors.

## Installation from this repository

The imported framework requires Python 3.10 or later.

```sh
git clone https://github.com/GoreeCloud/web-scraper.git
cd web-scraper
python -m pip install -e .
```

For additional fetching, CLI, and browser capabilities, after reviewing optional dependencies and installation scripts:

```sh
python -m pip install -e ".[fetchers]"
goreecloud-web-scraper --help
```

The `goreecloud-web-scraper` and `goreecloud-web-scraper-mcp` entry points are downstream aliases. The existing Python import namespace (`scrapling`) and original CLI entry points (`scrapling`, `scrapling-mcp`) are **intentionally retained for compatibility**. The distribution metadata name is `goreecloud-web-scraper`; no release to PyPI or container registry is implied.

The new Python alias goreecloud_web_scraper delegates public entry points to the original implementation.

## Python example

```python
from goreecloud_web_scraper import Selector

page = Selector("<html><body><h1>Hello</h1></body></html>")
print(page.css("h1::text").get())
```

See the [original upstream README](UPSTREAM_README.md) for broader examples and optional installation instructions. The [upstream documentation](https://scrapling.readthedocs.io/en/latest/) describes the source foundation, not independent GoreeCloud release acceptance.

## Browser privacy defaults (development)

The inherited browser engine's earlier defaults allowed geolocation and notification permissions without consent, ignored HTTPS certificate errors and allowed service workers. GoreeCloud Web Scraper now defaults to `permissions=[]`, `ignore_https_errors=False`, and `service_workers="block"` for local and remote stealth browser contexts. These defaults are verified by offline CI tests. A caller who intentionally needs a sensitive capability can explicitly opt in with the existing `additional_args` settings, which should be scoped to an authorized use case.

Service-worker restrictions and a page-request interceptor are **not** general network isolation. A local development smoke can use the opt-in `scripts/browser_loopback_smoke.py` script with a reviewed browser executable and SHA-256, running against an owned temporary 127.0.0.1 server. Run it only in an approved isolated development environment with `GOREECLOUD_BROWSER_EXECUTABLE` and `GOREECLOUD_BROWSER_SHA256` provided for the exact reviewed executable. This browser probe is not part of the hosted CI matrix and is not evidence of safe arbitrary web browsing. **Chromium sandbox is now requested by default** for locally launched browser sessions (`chromium_sandbox=True`, supported by Patchright/Playwright). If the operating system or browser cannot provide a working sandbox, startup fails rather than silently retrying without one. Browser launch flags attempting `--no-sandbox` or `--disable-setuid-sandbox` are rejected while sandboxing is required. A legacy caller must explicitly opt out with `chromium_sandbox=False`; this removes a major defense and is not approved for untrusted content or network-exposed services. Remote CDP browser sandboxing is controlled by the separate browser host, not by this client-side flag.

An owned-loopback test with the reviewed local Chromium binary successfully rendered a JavaScript-updated page under the enabled browser sandbox. This is **not** network isolation or comprehensive browser security acceptance: sandbox effectiveness, unsupported OSes, browser downloads, filesystem/network policy, CDP sessions, proxy settings, malicious content, and end-to-end SSRF controls remain unverified. Do not run untrusted pages or production scraping until those boundaries are assessed and accepted.

## MCP transport safety (development)

MCP (Model Context Protocol) is **optional**. After reviewing the optional dependencies, install `.[ai]`; the branded `goreecloud-web-scraper-mcp` command retains the original `scrapling-mcp` compatibility alias. The default stdio transport does not open a TCP listener.

Streamable HTTP is **authenticated by default**. Prefer `SCRAPLING_MCP_AUTH_TOKEN` over a CLI token argument, since command arguments can appear in process listings. Without a token, `--http` refuses to start. The explicit `--no-auth` opt-out is permitted **only on a loopback bind**, and Host/Origin restrictions are enforced. Non-loopback bindings require both an authentication token and an explicit `--allowed-host` list. HTTP itself is not encrypted: if a private remote endpoint is needed, use trusted TLS termination, network isolation and firewall policy. The original environment-variable spelling remains for compatibility.

MCP tools can fetch URLs and open browser sessions using the process's actual network and filesystem privileges. This is **not** a general-purpose SSRF-safe public API. Use only permitted targets, handle sensitive data deliberately, and bound resources. CI validates token, Host/Origin, metadata and startup protections through in-memory MCP HTTP requests, without opening an external network listener. This does not imply full external MCP integration, browser or production acceptance.

## Checkpoint safety (development)

Spider checkpoints are local state stored as `checkpoint.pkl`. The downstream loader now rejects arbitrary pickle classes, checkpoint symlinks, nonregular files, invalid structures, and checkpoint files over 64 MiB. Writes are atomic and create private temporary files (0600 on POSIX). This is a safety improvement, not a guarantee that arbitrary untrusted checkpoint data is safe or that all custom upstream checkpoint payloads remain compatible.

Do not import checkpoint files from another person, share a checkpoint directory with untrusted users, or rely on saved checkpoints for recovery of sensitive production workloads without additional testing. Unsupported legacy object types are deliberately rejected and start fresh. Operators should keep checkpoint directories private, back up any needed prior state, and restrict access to credentials and scraped content.

## Wheel provenance and build reproducibility (development)

A read-only CI gate builds the package wheel twice using an identical environment and fixed `SOURCE_DATE_EPOCH`, compares the resulting bytes, then validates the archive's embedded BSD-3-Clause license against the exact repository `LICENSE`, distribution metadata, original D4Vinci/Scrapling attribution, preserved CLI aliases and every wheel `RECORD` digest. Negative checks must reject a tampered payload and a missing license. The SHA-256 is written to CI logs / job summary; the workflow neither publishes packages nor creates a signed release.

Passing this check establishes **only same-run, same-environment artifact reproducibility and local wheel integrity**. Build-tool versions are not fully locked; no independent builder, cross-platform reproducibility, cryptographic attestation, complete dependency-license/SBOM evaluation or production release approval is implied.

## Governance and provenance

- **License:** [BSD 3-Clause](LICENSE), preserving upstream copyright.
- **Provenance, synchronization, and modification scope:** [IMPORT_PROVENANCE.md](IMPORT_PROVENANCE.md).
- **Additional bundled component license:** [agent-skill/Scrapling-Skill/LICENSE.txt](agent-skill/Scrapling-Skill/LICENSE.txt).
- **Third-party acknowledgments:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Validation:** CI performs static import and license integrity, Python 3.10/3.12/3.13 wheel/package and CLI smoke checks, parser/checkpoint regressions, owned loopback HTTP fetcher tests, browser configuration privacy and sandbox defaults, in-memory MCP security tests, and same-environment wheel reproducibility/integrity checks. Live HTTP/browser/MCP integration, dependency security and production acceptance remain separate release gates.
- **Publishing:** Upstream package/container publishing workflows are not enabled in this rebranded repository.

Use web scraping responsibly, respecting applicable laws, site policies, privacy, and rate limits. Do not treat browser or anti-bot capabilities as permission to access restricted systems.
