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

## Checkpoint safety (development)

Spider checkpoints are local state stored as `checkpoint.pkl`. The downstream loader now rejects arbitrary pickle classes, checkpoint symlinks, nonregular files, invalid structures, and checkpoint files over 64 MiB. Writes are atomic and create private temporary files (0600 on POSIX). This is a safety improvement, not a guarantee that arbitrary untrusted checkpoint data is safe or that all custom upstream checkpoint payloads remain compatible.

Do not import checkpoint files from another person, share a checkpoint directory with untrusted users, or rely on saved checkpoints for recovery of sensitive production workloads without additional testing. Unsupported legacy object types are deliberately rejected and start fresh. Operators should keep checkpoint directories private, back up any needed prior state, and restrict access to credentials and scraped content.

## Governance and provenance

- **License:** [BSD 3-Clause](LICENSE), preserving upstream copyright.
- **Provenance, synchronization, and modification scope:** [IMPORT_PROVENANCE.md](IMPORT_PROVENANCE.md).
- **Additional bundled component license:** [agent-skill/Scrapling-Skill/LICENSE.txt](agent-skill/Scrapling-Skill/LICENSE.txt).
- **Third-party acknowledgments:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- **Validation:** CI performs static import and license integrity, Python 3.10/3.12/3.13 wheel/package and CLI smoke checks, parser/checkpoint regressions, and owned loopback HTTP fetcher tests. Live HTTP/browser/MCP integration, dependency security and production acceptance remain separate release gates.
- **Publishing:** Upstream package/container publishing workflows are not enabled in this rebranded repository.

Use web scraping responsibly, respecting applicable laws, site policies, privacy, and rate limits. Do not treat browser or anti-bot capabilities as permission to access restricted systems.
