# Rebranded Import — Source Provenance

| Field | Verified import baseline |
| --- | --- |
| Downstream product | GoreeCloud Web Scraper |
| Downstream GitHub repository | https://github.com/GoreeCloud/web-scraper |
| Original upstream | https://github.com/D4Vinci/Scrapling |
| Upstream default branch | `main` |
| Source commit | `bc602488b44e978da3266841e913af17577ec0fd` |
| Upstream source version | `0.5.1` |
| Import date | 2026-11-07 |
| Source license | BSD-3-Clause, with original copyright and disclaimer retained |
| Import type | Rebranded import with upstream Git history preserved |

## Scope of downstream modifications

- Product name, repository links, packaging metadata, setup metadata, and Docker image label/entry point updated to GoreeCloud Web Scraper.
- New branded README, upstream README snapshot, and attribution notice.
- New GoreeCloud Python import alias and command aliases `goreecloud-web-scraper` and `goreecloud-web-scraper-mcp`.
- Internal `scrapling` Python package and original command aliases kept for compatibility.
- Upstream release/PyPI/Docker publishing workflows disabled in the downstream checkout. A read-only static import-validation workflow replaces them. These workflows remain recoverable in upstream Git history.

The historical upstream commits remain attributed to their original authors. Later modifications are downstream changes and do not imply upstream endorsement.

## Future upstream updates

Fetch original upstream into a local import branch, inspect the incoming diff and licensing, review dependency and workflow changes, resolve downstream rebranding conflicts, run tests, and merge through the repository's normal release gates. Do not blindly mirror upstream deployment workflows or force-push the downstream default branch.
