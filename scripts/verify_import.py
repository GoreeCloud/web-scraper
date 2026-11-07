"""Dependency-free static checks for the attributed GoreeCloud import."""
from pathlib import Path
import hashlib
import sys
import tomllib

root=Path(__file__).resolve().parents[1]
meta=tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
assert meta["name"] == "goreecloud-web-scraper"
assert meta["license"] == {"file":"LICENSE"}
scripts=meta["scripts"]
assert scripts["goreecloud-web-scraper"] == "scrapling.cli:main"
assert scripts["goreecloud-web-scraper-mcp"] == "scrapling.cli:mcp"
assert scripts["scrapling"] == "scrapling.cli:main"
assert scripts["scrapling-mcp"] == "scrapling.cli:mcp"
license_bytes=(root / "LICENSE").read_bytes()
expected="5c782ef0346e4fbfe0dc76fd435f181a0f1e4a1a7a6b13c169c6e74314ff5964"
assert hashlib.sha256(license_bytes).hexdigest()==expected, "upstream BSD license has changed"
assert (root / "agent-skill/Scrapling-Skill/LICENSE.txt").read_bytes()==license_bytes
assert "bc602488b44e978da3266841e913af17577ec0fd" in (root / "IMPORT_PROVENANCE.md").read_text()
assert "Karim Shoair" in (root / "THIRD_PARTY_NOTICES.md").read_text()
assert "GoreeCloud Web Scraper" in (root / "README.md").read_text()
assert (root / "goreecloud_web_scraper/__init__.py").exists()
assert "goreecloud_web_scraper*" in (root / "pyproject.toml").read_text()
assert not (root / ".github/workflows/release-and-publish.yml").exists()
assert not (root / ".github/workflows/docker-build.yml").exists()
print("Import static integrity checks passed", file=sys.stdout)
