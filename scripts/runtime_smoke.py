"""Wheel-installed offline smoke test; run outside the source checkout."""
from importlib import metadata
import sys
from pathlib import Path

# Verify the wheel, not an accidental import from the source checkout.
source_root = Path(__file__).resolve().parents[1]
cwd = Path.cwd().resolve()
assert cwd != source_root and source_root not in cwd.parents, "run outside source checkout"

distribution = metadata.distribution("goreecloud-web-scraper")
assert distribution.version == "0.5.1"

from goreecloud_web_scraper import Selector as BrandedSelector
from scrapling import Selector as UpstreamSelector

assert BrandedSelector is UpstreamSelector

html = '<html><body><ul><li class="fruit">Apple</li><li class="fruit">Pear</li></ul></body></html>'
page = BrandedSelector(html, adaptive=False)
assert page.css("li.fruit::text").getall() == ["Apple", "Pear"]
assert len(page.xpath("//li")) == 2
scripts = {p.name: p.value for p in distribution.entry_points if p.group == "console_scripts"}
assert scripts["goreecloud-web-scraper"] == "scrapling.cli:main"
assert scripts["goreecloud-web-scraper-mcp"] == "scrapling.cli:mcp"
assert scripts["scrapling"] == "scrapling.cli:main"
print(f"Wheel/runtime smoke passed using Python {sys.version.split()[0]}")
