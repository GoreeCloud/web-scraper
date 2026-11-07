"""GoreeCloud Web Scraper public import alias for the attributed Scrapling foundation."""
from importlib import import_module
from scrapling import __version__
__all__ = ["Selector", "Fetcher", "AsyncFetcher", "StealthyFetcher"]

def __getattr__(name: str):
    if name in __all__:
        return getattr(import_module("scrapling"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

def __dir__() -> list[str]:
    return sorted(list(globals()) + __all__)
