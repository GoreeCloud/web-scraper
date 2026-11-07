"""GoreeCloud browser privacy/security default configuration without launching a browser."""
import pytest
from scrapling.engines._browsers._stealth import StealthySession, AsyncStealthySession


@pytest.mark.parametrize("session_class", [StealthySession, AsyncStealthySession])
def test_browser_defaults_do_not_grant_sensitive_capabilities(session_class):
    session = session_class()
    ctx = session._context_options
    assert ctx["ignore_https_errors"] is False
    assert ctx["service_workers"] == "block"
    assert ctx["permissions"] == []
    assert not session._is_alive


@pytest.mark.parametrize("session_class", [StealthySession, AsyncStealthySession])
def test_browser_sensitive_options_require_explicit_opt_in(session_class):
    session = session_class(additional_args={
        "ignore_https_errors": True,
        "service_workers": "allow",
        "permissions": ["geolocation"],
    })
    ctx = session._context_options
    assert ctx["ignore_https_errors"] is True
    assert ctx["service_workers"] == "allow"
    assert ctx["permissions"] == ["geolocation"]
    assert not session._is_alive


def test_no_implicit_notifications_or_geolocation_on_simple_fetch():
    session = StealthySession(headless=True, block_webrtc=True)
    assert session._context_options["permissions"] == []
    assert session._config.block_webrtc is True
